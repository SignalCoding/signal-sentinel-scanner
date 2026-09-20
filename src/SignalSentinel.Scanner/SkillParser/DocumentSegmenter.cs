// -----------------------------------------------------------------------
// <copyright file="DocumentSegmenter.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text;
using Markdig;
using Markdig.Helpers;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.SkillParser;

/// <summary>
/// v3.0.0 (WP10): splits a SKILL.md document into typed segments (frontmatter, prose,
/// fenced code, inline code, links, HTML) so skill rules can evaluate only the regions
/// where their patterns are meaningful. Built on Markdig's CommonMark parser.
/// </summary>
/// <remarks>
/// <para>
/// Prose segments have inline code spans removed and link destinations stripped (link
/// text is retained); the removed content surfaces as separate
/// <see cref="SegmentKind.InlineCode"/> and <see cref="SegmentKind.Link"/> segments.
/// Fenced and indented code blocks surface as <see cref="SegmentKind.FencedCode"/> with
/// the fence lines excluded and the info string carried as
/// <see cref="DocumentSegment.Language"/>.
/// </para>
/// <para>
/// The walk is iterative (explicit stacks) rather than recursive so pathologically
/// nested quotes/lists/emphasis in hostile input cannot overflow the call stack. Input
/// size is bounded upstream by SkillReader's 5 MB skill-file limit.
/// </para>
/// </remarks>
public static class DocumentSegmenter
{
    private static readonly MarkdownPipeline Pipeline =
        new MarkdownPipelineBuilder().UsePreciseSourceLocation().Build();

    /// <summary>
    /// Segments the full raw content of a SKILL.md file. Returns an empty list for
    /// null or empty input.
    /// </summary>
    public static IReadOnlyList<DocumentSegment> Segment(string? rawContent)
    {
        if (string.IsNullOrEmpty(rawContent))
        {
            return [];
        }

        var segments = new List<DocumentSegment>();

        var body = SplitFrontmatter(rawContent, out var frontmatter, out var bodyStartLine);
        if (frontmatter is not null)
        {
            segments.Add(new DocumentSegment
            {
                Kind = SegmentKind.Frontmatter,
                Content = frontmatter,
                StartLine = 2
            });
        }

        if (string.IsNullOrWhiteSpace(body))
        {
            return segments;
        }

        MarkdownDocument document;
        try
        {
            // UsePreciseSourceLocation: inline elements then carry absolute source
            // spans, so InlineCode/Link segment StartLine values are correct.
            document = Markdown.Parse(body, Pipeline);
        }
        catch (ArgumentException)
        {
            // Markdig enforces a nesting-depth limit and throws on pathological input
            // (thousands of nested quotes/lists). Degrade to a single prose segment of
            // the raw body so hostile nesting can never hide content from the rules.
            segments.Add(new DocumentSegment
            {
                Kind = SegmentKind.Prose,
                Content = body,
                StartLine = bodyStartLine
            });
            return segments;
        }

        var lineIndex = BuildLineIndex(body);

        var pending = new Stack<Block>();
        PushChildren(pending, document);

        while (pending.Count > 0)
        {
            var block = pending.Pop();
            switch (block)
            {
                case FencedCodeBlock fenced:
                    segments.Add(new DocumentSegment
                    {
                        Kind = SegmentKind.FencedCode,
                        Content = LinesText(fenced.Lines),
                        Language = string.IsNullOrWhiteSpace(fenced.Info)
                            ? null
                            : fenced.Info.Trim().ToLowerInvariant(),
                        StartLine = fenced.Line + bodyStartLine
                    });
                    break;

                // Indented code block. Must come after FencedCodeBlock (which derives from it).
                case CodeBlock indented:
                    segments.Add(new DocumentSegment
                    {
                        Kind = SegmentKind.FencedCode,
                        Content = LinesText(indented.Lines),
                        StartLine = indented.Line + bodyStartLine
                    });
                    break;

                case HtmlBlock html:
                    segments.Add(new DocumentSegment
                    {
                        Kind = SegmentKind.HtmlBlock,
                        Content = LinesText(html.Lines),
                        StartLine = html.Line + bodyStartLine
                    });
                    break;

                case LeafBlock leaf:
                    ExtractProse(leaf, body, lineIndex, bodyStartLine, segments);
                    break;

                case ContainerBlock container:
                    PushChildren(pending, container);
                    break;
            }
        }

        // The block walk emits inline segments before their parent prose block;
        // restore document order so concatenated text reads naturally.
        segments.Sort(static (a, b) => a.StartLine.CompareTo(b.StartLine));

        return segments;
    }

    private static void PushChildren(Stack<Block> pending, ContainerBlock container)
    {
        // Push in reverse so Pop visits children in document order.
        for (var i = container.Count - 1; i >= 0; i--)
        {
            pending.Push(container[i]);
        }
    }

    private static void ExtractProse(
        LeafBlock leaf,
        string body,
        List<int> lineIndex,
        int bodyStartLine,
        List<DocumentSegment> segments)
    {
        if (leaf.Inline is null)
        {
            return;
        }

        var prose = new StringBuilder();
        var pending = new Stack<Inline>();
        PushInlines(pending, leaf.Inline);

        while (pending.Count > 0)
        {
            var inline = pending.Pop();
            switch (inline)
            {
                case LiteralInline literal:
                    prose.Append(literal.Content.ToString());
                    break;

                case LineBreakInline:
                    prose.Append('\n');
                    break;

                case CodeInline code:
                    segments.Add(new DocumentSegment
                    {
                        Kind = SegmentKind.InlineCode,
                        Content = code.Content,
                        StartLine = LineAt(lineIndex, code.Span.Start) + bodyStartLine - 1
                    });
                    prose.Append(' ');
                    break;

                case LinkInline link:
                    segments.Add(new DocumentSegment
                    {
                        Kind = SegmentKind.Link,
                        Content = LinkDestination(link),
                        StartLine = LineAt(lineIndex, link.Span.Start) + bodyStartLine - 1
                    });
                    // The title attribute was part of the raw body pre-WP10; keep it
                    // visible to prose-scanning rules as well as Link-scanning ones.
                    if (!string.IsNullOrEmpty(link.Title))
                    {
                        prose.Append(' ').Append(link.Title);
                    }

                    // Link text / image alt text stays in prose; only the destination
                    // and title are segregated into the Link segment.
                    PushInlines(pending, link);
                    break;

                case AutolinkInline autolink:
                    // <https://...> autolinks are LeafInline, not LinkInline. The URL
                    // was plain text pre-WP10, so it stays in prose AND surfaces as a
                    // Link segment; dropping it would blind every rule to the URL.
                    segments.Add(new DocumentSegment
                    {
                        Kind = SegmentKind.Link,
                        Content = autolink.Url ?? string.Empty,
                        StartLine = LineAt(lineIndex, autolink.Span.Start) + bodyStartLine - 1
                    });
                    prose.Append(autolink.Url);
                    break;

                case HtmlInline html:
                    segments.Add(new DocumentSegment
                    {
                        Kind = SegmentKind.HtmlBlock,
                        Content = html.Tag,
                        StartLine = LineAt(lineIndex, html.Span.Start) + bodyStartLine - 1
                    });
                    break;

                case ContainerInline container:
                    PushInlines(pending, container);
                    break;
            }
        }

        var text = prose.ToString();
        if (!string.IsNullOrWhiteSpace(text))
        {
            segments.Add(new DocumentSegment
            {
                Kind = SegmentKind.Prose,
                Content = text,
                StartLine = leaf.Line + bodyStartLine
            });
        }
    }

    private static void PushInlines(Stack<Inline> pending, ContainerInline container)
    {
        var child = container.LastChild;
        while (child is not null)
        {
            pending.Push(child);
            child = child.PreviousSibling;
        }
    }

    // The Link segment carries the destination and the title attribute. The label
    // (link text / image alt) is intentionally NOT included: it already remains in the
    // Prose segment, and including it made prose prose-patterns (e.g. SS-016's
    // curl-pipe-sh) fire on documentation labels.
    private static string LinkDestination(LinkInline link)
    {
        var url = link.Url ?? string.Empty;
        var title = link.Title ?? string.Empty;
        return (url + " " + title).Trim();
    }

    private static string LinesText(StringLineGroup lines)
    {
        var sb = new StringBuilder();
        foreach (StringLine line in lines)
        {
            sb.Append(line.Slice.ToString());
            sb.Append('\n');
        }

        return sb.ToString();
    }

    private static List<int> BuildLineIndex(string text)
    {
        var starts = new List<int> { 0 };
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '\n')
            {
                starts.Add(i + 1);
            }
        }

        return starts;
    }

    /// <summary>1-based line number within <paramref name="lineIndex"/>'s text.</summary>
    private static int LineAt(List<int> lineIndex, int offset)
    {
        var i = lineIndex.BinarySearch(offset);
        if (i < 0)
        {
            i = ~i - 1;
        }

        return i + 1;
    }

    /// <summary>
    /// Splits a leading YAML frontmatter block (lines that are exactly <c>---</c>)
    /// from the markdown body without truncating, so line numbers stay correct for the
    /// full raw content. Returns the body; <paramref name="bodyStartLine"/> is the
    /// 1-based line of the file where the body begins.
    /// </summary>
    private static string SplitFrontmatter(string content, out string? frontmatter, out int bodyStartLine)
    {
        frontmatter = null;
        bodyStartLine = 1;

        if (!content.StartsWith("---", StringComparison.Ordinal))
        {
            return content;
        }

        // Fence lines allow trailing whitespace, matching FrontmatterParser's
        // "^---\s*\n" form (hand-edited YAML commonly has trailing spaces).
        var firstNewline = content.IndexOf('\n', StringComparison.Ordinal);
        if (firstNewline < 0 || !IsFenceLine(content.AsSpan(0, firstNewline)))
        {
            return content;
        }

        var lineStart = firstNewline + 1;
        var frontmatterStart = lineStart;
        var lineNumber = 2;
        while (lineStart <= content.Length)
        {
            var newline = content.IndexOf('\n', lineStart);
            var lineEnd = newline < 0 ? content.Length : newline;
            if (IsFenceLine(content.AsSpan(lineStart, lineEnd - lineStart)))
            {
                // FrontmatterParser requires a newline AFTER the closing fence; a
                // closing fence at EOF means no frontmatter there either.
                if (newline < 0)
                {
                    break;
                }

                frontmatter = content[frontmatterStart..lineStart];
                var bodyStart = newline + 1;
                bodyStartLine = lineNumber + 1;
                return content[bodyStart..];
            }

            if (newline < 0)
            {
                break;
            }

            lineStart = newline + 1;
            lineNumber++;
        }

        // No closing fence: treat the whole document as body (matches FrontmatterParser).
        return content;
    }

    /// <summary>A fence line is exactly <c>---</c> plus optional trailing whitespace.</summary>
    private static bool IsFenceLine(ReadOnlySpan<char> line) =>
        line.TrimEnd().SequenceEqual("---");
}
