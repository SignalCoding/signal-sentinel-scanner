// -----------------------------------------------------------------------
// <copyright file="DocumentSegment.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Core.Models;

/// <summary>
/// v3.0.0 (WP10): classification of a region of a SKILL.md document. Flags enum so
/// rules can declare the combination of segment kinds they evaluate
/// (<see cref="DocumentSegment"/>.Kind always carries exactly one value).
/// </summary>
[System.Flags]
public enum SegmentKind
{
    /// <summary>No segments.</summary>
    None = 0,

    /// <summary>YAML frontmatter block (without the surrounding <c>---</c> fences).</summary>
    Frontmatter = 1,

    /// <summary>
    /// Plain markdown text (paragraphs, headings, list items, block quotes) with inline
    /// code spans removed and link destinations stripped (link text is retained).
    /// </summary>
    Prose = 2,

    /// <summary>
    /// Fenced or indented code block (content only, fences excluded). The
    /// <see cref="DocumentSegment.Language"/> hint carries the fence info string.
    /// </summary>
    FencedCode = 4,

    /// <summary>Inline code span (<c>`code`</c>) found inside a prose block.</summary>
    InlineCode = 8,

    /// <summary>
    /// Inline link found inside a prose block; content is the destination URL followed
    /// by the link text.
    /// </summary>
    Link = 16,

    /// <summary>Raw HTML block or inline HTML element.</summary>
    HtmlBlock = 32,

    /// <summary>Every segment kind.</summary>
    All = Frontmatter | Prose | FencedCode | InlineCode | Link | HtmlBlock
}

/// <summary>
/// v3.0.0 (WP10): one classified region of a SKILL.md document, produced by the
/// scanner's DocumentSegmenter and consumed by skill rules through SegmentFilter.
/// </summary>
public sealed record DocumentSegment
{
    /// <summary>
    /// The single segment kind this region was classified as. Never a combination.
    /// </summary>
    public required SegmentKind Kind { get; init; }

    /// <summary>
    /// Segment text. For <see cref="SegmentKind.Prose"/> this is the block's text with
    /// inline code spans removed and link URLs stripped; for
    /// <see cref="SegmentKind.FencedCode"/> it is the code without the fence lines.
    /// </summary>
    public required string Content { get; init; }

    /// <summary>
    /// Fence info string for <see cref="SegmentKind.FencedCode"/> (e.g. "bash",
    /// "python"), lower-cased. Null for all other kinds and for fences without a hint.
    /// </summary>
    public string? Language { get; init; }

    /// <summary>
    /// 1-based line number in the original SKILL.md file where the segment starts
    /// (frontmatter occupies lines 2 and up when present).
    /// </summary>
    public int StartLine { get; init; }
}
