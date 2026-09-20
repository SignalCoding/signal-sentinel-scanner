// -----------------------------------------------------------------------
// <copyright file="PipelineTaint.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;

namespace SignalSentinel.Core.Security;

/// <summary>
/// How a fetched payload reaches an execution sink.
/// </summary>
public enum TaintFlow
{
    /// <summary>Source and sink piped together on one line: <c>curl ... | bash</c>.</summary>
    DirectPipe,

    /// <summary>The pipe is base64-decoded before the sink: <c>curl ... | base64 -d | bash</c>.</summary>
    EncodedPipe,

    /// <summary>A variable captures the source; a later line feeds it to a sink.</summary>
    VariableMediated
}

/// <summary>
/// One fetch-to-exec finding: a network fetch whose output reaches a command,
/// script or dynamic-evaluation sink.
/// </summary>
public sealed record TaintFinding
{
    /// <summary>1-based line number of the source call.</summary>
    public required int SourceLine { get; init; }

    /// <summary>The matched source text (e.g. <c>curl https://...</c>), truncated.</summary>
    public required string SourceText { get; init; }

    /// <summary>1-based line number of the sink.</summary>
    public required int SinkLine { get; init; }

    /// <summary>The matched sink text (e.g. <c>| bash</c>), truncated.</summary>
    public required string SinkText { get; init; }

    /// <summary>How the taint reached the sink.</summary>
    public required TaintFlow Flow { get; init; }

    /// <summary>The captured variable name, when <see cref="Flow"/> is <see cref="TaintFlow.VariableMediated"/>.</summary>
    public string? Variable { get; init; }

    /// <summary>
    /// False only for the "echo &lt;b64&gt; | base64 -d | bash" shape, where the payload is
    /// embedded in the script rather than fetched. Callers should not describe the source
    /// as a network fetch when this is false.
    /// </summary>
    public required bool HasNetworkSource { get; init; }
}

/// <summary>
/// Line-oriented fetch-to-exec taint analysis for Bash/Zsh, PowerShell, Python,
/// JavaScript/TypeScript, and fenced code blocks of arbitrary or no declared language.
/// </summary>
/// <remarks>
/// This is deliberately not a parser. A real shell/AST analysis is out of scope for a
/// static scanner that must run in milliseconds against untrusted, possibly malformed
/// script content. Instead it looks for two things on a bounded window of lines: a
/// "source" call that fetches something over the network, and a "sink" that runs a
/// string as code or hands it to a shell. A source piped straight into a sink is
/// Critical; a source assigned to a variable that is used in a sink within
/// <see cref="MaxVariableWindowLines"/> lines is High. This catches the overwhelming
/// majority of real "curl | bash" style installers and their base64-wrapped and
/// variable-mediated variants, at the cost of missing anything that goes through a
/// function call, a file write/read round-trip, or more than one variable hop.
/// </remarks>
public static partial class PipelineTaint
{
    /// <summary>Variable-mediated flows are only tracked this many lines ahead of the source.</summary>
    public const int MaxVariableWindowLines = 20;

    /// <summary>Lines beyond this length are truncated before matching, to bound regex cost.</summary>
    private const int MaxLineLength = 2_000;

    /// <summary>Scripts beyond this many lines are truncated; taint analysis is best-effort, not exhaustive.</summary>
    private const int MaxLines = 20_000;

    /// <summary>
    /// At most this many findings per analysed input. A script of nothing but
    /// <c>curl ... | bash</c> lines should not produce a 20,000-finding report.
    /// </summary>
    public const int MaxFindingsPerInput = 100;

    private const int MaxEvidenceLength = 100;

    // ---------------------------------------------------------------- sources

    [GeneratedRegex(
        @"\b(curl|wget)\s+(?:-\S+\s+)*['""]?(?:https?|ftp)://\S+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex CurlWgetSource();

    [GeneratedRegex(
        @"\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex PowerShellWebSource();

    [GeneratedRegex(
        @"(urllib\.request\.urlopen|requests\.(get|post|put)|httpx\.(get|post)|urllib2\.urlopen)\s*\(",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex PythonWebSource();

    [GeneratedRegex(
        @"(\bfetch\s*\(|axios\.(get|post)\s*\(|http\.get\s*\(|https\.get\s*\()",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex JavaScriptWebSource();

    // ---------------------------------------------------------------- sinks

    // Path-prefixed (/bin/bash) and env-prefixed (| env bash) shells are included:
    // both appear in real installers. powershell/pwsh execute piped stdin as commands.
    [GeneratedRegex(
        @"\|\s*(?:sudo\s+)?(?:env\s+)?(?:/(?:[\w.-]+/)*)?(sh|bash|zsh|dash|ksh|python[0-9.]*|node|perl|ruby|powershell|pwsh)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex ShellPipeSink();

    [GeneratedRegex(
        @"\|\s*(Invoke-Expression|iex)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex PowerShellPipeSink();

    [GeneratedRegex(
        @"\b(bash|sh|zsh)\s+<\(|\b(bash|sh|zsh)\s+-c\s+[""']?\$\(|source\s+<\(",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex ProcessSubstitutionSink();

    [GeneratedRegex(
        @"\b(eval|Invoke-Expression|iex)\s*[\(\s]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex EvalSink();

    [GeneratedRegex(
        @"\bexec\s*\(|subprocess\.\w+\s*\([^)]*shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\(",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex PythonExecSink();

    [GeneratedRegex(
        @"child_process\.(exec|execSync|spawn)\s*\(|require\s*\(\s*['""]child_process['""]\s*\)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex NodeExecSink();

    private static readonly Regex[] SourcePatterns =
    [
        CurlWgetSource(), PowerShellWebSource(), PythonWebSource(), JavaScriptWebSource()
    ];

    private static readonly Regex[] SinkPatterns =
    [
        ShellPipeSink(), PowerShellPipeSink(), ProcessSubstitutionSink(),
        EvalSink(), PythonExecSink(), NodeExecSink()
    ];

    [GeneratedRegex(@"\bbase64\s+(-d|--decode)\b|\bbase64\.b64decode\s*\(|\batob\s*\(|\bFromBase64String\s*\(",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex Base64Decode();

    // ---------------------------------------------------------------- variable capture

    // "x=$(curl ...)", "x=`curl ...`", "$x = Invoke-WebRequest ...", "x = requests.get(...)",
    // "const body = await fetch(...)", "local -r data=$(...)".
    [GeneratedRegex(
        @"^\s*(?:(?:const|let|var|local|declare|typeset|export|my|final)(?:\s+-[a-zA-Z]+)*\s+)?(?:\$)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\$\(|`)?\s*(.+)$",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex VariableAssignment();

    /// <summary>
    /// Finds fetch-to-exec taint flows in a block of script or code.
    /// </summary>
    public static IReadOnlyList<TaintFinding> Analyse(string? content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return [];
        }

        var lines = SplitLines(content);
        var findings = new List<TaintFinding>();
        var pendingVariables = new Dictionary<string, (int Line, string SourceText)>(StringComparer.Ordinal);

        for (var i = 0; i < lines.Length; i++)
        {
            if (findings.Count >= MaxFindingsPerInput)
            {
                break;
            }

            var line = lines[i];
            if (line.Length == 0 || IsCommentLine(line))
            {
                continue;
            }

            var lineNumber = i + 1;
            var hasSource = TryMatchAny(SourcePatterns, line, out var sourceMatch);
            var hasSink = TryMatchAny(SinkPatterns, line, out var sinkMatch);
            var decodeMatch = Base64Decode().SafeMatch(line);
            var hasDecode = decodeMatch is { Success: true };

            // Direct pipe (source -> sink), or a base64-decode step feeding a sink. The
            // decode case does not require a network source: "echo <payload> | base64 -d
            // | bash" hides the command in the script itself rather than fetching it, but
            // is the same "decode an opaque string and run it" attack.
            if ((hasSource || hasDecode) && hasSink)
            {
                findings.Add(new TaintFinding
                {
                    SourceLine = lineNumber,
                    SourceText = Truncate(hasSource ? sourceMatch : decodeMatch!.Value),
                    SinkLine = lineNumber,
                    SinkText = Truncate(sinkMatch),
                    Flow = hasDecode ? TaintFlow.EncodedPipe : TaintFlow.DirectPipe,
                    HasNetworkSource = hasSource
                });
                continue;
            }

            // A sink on this line that consumes a variable captured from an earlier source.
            if (hasSink)
            {
                foreach (var (variable, capture) in pendingVariables)
                {
                    if (findings.Count >= MaxFindingsPerInput)
                    {
                        break;
                    }

                    if (!ReferencesVariable(line, variable))
                    {
                        continue;
                    }

                    findings.Add(new TaintFinding
                    {
                        SourceLine = capture.Line,
                        SourceText = Truncate(capture.SourceText),
                        SinkLine = lineNumber,
                        SinkText = Truncate(sinkMatch),
                        Flow = TaintFlow.VariableMediated,
                        Variable = variable,
                        HasNetworkSource = true
                    });
                }
            }

            // A bare fetch (no pipe on this line): remember it in case a later line
            // assigns it to a variable and a further line feeds that variable to a sink.
            if (hasSource)
            {
                var assignment = VariableAssignment().Match(line);
                if (assignment.Success && SourcePatterns.Any(p => p.SafeIsMatch(assignment.Groups[2].Value)))
                {
                    pendingVariables[assignment.Groups[1].Value] = (lineNumber, sourceMatch);
                }
            }

            // Drop variables that have aged out of the tracking window.
            if (pendingVariables.Count > 0)
            {
                var expired = pendingVariables
                    .Where(kv => lineNumber - kv.Value.Line > MaxVariableWindowLines)
                    .Select(kv => kv.Key)
                    .ToList();
                foreach (var key in expired)
                {
                    pendingVariables.Remove(key);
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// Runs <see cref="Analyse"/> against every fenced code block in Markdown-ish text
    /// (skill instructions, MCP server instructions, tool/prompt descriptions), tagged or
    /// not (```bash, ```, ~~~python, ...). Line numbers are relative to the block content.
    /// </summary>
    /// <remarks>
    /// Fences are found by a linear line walk, not a regex: a multiline regex over
    /// attacker-controlled Markdown is a quadratic-time (and therefore timeout/evasion)
    /// risk, and a CRLF or unterminated closing fence would silently hide the block.
    /// Detection is deliberately favourable over CommonMark strictness: a fence-only
    /// line of the same marker closes a block, a block that never closes runs to end of
    /// input, and only the first whitespace-delimited token of the info string is the
    /// reported language ("```bash -e" -> "bash").
    /// </remarks>
    public static IEnumerable<(string Language, IReadOnlyList<TaintFinding> Findings)> AnalyseFencedCodeBlocks(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            yield break;
        }

        var inFence = false;
        var fenceChar = '`';
        var language = "unspecified";
        var body = new System.Text.StringBuilder();

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var trimmed = line.TrimStart();
            var isFence = trimmed.StartsWith("```", StringComparison.Ordinal)
                || trimmed.StartsWith("~~~", StringComparison.Ordinal);

            if (!inFence)
            {
                if (isFence)
                {
                    inFence = true;
                    fenceChar = trimmed[0];
                    language = FirstToken(trimmed.TrimStart(fenceChar).Trim());
                    body.Clear();
                }

                continue;
            }

            if (isFence && IsFenceOnly(trimmed, fenceChar))
            {
                var closed = Analyse(body.ToString());
                if (closed.Count > 0)
                {
                    yield return (language, closed);
                }

                inFence = false;
                continue;
            }

            body.Append(line).Append('\n');
        }

        if (inFence && body.Length > 0)
        {
            // Unterminated fence: the rest of the document is the block.
            var unterminated = Analyse(body.ToString());
            if (unterminated.Count > 0)
            {
                yield return (language, unterminated);
            }
        }
    }

    private static string FirstToken(string infoString)
    {
        if (infoString.Length == 0)
        {
            return "unspecified";
        }

        var spaceIndex = infoString.IndexOfAny([' ', '\t']);
        return spaceIndex < 0 ? infoString : infoString[..spaceIndex];
    }

    private static bool IsFenceOnly(string trimmedLine, char fenceChar)
    {
        foreach (var ch in trimmedLine)
        {
            if (ch != fenceChar)
            {
                return false;
            }
        }

        return trimmedLine.Length >= 3;
    }

    private static string[] SplitLines(string content)
    {
        var raw = content.Split('\n');
        var lines = new string[Math.Min(raw.Length, MaxLines)];
        for (var i = 0; i < lines.Length; i++)
        {
            var line = raw[i].TrimEnd('\r');
            lines[i] = line.Length > MaxLineLength ? line[..MaxLineLength] : line;
        }

        return lines;
    }

    private static bool IsCommentLine(string line)
    {
        var trimmed = line.TrimStart();
        if (trimmed.StartsWith("#!", StringComparison.Ordinal))
        {
            return false; // shebang, not a comment for our purposes
        }

        return trimmed.StartsWith('#') || trimmed.StartsWith("//", StringComparison.Ordinal)
            || trimmed.StartsWith("REM ", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryMatchAny(Regex[] patterns, string line, out string matchedText)
    {
        foreach (var pattern in patterns)
        {
            var m = pattern.SafeMatch(line);
            if (m is { Success: true })
            {
                matchedText = m.Value;
                return true;
            }
        }

        matchedText = string.Empty;
        return false;
    }

    private static bool ReferencesVariable(string line, string variable)
    {
        // "$x", "${x}", or bare "x" (PowerShell/Python style) as a whole token.
        var pattern = $@"\$\{{?{Regex.Escape(variable)}\}}?\b|(?<![\w$]){Regex.Escape(variable)}\b";
        return SafeIsMatch(pattern, line);
    }

    private static bool SafeIsMatch(string pattern, string input)
    {
        try
        {
            return Regex.IsMatch(input, pattern, RegexOptions.None, TimeSpan.FromMilliseconds(500));
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static string Truncate(string value) =>
        value.Length <= MaxEvidenceLength ? value : value[..(MaxEvidenceLength - 3)] + "...";

    private static bool SafeIsMatch(this Regex pattern, string input)
    {
        try
        {
            return pattern.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static Match? SafeMatch(this Regex pattern, string input)
    {
        try
        {
            return pattern.Match(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return null;
        }
    }
}
