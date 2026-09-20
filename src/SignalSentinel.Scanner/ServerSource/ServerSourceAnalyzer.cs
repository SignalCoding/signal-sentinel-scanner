// -----------------------------------------------------------------------
// <copyright file="ServerSourceAnalyzer.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;
using SignalSentinel.Scanner.SkillParser;

namespace SignalSentinel.Scanner.ServerSource;

/// <summary>
/// v3.0.0 (WP9): regex-level static pass over an MCP server's JS/TS/Python source. Finds
/// files that register tools and reports dangerous sinks in those same files. Bounded
/// like <see cref="FileForensics"/>: capped file and directory counts, no reparse-point
/// traversal, per-file size limit, excluded vendor directories.
/// </summary>
public static partial class ServerSourceAnalyzer
{
    /// <summary>Maximum source files read per run.</summary>
    public const int MaxFiles = 500;

    /// <summary>Maximum directories visited per run.</summary>
    public const int MaxDirectories = 2_000;

    /// <summary>Files above this size are skipped (minified bundles, vendored blobs).</summary>
    public const long MaxFileBytes = 1024 * 1024;

    /// <summary>Cap on sinks reported per run so a hostile tree cannot flood the report.</summary>
    public const int MaxSinks = 200;

    private const int MaxSnippetLength = 160;

    private static readonly HashSet<string> SourceExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".py"
    };

    /// <summary>Walks <paramref name="directory"/> and returns co-located tool registrations and sinks.</summary>
    public static async Task<ServerSourceAnalysis> AnalyseAsync(string directory, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        var root = Path.GetFullPath(directory);
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException($"Server source directory not found: {directory}");
        }

        var sinks = new List<SourceSink>();
        var filesScanned = 0;
        var toolFiles = 0;
        var directoriesVisited = 0;
        var truncated = false;

        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (filesScanned >= MaxFiles || directoriesVisited >= MaxDirectories)
            {
                truncated = true;
                break;
            }

            var dir = pending.Pop();
            directoriesVisited++;

            IEnumerable<string> entries;
            try
            {
                entries = Directory.EnumerateFileSystemEntries(dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                FileSystemInfo info;
                try
                {
                    info = Directory.Exists(entry) ? new DirectoryInfo(entry) : new FileInfo(entry);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    continue;
                }

                // Links are never followed: a symlink to /etc or ~ must not widen the walk.
                if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    continue;
                }

                if (info is DirectoryInfo)
                {
                    if (!ScriptInventory.IsExcludedDirectoryName(info.Name) && !info.Name.StartsWith('.'))
                    {
                        pending.Push(info.FullName);
                    }

                    continue;
                }

                if (!SourceExtensions.Contains(info.Extension) || info.Name.EndsWith(".d.ts", StringComparison.OrdinalIgnoreCase)
                    || info.Name.EndsWith(".min.js", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (filesScanned >= MaxFiles)
                {
                    truncated = true;
                    break;
                }

                var fileInfo = (FileInfo)info;
                if (fileInfo.Length == 0 || fileInfo.Length > MaxFileBytes || !IsInside(root, fileInfo.FullName))
                {
                    continue;
                }

                string content;
                try
                {
                    content = await File.ReadAllTextAsync(fileInfo.FullName, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    continue;
                }

                filesScanned++;
                var relative = Path.GetRelativePath(root, fileInfo.FullName).Replace('\\', '/');
                var isPython = fileInfo.Extension.Equals(".py", StringComparison.OrdinalIgnoreCase);

                if (!RegistersTools(content, isPython))
                {
                    continue;
                }

                toolFiles++;
                foreach (var sink in FindSinks(content, relative, isPython))
                {
                    if (sinks.Count >= MaxSinks)
                    {
                        truncated = true;
                        break;
                    }

                    sinks.Add(sink);
                }
            }
        }

        return new ServerSourceAnalysis
        {
            RootPath = root,
            DisplayName = new DirectoryInfo(root).Name is { Length: > 0 } leaf ? leaf : root,
            FilesScanned = filesScanned,
            ToolFiles = toolFiles,
            Truncated = truncated,
            Sinks = sinks
        };
    }

    /// <summary>True when the file contains an MCP tool registration for its language.</summary>
    internal static bool RegistersTools(string content, bool isPython) =>
        isPython
            ? InjectionPatterns.SafeIsMatch(PythonToolRegistration(), content)
            : InjectionPatterns.SafeIsMatch(JsToolRegistration(), content);

    /// <summary>Enumerates dangerous sinks in <paramref name="content"/> with 1-based line numbers.</summary>
    internal static IReadOnlyList<SourceSink> FindSinks(string content, string relativePath, bool isPython)
    {
        var sinks = new List<SourceSink>();
        var referencesChildProcess = !isPython && InjectionPatterns.SafeIsMatch(ChildProcessImport(), content);

        foreach (var family in isPython ? PythonSinks : JsSinks)
        {
            if (family.RequiresChildProcessImport && !referencesChildProcess)
            {
                continue;
            }

            foreach (var match in InjectionPatterns.SafeMatches(family.Pattern, content))
            {
                var (line, snippet) = Locate(content, match.Index);
                if (isPython ? IsPythonComment(snippet) : IsJsComment(snippet))
                {
                    continue;
                }

                sinks.Add(new SourceSink
                {
                    RelativePath = relativePath,
                    Line = line,
                    Kind = family.Kind,
                    Rationale = family.Rationale,
                    Severity = family.Severity,
                    Snippet = snippet
                });
            }
        }

        return sinks
            .OrderBy(s => s.Line)
            .ThenBy(s => s.Kind, StringComparer.Ordinal)
            .ToList();
    }

    private static (int Line, string Snippet) Locate(string content, int index)
    {
        var line = 1;
        var lineStart = 0;
        for (var i = 0; i < index && i < content.Length; i++)
        {
            if (content[i] == '\n')
            {
                line++;
                lineStart = i + 1;
            }
        }

        var lineEnd = content.IndexOf('\n', index);
        if (lineEnd < 0)
        {
            lineEnd = content.Length;
        }

        var snippet = content[lineStart..lineEnd].Trim().TrimEnd('\r');
        if (snippet.Length > MaxSnippetLength)
        {
            snippet = snippet[..(MaxSnippetLength - 3)] + "...";
        }

        return (line, StripControl(snippet));
    }

    private static string StripControl(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            builder.Append(char.IsControl(c) ? ' ' : c);
        }

        return builder.ToString();
    }

    private static bool IsPythonComment(string line) => line.StartsWith('#');

    private static bool IsJsComment(string line) =>
        line.StartsWith("//", StringComparison.Ordinal) || line.StartsWith('*') || line.StartsWith("/*", StringComparison.Ordinal);

    private static bool IsInside(string baseDir, string candidate)
    {
        var baseWithSep = baseDir.EndsWith(Path.DirectorySeparatorChar) ? baseDir : baseDir + Path.DirectorySeparatorChar;
        var comparison = RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
            ? StringComparison.Ordinal
            : StringComparison.OrdinalIgnoreCase;
        return candidate.StartsWith(baseWithSep, comparison);
    }

    private sealed record SinkFamily(string Kind, Regex Pattern, Severity Severity, string Rationale, bool RequiresChildProcessImport = false);

    private static readonly SinkFamily[] JsSinks =
    [
        new("child_process.exec", JsChildProcessExec(), Severity.High,
            "Shell command execution reachable from a tool handler; tool arguments become command-line text.", RequiresChildProcessImport: true),
        new("child_process.spawn(shell)", JsSpawnShell(), Severity.High,
            "spawn with shell:true is shell execution under another name.", RequiresChildProcessImport: true),
        new("eval", JsEval(), Severity.High,
            "Dynamic code evaluation in a process that receives model-controlled input."),
        new("new Function", JsNewFunction(), Severity.High,
            "Runtime function construction from strings is eval by another route."),
        new("vm.runIn*Context", JsVmRun(), Severity.High,
            "Node vm contexts are not a security boundary; code still runs with process privileges."),
        new("write under home", JsHomeWrite(), Severity.Medium,
            "The server writes beneath the user's home directory, where agent config, shell rc files and credentials live.")
    ];

    private static readonly SinkFamily[] PythonSinks =
    [
        new("subprocess shell=True", PySubprocessShell(), Severity.High,
            "subprocess with shell=True turns tool arguments into shell syntax."),
        new("os.system / os.popen", PyOsSystem(), Severity.High,
            "Direct shell execution reachable from a tool handler."),
        new("pickle.load", PyPickle(), Severity.High,
            "Unpickling untrusted bytes is arbitrary code execution."),
        new("eval / exec", PyEvalExec(), Severity.High,
            "Dynamic code evaluation in a process that receives model-controlled input."),
        new("yaml.load (unsafe loader)", PyYamlLoad(), Severity.Medium,
            "yaml.load without SafeLoader instantiates arbitrary Python objects."),
        new("write under home", PyHomeWrite(), Severity.Medium,
            "The server writes beneath the user's home directory, where agent config, shell rc files and credentials live.")
    ];

    // --- registrations -----------------------------------------------------------------

    [GeneratedRegex(
        @"(?:\.(?:tool|registerTool|addTool)\s*\(\s*[""'`]|ListToolsRequestSchema|CallToolRequestSchema|setRequestHandler\s*\(\s*(?:ListTools|CallTool)RequestSchema|['""]tools/(?:list|call)['""])",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex JsToolRegistration();

    [GeneratedRegex(
        @"(?:^|\n)\s*@[\w.]+\.(?:tool|list_tools|call_tool)\s*(?:\(|\r?\n)|FastMCP\s*\(|from\s+mcp(?:\.\w+)*\s+import|import\s+mcp\b",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PythonToolRegistration();

    // --- JS/TS sinks -------------------------------------------------------------------

    [GeneratedRegex(@"(?:require\s*\(\s*[""'](?:node:)?child_process[""']\s*\)|from\s+[""'](?:node:)?child_process[""'])",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex ChildProcessImport();

    [GeneratedRegex(@"\b(?:child_process\.|cp\.)?(?:exec|execSync|execFile|execFileSync)\s*\(",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex JsChildProcessExec();

    [GeneratedRegex(@"\bspawn(?:Sync)?\s*\([^)\n]{0,400}shell\s*:\s*true",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex JsSpawnShell();

    [GeneratedRegex(@"(?<![\w.$])eval\s*\(", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex JsEval();

    [GeneratedRegex(@"\bnew\s+Function\s*\(", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex JsNewFunction();

    [GeneratedRegex(@"\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex JsVmRun();

    [GeneratedRegex(
        @"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile|copyFileSync|rename|renameSync)\s*\([^)\n]{0,300}?(?:os\.homedir\s*\(\s*\)|process\.env\.(?:HOME|USERPROFILE)|[""'`]~/|\$HOME|%USERPROFILE%)",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex JsHomeWrite();

    // --- Python sinks ------------------------------------------------------------------

    [GeneratedRegex(@"\bsubprocess\.\w+\s*\([^)\n]{0,400}shell\s*=\s*True",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PySubprocessShell();

    [GeneratedRegex(@"\bos\.(?:system|popen|execv?p?e?|spawn\w*)\s*\(", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PyOsSystem();

    [GeneratedRegex(@"\b(?:pickle|cPickle|dill|shelve)\.loads?\s*\(|\bpickle\.Unpickler\s*\(",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PyPickle();

    [GeneratedRegex(@"(?<![\w.])(?:eval|exec)\s*\(", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PyEvalExec();

    [GeneratedRegex(@"\byaml\.load\s*\((?![^)\n]*(?:SafeLoader|safe_load|Loader\s*=\s*yaml\.SafeLoader))",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PyYamlLoad();

    // The middle segment may cross ')' because the home marker is usually a nested call
    // (expanduser('~'), Path.home()) whose closing paren precedes the mode argument.
    [GeneratedRegex(
        @"\b(?:open|Path)\s*\([^)\n]{0,300}?(?:expanduser\s*\(\s*[""']~|Path\.home\s*\(\s*\)|environ(?:\.get)?\s*[\[(]\s*[""'](?:HOME|USERPROFILE)[""']|[""']~/)[^\n]{0,200}?(?:[""'][wax]\+?[""']|mode\s*=\s*[""'][wax]|write_text|write_bytes|\.open\s*\(\s*[""'][wax])",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PyHomeWrite();
}
