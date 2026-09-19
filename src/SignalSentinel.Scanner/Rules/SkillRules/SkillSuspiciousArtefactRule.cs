// -----------------------------------------------------------------------
// <copyright file="SkillSuspiciousArtefactRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-035: Flags files inside a skill package whose content does not match their
/// name, or whose presence has no legitimate place in a Markdown-plus-scripts skill.
/// Maps to OWASP ASI04 (Supply Chain Vulnerabilities).
/// </summary>
/// <remarks>
/// Works over <see cref="SkillDefinition.Artefacts"/> produced by
/// <c>FileForensics</c>. Checks, in order of severity:
/// <list type="bullet">
/// <item>Magic bytes say executable/archive but the extension says text (High).</item>
/// <item>Native executable anywhere in the package (High).</item>
/// <item>Double extension ending in an executable type, e.g. <c>README.md.exe</c> (High).</item>
/// <item>Archive present (Medium): opaque content the scanner cannot read.</item>
/// <item>Orphan <c>.pyc</c> with no sibling <c>.py</c> (Medium): compiled code with no source.</item>
/// <item>Hidden files outside a small allowlist (Low).</item>
/// </list>
/// </remarks>
public sealed class SkillSuspiciousArtefactRule : IRule
{
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".xml", ".csv", ".ini", ".cfg", ".conf",
        ".py", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".js", ".mjs", ".ts", ".mts", ".rb", ".pl",
        ".php", ".lua", ".bat", ".cmd", ".vbs", ".html", ".htm", ".css", ".svg", ".rst", ".env", ".lock"
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".com", ".scr", ".msi", ".so", ".dylib", ".bin", ".app", ".pif"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".jar", ".whl", ".egg", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar"
    };

    private static readonly HashSet<string> HiddenAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        ".gitignore", ".gitattributes", ".editorconfig", ".sentinel-sig", ".sigstore", ".env.example",
        ".prettierrc", ".eslintrc", ".eslintrc.json", ".npmrc", ".nvmrc", ".python-version", ".tool-versions",
        ".markdownlint.json", ".markdownlintrc", ".yamllint", ".dockerignore", ".keep", ".gitkeep"
    };

    private static readonly HashSet<string> HiddenAllowlistDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        ".github", ".vscode", ".claude", ".cursor", ".codex", ".factory", ".agent-skills", ".agents"
    };

    /// <inheritdoc />
    public string Id => RuleConstants.Rules.SkillSuspiciousArtefact;

    /// <inheritdoc />
    public string Name => "Skill Suspicious File Artefact";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI04;

    /// <inheritdoc />
    public string Description =>
        "Flags binaries, archives, orphan bytecode, hidden files, and files whose magic bytes contradict their extension inside a skill package.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST01, OwaspAstCodes.AST06];

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (skill.Artefacts.Count == 0)
            {
                continue;
            }

            var pythonSources = new HashSet<string>(
                skill.Artefacts.Where(a => a.Extension == ".py").Select(a => StripExtension(a.RelativePath)),
                StringComparer.OrdinalIgnoreCase);

            foreach (var artefact in skill.Artefacts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var finding = Evaluate(skill, artefact, pythonSources);
                if (finding is not null)
                {
                    findings.Add(finding);
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private Finding? Evaluate(SkillDefinition skill, FileArtefact artefact, HashSet<string> pythonSources)
    {
        var name = Path.GetFileName(artefact.RelativePath);
        var isBinaryKind = IsNativeExecutable(artefact.Kind);
        var isArchiveKind = IsArchive(artefact.Kind);

        // 1. Content contradicts the extension.
        if ((isBinaryKind || isArchiveKind || artefact.Kind is FileArtefactKind.JavaClass or FileArtefactKind.PythonBytecode)
            && TextExtensions.Contains(artefact.Extension))
        {
            return Create(skill, artefact, Severity.High,
                "File Content Contradicts Extension",
                $"'{artefact.RelativePath}' has a text extension but its leading bytes identify it as {Describe(artefact.Kind)}. Renaming a payload to look like documentation is a common evasion.",
                "Remove the file. If it is a legitimate binary, ship it with its true extension and document why the skill needs it.",
                0.95);
        }

        // 2. Double extension ending in an executable type.
        if (HasExecutableDoubleExtension(name))
        {
            return Create(skill, artefact, Severity.High,
                "Executable Hidden Behind Double Extension",
                $"'{artefact.RelativePath}' uses a double extension that ends in an executable type. File browsers that hide known extensions will display it as a harmless document.",
                "Remove the file. Skills should not carry executables.",
                0.95);
        }

        // 3. Native executable anywhere.
        if (isBinaryKind || ExecutableExtensions.Contains(artefact.Extension))
        {
            return Create(skill, artefact, Severity.High,
                "Executable Binary In Skill Package",
                $"'{artefact.RelativePath}' is {Describe(artefact.Kind)}. A skill is Markdown plus optionally readable scripts; a compiled binary cannot be reviewed and runs with the agent's privileges.",
                "Remove the binary. If a native dependency is genuinely required, have the skill install it from a pinned, verifiable package source instead of bundling it.",
                0.9);
        }

        // 4. Archive present.
        if (isArchiveKind || ArchiveExtensions.Contains(artefact.Extension))
        {
            return Create(skill, artefact, Severity.Medium,
                "Archive In Skill Package",
                $"'{artefact.RelativePath}' is {Describe(artefact.Kind)}. Archived content is opaque to this scanner and to any reviewer reading the skill.",
                "Unpack the archive into plain files so its contents can be reviewed, or remove it.",
                0.85);
        }

        // 5. Orphan bytecode.
        if (artefact.Kind == FileArtefactKind.PythonBytecode || artefact.Extension == ".pyc")
        {
            var stem = StripExtension(artefact.RelativePath);
            // CPython writes pkg/__pycache__/module.cpython-312.pyc for pkg/module.py;
            // strip both the version tag and the cache directory.
            var tagIndex = stem.IndexOf(".cpython-", StringComparison.OrdinalIgnoreCase);
            if (tagIndex > 0)
            {
                stem = stem[..tagIndex];
            }

            var cacheSegment = "__pycache__" + Path.DirectorySeparatorChar;
            var cacheIndex = stem.LastIndexOf(cacheSegment, StringComparison.OrdinalIgnoreCase);
            if (cacheIndex >= 0)
            {
                stem = stem.Remove(cacheIndex, cacheSegment.Length);
            }

            if (!pythonSources.Contains(stem))
            {
                return Create(skill, artefact, Severity.Medium,
                    "Compiled Python Without Source",
                    $"'{artefact.RelativePath}' is Python bytecode with no matching .py file in the package. Bytecode executes like source but cannot be read.",
                    "Ship the .py source and let the interpreter compile it. Remove orphan .pyc files.",
                    0.85);
            }
            return null;
        }

        if (artefact.Kind == FileArtefactKind.JavaClass)
        {
            return Create(skill, artefact, Severity.Medium,
                "Compiled Java Class In Skill Package",
                $"'{artefact.RelativePath}' is a compiled Java class. Bytecode cannot be reviewed as part of the skill.",
                "Remove compiled classes; ship source or reference a published, pinned artefact.",
                0.85);
        }

        // 6. Hidden files outside the allowlist.
        if (artefact.IsHidden && !IsAllowlistedHidden(artefact.RelativePath, name))
        {
            return Create(skill, artefact, Severity.Low,
                "Hidden File In Skill Package",
                $"'{artefact.RelativePath}' is hidden. Hidden files are skipped by casual review and by many listing tools.",
                "Remove the file or rename it so it is visible. Only standard tool configuration files (.gitignore, .editorconfig, etc.) belong hidden.",
                0.7);
        }

        return null;
    }

    private static bool IsAllowlistedHidden(string relativePath, string name)
    {
        if (HiddenAllowlist.Contains(name))
        {
            return true;
        }

        // A visible file inside an allowlisted hidden directory (.github/workflows/x.yml)
        // is fine; the directory is the convention, not the file.
        var parts = relativePath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (parts.Length > 1 && HiddenAllowlistDirectories.Contains(parts[0]) && !name.StartsWith('.'))
        {
            return true;
        }

        return false;
    }

    private static bool HasExecutableDoubleExtension(string fileName)
    {
        var first = fileName.IndexOf('.', StringComparison.Ordinal);
        var last = fileName.LastIndexOf('.');
        if (first <= 0 || first == last)
        {
            return false;
        }

        var lastExt = fileName[last..];
        if (!ExecutableExtensions.Contains(lastExt) && lastExt is not (".bat" or ".cmd" or ".vbs" or ".ps1" or ".js" or ".wsf" or ".hta"))
        {
            return false;
        }

        // The penultimate segment must itself look like a document/data extension.
        var inner = fileName[first..last];
        var innerLast = inner.LastIndexOf('.');
        var innerExt = innerLast >= 0 ? inner[innerLast..] : inner;
        return TextExtensions.Contains(innerExt) || innerExt is ".pdf" or ".doc" or ".docx" or ".png" or ".jpg" or ".jpeg";
    }

    private static bool IsNativeExecutable(FileArtefactKind kind) =>
        kind is FileArtefactKind.PortableExecutable or FileArtefactKind.Elf or FileArtefactKind.MachO;

    private static bool IsArchive(FileArtefactKind kind) =>
        kind is FileArtefactKind.Zip or FileArtefactKind.Gzip or FileArtefactKind.Bzip2
            or FileArtefactKind.Xz or FileArtefactKind.SevenZip or FileArtefactKind.Rar;

    private static string Describe(FileArtefactKind kind) => kind switch
    {
        FileArtefactKind.PortableExecutable => "a Windows PE executable",
        FileArtefactKind.Elf => "a Linux ELF binary",
        FileArtefactKind.MachO => "a macOS Mach-O binary",
        FileArtefactKind.Zip => "a ZIP archive",
        FileArtefactKind.Gzip => "a gzip stream",
        FileArtefactKind.Bzip2 => "a bzip2 stream",
        FileArtefactKind.Xz => "an xz stream",
        FileArtefactKind.SevenZip => "a 7-Zip archive",
        FileArtefactKind.Rar => "a RAR archive",
        FileArtefactKind.JavaClass => "a compiled Java class",
        FileArtefactKind.PythonBytecode => "CPython bytecode",
        FileArtefactKind.Shebang => "a script with a shebang",
        _ => "an unrecognised binary"
    };

    private static string StripExtension(string relativePath)
    {
        var ext = Path.GetExtension(relativePath);
        return ext.Length > 0 ? relativePath[..^ext.Length] : relativePath;
    }

    private Finding Create(SkillDefinition skill, FileArtefact artefact, Severity severity, string title, string description, string remediation, double confidence)
    {
        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = severity,
            Title = $"{title}: {skill.Name}",
            Description = description,
            Remediation = remediation,
            ServerName = skill.Name,
            Evidence = DescriptionScan.Truncate($"{artefact.RelativePath} [{artefact.Kind}, {artefact.Size} bytes]"),
            Confidence = confidence,
            Source = FindingSource.Skill,
            SkillFilePath = skill.FilePath
        };
    }
}
