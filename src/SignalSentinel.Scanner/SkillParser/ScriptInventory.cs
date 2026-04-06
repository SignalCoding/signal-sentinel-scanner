// -----------------------------------------------------------------------
// <copyright file="ScriptInventory.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Runtime.InteropServices;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.SkillParser;

/// <summary>
/// Inventories bundled scripts (.py, .sh, .ps1, .js, .ts) within a skill package directory.
/// Security hardened with file size limits and safe path validation.
/// </summary>
public static class ScriptInventory
{
    private const long MaxScriptFileSize = 1 * 1024 * 1024; // 1 MB
    private const int MaxScriptsPerPackage = 100;

    private static readonly Dictionary<string, ScriptLanguage> ExtensionMap = new(StringComparer.OrdinalIgnoreCase)
    {
        [".py"] = ScriptLanguage.Python,
        [".sh"] = ScriptLanguage.Bash,
        [".bash"] = ScriptLanguage.Bash,
        [".ps1"] = ScriptLanguage.PowerShell,
        [".psm1"] = ScriptLanguage.PowerShell,
        [".js"] = ScriptLanguage.JavaScript,
        [".mjs"] = ScriptLanguage.JavaScript,
        [".ts"] = ScriptLanguage.TypeScript,
        [".mts"] = ScriptLanguage.TypeScript,
    };

    /// <summary>
    /// Discovers and loads bundled scripts from a skill package directory.
    /// </summary>
    public static async Task<IReadOnlyList<BundledScript>> DiscoverAsync(
        string skillDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(skillDirectory);

        if (!Directory.Exists(skillDirectory))
        {
            return [];
        }

        var scripts = new List<BundledScript>();
        var baseDir = Path.GetFullPath(skillDirectory);

        foreach (var ext in ExtensionMap.Keys)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string[] files;
            try
            {
                files = Directory.GetFiles(baseDir, $"*{ext}", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }
            catch (IOException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (scripts.Count >= MaxScriptsPerPackage)
                {
                    break;
                }

                var fullPath = Path.GetFullPath(file);

                // Security: Resolve symlinks before containment check to prevent escape
                var resolvedPath = fullPath;
                try
                {
                    if ((File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
                    {
                        resolvedPath = File.ResolveLinkTarget(fullPath, returnFinalTarget: true)?.FullName ?? fullPath;
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    continue;
                }

                // Security: Ensure file is within the skill directory (no symlink escape)
                var baseDirWithSep = baseDir.EndsWith(Path.DirectorySeparatorChar)
                    ? baseDir
                    : baseDir + Path.DirectorySeparatorChar;
                var comparison = RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
                    ? StringComparison.Ordinal
                    : StringComparison.OrdinalIgnoreCase;
                if (!resolvedPath.StartsWith(baseDirWithSep, comparison) &&
                    !string.Equals(resolvedPath, baseDir, comparison))
                {
                    continue;
                }

                // Skip node_modules, __pycache__, .git
                var relativePath = Path.GetRelativePath(baseDir, fullPath);
                if (IsExcludedPath(relativePath))
                {
                    continue;
                }

                var fileInfo = new FileInfo(fullPath);
                if (!fileInfo.Exists || fileInfo.Length > MaxScriptFileSize)
                {
                    scripts.Add(new BundledScript
                    {
                        RelativePath = relativePath,
                        FullPath = fullPath,
                        Language = ExtensionMap[ext],
                        Content = null,
                        FileSize = fileInfo.Exists ? fileInfo.Length : 0
                    });
                    continue;
                }

                string? content = null;
                try
                {
                    content = await File.ReadAllTextAsync(fullPath, cancellationToken);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Security: Silently skip unreadable files
                }

                scripts.Add(new BundledScript
                {
                    RelativePath = relativePath,
                    FullPath = fullPath,
                    Language = ExtensionMap[ext],
                    Content = content,
                    FileSize = fileInfo.Length
                });
            }
        }

        return scripts;
    }

    private static bool IsExcludedPath(string relativePath)
    {
        var parts = relativePath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        foreach (var part in parts)
        {
            if (part is "node_modules" or "__pycache__" or ".git" or ".venv" or "venv" or "dist" or "build")
            {
                return true;
            }
        }
        return false;
    }
}
