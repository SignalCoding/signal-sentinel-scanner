// -----------------------------------------------------------------------
// <copyright file="DataFileInventory.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Runtime.InteropServices;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.SkillParser;

/// <summary>
/// ast04-metadata-integrity: inventories shipped metadata sidecar files (<c>.yaml</c>,
/// <c>.yml</c>, <c>.json</c>, <c>.toml</c>) within a skill package directory, read as
/// <b>data</b> rather than as executable content - a parallel surface to
/// <see cref="ScriptInventory"/>, kept separate so nothing starts treating these
/// extensions as scripts for other rules. Security hardened with the same file size
/// limits and safe path validation as <see cref="ScriptInventory"/>.
/// </summary>
public static class DataFileInventory
{
    private const long MaxDataFileSize = 1 * 1024 * 1024; // 1 MB, mirrors ScriptInventory
    private const int MaxDataFilesPerPackage = 100;

    private static readonly string[] DataExtensions = [".yaml", ".yml", ".json", ".toml"];

    /// <summary>
    /// Discovers and loads shipped metadata sidecar files from a skill package directory.
    /// </summary>
    public static async Task<IReadOnlyList<BundledDataFile>> DiscoverAsync(
        string skillDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(skillDirectory);

        if (!Directory.Exists(skillDirectory))
        {
            return [];
        }

        var dataFiles = new List<BundledDataFile>();
        var baseDir = Path.GetFullPath(skillDirectory);

        foreach (var ext in DataExtensions)
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
                if (dataFiles.Count >= MaxDataFilesPerPackage)
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

                var relativePath = Path.GetRelativePath(baseDir, fullPath);
                if (IsExcludedPath(relativePath))
                {
                    continue;
                }

                var fileInfo = new FileInfo(fullPath);
                if (!fileInfo.Exists || fileInfo.Length > MaxDataFileSize)
                {
                    dataFiles.Add(new BundledDataFile
                    {
                        RelativePath = relativePath,
                        FullPath = fullPath,
                        Extension = ext,
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

                dataFiles.Add(new BundledDataFile
                {
                    RelativePath = relativePath,
                    FullPath = fullPath,
                    Extension = ext,
                    Content = content,
                    FileSize = fileInfo.Length
                });
            }
        }

        return dataFiles;
    }

    private static bool IsExcludedPath(string relativePath)
    {
        var parts = relativePath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        foreach (var part in parts)
        {
            if (ScriptInventory.IsExcludedDirectoryName(part))
            {
                return true;
            }
        }
        return false;
    }
}
