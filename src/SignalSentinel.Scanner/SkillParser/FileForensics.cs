// -----------------------------------------------------------------------
// <copyright file="FileForensics.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Runtime.InteropServices;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.SkillParser;

/// <summary>
/// Walks a skill package and classifies every file by its leading bytes so rules can
/// reason about what a file <em>is</em> rather than what its name says. Bounded in file
/// count and total bytes, skips the same directories as <see cref="ScriptInventory"/>,
/// and refuses to follow symlinks that leave the package.
/// </summary>
public static class FileForensics
{
    /// <summary>Maximum number of files classified per package.</summary>
    public const int MaxFiles = 500;

    /// <summary>Maximum total bytes on disk across classified files.</summary>
    public const long MaxTotalBytes = 50L * 1024 * 1024;

    private const int HeaderLength = 16;

    private static readonly HashSet<string> WindowsExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".com", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".pif"
    };

    /// <summary>
    /// Classifies every file under <paramref name="skillDirectory"/>.
    /// </summary>
    public static async Task<IReadOnlyList<FileArtefact>> AnalyseAsync(
        string skillDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(skillDirectory);

        if (!Directory.Exists(skillDirectory))
        {
            return [];
        }

        var baseDir = Path.GetFullPath(skillDirectory);
        var artefacts = new List<FileArtefact>();
        long totalBytes = 0;

        var pending = new Stack<string>();
        pending.Push(baseDir);

        while (pending.Count > 0 && artefacts.Count < MaxFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var dir = pending.Pop();

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
                if (artefacts.Count >= MaxFiles)
                {
                    break;
                }

                FileSystemInfo info;
                try
                {
                    info = Directory.Exists(entry) ? new DirectoryInfo(entry) : new FileInfo(entry);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    continue;
                }

                // Symlinks: never follow directory links, and only accept file links that
                // resolve inside the package.
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    if (info is DirectoryInfo)
                    {
                        continue;
                    }

                    string? target;
                    try
                    {
                        target = info.ResolveLinkTarget(returnFinalTarget: true)?.FullName;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        continue;
                    }

                    if (target is null || !IsInside(baseDir, target))
                    {
                        continue;
                    }
                }

                if (info is DirectoryInfo)
                {
                    if (!ScriptInventory.IsExcludedDirectoryName(info.Name))
                    {
                        pending.Push(info.FullName);
                    }
                    continue;
                }

                var file = (FileInfo)info;
                var relative = Path.GetRelativePath(baseDir, file.FullName);
                if (relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    .Any(ScriptInventory.IsExcludedDirectoryName))
                {
                    continue;
                }

                long size;
                try
                {
                    size = file.Length;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    continue;
                }

                if (totalBytes + size > MaxTotalBytes)
                {
                    // Record it with an unknown kind so the count is honest, but stop
                    // reading bytes once the budget is spent.
                    artefacts.Add(Describe(file, relative, FileArtefactKind.Unknown, size));
                    continue;
                }

                totalBytes += size;
                var kind = await ClassifyAsync(file.FullName, cancellationToken);
                artefacts.Add(Describe(file, relative, kind, size));
            }
        }

        return artefacts;
    }

    /// <summary>
    /// Classifies a file by its first bytes. Returns <see cref="FileArtefactKind.Unknown"/>
    /// for anything unrecognised or unreadable.
    /// </summary>
    public static async Task<FileArtefactKind> ClassifyAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);

        var header = new byte[HeaderLength];
        int read;
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: HeaderLength, useAsync: true);
            read = await stream.ReadAtLeastAsync(header, HeaderLength, throwOnEndOfStream: false, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return FileArtefactKind.Unknown;
        }

        return Classify(header.AsSpan(0, read));
    }

    /// <summary>
    /// Pure magic-byte classifier over the first bytes of a file.
    /// </summary>
    public static FileArtefactKind Classify(ReadOnlySpan<byte> header)
    {
        if (header.Length < 2)
        {
            return FileArtefactKind.Unknown;
        }

        if (header[0] == (byte)'#' && header[1] == (byte)'!')
        {
            return FileArtefactKind.Shebang;
        }

        if (header[0] == (byte)'M' && header[1] == (byte)'Z')
        {
            return FileArtefactKind.PortableExecutable;
        }

        if (header.Length >= 4)
        {
            if (header[0] == 0x7F && header[1] == (byte)'E' && header[2] == (byte)'L' && header[3] == (byte)'F')
            {
                return FileArtefactKind.Elf;
            }

            // Mach-O thin (FE ED FA CE / CF and byte-swapped) and fat (CA FE BA BE).
            if ((header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA && (header[3] == 0xCE || header[3] == 0xCF)) ||
                ((header[0] == 0xCE || header[0] == 0xCF) && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE))
            {
                return FileArtefactKind.MachO;
            }

            if (header[0] == 0xCA && header[1] == 0xFE && header[2] == 0xBA && header[3] == 0xBE)
            {
                // Shares the fat Mach-O magic. Java class files carry a minor/major version
                // next; fat Mach-O carries a small architecture count. Treat a big-endian
                // count <= 0x40 as Mach-O, anything else as a class file.
                if (header.Length >= 8)
                {
                    var next = (header[4] << 24) | (header[5] << 16) | (header[6] << 8) | header[7];
                    return next is > 0 and <= 0x40 ? FileArtefactKind.MachO : FileArtefactKind.JavaClass;
                }
                return FileArtefactKind.JavaClass;
            }

            if (header[0] == (byte)'P' && header[1] == (byte)'K' &&
                ((header[2] == 0x03 && header[3] == 0x04) || (header[2] == 0x05 && header[3] == 0x06) || (header[2] == 0x07 && header[3] == 0x08)))
            {
                return FileArtefactKind.Zip;
            }

            if (header[0] == (byte)'R' && header[1] == (byte)'a' && header[2] == (byte)'r' && header[3] == (byte)'!')
            {
                return FileArtefactKind.Rar;
            }

            // CPython 3.x pyc: 2-byte version-specific magic, then 0x0D 0x0A.
            if (header[2] == 0x0D && header[3] == 0x0A && header[1] == 0x0D)
            {
                return FileArtefactKind.PythonBytecode;
            }
        }

        if (header[0] == 0x1F && header[1] == 0x8B)
        {
            return FileArtefactKind.Gzip;
        }

        if (header.Length >= 3 && header[0] == (byte)'B' && header[1] == (byte)'Z' && header[2] == (byte)'h')
        {
            return FileArtefactKind.Bzip2;
        }

        if (header.Length >= 6 &&
            header[0] == 0xFD && header[1] == (byte)'7' && header[2] == (byte)'z' &&
            header[3] == (byte)'X' && header[4] == (byte)'Z' && header[5] == 0x00)
        {
            return FileArtefactKind.Xz;
        }

        if (header.Length >= 6 &&
            header[0] == (byte)'7' && header[1] == (byte)'z' && header[2] == 0xBC &&
            header[3] == 0xAF && header[4] == 0x27 && header[5] == 0x1C)
        {
            return FileArtefactKind.SevenZip;
        }

        return FileArtefactKind.Unknown;
    }

    private static FileArtefact Describe(FileInfo file, string relative, FileArtefactKind kind, long size)
    {
        var extension = file.Extension.ToLowerInvariant();
        var hidden = file.Name.StartsWith('.') || (file.Attributes & FileAttributes.Hidden) != 0;

        bool executable;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            executable = WindowsExecutableExtensions.Contains(extension);
        }
        else
        {
            try
            {
                var mode = File.GetUnixFileMode(file.FullName);
                executable = (mode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
            {
                executable = false;
            }
        }

        return new FileArtefact
        {
            RelativePath = relative,
            Extension = extension,
            Kind = kind,
            Size = size,
            IsHidden = hidden,
            IsExecutable = executable
        };
    }

    private static bool IsInside(string baseDir, string candidate)
    {
        var baseWithSep = baseDir.EndsWith(Path.DirectorySeparatorChar) ? baseDir : baseDir + Path.DirectorySeparatorChar;
        var comparison = RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
            ? StringComparison.Ordinal
            : StringComparison.OrdinalIgnoreCase;
        return candidate.StartsWith(baseWithSep, comparison) || string.Equals(candidate, baseDir, comparison);
    }
}
