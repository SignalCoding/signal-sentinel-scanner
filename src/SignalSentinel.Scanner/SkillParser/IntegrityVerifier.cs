// -----------------------------------------------------------------------
// <copyright file="IntegrityVerifier.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Security.Cryptography;
using System.Text;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.SkillParser;

/// <summary>
/// Computes and verifies integrity artefacts for Agent Skills (SS-024).
/// Looks for sibling signature files (<c>.sentinel-sig</c>, <c>SHA256SUMS</c>, <c>.sigstore</c>)
/// and computes a content hash of the SKILL.md + bundled scripts.
/// </summary>
public static class IntegrityVerifier
{
    /// <summary>
    /// Names of files that, if present alongside SKILL.md, indicate the skill has
    /// been published with integrity metadata.
    /// </summary>
    private static readonly string[] SignatureFileNames =
    [
        ".sentinel-sig",
        "SHA256SUMS",
        "SHA256SUMS.txt",
        "sha256sums.txt",
        "checksums.sha256",
        ".sigstore",
        "cosign.sig",
        "SKILL.sig",
        "skill.oms.sig"
    ];

    /// <summary>
    /// Checksum manifests whose lines are <c>&lt;hex&gt;  &lt;path&gt;</c> (sha256sum format).
    /// </summary>
    private static readonly string[] ChecksumManifestNames = ["SHA256SUMS", "SHA256SUMS.txt", "sha256sums.txt", "checksums.sha256"];

    private const int MaxChecksumLines = 1_000;
    private const long MaxManifestSize = 1L * 1024 * 1024;
    private const long MaxHashedFileSize = 50L * 1024 * 1024;

    /// <summary>
    /// Aggregate cap on bytes hashed per manifest so a hostile manifest cannot turn
    /// the scanner into a disk-reading loop.
    /// </summary>
    private const long MaxTotalHashedBytes = 200L * 1024 * 1024;

    /// <summary>
    /// v2.4.1 (G12d): frontmatter keys from the OWASP Agentic Skills Top 10
    /// "Universal Skill Format" proposal that indicate the skill carries its own
    /// inline integrity metadata rather than (or in addition to) a sibling file.
    /// </summary>
    private static readonly HashSet<string> InlineIntegrityFrontmatterKeys =
        new(StringComparer.OrdinalIgnoreCase) { "signature", "content_hash", "content-hash" };

    /// <summary>
    /// Verifies a skill's integrity artefacts.
    /// </summary>
    /// <param name="skill">Skill definition.</param>
    /// <param name="verifyChecksums">
    /// When true (default) and a checksum manifest is present, every listed file is
    /// hashed and compared. Pass false when only presence detection is needed, to
    /// avoid hashing the package twice in one scan.
    /// </param>
    /// <returns>Integrity report for the skill.</returns>
    public static IntegrityReport Verify(SkillDefinition skill, bool verifyChecksums = true)
    {
        ArgumentNullException.ThrowIfNull(skill);

        var directory = Path.GetDirectoryName(skill.FilePath);
        var signaturePresent = false;
        string? signatureFileName = null;

        var checksumResults = new List<ChecksumResult>();

        if (!string.IsNullOrEmpty(directory) && Directory.Exists(directory))
        {
            foreach (var candidate in SignatureFileNames)
            {
                var candidatePath = Path.Combine(directory, candidate);
                if (File.Exists(candidatePath))
                {
                    signaturePresent = true;
                    signatureFileName = candidate;
                    break;
                }
            }

            // OpenClaw / OMS-style detached signatures: <anything>.oms.sig
            if (!signaturePresent)
            {
                var omsSig = TryFindOmsSignature(directory);
                if (omsSig is not null)
                {
                    signaturePresent = true;
                    signatureFileName = omsSig;
                }
            }

            if (verifyChecksums)
            {
                foreach (var manifestName in ChecksumManifestNames)
                {
                    var manifestPath = Path.Combine(directory, manifestName);
                    if (File.Exists(manifestPath))
                    {
                        checksumResults.AddRange(VerifyChecksumManifest(directory, manifestPath));
                        break;
                    }
                }
            }
        }

        // v2.4.1 (G12d): recognise the OWASP Agentic Skills Top 10 "Universal Skill
        // Format" inline integrity fields (frontmatter signature: / content_hash:)
        // as an alternative to a sibling signature file. Either form demonstrates
        // the publisher made integrity verification possible.
        if (!signaturePresent)
        {
            foreach (var kvp in skill.ExtraFrontmatter)
            {
                if (!string.IsNullOrWhiteSpace(kvp.Value) &&
                    InlineIntegrityFrontmatterKeys.Contains(kvp.Key))
                {
                    signaturePresent = true;
                    signatureFileName = $"frontmatter:{kvp.Key}";
                    break;
                }
            }
        }

        var contentHash = ComputeContentHash(skill);

        return new IntegrityReport
        {
            SkillName = skill.Name,
            SkillFilePath = skill.FilePath,
            SignaturePresent = signaturePresent,
            SignatureFileName = signatureFileName,
            ContentHash = contentHash,
            ChecksumResults = checksumResults
        };
    }

    private static string? TryFindOmsSignature(string directory)
    {
        try
        {
            return Directory.EnumerateFiles(directory, "*.oms.sig", SearchOption.TopDirectoryOnly)
                .Select(Path.GetFileName)
                .FirstOrDefault(n => n is not null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses a sha256sum-format manifest and verifies every listed file against the
    /// bytes on disk. Lines that are blank, comments, or malformed are skipped; paths
    /// that escape the skill directory are reported as <see cref="ChecksumStatus.Invalid"/>.
    /// </summary>
    internal static IReadOnlyList<ChecksumResult> VerifyChecksumManifest(string directory, string manifestPath)
    {
        List<string> lines;
        try
        {
            var manifestInfo = new FileInfo(manifestPath);
            if ((manifestInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                // A symlinked manifest reports the link's size, not the target's, so the
                // size cap below could be bypassed. Manifests must be real files.
                return [];
            }

            if (manifestInfo.Length > MaxManifestSize)
            {
                return [];
            }

            lines = File.ReadLines(manifestPath).Take(MaxChecksumLines).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }

        var results = new List<ChecksumResult>();
        var baseDir = Path.GetFullPath(directory);
        var hashCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        long hashedBytes = 0;

        foreach (var raw in lines)
        {
            var parsed = ParseChecksumLine(raw);
            if (parsed is null)
            {
                continue;
            }

            var (expectedHex, relativePath) = parsed.Value;

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(Path.Combine(baseDir, relativePath));
            }
            catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException)
            {
                results.Add(Invalid(relativePath, expectedHex));
                continue;
            }

            if (!IsInside(baseDir, fullPath))
            {
                results.Add(Invalid(relativePath, expectedHex));
                continue;
            }

            if (!File.Exists(fullPath))
            {
                results.Add(new ChecksumResult { RelativePath = relativePath, Expected = expectedHex, Status = ChecksumStatus.Missing });
                continue;
            }

            string actualHex;
            try
            {
                var info = new FileInfo(fullPath);

                // A manifest entry that is a symlink must resolve inside the package too;
                // otherwise the manifest becomes a hash oracle for arbitrary host files.
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    var target = info.ResolveLinkTarget(returnFinalTarget: true)?.FullName;
                    if (target is null || !IsInside(baseDir, target))
                    {
                        results.Add(Invalid(relativePath, expectedHex));
                        continue;
                    }
                    fullPath = target;
                    info = new FileInfo(fullPath);
                }

                if (!hashCache.TryGetValue(fullPath, out var cached))
                {
                    if (info.Length > MaxHashedFileSize || hashedBytes + info.Length > MaxTotalHashedBytes)
                    {
                        results.Add(Invalid(relativePath, expectedHex));
                        continue;
                    }

                    hashedBytes += info.Length;
                    using var stream = File.OpenRead(fullPath);
                    cached = Convert.ToHexStringLower(SHA256.HashData(stream));
                    hashCache[fullPath] = cached;
                }

                actualHex = cached;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                results.Add(Invalid(relativePath, expectedHex));
                continue;
            }

            results.Add(new ChecksumResult
            {
                RelativePath = relativePath,
                Expected = expectedHex,
                Actual = actualHex,
                Status = string.Equals(actualHex, expectedHex, StringComparison.OrdinalIgnoreCase)
                    ? ChecksumStatus.Match
                    : ChecksumStatus.Mismatch
            });
        }

        return results;
    }

    private static ChecksumResult Invalid(string relativePath, string expectedHex) =>
        new() { RelativePath = relativePath, Expected = expectedHex, Status = ChecksumStatus.Invalid };

    /// <summary>
    /// Parses one sha256sum line: 64 hex chars, whitespace, optional binary marker
    /// (<c>*</c>), then the path. Returns null for anything else.
    /// </summary>
    internal static (string Hex, string Path)? ParseChecksumLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        var trimmed = line.Trim();
        if (trimmed.StartsWith('#'))
        {
            return null;
        }

        // GNU sha256sum prefixes a line with '\' when the filename needed escaping.
        if (trimmed.StartsWith('\\'))
        {
            trimmed = trimmed[1..];
        }

        // Some tools emit "SHA256 (file) = hex" (BSD style). Support it too.
        if (trimmed.StartsWith("SHA256 (", StringComparison.OrdinalIgnoreCase))
        {
            var close = trimmed.IndexOf(") = ", StringComparison.Ordinal);
            if (close > 8)
            {
                var bsdPath = NormalisePath(trimmed[8..close]);
                var bsdHex = trimmed[(close + 4)..].Trim();
                return IsSha256Hex(bsdHex) && bsdPath.Length > 0 ? (bsdHex.ToLowerInvariant(), bsdPath) : null;
            }
            return null;
        }

        var split = trimmed.IndexOfAny([' ', '\t']);
        if (split != 64)
        {
            return null;
        }

        var hex = trimmed[..64];
        if (!IsSha256Hex(hex))
        {
            return null;
        }

        var rest = trimmed[64..].TrimStart();
        if (rest.StartsWith('*'))
        {
            rest = rest[1..];
        }

        rest = NormalisePath(rest);
        if (rest.Length == 0)
        {
            return null;
        }

        return (hex.ToLowerInvariant(), rest);
    }

    /// <summary>
    /// Manifests written on Unix use '/'; normalise to the local separator and drop a
    /// leading <c>./</c>.
    /// </summary>
    private static string NormalisePath(string path)
    {
        var p = path.Trim().Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
        if (p.StartsWith("." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            p = p[2..];
        }

        return p;
    }

    private static bool IsSha256Hex(string s)
    {
        if (s.Length != 64)
        {
            return false;
        }

        foreach (var c in s)
        {
            if (!Uri.IsHexDigit(c))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsInside(string baseDir, string candidate)
    {
        var baseWithSep = baseDir.EndsWith(Path.DirectorySeparatorChar) ? baseDir : baseDir + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        return candidate.StartsWith(baseWithSep, comparison);
    }

    private static string ComputeContentHash(SkillDefinition skill)
    {
        using var buffer = new MemoryStream();

        var skillBytes = Encoding.UTF8.GetBytes(skill.RawContent);
        buffer.Write(skillBytes, 0, skillBytes.Length);

        foreach (var script in skill.Scripts.OrderBy(s => s.RelativePath, StringComparer.Ordinal))
        {
            var header = Encoding.UTF8.GetBytes($"\n---{script.RelativePath}---\n");
            buffer.Write(header, 0, header.Length);

            if (!string.IsNullOrEmpty(script.Content))
            {
                var scriptBytes = Encoding.UTF8.GetBytes(script.Content);
                buffer.Write(scriptBytes, 0, scriptBytes.Length);
            }
        }

        var hash = SHA256.HashData(buffer.ToArray());

        var hex = new StringBuilder(hash.Length * 2);
        foreach (var b in hash)
        {
#pragma warning disable CA1305 // FormatProvider not required for "x2" (invariant hex formatting)
            hex.Append(b.ToString("x2"));
#pragma warning restore CA1305
        }
        return $"sha256:{hex}";
    }
}

/// <summary>
/// Integrity verification result for a single skill.
/// </summary>
public sealed record IntegrityReport
{
    /// <summary>
    /// Skill name.
    /// </summary>
    public required string SkillName { get; init; }

    /// <summary>
    /// Path to the SKILL.md file.
    /// </summary>
    public required string SkillFilePath { get; init; }

    /// <summary>
    /// True if a sibling signature file was detected.
    /// </summary>
    public required bool SignaturePresent { get; init; }

    /// <summary>
    /// Name of the signature file found (if any).
    /// </summary>
    public string? SignatureFileName { get; init; }

    /// <summary>
    /// SHA-256 hash of skill content (SKILL.md + bundled scripts).
    /// </summary>
    public required string ContentHash { get; init; }

    /// <summary>
    /// Per-file verification results when a checksum manifest was present. Empty
    /// when no manifest exists.
    /// </summary>
    public IReadOnlyList<ChecksumResult> ChecksumResults { get; init; } = [];
}

/// <summary>
/// Outcome of checking one manifest entry against the file on disk.
/// </summary>
public enum ChecksumStatus
{
    /// <summary>Hash matches.</summary>
    Match,

    /// <summary>File exists but its hash differs from the manifest.</summary>
    Mismatch,

    /// <summary>Manifest lists the file but it is not present.</summary>
    Missing,

    /// <summary>Entry could not be verified (path escapes the package, unreadable, oversized).</summary>
    Invalid
}

/// <summary>
/// One line of a checksum manifest, verified.
/// </summary>
public sealed record ChecksumResult
{
    /// <summary>Path exactly as written in the manifest, separator-normalised.</summary>
    public required string RelativePath { get; init; }

    /// <summary>Expected lower-case hex digest from the manifest.</summary>
    public required string Expected { get; init; }

    /// <summary>Computed lower-case hex digest, when the file could be read.</summary>
    public string? Actual { get; init; }

    /// <summary>Verification outcome.</summary>
    public required ChecksumStatus Status { get; init; }
}
