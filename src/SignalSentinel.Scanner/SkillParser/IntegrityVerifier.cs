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
        ".sigstore",
        "cosign.sig",
        "SKILL.sig"
    ];

    /// <summary>
    /// Verifies a skill's integrity artefacts.
    /// </summary>
    /// <param name="skill">Skill definition.</param>
    /// <returns>Integrity report for the skill.</returns>
    public static IntegrityReport Verify(SkillDefinition skill)
    {
        ArgumentNullException.ThrowIfNull(skill);

        var directory = Path.GetDirectoryName(skill.FilePath);
        var signaturePresent = false;
        string? signatureFileName = null;

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
        }

        var contentHash = ComputeContentHash(skill);

        return new IntegrityReport
        {
            SkillName = skill.Name,
            SkillFilePath = skill.FilePath,
            SignaturePresent = signaturePresent,
            SignatureFileName = signatureFileName,
            ContentHash = contentHash
        };
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
}
