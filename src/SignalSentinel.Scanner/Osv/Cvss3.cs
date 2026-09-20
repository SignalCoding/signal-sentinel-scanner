// -----------------------------------------------------------------------
// <copyright file="Cvss3.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Osv;

/// <summary>
/// v3.0.0 (WP6): minimal CVSS 3.0/3.1 base-score calculator. OSV reports severity as a
/// vector string ("CVSS:3.1/AV:N/..."), so the scanner computes the base score itself
/// rather than trusting a pre-banded label. Only the eight base metrics are read;
/// anything missing or malformed yields no score.
/// </summary>
public static class Cvss3
{
    /// <summary>Computes the base score (0.0–10.0), or null when the vector is unusable.</summary>
    public static double? BaseScore(string? vector)
    {
        if (string.IsNullOrWhiteSpace(vector))
        {
            return null;
        }

        var metrics = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in vector.Split('/'))
        {
            var colon = part.IndexOf(':');
            if (colon > 0)
            {
                metrics[part[..colon]] = part[(colon + 1)..];
            }
        }

        if (!metrics.TryGetValue("AV", out var av) || !metrics.TryGetValue("AC", out var ac)
            || !metrics.TryGetValue("PR", out var pr) || !metrics.TryGetValue("UI", out var ui)
            || !metrics.TryGetValue("S", out var scope) || !metrics.TryGetValue("C", out var conf)
            || !metrics.TryGetValue("I", out var integ) || !metrics.TryGetValue("A", out var avail))
        {
            return null;
        }

        var scopeChanged = scope == "C";
        if (scope is not ("U" or "C"))
        {
            return null;
        }

        double? prValue = pr switch
        {
            "N" => 0.85,
            "L" => scopeChanged ? 0.68 : 0.62,
            "H" => scopeChanged ? 0.50 : 0.27,
            _ => null
        };

        double? avValue = av switch { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => null };
        double? acValue = ac switch { "L" => 0.77, "H" => 0.44, _ => null };
        double? uiValue = ui switch { "N" => 0.85, "R" => 0.62, _ => null };
        double? cValue = conf switch { "H" => 0.56, "L" => 0.22, "N" => 0.0, _ => null };
        double? iValue = integ switch { "H" => 0.56, "L" => 0.22, "N" => 0.0, _ => null };
        double? aValue = avail switch { "H" => 0.56, "L" => 0.22, "N" => 0.0, _ => null };

        if (prValue is null || avValue is null || acValue is null || uiValue is null
            || cValue is null || iValue is null || aValue is null)
        {
            return null;
        }

        var iscBase = 1 - ((1 - cValue.Value) * (1 - iValue.Value) * (1 - aValue.Value));
        var impact = scopeChanged
            ? (7.52 * (iscBase - 0.029)) - (3.25 * Math.Pow(iscBase - 0.02, 15))
            : 6.42 * iscBase;
        var exploitability = 8.22 * avValue.Value * acValue.Value * prValue.Value * uiValue.Value;

        if (impact <= 0)
        {
            return 0.0;
        }

        var raw = scopeChanged
            ? Math.Min(1.08 * (impact + exploitability), 10)
            : Math.Min(impact + exploitability, 10);
        return RoundUp(raw);
    }

    /// <summary>Maps a base score to the scanner severity bands.</summary>
    public static Severity ToSeverity(double score) => score switch
    {
        >= 9.0 => Severity.Critical,
        >= 7.0 => Severity.High,
        >= 4.0 => Severity.Medium,
        > 0.0 => Severity.Low,
        _ => Severity.Info
    };

    // CVSS "roundup": the smallest number with one decimal that is >= the input.
    private static double RoundUp(double value) => Math.Ceiling(value * 10.0 - 1e-7) / 10.0;
}
