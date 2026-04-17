// -----------------------------------------------------------------------
// <copyright file="LevenshteinDistance.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Core.Security;

/// <summary>
/// Levenshtein edit distance utility used by SS-023 Shadow Tool Injection detection.
/// Uses two-row dynamic programming so memory is O(min(|a|,|b|)).
/// </summary>
public static class LevenshteinDistance
{
    /// <summary>
    /// Computes the Levenshtein edit distance between two strings.
    /// Returns 0 for identical strings; case-sensitive comparison.
    /// </summary>
    /// <param name="a">First string.</param>
    /// <param name="b">Second string.</param>
    /// <returns>Edit distance.</returns>
    public static int Compute(string a, string b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        if (a == b)
        {
            return 0;
        }
        if (a.Length == 0)
        {
            return b.Length;
        }
        if (b.Length == 0)
        {
            return a.Length;
        }

        // Ensure a is the shorter string for memory efficiency
        if (a.Length > b.Length)
        {
            (a, b) = (b, a);
        }

        var previous = new int[a.Length + 1];
        var current = new int[a.Length + 1];

        for (var i = 0; i <= a.Length; i++)
        {
            previous[i] = i;
        }

        for (var j = 1; j <= b.Length; j++)
        {
            current[0] = j;
            for (var i = 1; i <= a.Length; i++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                current[i] = Math.Min(
                    Math.Min(current[i - 1] + 1, previous[i] + 1),
                    previous[i - 1] + cost);
            }

            (previous, current) = (current, previous);
        }

        return previous[a.Length];
    }
}
