// -----------------------------------------------------------------------
// <copyright file="DescriptionScan.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// Shared helper for rules that apply <see cref="InjectionPatterns.AllPatterns"/> to a
/// free-text metadata field (tool/prompt/resource descriptions, server instructions).
/// </summary>
internal static class DescriptionScan
{
    /// <summary>
    /// Returns every injection pattern that matches <paramref name="text"/>, with the
    /// first matched span truncated to the evidence limit.
    /// </summary>
    internal static IEnumerable<(InjectionPattern Pattern, string Evidence)> Matches(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            yield break;
        }

        foreach (var pattern in InjectionPatterns.AllPatterns)
        {
            if (!InjectionPatterns.SafeIsMatch(pattern.Pattern, text))
            {
                continue;
            }

            var match = InjectionPatterns.SafeMatches(pattern.Pattern, text).FirstOrDefault();
            yield return (pattern, Truncate(match?.Value ?? "(matched)"));
        }
    }

    internal static string Truncate(string evidence)
    {
        if (evidence.Length <= RuleConstants.Limits.MaxEvidenceLength)
        {
            return evidence;
        }

        return evidence[..(RuleConstants.Limits.MaxEvidenceLength - 3)] + "...";
    }
}
