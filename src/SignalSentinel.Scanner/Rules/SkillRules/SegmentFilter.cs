// -----------------------------------------------------------------------
// <copyright file="SegmentFilter.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.SkillParser;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// v3.0.0 (WP10): shared helper that hands each skill rule only the document segments
/// it declared via <see cref="IRule.ApplicableSegments"/>. When a
/// <see cref="SkillDefinition"/> carries no pre-computed <see cref="SkillDefinition.Segments"/>
/// (hand-constructed definitions, e.g. in tests), the document is segmented on demand
/// so both paths behave identically.
/// </summary>
public static class SegmentFilter
{
    /// <summary>
    /// Segments of the skill document whose kind intersects <paramref name="kinds"/>.
    /// </summary>
    public static IReadOnlyList<DocumentSegment> SegmentsFor(SkillDefinition skill, SegmentKind kinds)
    {
        ArgumentNullException.ThrowIfNull(skill);

        var segments = skill.Segments.Count > 0
            ? skill.Segments
            : DocumentSegmenter.Segment(skill.RawContent);

        var matched = new List<DocumentSegment>();
        foreach (var segment in segments)
        {
            if ((segment.Kind & kinds) != 0)
            {
                matched.Add(segment);
            }
        }

        return matched;
    }

    /// <summary>
    /// The concatenated text of the matching segments, one segment per line group.
    /// This is the drop-in replacement for scanning <c>skill.InstructionsBody</c>.
    /// </summary>
    public static string TextFor(SkillDefinition skill, SegmentKind kinds)
    {
        var sb = new StringBuilder();
        foreach (var segment in SegmentsFor(skill, kinds))
        {
            sb.Append(segment.Content);
            if (segment.Content.Length == 0 || segment.Content[^1] != '\n')
            {
                sb.Append('\n');
            }
        }

        return sb.ToString();
    }
}
