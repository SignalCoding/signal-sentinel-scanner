// -----------------------------------------------------------------------
// <copyright file="RegexEngineIntegrityTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// v3.0.1 round 2 (T2, T3): .NET regex engine integrity guards.
//
// The v3.0.1 corpus re-scan produced an SS-011 High "Cross-Tool Manipulation"
// on a skill whose evidence (419 characters beginning ", mention that these can
// be used to pull in context directly.") cannot be produced by the
// CrossToolManipulation() pattern at all. Reproduced outside the scanner on SDK
// 10.0.401: for the same input and the same pattern string, the interpreted and
// NonBacktracking engines report NO match while RegexOptions.Compiled and the
// [GeneratedRegex] source-generated engine return a bogus match. Bisection
// pinned the trigger to the lazy bounded loop over a group - "(?:\w+\s+){0,2}?"
// and friends; the explicit optional-group form and the greedy "{0,2}" agree
// across engines.
//
// T2 bans the construct outright in shipped patterns. T3 cross-checks every
// shipped pattern against the interpreted engine over the real-world corpus, so
// any future divergence (this class of bug is not specific to one construct)
// fails the build rather than quietly poisoning a scan report.

using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Shouldly;
using SignalSentinel.Core.Security;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SharedPatterns;

public class RegexEngineIntegrityTests
{
    /// <summary>Maximum input length, matching InjectionPatterns.SafeMatches.</summary>
    private const int MaxInputLength = 100_000;

    /// <summary>Maximum matches compared per pattern, matching SafeMatches.</summary>
    private const int MaxMatches = 100;

    /// <summary>
    /// A lazy bounded loop over a group - <c>){n,m}?</c>. Miscompiled by the
    /// compiled/source-generated engines on .NET SDK 10.0.401.
    /// </summary>
    private static readonly Regex LazyBoundedGroupLoop =
        new(@"\)\{\d+,\d+\}\?", RegexOptions.None, TimeSpan.FromSeconds(5));

    // ---- T2: pattern hygiene -------------------------------------------------

    [Fact]
    public void NoShippedPattern_UsesALazyBoundedGroupLoop()
    {
        var offenders = new List<string>();

        foreach (var (id, regex) in AllShippedRegexes())
        {
            var source = regex.ToString();
            foreach (Match match in LazyBoundedGroupLoop.Matches(source))
            {
                offenders.Add(string.Create(CultureInfo.InvariantCulture,
                    $"{id}: '{match.Value}' at offset {match.Index} of the pattern"));
            }
        }

        offenders.ShouldBeEmpty(
            "Lazy bounded loops over a group are miscompiled by the compiled and " +
            "source-generated regex engines (SDK 10.0.401). Rewrite them as explicit " +
            "optional groups, e.g. (?:\\w+\\s+)?(?:\\w+\\s+)?. Offenders:" +
            Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    [Fact]
    public void PatternInventory_IsNotEmpty()
    {
        // Guards the reflection walk itself: a namespace rename must not silently
        // turn the hygiene and engine-consistency guards into no-ops.
        var inventory = AllShippedRegexes();

        inventory.Count.ShouldBeGreaterThan(25);
        inventory.ShouldContain(p => p.Id == "INJECTION-004");
        inventory.ShouldContain(p => p.Id.StartsWith("SkillHiddenContentRule.", StringComparison.Ordinal));
    }

    // ---- T3: engine consistency over the real-world corpus -------------------

    [Fact]
    public void ShippedPatterns_AgreeWithTheInterpretedEngine_OverTheCorpus()
    {
        var corpusFiles = CorpusFiles();
        corpusFiles.ShouldNotBeEmpty("No corpus files found under " + RealWorldSkillFixtures.Dir);

        var comparisons = 0;
        var mismatches = new List<string>();

        foreach (var (id, shipped) in CorePatterns())
        {
            var reference = new Regex(
                shipped.ToString(),
                shipped.Options & ~RegexOptions.Compiled,
                TimeSpan.FromSeconds(5));

            foreach (var (path, text) in corpusFiles)
            {
                var shippedMatches = MatchSet(shipped, text);
                var referenceMatches = MatchSet(reference, text);

                if (shippedMatches is null || referenceMatches is null)
                {
                    continue; // a timeout on either engine is not a correctness signal
                }

                comparisons++;

                if (!shippedMatches.SequenceEqual(referenceMatches, StringComparer.Ordinal))
                {
                    mismatches.Add(string.Create(CultureInfo.InvariantCulture,
                        $"{id} on {path}:{Environment.NewLine}" +
                        $"    shipped   : [{string.Join(", ", shippedMatches)}]{Environment.NewLine}" +
                        $"    interpreted: [{string.Join(", ", referenceMatches)}]"));
                }
            }
        }

        comparisons.ShouldBeGreaterThan(100, "too few comparisons ran to be meaningful");
        mismatches.ShouldBeEmpty(
            "The shipped regex engine disagrees with the interpreted engine. A shipped " +
            "pattern that matches text the reference engine rejects produces fabricated " +
            "findings. Mismatches:" + Environment.NewLine +
            string.Join(Environment.NewLine, mismatches));
    }

    // ---- helpers -------------------------------------------------------------

    /// <summary>The three shared pattern catalogues, with their finding ids.</summary>
    private static List<(string Id, Regex Regex)> CorePatterns()
    {
        var patterns = new List<(string Id, Regex Regex)>();

        foreach (var pattern in InjectionPatterns.AllPatterns)
        {
            patterns.Add((pattern.Id, pattern.Pattern));
        }

        foreach (var (id, _, pattern, _, _) in ExfiltrationPatterns.AllPatterns)
        {
            patterns.Add((id, pattern));
        }

        foreach (var (id, _, pattern, _, _) in ObfuscationPatterns.AllPatterns)
        {
            patterns.Add((id, pattern));
        }

        return patterns;
    }

    /// <summary>
    /// Every catalogued pattern plus every parameterless static Regex accessor
    /// (including the private [GeneratedRegex] partials) declared under
    /// SignalSentinel.Core.Security and SignalSentinel.Scanner.Rules.
    /// </summary>
    private static List<(string Id, Regex Regex)> AllShippedRegexes()
    {
        var patterns = CorePatterns();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        Assembly[] assemblies =
        [
            typeof(InjectionPatterns).Assembly,
            typeof(SkillInjectionRule).Assembly
        ];

        foreach (var assembly in assemblies)
        {
            foreach (var type in assembly.GetTypes())
            {
                if (type.Namespace is not { } ns)
                {
                    continue;
                }

                if (!ns.StartsWith("SignalSentinel.Core.Security", StringComparison.Ordinal)
                    && !ns.StartsWith("SignalSentinel.Scanner.Rules", StringComparison.Ordinal))
                {
                    continue;
                }

                const BindingFlags flags =
                    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.DeclaredOnly;

                foreach (var method in type.GetMethods(flags))
                {
                    if (method.ReturnType != typeof(Regex)
                        || method.GetParameters().Length != 0
                        || method.IsGenericMethodDefinition)
                    {
                        continue;
                    }

                    var id = type.Name + "." + method.Name;
                    if (!seen.Add(id))
                    {
                        continue;
                    }

                    if (method.Invoke(null, null) is Regex regex)
                    {
                        patterns.Add((id, regex));
                    }
                }
            }
        }

        return patterns;
    }

    /// <summary>Every markdown and script file in the real-world corpus, read as-is.</summary>
    private static List<(string Path, string Text)> CorpusFiles()
    {
        var files = new List<(string Path, string Text)>();
        var root = RealWorldSkillFixtures.Dir;

        if (!Directory.Exists(root))
        {
            return files;
        }

        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            var extension = Path.GetExtension(file);
            if (extension is not (".md" or ".py" or ".js"))
            {
                continue;
            }

            var text = File.ReadAllText(file);
            if (text.Length > MaxInputLength)
            {
                text = text[..MaxInputLength];
            }

            files.Add((Path.GetRelativePath(root, file), text));
        }

        return files;
    }

    /// <summary>
    /// The index:length list of the first <see cref="MaxMatches"/> matches, or null
    /// if the engine timed out (not a correctness signal).
    /// </summary>
    private static List<string>? MatchSet(Regex regex, string input)
    {
        var matches = new List<string>();
        var builder = new StringBuilder();

        try
        {
            foreach (Match match in regex.Matches(input))
            {
                builder.Clear();
                builder.Append(CultureInfo.InvariantCulture, $"{match.Index}:{match.Length}");
                matches.Add(builder.ToString());

                if (matches.Count >= MaxMatches)
                {
                    break;
                }
            }
        }
        catch (RegexMatchTimeoutException)
        {
            return null;
        }

        return matches;
    }
}
