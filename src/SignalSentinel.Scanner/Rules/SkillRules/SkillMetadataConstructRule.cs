// -----------------------------------------------------------------------
// <copyright file="SkillMetadataConstructRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-043: Dangerous Construct in Shipped Skill Metadata (ast04-metadata-integrity, spec
/// section 6/C1). Scans shipped <c>.yaml</c>/<c>.yml</c>/<c>.json</c>/<c>.toml</c> metadata
/// sidecar files (<see cref="SkillDefinition.DataFiles"/>, populated by
/// <see cref="SkillParser.DataFileInventory"/>) for three construct families that share one
/// theme - the shipped metadata is not what it appears to be:
/// <list type="bullet">
/// <item>code execution: YAML tags such as <c>!!python/object/apply</c>, <c>!!python/name</c>,
/// <c>!!python/module</c>.</item>
/// <item>prototype pollution: <c>__proto__</c>, <c>constructor</c>, <c>prototype</c> used as
/// keys in shipped JSON or YAML.</item>
/// <item>parser ambiguity: duplicate keys (YAML/JSON) or duplicate tables (TOML).</item>
/// </list>
/// Severity is High when a consuming operation also ships in a bundled script - an unsafe
/// deserialisation loader (<c>yaml.load</c> without <c>SafeLoader</c>, <c>yaml.unsafe_load</c>,
/// <c>pickle.load</c>/<c>loads</c>, <c>marshal.loads</c>) for the code-execution family, or a
/// recursive object merge for the prototype-pollution family - and Medium otherwise. An unsafe
/// loader alone, with no data-file construct, is also a genuine weakness (spec A2) and fires at
/// Medium on its own.
/// </summary>
public sealed partial class SkillMetadataConstructRule : IRule
{
    private const int MaxWalkDepth = 50;

    private static readonly string[] CodeExecutionTagFragments =
    [
        "python/object/apply", "python/name", "python/module"
    ];

    private static readonly HashSet<string> PollutionKeys =
        new(StringComparer.Ordinal) { "__proto__", "constructor", "prototype" };

    public string Id => RuleConstants.Rules.SkillMetadataConstruct;
    public string Name => "Dangerous Construct in Shipped Skill Metadata";
    public string OwaspCode => OwaspAsiCodes.ASI01;
    public string Description =>
        "Detects code-executing YAML tags, prototype-pollution keys, and duplicate-key/table " +
        "parser ambiguity in shipped skill metadata data files, escalating to High when a " +
        "bundled script consumes the construct unsafely.";
    public bool EnabledByDefault => true;
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST04];

    [GeneratedRegex(
        @"^\s*\[\s*([A-Za-z0-9_.-]+)\s*\]\s*(?:#.*)?$",
        RegexOptions.Multiline | RegexOptions.Compiled,
        matchTimeoutMilliseconds: RuleConstants.Limits.RegexTimeoutMs)]
    private static partial Regex TomlTableHeader();

    [GeneratedRegex(
        @"\byaml\s*\.\s*unsafe_load\s*\(",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: RuleConstants.Limits.RegexTimeoutMs)]
    private static partial Regex YamlUnsafeLoad();

    [GeneratedRegex(
        @"\byaml\s*\.\s*load\s*\(([^)]*)\)",
        RegexOptions.Compiled | RegexOptions.Singleline,
        matchTimeoutMilliseconds: RuleConstants.Limits.RegexTimeoutMs)]
    private static partial Regex YamlLoad();

    [GeneratedRegex(
        @"\bpickle\s*\.\s*loads?\s*\(",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: RuleConstants.Limits.RegexTimeoutMs)]
    private static partial Regex PickleLoad();

    [GeneratedRegex(
        @"\bmarshal\s*\.\s*loads\s*\(",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: RuleConstants.Limits.RegexTimeoutMs)]
    private static partial Regex MarshalLoads();

    [GeneratedRegex(
        @"function\s+(\w*[Mm]erge\w*)\s*\(",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: RuleConstants.Limits.RegexTimeoutMs)]
    private static partial Regex MergeFunctionName();

    [GeneratedRegex(
        @"for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+\w+\s*\)",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: RuleConstants.Limits.RegexTimeoutMs)]
    private static partial Regex ForInLoop();

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var constructs = new List<MetadataConstruct>();
            foreach (var dataFile in skill.DataFiles)
            {
                cancellationToken.ThrowIfCancellationRequested();
                constructs.AddRange(AnalyseDataFile(dataFile));
            }

            var hasUnsafeLoader = skill.Scripts.Any(s => HasUnsafeLoader(s.Content));
            var hasRecursiveMerge = skill.Scripts.Any(s => HasRecursiveMerge(s.Content));

            foreach (var construct in constructs)
            {
                var consumerPresent = construct.Family switch
                {
                    ConstructFamily.CodeExecution => hasUnsafeLoader,
                    ConstructFamily.PrototypePollution => hasRecursiveMerge,
                    _ => false
                };

                findings.Add(BuildFinding(skill, construct, consumerPresent));
            }

            // v3.1.0 (A2): an unsafe deserialisation loader is a genuine weakness on its
            // own. Only surface it standalone when no code-execution construct already
            // produced a (higher-signal) finding for the same pairing.
            if (hasUnsafeLoader && constructs.All(c => c.Family != ConstructFamily.CodeExecution))
            {
                findings.Add(BuildUnsafeLoaderAloneFinding(skill));
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private Finding BuildFinding(SkillDefinition skill, MetadataConstruct construct, bool consumerPresent)
    {
        var severity = consumerPresent ? Severity.High : Severity.Medium;

        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = severity,
            Title = $"Dangerous Construct in Shipped Skill Metadata: {construct.Summary}",
            Description = $"Skill '{skill.Name}' ships '{construct.RelativePath}' containing {construct.Summary}." +
                (consumerPresent
                    ? $" A bundled script also {construct.ConsumerVerb}, so the construct is reachable."
                    : " No bundled script was found consuming it, but shipped metadata should never carry this construct."),
            Remediation = construct.Remediation,
            ServerName = skill.Name,
            Evidence = TruncateEvidence($"{construct.RelativePath}: {construct.Evidence}"),
            Confidence = consumerPresent ? 0.9 : 0.75,
            Source = FindingSource.Skill,
            SkillFilePath = skill.FilePath
        };
    }

    private Finding BuildUnsafeLoaderAloneFinding(SkillDefinition skill)
    {
        var script = skill.Scripts.First(s => HasUnsafeLoader(s.Content));
        var evidence = MatchUnsafeLoader(script.Content!)?.Value ?? "(unsafe loader)";

        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = Severity.Medium,
            Title = "Dangerous Construct in Shipped Skill Metadata: Unsafe Deserialisation Loader",
            Description = $"Skill '{skill.Name}' bundles '{script.RelativePath}', which deserialises " +
                "content with an unsafe loader (yaml.load without SafeLoader, yaml.unsafe_load, " +
                "pickle.load/loads, or marshal.loads). This is a genuine weakness independent of " +
                "whether a malicious payload currently ships alongside it.",
            Remediation = "Use a safe deserialiser: yaml.safe_load (or yaml.load with Loader=yaml.SafeLoader), " +
                "json.load, or avoid pickle/marshal for untrusted data entirely.",
            ServerName = skill.Name,
            Evidence = TruncateEvidence($"{script.RelativePath}: {evidence}"),
            Confidence = 0.8,
            Source = FindingSource.Skill,
            SkillFilePath = skill.FilePath
        };
    }

    private static List<MetadataConstruct> AnalyseDataFile(BundledDataFile dataFile)
    {
        if (string.IsNullOrEmpty(dataFile.Content))
        {
            return [];
        }

        return dataFile.Extension switch
        {
            ".yaml" or ".yml" => AnalyseYaml(dataFile),
            ".json" => AnalyseJson(dataFile),
            ".toml" => AnalyseToml(dataFile),
            _ => []
        };
    }

    // ---- YAML: code-execution tags, prototype-pollution keys, duplicate keys ----------

    private static List<MetadataConstruct> AnalyseYaml(BundledDataFile dataFile)
    {
        var found = new List<MetadataConstruct>();
        var stream = new YamlStream();
        try
        {
            stream.Load(new StringReader(dataFile.Content!));
        }
        catch (YamlException ex)
        {
            if (ex.Message.StartsWith("Duplicate key", StringComparison.Ordinal))
            {
                found.Add(MetadataConstruct.ParserAmbiguity(
                    dataFile.RelativePath,
                    $"duplicate key ({ex.Message})"));
            }

            // Any other YAML parse failure is a malformed file, not our concern here.
            return found;
        }

        foreach (var document in stream.Documents)
        {
            WalkYamlNode(document.RootNode, dataFile.RelativePath, found, 0);
        }

        return found;
    }

    private static void WalkYamlNode(
        YamlNode node, string relativePath, List<MetadataConstruct> found, int depth)
    {
        if (depth > MaxWalkDepth)
        {
            return;
        }

        var tag = node.Tag.IsEmpty ? null : node.Tag.Value;
        if (tag is not null)
        {
            foreach (var fragment in CodeExecutionTagFragments)
            {
                if (tag.Contains(fragment, StringComparison.Ordinal))
                {
                    found.Add(MetadataConstruct.CodeExecution(relativePath, $"YAML tag '{tag}'"));
                    break;
                }
            }
        }

        switch (node)
        {
            case YamlMappingNode mapping:
                foreach (var (key, value) in mapping.Children)
                {
                    if (key is YamlScalarNode { Value: { } keyText } && PollutionKeys.Contains(keyText))
                    {
                        found.Add(MetadataConstruct.PrototypePollution(relativePath, $"key '{keyText}'"));
                    }

                    WalkYamlNode(key, relativePath, found, depth + 1);
                    WalkYamlNode(value, relativePath, found, depth + 1);
                }

                break;

            case YamlSequenceNode sequence:
                foreach (var child in sequence.Children)
                {
                    WalkYamlNode(child, relativePath, found, depth + 1);
                }

                break;
        }
    }

    // ---- JSON: prototype-pollution keys, duplicate keys --------------------------------

    private static List<MetadataConstruct> AnalyseJson(BundledDataFile dataFile)
    {
        var found = new List<MetadataConstruct>();
        try
        {
            using var document = JsonDocument.Parse(dataFile.Content!);
            WalkJsonElement(document.RootElement, dataFile.RelativePath, found, 0);
        }
        catch (JsonException)
        {
            // Malformed JSON is not our concern here.
        }

        return found;
    }

    private static void WalkJsonElement(
        JsonElement element, string relativePath, List<MetadataConstruct> found, int depth)
    {
        if (depth > MaxWalkDepth)
        {
            return;
        }

        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var seenKeys = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                {
                    if (!seenKeys.Add(property.Name))
                    {
                        found.Add(MetadataConstruct.ParserAmbiguity(
                            relativePath, $"duplicate key '{property.Name}'"));
                    }

                    if (PollutionKeys.Contains(property.Name))
                    {
                        found.Add(MetadataConstruct.PrototypePollution(
                            relativePath, $"key '{property.Name}'"));
                    }

                    WalkJsonElement(property.Value, relativePath, found, depth + 1);
                }

                break;

            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    WalkJsonElement(item, relativePath, found, depth + 1);
                }

                break;
        }
    }

    // ---- TOML: duplicate tables (no TOML parser dependency; a bounded header scan is the
    // practical option - see impl report) ------------------------------------------------

    private static List<MetadataConstruct> AnalyseToml(BundledDataFile dataFile)
    {
        var found = new List<MetadataConstruct>();
        var seenTables = new HashSet<string>(StringComparer.Ordinal);
        MatchCollection matches;
        try
        {
            matches = TomlTableHeader().Matches(dataFile.Content!);
        }
        catch (RegexMatchTimeoutException)
        {
            return found;
        }

        foreach (Match match in matches)
        {
            var table = match.Groups[1].Value;
            if (!seenTables.Add(table))
            {
                found.Add(MetadataConstruct.ParserAmbiguity(
                    dataFile.RelativePath, $"duplicate table [{table}]"));
            }
        }

        return found;
    }

    // ---- Bundled-script consumer detection ----------------------------------------------

    private static bool HasUnsafeLoader(string? scriptContent) =>
        MatchUnsafeLoader(scriptContent) is not null;

    private static Match? MatchUnsafeLoader(string? scriptContent)
    {
        if (string.IsNullOrEmpty(scriptContent))
        {
            return null;
        }

        try
        {
            var unsafeLoad = YamlUnsafeLoad().Match(scriptContent);
            if (unsafeLoad.Success)
            {
                return unsafeLoad;
            }

            foreach (Match load in YamlLoad().Matches(scriptContent))
            {
                if (!load.Groups[1].Value.Contains("SafeLoader", StringComparison.Ordinal))
                {
                    return load;
                }
            }

            var pickle = PickleLoad().Match(scriptContent);
            if (pickle.Success)
            {
                return pickle;
            }

            var marshal = MarshalLoads().Match(scriptContent);
            if (marshal.Success)
            {
                return marshal;
            }
        }
        catch (RegexMatchTimeoutException)
        {
            return null;
        }

        return null;
    }

    private static bool HasRecursiveMerge(string? scriptContent)
    {
        if (string.IsNullOrEmpty(scriptContent))
        {
            return false;
        }

        try
        {
            var mergeMatch = MergeFunctionName().Match(scriptContent);
            if (!mergeMatch.Success)
            {
                return false;
            }

            if (!ForInLoop().IsMatch(scriptContent))
            {
                return false;
            }

            var functionName = mergeMatch.Groups[1].Value;

            // Definition plus at least one self-call: a plain, bounded substring count
            // (the function name is a literal, not a pattern - no regex needed here).
            return CountOccurrences(scriptContent, functionName) >= 2;
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var index = 0;
        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }

        return count;
    }

    private static string TruncateEvidence(string evidence) =>
        evidence.Length <= RuleConstants.Limits.MaxEvidenceLength
            ? evidence
            : evidence[..(RuleConstants.Limits.MaxEvidenceLength - 3)] + "...";

    private enum ConstructFamily
    {
        CodeExecution,
        PrototypePollution,
        ParserAmbiguity
    }

    private sealed record MetadataConstruct(
        ConstructFamily Family,
        string RelativePath,
        string Summary,
        string Evidence,
        string Remediation,
        string ConsumerVerb)
    {
        public static MetadataConstruct CodeExecution(string relativePath, string evidence) => new(
            ConstructFamily.CodeExecution,
            relativePath,
            "a code-executing YAML tag",
            evidence,
            "Remove the code-executing tag from shipped metadata; if custom construction is " +
            "genuinely required, use an explicit, reviewed constructor allow-list rather than " +
            "PyYAML's default loader.",
            "deserialises it with an unsafe loader");

        public static MetadataConstruct PrototypePollution(string relativePath, string evidence) => new(
            ConstructFamily.PrototypePollution,
            relativePath,
            "a prototype-pollution key (__proto__/constructor/prototype)",
            evidence,
            "Remove the reserved key from shipped metadata, and if the consumer merges objects, " +
            "use a merge that rejects or ignores __proto__/constructor/prototype keys " +
            "(e.g. Object.create(null) targets, or a allow-listed key set).",
            "recursively merges it into a shared object");

        public static MetadataConstruct ParserAmbiguity(string relativePath, string evidence) => new(
            ConstructFamily.ParserAmbiguity,
            relativePath,
            "duplicate-key/table parser ambiguity",
            evidence,
            "Remove the duplicate key/table so every parser resolves the file identically; a " +
            "validator and a loader disagreeing on which value wins is itself the vulnerability.",
            string.Empty);
    }
}
