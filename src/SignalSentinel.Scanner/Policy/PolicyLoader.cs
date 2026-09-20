// -----------------------------------------------------------------------
// <copyright file="PolicyLoader.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Reflection;
using System.Text.Json;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Policy;

/// <summary>
/// v3.0.0 (WP7): resolves a <c>--policy</c> argument — the <c>default</c>,
/// <c>strict</c>, or <c>defence</c> embedded preset, or a path to a JSON file of the
/// same shape — into a <see cref="ResolvedPolicy"/>.
/// </summary>
public static class PolicyLoader
{
    private static readonly string[] PresetNames = ["default", "strict", "defence"];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    /// <summary>
    /// Resolves <paramref name="policyArg"/> to a policy. On failure returns false and
    /// sets <paramref name="error"/> to an operator-facing message.
    /// </summary>
    public static bool TryResolve(string policyArg, out ResolvedPolicy? policy, out string? error)
    {
        policy = null;
        error = null;

        if (string.IsNullOrWhiteSpace(policyArg))
        {
            error = "--policy expects a preset name (default, strict, defence) or a path to a JSON file.";
            return false;
        }

        var arg = policyArg.Trim();
        if (PresetNames.Contains(arg, StringComparer.OrdinalIgnoreCase))
        {
            if (arg.Equals("default", StringComparison.OrdinalIgnoreCase))
            {
                policy = ResolvedPolicy.Default;
                return true;
            }

            var json = ReadPreset(arg.ToLowerInvariant(), out error);
            if (json is null)
            {
                return false;
            }

            return TryParse(json, arg.ToLowerInvariant(), out policy, out error);
        }

        if (!File.Exists(arg))
        {
            error = LooksLikePath(arg)
                ? $"Policy file not found: {arg}"
                : $"Unknown policy preset '{arg}'. Presets: {string.Join(", ", PresetNames)}; or pass a path to a JSON file.";
            return false;
        }

        string fileJson;
        try
        {
            fileJson = File.ReadAllText(arg);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = $"Policy file could not be read: {arg} ({ex.Message})";
            return false;
        }

        return TryParse(fileJson, arg, out policy, out error);
    }

    private static bool LooksLikePath(string arg) =>
        arg.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
        || arg.Contains(Path.DirectorySeparatorChar)
        || arg.Contains(Path.AltDirectorySeparatorChar);

    private static string? ReadPreset(string name, out string? error)
    {
        var assembly = typeof(PolicyLoader).Assembly;
        var resourceName = assembly
            .GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith($".Presets.{name}.json", StringComparison.OrdinalIgnoreCase));

        if (resourceName is null)
        {
            error = $"Embedded policy preset '{name}' is missing from this build.";
            return null;
        }

        using var stream = assembly.GetManifestResourceStream(resourceName)!;
        using var reader = new StreamReader(stream);
        error = null;
        return reader.ReadToEnd();
    }

    private static bool TryParse(string json, string name, out ResolvedPolicy? policy, out string? error)
    {
        policy = null;
        error = null;

        PolicyFileDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<PolicyFileDto>(json, JsonOptions);
        }
        catch (JsonException ex)
        {
            error = $"Policy '{name}' is not valid JSON: {ex.Message}";
            return false;
        }

        if (dto is null)
        {
            error = $"Policy '{name}' is empty.";
            return false;
        }

        var overrides = new Dictionary<string, Severity>(StringComparer.OrdinalIgnoreCase);
        if (dto.SeverityOverrides is not null)
        {
            foreach (var (ruleId, severityText) in dto.SeverityOverrides)
            {
                if (!TryParseSeverity(severityText, out var severity))
                {
                    error = $"Policy '{name}': severity override for '{ruleId}' is not a valid severity ('{severityText}').";
                    return false;
                }

                overrides[NormaliseRuleId(ruleId)] = severity;
            }
        }

        Severity? failOn = null;
        if (dto.FailOn is not null)
        {
            if (!TryParseSeverity(dto.FailOn, out var parsed))
            {
                error = $"Policy '{name}': failOn '{dto.FailOn}' is not one of: critical, high, medium, low, info.";
                return false;
            }

            failOn = parsed;
        }

        if (dto.MinConfidence is < 0 or > 1)
        {
            error = $"Policy '{name}': minConfidence must be in [0, 1].";
            return false;
        }

        policy = new ResolvedPolicy
        {
            Name = name,
            SeverityOverrides = overrides,
            BumpOneBandRules = NormaliseRuleIds(dto.BumpOneBand),
            BumpAllOneBand = dto.BumpAllOneBand,
            DisabledRules = NormaliseRuleIds(dto.DisabledRules),
            FailOn = failOn,
            MinConfidence = dto.MinConfidence,
            ImpliesOffline = dto.Offline
        };
        return true;
    }

    private static bool TryParseSeverity(string text, out Severity severity) =>
        Enum.TryParse(text, ignoreCase: true, out severity) && Enum.IsDefined(severity);

    private static string NormaliseRuleId(string ruleId) => ruleId.Trim().ToUpperInvariant();

    private static HashSet<string> NormaliseRuleIds(List<string>? ruleIds) =>
        ruleIds is null
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(ruleIds.Select(NormaliseRuleId), StringComparer.OrdinalIgnoreCase);

    /// <summary>JSON shape of a policy file or embedded preset.</summary>
    private sealed class PolicyFileDto
    {
        public Dictionary<string, string>? SeverityOverrides { get; set; }

        public List<string>? DisabledRules { get; set; }

        public List<string>? BumpOneBand { get; set; }

        public bool BumpAllOneBand { get; set; }

        public string? FailOn { get; set; }

        public double? MinConfidence { get; set; }

        public bool Offline { get; set; }
    }
}
