// -----------------------------------------------------------------------
// <copyright file="SkillScopeViolationRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-012: Detects mismatch between a skill's stated purpose (frontmatter) and
/// its actual instructions (body). A skill that says it "formats code" but instructs
/// the agent to access the filesystem or make network requests is a scope violation.
/// Maps to OWASP ASI02 (Tool Misuse and Exploitation).
/// </summary>
public sealed partial class SkillScopeViolationRule : IRule
{
    public string Id => RuleConstants.Rules.SkillScopeViolation;
    public string Name => "Skill Scope Violation Detection";
    public string OwaspCode => OwaspAsiCodes.ASI02;
    public string Description =>
        "Detects mismatch between a skill's stated purpose and its actual instructions, " +
        "indicating the skill may perform actions beyond its described scope.";
    public bool EnabledByDefault => true;
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST03];

    // v2.3.0: lemma/synonym table used to check whether a skill's frontmatter description
    // implicitly declares a dangerous capability. Matching is OrdinalIgnoreCase against
    // each synonym; any hit means "the skill has declared this capability, do not flag".
    // v2.3.0 fix #22b: filesystem row extended with disk/volume/mount/proc/sys aliases.
    private static readonly Dictionary<string, string[]> CapabilitySynonyms =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["filesystem access"] = [
                "filesystem", "file system", "file access", "read files", "write files",
                "disk access", "disk", "disk/memory", "local files", "volume", "mount",
                "/proc", "/sys", "/dev", "procfs", "sysfs"
            ],
            ["network access"] = [
                "network", "network access", "http", "https", "web", "api",
                "online", "internet", "outbound", "fetch requests", "remote call"
            ],
            ["shell/command execution"] = [
                "shell", "command", "command line", "terminal", "cli", "subprocess",
                "execute commands", "run commands", "docker exec", "system call"
            ],
            ["inline code execution (e.g. python3 -c)"] = [
                "inline code", "script", "scripting", "evaluate code",
                "dynamic execution", "run code", "code evaluation"
            ]
        };

    // v2.3.0 fix #22a: authoritative map from YAML `capabilities:` tokens to
    // lemma-table row keys. When a skill's frontmatter declares a capability
    // token present in this map, the corresponding capability is considered
    // declared and SS-012 will not fire on it - regardless of what the
    // description prose says. This respects the structured declaration as
    // the ground truth.
    private static readonly Dictionary<string, string> YamlCapabilityToLemma =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // Filesystem
            ["read-filesystem"] = "filesystem access",
            ["read_filesystem"] = "filesystem access",
            ["write-filesystem"] = "filesystem access",
            ["write_filesystem"] = "filesystem access",
            ["filesystem"] = "filesystem access",
            ["fs"] = "filesystem access",
            ["read-docker-socket"] = "filesystem access",
            ["read_docker_socket"] = "filesystem access",
            ["docker_daemon_read"] = "filesystem access",
            ["docker-daemon-read"] = "filesystem access",
            ["read-proc"] = "filesystem access",
            ["read_proc"] = "filesystem access",
            ["read-sysfs"] = "filesystem access",
            ["read_sysfs"] = "filesystem access",
            ["local_system_metrics_read"] = "filesystem access",
            ["local-system-metrics-read"] = "filesystem access",
            ["system_metrics_read"] = "filesystem access",
            // Network
            ["network"] = "network access",
            ["http"] = "network access",
            ["https"] = "network access",
            ["outbound-http"] = "network access",
            ["outbound_http"] = "network access",
            ["internet"] = "network access",
            ["network_access"] = "network access",
            ["network-access"] = "network access",
            // Shell / command execution
            ["shell"] = "shell/command execution",
            ["exec"] = "shell/command execution",
            ["subprocess"] = "shell/command execution",
            ["command-execution"] = "shell/command execution",
            ["command_execution"] = "shell/command execution",
            ["shell-command-execution"] = "shell/command execution",
            ["shell_command_execution"] = "shell/command execution",
            ["run-commands"] = "shell/command execution",
            ["run_commands"] = "shell/command execution",
            // Inline code
            ["eval"] = "inline code execution (e.g. python3 -c)",
            ["inline-code"] = "inline code execution (e.g. python3 -c)",
            ["inline_code"] = "inline code execution (e.g. python3 -c)",
            ["code-evaluation"] = "inline code execution (e.g. python3 -c)",
            ["code_evaluation"] = "inline code execution (e.g. python3 -c)"
        };

    [GeneratedRegex(
        @"\b(read_file|write_file|readFile|writeFile|fs\.|filesystem|file\s+system|open\s+file|create\s+file|delete\s+file|mkdir|rmdir)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex FileSystemCapability();

    [GeneratedRegex(
        @"\b(http|https|fetch|curl|wget|request|api\s+call|endpoint|webhook|socket)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex NetworkCapability();

    [GeneratedRegex(
        @"\b(exec|spawn|shell|subprocess|child_process|system\(|popen|Process\.Start|os\.system|sh\s+-c|bash\s+-c|cmd\s+/c|powershell\s+-)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex ShellCapability();

    [GeneratedRegex(
        @"\b(python3?\s+-c|bash\s+-c|sh\s+-c|node\s+-e|ruby\s+-e|perl\s+-e|powershell\s+-Command)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex InlineCodeExecution();

    [GeneratedRegex(
        @"\b(format|lint|style|beautif|indent|prettif|syntax|highlight|color|theme|render|display|convert|transform)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex BenignPurpose();

    private static readonly (Regex Pattern, string Capability, Severity Severity)[] DangerousCapabilities =
    [
        (FileSystemCapability(), "filesystem access", Severity.High),
        (NetworkCapability(), "network access", Severity.High),
        (ShellCapability(), "shell/command execution", Severity.Critical),
        (InlineCodeExecution(), "inline code execution (e.g. python3 -c)", Severity.High),
    ];

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var statedPurpose = skill.Description ?? skill.Name;
            var isBenignPurpose = SafeIsMatch(BenignPurpose(), statedPurpose);

            // v2.3.0 fix #22a: collect capabilities the skill declares in its
            // YAML `capabilities:` block, mapped to the lemma-table keys so we
            // can skip firing on anything declared there.
            var yamlDeclared = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var rawCapability in skill.Capabilities)
            {
                if (YamlCapabilityToLemma.TryGetValue(rawCapability.Trim(), out var lemma))
                {
                    yamlDeclared.Add(lemma);
                }
            }

            foreach (var (pattern, capability, severity) in DangerousCapabilities)
            {
                // v2.3.0 fix #22a: YAML capabilities block is authoritative.
                if (yamlDeclared.Contains(capability))
                {
                    continue;
                }

                // v2.3.0: prefer a case-insensitive synonym hit on the stated purpose;
                // fall back to the regex match for code-like mentions (e.g. "fs.read").
                var purposeHasCapability = PurposeDeclaresCapability(statedPurpose, capability)
                    || SafeIsMatch(pattern, statedPurpose);
                var bodyHasCapability = SafeIsMatch(pattern, skill.InstructionsBody);

                // Scope violation: body uses capability not mentioned in purpose
                if (bodyHasCapability && !purposeHasCapability)
                {
                    var effectiveSeverity = isBenignPurpose ? severity : Severity.Medium;

                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        AstCodes = AstCodes,
                        Severity = effectiveSeverity,
                        Title = $"Skill Scope Violation: Undeclared {capability}",
                        Description = $"Skill '{skill.Name}' is described as '{Truncate(statedPurpose, 100)}' " +
                            $"but its instructions reference {capability} which is not part of its stated purpose.",
                        Remediation = $"Either update the skill description to include {capability}, " +
                            $"or remove the {capability} instructions if they are not needed.",
                        ServerName = skill.Name,
                        Evidence = capability,
                        Confidence = isBenignPurpose ? 0.85 : 0.7,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static bool SafeIsMatch(Regex pattern, string? input)
    {
        if (string.IsNullOrEmpty(input)) return false;
        try { return pattern.IsMatch(input); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static bool PurposeDeclaresCapability(string? statedPurpose, string capabilityKey)
    {
        if (string.IsNullOrEmpty(statedPurpose))
        {
            return false;
        }
        if (!CapabilitySynonyms.TryGetValue(capabilityKey, out var synonyms))
        {
            return false;
        }
        foreach (var synonym in synonyms)
        {
            if (statedPurpose.Contains(synonym, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..(maxLength - 3)] + "...";
}
