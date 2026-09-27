// -----------------------------------------------------------------------
// <copyright file="SkillExcessivePermRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-017: Detects skills requesting filesystem, network, or shell access beyond their stated scope.
/// Also flags dangerous context settings like "context: full" combined with excessive capabilities.
/// Maps to OWASP ASI02 (Tool Misuse and Exploitation).
/// </summary>
public sealed partial class SkillExcessivePermRule : IRule
{
    /// <summary>
    /// v2.4.1 (G12d): frontmatter <c>network:</c> values treated as an unconstrained
    /// boolean grant rather than a domain allowlist.
    /// </summary>
    private static readonly HashSet<string> BooleanNetworkValues =
        new(StringComparer.OrdinalIgnoreCase) { "true", "yes", "unrestricted", "any", "*", "all" };

    /// <summary>
    /// v2.5.0 (G15a): frontmatter <c>risk_tier</c> values treated as a low-risk
    /// self-declaration for the purposes of the mismatch check below.
    /// v3.1.0 (A1): extended to the Universal Skill Format <c>L0</c>/<c>L1</c>
    /// ladder and the bare numeric equivalents.
    /// </summary>
    private static readonly HashSet<string> LowRiskTierValues =
        new(StringComparer.OrdinalIgnoreCase) { "low", "minimal", "none", "l0", "l1", "0", "1" };

    /// <summary>
    /// v2.5.0 (G15a): frontmatter <c>risk_tier</c> values treated as a high-risk
    /// self-declaration for the undocumented-risk check below.
    /// v3.1.0 (A1): extended to the Universal Skill Format <c>L2</c>/<c>L3</c>
    /// ladder and the bare numeric equivalents.
    /// </summary>
    private static readonly HashSet<string> HighRiskTierValues =
        new(StringComparer.OrdinalIgnoreCase) { "high", "critical", "l2", "l3", "2", "3" };

    /// <summary>
    /// v3.1.0 (A1): frontmatter <c>shell</c> values treated as a truthy grant.
    /// </summary>
    private static readonly HashSet<string> ShellTruthyValues =
        new(StringComparer.OrdinalIgnoreCase) { "true", "yes", "1" };

    public string Id => RuleConstants.Rules.SkillExcessivePermissions;
    public string Name => "Skill Excessive Permissions Detection";

    /// <summary>
    /// v3.0.0 (WP10): permission-seeking directives live in prose and frontmatter.
    /// </summary>
    public SegmentKind ApplicableSegments => SegmentKind.Frontmatter | SegmentKind.Prose;
    public string OwaspCode => OwaspAsiCodes.ASI02;
    public string Description =>
        "Detects skills requesting excessive filesystem, network, or shell access, " +
        "and flags dangerous context/agent settings in frontmatter.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(
        @"\b(read\s+any\s+file|write\s+any\s+file|access\s+all\s+files|full\s+filesystem|entire\s+filesystem|read\s+all\s+directories|recursive\s+access|unrestricted\s+access)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex UnrestrictedFilesystem();

    // v2.4.0 tightened: bare "any url" is common in descriptive prose (e.g. a skill
    // that *handles* "any URL the user pastes"). Fire only when the phrase appears in
    // the context of a request / grant / declaration ("requires access to any url",
    // "grants unrestricted network") or in a YAML-style declared-capability form
    // ("network: unrestricted"). Otherwise we get noise on legitimate connectors.
    [GeneratedRegex(
        @"\b(?:requires?|needs?|requests?|grants?|allows?|enables?|permits?|gives?|provides?)\s+(?:access\s+(?:to\s+)?)?(?:any\s+(?:url|endpoint|host|server|domain|origin)|unrestricted\s+(?:network|url|internet|access|outbound)|full\s+network|all\s+ports|arbitrary\s+(?:network|host|url|endpoint))\b|\bnetwork\s*(?:access)?\s*:\s*(?:unrestricted|any|\*|all)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex UnrestrictedNetwork();

    [GeneratedRegex(
        @"\b(run\s+any\s+command|execute\s+any|arbitrary\s+command|arbitrary\s+code|unrestricted\s+shell|full\s+shell|root\s+access|admin\s+access|sudo|as\s+root)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex UnrestrictedShell();

    // v3.1.1 (R2): bare capability nouns used to look up whether the author has
    // explicitly closed the corresponding capability elsewhere in the document
    // (frontmatter or prose) - see CapabilityIsExplicitlyClosed.
    [GeneratedRegex(@"\bshell\b", RegexOptions.IgnoreCase | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex ShellCapabilityNoun();

    [GeneratedRegex(@"\bnetwork\b", RegexOptions.IgnoreCase | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex NetworkCapabilityNoun();

    [GeneratedRegex(@"\bfilesystem\b", RegexOptions.IgnoreCase | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex FilesystemCapabilityNoun();

    // v3.1.1 (R2): the closed/negated-clause word list from the
    // ss017-scoped-declarations spec, mirroring SensitiveDataRule's (SS-008)
    // Negation() shape. A capability noun found inside one of these clauses is
    // the author's own explicit denial, not a request.
    [GeneratedRegex(
        @"\b(?:no|not|never|closed|disabled|false|denied|without)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex ClosingClauseNegation();

    // v3.1.1 (R2): sentence splitter for the negation check. Unlike SS-008's
    // SentenceBreak, this does not treat a bare newline as a sentence break:
    // frontmatter YAML folded scalars (`>-`) wrap a single sentence across
    // several raw lines, so a hard \n split would sever "shell is an" from
    // "explicit closed declaration" and hide the negation. Whitespace
    // (including \n) is normalised to a single space before this splits on
    // sentence-ending punctuation only.
    [GeneratedRegex(@"[.!?;]+", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex NegationSentenceBreak();

    [GeneratedRegex(@"\s+", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex WhitespaceRun();

    // Words allowed between a capability noun and a negation word for the
    // negation to count as governing it. Mirrors SS-008's NegationWindow.
    private const int NegationWindow = 4;

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // v2.5.0 (G15c): accumulated as danger signals are found below, then
            // cross-checked against the skill's self-declared risk_tier.
            var dangerSignals = new List<string>();

            // Check frontmatter: dangerous context settings
            if (skill.Context is not null)
            {
                var contextLower = skill.Context.ToLowerInvariant();
                if (contextLower is "full" or "fork")
                {
                    dangerSignals.Add($"context: {skill.Context}");
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = $"Skill Excessive Permissions: Dangerous Context Setting ({skill.Context})",
                        Description = $"Skill '{skill.Name}' uses 'context: {skill.Context}' which grants " +
                            "broad access to the agent's conversation context.",
                        Remediation = "Use a more restrictive context setting unless full context access " +
                            "is absolutely required for the skill's functionality.",
                        ServerName = skill.Name,
                        Evidence = $"context: {skill.Context}",
                        Confidence = 0.8,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }

            // Check frontmatter: agent override
            if (skill.Agent is not null)
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Medium,
                    Title = "Skill Excessive Permissions: Custom Agent Override",
                    Description = $"Skill '{skill.Name}' specifies a custom agent configuration " +
                        "which could bypass default safety controls.",
                    Remediation = "Review the custom agent configuration and ensure it maintains " +
                        "appropriate safety boundaries.",
                    ServerName = skill.Name,
                    Evidence = $"agent: {Truncate(skill.Agent, 50)}",
                    Confidence = 0.7,
                    Source = FindingSource.Skill,
                    SkillFilePath = skill.FilePath
                });
            }

            // Check frontmatter: missing metadata
            if (string.IsNullOrWhiteSpace(skill.Description))
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Low,
                    Title = "Skill Excessive Permissions: Missing Description",
                    Description = $"Skill '{skill.Name}' has no description in frontmatter. " +
                        "Missing metadata reduces transparency (opacity equals risk).",
                    Remediation = "Add a clear description to the skill's YAML frontmatter " +
                        "explaining what the skill does.",
                    ServerName = skill.Name,
                    Confidence = 0.95,
                    Source = FindingSource.Skill,
                    SkillFilePath = skill.FilePath
                });
            }

            // v2.4.1 (G12d): frontmatter-level network permission shape. A boolean
            // network grant ("network: true"/"unrestricted"/"any"/"*"/"all") is
            // strictly worse than a declared domain allowlist ("network.allow: [...]")
            // per the OWASP Agentic Skills Top 10 "Universal Skill Format" proposal -
            // a boolean has no way to constrain scope. Skip firing when the skill also
            // (or instead) declares network.allow.
            var hasNetworkAllowlist = skill.ExtraFrontmatter.Keys.Any(
                k => string.Equals(k, "network.allow", StringComparison.OrdinalIgnoreCase));
            if (!hasNetworkAllowlist)
            {
                var networkValue = skill.ExtraFrontmatter.FirstOrDefault(
                    kvp => string.Equals(kvp.Key, "network", StringComparison.OrdinalIgnoreCase)).Value;
                if (networkValue is not null && BooleanNetworkValues.Contains(networkValue.Trim()))
                {
                    dangerSignals.Add($"network: {networkValue.Trim()}");
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Medium,
                        Title = "Skill Excessive Permissions: Boolean Network Permission (no domain allowlist)",
                        Description = $"Skill '{skill.Name}' declares 'network: {networkValue.Trim()}' - " +
                            "a boolean/unrestricted network grant rather than an explicit domain allowlist. " +
                            "A boolean permission model cannot constrain which hosts the skill may reach.",
                        Remediation = "Replace the boolean network grant with a 'network.allow' frontmatter " +
                            "field listing the specific domains the skill needs to reach.",
                        ServerName = skill.Name,
                        Evidence = $"network: {networkValue.Trim()}",
                        Confidence = 0.8,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }

            // Check instructions for excessive capability requests
            if (CheckPattern(findings, skill, UnrestrictedFilesystem(), "Unrestricted Filesystem Access",
                "requests unrestricted filesystem access",
                "Restrict filesystem access to specific directories needed by the skill.",
                FilesystemCapabilityNoun()))
            {
                dangerSignals.Add("unrestricted filesystem access");
            }

            if (CheckPattern(findings, skill, UnrestrictedNetwork(), "Unrestricted Network Access",
                "requests unrestricted network access",
                "Restrict network access to specific endpoints needed by the skill.",
                NetworkCapabilityNoun()))
            {
                dangerSignals.Add("unrestricted network access");
            }

            if (CheckPattern(findings, skill, UnrestrictedShell(), "Unrestricted Shell Access",
                "requests unrestricted shell/command execution",
                "Avoid requesting arbitrary command execution. Specify the exact commands needed.",
                ShellCapabilityNoun(),
                matchValue => IsBoundedShellMatch(skill, matchValue)))
            {
                dangerSignals.Add("unrestricted shell access");
            }

            // v3.1.0 (A1), narrowed by v3.1.1 (R1, ss017-scoped-declarations):
            // derive the implied risk floor from declared permissions
            // independently of observed (prose) capability - but only when what
            // is declared is unbounded. A skill that declares shell access, or a
            // write/network scope with an unbounded entry, but says nothing
            // dangerous in its body must still raise the floor - this is
            // precisely the spoofing case the risk-tier check exists to catch.
            // An enumerated allowlist of concrete hosts or paths is a narrower,
            // more honest declaration than a boolean grant and must not be
            // punished the same way (R1).
            var declaredShell = skill.ExtraFrontmatter.FirstOrDefault(
                kvp => string.Equals(kvp.Key, "shell", StringComparison.OrdinalIgnoreCase)).Value?.Trim();
            if (declaredShell is not null && ShellTruthyValues.Contains(declaredShell))
            {
                dangerSignals.Add("declared shell: true");
            }

            var declaredFilesWrite = skill.ExtraFrontmatter.FirstOrDefault(
                kvp => string.Equals(kvp.Key, "files.write", StringComparison.OrdinalIgnoreCase)).Value;
            if (DeclaredPermissionScope.HasUnboundedEntry(
                declaredFilesWrite, DeclaredPermissionScope.IsUnboundedFilesWriteEntry))
            {
                dangerSignals.Add("declared files.write scope (unbounded)");
            }

            var declaredNetworkAllow = skill.ExtraFrontmatter.FirstOrDefault(
                kvp => string.Equals(kvp.Key, "network.allow", StringComparison.OrdinalIgnoreCase)).Value;
            if (DeclaredPermissionScope.HasUnboundedEntry(
                declaredNetworkAllow, DeclaredPermissionScope.IsUnboundedNetworkEntry))
            {
                dangerSignals.Add("declared network.allow scope (unbounded)");
            }

            // v2.5.0 (G15c): cross-check the skill's self-declared risk_tier
            // (Universal Skill Format) against what the rule actually observed.
            var riskTier = skill.ExtraFrontmatter.FirstOrDefault(
                kvp => string.Equals(kvp.Key, "risk_tier", StringComparison.OrdinalIgnoreCase)).Value?.Trim();

            if (dangerSignals.Count > 0)
            {
                if (riskTier is not null && LowRiskTierValues.Contains(riskTier))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Skill Excessive Permissions: Risk Tier Understated",
                        Description = $"Skill '{skill.Name}' declares 'risk_tier: {riskTier}' but " +
                            $"actually requests: {string.Join(", ", dangerSignals)}. A self-declared " +
                            "low risk tier that doesn't match observed permissions either reflects " +
                            "careless authoring or is an attempt to bypass risk-tier-based approval " +
                            "gates.",
                        Remediation = "Correct the 'risk_tier' declaration to reflect the skill's " +
                            "actual permission footprint, or reduce the requested permissions to " +
                            "match the declared tier.",
                        ServerName = skill.Name,
                        Evidence = $"risk_tier: {riskTier}; observed: {string.Join(", ", dangerSignals)}",
                        Confidence = 0.75,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
                else if (riskTier is null || !HighRiskTierValues.Contains(riskTier))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Info,
                        Title = "Skill Excessive Permissions: Missing Risk Tier Declaration",
                        Description = $"Skill '{skill.Name}' requests {string.Join(", ", dangerSignals)} " +
                            "but does not declare a 'risk_tier' frontmatter field. Explicitly " +
                            "declaring 'risk_tier: high' improves transparency for consumers that " +
                            "gate skill installation on declared risk.",
                        Remediation = "Add a 'risk_tier: high' (or 'critical') frontmatter field " +
                            "reflecting the skill's actual permission footprint.",
                        ServerName = skill.Name,
                        Evidence = $"observed: {string.Join(", ", dangerSignals)}",
                        Confidence = 0.6,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private bool CheckPattern(
        List<Finding> findings,
        SkillDefinition skill,
        Regex pattern,
        string patternName,
        string verb,
        string remediation,
        Regex capabilityNoun,
        Func<string, bool>? isMatchSuppressed = null)
    {
        // v3.0.0 (WP10): permission-seeking instructions live in prose/frontmatter;
        // code examples in fenced blocks are not directives to the agent.
        var documentText = SegmentFilter.TextFor(skill, ApplicableSegments);
        if (!SafeIsMatch(pattern, documentText)) return false;

        // v3.1.1 (R2): a skill that explicitly and closedly declares this
        // capability elsewhere in the document ("shell is an explicit closed
        // declaration", "shell: false") has denied it, regardless of how the
        // triggering phrase itself reads.
        if (CapabilityIsExplicitlyClosed(documentText, capabilityNoun)) return false;

        var match = SafeMatches(pattern, documentText)
            .FirstOrDefault(m => isMatchSuppressed is null || !isMatchSuppressed(m.Value));
        if (match is null) return false;

        findings.Add(new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = Severity.High,
            Title = $"Skill Excessive Permissions: {patternName}",
            Description = $"Skill '{skill.Name}' {verb} in its instructions.",
            Remediation = remediation,
            ServerName = skill.Name,
            Evidence = TruncateEvidence(match.Value),
            Confidence = 0.85,
            Source = FindingSource.Skill,
            SkillFilePath = skill.FilePath
        });

        return true;
    }

    /// <summary>
    /// v3.1.1 (R1 extension, found necessary by the AST06 V3/C4 corpus pair):
    /// the bare, context-free shell phrases - "sudo", "root access", "admin
    /// access", "as root" - describe a *means* of shell access rather than an
    /// inherently unbounded one. When the skill also declares a non-empty,
    /// concrete <c>shell.commands</c> allow-list (Universal Skill Format's
    /// <c>permissions.shell.commands</c>), that means is bounded to specific
    /// executables and this match is suppressed. "unrestricted shell", "full
    /// shell", "arbitrary command/code" and "run/execute any ..." are never
    /// suppressed this way - no commands allow-list makes those narrower.
    /// </summary>
    private static readonly HashSet<string> BoundedEligibleShellPhrases =
        new(StringComparer.OrdinalIgnoreCase) { "sudo", "root access", "admin access", "as root" };

    private static bool IsBoundedShellMatch(SkillDefinition skill, string matchedValue)
    {
        if (!BoundedEligibleShellPhrases.Contains(matchedValue)) return false;

        var declaredShellCommands = skill.ExtraFrontmatter.FirstOrDefault(
            kvp => string.Equals(kvp.Key, "shell.commands", StringComparison.OrdinalIgnoreCase)).Value;
        return DeclaredPermissionScope.HasNonEmptyDeclaredScope(declaredShellCommands) &&
            !DeclaredPermissionScope.HasUnboundedEntry(
                declaredShellCommands, DeclaredPermissionScope.IsUnboundedShellCommandEntry);
    }

    /// <summary>
    /// v3.1.1 (R2): true when <paramref name="capabilityNoun"/> (e.g. bare
    /// "shell") appears in some sentence of <paramref name="documentText"/>
    /// within <see cref="NegationWindow"/> words of a closing/negation word
    /// (<c>no</c>, <c>not</c>, <c>never</c>, <c>closed</c>, <c>disabled</c>,
    /// <c>false</c>, <c>denied</c>, <c>without</c>). Mirrors
    /// SensitiveDataRule's (SS-008) global pre-check: an explicit denial
    /// anywhere in the document is the author's own answer and is taken as
    /// authoritative for every mention of that capability, not just the one
    /// next to the denial.
    /// </summary>
    private static bool CapabilityIsExplicitlyClosed(string documentText, Regex capabilityNoun)
    {
        var normalized = WhitespaceRun().Replace(documentText, " ");
        foreach (var sentence in NegationSentenceBreak().Split(normalized))
        {
            var noun = capabilityNoun.Match(sentence);
            if (!noun.Success) continue;

            foreach (Match negation in ClosingClauseNegation().Matches(sentence))
            {
                var before = negation.Index < noun.Index &&
                    WordsBetween(sentence, negation.Index + negation.Length, noun.Index) <= NegationWindow;
                var after = negation.Index > noun.Index &&
                    WordsBetween(sentence, noun.Index + noun.Length, negation.Index) <= NegationWindow;
                if (before || after) return true;
            }
        }

        return false;
    }

    private static int WordsBetween(string text, int start, int end)
    {
        if (end <= start) return 0;

        var count = 0;
        var inWord = false;
        for (var i = start; i < end; i++)
        {
            var isWord = char.IsLetterOrDigit(text[i]) || text[i] == '_' || text[i] == '\'';
            if (isWord && !inWord) count++;
            inWord = isWord;
        }

        return count;
    }

    private static bool SafeIsMatch(Regex pattern, string? input)
    {
        if (string.IsNullOrEmpty(input)) return false;
        try { return pattern.IsMatch(input); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static IEnumerable<Match> SafeMatches(Regex pattern, string? input)
    {
        if (string.IsNullOrEmpty(input)) yield break;
        MatchCollection? matches;
        try { matches = pattern.Matches(input); }
        catch (RegexMatchTimeoutException) { yield break; }
        foreach (Match m in matches) yield return m;
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..(maxLength - 3)] + "...";

    private static string TruncateEvidence(string evidence) =>
        evidence.Length <= RuleConstants.Limits.MaxEvidenceLength
            ? evidence
            : evidence[..(RuleConstants.Limits.MaxEvidenceLength - 3)] + "...";
}
