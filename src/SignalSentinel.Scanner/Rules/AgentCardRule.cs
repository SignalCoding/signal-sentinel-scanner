// -----------------------------------------------------------------------
// <copyright file="AgentCardRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.AgentCard;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// v3.0.0 (WP9): SS-042. Evaluates an A2A Agent Card supplied via <c>--agent-card</c>:
/// injection patterns in the agent and skill descriptions (ASI01), missing or empty
/// security schemes (ASI03, Medium), and a plaintext <c>http:</c> endpoint (ASI03, Medium).
/// A card that could not be loaded yields one Info finding so the gap is visible.
/// </summary>
public sealed class AgentCardRule : IRule
{
    /// <inheritdoc />
    public string Id => RuleConstants.Rules.AgentCard;

    /// <inheritdoc />
    public string Name => "A2A Agent Card Findings";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI01;

    /// <inheritdoc />
    public string Description =>
        "Evaluates an A2A Agent Card (--agent-card) for prompt injection in descriptions, " +
        "absent or empty securitySchemes, and plaintext http endpoints.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST04];

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if (context.AgentCard is not { } card)
        {
            return Task.FromResult(Enumerable.Empty<Finding>());
        }

        var findings = new List<Finding>();

        if (card.Status != AgentCardStatus.Loaded)
        {
            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspAsiCodes.ASI01,
                Severity = Severity.Info,
                Title = "Agent Card Could Not Be Evaluated",
                Description = $"The Agent Card at '{card.Source}' could not be loaded ({card.FailureReason ?? "unknown"}), " +
                    "so its descriptions and authentication posture are unverified.",
                Remediation = "Check the URL or path, confirm the card is valid JSON, and re-run.",
                ServerName = card.DisplayName,
                Evidence = card.FailureReason,
                Confidence = 1.0
            });
            return Task.FromResult<IEnumerable<Finding>>(findings);
        }

        AddInjection(findings, card, "agent description", null, card.Description);
        foreach (var skill in card.Skills)
        {
            AddInjection(findings, card, "skill description", skill.Name, skill.Description);
        }

        if (!card.DeclaresSecurityScheme)
        {
            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspAsiCodes.ASI03,
                Severity = Severity.Medium,
                Title = card.SecuritySchemesEmpty
                    ? "Agent Card Declares Empty securitySchemes"
                    : "Agent Card Declares No Authentication",
                Description = card.SecuritySchemesEmpty
                    ? "The card's 'securitySchemes' is present but empty: the agent advertises that any caller may " +
                      "invoke it without credentials."
                    : "The card declares neither 'securitySchemes' nor a legacy 'authentication' block, so callers " +
                      "cannot know how the agent authenticates and unauthenticated access is the likely default.",
                Remediation =
                    "Declare at least one scheme (OAuth2, OpenID Connect, API key or HTTP bearer) in 'securitySchemes' " +
                    "and reference it from 'security'.",
                ServerName = card.DisplayName,
                Evidence = card.SecuritySchemesEmpty ? "securitySchemes: {}" : "securitySchemes: (absent)",
                Confidence = 0.9
            });
        }

        if (card.EndpointUrl is { } endpoint
            && Uri.TryCreate(endpoint, UriKind.Absolute, out var uri)
            && uri.Scheme == Uri.UriSchemeHttp)
        {
            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspAsiCodes.ASI03,
                Severity = Severity.Medium,
                Title = "Agent Card Endpoint Uses Plaintext HTTP",
                Description = "The agent's declared endpoint 'url' is http:, so task payloads and any credentials " +
                    "travel unencrypted and can be tampered with in transit.",
                Remediation = "Serve the A2A endpoint over https and update the card's 'url'.",
                ServerName = card.DisplayName,
                Evidence = DescriptionScan.Truncate(endpoint),
                Confidence = 0.95
            });
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private void AddInjection(List<Finding> findings, AgentCardAnalysis card, string field, string? itemName, string? text)
    {
        foreach (var (pattern, evidence) in DescriptionScan.Matches(text))
        {
            var where = itemName is null ? $"the {field}" : $"the {field} of '{itemName}'";
            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspAsiCodes.ASI01,
                Severity = pattern.Severity,
                Title = $"Agent Card Injection: {pattern.Name}{(itemName is null ? string.Empty : $" ({itemName})")}",
                Description = $"{pattern.Description}. Pattern '{pattern.Id}' matched in {where}. Agent Card text is " +
                    "shown to orchestrating agents when they select a remote agent, so it is a cross-agent injection channel.",
                Remediation = "Keep card descriptions factual. Remove directive language, URLs, encoded content and hidden characters.",
                ServerName = card.DisplayName,
                ToolName = itemName,
                Evidence = evidence,
                Confidence = 0.9
            });
        }
    }
}
