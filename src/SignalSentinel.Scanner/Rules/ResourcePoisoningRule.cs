// -----------------------------------------------------------------------
// <copyright file="ResourcePoisoningRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-031: Detects poisoned MCP resource metadata and suspicious resource URIs.
/// Maps to OWASP ASI01 (description injection) and OWASP MCP06 (insecure resource exposure).
/// </summary>
/// <remarks>
/// Two independent checks:
/// <list type="bullet">
/// <item>Injection patterns in <c>name</c> / <c>description</c> (same set as SS-001).</item>
/// <item>URI heuristics: <c>file://</c> pointing at home directories, credential stores,
/// or system paths; <c>data:</c> URIs (inline payload); non-standard schemes that
/// suggest the resource is a side channel rather than data.</item>
/// </list>
/// </remarks>
public sealed partial class ResourcePoisoningRule : IRule
{
    /// <inheritdoc />
    public string Id => RuleConstants.Rules.ResourcePoisoning;

    /// <inheritdoc />
    public string Name => "MCP Resource Poisoning";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI01;

    /// <inheritdoc />
    public string Description =>
        "Detects prompt injection in MCP resource names/descriptions and flags resource " +
        "URIs that expose credential stores, home directories, or inline payloads.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST04];

    // file:// URIs that reach into places an MCP resource has no business exposing.
    [GeneratedRegex(
        @"^file:(//)?/?([A-Za-z]:[\\/])?(" +
        @"(home|Users|root)[\\/][^\\/]+[\\/]\.(ssh|aws|azure|gnupg|gcloud|kube|docker|npmrc|pypirc|netrc|git-credentials|env)" +
        @"|etc[\\/](passwd|shadow|sudoers|ssh)" +
        @"|proc[\\/]" +
        @"|Windows[\\/]System32[\\/]config" +
        @"|Users[\\/][^\\/]+[\\/]AppData[\\/](Roaming|Local)[\\/](Microsoft[\\/]Credentials|Code|Claude|Cursor)" +
        @")",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex SensitiveFileUri();

    [GeneratedRegex(@"^data:", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 100)]
    private static partial Regex DataUri();

    [GeneratedRegex(@"^(javascript|vbscript|jar|ms-|shell|cmd|powershell|exec):", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 100)]
    private static partial Regex ExecutableScheme();

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            foreach (var resource in server.Resources)
            {
                cancellationToken.ThrowIfCancellationRequested();

                foreach (var (pattern, evidence) in DescriptionScan.Matches(resource.Description))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = pattern.Severity,
                        Title = $"Resource Poisoning: {pattern.Name}",
                        Description = $"{pattern.Description}. Pattern '{pattern.Id}' matched in the description of resource '{resource.Name}'.",
                        Remediation = "Resource descriptions must describe the data, not instruct the agent. Remove directive or encoded content.",
                        ServerName = server.ServerName,
                        ToolName = resource.Name,
                        Evidence = evidence,
                        Confidence = 0.9,
                        McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
                    });
                }

                foreach (var (pattern, evidence) in DescriptionScan.Matches(resource.Name))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = pattern.Severity,
                        Title = $"Resource Poisoning: {pattern.Name} (in name)",
                        Description = $"{pattern.Description}. Pattern '{pattern.Id}' matched in the name of a resource.",
                        Remediation = "Resource names must be short identifiers. Remove instruction-like or encoded content.",
                        ServerName = server.ServerName,
                        ToolName = resource.Name,
                        Evidence = evidence,
                        Confidence = 0.85,
                        McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
                    });
                }

                var uriFinding = EvaluateUri(server.ServerName, resource.Name, resource.Uri);
                if (uriFinding is not null)
                {
                    findings.Add(uriFinding);
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private Finding? EvaluateUri(string serverName, string resourceName, string uri)
    {
        if (string.IsNullOrWhiteSpace(uri))
        {
            return null;
        }

        var normalised = Uri.UnescapeDataString(uri.Trim());

        if (SafeMatch(SensitiveFileUri(), normalised))
        {
            return Create(serverName, resourceName, uri, Severity.High,
                "Resource Exposes Sensitive Local Path",
                "Resource URI points at a credential store, home-directory dotfile, or system path. " +
                "Any client that reads this resource hands the content to the model.",
                "Restrict resources to application data. Never expose ~/.ssh, ~/.aws, /etc, /proc, or IDE credential stores.");
        }

        if (SafeMatch(DataUri(), normalised))
        {
            return Create(serverName, resourceName, uri, Severity.Medium,
                "Resource Uses Inline data: URI",
                "Resource content is embedded in the URI itself. Inline payloads bypass any " +
                "content-based inspection the client applies to fetched resources.",
                "Serve resource content through resources/read with a stable URI so it can be inspected and versioned.");
        }

        if (SafeMatch(ExecutableScheme(), normalised))
        {
            return Create(serverName, resourceName, uri, Severity.High,
                "Resource Uses Executable URI Scheme",
                "Resource URI scheme implies execution rather than data retrieval.",
                "Resources must use data schemes (file, http(s), custom read-only schemes). Remove executable schemes.");
        }

        return null;
    }

    private Finding Create(string serverName, string resourceName, string uri, Severity severity, string title, string description, string remediation)
    {
        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = severity,
            Title = title,
            Description = $"{description} Resource: '{resourceName}'.",
            Remediation = remediation,
            ServerName = serverName,
            ToolName = resourceName,
            Evidence = DescriptionScan.Truncate(uri),
            Confidence = 0.85,
            McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
        };
    }

    private static bool SafeMatch(Regex regex, string input)
    {
        try
        {
            return regex.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
}
