// -----------------------------------------------------------------------
// <copyright file="CapabilitySurfaceRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-INFO-005: Summarises each server's negotiated capability surface.
/// Informational (does not affect grade). Maps to OWASP ASI02.
/// </summary>
/// <remarks>
/// Emits one Info finding per connected server listing which primitives it offers
/// and which dynamic behaviours it has enabled. <c>tools.listChanged</c> means the tool
/// set can change mid-session (the rug-pull precondition SS-022 detects after the fact);
/// <c>resources.subscribe</c> means the server can push content updates;
/// <c>experimental</c> keys are vendor extensions with no spec-defined semantics. The
/// finding exists so operators can see the surface at a glance and so baselines record
/// it; a change in capability surface between scans is itself a supply-chain signal.
/// </remarks>
public sealed class CapabilitySurfaceRule : IRule
{
    /// <inheritdoc />
    public string Id => RuleConstants.Rules.CapabilitySurface;

    /// <inheritdoc />
    public string Name => "MCP Capability Surface";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI02;

    /// <inheritdoc />
    public string Description =>
        "Informational summary of each server's negotiated capabilities, dynamic-list " +
        "flags, and experimental extensions.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST03];

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

            if (!server.ConnectionSuccessful || server.Capabilities is null)
            {
                continue;
            }

            var caps = server.Capabilities;
            var offered = new List<string>();
            var dynamic = new List<string>();

            if (caps.Tools is not null)
            {
                offered.Add($"tools({server.Tools.Count})");
                if (caps.Tools.ListChanged)
                {
                    dynamic.Add("tools.listChanged");
                }
            }

            if (caps.Resources is not null)
            {
                offered.Add($"resources({server.Resources.Count})");
                if (caps.Resources.ListChanged)
                {
                    dynamic.Add("resources.listChanged");
                }
                if (caps.Resources.Subscribe)
                {
                    dynamic.Add("resources.subscribe");
                }
            }

            if (caps.Prompts is not null)
            {
                offered.Add($"prompts({server.Prompts.Count})");
                if (caps.Prompts.ListChanged)
                {
                    dynamic.Add("prompts.listChanged");
                }
            }

            if (caps.Logging is not null)
            {
                offered.Add("logging");
            }

            if (caps.Completions is not null)
            {
                offered.Add("completions");
            }

            var experimentalKeys = ExperimentalKeys(caps.Experimental);

            var parts = new List<string>
            {
                $"Offers: {(offered.Count > 0 ? string.Join(", ", offered) : "none")}.",
                $"Dynamic: {(dynamic.Count > 0 ? string.Join(", ", dynamic) : "none")}.",
                $"Experimental: {(experimentalKeys.Count > 0 ? string.Join(", ", experimentalKeys) : "none")}."
            };

            var notes = new List<string>();
            if (dynamic.Contains("tools.listChanged"))
            {
                notes.Add("tools.listChanged means the tool set can change after approval; pin with --baseline so SS-022 can detect drift.");
            }
            if (experimentalKeys.Count > 0)
            {
                notes.Add("Experimental capabilities have no spec-defined semantics; confirm with the vendor what each one enables.");
            }

            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                Severity = Severity.Info,
                Title = "MCP Capability Surface",
                Description = string.Join(" ", parts) + (notes.Count > 0 ? " " + string.Join(" ", notes) : string.Empty),
                Remediation =
                    "No action required. Review whether every offered primitive is needed; disable " +
                    "unused ones server-side to reduce attack surface.",
                ServerName = server.ServerName,
                Evidence = DescriptionScan.Truncate(string.Join(";", offered.Concat(dynamic).Concat(experimentalKeys))),
                Confidence = 1.0,
                McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
            });
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static List<string> ExperimentalKeys(JsonElement? experimental)
    {
        var keys = new List<string>();
        if (experimental is not { ValueKind: JsonValueKind.Object } obj)
        {
            return keys;
        }

        foreach (var prop in obj.EnumerateObject())
        {
            if (keys.Count >= 20)
            {
                keys.Add("...");
                break;
            }

            var name = new string([.. prop.Name.Where(c => !char.IsControl(c))]);
            keys.Add(name.Length > 64 ? name[..64] : name);
        }

        return keys;
    }
}
