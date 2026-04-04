// -----------------------------------------------------------------------
// <copyright file="OwaspMcpMapping.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Core.Models;

/// <summary>
/// OWASP MCP Top 10 (2026) protocol-level risk codes.
/// Complements the ASI01-ASI10 agent-level codes with protocol-specific risks.
/// </summary>
public static class OwaspMcpCodes
{
    public const string MCP01 = "MCP01";
    public const string MCP02 = "MCP02";
    public const string MCP03 = "MCP03";
    public const string MCP04 = "MCP04";
    public const string MCP05 = "MCP05";
    public const string MCP06 = "MCP06";
    public const string MCP07 = "MCP07";
    public const string MCP08 = "MCP08";
    public const string MCP09 = "MCP09";
    public const string MCP10 = "MCP10";

    public static string GetDescription(string code) => code switch
    {
        MCP01 => "Tool Poisoning - Malicious instructions hidden in tool descriptions",
        MCP02 => "Excessive Permissions - Tools with overly broad capabilities or access",
        MCP03 => "Insecure Tool Discovery - Unvalidated or spoofed tool registrations",
        MCP04 => "Tool Argument Injection - Manipulated parameters enabling unintended operations",
        MCP05 => "Insecure Data Handling - Sensitive data exposed through tool responses",
        MCP06 => "Insecure Resource Exposure - Unprotected resources accessible via MCP",
        MCP07 => "Authentication Gaps - Missing or weak authentication on MCP endpoints",
        MCP08 => "Over-Privileged Servers - MCP servers with excessive system access",
        MCP09 => "Insecure Transport - Unencrypted or poorly secured MCP connections",
        MCP10 => "Logging Failures - Insufficient audit logging of MCP operations",
        _ => "Unknown OWASP MCP code"
    };

    /// <summary>
    /// Maps ASI codes to their most relevant MCP codes for dual mapping.
    /// A single finding can map to both an ASI code and an MCP code.
    /// </summary>
    public static string? GetCorrespondingMcpCode(string ruleId) => ruleId switch
    {
        "SS-001" => MCP01,  // Tool Poisoning → MCP Tool Poisoning
        "SS-002" => MCP02,  // Overbroad Permissions → MCP Excessive Permissions
        "SS-003" => MCP07,  // Missing Auth → MCP Authentication Gaps
        "SS-004" => MCP03,  // Supply Chain → MCP Insecure Tool Discovery
        "SS-005" => MCP08,  // Code Execution → MCP Over-Privileged Servers
        "SS-006" => MCP05,  // Memory Write → MCP Insecure Data Handling
        "SS-007" => MCP09,  // Inter-Agent → MCP Insecure Transport
        "SS-008" => MCP05,  // Sensitive Data → MCP Insecure Data Handling
        "SS-009" => MCP01,  // Excessive Description → MCP Tool Poisoning
        "SS-010" => MCP02,  // Cross-Server Paths → MCP Excessive Permissions
        "SS-019" => MCP07,  // Credential Hygiene → MCP Authentication Gaps
        "SS-020" => MCP07,  // OAuth Compliance → MCP Authentication Gaps
        "SS-021" => MCP03,  // Package Provenance → MCP Insecure Tool Discovery
        _ => null
    };
}
