// -----------------------------------------------------------------------
// <copyright file="RuleConstants.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Core;

/// <summary>
/// Centralised constants for rule identifiers, OWASP codes, and security limits.
/// </summary>
/// <remarks>
/// <para>
/// This class prevents magic strings from being scattered throughout the codebase,
/// ensuring consistency and making maintenance easier.
/// </para>
/// <para>
/// Rule IDs follow the SS-XXX convention where SS = Signal Sentinel.
/// Limits are calibrated for defence-grade security posture.
/// </para>
/// </remarks>
public static class RuleConstants
{
    /// <summary>
    /// Rule IDs following SS-XXX naming convention.
    /// </summary>
    public static class Rules
    {
        // MCP Rules (SS-001 to SS-010, original v1.0)
        public const string ToolPoisoning = "SS-001";
        public const string OverbroadPermissions = "SS-002";
        public const string MissingAuthentication = "SS-003";
        public const string SupplyChain = "SS-004";
        public const string CodeExecution = "SS-005";
        public const string MemoryContextWrite = "SS-006";
        public const string InterAgentProxy = "SS-007";
        public const string SensitiveDataAccess = "SS-008";
        public const string ExcessiveDescription = "SS-009";
        public const string CrossServerAttackPaths = "SS-010";

        // Skill Rules (SS-011 to SS-018, v2.0)
        public const string SkillInjection = "SS-011";
        public const string SkillScopeViolation = "SS-012";
        public const string SkillCredentialAccess = "SS-013";
        public const string SkillExfiltration = "SS-014";
        public const string SkillObfuscation = "SS-015";
        public const string SkillScriptPayload = "SS-016";
        public const string SkillExcessivePermissions = "SS-017";
        public const string SkillHiddenContent = "SS-018";

        // New MCP Rules (SS-019 to SS-021, v2.0)
        public const string CredentialHygiene = "SS-019";
        public const string OAuthCompliance = "SS-020";
        public const string PackageProvenance = "SS-021";
    }

    /// <summary>
    /// Security limits for resource protection.
    /// </summary>
    public static class Limits
    {
        public const int MaxDescriptionLength = 100_000;
        public const int MaxEvidenceLength = 100;
        public const int MaxResponseSizeBytes = 10 * 1024 * 1024;
        public const int MaxToolsPerServer = 10_000;
        public const int MaxResourcesPerServer = 10_000;
        public const int MaxPromptsPerServer = 1_000;
        public const int MaxServers = 100;
        public const int MaxConfigFileSizeBytes = 10 * 1024 * 1024;
        public const int MaxServersPerConfig = 100;
        public const int RegexTimeoutMs = 500;
    }
}
