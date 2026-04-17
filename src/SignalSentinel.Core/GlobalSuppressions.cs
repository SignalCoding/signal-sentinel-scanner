// -----------------------------------------------------------------------
// <copyright file="GlobalSuppressions.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

// Thread-safety: KnownLegitimateServers HashSet is only added to during initialisation
// or via explicit AddLegitimateServer calls. In production usage, this is effectively read-only.
[assembly: SuppressMessage(
    "Design",
    "CA1002:Do not expose generic lists",
    Justification = "Internal implementation detail")]

// Regex patterns are pre-compiled with GeneratedRegex and have timeout protection
[assembly: SuppressMessage(
    "Security",
    "MA0009:Regex should not be vulnerable to ReDoS",
    Justification = "All regex patterns use matchTimeoutMilliseconds parameter")]

// Using StringComparison explicitly where needed, implicit comparison is intentional for performance
[assembly: SuppressMessage(
    "Globalization",
    "CA1307:Specify StringComparison for clarity",
    Justification = "Ordinal comparison is intentional for security pattern matching")]

// CA1034: Nested types should not be visible — intentional grouping of constants by category
[assembly: SuppressMessage(
    "Design",
    "CA1034:Nested types should not be visible",
    Justification = "Intentional grouping of constants by category (Rules, Limits)",
    Scope = "type",
    Target = "~T:SignalSentinel.Core.RuleConstants.Rules")]
[assembly: SuppressMessage(
    "Design",
    "CA1034:Nested types should not be visible",
    Justification = "Intentional grouping of constants by category (Rules, Limits)",
    Scope = "type",
    Target = "~T:SignalSentinel.Core.RuleConstants.Limits")]

// CA1056: URI properties should not be strings — these are JSON deserialization models
[assembly: SuppressMessage(
    "Design",
    "CA1056:URI-like properties should not be strings",
    Justification = "JSON deserialization model — changing to System.Uri would break JSON parsing",
    Scope = "member",
    Target = "~P:SignalSentinel.Core.McpProtocol.McpResourceDefinition.Uri")]
[assembly: SuppressMessage(
    "Design",
    "CA1056:URI-like properties should not be strings",
    Justification = "JSON deserialization model — changing to System.Uri would break JSON parsing",
    Scope = "member",
    Target = "~P:SignalSentinel.Core.McpProtocol.McpServerConfig.Url")]

// CA1055: URI return values should not be strings — returns URL strings used in reports
[assembly: SuppressMessage(
    "Design",
    "CA1055:URI-like return values should not be strings",
    Justification = "Returns URL string used in security reports, not for navigation",
    Scope = "member",
    Target = "~M:SignalSentinel.Core.Models.OwaspAsiCodes.GetDocumentationUrl(System.String)")]

// CA1308: Use ToUpperInvariant — ToLowerInvariant is intentional in all cases below
[assembly: SuppressMessage(
    "Globalization",
    "CA1308:Normalize strings to uppercase",
    Justification = "URL fragments require lowercase per convention",
    Scope = "member",
    Target = "~M:SignalSentinel.Core.Models.OwaspAsiCodes.GetDocumentationUrl(System.String)")]
[assembly: SuppressMessage(
    "Globalization",
    "CA1308:Normalize strings to uppercase",
    Justification = "Lowercase normalisation is correct for case-insensitive name comparison",
    Scope = "member",
    Target = "~M:SignalSentinel.Core.Security.TyposquatDetector.NormalizeName(System.String)")]
[assembly: SuppressMessage(
    "Globalization",
    "CA1308:Normalize strings to uppercase",
    Justification = "Hex hashes are conventionally lowercase",
    Scope = "member",
    Target = "~M:SignalSentinel.Core.Security.HashPinning.ComputeToolHash(SignalSentinel.Core.McpProtocol.McpToolDefinition)")]
[assembly: SuppressMessage(
    "Globalization",
    "CA1308:Normalize strings to uppercase",
    Justification = "Hex hashes are conventionally lowercase",
    Scope = "member",
    Target = "~M:SignalSentinel.Core.Security.HashPinning.ComputeServerManifestHash(System.String,System.Collections.Generic.IEnumerable{SignalSentinel.Core.McpProtocol.McpToolDefinition})")]
[assembly: SuppressMessage(
    "Globalization",
    "CA1308:Normalize strings to uppercase",
    Justification = "Sigma modifier and level tokens are defined in lowercase by the Sigma specification",
    Scope = "member",
    Target = "~M:SignalSentinel.Core.RuleFormats.SigmaRuleLoader.ParseField(System.String)~System.ValueTuple{System.String,SignalSentinel.Core.RuleFormats.SigmaMatchType}")]
[assembly: SuppressMessage(
    "Globalization",
    "CA1308:Normalize strings to uppercase",
    Justification = "Sigma severity levels are defined in lowercase by the Sigma specification",
    Scope = "member",
    Target = "~M:SignalSentinel.Core.RuleFormats.SigmaRuleLoader.MapLevel(System.String)~SignalSentinel.Core.Models.Severity")]

// CA1812: YamlDotNet uses reflection to instantiate deserialisation DTOs
[assembly: SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated reflectively by YamlDotNet deserialiser",
    Scope = "type",
    Target = "~T:SignalSentinel.Core.RuleFormats.SigmaRuleLoader.SigmaRawDocument")]
[assembly: SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated reflectively by YamlDotNet deserialiser",
    Scope = "type",
    Target = "~T:SignalSentinel.Core.RuleFormats.SigmaRuleLoader.SigmaRawLogSource")]
