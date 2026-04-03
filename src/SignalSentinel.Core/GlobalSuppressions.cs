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
