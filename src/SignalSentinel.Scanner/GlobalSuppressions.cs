// -----------------------------------------------------------------------
// <copyright file="GlobalSuppressions.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.

using System.Diagnostics.CodeAnalysis;

// Console application - synchronous entry point is appropriate
[assembly: SuppressMessage(
    "Design",
    "CA1031:Do not catch general exception types",
    Justification = "CLI entry point catches all exceptions for user-friendly error messages")]

// ConfigureAwait(false) not needed in console applications without synchronization context
[assembly: SuppressMessage(
    "Reliability",
    "CA2007:Consider calling ConfigureAwait on the awaited task",
    Justification = "Console application has no synchronization context")]

// Process spawning is core functionality for MCP stdio transport
[assembly: SuppressMessage(
    "Security",
    "CA1062:Validate arguments of public methods",
    Justification = "ArgumentNullException.ThrowIfNull is used at method entry")]

// CA1515: Console application types don't need to be internal — public visibility aids testing and extensibility
[assembly: SuppressMessage(
    "Maintainability",
    "CA1515:Consider making public types internal",
    Justification = "Console application types are public for testability and potential library consumption")]

// CA1305: Report generators produce invariant English output; locale-sensitive formatting not required
[assembly: SuppressMessage(
    "Globalization",
    "CA1305:Specify IFormatProvider",
    Justification = "Report generators produce invariant English output; locale formatting not required")]

// CA1849: Synchronous Console.Error.WriteLine is appropriate in error/catch paths of CLI application
[assembly: SuppressMessage(
    "Performance",
    "CA1849:Call async methods when in an async method",
    Justification = "Synchronous console output is appropriate in CLI error paths and catch blocks")]

// CA1308: ToLowerInvariant is intentional for URL building, protocol matching, and case-insensitive comparisons
[assembly: SuppressMessage(
    "Globalization",
    "CA1308:Normalize strings to uppercase",
    Justification = "ToLowerInvariant is intentional for URL fragments, protocol matching, and package name normalisation")]

// CA1307: Ordinal string comparison is the intended default for security pattern matching
[assembly: SuppressMessage(
    "Globalization",
    "CA1307:Specify StringComparison for clarity",
    Justification = "Ordinal comparison is intentional for security-sensitive string operations")]

// CA1847: String.Contains(string) is used for readability in non-hot-path code
[assembly: SuppressMessage(
    "Performance",
    "CA1847:Use char literal for a single character lookup",
    Justification = "String.Contains(string) is used for readability in non-hot-path security rule code")]

// CA1056: URI properties are strings for JSON deserialization and CLI argument parsing
[assembly: SuppressMessage(
    "Design",
    "CA1056:URI-like properties should not be strings",
    Justification = "URI properties are strings for JSON deserialization compatibility and CLI argument passing")]

// CA2000: HttpClientHandler ownership is transferred to HttpClient which manages its disposal
[assembly: SuppressMessage(
    "Reliability",
    "CA2000:Dispose objects before losing scope",
    Justification = "HttpClientHandler ownership is transferred to HttpClient; StringContent is consumed by PostAsync")]

// CA1303: CLI tools use literal strings for help text and version output — resource tables are not appropriate
[assembly: SuppressMessage(
    "Globalization",
    "CA1303:Do not pass literals as localized parameters",
    Justification = "CLI tool — help text and version strings are not localised")]
