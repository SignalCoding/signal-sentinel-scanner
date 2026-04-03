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
