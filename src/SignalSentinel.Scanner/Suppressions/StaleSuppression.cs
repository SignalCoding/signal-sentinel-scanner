// -----------------------------------------------------------------------
// <copyright file="StaleSuppression.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Scanner.Suppressions;

/// <summary>
/// v2.4.0 (N4): report entry describing a suppression that no longer has any
/// matching finding in the current scan, or whose expiry date is in the past.
/// </summary>
public sealed record StaleSuppression
{
    /// <summary>The offending suppression entry, verbatim from the file.</summary>
    public required SuppressionEntry Entry { get; init; }

    /// <summary>Zero-based index into the suppression file so callers can offer a clear remediation hint.</summary>
    public required int Index { get; init; }

    /// <summary>Why the entry was flagged stale.</summary>
    public required StaleSuppressionReason Reason { get; init; }
}

/// <summary>Classification of a stale suppression.</summary>
public enum StaleSuppressionReason
{
    /// <summary>Default, unused - present to satisfy CA1008.</summary>
    None = 0,

    /// <summary>The entry's <c>expiresOn</c> is before the scan time.</summary>
    Expired = 1,

    /// <summary>No finding in the current scan matches the entry.</summary>
    NoMatch = 2,
}
