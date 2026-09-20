// -----------------------------------------------------------------------
// <copyright file="OsvVulnDetail.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Osv;

/// <summary>
/// v3.0.0 (WP6): the reportable subset of an OSV vulnerability record as returned by
/// <c>/v1/vulns/{id}</c>. <see cref="Severity"/> is null when the record carries neither
/// a CVSS v3 vector nor a recognisable database label.
/// </summary>
/// <param name="Summary">Short summary, truncated to 200 characters; empty when absent.</param>
/// <param name="Severity">Band derived from CVSS v3 or the database label, if any.</param>
/// <param name="Aliases">Other identifiers for the same advisory (CVE, PYSEC, GHSA...).</param>
public sealed record OsvVulnDetail(string Summary, Severity? Severity, IReadOnlyList<string> Aliases);
