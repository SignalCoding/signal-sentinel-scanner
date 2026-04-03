namespace SignalSentinel.Core.Models;

/// <summary>
/// Severity levels for security findings, aligned with OWASP and industry standards.
/// </summary>
public enum Severity
{
    /// <summary>
    /// Informational finding - no immediate security risk.
    /// </summary>
    Info = 0,

    /// <summary>
    /// Low severity - minor security concern.
    /// </summary>
    Low = 1,

    /// <summary>
    /// Medium severity - moderate security risk requiring attention.
    /// </summary>
    Medium = 2,

    /// <summary>
    /// High severity - significant security risk requiring prompt remediation.
    /// </summary>
    High = 3,

    /// <summary>
    /// Critical severity - severe security risk requiring immediate action.
    /// </summary>
    Critical = 4
}
