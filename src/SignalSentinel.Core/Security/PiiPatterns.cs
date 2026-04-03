using System.Text.RegularExpressions;

namespace SignalSentinel.Core.Security;

/// <summary>
/// Regex patterns for detecting PII and sensitive data in tool descriptions.
/// Used for OWASP ASI09 (Sensitive Data Leakage) detection.
/// </summary>
public static partial class PiiPatterns
{
    /// <summary>
    /// UK National Insurance Number pattern.
    /// </summary>
    [GeneratedRegex(
        @"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    public static partial Regex UkNationalInsuranceNumber();

    /// <summary>
    /// UK NHS Number pattern.
    /// </summary>
    [GeneratedRegex(
        @"\b\d{3}\s?\d{3}\s?\d{4}\b",
        RegexOptions.Compiled)]
    public static partial Regex UkNhsNumber();

    /// <summary>
    /// UK Passport Number pattern.
    /// </summary>
    [GeneratedRegex(
        @"\b\d{9}\b",
        RegexOptions.Compiled)]
    public static partial Regex UkPassportNumber();

    /// <summary>
    /// Credit card number pattern (major cards).
    /// </summary>
    [GeneratedRegex(
        @"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        RegexOptions.Compiled)]
    public static partial Regex CreditCardNumber();

    /// <summary>
    /// Email address pattern.
    /// </summary>
    [GeneratedRegex(
        @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        RegexOptions.Compiled)]
    public static partial Regex EmailAddress();

    /// <summary>
    /// UK phone number pattern.
    /// </summary>
    [GeneratedRegex(
        @"\b(?:(?:\+44\s?|0)(?:7\d{3}|\d{4})[\s.-]?\d{3}[\s.-]?\d{3,4})\b",
        RegexOptions.Compiled)]
    public static partial Regex UkPhoneNumber();

    /// <summary>
    /// UK postcode pattern.
    /// </summary>
    [GeneratedRegex(
        @"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    public static partial Regex UkPostcode();

    /// <summary>
    /// IP address pattern (IPv4).
    /// </summary>
    [GeneratedRegex(
        @"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        RegexOptions.Compiled)]
    public static partial Regex IpAddressV4();

    /// <summary>
    /// API key patterns (generic).
    /// </summary>
    [GeneratedRegex(
        @"\b(sk-[a-zA-Z0-9]{32,}|api[_-]?key[_-]?[=:]\s*['""]?[a-zA-Z0-9]{16,}|bearer\s+[a-zA-Z0-9._-]{20,})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    public static partial Regex ApiKeyPattern();

    /// <summary>
    /// All PII detection patterns with metadata.
    /// </summary>
    public static IReadOnlyList<PiiPattern> AllPatterns { get; } =
    [
        new("PII-001", "UK National Insurance Number", UkNationalInsuranceNumber(), "NINO"),
        new("PII-002", "UK NHS Number", UkNhsNumber(), "NHS Number"),
        new("PII-003", "Credit Card Number", CreditCardNumber(), "Credit Card"),
        new("PII-004", "Email Address", EmailAddress(), "Email"),
        new("PII-005", "UK Phone Number", UkPhoneNumber(), "Phone"),
        new("PII-006", "UK Postcode", UkPostcode(), "Postcode"),
        new("PII-007", "IP Address (v4)", IpAddressV4(), "IP Address"),
        new("PII-008", "API Key / Secret", ApiKeyPattern(), "API Key")
    ];
}

/// <summary>
/// Represents a PII detection pattern.
/// </summary>
public sealed record PiiPattern(
    string Id,
    string Name,
    Regex Pattern,
    string DataType
);
