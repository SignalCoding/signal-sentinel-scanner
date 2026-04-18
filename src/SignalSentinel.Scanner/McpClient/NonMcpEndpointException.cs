// -----------------------------------------------------------------------
// <copyright file="NonMcpEndpointException.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Scanner.McpClient;

/// <summary>
/// Thrown when the scanner detects that an HTTP endpoint is not an MCP server at all
/// (for example: a React SPA with catch-all routing returning <c>text/html</c> for
/// every path). Callers catch this and populate <see cref="ServerEnumeration.NonMcpEvidence"/>
/// so the SS-INFO-001 rule can emit an informational finding.
/// </summary>
public sealed class NonMcpEndpointException : Exception
{
    /// <summary>
    /// Content-Type header observed on the first response.
    /// </summary>
    public string? ContentType { get; }

    /// <summary>
    /// First 200 characters of the response body (diagnostic snippet).
    /// </summary>
    public string? BodySnippet { get; }

    /// <summary>
    /// Short reason for the classification (e.g. "response body is HTML").
    /// </summary>
    public string ReasonText { get; }

    public NonMcpEndpointException(string reason, string? contentType, string? bodySnippet)
        : base($"Non-MCP endpoint: {reason}")
    {
        ReasonText = reason;
        ContentType = contentType;
        BodySnippet = bodySnippet;
    }

    public NonMcpEndpointException()
        : this("non-MCP endpoint", null, null)
    {
    }

    public NonMcpEndpointException(string message)
        : this(message, null, null)
    {
    }

    public NonMcpEndpointException(string message, Exception innerException)
        : base(message, innerException)
    {
        ReasonText = message;
    }
}
