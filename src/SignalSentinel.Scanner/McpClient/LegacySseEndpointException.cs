// -----------------------------------------------------------------------
// <copyright file="LegacySseEndpointException.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Scanner.McpClient;

/// <summary>
/// v3.0.0: thrown when an HTTP endpoint rejects the JSON-RPC POST but opens a
/// <c>text/event-stream</c> on GET, i.e. it is an MCP server on the legacy
/// HTTP+SSE transport (retired by the 2025-03-26 specification) which this client
/// does not speak. Callers catch it and populate
/// <see cref="ServerEnumeration.LegacySseEvidence"/> so SS-INFO-004 can report the
/// target as detected-but-not-scanned rather than as a non-MCP endpoint.
/// </summary>
public sealed class LegacySseEndpointException : Exception
{
    /// <summary>
    /// HTTP status the endpoint returned for the JSON-RPC POST (typically 405).
    /// </summary>
    public int PostStatusCode { get; }

    public LegacySseEndpointException(int postStatusCode)
        : base($"Legacy HTTP+SSE endpoint: POST returned {postStatusCode}, GET opened text/event-stream")
    {
        PostStatusCode = postStatusCode;
    }

    public LegacySseEndpointException()
        : this(0)
    {
    }

    public LegacySseEndpointException(string message)
        : base(message)
    {
    }

    public LegacySseEndpointException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
