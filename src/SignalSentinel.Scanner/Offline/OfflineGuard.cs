// -----------------------------------------------------------------------
// <copyright file="OfflineGuard.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Scanner.Offline;

/// <summary>
/// Gatekeeper for outbound network operations.
/// When enabled, any attempt to perform HTTP/WebSocket/DNS work throws
/// <see cref="OfflineViolationException"/>. Ensures Scanner honours the
/// <c>--offline</c> contract for air-gapped customers.
/// </summary>
public static class OfflineGuard
{
    private static bool _offlineEnabled;

    /// <summary>
    /// Whether offline mode is currently enforced for this process.
    /// Set once at program start; callers use <see cref="EnsureAllowed"/>
    /// or <see cref="IsOffline"/> to consult the state.
    /// </summary>
    public static bool IsOffline => _offlineEnabled;

    /// <summary>
    /// Enables offline enforcement. Safe to call multiple times.
    /// </summary>
    public static void Enable() => _offlineEnabled = true;

    /// <summary>
    /// Resets offline enforcement. Intended for test scenarios where the static state
    /// must be cleared between runs; production code paths enable offline once at startup.
    /// </summary>
    public static void Reset() => _offlineEnabled = false;

    /// <summary>
    /// Throws if offline mode is enabled. Call at every network entry point.
    /// </summary>
    /// <param name="operation">Short description of the attempted operation (e.g. "HTTP GET", "WebSocket connect").</param>
    public static void EnsureAllowed(string operation)
    {
        if (_offlineEnabled)
        {
            throw new OfflineViolationException(operation);
        }
    }
}

/// <summary>
/// Thrown when code attempts a network operation while Scanner is in offline mode.
/// </summary>
public sealed class OfflineViolationException : InvalidOperationException
{
    /// <summary>
    /// Initialises a new instance of the <see cref="OfflineViolationException"/> class.
    /// </summary>
    public OfflineViolationException()
        : base("Network operation blocked by --offline mode.")
    {
    }

    /// <summary>
    /// Initialises a new instance of the <see cref="OfflineViolationException"/> class.
    /// </summary>
    /// <param name="operation">Operation that was attempted.</param>
    public OfflineViolationException(string operation)
        : base($"Network operation blocked by --offline mode: {operation}")
    {
        Operation = operation;
    }

    /// <summary>
    /// Initialises a new instance of the <see cref="OfflineViolationException"/> class.
    /// </summary>
    /// <param name="message">Custom message.</param>
    /// <param name="innerException">Inner exception.</param>
    public OfflineViolationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>
    /// The operation that was attempted when offline mode blocked execution.
    /// </summary>
    public string? Operation { get; }
}
