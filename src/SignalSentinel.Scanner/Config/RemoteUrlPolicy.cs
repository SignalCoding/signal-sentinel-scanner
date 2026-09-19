// -----------------------------------------------------------------------
// <copyright file="RemoteUrlPolicy.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Net;
using System.Net.Sockets;

namespace SignalSentinel.Scanner.Config;

/// <summary>
/// Validates <c>--remote</c> targets. Syntax checks always apply; the private-network
/// (SSRF) check is applied unless the operator has passed <c>--allow-private</c>.
/// </summary>
/// <remarks>
/// v3.0.0: the SSRF block previously lived inline in <c>Program.ValidateUrl</c> and could
/// not be bypassed, which contradicted SS-INFO-002 (which exists precisely to annotate
/// scans of non-public targets). Splitting syntax from network policy lets the CLI
/// accept a loopback/RFC1918 target when explicitly asked to and still emit SS-INFO-002.
/// The check resolves DNS at validation time only; a host that changes its answer between
/// validation and connection (DNS rebinding) is not defended against here.
/// </remarks>
internal static class RemoteUrlPolicy
{
    internal const int MaxUrlLength = 2048;

    private static readonly HashSet<string> AllowedSchemes =
        new(StringComparer.Ordinal) { "http", "https", "ws", "wss" };

    /// <summary>
    /// Returns true when the URL is absolute, within length limits, and uses an
    /// http/https/ws/wss scheme. Performs no network I/O.
    /// </summary>
    internal static bool IsValidSyntax(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || url.Length > MaxUrlLength)
        {
            return false;
        }

        return Uri.TryCreate(url, UriKind.Absolute, out var uri)
            && AllowedSchemes.Contains(uri.Scheme);
    }

    /// <summary>
    /// Returns true when the URL host resolves to at least one loopback, RFC1918,
    /// link-local, or IPv6 link-local address. Returns false when DNS resolution fails
    /// (the caller should not block on a DNS failure).
    /// </summary>
    internal static bool TargetsPrivateNetwork(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        IPAddress[] addresses;
        try
        {
            addresses = Dns.GetHostAddresses(uri.DnsSafeHost);
        }
        catch (SocketException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }

        return addresses.Any(IsPrivateAddress);
    }

    /// <summary>
    /// Classifies a single address as private/non-routable for SSRF purposes.
    /// </summary>
    internal static bool IsPrivateAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            // 10.0.0.0/8
            if (bytes[0] == 10)
            {
                return true;
            }

            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                return true;
            }

            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168)
            {
                return true;
            }

            // 169.254.0.0/16 link-local, includes cloud metadata 169.254.169.254
            if (bytes[0] == 169 && bytes[1] == 254)
            {
                return true;
            }

            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // fe80::/10 link-local
            if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
            {
                return true;
            }

            // fc00::/7 unique local
            if ((bytes[0] & 0xfe) == 0xfc)
            {
                return true;
            }

            // IPv4-mapped IPv6 (::ffff:a.b.c.d) - classify by the embedded IPv4
            if (address.IsIPv4MappedToIPv6)
            {
                return IsPrivateAddress(address.MapToIPv4());
            }
        }

        return false;
    }
}
