// -----------------------------------------------------------------------
// <copyright file="NonPublicTarget.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Net;
using System.Net.Sockets;

namespace SignalSentinel.Core.Network;

/// <summary>
/// Classifies scan targets as public (internet-routable) or non-public (loopback,
/// RFC 1918, link-local, DNS-to-loopback helpers). v2.4.0 A1 / A4.
/// </summary>
/// <remarks>
/// <para>
/// Rules that evaluate production transport posture (e.g. "remote MCP server must
/// use TLS") should not fire against non-public targets because such targets are
/// either already on an encrypted tunnel, running on the same host, or deliberately
/// not reachable from the internet. Firing an Insecure-Transport finding against
/// <c>http://127.0.0.1:5001/mcp</c> is a false positive - the TLS question does not
/// apply.
/// </para>
/// <para>
/// Instead of suppressing such findings silently, the scanner emits a dedicated
/// informational rule (SS-INFO-002) making it explicit to the operator that this
/// scan did not evaluate production posture. This avoids the failure mode where
/// a CI pipeline accidentally scans <c>http://localhost</c> and receives a clean
/// report.
/// </para>
/// </remarks>
public static class NonPublicTarget
{
    private static readonly string[] HostnameSuffixes =
    {
        ".local",
        ".internal",
        ".lan",
        ".home.arpa",
        ".lvh.me",
        ".nip.io",
    };

    private static readonly string[] LiteralHostnames =
    {
        "localhost",
    };

    /// <summary>
    /// Classification of a scan target.
    /// </summary>
    public enum Classification
    {
        /// <summary>
        /// Public, internet-routable target. Transport posture rules apply.
        /// </summary>
        Public,

        /// <summary>
        /// Loopback (127.0.0.0/8 or ::1). Typically an SSH tunnel.
        /// </summary>
        Loopback,

        /// <summary>
        /// RFC 1918 private address space (10/8, 172.16/12, 192.168/16).
        /// </summary>
        PrivateNetwork,

        /// <summary>
        /// Link-local (169.254/16 or fe80::/10).
        /// </summary>
        LinkLocal,

        /// <summary>
        /// Hostname matches a known non-public suffix (*.local, *.lvh.me, etc.).
        /// </summary>
        NonPublicHostname,

        /// <summary>
        /// Not an HTTP / HTTPS / WS / WSS URL (e.g. stdio transport, file://).
        /// </summary>
        NotNetworkTarget,

        /// <summary>
        /// Input could not be parsed; conservative default.
        /// </summary>
        Unknown,
    }

    /// <summary>
    /// Classifies a URL via its <see cref="Uri"/> form.
    /// </summary>
    public static Classification Classify(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (uri.Scheme is not ("http" or "https" or "ws" or "wss"))
        {
            return Classification.NotNetworkTarget;
        }
        return ClassifyHost(uri.Host);
    }

    /// <summary>
    /// Classifies a URL string or bare hostname. Returns <see cref="Classification.Public"/>
    /// if the target is internet-routable, or a specific non-public classification otherwise.
    /// </summary>
    /// <param name="urlOrHost">A URL ("https://example.com/mcp") or bare hostname.</param>
    /// <returns>The target classification.</returns>
    public static Classification Classify(string? urlOrHost)
    {
        if (string.IsNullOrWhiteSpace(urlOrHost))
        {
            return Classification.Unknown;
        }

        if (Uri.TryCreate(urlOrHost, UriKind.Absolute, out var parsed))
        {
            return Classify(parsed);
        }

        return ClassifyHost(urlOrHost.Trim());
    }

    /// <summary>
    /// Classifies a bare hostname or IP literal (no scheme, no port).
    /// </summary>
    public static Classification ClassifyHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return Classification.Unknown;
        }

        host = host.Trim().TrimEnd('.');

        // Strip IPv6 brackets: "[::1]" -> "::1"
        if (host.StartsWith('[') && host.EndsWith(']') && host.Length >= 2)
        {
            host = host[1..^1];
        }

        // Literal IP address?
        if (IPAddress.TryParse(host, out var ip))
        {
            return ClassifyAddress(ip);
        }

        // Hostname rules.
        foreach (var literal in LiteralHostnames)
        {
            if (string.Equals(host, literal, StringComparison.OrdinalIgnoreCase))
            {
                return Classification.Loopback;
            }
        }

        foreach (var suffix in HostnameSuffixes)
        {
            if (host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return Classification.NonPublicHostname;
            }
        }

        return Classification.Public;
    }

    /// <summary>
    /// Classifies a parsed IP address.
    /// </summary>
    public static Classification ClassifyAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (IPAddress.IsLoopback(address))
        {
            return Classification.Loopback;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            // 10.0.0.0/8
            if (bytes[0] == 10)
            {
                return Classification.PrivateNetwork;
            }
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                return Classification.PrivateNetwork;
            }
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168)
            {
                return Classification.PrivateNetwork;
            }
            // 169.254.0.0/16
            if (bytes[0] == 169 && bytes[1] == 254)
            {
                return Classification.LinkLocal;
            }
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal)
            {
                return Classification.LinkLocal;
            }
            if (address.IsIPv6SiteLocal)
            {
                return Classification.PrivateNetwork;
            }
            // Unique local fc00::/7
            var b = address.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC)
            {
                return Classification.PrivateNetwork;
            }
        }

        return Classification.Public;
    }

    /// <summary>
    /// Returns true when the classification indicates a non-public target whose
    /// transport posture should not be evaluated by public-facing rules.
    /// </summary>
    public static bool IsNonPublic(Classification c)
    {
        return c is Classification.Loopback
            or Classification.PrivateNetwork
            or Classification.LinkLocal
            or Classification.NonPublicHostname;
    }

    /// <summary>
    /// Returns a short operator-friendly label for a classification.
    /// </summary>
    public static string Label(Classification c) => c switch
    {
        Classification.Loopback => "loopback",
        Classification.PrivateNetwork => "RFC 1918 private network",
        Classification.LinkLocal => "link-local",
        Classification.NonPublicHostname => "non-public hostname",
        Classification.Public => "public",
        Classification.NotNetworkTarget => "non-network target",
        Classification.Unknown => "unknown",
        _ => "unknown",
    };
}
