> # [SUPERSEDED - archived 2026-04-18]
>
> **This document has been superseded by the v2.0 dashboard ingestion spec.**
>
> The v1.0 push-model approach documented below was reviewed against the Scanner v2.3.x codebase and rejected in favour of an operator-mediated, pull-ingest model. Key reasons:
>
> 1. The push model turned the scanner into a network client by default, breaking its offline-capable, deterministic, no-telemetry positioning.
> 2. It collided with `--offline` mode (`OfflineGuard.Enable()` would throw mid-push).
> 3. It required scanner APIs that did not exist (`McpConnection.CallToolAsync`, `ServerEnumeration.Connection`).
> 4. It created a trust boundary where the scanner had to validate dashboard-returned URLs.
> 5. It did not account for interactions with `SS-INFO-001` (dashboard could be flagged non-MCP mid-scan and still be pushed to) or suppressions (counter-factual grades were absent from the DB schema).
>
> The replacement spec inverts the trust model: the scanner emits `scan.json`; the operator moves the artefact; the dashboard validates and ingests. See the new spec for the full rationale in its section 0.
>
> This file is retained for historical record only. Do not implement.
>
> ---
># Scanner-Dashboard Integration Specification

> **Version**: 2.0.0  
> **Date**: 2026-04-18  
> **Status**: Approved for Implementation

## Overview

This document specifies how **Signal Sentinel Scanner** (v2.4.0+) integrates with **Signal Sentinel Dashboard** to enable:

1. **MCP-native integration**: Scanner auto-discovers Dashboard MCP server and pushes via `submit_scan` tool
2. **HTTP fallback**: Scanner can push via REST API when MCP not available
3. Dashboard displays scan history (newest first)
4. Users can drill down into findings from the Dashboard UI
5. Gateway remains independent (Dashboard is optional UI layer)

## Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                           User Workstation / CI Environment                  â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚                                                                             â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                                                        â”‚
â”‚  â”‚ Scanner CLI     â”‚                                                        â”‚
â”‚  â”‚ sentinel-scan   â”‚                                                        â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”˜                                                        â”‚
â”‚           â”‚                                                                 â”‚
â”‚           â”‚ 1. Discovers MCP configs                                        â”‚
â”‚           â”‚ 2. Enumerates all servers (including Dashboard)                 â”‚
â”‚           â”‚ 3. Runs security rules                                          â”‚
â”‚           â”‚ 4. Detects "sentinel-dashboard" MCP with submit_scan tool       â”‚
â”‚           â”‚ 5. Pushes scan result via MCP tool call                         â”‚
â”‚           â”‚                                                                 â”‚
â”‚           â–¼                                                                 â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”‚
â”‚  â”‚                    Push Strategy (Priority Order)                    â”‚   â”‚
â”‚  â”‚                                                                      â”‚   â”‚
â”‚  â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚   â”‚
â”‚  â”‚  â”‚ Option A: MCP Tool   â”‚    â”‚ Option B: HTTP API                 â”‚ â”‚   â”‚
â”‚  â”‚  â”‚ (Auto-discovered)    â”‚    â”‚ (--push-to flag)                   â”‚ â”‚   â”‚
â”‚  â”‚  â”‚                      â”‚    â”‚                                    â”‚ â”‚   â”‚
â”‚  â”‚  â”‚ tools/call:          â”‚    â”‚ POST /api/scans                    â”‚ â”‚   â”‚
â”‚  â”‚  â”‚   submit_scan        â”‚    â”‚ Authorization: Bearer <key>        â”‚ â”‚   â”‚
â”‚  â”‚  â”‚   {scan_result:...}  â”‚    â”‚ Content-Type: application/json     â”‚ â”‚   â”‚
â”‚  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â”‚   â”‚
â”‚  â”‚             â”‚                               â”‚                       â”‚   â”‚
â”‚  â”‚             â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                       â”‚   â”‚
â”‚  â”‚                             â”‚                                       â”‚   â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚
â”‚                                â–¼                                           â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”‚
â”‚  â”‚                      Dashboard (MCP Server + Blazor UI)              â”‚   â”‚
â”‚  â”‚                                                                      â”‚   â”‚
â”‚  â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚   â”‚
â”‚  â”‚  â”‚ MCP Interface   â”‚  â”‚ Scan Store      â”‚  â”‚ Blazor UI           â”‚  â”‚   â”‚
â”‚  â”‚  â”‚                 â”‚  â”‚ (SQLite)        â”‚  â”‚                     â”‚  â”‚   â”‚
â”‚  â”‚  â”‚ Tools:          â”‚  â”‚                 â”‚  â”‚ - Scan list         â”‚  â”‚   â”‚
â”‚  â”‚  â”‚ - submit_scan   â”‚â”€â”€â”‚ INSERT scan     â”‚  â”‚ - Findings detail   â”‚  â”‚   â”‚
â”‚  â”‚  â”‚ - list_scans    â”‚  â”‚                 â”‚  â”‚ - Trend charts      â”‚  â”‚   â”‚
â”‚  â”‚  â”‚ - get_scan      â”‚  â”‚                 â”‚  â”‚ - Grade history     â”‚  â”‚   â”‚
â”‚  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚   â”‚
â”‚  â”‚                                                                      â”‚   â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚
â”‚                                                                             â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Integration Methods

### Method 1: MCP Tool Discovery (Preferred - Zero Config)

When Scanner discovers a Dashboard MCP server during `--discover`, it automatically pushes the scan result via the `submit_scan` tool. **No additional flags required.**

```bash
# Scanner auto-discovers dashboard and pushes scan
sentinel-scan --discover --skills

# Output:
# Signal Sentinel Scanner v2.4.0
# ================================
# Discovering MCP configurations...
# Found 3 configuration file(s)
# ...
# Found sentinel-dashboard MCP server with submit_scan tool
# Pushing scan via MCP...
# Scan submitted: scan_20260418T143000Z_abc123
# View at: https://dashboard.local:5001/scans/scan_20260418T143000Z_abc123
```

### Method 2: HTTP API (Explicit - For Remote/CI)

When Dashboard MCP is not discoverable (e.g., remote server, CI pipeline), use explicit HTTP push.

```bash
# Explicit HTTP push
sentinel-scan --discover --push-to https://dashboard.example.com --api-key <key>

# CI/CD example
sentinel-scan --discover --skills --ci \
  --push-to $DASHBOARD_URL \
  --api-key $DASHBOARD_API_KEY
```

### Method 3: Disable Auto-Push

To scan without pushing (local history only):

```bash
sentinel-scan --discover --no-push
```

### Push Priority Logic

```
1. If --no-push specified â†’ Skip all remote push
2. If Dashboard MCP discovered with submit_scan tool â†’ Use MCP
3. Else if --push-to specified â†’ Use HTTP API  
4. Else â†’ Local history only (no remote push)
```

---

## Scanner Changes Required (v2.4.0)

### 1. New CLI Flags

| Flag | Description |
|------|-------------|
| `--push-to <url>` | HTTP API endpoint for Dashboard |
| `--api-key <key>` | API key for HTTP authentication |
| `--no-push` | Disable auto-push even if Dashboard MCP found |

**Implementation in `Program.cs`:**

```csharp
case "--push-to":
    if (i + 1 < args.Length)
    {
        var url = args[++i];
        if (!ValidateUrl(url))
        {
            Console.Error.WriteLine("Error: Invalid dashboard URL");
            return null;
        }
        config = config with { PushToDashboard = url };
    }
    break;

case "--api-key":
    if (i + 1 < args.Length)
    {
        config = config with { DashboardApiKey = args[++i] };
    }
    break;

case "--no-push":
    config = config with { NoPush = true };
    break;
```

### 2. New `ScanConfig` Properties

```csharp
// In Config/ScanConfig.cs
public record ScanConfig
{
    // ... existing properties ...
    
    /// <summary>Dashboard URL for HTTP push (optional).</summary>
    public string? PushToDashboard { get; init; }
    
    /// <summary>API key for Dashboard HTTP authentication.</summary>
    public string? DashboardApiKey { get; init; }
    
    /// <summary>Disable auto-push to Dashboard MCP.</summary>
    public bool NoPush { get; init; }
}
```

### 3. Dashboard MCP Detection

Create `src/SignalSentinel.Scanner/Dashboard/DashboardMcpDetector.cs`:

```csharp
using SignalSentinel.Scanner.McpClient;

namespace SignalSentinel.Scanner.Dashboard;

/// <summary>
/// Detects Dashboard MCP server among enumerated servers.
/// </summary>
public static class DashboardMcpDetector
{
    /// <summary>
    /// Dashboard server names to look for (case-insensitive).
    /// </summary>
    private static readonly string[] DashboardServerNames =
    [
        "sentinel-dashboard",
        "signal-sentinel-dashboard",
        "dashboard"
    ];

    /// <summary>
    /// Required tool name for scan submission.
    /// </summary>
    public const string SubmitScanTool = "submit_scan";

    /// <summary>
    /// Finds a Dashboard MCP server with submit_scan capability.
    /// </summary>
    public static ServerEnumeration? FindDashboard(IEnumerable<ServerEnumeration> servers)
    {
        foreach (var server in servers)
        {
            // Check server name matches
            var nameMatch = DashboardServerNames.Any(name =>
                server.ServerName.Contains(name, StringComparison.OrdinalIgnoreCase));
            
            if (!nameMatch)
                continue;
            
            // Check has submit_scan tool
            var hasSubmitTool = server.Tools.Any(t =>
                string.Equals(t.Name, SubmitScanTool, StringComparison.OrdinalIgnoreCase));
            
            if (hasSubmitTool)
                return server;
        }
        
        return null;
    }
}
```

### 4. MCP Push Client

Create `src/SignalSentinel.Scanner/Dashboard/DashboardMcpPusher.cs`:

```csharp
using System.Text.Json;
using System.Text.Json.Serialization;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;

namespace SignalSentinel.Scanner.Dashboard;

/// <summary>
/// Pushes scan results to Dashboard via MCP tools/call.
/// </summary>
public sealed class DashboardMcpPusher
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    /// <summary>
    /// Pushes scan result via MCP submit_scan tool.
    /// </summary>
    public static async Task<DashboardPushResponse> PushAsync(
        McpConnection connection,
        ScanResult result,
        CancellationToken cancellationToken = default)
    {
        // Serialize scan result to JSON for the tool argument
        var scanJson = JsonSerializer.Serialize(result, JsonOptions);
        
        // Call tools/call with submit_scan
        var toolResult = await connection.CallToolAsync(
            DashboardMcpDetector.SubmitScanTool,
            new Dictionary<string, object>
            {
                ["scan_result"] = JsonDocument.Parse(scanJson).RootElement
            },
            cancellationToken);
        
        // Parse response
        if (toolResult.IsError)
        {
            throw new InvalidOperationException(
                $"Dashboard rejected scan: {toolResult.ErrorMessage}");
        }
        
        // Extract scan ID and URL from tool response
        var responseJson = toolResult.Content.FirstOrDefault()?.Text
            ?? throw new InvalidOperationException("Empty response from Dashboard");
        
        return JsonSerializer.Deserialize<DashboardPushResponse>(responseJson, JsonOptions)
            ?? throw new InvalidOperationException("Invalid response format from Dashboard");
    }
}
```

### 5. HTTP Push Client (Fallback)

Create `src/SignalSentinel.Scanner/Dashboard/DashboardHttpClient.cs`:

```csharp
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Dashboard;

/// <summary>
/// Pushes scan results to Dashboard via HTTP API.
/// </summary>
public sealed class DashboardHttpClient : IDisposable
{
    private readonly HttpClient _client;
    private readonly string _baseUrl;
    
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public DashboardHttpClient(string baseUrl, string? apiKey = null)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        
        if (!string.IsNullOrEmpty(apiKey))
        {
            _client.DefaultRequestHeaders.Authorization = 
                new AuthenticationHeaderValue("Bearer", apiKey);
        }
    }

    public async Task<DashboardPushResponse> PushScanAsync(
        ScanResult result, 
        CancellationToken cancellationToken = default)
    {
        var response = await _client.PostAsJsonAsync(
            $"{_baseUrl}/api/scans", result, JsonOptions, cancellationToken);
        
        response.EnsureSuccessStatusCode();
        
        return await response.Content.ReadFromJsonAsync<DashboardPushResponse>(
            JsonOptions, cancellationToken) 
            ?? throw new InvalidOperationException("Empty response from Dashboard");
    }

    public void Dispose() => _client.Dispose();
}

/// <summary>
/// Response from Dashboard after pushing a scan.
/// </summary>
public sealed record DashboardPushResponse
{
    public required string ScanId { get; init; }
    public required string ViewUrl { get; init; }
    public required DateTimeOffset ReceivedAt { get; init; }
}
```

### 6. Integration in `RunScanAsync`

After building the scan result, add this push logic:

```csharp
// Push to Dashboard (MCP or HTTP)
if (!config.NoPush)
{
    var pushed = false;
    
    // Try MCP push first (auto-discovered)
    var dashboardServer = DashboardMcpDetector.FindDashboard(serverEnumerations);
    if (dashboardServer is not null && dashboardServer.ConnectionSuccessful)
    {
        try
        {
            Log($"Found Dashboard MCP: {dashboardServer.ServerName}");
            Log("Pushing scan via MCP submit_scan tool...");
            
            // Re-use existing connection from enumeration
            var pushResponse = await DashboardMcpPusher.PushAsync(
                dashboardServer.Connection!, result, cancellationToken);
            
            Log($"Scan submitted: {pushResponse.ScanId}");
            Log($"View at: {pushResponse.ViewUrl}");
            pushed = true;
        }
        catch (Exception ex)
        {
            Log($"MCP push failed: {SanitizeErrorMessage(ex.Message)}");
            // Fall through to HTTP if available
        }
    }
    
    // Fall back to HTTP push if MCP failed or not available
    if (!pushed && config.PushToDashboard is not null)
    {
        try
        {
            Log($"Pushing scan via HTTP: {SanitizeForDisplay(config.PushToDashboard)}");
            using var httpClient = new DashboardHttpClient(
                config.PushToDashboard, config.DashboardApiKey);
            
            var pushResponse = await httpClient.PushScanAsync(result, cancellationToken);
            Log($"Scan submitted: {pushResponse.ScanId}");
            Log($"View at: {pushResponse.ViewUrl}");
            pushed = true;
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine($"Warning: HTTP push failed: {SanitizeErrorMessage(ex.Message)}");
        }
    }
    
    if (!pushed && dashboardServer is null && config.PushToDashboard is null)
    {
        Log("No Dashboard detected. Use --push-to <url> for remote push.");
    }
}
```

---

## Dashboard MCP Server Specification

The Dashboard must expose an MCP server interface with these tools:

### Tool: `submit_scan`

Receives a scan result from Scanner.

```json
{
  "name": "submit_scan",
  "description": "Submit a security scan report from Signal Sentinel Scanner",
  "inputSchema": {
    "type": "object",
    "properties": {
      "scan_result": {
        "type": "object",
        "description": "Complete ScanResult object from Scanner"
      }
    },
    "required": ["scan_result"]
  }
}
```

**Response (in tool result content):**

```json
{
  "scanId": "scan_20260418T143000Z_abc123",
  "viewUrl": "https://dashboard.local:5001/scans/scan_20260418T143000Z_abc123",
  "receivedAt": "2026-04-18T14:30:01Z"
}
```

**Error handling:**

```json
{
  "isError": true,
  "content": [{"type": "text", "text": "Invalid scan format: missing scanTimestamp"}]
}
```

### Tool: `list_scans` (Optional - for AI agents)

```json
{
  "name": "list_scans",
  "description": "List recent security scans",
  "inputSchema": {
    "type": "object",
    "properties": {
      "limit": {"type": "integer", "default": 10, "maximum": 100},
      "environment": {"type": "string"},
      "min_grade": {"type": "string", "enum": ["A", "B", "C", "D", "F"]}
    }
  }
}
```

### Tool: `get_scan` (Optional - for AI agents)

```json
{
  "name": "get_scan",
  "description": "Get full details of a specific scan",
  "inputSchema": {
    "type": "object",
    "properties": {
      "scan_id": {"type": "string"}
    },
    "required": ["scan_id"]
  }
}
```

---

## Dashboard HTTP API (Fallback)

### POST `/api/scans`

Same as MCP `submit_scan` but via HTTP.

**Request:**
```http
POST /api/scans HTTP/1.1
Authorization: Bearer <api-key>
Content-Type: application/json

{ ...ScanResult... }
```

**Response:**
```json
{
  "scanId": "scan_20260418T143000Z_abc123",
  "viewUrl": "https://dashboard.example.com/scans/...",
  "receivedAt": "2026-04-18T14:30:01Z"
}
```

### GET `/api/scans`

List scans with filtering.

### GET `/api/scans/{scanId}`

Get full scan details.

---

## Dashboard Database Schema

```sql
CREATE TABLE Scans (
    Id TEXT PRIMARY KEY,
    Timestamp TEXT NOT NULL,
    ScannerVersion TEXT NOT NULL,
    Grade TEXT NOT NULL,
    Score INTEGER NOT NULL,
    Environment TEXT,
    RubricVersion TEXT,
    ServerCount INTEGER NOT NULL,
    SkillCount INTEGER NOT NULL,
    FindingCount INTEGER NOT NULL,
    CriticalCount INTEGER NOT NULL,
    HighCount INTEGER NOT NULL,
    MediumCount INTEGER NOT NULL,
    LowCount INTEGER NOT NULL,
    InfoCount INTEGER NOT NULL,
    ScanDurationMs INTEGER NOT NULL,
    RawJson TEXT NOT NULL,
    ReceivedAt TEXT NOT NULL,
    SourceType TEXT NOT NULL,  -- 'mcp' or 'http'
    SourceIp TEXT,
    DeletedAt TEXT
);

CREATE INDEX IX_Scans_Timestamp ON Scans(Timestamp DESC);
CREATE INDEX IX_Scans_Environment ON Scans(Environment);
CREATE INDEX IX_Scans_Grade ON Scans(Grade);
```

---

## Security Considerations

### MCP Push Security

1. **No additional auth needed** - MCP connection already authenticated
2. **Size limit**: Dashboard should reject scans > 10MB
3. **Rate limit**: Max 60 scans/minute per MCP client
4. **Validation**: Reject malformed ScanResult objects

### HTTP Push Security

1. **API key required**: `Authorization: Bearer <key>`
2. **TLS required**: HTTPS only in production
3. **Rate limit**: 60 scans/minute per API key
4. **IP allowlist**: Optional for enterprise

### Scanner Security

1. **Don't include Dashboard findings in scan**: When scanning Dashboard MCP, exclude its own submit_scan tool from findings
2. **Sanitize before push**: Strip any PII from local paths before sending
3. **Fail gracefully**: Push failures don't fail the scan

---

## Testing

### Scanner Unit Tests

```csharp
[Fact]
public void DashboardMcpDetector_FindsDashboard_WithSubmitScanTool()
{
    var servers = new[]
    {
        CreateServer("filesystem", ["read_file", "write_file"]),
        CreateServer("sentinel-dashboard", ["submit_scan", "list_scans"]),
    };
    
    var dashboard = DashboardMcpDetector.FindDashboard(servers);
    
    Assert.NotNull(dashboard);
    Assert.Equal("sentinel-dashboard", dashboard.ServerName);
}

[Fact]
public void DashboardMcpDetector_ReturnsNull_WhenNoSubmitScanTool()
{
    var servers = new[]
    {
        CreateServer("sentinel-dashboard", ["list_scans", "get_scan"]), // Missing submit_scan
    };
    
    var dashboard = DashboardMcpDetector.FindDashboard(servers);
    
    Assert.Null(dashboard);
}
```

### Dashboard Integration Tests

```csharp
[Fact]
public async Task SubmitScan_ViaHttp_Returns201()
{
    var client = _factory.CreateClient();
    var scan = CreateTestScanResult();
    
    var response = await client.PostAsJsonAsync("/api/scans", scan);
    
    Assert.Equal(HttpStatusCode.Created, response.StatusCode);
}

[Fact]
public async Task SubmitScan_ViaMcp_StoresScan()
{
    var mcpClient = CreateMcpClient();
    var scan = CreateTestScanResult();
    
    var result = await mcpClient.CallToolAsync("submit_scan", new { scan_result = scan });
    
    Assert.False(result.IsError);
    var response = JsonSerializer.Deserialize<DashboardPushResponse>(result.Content[0].Text);
    Assert.NotNull(response?.ScanId);
}
```

---

## Migration Path

| Phase | Scanner | Dashboard | Status |
|-------|---------|-----------|--------|
| 1 | Add `--push-to`, `--api-key` flags | Add HTTP `/api/scans` endpoint | Ready |
| 2 | Add MCP auto-detection | Add MCP server with `submit_scan` | Ready |
| 3 | Add `--no-push` flag | Add `list_scans`, `get_scan` tools | Ready |
| 4 | Release v2.4.0 | Deploy to VPS | Pending |

---

## Appendix: Full ScanResult Schema

See `SignalSentinel.Core.Models.ScanResult` - the Dashboard accepts this exact format via both MCP and HTTP.

