using System.Runtime.InteropServices;
using System.Text.Json;
using SignalSentinel.Core.McpProtocol;

namespace SignalSentinel.Scanner.Config;

/// <summary>
/// Discovers MCP configurations from known application locations.
/// Security hardened with path validation and safe file reading.
/// </summary>
public static class ConfigDiscovery
{
    // Security: Maximum config file size to prevent memory exhaustion
    private const long MaxConfigFileSizeBytes = 10 * 1024 * 1024; // 10MB

    // Security: Maximum number of servers per config file
    private const int MaxServersPerConfig = 100;

    // Security: Allowed config file extensions
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".json"
    };

    /// <summary>
    /// Known MCP configuration file locations by application.
    /// </summary>
    private static readonly IReadOnlyList<(string Application, Func<string> PathResolver)> KnownConfigLocations =
    [
        ("Claude Desktop", GetClaudeDesktopConfigPath),
        ("Cursor", GetCursorConfigPath),
        ("VS Code", GetVsCodeConfigPath),
        ("Windsurf", GetWindsurfConfigPath),
        ("Zed", GetZedConfigPath)
    ];

    /// <summary>
    /// Discovers all MCP configurations from known locations.
    /// </summary>
    public static async Task<IReadOnlyList<McpConfigFile>> DiscoverAllAsync(CancellationToken cancellationToken = default)
    {
        var configs = new List<McpConfigFile>();

        foreach (var (application, pathResolver) in KnownConfigLocations)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var path = pathResolver();

                // Security: Validate path before accessing
                if (!IsPathSafe(path))
                {
                    continue;
                }

                if (File.Exists(path))
                {
                    var config = await ParseConfigFileAsync(path, application, cancellationToken);
                    if (config is not null && config.Servers.Count > 0)
                    {
                        configs.Add(config);
                    }
                }
            }
            catch (Exception)
            {
                // Security: Silently ignore errors for individual config files
                // Don't expose which paths failed or why
            }
        }

        return configs;
    }

    /// <summary>
    /// Parses a specific MCP configuration file with security validation.
    /// </summary>
    public static async Task<McpConfigFile?> ParseConfigFileAsync(
        string filePath,
        string sourceApplication,
        CancellationToken cancellationToken = default)
    {
        // Security: Validate file path
        if (!IsPathSafe(filePath))
        {
            return null;
        }

        // Security: Validate file extension
        var extension = Path.GetExtension(filePath);
        if (!AllowedExtensions.Contains(extension))
        {
            return null;
        }

        if (!File.Exists(filePath))
        {
            return null;
        }

        try
        {
            // Security: Check file size before reading
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > MaxConfigFileSizeBytes)
            {
                return null;
            }

            // Security: Read with cancellation support
            var json = await File.ReadAllTextAsync(filePath, cancellationToken);

            // Security: Validate JSON before parsing
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }

            // Security: Use safe JSON parsing options
            var jsonOptions = new JsonDocumentOptions
            {
                MaxDepth = 32,
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip
            };

            using var doc = JsonDocument.Parse(json, jsonOptions);
            var root = doc.RootElement;

            var servers = new List<McpServerConfig>();

            // Check for mcpServers property (Claude Desktop, Cursor format)
            if (root.TryGetProperty("mcpServers", out var mcpServers) && 
                mcpServers.ValueKind == JsonValueKind.Object)
            {
                foreach (var server in mcpServers.EnumerateObject())
                {
                    // Security: Limit servers per config
                    if (servers.Count >= MaxServersPerConfig)
                    {
                        break;
                    }

                    var config = ParseServerConfig(server.Name, server.Value, filePath);
                    if (config is not null)
                    {
                        servers.Add(config);
                    }
                }
            }

            // Check for servers array (alternative format)
            if (root.TryGetProperty("servers", out var serversArray) && 
                serversArray.ValueKind == JsonValueKind.Array)
            {
                foreach (var server in serversArray.EnumerateArray())
                {
                    // Security: Limit servers per config
                    if (servers.Count >= MaxServersPerConfig)
                    {
                        break;
                    }

                    if (server.TryGetProperty("name", out var nameElement) &&
                        nameElement.ValueKind == JsonValueKind.String)
                    {
                        var config = ParseServerConfig(nameElement.GetString() ?? "unknown", server, filePath);
                        if (config is not null)
                        {
                            servers.Add(config);
                        }
                    }
                }
            }

            return new McpConfigFile
            {
                FilePath = filePath,
                SourceApplication = sourceApplication,
                Servers = servers
            };
        }
        catch (JsonException)
        {
            // Security: Don't expose parsing errors
            return null;
        }
        catch (IOException)
        {
            // Security: Don't expose IO errors
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            // Security: Don't expose permission errors
            return null;
        }
    }

    /// <summary>
    /// Validates that a file path is safe to access.
    /// </summary>
    private static bool IsPathSafe(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            // Security: Get the full path to resolve any relative components
            var fullPath = Path.GetFullPath(path);

            // Security: Ensure path is within user profile or common app directories
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            var allowedRoots = new[] { userProfile, appData, localAppData }
                .Where(p => !string.IsNullOrEmpty(p))
                .ToArray();

            // Security: Path must be under an allowed root
            var isUnderAllowedRoot = allowedRoots.Any(root =>
                fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase));

            if (!isUnderAllowedRoot)
            {
                return false;
            }

            // Security: Check for path traversal attempts
            if (path.Contains("..") || 
                path.Contains('\0') ||
                path.Contains('\r') ||
                path.Contains('\n'))
            {
                return false;
            }

            // Security: Reject paths with suspicious patterns
            var suspicious = new[] { "/etc/", "\\windows\\", "/proc/", "/dev/" };
            if (suspicious.Any(s => fullPath.Contains(s, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            return true;
        }
        catch
        {
            // Security: If we can't validate the path, reject it
            return false;
        }
    }

    private static McpServerConfig? ParseServerConfig(string name, JsonElement element, string sourceFile)
    {
        try
        {
            // Security: Validate server name
            if (string.IsNullOrWhiteSpace(name) || name.Length > 256)
            {
                return null;
            }

            // Security: Remove control characters from name
            name = new string(name.Where(c => !char.IsControl(c)).ToArray());

            string? command = null;
            List<string>? args = null;
            Dictionary<string, string>? env = null;
            string? url = null;
            var transport = McpTransportType.Stdio;

            if (element.TryGetProperty("command", out var cmdElement) &&
                cmdElement.ValueKind == JsonValueKind.String)
            {
                command = cmdElement.GetString();

                // Security: Validate command
                if (command is not null && command.Length > 1000)
                {
                    command = command[..1000];
                }
            }

            if (element.TryGetProperty("args", out var argsElement) && 
                argsElement.ValueKind == JsonValueKind.Array)
            {
                args = [];
                var argCount = 0;
                foreach (var arg in argsElement.EnumerateArray())
                {
                    // Security: Limit number of arguments
                    if (++argCount > 100)
                    {
                        break;
                    }

                    if (arg.ValueKind == JsonValueKind.String)
                    {
                        var argValue = arg.GetString();
                        if (!string.IsNullOrEmpty(argValue))
                        {
                            // Security: Limit argument length
                            if (argValue.Length > 10000)
                            {
                                argValue = argValue[..10000];
                            }
                            args.Add(argValue);
                        }
                    }
                }
            }

            if (element.TryGetProperty("env", out var envElement) && 
                envElement.ValueKind == JsonValueKind.Object)
            {
                env = [];
                var envCount = 0;
                foreach (var prop in envElement.EnumerateObject())
                {
                    // Security: Limit number of environment variables
                    if (++envCount > 50)
                    {
                        break;
                    }

                    if (prop.Value.ValueKind == JsonValueKind.String)
                    {
                        var key = prop.Name;
                        var value = prop.Value.GetString();

                        // Security: Validate key and value
                        if (!string.IsNullOrEmpty(key) && key.Length <= 256 && value is not null)
                        {
                            // Security: Limit value length
                            if (value.Length > 10000)
                            {
                                value = value[..10000];
                            }
                            env[key] = value;
                        }
                    }
                }
            }

            if (element.TryGetProperty("url", out var urlElement) &&
                urlElement.ValueKind == JsonValueKind.String)
            {
                url = urlElement.GetString();

                // Security: Validate URL and determine transport
                if (url is not null)
                {
                    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                    {
                        url = null; // Invalid URL, ignore
                    }
                    else if (uri.Scheme is "ws" or "wss")
                    {
                        transport = McpTransportType.WebSocket;
                    }
                    else if (uri.Scheme is "http" or "https")
                    {
                        transport = McpTransportType.Http;
                    }
                    else
                    {
                        url = null; // Unsupported scheme, ignore
                    }
                }
            }

            if (element.TryGetProperty("transport", out var transportElement) &&
                transportElement.ValueKind == JsonValueKind.String)
            {
                var transportStr = transportElement.GetString()?.ToLowerInvariant();
                transport = transportStr switch
                {
                    "stdio" => McpTransportType.Stdio,
                    "http" or "sse" => McpTransportType.Http,
                    "streamable-http" => McpTransportType.StreamableHttp,
                    "websocket" or "ws" or "wss" => McpTransportType.WebSocket,
                    _ => McpTransportType.Stdio
                };
            }

            return new McpServerConfig
            {
                Name = name,
                Transport = transport,
                Command = command,
                Args = args,
                Env = env,
                Url = url,
                SourceConfigPath = sourceFile
            };
        }
        catch
        {
            // Security: Don't expose parsing errors
            return null;
        }
    }

    private static string GetClaudeDesktopConfigPath()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Claude", "claude_desktop_config.json");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library", "Application Support", "Claude", "claude_desktop_config.json");
        }
        else
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".config", "claude", "claude_desktop_config.json");
        }
    }

    private static string GetCursorConfigPath()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".cursor", "mcp.json");
    }

    private static string GetVsCodeConfigPath()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Code", "User", "settings.json");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library", "Application Support", "Code", "User", "settings.json");
        }
        else
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".config", "Code", "User", "settings.json");
        }
    }

    private static string GetWindsurfConfigPath()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".windsurf", "mcp.json");
    }

    private static string GetZedConfigPath()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Zed", "settings.json");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".config", "zed", "settings.json");
        }
        else
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".config", "zed", "settings.json");
        }
    }
}
