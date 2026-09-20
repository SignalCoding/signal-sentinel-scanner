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
    /// Allowed root directories for user-level config discovery.
    /// </summary>
    private static IReadOnlyList<string> UserRoots
    {
        get
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return new[] { userProfile, appData, localAppData }
                .Where(p => !string.IsNullOrEmpty(p))
                .ToArray();
        }
    }

    /// <summary>
    /// v3.0.0 (WP8): user-level MCP configuration candidates by application. Pure path
    /// construction, split out from discovery so the catalogue is testable.
    /// </summary>
    internal static IReadOnlyList<(string Application, string FullPath)> UserConfigCandidates(
        string userProfile, string appData, string localAppData)
    {
        var windows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        var osx = RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

        string ClaudeDesktop() => windows
            ? Path.Combine(appData, "Claude", "claude_desktop_config.json")
            : osx
                ? Path.Combine(userProfile, "Library", "Application Support", "Claude", "claude_desktop_config.json")
                : Path.Combine(userProfile, ".config", "claude", "claude_desktop_config.json");

        string VsCodeUserDir() => windows
            ? Path.Combine(appData, "Code", "User")
            : osx
                ? Path.Combine(userProfile, "Library", "Application Support", "Code", "User")
                : Path.Combine(userProfile, ".config", "Code", "User");

        string ZedDir() => windows
            ? Path.Combine(appData, "Zed")
            : Path.Combine(userProfile, ".config", "zed");

        return
        [
            ("Claude Desktop", ClaudeDesktop()),
            ("Cursor", Path.Combine(userProfile, ".cursor", "mcp.json")),
            ("VS Code", Path.Combine(VsCodeUserDir(), "settings.json")),
            ("Windsurf", Path.Combine(userProfile, ".windsurf", "mcp.json")),
            ("Zed", Path.Combine(ZedDir(), "settings.json")),
            ("Claude Code", Path.Combine(userProfile, ".claude.json")),
            ("Gemini CLI", Path.Combine(userProfile, ".gemini", "settings.json")),
            ("OpenCode", Path.Combine(userProfile, ".config", "opencode", "opencode.json")),
            ("VS Code / Copilot", Path.Combine(VsCodeUserDir(), "mcp.json")),
            ("GitHub Copilot (JetBrains)", Path.Combine(userProfile, ".config", "github-copilot", "intellij", "mcp.json")),
            ("Amazon Q Developer", Path.Combine(userProfile, ".aws", "amazonq", "mcp.json")),
        ];
    }

    /// <summary>
    /// v3.0.0 (WP8): project-level MCP configuration candidates, relative to the current
    /// working directory. Codex CLI's config.toml is out of scope (TOML).
    /// </summary>
    internal static IReadOnlyList<(string Application, string RelativePath)> ProjectConfigCandidates =>
    [
        ("Claude Code (project)", ".mcp.json"),
        ("Gemini CLI (project)", Path.Combine(".gemini", "settings.json")),
        ("OpenCode (project)", "opencode.json"),
        ("VS Code / Copilot (project)", Path.Combine(".vscode", "mcp.json")),
        ("Amazon Q Developer (project)", Path.Combine(".amazonq", "mcp.json")),
        ("Cursor (project)", Path.Combine(".cursor", "mcp.json")),
    ];

    /// <summary>
    /// Discovers all MCP configurations from known locations.
    /// </summary>
    public static async Task<IReadOnlyList<McpConfigFile>> DiscoverAllAsync(CancellationToken cancellationToken = default)
    {
        var configs = new List<McpConfigFile>();

        // v3.0.0 (WP8): the same file can appear as both a user-level and a
        // project-level candidate (e.g. running the scanner with CWD == the user
        // profile); each path is loaded once.
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userRoots = UserRoots;

        foreach (var (application, path) in UserConfigCandidates(userProfile, appData, localAppData))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!seenPaths.Add(Path.GetFullPath(path)))
            {
                continue;
            }

            var config = await TryLoadAsync(path, application, userRoots, cancellationToken);
            if (config is not null)
            {
                configs.Add(config);
            }
        }

        // v3.0.0 (WP8): project-level configs live under the working directory, which is
        // not necessarily inside the user profile, so they get their own allowed root.
        var cwd = Path.GetFullPath(Environment.CurrentDirectory);
        string[] projectRoots = [cwd];
        foreach (var (application, relativePath) in ProjectConfigCandidates)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!seenPaths.Add(Path.GetFullPath(Path.Combine(cwd, relativePath))))
            {
                continue;
            }

            var config = await TryLoadAsync(
                Path.Combine(cwd, relativePath), application, projectRoots, cancellationToken);
            if (config is not null)
            {
                configs.Add(config);
            }
        }

        return configs;
    }

    private static async Task<McpConfigFile?> TryLoadAsync(
        string path,
        string application,
        IReadOnlyList<string> allowedRoots,
        CancellationToken cancellationToken)
    {
        try
        {
            // Security: Validate path before accessing
            if (!IsPathSafe(path, allowedRoots))
            {
                return null;
            }

            if (File.Exists(path))
            {
                var config = await ParseConfigFileCoreAsync(path, application, allowedRoots, cancellationToken);
                if (config is not null && config.Servers.Count > 0)
                {
                    return config;
                }
            }
        }
        catch (Exception)
        {
            // Security: Silently ignore errors for individual config files
            // Don't expose which paths failed or why
        }

        return null;
    }

    /// <summary>
    /// Parses a specific MCP configuration file with security validation. The path must
    /// sit under a user-profile root (user-supplied files) — project-level discovery uses
    /// its own working-directory root instead.
    /// </summary>
    public static Task<McpConfigFile?> ParseConfigFileAsync(
        string filePath,
        string sourceApplication,
        CancellationToken cancellationToken = default) =>
        ParseConfigFileCoreAsync(filePath, sourceApplication, UserRoots, cancellationToken);

    private static async Task<McpConfigFile?> ParseConfigFileCoreAsync(
        string filePath,
        string sourceApplication,
        IReadOnlyList<string> allowedRoots,
        CancellationToken cancellationToken = default)
    {
        // Security: Validate file path
        if (!IsPathSafe(filePath, allowedRoots))
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

            // Check for servers (alternative format): an array of named entries, or the
            // VS Code mcp.json shape where "servers" is an object keyed by name.
            if (root.TryGetProperty("servers", out var serversElement))
            {
                if (serversElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var server in serversElement.EnumerateObject())
                    {
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
                else if (serversElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var server in serversElement.EnumerateArray())
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
            }

            // v3.0.0 (WP8): OpenCode's opencode.json uses an "mcp" object keyed by name.
            if (root.TryGetProperty("mcp", out var mcpElement) &&
                mcpElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var server in mcpElement.EnumerateObject())
                {
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
    /// Validates that a file path is safe to access: it must resolve under one of the
    /// supplied allowed roots and carry no traversal or suspicious segments.
    /// </summary>
    internal static bool IsPathSafe(string? path, IReadOnlyList<string> allowedRoots)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            // Security: Get the full path to resolve any relative components
            var fullPath = Path.GetFullPath(path);

            // Security: Path must be under an allowed root. The root is normalised with
            // a trailing separator so a sibling whose name merely starts with the root's
            // name (Roaming-evil vs Roaming) does not pass.
            var isUnderAllowedRoot = allowedRoots.Any(root =>
            {
                if (string.IsNullOrEmpty(root))
                {
                    return false;
                }

                var normalizedRoot = Path.GetFullPath(root);
                if (!normalizedRoot.EndsWith(Path.DirectorySeparatorChar))
                {
                    normalizedRoot += Path.DirectorySeparatorChar;
                }

                return fullPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase);
            });

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
            name = new string([.. name.Where(c => !char.IsControl(c))]);

            // v3.0.0 (WP8): OpenCode entries carry "enabled": honour an explicit opt-out.
            if (element.TryGetProperty("enabled", out var enabledElement) &&
                enabledElement.ValueKind == JsonValueKind.False)
            {
                return null;
            }

            string? command = null;
            List<string>? args = null;
            Dictionary<string, string>? env = null;
            Dictionary<string, string>? headers = null;
            string? url = null;
            var transport = McpTransportType.Stdio;

            if (element.TryGetProperty("command", out var cmdElement))
            {
                if (cmdElement.ValueKind == JsonValueKind.String)
                {
                    command = cmdElement.GetString();
                }
                else if (cmdElement.ValueKind == JsonValueKind.Array)
                {
                    // v3.0.0 (WP8): OpenCode local servers shape command as an argv array.
                    var argv = cmdElement.EnumerateArray()
                        .Where(a => a.ValueKind == JsonValueKind.String)
                        .Select(a => a.GetString()!)
                        .Take(101)
                        .ToList();
                    if (argv.Count > 0)
                    {
                        command = argv[0];
                        args = argv.Skip(1).ToList();
                    }
                }

                // Security: Validate command
                if (command is not null && command.Length > 1000)
                {
                    command = command[..1000];
                }
            }

            if (args is null &&
                element.TryGetProperty("args", out var argsElement) &&
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

            // v3.0.0 (WP8): OpenCode names the environment map "environment".
            if (!element.TryGetProperty("env", out var envElement) || envElement.ValueKind != JsonValueKind.Object)
            {
                element.TryGetProperty("environment", out envElement);
            }

            if (envElement.ValueKind == JsonValueKind.Object)
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

            // Optional custom HTTP headers (e.g. Authorization: Bearer ...)
            // applied on every outgoing MCP HTTP/WebSocket request.
            if (element.TryGetProperty("headers", out var headersElement) &&
                headersElement.ValueKind == JsonValueKind.Object)
            {
                headers = [];
                var headerCount = 0;
                foreach (var prop in headersElement.EnumerateObject())
                {
                    // Security: Limit number of headers
                    if (++headerCount > 32)
                    {
                        break;
                    }

                    if (prop.Value.ValueKind != JsonValueKind.String)
                    {
                        continue;
                    }

                    var key = prop.Name;
                    var value = prop.Value.GetString();

                    // Security: Reject control chars, empty names, CRLF smuggling
                    if (string.IsNullOrWhiteSpace(key) || key.Length > 256 || value is null)
                    {
                        continue;
                    }
                    if (key.Any(char.IsControl) || value.Any(c => c == '\r' || c == '\n'))
                    {
                        continue;
                    }

                    // Security: Bound value length
                    if (value.Length > 4096)
                    {
                        value = value[..4096];
                    }

                    headers[key] = value;
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

            // v3.0.0 (WP8): VS Code mcp.json and OpenCode carry the transport as "type".
            if (!element.TryGetProperty("transport", out var transportElement) || transportElement.ValueKind != JsonValueKind.String)
            {
                element.TryGetProperty("type", out transportElement);
            }

            if (transportElement.ValueKind == JsonValueKind.String)
            {
                var transportStr = transportElement.GetString()?.ToLowerInvariant();
                transport = transportStr switch
                {
                    "stdio" or "local" => McpTransportType.Stdio,
                    "http" or "sse" => McpTransportType.Http,
                    "streamable-http" => McpTransportType.StreamableHttp,
                    "remote" => url is not null ? McpTransportType.Http : McpTransportType.Stdio,
                    "websocket" or "ws" or "wss" => McpTransportType.WebSocket,
                    _ => McpTransportType.Stdio
                };
            }

            // An entry with neither a command nor a URL is not a runnable server
            // (e.g. OpenCode "remote" without a url); drop it rather than emit a hollow
            // configuration that rules would see as a stdio server with no command.
            if (command is null && url is null)
            {
                return null;
            }

            return new McpServerConfig
            {
                Name = name,
                Transport = transport,
                Command = command,
                Args = args,
                Env = env,
                Url = url,
                Headers = headers,
                SourceConfigPath = sourceFile
            };
        }
        catch
        {
            // Security: Don't expose parsing errors
            return null;
        }
    }

}
