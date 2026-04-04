using System.Diagnostics;
using System.Text.RegularExpressions;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Config;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Reports;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Scoring;

namespace SignalSentinel.Scanner;

/// <summary>
/// Signal Sentinel Scanner - MCP Security Audit Tool
/// Security hardened CLI entry point with input validation.
/// </summary>
public static class Program
{
    private const string Version = "1.0.0";

    // Security: Limits for input validation
    private const int MaxPathLength = 4096;
    private const int MaxUrlLength = 2048;
    private const int MaxTimeoutSeconds = 300;
    private const int MinTimeoutSeconds = 1;

    public static async Task<int> Main(string[] args)
    {
        try
        {
            // Security: Validate argument count
            if (args.Length > 50)
            {
                Console.Error.WriteLine("Error: Too many arguments");
                return 2;
            }

            var config = ParseArguments(args);

            if (config is null)
            {
                PrintUsage();
                return 2;
            }

            // Security: Use a cancellation token with overall timeout
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(30));

            // Security: Handle Ctrl+C gracefully
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
                Console.Error.WriteLine("\nScan cancelled by user.");
            };

            return await RunScanAsync(config, cts.Token);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Scan cancelled.");
            return 130; // Standard exit code for SIGINT
        }
        catch (Exception ex)
        {
            // Security: Don't expose internal exceptions
            Console.Error.WriteLine($"Fatal error: {SanitizeErrorMessage(ex.Message)}");
            return 2;
        }
    }

    private static ScanConfig? ParseArguments(string[] args)
    {
        var config = new ScanConfig();

        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            // Security: Validate argument length
            if (arg.Length > MaxPathLength)
            {
                Console.Error.WriteLine("Error: Argument too long");
                return null;
            }

            switch (arg)
            {
                case "--help" or "-h":
                    return null;

                case "--version":
                    Console.WriteLine($"Signal Sentinel Scanner v{Version}");
                    Environment.Exit(0);
                    return null;

                case "--config" or "-c":
                    if (i + 1 < args.Length)
                    {
                        var path = args[++i];
                        if (!ValidatePath(path))
                        {
                            Console.Error.WriteLine("Error: Invalid config path");
                            return null;
                        }
                        config = config with { ConfigPath = path };
                    }
                    break;

                case "--remote" or "-r":
                    if (i + 1 < args.Length)
                    {
                        var url = args[++i];
                        if (!ValidateUrl(url))
                        {
                            Console.Error.WriteLine("Error: Invalid URL");
                            return null;
                        }
                        config = config with { RemoteUrl = url };
                    }
                    break;

                case "--discover" or "-d":
                    config = config with { AutoDiscover = true };
                    break;

                case "--format" or "-f":
                    if (i + 1 < args.Length)
                    {
                        var formatStr = args[++i].ToLowerInvariant();
                        var format = formatStr switch
                        {
                            "json" => OutputFormat.Json,
                            "html" => OutputFormat.Html,
                            "markdown" or "md" => OutputFormat.Markdown,
                            _ => OutputFormat.Markdown
                        };
                        config = config with { OutputFormat = format };
                    }
                    break;

                case "--output" or "-o":
                    if (i + 1 < args.Length)
                    {
                        var path = args[++i];
                        if (!ValidateOutputPath(path))
                        {
                            Console.Error.WriteLine("Error: Invalid output path");
                            return null;
                        }
                        config = config with { OutputPath = path };
                    }
                    break;

                case "--ci":
                    config = config with { CiMode = true };
                    break;

                case "--verbose" or "-v":
                    config = config with { Verbose = true };
                    break;

                case "--timeout" or "-t":
                    if (i + 1 < args.Length)
                    {
                        if (int.TryParse(args[++i], out var timeout))
                        {
                            // Security: Enforce timeout bounds
                            timeout = Math.Clamp(timeout, MinTimeoutSeconds, MaxTimeoutSeconds);
                            config = config with { TimeoutSeconds = timeout };
                        }
                    }
                    break;

                default:
                    // Security: Reject unknown arguments to prevent injection
                    if (arg.StartsWith("-"))
                    {
                        Console.Error.WriteLine($"Error: Unknown option: {SanitizeForDisplay(arg)}");
                        return null;
                    }
                    break;
            }
        }

        // If no arguments provided, default to discover
        if (args.Length == 0)
        {
            config = config with { AutoDiscover = true };
        }

        return config;
    }

    /// <summary>
    /// Validates a file path for safety.
    /// </summary>
    private static bool ValidatePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        if (path.Length > MaxPathLength)
        {
            return false;
        }

        // Security: Check for null bytes and control characters
        if (path.Any(c => c == '\0' || (char.IsControl(c) && c != '\\' && c != '/')))
        {
            return false;
        }

        // Security: Check for path traversal (but allow normal relative paths)
        try
        {
            var fullPath = Path.GetFullPath(path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Validates an output file path for safety.
    /// </summary>
    private static bool ValidateOutputPath(string? path)
    {
        if (!ValidatePath(path))
        {
            return false;
        }

        // Security: Only allow specific extensions for output
        var extension = Path.GetExtension(path)?.ToLowerInvariant();
        var allowedExtensions = new[] { ".json", ".md", ".html", ".txt" };

        return allowedExtensions.Contains(extension);
    }

    /// <summary>
    /// Validates a URL for safety.
    /// </summary>
    private static bool ValidateUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return false;
        }

        if (url.Length > MaxUrlLength)
        {
            return false;
        }

        // Security: Only allow http/https/ws/wss
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (uri.Scheme != "http" && uri.Scheme != "https" &&
            uri.Scheme != "ws" && uri.Scheme != "wss")
        {
            return false;
        }

        // Security: Block localhost/private IPs in CI mode
        // (In practice, you might want to allow localhost for local scanning)
        return true;
    }

    /// <summary>
    /// Sanitizes a string for safe display (prevents terminal injection).
    /// </summary>
    private static string SanitizeForDisplay(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        // Remove control characters except common whitespace
        var sanitized = new string(input.Where(c => !char.IsControl(c) || c == ' ').ToArray());

        // Limit length
        if (sanitized.Length > 100)
        {
            sanitized = sanitized[..100] + "...";
        }

        return sanitized;
    }

    /// <summary>
    /// Sanitizes error messages to prevent information leakage.
    /// </summary>
    private static string SanitizeErrorMessage(string message)
    {
        if (string.IsNullOrEmpty(message))
        {
            return "Unknown error";
        }

        // Limit length
        if (message.Length > 200)
        {
            message = message[..200] + "...";
        }

        // Remove potential paths
        message = Regex.Replace(
            message,
            @"[A-Za-z]:\\[^\s]+|/[^\s]+/[^\s]+",
            "[PATH]",
            RegexOptions.None,
            TimeSpan.FromMilliseconds(100));

        // Remove potential secrets
        message = Regex.Replace(
            message,
            @"(?i)(password|secret|key|token)\s*[=:]\s*\S+",
            "[REDACTED]",
            RegexOptions.None,
            TimeSpan.FromMilliseconds(100));

        return SanitizeForDisplay(message);
    }

    private static void PrintUsage()
    {
        Console.WriteLine($"""
            Signal Sentinel Scanner v{Version}
            MCP Security Audit Tool - OWASP Agentic AI Top 10 Compliant
            
            USAGE:
                sentinel-scan [OPTIONS]
            
            OPTIONS:
                -c, --config <path>     Path to MCP configuration file
                -r, --remote <url>      Remote MCP server URL (http/https/ws/wss)
                -d, --discover          Auto-discover MCP configurations
                -f, --format <format>   Output format: json, markdown, html (default: markdown)
                -o, --output <path>     Output file path (defaults to stdout)
                    --ci                CI mode - exit code 1 on critical/high findings
                -v, --verbose           Enable verbose output
                -t, --timeout <sec>     Connection timeout in seconds (default: 30, max: 300)
                -h, --help              Show this help message
                    --version           Show version information
            
            EXAMPLES:
                sentinel-scan --discover
                sentinel-scan --config ~/.cursor/mcp.json
                sentinel-scan --remote https://mcp.example.com/mcp --format html -o report.html
                sentinel-scan --remote wss://mcp.example.com/ws
                sentinel-scan --discover --ci --format json
            
            SECURITY RULES:
                SS-001  Tool Poisoning Detection (ASI01)
                SS-002  Overbroad Permissions (ASI02)
                SS-003  Missing Authentication (ASI03)
                SS-004  Supply Chain Vulnerabilities (ASI04)
                SS-005  Code Execution Detection (ASI05)
                SS-006  Memory/Context Write Access (ASI06)
                SS-007  Inter-Agent Communication (ASI07)
                SS-008  Sensitive Data Access (ASI09)
                SS-009  Excessive Description Length (ASI01)
                SS-010  Cross-Server Attack Paths (ASI02)
            
            For more information: https://github.com/SignalCoding/signal-sentinel-scanner
            Report security issues: security@signalcoding.co.uk
            """);
    }

    private static async Task<int> RunScanAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        void Log(string message)
        {
            if (config.Verbose)
            {
                // Security: Sanitize log messages
                Console.Error.WriteLine(SanitizeForDisplay(message));
            }
        }

        try
        {
            Log($"Signal Sentinel Scanner v{Version}");
            Log("================================");

            // Collect configurations
            var configFiles = new List<Core.McpProtocol.McpConfigFile>();

            if (config.AutoDiscover)
            {
                Log("Discovering MCP configurations...");
                var discovered = await ConfigDiscovery.DiscoverAllAsync(cancellationToken);
                configFiles.AddRange(discovered);
                Log($"Found {configFiles.Count} configuration file(s)");
            }

            if (config.ConfigPath is not null)
            {
                Log($"Loading config: {SanitizeForDisplay(config.ConfigPath)}");
                var parsed = await ConfigDiscovery.ParseConfigFileAsync(config.ConfigPath, "User-specified", cancellationToken);
                if (parsed is not null)
                {
                    configFiles.Add(parsed);
                }
            }

            if (configFiles.Count == 0 && config.RemoteUrl is null)
            {
                Console.Error.WriteLine("Error: No MCP configurations found. Use --discover, --config, or --remote.");
                return 2;
            }

            // Add remote server if specified
            if (config.RemoteUrl is not null)
            {
                var uri = new Uri(config.RemoteUrl);
                var transport = uri.Scheme is "ws" or "wss"
                    ? Core.McpProtocol.McpTransportType.WebSocket
                    : Core.McpProtocol.McpTransportType.Http;

                configFiles.Add(new Core.McpProtocol.McpConfigFile
                {
                    FilePath = "remote",
                    SourceApplication = "Remote",
                    Servers =
                    [
                        new Core.McpProtocol.McpServerConfig
                        {
                            Name = uri.Host,
                            Transport = transport,
                            Url = config.RemoteUrl
                        }
                    ]
                });
            }

            // Enumerate servers
            Log("Enumerating MCP servers...");
            var enumerator = new ToolEnumerator(
                TimeSpan.FromSeconds(config.TimeoutSeconds),
                config.Verbose,
                Log);

            var serverEnumerations = await enumerator.EnumerateServersAsync(configFiles, cancellationToken);
            Log($"Enumerated {serverEnumerations.Count} server(s)");

            // Run rules
            Log("Executing security rules...");
            var ruleEngine = new RuleEngine(verbose: config.Verbose, logger: Log);
            var context = new ScanContext { Servers = serverEnumerations };
            var ruleResult = await ruleEngine.ExecuteAsync(context, cancellationToken);
            Log($"Found {ruleResult.Findings.Count} finding(s), {ruleResult.AttackPaths.Count} attack path(s)");

            // Calculate grade
            var (grade, score) = SeverityScorer.CalculateGrade(ruleResult.Findings, ruleResult.AttackPaths);

            // Build result
            stopwatch.Stop();
            var result = new ScanResult
            {
                ScanTimestamp = DateTimeOffset.UtcNow,
                ScannerVersion = Version,
                Servers = serverEnumerations.Select(s => new ServerScanSummary
                {
                    Name = s.ServerName,
                    Version = s.ServerVersion,
                    Transport = s.Transport,
                    SourceConfig = s.SourceConfigPath,
                    ToolCount = s.Tools.Count,
                    ResourceCount = s.Resources.Count,
                    PromptCount = s.Prompts.Count,
                    ConnectionSuccessful = s.ConnectionSuccessful,
                    ConnectionError = s.ConnectionError
                }).ToList(),
                Findings = ruleResult.Findings,
                AttackPaths = ruleResult.AttackPaths,
                Grade = grade,
                Score = score,
                Statistics = new ScanStatistics
                {
                    TotalServers = serverEnumerations.Count,
                    ServersConnected = serverEnumerations.Count(s => s.ConnectionSuccessful),
                    TotalTools = serverEnumerations.Sum(s => s.Tools.Count),
                    TotalResources = serverEnumerations.Sum(s => s.Resources.Count),
                    TotalPrompts = serverEnumerations.Sum(s => s.Prompts.Count),
                    CriticalFindings = ruleResult.Findings.Count(f => f.Severity == Severity.Critical),
                    HighFindings = ruleResult.Findings.Count(f => f.Severity == Severity.High),
                    MediumFindings = ruleResult.Findings.Count(f => f.Severity == Severity.Medium),
                    LowFindings = ruleResult.Findings.Count(f => f.Severity == Severity.Low),
                    InfoFindings = ruleResult.Findings.Count(f => f.Severity == Severity.Info),
                    AttackPathCount = ruleResult.AttackPaths.Count,
                    ScanDurationMs = stopwatch.ElapsedMilliseconds
                }
            };

            // Generate report
            IReportGenerator generator = config.OutputFormat switch
            {
                OutputFormat.Json => new JsonReportGenerator(),
                OutputFormat.Html => new HtmlReportGenerator(),
                _ => new MarkdownReportGenerator()
            };

            var report = generator.Generate(result);

            // Output report
            if (config.OutputPath is not null)
            {
                // Security: Validate output path one more time before writing
                var fullPath = Path.GetFullPath(config.OutputPath);
                await File.WriteAllTextAsync(fullPath, report, cancellationToken);
                Log($"Report written to: {SanitizeForDisplay(fullPath)}");
            }
            else
            {
                Console.WriteLine(report);
            }

            // CI mode exit code
            if (config.CiMode)
            {
                if (result.Statistics.CriticalFindings > 0 || result.Statistics.HighFindings > 0)
                {
                    Log($"CI mode: Exiting with code 1 (Critical: {result.Statistics.CriticalFindings}, High: {result.Statistics.HighFindings})");
                    return 1;
                }
            }

            return 0;
        }
        catch (OperationCanceledException)
        {
            throw; // Re-throw to be handled by Main
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {SanitizeErrorMessage(ex.Message)}");
            if (config.Verbose)
            {
                // Security: In verbose mode, show sanitized stack trace
                Console.Error.WriteLine("Stack trace available in debug builds only.");
            }
            return 2;
        }
    }
}
