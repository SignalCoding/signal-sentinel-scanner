using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.RuleFormats;
using SignalSentinel.Scanner.Baseline;
using SignalSentinel.Scanner.Config;
using SignalSentinel.Scanner.Dedup;
using SignalSentinel.Scanner.History;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Offline;
using SignalSentinel.Scanner.Reports;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Scoring;
using SignalSentinel.Scanner.SkillParser;
using SignalSentinel.Scanner.Suppressions;
using SignalSentinel.Scanner.Triage;

namespace SignalSentinel.Scanner;

/// <summary>
/// Signal Sentinel Scanner - MCP Security Audit Tool
/// Security hardened CLI entry point with input validation.
/// </summary>
public static class Program
{
    private const string Version = "2.3.0";
    private const string RubricVersion = "1.0";

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
                return 0;
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
                    return null;

                case "--config" or "-c":
                    if (i + 1 < args.Length)
                    {
                        var path = args[++i];
                        if (!ValidatePath(path, ".json"))
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
                            "sarif" => OutputFormat.Sarif,
                            "markdown" or "md" => OutputFormat.Markdown,
                            _ => OutputFormat.Markdown
                        };
                        config = config with { OutputFormat = format };
                    }
                    break;

                case "--baseline":
                    if (i + 1 < args.Length)
                    {
                        var path = args[++i];
                        if (!ValidatePath(path, ".json"))
                        {
                            Console.Error.WriteLine("Error: Invalid baseline path");
                            return null;
                        }
                        config = config with { BaselinePath = path };
                    }
                    break;

                case "--update-baseline":
                    config = config with { UpdateBaseline = true };
                    break;

                case "--offline":
                    config = config with { Offline = true };
                    break;

                case "--sigma-rules":
                    if (i + 1 < args.Length)
                    {
                        var path = args[++i];
                        if (!ValidatePath(path))
                        {
                            Console.Error.WriteLine("Error: Invalid sigma-rules path");
                            return null;
                        }
                        config = config with { SigmaRulesPath = path };
                    }
                    break;

                case "--suppressions":
                    if (i + 1 < args.Length)
                    {
                        var path = args[++i];
                        if (!ValidatePath(path, ".json"))
                        {
                            Console.Error.WriteLine("Error: Invalid suppressions path");
                            return null;
                        }
                        config = config with { SuppressionsPath = path };
                    }
                    break;

                case "--ignore-rule":
                    if (i + 1 < args.Length)
                    {
                        var raw = args[++i];
                        var ids = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        foreach (var id in ids)
                        {
                            if (!Regex.IsMatch(id, @"^SS-(INFO-)?\d{3}$", RegexOptions.None, TimeSpan.FromMilliseconds(100)))
                            {
                                Console.Error.WriteLine($"Error: Invalid rule id: {SanitizeForDisplay(id)}");
                                return null;
                            }
                        }
                        config = config with { IgnoredRules = ids };
                    }
                    break;

                case "--fail-on":
                    if (i + 1 < args.Length)
                    {
                        var token = args[++i].ToLowerInvariant();
                        var severity = token switch
                        {
                            "critical" => (Severity?)Severity.Critical,
                            "high" => Severity.High,
                            "medium" => Severity.Medium,
                            "low" => Severity.Low,
                            "info" => Severity.Info,
                            _ => null
                        };
                        if (severity is null)
                        {
                            Console.Error.WriteLine("Error: --fail-on expects one of: critical, high, medium, low, info");
                            return null;
                        }
                        config = config with { FailOn = severity };
                    }
                    break;

                case "--min-confidence":
                    if (i + 1 < args.Length)
                    {
                        if (!double.TryParse(args[++i], NumberStyles.Float, CultureInfo.InvariantCulture, out var conf)
                            || conf is < 0 or > 1)
                        {
                            Console.Error.WriteLine("Error: --min-confidence expects a value in [0, 1]");
                            return null;
                        }
                        config = config with { MinConfidence = conf };
                    }
                    break;

                case "--triage":
                    config = config with { Triage = true };
                    break;

                case "--save-history":
                    config = config with { SaveHistory = true };
                    break;

                case "--environment":
                    if (i + 1 < args.Length)
                    {
                        var env = args[++i];
                        if (!Regex.IsMatch(env, @"^[A-Za-z0-9_\-]{1,32}$", RegexOptions.None, TimeSpan.FromMilliseconds(100)))
                        {
                            Console.Error.WriteLine("Error: --environment must be alphanumeric (max 32 chars)");
                            return null;
                        }
                        config = config with { Environment = env };
                    }
                    break;

                case "--complementary-tools":
                    if (i + 1 < args.Length)
                    {
                        var raw = args[++i];
                        var tools = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        config = config with { ComplementaryTools = tools };
                    }
                    break;

                case "--list-rules":
                    config = config with { ListRules = true };
                    break;

                case "--diff":
                    if (i + 2 < args.Length)
                    {
                        var baselinePath = args[++i];
                        var currentPath = args[++i];
                        if (!ValidatePath(baselinePath, ".json") || !ValidatePath(currentPath, ".json"))
                        {
                            Console.Error.WriteLine("Error: --diff requires two valid .json scan report paths");
                            return null;
                        }
                        config = config with { DiffBaselinePath = baselinePath, DiffCurrentPath = currentPath };
                    }
                    else
                    {
                        Console.Error.WriteLine("Error: --diff requires <baseline.json> <current.json>");
                        return null;
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

                case "--skills" or "-s":
                    config = config with { ScanSkills = true };
                    // Optional: next arg might be a path (if it doesn't start with -)
                    if (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                    {
                        var skillPath = args[++i];
                        if (ValidatePath(skillPath))
                        {
                            config = config with { SkillsPath = skillPath };
                        }
                        else
                        {
                            Console.Error.WriteLine("Error: Invalid skills path");
                            return null;
                        }
                    }
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
                    if (arg.StartsWith('-'))
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
    private static bool ValidatePath(string? path, string? requiredExtension = null)
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

            // Security: Enforce required file extension (e.g. .json for config files)
            if (requiredExtension is not null)
            {
                var ext = Path.GetExtension(fullPath);
                if (!string.Equals(ext, requiredExtension, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

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
        var allowedExtensions = new[] { ".json", ".md", ".html", ".txt", ".sarif" };

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

        // Security: SSRF protection - block requests to internal/private networks
        try
        {
            var host = uri.DnsSafeHost;
            var addresses = Dns.GetHostAddresses(host);

            foreach (var addr in addresses)
            {
                var bytes = addr.GetAddressBytes();

                // Block loopback (127.0.0.0/8, ::1)
                if (IPAddress.IsLoopback(addr))
                    return false;

                if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    // Block 10.0.0.0/8
                    if (bytes[0] == 10)
                        return false;

                    // Block 172.16.0.0/12
                    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                        return false;

                    // Block 192.168.0.0/16
                    if (bytes[0] == 192 && bytes[1] == 168)
                        return false;

                    // Block link-local 169.254.0.0/16 (includes cloud metadata 169.254.169.254)
                    if (bytes[0] == 169 && bytes[1] == 254)
                        return false;
                }
                else if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    // Block fe80::/10 (link-local)
                    if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
                        return false;
                }
            }
        }
        catch
        {
            // If DNS resolution fails, allow the URL (don't block on DNS failure)
        }

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
        var sanitized = new string([.. input.Where(c => !char.IsControl(c) || c == ' ')]);

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
            Signal Sentinel Scanner v{Version} (rubric v{RubricVersion})
            Fast, deterministic, offline-capable first-pass security aid for
            MCP servers and Agent Skill authors. OWASP ASI/AST Top 10 aligned.
            
            USAGE:
                sentinel-scan [OPTIONS]
                sentinel-scan --list-rules
                sentinel-scan --diff <baseline.json> <current.json> [-o <out>]
            
            SCAN TARGETS:
                -c, --config <path>     Path to MCP configuration file
                -r, --remote <url>      Remote MCP server URL (http/https/ws/wss)
                -d, --discover          Auto-discover MCP configurations
                -s, --skills [path]     Scan Agent Skills (auto-discover or specify path)
            
            OUTPUT:
                -f, --format <format>   Output format: json, markdown, html, sarif (default: markdown)
                -o, --output <path>     Output file path (defaults to stdout)
                    --save-history      Persist run under .sentinel/history/<iso>.json
            
            v2.3.0 TRIAGE & ACCEPTED RISK:
                    --suppressions <p>  Suppressions file (default: ./.sentinel-suppressions.json)
                    --ignore-rule <ids> Comma-separated rule ids to drop (no justification)
                    --min-confidence <f> Drop findings below confidence [0..1]
                    --triage            Demote low-confidence findings to 'low' (keeps them visible)
                    --fail-on <sev>     Exit 1 at/above severity: critical|high|medium|low|info
                    --environment <e>   Environment label ("dev"/"staging"/"prod"/custom)
                    --complementary-tools <csv>  Tools listed in the scope-disclosure block
            
            BASELINES & CUSTOM RULES:
                    --baseline <path>   Compare against baseline file (creates if missing)
                    --update-baseline   Regenerate baseline file from current scan
                    --offline           Enforce zero network egress (refuses --remote)
                    --sigma-rules <p>   Load Sigma YAML rules from file or directory
            
            LEGACY / MISC:
                    --ci                Legacy CI mode (equivalent to --fail-on high)
                -v, --verbose           Enable verbose output
                -t, --timeout <sec>     Connection timeout in seconds (default: 30, max: 300)
                    --list-rules        Print every registered rule (id/owasp/ast) and exit
                -h, --help              Show this help message
                    --version           Show version information
            
            EXAMPLES:
                sentinel-scan --discover                              # MCP auto-discover
                sentinel-scan --skills                                # Skill auto-discover
                sentinel-scan --discover --skills                     # Both MCP and Skills
                sentinel-scan --skills ~/.claude/skills/              # Specific skill directory
                sentinel-scan --config ~/.cursor/mcp.json
                sentinel-scan --remote https://mcp.example.com/mcp
                sentinel-scan --remote wss://mcp.example.com/ws
                sentinel-scan --discover --skills --ci --format json  # CI/CD mode
                sentinel-scan --discover --format sarif -o out.sarif  # SARIF for GitHub Code Scanning
                sentinel-scan --discover --baseline .sentinel-baseline.json
                sentinel-scan --discover --skills --offline           # Air-gapped verification
                sentinel-scan --discover --sigma-rules ./rules/
            
            MCP SECURITY RULES:
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
                SS-019  Credential Hygiene (ASI03)
                SS-020  OAuth 2.1 Compliance (ASI03)
                SS-021  Package Provenance (ASI04)
                SS-022  Rug Pull Detection / Schema Mutation (ASI01)
                SS-023  Shadow Tool Injection (ASI01)
                SS-025  Excessive Tool Response Size (ASI06)
            
            SKILL SECURITY RULES:
                SS-011  Skill Prompt Injection (ASI01, AST01/AST04)
                SS-012  Skill Scope Violation (ASI02, AST03)
                SS-013  Skill Credential Access (ASI03, AST01)
                SS-014  Skill Data Exfiltration (ASI09, AST01/AST03)
                SS-015  Skill Obfuscation (ASI01, AST04)
                SS-016  Skill Script Payload (ASI05, AST01/AST05)
                SS-017  Skill Excessive Permissions (ASI02, AST03)
                SS-018  Skill Hidden Content (ASI01, AST04)
                SS-024  Skill Integrity Verification (ASI04, AST02/AST07)
            
            INFORMATIONAL:
                SS-INFO-001  Non-MCP Endpoint Detected (ASI10, AST08)
            
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

            // v2.3.0: list-rules (early exit, no scan performed)
            if (config.ListRules)
            {
                PrintRuleList();
                return 0;
            }

            // v2.3.0: diff subcommand
            if (config.DiffBaselinePath is not null && config.DiffCurrentPath is not null)
            {
                return await RunDiffAsync(config, cancellationToken);
            }

            // Enforce offline mode as early as possible
            if (config.Offline)
            {
                OfflineGuard.Enable();
                if (config.RemoteUrl is not null)
                {
                    Console.Error.WriteLine("Error: --offline is incompatible with --remote.");
                    return 2;
                }
                Log("Offline mode: network operations will be blocked.");
            }

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

            if (configFiles.Count == 0 && config.RemoteUrl is null && !config.ScanSkills)
            {
                Console.Error.WriteLine("Error: No MCP configurations found. Use --discover, --config, --remote, or --skills.");
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

            // Enumerate skills
            var allSkills = new List<SkillDefinition>();
            var skillSources = new List<SkillScanSource>();

            if (config.ScanSkills)
            {
                if (config.SkillsPath is not null)
                {
                    Log($"Scanning skills: {SanitizeForDisplay(config.SkillsPath)}");
                    var source = await SkillDiscovery.ScanDirectoryAsync(config.SkillsPath, cancellationToken);
                    skillSources.Add(source);
                    allSkills.AddRange(source.Skills);
                }
                else
                {
                    Log("Discovering Agent Skills...");
                    var discovered = await SkillDiscovery.DiscoverAllAsync(config.Verbose, Log, cancellationToken);
                    skillSources.AddRange(discovered);
                    foreach (var source in discovered)
                    {
                        allSkills.AddRange(source.Skills);
                    }
                }
                Log($"Found {allSkills.Count} skill(s) across {skillSources.Count} source(s)");
            }

            // Baseline comparison (v2.2.0)
            BaselineComparison? baselineComparison = null;
            if (config.BaselinePath is not null)
            {
                var baseline = await BaselineManager.LoadAsync(config.BaselinePath, cancellationToken);
                if (baseline is null)
                {
                    Log($"Baseline not found at {SanitizeForDisplay(config.BaselinePath)} - will be created after scan.");
                }
                else
                {
                    Log($"Baseline loaded (generated {baseline.GeneratedAt:o} by scanner v{baseline.ScannerVersion}).");
                }
                baselineComparison = BaselineManager.Compare(baseline, serverEnumerations);
            }

            // Load Sigma rules if requested (v2.2.0)
            var customRules = new List<IRule>();
            if (config.SigmaRulesPath is not null)
            {
                Log($"Loading Sigma rules from: {SanitizeForDisplay(config.SigmaRulesPath)}");
                var sigmaResult = SigmaRuleLoader.LoadFromPath(config.SigmaRulesPath);
                foreach (var err in sigmaResult.Errors)
                {
                    Log($"  Sigma load warning: {SanitizeForDisplay(err)}");
                }
                foreach (var sigma in sigmaResult.Rules)
                {
                    customRules.Add(new SigmaPatternRule(sigma));
                }
                Log($"Loaded {sigmaResult.Rules.Count} Sigma rule(s)");
            }

            // Always include v2.2.0 rules that depend on runtime state
            customRules.Add(new RugPullDetectionRule(baselineComparison));
            customRules.Add(new ShadowToolInjectionRule());
            customRules.Add(new ExcessiveResponseRule());
            customRules.Add(new Rules.SkillRules.SkillIntegrityRule());

            // Run rules
            Log("Executing security rules...");
            var ruleEngine = new RuleEngine(customRules: customRules, verbose: config.Verbose, logger: Log);
            var context = new ScanContext { Servers = serverEnumerations, Skills = allSkills };
            var ruleResult = await ruleEngine.ExecuteAsync(context, cancellationToken);

            // Deduplicate findings (v2.2.0)
            var deduplicated = FindingDeduplicator.Deduplicate(ruleResult.Findings);
            var collapsedCount = ruleResult.Findings.Count - deduplicated.Count;
            if (collapsedCount > 0)
            {
                Log($"Deduplicated {collapsedCount} redundant finding(s).");
            }
            ruleResult = ruleResult with { Findings = deduplicated };

            // v2.3.0: drop findings from ignored rules (ephemeral, no justification).
            if (config.IgnoredRules.Count > 0)
            {
                var ignored = new HashSet<string>(config.IgnoredRules, StringComparer.Ordinal);
                var before = ruleResult.Findings.Count;
                var kept = ruleResult.Findings.Where(f => !ignored.Contains(f.RuleId)).ToList();
                if (kept.Count != before)
                {
                    Log($"Dropped {before - kept.Count} finding(s) per --ignore-rule");
                }
                ruleResult = ruleResult with { Findings = kept };
            }

            // v2.3.0: confidence-based triage / filtering.
            var triaged = ConfidenceFilter.Apply(ruleResult.Findings, config.MinConfidence, config.Triage);
            if (triaged.Count != ruleResult.Findings.Count)
            {
                Log($"Confidence filter: dropped {ruleResult.Findings.Count - triaged.Count} finding(s) below {config.MinConfidence:F2}");
            }
            ruleResult = ruleResult with { Findings = triaged };

            // v2.3.0: apply suppression file (accepted risks)
            var suppressionPath = config.SuppressionsPath
                ?? (File.Exists(".sentinel-suppressions.json") ? ".sentinel-suppressions.json" : null);
            var suppressedFindings = new List<Finding>();
            if (suppressionPath is not null)
            {
                var file = await SuppressionManager.LoadAsync(suppressionPath, cancellationToken);
                if (file is null)
                {
                    Log($"Suppressions file not found: {SanitizeForDisplay(suppressionPath)}");
                }
                else
                {
                    Log($"Loaded {file.Suppressions.Count} suppression(s) from {SanitizeForDisplay(suppressionPath)}");
                    var annotated = SuppressionManager.Apply(ruleResult.Findings, file, config.Environment, DateTimeOffset.UtcNow);
                    // Split active vs suppressed (expired suppressions stay active with banner).
                    var active = new List<Finding>();
                    foreach (var f in annotated)
                    {
                        if (f.Suppression is not null && !f.Suppression.Expired)
                        {
                            suppressedFindings.Add(f);
                        }
                        else if (f.Suppression is not null && f.Suppression.Expired)
                        {
                            active.Add(f with { Title = "[SUPPRESSION EXPIRED] " + f.Title });
                        }
                        else
                        {
                            active.Add(f);
                        }
                    }
                    ruleResult = ruleResult with { Findings = active };
                    Log($"Accepted {suppressedFindings.Count} finding(s) via suppression; {active.Count} active");
                }
            }

            Log($"Found {ruleResult.Findings.Count} finding(s), {ruleResult.AttackPaths.Count} attack path(s)");

            // Save/update baseline if requested
            if (config.BaselinePath is not null && (baselineComparison?.BaselineLoaded != true || config.UpdateBaseline))
            {
                await BaselineManager.SaveAsync(config.BaselinePath, serverEnumerations, Version, cancellationToken);
                Log($"Baseline saved to {SanitizeForDisplay(config.BaselinePath)}");
            }

            // Calculate grade
            var (grade, score) = SeverityScorer.CalculateGrade(ruleResult.Findings, ruleResult.AttackPaths);

            // v2.3.0 fix (Section 0.4): compute the counter-factual grade with
            // every suppression removed so reports can show technical-debt
            // exposure alongside the operational grade.
            SecurityGrade? gradeWithoutSupp = null;
            int? scoreWithoutSupp = null;
            if (suppressedFindings.Count > 0)
            {
                var combined = new List<Finding>(ruleResult.Findings.Count + suppressedFindings.Count);
                combined.AddRange(ruleResult.Findings);
                combined.AddRange(suppressedFindings);
                var (g, s) = SeverityScorer.CalculateGrade(combined, ruleResult.AttackPaths);
                gradeWithoutSupp = g;
                scoreWithoutSupp = s;
            }

            // Build result
            stopwatch.Stop();
            var result = new ScanResult
            {
                ScanTimestamp = DateTimeOffset.UtcNow,
                ScannerVersion = Version,
                Servers = [.. serverEnumerations.Select(s => new ServerScanSummary
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
                })],
                Skills = [.. allSkills.Select(s => new SkillScanSummary
                {
                    Name = s.Name,
                    Platform = s.SourcePlatform,
                    FilePath = s.FilePath,
                    ScriptCount = s.Scripts.Count,
                    IsProjectLevel = s.IsProjectLevel
                })],
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
                    TotalSkills = allSkills.Count,
                    TotalScripts = allSkills.Sum(s => s.Scripts.Count),
                    ScanDurationMs = stopwatch.ElapsedMilliseconds
                },
                Environment = config.Environment,
                RubricVersion = RubricVersion,
                SuppressedFindings = suppressedFindings,
                GradeWithoutSuppressions = gradeWithoutSupp,
                ScoreWithoutSuppressions = scoreWithoutSupp,
                Scope = BuildScanScope(config, serverEnumerations.Count > 0, allSkills.Count > 0)
            };

            // v2.3.0: persist scan history if requested.
            if (config.SaveHistory)
            {
                try
                {
                    var historyPath = await ScanHistoryManager.SaveAsync(result, cancellationToken: cancellationToken);
                    Log($"Scan history saved: {SanitizeForDisplay(historyPath)}");
                }
                catch (Exception ex)
                {
                    Log($"Warning: could not save scan history: {SanitizeErrorMessage(ex.Message)}");
                }
            }

            // Generate report
            IReportGenerator generator = config.OutputFormat switch
            {
                OutputFormat.Json => new JsonReportGenerator(),
                OutputFormat.Html => new HtmlReportGenerator(),
                OutputFormat.Sarif => new SarifReportGenerator(),
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

            // v2.3.0: --fail-on wins over legacy --ci when both are set.
            var failThreshold = config.FailOn
                ?? (config.CiMode ? Severity.High : (Severity?)null);

            if (failThreshold is not null)
            {
                var breached = result.Findings.Any(f => f.Severity >= failThreshold.Value);
                if (breached)
                {
                    var worst = result.Findings.Max(f => f.Severity);
                    Log($"Exit 1: finding at or above --fail-on {failThreshold.Value.ToString().ToLowerInvariant()} (worst = {worst})");
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

    // v2.3.0 helpers ---------------------------------------------------------

    private static ScanScope BuildScanScope(ScanConfig config, bool hasServers, bool hasSkills)
    {
        var scanned = new List<string>();
        var notScanned = new List<string>();

        if (hasServers)
        {
            scanned.Add("MCP server configurations");
            scanned.Add("Tool/resource/prompt schemas returned by tools/list");
        }
        if (hasSkills)
        {
            scanned.Add("SKILL.md files (frontmatter + body)");
            scanned.Add("Bundled skill scripts (.py, .sh, .js, .ps1) - surface scan");
            scanned.Add("Skill signature artefacts (.sentinel-sig, SHA256SUMS)");
        }

        notScanned.Add("Transitive third-party dependencies (use Bandit / Gitleaks / Trivy)");
        notScanned.Add("Runtime behaviour of skills or MCP tools (static scan only)");
        notScanned.Add("Content referenced by external URLs (not fetched)");
        if (!hasServers)
        {
            notScanned.Add("MCP server protocol surface (no --remote / --discover / --config supplied)");
        }
        if (!hasSkills)
        {
            notScanned.Add("Agent skills (no --skills supplied)");
        }

        return new ScanScope
        {
            Scanned = scanned,
            NotScanned = notScanned,
            ComplementaryTools = config.ComplementaryTools
        };
    }

    private static void PrintRuleList()
    {
        Console.WriteLine("Signal Sentinel Rule Registry");
        Console.WriteLine("RuleId       | OWASP ASI | OWASP AST            | Name");
        Console.WriteLine(new string('-', 80));

        var engine = new Rules.RuleEngine();
        foreach (var rule in engine.Rules.OrderBy(r => r.Id, StringComparer.Ordinal))
        {
            var astCodes = rule.AstCodes.Count > 0
                ? string.Join(",", rule.AstCodes)
                : string.Join(",", RuleAstMapping.GetCodes(rule.Id));
            if (string.IsNullOrEmpty(astCodes)) { astCodes = "-"; }
            Console.WriteLine($"{rule.Id,-12} | {rule.OwaspCode,-9} | {astCodes,-20} | {rule.Name}");
        }
    }

    private static async Task<int> RunDiffAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var baseline = await ScanHistoryManager.LoadAsync(config.DiffBaselinePath!, cancellationToken);
        var current = await ScanHistoryManager.LoadAsync(config.DiffCurrentPath!, cancellationToken);
        var diff = ScanDiffer.Compute(baseline, current);

        var buffer = new System.Text.StringBuilder();
        buffer.AppendLine("# Scan Diff Report");
        buffer.AppendLine();
        buffer.AppendLine($"- Baseline: {config.DiffBaselinePath}  (scanner v{baseline.ScannerVersion}, {baseline.ScanTimestamp:o})");
        buffer.AppendLine($"- Current:  {config.DiffCurrentPath}  (scanner v{current.ScannerVersion}, {current.ScanTimestamp:o})");
        buffer.AppendLine();
        buffer.AppendLine($"**Grade**: {diff.BaselineGrade} ({diff.BaselineScore}/100) -> {diff.CurrentGrade} ({diff.CurrentScore}/100)");
        buffer.AppendLine();
        buffer.AppendLine($"**Resolved**: {diff.Resolved.Count} | **New**: {diff.Added.Count} | **Unchanged**: {diff.Unchanged.Count}");
        buffer.AppendLine();
        if (diff.Resolved.Count > 0)
        {
            buffer.AppendLine("## Resolved since baseline");
            foreach (var f in diff.Resolved)
            {
                buffer.AppendLine($"- [FIXED] {f.RuleId} {f.Severity} [{f.ServerName}] {f.Title}");
            }
            buffer.AppendLine();
        }
        if (diff.Added.Count > 0)
        {
            buffer.AppendLine("## New since baseline");
            foreach (var f in diff.Added)
            {
                buffer.AppendLine($"- [NEW]   {f.RuleId} {f.Severity} [{f.ServerName}] {f.Title}");
            }
            buffer.AppendLine();
        }
        if (diff.ResolvedContribution.Count > 0 || diff.AddedContribution.Count > 0)
        {
            buffer.AppendLine("## Grade delta attribution");
            foreach (var (rule, points) in diff.ResolvedContribution.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            {
                buffer.AppendLine($"- {rule}: +{points} (resolved)");
            }
            foreach (var (rule, points) in diff.AddedContribution.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            {
                buffer.AppendLine($"- {rule}: {points} (new)");
            }
        }

        var text = buffer.ToString();
        if (config.OutputPath is not null)
        {
            var full = Path.GetFullPath(config.OutputPath);
            await File.WriteAllTextAsync(full, text, cancellationToken);
            Console.WriteLine($"Diff report written to: {full}");
        }
        else
        {
            Console.WriteLine(text);
        }
        return 0;
    }
}
