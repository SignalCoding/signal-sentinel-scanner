using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-010: Detects cross-server attack paths by analyzing capability combinations.
/// Covers multiple OWASP ASI codes depending on the attack path type.
/// </summary>
public sealed partial class CrossServerAttackPathRule : IRule
{
    public string Id => RuleConstants.Rules.CrossServerAttackPaths;
    public string Name => "Cross-Server Attack Path Analysis";
    public string OwaspCode => OwaspAsiCodes.ASI02;
    public string Description => "Analyzes tool capabilities across multiple MCP servers to identify potential attack chains.";
    public bool EnabledByDefault => true;

    private readonly List<AttackPath> _detectedAttackPaths = [];

    public IReadOnlyList<AttackPath> DetectedAttackPaths => _detectedAttackPaths;

    [GeneratedRegex(@"\b(read|get|fetch|retrieve|load|download|query|select)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ReadPattern();

    [GeneratedRegex(@"\b(write|save|store|upload|create|insert|update|modify|put)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex WritePattern();

    [GeneratedRegex(@"\b(http|https|url|endpoint|api|request|fetch|curl|wget|socket|network)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex NetworkPattern();

    [GeneratedRegex(@"\b(file|path|directory|folder|disk|filesystem|fs)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex FilePattern();

    [GeneratedRegex(@"\b(database|db|sql|query|table|mongo|redis|postgres|mysql)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex DatabasePattern();

    [GeneratedRegex(@"\b(exec|execute|run|shell|command|script|eval|system|spawn)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ExecutePattern();

    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        
        var findings = new List<Finding>();
        _detectedAttackPaths.Clear();

        // Only analyze if multiple servers
        var connectedServers = context.Servers.Where(s => s.ConnectionSuccessful).ToList();
        if (connectedServers.Count < 2)
        {
            return Task.FromResult<IEnumerable<Finding>>(findings);
        }

        // Build capability map for all tools
        var capabilityMap = new Dictionary<string, List<(string ServerName, string ToolName, ToolCapability Caps)>>();
        foreach (var server in connectedServers)
        {
            foreach (var tool in server.Tools)
            {
                var caps = ClassifyTool(tool.Name, tool.Description ?? string.Empty);
                if (caps != ToolCapability.None)
                {
                    var key = server.ServerName;
                    if (!capabilityMap.ContainsKey(key))
                    {
                        capabilityMap[key] = [];
                    }
                    capabilityMap[key].Add((server.ServerName, tool.Name, caps));
                }
            }
        }

        // Detect attack paths
        var attackPathId = 0;

        // Attack Path 1: Read File + Network Access = Data Exfiltration
        var fileReaders = capabilityMap.Values.SelectMany(v => v)
            .Where(t => t.Caps.HasFlag(ToolCapability.ReadFile))
            .ToList();
        var networkSenders = capabilityMap.Values.SelectMany(v => v)
            .Where(t => t.Caps.HasFlag(ToolCapability.NetworkAccess))
            .ToList();

        foreach (var reader in fileReaders)
        {
            foreach (var sender in networkSenders)
            {
                if (reader.ServerName != sender.ServerName)
                {
                    var path = new AttackPath
                    {
                        Id = $"AP-{++attackPathId:D3}",
                        Description = "Data Exfiltration: File read capability combined with network access enables reading local files and sending them to external endpoints.",
                        Severity = Severity.Critical,
                        OwaspCodes = [OwaspAsiCodes.ASI02, OwaspAsiCodes.ASI09],
                        Steps =
                        [
                            new AttackPathStep
                            {
                                ServerName = reader.ServerName,
                                ToolName = reader.ToolName,
                                Capability = ToolCapability.ReadFile,
                                Description = "Read sensitive file content"
                            },
                            new AttackPathStep
                            {
                                ServerName = sender.ServerName,
                                ToolName = sender.ToolName,
                                Capability = ToolCapability.NetworkAccess,
                                Description = "Exfiltrate data to external endpoint"
                            }
                        ],
                        Remediation = "Implement network egress controls. Restrict file read access to necessary paths. Monitor for unusual data transfer patterns."
                    };
                    _detectedAttackPaths.Add(path);

                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspAsiCodes.ASI09,
                        Severity = Severity.Critical,
                        Title = "Cross-Server Data Exfiltration Path",
                        Description = $"Attack path detected: {reader.ServerName}:{reader.ToolName} (file read) -> {sender.ServerName}:{sender.ToolName} (network send) enables data exfiltration.",
                        Remediation = path.Remediation,
                        ServerName = $"{reader.ServerName} -> {sender.ServerName}",
                        Evidence = $"Path ID: {path.Id}",
                        Confidence = 0.85
                    });
                }
            }
        }

        // Attack Path 2: Database Read + File Write = Data Dump
        var dbReaders = capabilityMap.Values.SelectMany(v => v)
            .Where(t => t.Caps.HasFlag(ToolCapability.ReadData))
            .ToList();
        var fileWriters = capabilityMap.Values.SelectMany(v => v)
            .Where(t => t.Caps.HasFlag(ToolCapability.WriteFile))
            .ToList();

        foreach (var dbReader in dbReaders)
        {
            foreach (var fileWriter in fileWriters)
            {
                if (dbReader.ServerName != fileWriter.ServerName)
                {
                    var path = new AttackPath
                    {
                        Id = $"AP-{++attackPathId:D3}",
                        Description = "Database Dump: Database read capability combined with file write enables extracting database contents to the filesystem.",
                        Severity = Severity.High,
                        OwaspCodes = [OwaspAsiCodes.ASI02, OwaspAsiCodes.ASI09],
                        Steps =
                        [
                            new AttackPathStep
                            {
                                ServerName = dbReader.ServerName,
                                ToolName = dbReader.ToolName,
                                Capability = ToolCapability.ReadData,
                                Description = "Query database for sensitive data"
                            },
                            new AttackPathStep
                            {
                                ServerName = fileWriter.ServerName,
                                ToolName = fileWriter.ToolName,
                                Capability = ToolCapability.WriteFile,
                                Description = "Write data to filesystem"
                            }
                        ],
                        Remediation = "Implement database query auditing. Restrict file write paths. Consider making file operations append-only."
                    };
                    _detectedAttackPaths.Add(path);

                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspAsiCodes.ASI02,
                        Severity = Severity.High,
                        Title = "Cross-Server Database Dump Path",
                        Description = $"Attack path detected: {dbReader.ServerName}:{dbReader.ToolName} (DB read) -> {fileWriter.ServerName}:{fileWriter.ToolName} (file write) enables data dumping.",
                        Remediation = path.Remediation,
                        ServerName = $"{dbReader.ServerName} -> {fileWriter.ServerName}",
                        Evidence = $"Path ID: {path.Id}",
                        Confidence = 0.8
                    });
                }
            }
        }

        // Attack Path 3: Network Read + Code Execution = Remote Code Execution
        var networkReaders = capabilityMap.Values.SelectMany(v => v)
            .Where(t => t.Caps.HasFlag(ToolCapability.NetworkAccess))
            .ToList();
        var codeExecutors = capabilityMap.Values.SelectMany(v => v)
            .Where(t => t.Caps.HasFlag(ToolCapability.CodeExecution))
            .ToList();

        foreach (var netReader in networkReaders)
        {
            foreach (var executor in codeExecutors)
            {
                if (netReader.ServerName != executor.ServerName)
                {
                    var path = new AttackPath
                    {
                        Id = $"AP-{++attackPathId:D3}",
                        Description = "Remote Code Execution: Network fetch capability combined with code execution enables downloading and running arbitrary code.",
                        Severity = Severity.Critical,
                        OwaspCodes = [OwaspAsiCodes.ASI04, OwaspAsiCodes.ASI05],
                        Steps =
                        [
                            new AttackPathStep
                            {
                                ServerName = netReader.ServerName,
                                ToolName = netReader.ToolName,
                                Capability = ToolCapability.NetworkAccess,
                                Description = "Fetch malicious code from external source"
                            },
                            new AttackPathStep
                            {
                                ServerName = executor.ServerName,
                                ToolName = executor.ToolName,
                                Capability = ToolCapability.CodeExecution,
                                Description = "Execute fetched code"
                            }
                        ],
                        Remediation = "Restrict network access to allowlisted domains. Implement code signing requirements. Sandbox code execution environments."
                    };
                    _detectedAttackPaths.Add(path);

                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspAsiCodes.ASI05,
                        Severity = Severity.Critical,
                        Title = "Cross-Server Remote Code Execution Path",
                        Description = $"Attack path detected: {netReader.ServerName}:{netReader.ToolName} (network) -> {executor.ServerName}:{executor.ToolName} (execute) enables remote code execution.",
                        Remediation = path.Remediation,
                        ServerName = $"{netReader.ServerName} -> {executor.ServerName}",
                        Evidence = $"Path ID: {path.Id}",
                        Confidence = 0.9
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static ToolCapability ClassifyTool(string name, string description)
    {
        var combined = $"{name} {description}";
        var caps = ToolCapability.None;

        if (ReadPattern().IsMatch(combined) && FilePattern().IsMatch(combined))
            caps |= ToolCapability.ReadFile;

        if (WritePattern().IsMatch(combined) && FilePattern().IsMatch(combined))
            caps |= ToolCapability.WriteFile;

        if (ReadPattern().IsMatch(combined) && DatabasePattern().IsMatch(combined))
            caps |= ToolCapability.ReadData;

        if (WritePattern().IsMatch(combined) && DatabasePattern().IsMatch(combined))
            caps |= ToolCapability.WriteData;

        if (NetworkPattern().IsMatch(combined))
            caps |= ToolCapability.NetworkAccess;

        if (ExecutePattern().IsMatch(combined))
            caps |= ToolCapability.CodeExecution;

        return caps;
    }
}
