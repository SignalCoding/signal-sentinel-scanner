// -----------------------------------------------------------------------
// <copyright file="LemmaRegressionTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

/// <summary>
/// v2.4.0 regression tests for the lemma-tightening work (A3, B1, B2, B3).
/// Each test is phrased against a concrete false positive observed during
/// live production scans so the regressions are pinned to real scenarios.
/// </summary>
public class LemmaRegressionTests
{
    // ---- A3: SS-008 certificate vs credential ------------------------------

    [Theory]
    [InlineData("tls_expiry", "Returns the expiry date of the server TLS certificate.")]
    [InlineData("get_certificate", "Fetches the server's public TLS certificate chain.")]
    [InlineData("ca_bundle", "Downloads the trusted CA bundle.")]
    [InlineData("public_key", "Returns the public key for the given principal.")]
    public async Task Ss008_DoesNotFire_OnPublicCertTools(string toolName, string description)
    {
        var findings = await Run(new SensitiveDataRule(), toolName, description);
        findings.ShouldNotContain(f => f.RuleId == "SS-008" && f.Title.Contains("Credential"));
    }

    [Theory]
    [InlineData("get_api_key")]
    [InlineData("fetch_password")]
    [InlineData("load_private_key")]
    [InlineData("vault_secret")]
    [InlineData("bearer_token")]
    public async Task Ss008_StillFires_OnRealCredentialTools(string toolName)
    {
        var findings = await Run(new SensitiveDataRule(), toolName, "Handles secret material.");
        findings.ShouldContain(f => f.RuleId == "SS-008" && f.Title.Contains("Credential"));
    }

    // ---- B1: SS-002 admin privilege phrase-based ---------------------------

    [Theory]
    [InlineData("get_system_status", "Returns the system health check status.")]
    [InlineData("system_info", "Returns CPU and memory info for the running host.")]
    [InlineData("root_cause_analysis", "Identifies root causes for the recent incident.")]
    public async Task Ss002_DoesNotFire_OnInformationalTools(string toolName, string description)
    {
        var findings = await Run(new OverbroadPermissionsRule(), toolName, description);
        findings.ShouldNotContain(f => f.RuleId == "SS-002");
    }

    [Theory]
    [InlineData("run_as_root", "Runs the given command with root access.")]
    [InlineData("sudo_exec", "Executes a shell command with sudo.")]
    [InlineData("elevate", "Requests elevated privileges for the current session.")]
    [InlineData("impersonate_user", "Impersonates another user for the API call.")]
    public async Task Ss002_StillFires_OnActualPrivEsc(string toolName, string description)
    {
        var findings = await Run(new OverbroadPermissionsRule(), toolName, description);
        findings.ShouldContain(f => f.RuleId == "SS-002");
    }

    // ---- B2: SS-005 code-execution phrase-based ----------------------------

    [Theory]
    [InlineData("get_execution_status", "Returns the execution state of the workflow.")]
    [InlineData("run_report", "Runs the weekly sales report.")]
    [InlineData("execute_query", "Executes a read-only SELECT query.")]
    public async Task Ss005_DoesNotFire_OnReadOnlyTools(string toolName, string description)
    {
        var findings = await Run(new CodeExecutionRule(), toolName, description);
        findings.ShouldNotContain(f => f.RuleId == "SS-005");
    }

    [Theory]
    [InlineData("eval_expression", "Calls eval() on the supplied input.")]
    [InlineData("shell_exec", "Runs arbitrary code via bash -c.")]
    [InlineData("python_subprocess", "Uses subprocess.Popen to spawn a shell.")]
    public async Task Ss005_StillFires_OnActualCodeExecution(string toolName, string description)
    {
        var findings = await Run(new CodeExecutionRule(), toolName, description);
        findings.ShouldContain(f => f.RuleId == "SS-005");
    }

    // ---- B3: SS-006 RAM vs RAG ---------------------------------------------

    [Theory]
    [InlineData("memory_usage", "Returns the process's memory usage in MB.")]
    [InlineData("ram_stats", "Returns RAM usage statistics.")]
    [InlineData("proc_meminfo", "Reads /proc/meminfo and returns parsed fields.")]
    [InlineData("heap_snapshot", "Takes a heap snapshot and returns it as a file.")]
    public async Task Ss006_DoesNotFire_OnHostResourceTools(string toolName, string description)
    {
        var findings = await Run(new MemoryWriteRule(), toolName, description);
        findings.ShouldNotContain(f => f.RuleId == "SS-006" || f.RuleId == "SS-007");
    }

    [Theory]
    [InlineData("write_agent_memory", "Writes an entry to the agent's long-term memory store.")]
    [InlineData("upsert_vector_store", "Upserts embeddings into the Pinecone vector index.")]
    [InlineData("save_conversation_history", "Persists the current conversation history for later retrieval.")]
    public async Task Ss006_StillFires_OnRealMemoryWrites(string toolName, string description)
    {
        var findings = await Run(new MemoryWriteRule(), toolName, description);
        findings.ShouldContain(f => f.RuleId == "SS-006" || f.RuleId == "SS-007");
    }

    // ---- helper ------------------------------------------------------------

    private static async Task<IReadOnlyList<Finding>> Run(IRule rule, string toolName, string description)
    {
        var ctx = new ScanContext
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig
                    {
                        Name = "server",
                        Transport = McpTransportType.Stdio,
                        Command = "node",
                        Args = ["server.js"],
                    },
                    ServerName = "server",
                    Transport = "Stdio",
                    ConnectionSuccessful = true,
                    Tools =
                    [
                        new McpToolDefinition
                        {
                            Name = toolName,
                            Description = description,
                        }
                    ],
                }
            ]
        };

        var findings = await rule.EvaluateAsync(ctx).ConfigureAwait(true);
        return [.. findings];
    }
}
