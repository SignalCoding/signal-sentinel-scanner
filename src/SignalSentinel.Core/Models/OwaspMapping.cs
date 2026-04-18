namespace SignalSentinel.Core.Models;

/// <summary>
/// OWASP Agentic AI Security Top 10 (2026) risk codes.
/// </summary>
public static class OwaspAsiCodes
{
    /// <summary>ASI01: Agent Goal Hijack - Redirecting agent goals via injected instructions.</summary>
    public const string ASI01 = "ASI01";

    /// <summary>ASI02: Tool Misuse &amp; Exploitation - Misusing legitimate tools via unsafe chaining.</summary>
    public const string ASI02 = "ASI02";

    /// <summary>ASI03: Identity &amp; Privilege Abuse - Exploiting delegated trust or credentials.</summary>
    public const string ASI03 = "ASI03";

    /// <summary>ASI04: Supply Chain Vulnerabilities - Compromised third-party tools or plugins.</summary>
    public const string ASI04 = "ASI04";

    /// <summary>ASI05: Unexpected Code Execution - Unsafe execution of dynamically generated code.</summary>
    public const string ASI05 = "ASI05";

    /// <summary>ASI06: Memory &amp; Context Poisoning - Poisoning RAG databases or agent memory.</summary>
    public const string ASI06 = "ASI06";

    /// <summary>ASI07: Insecure Inter-Agent Communication - Compromised agents sending malicious instructions.</summary>
    public const string ASI07 = "ASI07";

    /// <summary>ASI08: Cascading Failures - Single agent fault propagating via automation.</summary>
    public const string ASI08 = "ASI08";

    /// <summary>ASI09: Sensitive Data Leakage - Agent inadvertently leaking confidential data.</summary>
    public const string ASI09 = "ASI09";

    /// <summary>ASI10: Rogue Agents - Agents drifting from intended behaviour with harmful autonomy.</summary>
    public const string ASI10 = "ASI10";

    /// <summary>
    /// Gets the description for an OWASP ASI code.
    /// </summary>
    public static string GetDescription(string code) => code switch
    {
        ASI01 => "Agent Goal Hijack - Redirecting agent goals via injected instructions or poisoned content",
        ASI02 => "Tool Misuse & Exploitation - Misusing legitimate tools via unsafe chaining or manipulated outputs",
        ASI03 => "Identity & Privilege Abuse - Exploiting delegated trust or inherited credentials",
        ASI04 => "Supply Chain Vulnerabilities - Compromised third-party tools, plugins, registries",
        ASI05 => "Unexpected Code Execution - Unsafe execution of dynamically generated code",
        ASI06 => "Memory & Context Poisoning - Poisoning RAG databases or agent memory to bias future actions",
        ASI07 => "Insecure Inter-Agent Communication - Compromised agents sending malicious instructions to peers",
        ASI08 => "Cascading Failures - Single agent fault propagating via automation",
        ASI09 => "Sensitive Data Leakage - Agent inadvertently leaking confidential data in responses",
        ASI10 => "Rogue Agents - Agents drifting from intended behaviour with harmful autonomy",
        _ => "Unknown OWASP ASI code"
    };

    /// <summary>
    /// Gets the URL to the OWASP documentation for an ASI code.
    /// </summary>
    public static string GetDocumentationUrl(string code)
    {
        ArgumentNullException.ThrowIfNull(code);
        return $"https://owasp.org/www-project-agentic-ai-top-10/#{code.ToLowerInvariant()}";
    }
}

/// <summary>
/// OWASP Agentic Skills Top 10 (2026) risk codes (AST01..AST10).
/// Rules may map to one or more AST categories via <see cref="Finding.AstCodes"/>.
/// </summary>
public static class OwaspAstCodes
{
    /// <summary>AST01: Malicious Skills - Skill contains a deliberately harmful payload.</summary>
    public const string AST01 = "AST01";

    /// <summary>AST02: Supply Chain - Skill dependencies are unverified, unpinned, or compromised.</summary>
    public const string AST02 = "AST02";

    /// <summary>AST03: Over-Privileged - Skill declares or uses broader capabilities than necessary.</summary>
    public const string AST03 = "AST03";

    /// <summary>AST04: Insecure Metadata - Metadata (description, tags) is inaccurate or contains hidden content.</summary>
    public const string AST04 = "AST04";

    /// <summary>AST05: Unsafe Deserialisation - Skill uses unsafe YAML/JSON/pickle/etc. loaders.</summary>
    public const string AST05 = "AST05";

    /// <summary>AST06: Weak Isolation - Skill escapes intended sandbox (shell, network, filesystem).</summary>
    public const string AST06 = "AST06";

    /// <summary>AST07: Update Drift - Skill integrity cannot be verified across updates.</summary>
    public const string AST07 = "AST07";

    /// <summary>AST08: Poor Scanning - Sole reliance on a single scanner or regex-only analysis.</summary>
    public const string AST08 = "AST08";

    /// <summary>AST09: No Governance - No change-management, ownership, or review process for skills.</summary>
    public const string AST09 = "AST09";

    /// <summary>AST10: Cross-Platform Reuse - Skill mixes incompatible platform semantics unsafely.</summary>
    public const string AST10 = "AST10";

    /// <summary>
    /// Gets the short label for an AST code.
    /// </summary>
    public static string GetLabel(string code) => code switch
    {
        AST01 => "Malicious Skills",
        AST02 => "Supply Chain",
        AST03 => "Over-Privileged",
        AST04 => "Insecure Metadata",
        AST05 => "Unsafe Deserialisation",
        AST06 => "Weak Isolation",
        AST07 => "Update Drift",
        AST08 => "Poor Scanning",
        AST09 => "No Governance",
        AST10 => "Cross-Platform Reuse",
        _ => "Unknown AST code"
    };

    /// <summary>
    /// Gets the documentation URL for an AST code.
    /// </summary>
    public static string GetDocumentationUrl(string code)
    {
        ArgumentNullException.ThrowIfNull(code);
        return $"https://owasp.org/www-project-agentic-skills-top-10/#{code.ToLowerInvariant()}";
    }
}
