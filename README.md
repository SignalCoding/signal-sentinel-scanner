# Signal Sentinel

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)
[![OWASP](https://img.shields.io/badge/OWASP-ASI%20Top%2010-green.svg)](https://owasp.org/www-project-agentic-ai-top-10/)
[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)](https://github.com/SignalCoding/signal-sentinel-scanner/releases)

**Signal Sentinel** is a security-first MCP (Model Context Protocol) and Agent Skill security product family, designed to address the critical security gap in the agentic AI ecosystem.

## Products

| Product | Type | Description |
|---------|------|-------------|
| **Sentinel Scanner** | CLI Tool | Security audit tool for MCP server configurations AND Agent Skill packages |
| **Sentinel Gateway** | Proxy/Firewall | Real-time security enforcement between agents and MCP servers |
| **Sentinel Classify** | MCP Server | Document classification and sensitivity labelling |

## Signal Sentinel Scanner

The Scanner is a command-line tool that audits MCP server configurations and Agent Skill packages for security vulnerabilities. It produces a scored report with OWASP ASI01-ASI10 + MCP01-MCP10 dual mapping and remediation guidance.

### Installation

```bash
# Install as .NET global tool
dotnet tool install -g SignalSentinel.Scanner

# Or run via Docker
docker pull ghcr.io/signalcoding/signal-sentinel-scanner:latest
docker run --rm ghcr.io/signalcoding/signal-sentinel-scanner:latest --help
```

### Quick Start

```bash
# Auto-discover and scan all MCP configurations
sentinel-scan --discover

# Scan Agent Skills (auto-discover)
sentinel-scan --skills

# Scan both MCP and Skills
sentinel-scan --discover --skills

# Scan a specific skill directory
sentinel-scan --skills ~/.claude/skills/

# Scan a specific configuration file
sentinel-scan --config ~/.cursor/mcp.json

# Scan a remote MCP server (HTTP or WebSocket)
sentinel-scan --remote https://mcp.example.com/mcp
sentinel-scan --remote wss://mcp.example.com/ws

# Generate HTML report
sentinel-scan --discover --skills --format html --output report.html

# CI mode (exit code 1 on critical/high findings)
sentinel-scan --discover --skills --ci --format json
```

### Output Formats

- **Markdown** (default): Human-readable report with emoji indicators
- **JSON**: Machine-readable for CI/CD integration
- **HTML**: Styled report with Signal Coding branding

### Security Rules

21 security rules across MCP and Agent Skill scanning, aligned with OWASP Agentic AI Top 10 and OWASP MCP Top 10:

#### MCP Rules

| Rule | OWASP | Description |
|------|-------|-------------|
| SS-001 | ASI01 | Tool Poisoning Detection |
| SS-002 | ASI02 | Overbroad Permissions Detection |
| SS-003 | ASI03 | Missing Authentication Detection |
| SS-004 | ASI04 | Supply Chain Vulnerability Detection |
| SS-005 | ASI05 | Code Execution Capability Detection |
| SS-006 | ASI06 | Memory/Context Write Access Detection |
| SS-007 | ASI07 | Inter-Agent Communication Detection |
| SS-008 | ASI09 | Sensitive Data Access Detection |
| SS-009 | ASI01 | Excessive Description Length |
| SS-010 | ASI02 | Cross-Server Attack Path Analysis |
| SS-019 | ASI03 | Credential Hygiene Check |
| SS-020 | ASI03 | OAuth 2.1 Compliance Check |
| SS-021 | ASI04 | Package Provenance Check |

#### Skill Rules

| Rule | OWASP | Description |
|------|-------|-------------|
| SS-011 | ASI01 | Skill Prompt Injection Detection |
| SS-012 | ASI02 | Skill Scope Violation Detection |
| SS-013 | ASI03 | Skill Credential Access Detection |
| SS-014 | ASI09 | Skill Data Exfiltration Detection |
| SS-015 | ASI01 | Skill Obfuscation Detection |
| SS-016 | ASI05 | Skill Script Payload Detection |
| SS-017 | ASI02 | Skill Excessive Permissions Detection |
| SS-018 | ASI01 | Skill Hidden Content Detection |

### Supported Platforms (Auto-Discovery)

| Platform | MCP Configs | Agent Skills |
|----------|-------------|--------------|
| Claude Desktop | Yes | - |
| Claude Code | - | Yes |
| Cursor | Yes | Yes |
| VS Code | Yes | - |
| Windsurf | Yes | Yes |
| Zed | Yes | - |
| OpenAI Codex CLI | - | Yes |

### Grading System

| Grade | Description |
|-------|-------------|
| **A** | No critical/high findings, no attack paths |
| **B** | No critical findings, minor issues |
| **C** | 1-2 high findings or 1 attack path |
| **D** | Critical findings present |
| **F** | Multiple critical findings or attack paths |

### Transports

| Transport | Status |
|-----------|--------|
| stdio | Supported |
| HTTP/SSE | Supported |
| Streamable HTTP | Supported |
| WebSocket (ws/wss) | Supported |

## Building from Source

### Prerequisites

- .NET 10 SDK
- Git

### Build

```bash
git clone https://github.com/SignalCoding/signal-sentinel-scanner.git
cd signal-sentinel-scanner
dotnet build
```

### Test

```bash
dotnet test
```

### Package

```bash
dotnet pack -c Release
```

## Architecture

```
signal-sentinel/
  src/
    SignalSentinel.Core/             # Shared library (MCP protocol, security patterns, models)
    SignalSentinel.Scanner/          # CLI scanner application
      McpClient/                     # MCP connection and enumeration
      SkillParser/                   # SKILL.md parser, script inventory, auto-discovery
      Rules/                         # MCP security rules (SS-001 to SS-010, SS-019 to SS-021)
        SkillRules/                  # Skill security rules (SS-011 to SS-018)
      Scoring/                       # OWASP dual mapping and severity scoring
      Reports/                       # JSON, Markdown, HTML report generators
  tests/
    SignalSentinel.Scanner.Tests/    # Unit and integration tests (120 tests)
  deploy/
    docker/                          # Multi-arch Docker container
  .github/
    workflows/                       # CI/CD pipelines
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for our security policy and responsible disclosure process.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## About Signal Coding Limited

Signal Coding Limited builds enterprise software engineering tools with defence-grade governance. Our products are built to MOD JSP 440/656 compliance and OWASP security standards.

**Website:** [signalcoding.co.uk](https://signalcoding.co.uk)

---

Copyright 2026 Signal Coding Limited. All rights reserved.
