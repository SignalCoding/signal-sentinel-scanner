# Signal Sentinel

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)
[![OWASP](https://img.shields.io/badge/OWASP-ASI%20Top%2010-green.svg)](https://owasp.org/www-project-agentic-ai-top-10/)

**Signal Sentinel** is a security-first MCP (Model Context Protocol) security product family, designed to address the critical security gap in the agentic AI ecosystem.

## Products

| Product | Type | Description |
|---------|------|-------------|
| **Sentinel Scanner** | CLI Tool | Security audit tool for MCP server configurations |
| **Sentinel Gateway** | Proxy/Firewall | Real-time security enforcement between agents and MCP servers |
| **Sentinel Classify** | MCP Server | Document classification and sensitivity labelling |

## Signal Sentinel Scanner

The Scanner is a command-line tool that audits MCP server configurations for security vulnerabilities. It produces a scored report with OWASP ASI01-ASI10 mapping and remediation guidance.

### Installation

```bash
# Install as .NET global tool
dotnet tool install -g SignalSentinel.Scanner

# Or run via Docker
docker run signalcoding/sentinel-scanner --help
```

### Quick Start

```bash
# Auto-discover and scan all MCP configurations
sentinel-scan --discover

# Scan a specific configuration file
sentinel-scan --config ~/.cursor/mcp.json

# Scan a remote MCP server
sentinel-scan --remote https://mcp.example.com/mcp

# Generate HTML report
sentinel-scan --discover --format html --output report.html

# CI mode (exit code 1 on critical/high findings)
sentinel-scan --discover --ci --format json
```

### Output Formats

- **Markdown** (default): Human-readable report with emoji indicators
- **JSON**: Machine-readable for CI/CD integration
- **HTML**: Styled report with Signal Coding branding

### Security Rules

The Scanner implements 10 security rules aligned with OWASP Agentic AI Top 10:

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

### Grading System

| Grade | Description |
|-------|-------------|
| **A** | No critical/high findings, no attack paths |
| **B** | No critical findings, minor issues |
| **C** | 1-2 high findings or 1 attack path |
| **D** | Critical findings present |
| **F** | Multiple critical findings or attack paths |

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
├── src/
│   ├── SignalSentinel.Core/       # Shared library (MCP protocol, security patterns)
│   ├── SignalSentinel.Scanner/    # CLI scanner application
│   └── SignalSentinel.Gateway/    # Proxy/firewall (Phase 2)
├── tests/
│   └── SignalSentinel.Scanner.Tests/
├── deploy/
│   ├── docker/
│   └── azure/
└── policies/                      # Security policy templates
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
