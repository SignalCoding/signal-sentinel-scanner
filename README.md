# Signal Sentinel

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)
[![OWASP](https://img.shields.io/badge/OWASP-ASI%20Top%2010-green.svg)](https://owasp.org/www-project-agentic-ai-top-10/)
[![Version](https://img.shields.io/badge/version-2.3.0-blue.svg)](https://github.com/SignalCoding/signal-sentinel-scanner/releases)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-orange.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)

**Signal Sentinel** is a security-first MCP (Model Context Protocol) and Agent Skill security product family, designed to address the critical security gap in the agentic AI ecosystem.

> **Positioning:** Signal Sentinel Scanner is a fast, deterministic, offline-capable **first-pass authoring aid** for MCP operators and skill authors. It is not a substitute for a full runtime defence stack — pair it with Bandit, Gitleaks, Semgrep, and (for runtime) Sentinel Gateway / Enkrypt Skill Sentinel for defence in depth. Every report declares its scope explicitly in an "Scanner Scope" section.

## Products

| Product | Type | Description |
|---------|------|-------------|
| **Sentinel Scanner** | CLI Tool | Security audit tool for MCP server configurations AND Agent Skill packages |
| **Sentinel Gateway** | Proxy/Firewall | Real-time security enforcement between agents and MCP servers |
| **Sentinel Classify** | MCP Server | Document classification and sensitivity labelling |

## Signal Sentinel Scanner

The Scanner is a command-line tool that audits MCP server configurations and Agent Skill packages for security vulnerabilities. It produces a scored report with OWASP ASI01-ASI10 + AST01-AST10 + MCP01-MCP10 triple mapping and remediation guidance.

### What's new in v2.3.0

- `.sentinel-suppressions.json` — accept specific findings with a justification, approver and expiry; retained in every report format for audit.
- `--min-confidence <f>` and `--triage` — confidence-aware filtering; see [docs/confidence-rubric.md](docs/confidence-rubric.md).
- `sentinel-scan diff <baseline.json> <current.json>` — resolved / new / grade-attribution deltas between runs.
- `--save-history`, `--environment`, `--complementary-tools` — per-environment scoping + explicit scope disclosure in reports.
- `SS-INFO-001` non-MCP endpoint detection — no more misleading "Grade A" against a React SPA. When it fires, every MCP-protocol rule (SS-001..SS-010, SS-019..SS-025) is automatically suppressed for that target so the report is internally consistent.
- Case-insensitive, lemma-aware `SS-012` — eliminates mechanical false positives from "Network" vs "network access". Lemma table now covers `disk`, `volume`, `mount`, `/proc`, `/sys`, `/dev`, `procfs`, `sysfs` as filesystem synonyms.
- YAML `capabilities:` block is **authoritative** for SS-012. Declare `capabilities: [read-filesystem, shell_command_execution, network]` in a skill's frontmatter and SS-012 will trust it over prose-based heuristics.
- Suppressed scans now display a **technical-debt exposure banner**: "if these N suppression(s) were removed, your grade would be X (Y/100) instead of Z (W/100)" — no hidden risk behind a green grade.
- Pre-commit hook integrations for [pre-commit.com](https://pre-commit.com), [lefthook](https://github.com/evilmartians/lefthook) and [husky](https://typicode.github.io/husky/) under [`hooks/`](hooks/).

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

# Generate SARIF for GitHub Code Scanning (new in v2.2)
sentinel-scan --discover --format sarif --output results.sarif

# Air-gapped / offline scan (refuses --remote, blocks all network egress)
sentinel-scan --discover --skills --offline

# Baseline comparison for rug-pull / schema mutation detection (SS-022)
sentinel-scan --discover --baseline .sentinel-baseline.json
sentinel-scan --discover --update-baseline

# Load Sigma YAML rules from a file or directory
sentinel-scan --discover --sigma-rules ./sigma-rules/

# CI mode (exit code 1 on critical/high findings)
sentinel-scan --discover --skills --ci --format json
```

### What's New in v2.2.0

| Capability | Description |
|------------|-------------|
| **Rug Pull Detection (SS-022)** | Compare current scan against a saved baseline; flags schema mutations, additions, removals as Critical / High / Medium |
| **Shadow Tool Injection (SS-023)** | Typosquat detection using Levenshtein distance against privileged tools and cross-server duplicates |
| **Skill Integrity (SS-024)** | Detects skills that ship without `.sentinel-sig`, `SHA256SUMS`, or `cosign.sig` signature artefacts |
| **Excessive Response Size (SS-025)** | Flags tool descriptions > 10 KB and JSON schemas nested > 10 levels deep |
| **Offline Mode (`--offline`)** | Zero-network-egress guarantee for air-gapped / HMG / defence environments |
| **SARIF v2.1.0 Output** | OASIS-compliant, compatible with GitHub Code Scanning and IDE extensions |
| **Sigma Rule Import** | Load community Sigma YAML rules; supports `title/id/description/level/tags/logsource/detection` subset |
| **Finding Deduplication** | Collapses duplicate findings with `OccurrenceCount` (`[xN]` annotation in reports) |

### Output Formats

- **Markdown** (default): Human-readable report with emoji indicators
- **JSON**: Machine-readable for CI/CD integration
- **HTML**: Styled report with Signal Coding branding
- **SARIF v2.1.0**: OASIS standard, GitHub Code Scanning compatible *(new in v2.2)*

### Security Rules

25 security rules across MCP and Agent Skill scanning, aligned with OWASP Agentic AI Top 10 and OWASP MCP Top 10:

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
| SS-022 | ASI01 | Rug Pull Detection / Schema Mutation *(v2.2)* |
| SS-023 | ASI01 | Shadow Tool Injection (typosquat) *(v2.2)* |
| SS-025 | ASI06 | Excessive Tool Response Size *(v2.2)* |

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
| SS-024 | ASI04 | Skill Integrity Verification *(v2.2)* |

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
      RuleFormats/                   # Sigma YAML loader (v2.2)
      Security/                      # Levenshtein distance, hash pinning, credential patterns
    SignalSentinel.Scanner/          # CLI scanner application
      McpClient/                     # MCP connection and enumeration (stdio, HTTP, WebSocket)
      SkillParser/                   # SKILL.md parser, script inventory, integrity verifier
      Baseline/                      # Schema hasher + baseline manager (v2.2)
      Dedup/                         # Finding deduplication engine (v2.2)
      Offline/                       # Offline guard and violation exception (v2.2)
      Rules/                         # MCP security rules (SS-001..SS-010, SS-019..SS-023, SS-025)
        SkillRules/                  # Skill security rules (SS-011..SS-018, SS-024)
      Scoring/                       # OWASP dual mapping and severity scoring
      Reports/                       # JSON, Markdown, HTML, SARIF v2.1.0 report generators
  tests/
    SignalSentinel.Scanner.Tests/    # Unit and integration tests (254 tests)
  deploy/
    docker/                          # Multi-arch Docker container
  .github/
    workflows/                       # CI/CD pipelines (SHA-pinned actions)
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
