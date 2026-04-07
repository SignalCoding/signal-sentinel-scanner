# Signal Sentinel Scanner - Installation and Usage Guide

**Version:** 2.1.1  
**Last Updated:** 2026-04-06  
**Repository:** https://github.com/SignalCoding/signal-sentinel-scanner

---

## Table of Contents

1. [Installation Options](#installation-options)
2. [.NET Tool Installation](#net-tool-installation)
3. [Docker Installation](#docker-installation)
4. [Quick Start](#quick-start)
5. [Command Reference](#command-reference)
6. [Usage Examples](#usage-examples)
7. [Output Formats](#output-formats)
8. [CI/CD Integration](#cicd-integration)
9. [Troubleshooting](#troubleshooting)

---

## Installation Options

Signal Sentinel Scanner is available in two formats:

| Format | Best For | Prerequisites |
|--------|----------|---------------|
| **.NET Tool** | Developers with .NET installed | .NET 10 SDK or later |
| **Docker** | CI/CD pipelines, any environment | Docker |

---

## .NET Tool Installation

### Prerequisites

- .NET 10 SDK or later
- Windows, macOS, or Linux

### Install

```bash
dotnet tool install -g SignalSentinel.Scanner
```

### Verify Installation

```bash
sentinel-scan --version
```

**Expected output:**
```
Signal Sentinel Scanner v2.1.1
```

### Update

```bash
dotnet tool update -g SignalSentinel.Scanner
```

### Uninstall

```bash
dotnet tool uninstall -g SignalSentinel.Scanner
```

### NuGet Package Details

| Package | NuGet URL |
|---------|-----------|
| SignalSentinel.Scanner | https://www.nuget.org/packages/SignalSentinel.Scanner |
| SignalSentinel.Core | https://www.nuget.org/packages/SignalSentinel.Core |

---

## Docker Installation

### Prerequisites

- Docker installed and running

### Pull the Image

```bash
docker pull ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1
```

### Available Tags

| Tag | Description |
|-----|-------------|
| `2.1.1` | Specific version (recommended for CI/CD) |
| `2.1` | Latest 2.1.x patch version |
| `2` | Latest 2.x.x version |
| `latest` | Latest stable release |

### Verify Installation

```bash
docker run --rm ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1 --version
```

### Image Details

| Property | Value |
|----------|-------|
| Registry | GitHub Container Registry (ghcr.io) |
| Image | `ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1` |
| Base | Alpine Linux (.NET runtime-deps) |
| Architecture | linux/amd64, linux/arm64 |
| User | Non-root (sentinel, uid 1000) |
| Size | ~50MB compressed |

---

## Quick Start

### Auto-Discover and Scan (Recommended)

The scanner can automatically find MCP configurations and Agent Skills from popular applications:

**.NET Tool:**
```bash
# Auto-discover MCP configurations
sentinel-scan --discover

# Auto-discover Agent Skills
sentinel-scan --skills

# Scan both MCP and Skills
sentinel-scan --discover --skills

# Scan a specific skill directory
sentinel-scan --skills ~/.claude/skills/
```

**Docker:**
```bash
# Mount user config directories for auto-discovery
docker run --rm \
  -v "$HOME/.cursor:/home/sentinel/.cursor:ro" \
  -v "$HOME/.config:/home/sentinel/.config:ro" \
  ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1 --discover --skills
```

**Windows Docker:**
```powershell
docker run --rm `
  -v "$env:USERPROFILE\.cursor:/home/sentinel/.cursor:ro" `
  -v "$env:APPDATA:/home/sentinel/AppData/Roaming:ro" `
  ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1 --discover --skills
```

### Scan a Specific Config File

**.NET Tool:**
```bash
sentinel-scan --config ~/.cursor/mcp.json
```

**Docker:**
```bash
docker run --rm \
  -v "$HOME/.cursor/mcp.json:/config/mcp.json:ro" \
  ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1 --config /config/mcp.json
```

### Scan a Remote MCP Server

**.NET Tool:**
```bash
sentinel-scan --remote https://mcp.example.com/sse
```

**Docker:**
```bash
docker run --rm ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1 \
  --remote https://mcp.example.com/sse
```

---

## Command Reference

### Synopsis

```
sentinel-scan [OPTIONS]
```

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config <path>` | `-c` | Path to MCP configuration file | - |
| `--remote <url>` | `-r` | Remote MCP server URL (http/https/ws/wss) | - |
| `--discover` | `-d` | Auto-discover MCP configurations | - |
| `--skills [path]` | `-s` | Scan Agent Skills (auto-discover or specify path) | - |
| `--format <format>` | `-f` | Output format: json, markdown, html | markdown |
| `--output <path>` | `-o` | Output file path | stdout |
| `--ci` | - | CI mode - exit code 1 on critical/high findings | false |
| `--verbose` | `-v` | Enable verbose output | false |
| `--timeout <seconds>` | `-t` | Connection timeout (max: 300) | 30 |
| `--help` | `-h` | Show help message | - |
| `--version` | - | Show version information | - |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully (no critical/high findings in CI mode) |
| 1 | Critical or high severity findings detected (CI mode only) |
| 2 | Scan failed (connection error, invalid config, etc.) |

---

## Usage Examples

### Generate HTML Report

**.NET Tool:**
```bash
sentinel-scan --discover --format html --output security-report.html
```

**Docker:**
```bash
docker run --rm \
  -v "$HOME/.cursor:/home/sentinel/.cursor:ro" \
  -v "$(pwd):/output" \
  ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1 \
  --discover --skills --format html --output /output/security-report.html
```

### Generate JSON for Processing

```bash
sentinel-scan --discover --format json --output results.json
```

### Verbose Scan with Timeout

```bash
sentinel-scan --discover --verbose --timeout 60
```

### Scan Multiple Sources

```bash
# Scan local config and remote server
sentinel-scan --config ./mcp-config.json --remote https://mcp.example.com/sse
```

---

## Output Formats

### Markdown (Default)

Best for terminal output and documentation.

```bash
sentinel-scan --discover --format markdown
```

### JSON

Best for CI/CD pipelines and programmatic processing.

```bash
sentinel-scan --discover --format json
```

**Sample JSON structure:**
```json
{
  "scanDate": "2026-04-04T08:00:00Z",
  "scannerVersion": "2.1.1",
  "grade": "B",
  "score": 85,
  "summary": {
    "serversScanned": 2,
    "totalTools": 15,
    "criticalFindings": 0,
    "highFindings": 1,
    "mediumFindings": 3
  },
  "findings": [...],
  "owaspCompliance": {...}
}
```

### HTML

Best for reports and sharing with stakeholders.

```bash
sentinel-scan --discover --format html --output report.html
```

Features:
- Signal Coding branding
- Colour-coded severity badges
- OWASP compliance matrix
- Responsive design
- Print-friendly

---

## CI/CD Integration

### GitHub Actions

```yaml
name: MCP Security Scan

on:
  push:
    paths:
      - 'mcp-config.json'
      - '.cursor/mcp.json'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'
      
      - name: Install Signal Sentinel
        run: dotnet tool install -g SignalSentinel.Scanner
      
      - name: Run Security Scan
        run: sentinel-scan --config ./mcp-config.json --ci --format json --output scan-results.json
      
      - name: Upload Results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-scan-results
          path: scan-results.json
```

### GitHub Actions (Docker)

```yaml
name: MCP Security Scan

on: [push]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Scan
        run: sentinel-scan --config ./mcp-config.json --ci --format json
```

### Azure DevOps

```yaml
trigger:
  paths:
    include:
      - 'mcp-config.json'

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UseDotNet@2
    inputs:
      version: '10.0.x'
  
  - script: dotnet tool install -g SignalSentinel.Scanner
    displayName: 'Install Signal Sentinel'
  
  - script: sentinel-scan --config ./mcp-config.json --ci --format json
    displayName: 'Run MCP Security Scan'
```

### GitLab CI

```yaml
mcp-security-scan:
  image: ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1
  script:
    - sentinel-scan --config ./mcp-config.json --ci --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Jenkins (Declarative Pipeline)

```groovy
pipeline {
    agent any
    
    stages {
        stage('MCP Security Scan') {
            steps {
                sh 'dotnet tool install -g SignalSentinel.Scanner || true'
                sh 'sentinel-scan --config ./mcp-config.json --ci --format html --output mcp-security-report.html'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'mcp-security-report.html'
                    publishHTML([
                        reportName: 'MCP Security Report',
                        reportDir: '.',
                        reportFiles: 'mcp-security-report.html'
                    ])
                }
            }
        }
    }
}
```

---

## Supported Applications

Signal Sentinel auto-discovers MCP configurations and Agent Skills from:

| Application | MCP Configs | Agent Skills | Config Location (macOS/Linux) |
|-------------|:-----------:|:------------:|-------------------------------|
| Claude Desktop | ✅ | - | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | - | ✅ | `~/.claude/skills/` |
| Cursor | ✅ | ✅ | `~/.cursor/mcp.json`, `~/.cursor/skills/` |
| VS Code | ✅ | - | `~/.config/Code/User/settings.json` |
| Windsurf | ✅ | ✅ | `~/.windsurf/mcp.json`, `~/.windsurf/skills/` |
| Zed | ✅ | - | `~/.config/zed/settings.json` |
| OpenAI Codex CLI | - | ✅ | `~/.codex/skills/` |

---

## Security Rules

Signal Sentinel scans for OWASP Agentic AI Top 10 + OWASP MCP Top 10 vulnerabilities with 21 rules:

### MCP Rules

| Rule | OWASP Code | Description |
|------|------------|-------------|
| SS-001 | ASI01 | Tool Poisoning Detection |
| SS-002 | ASI02 | Overbroad Permissions |
| SS-003 | ASI03 | Missing Authentication |
| SS-004 | ASI04 | Supply Chain Vulnerabilities |
| SS-005 | ASI05 | Code Execution Detection |
| SS-006 | ASI06 | Memory/Context Write Access |
| SS-007 | ASI07 | Inter-Agent Communication |
| SS-008 | ASI09 | Sensitive Data Access |
| SS-009 | ASI01 | Excessive Description Length |
| SS-010 | ASI02 | Cross-Server Attack Paths |
| SS-019 | ASI03 | Credential Hygiene Check |
| SS-020 | ASI03 | OAuth 2.1 Compliance Check |
| SS-021 | ASI04 | Package Provenance Check |

### Skill Rules

| Rule | OWASP Code | Description |
|------|------------|-------------|
| SS-011 | ASI01 | Skill Prompt Injection Detection |
| SS-012 | ASI02 | Skill Scope Violation Detection |
| SS-013 | ASI03 | Skill Credential Access Detection |
| SS-014 | ASI09 | Skill Data Exfiltration Detection |
| SS-015 | ASI01 | Skill Obfuscation Detection |
| SS-016 | ASI05 | Skill Script Payload Detection |
| SS-017 | ASI02 | Skill Excessive Permissions Detection |
| SS-018 | ASI01 | Skill Hidden Content Detection |

---

## Grading System

| Grade | Score | Description |
|-------|-------|-------------|
| **A** | 90-100 | Excellent - No critical or high findings |
| **B** | 80-89 | Good - Minor issues only |
| **C** | 70-79 | Adequate - Some medium findings |
| **D** | 60-69 | Poor - High severity findings present |
| **F** | 0-59 | Failing - Critical issues detected |

---

## Troubleshooting

### "No MCP configurations found"

**Cause:** No config files found in standard locations.

**Solutions:**
1. Use `--config` to specify the config file path directly
2. Use `--remote` to scan a remote MCP server
3. Check that your MCP application has servers configured

### Connection timeout

**Cause:** MCP server not responding within timeout period.

**Solution:** Increase timeout with `--timeout`:
```bash
sentinel-scan --remote https://slow-server.com/mcp --timeout 120
```

### Docker permission denied

**Cause:** Config files not accessible to container.

**Solution:** Mount volumes with read-only access:
```bash
docker run --rm \
  -v "/path/to/config:/config:ro" \
  ghcr.io/signalcoding/signal-sentinel-scanner:2.1.1 --config /config/mcp.json
```

### "Tool not found" after installation

**Cause:** .NET tools directory not in PATH.

**Solution:**
```bash
# Add to PATH (Linux/macOS)
export PATH="$PATH:$HOME/.dotnet/tools"

# Add to PATH (Windows PowerShell)
$env:PATH += ";$env:USERPROFILE\.dotnet\tools"
```

---

## Support

- **Documentation:** https://github.com/SignalCoding/signal-sentinel-scanner#readme
- **Issues:** https://github.com/SignalCoding/signal-sentinel-scanner/issues
- **Security Issues:** security@signalcoding.co.uk

---

## License

Apache 2.0 - Copyright 2026 Signal Coding Limited

---

*Document generated for Signal Sentinel Scanner v2.1.1*
