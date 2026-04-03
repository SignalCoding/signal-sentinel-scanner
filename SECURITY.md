# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Signal Sentinel, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please email: **security@signalcoding.co.uk**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested remediation

### What to Expect

1. **Acknowledgement**: We will acknowledge receipt within 48 hours
2. **Assessment**: We will assess the vulnerability within 7 days
3. **Resolution**: Critical vulnerabilities will be patched within 30 days
4. **Disclosure**: We will coordinate disclosure timing with you

### Bug Bounty

We do not currently operate a bug bounty program, but we will publicly acknowledge security researchers who report valid vulnerabilities (with their permission).

## Security Standards

Signal Sentinel is built to comply with:

- **OWASP Top 10 2025** - Web application security
- **OWASP Agentic AI Top 10 (2026)** - AI agent security (ASI01-ASI10)
- **MOD JSP 440/656** - UK Defence secure development
- **NCSC Cyber Essentials Plus** - UK government security baseline

## Development Security

### Code Review
- All code changes require security-focused review
- Security-critical changes require senior review

### Dependencies
- All dependencies are pinned to exact versions
- Automated vulnerability scanning in CI/CD
- No packages with known critical vulnerabilities

### Secrets Management
- No secrets in source code
- Azure Key Vault / cloud-native secret stores only
- Credentials never appear in logs

### Supply Chain
- SBOM generated for every release
- Package integrity verification
- Official registries only (NuGet, npm)

## Security Features

### Scanner
- Detects 10 categories of MCP security vulnerabilities
- Identifies cross-server attack paths
- Supply chain integrity checks (hash pinning, typosquat detection)

### Gateway (Coming Soon)
- Real-time tool call filtering
- Response sanitisation (injection pattern removal)
- PII redaction
- Anomaly detection and kill switch

## Contact

- Security issues: security@signalcoding.co.uk
- General inquiries: info@signalcoding.co.uk

---

Copyright 2026 Signal Coding Limited. All rights reserved.
