# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.3.x   | :white_check_mark: |
| 2.2.x   | :white_check_mark: |
| 2.1.x   | :white_check_mark: (security fixes only) |
| 2.0.x   | :x: End of life    |
| 1.x.x   | :x: End of life    |

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
- **OWASP Agentic Skills Top 10 (2026)** - skill authoring supply chain (AST01-AST10) - see [owasp-ast-mapping.md](docs/owasp-ast-mapping.md)
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
- 26 security rules across MCP server and Agent Skill scanning (25 detection + 1 informational)
- **v2.3.0** credibility hardening:
  - `.sentinel-suppressions.json` schema v1.0 for accepted-risk management, with justification, approver, expiry, and per-environment scoping. Suppressed findings are retained in every report format for audit.
  - Confidence-aware triage: `--min-confidence` hard filter and `--triage` demotion mode (see [confidence-rubric.md](docs/confidence-rubric.md)).
  - Scan history + diff (`sentinel-scan diff`) attributes grade changes to the rules that caused them.
  - Non-MCP endpoint detection (`SS-INFO-001`) prevents misleading grades when `--remote` targets a non-MCP HTTP host. When it fires, all MCP-protocol rules for that target are automatically suppressed to keep reports internally consistent.
  - Skill YAML `capabilities:` block is authoritative for SS-012; declared capabilities are trusted over prose heuristics, eliminating false positives on "disk/memory/CPU" style descriptions.
  - Lemma table for SS-012 extended with filesystem synonyms (`disk`, `volume`, `mount`, `/proc`, `/sys`, `/dev`, `procfs`, `sysfs`) so operator-friendly descriptions no longer trigger scope-violation findings.
  - Suppressed scans surface a technical-debt exposure banner showing the counter-factual grade ("would be F instead of A") so suppressions cannot be used to hide risk.
  - Every report declares explicit scope (scanned, not scanned, complementary tools) in line with the "first-pass authoring aid" positioning.
  - Pre-commit hook integrations for pre-commit.com, lefthook, and husky.
- 16 MCP rules (SS-001..SS-010, SS-019..SS-023, SS-025): tool poisoning, overbroad permissions, missing auth, supply chain, code execution, memory write, inter-agent comms, sensitive data, credential hygiene, OAuth 2.1 compliance, package provenance, rug pull detection, shadow tool injection, excessive response size
- 9 Skill rules (SS-011..SS-018, SS-024): prompt injection, scope violation, credential access, data exfiltration, obfuscation, script payloads, excessive permissions, hidden content, skill integrity verification
- Cross-server attack path analysis
- Supply chain integrity checks (hash pinning, typosquat detection, Levenshtein distance)
- Baseline comparison with SHA-256 schema hashing for rug-pull detection
- Offline mode (`--offline`) enforces zero network egress for air-gapped / HMG environments
- SARIF v2.1.0 output compatible with GitHub Code Scanning
- Sigma YAML rule import for shared SOC detection content
- OWASP Agentic AI Top 10 (ASI01-ASI10) + OWASP MCP Top 10 (MCP01-MCP10) dual compliance mapping
- v2.1.1: SHA-pinned CI/CD, SSRF protection, symlink escape protection, regex timeouts, TLS enforcement, bounded reads
- v2.2.0: Deduplication engine collapses duplicate findings; integrity verifier detects unsigned skills

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
