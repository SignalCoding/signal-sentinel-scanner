# Project Configuration

**Project:** Signal Sentinel Scanner
**Date:** 2026-09-19
**Owner:** Signal Coding Limited

This file captures the output of the `startup-configuration` skill for this project. It is the canonical reference for the project's governance posture. Every other skill reads it to determine the level at which to operate.

Update this file (and bump the date) if any of the parameters change.

## Configuration

| Gate              | Selection | Agent Team Activated |
| ----------------- | --------- | -------------------- |
| Security Posture  | RESTRICTED | Enhanced Security Agent |
| AI Governance     | ENHANCED | AI Code Reviewer |
| Deployment        | GitHub Actions -> NuGet.org global tool + GHCR Docker image, tag-triggered | Supply-chain specialist |
| Compliance        | OWASP ASI Top 10, OWASP AST Top 10, OWASP MCP Top 10, NCSC Cyber Essentials Plus alignment | Security reviewer |
| Team Experience   | SENIOR | Terse guidance, decisions surfaced not explained |

## Activated Specialist Team

- Enhanced Security Agent (RESTRICTED posture; the product itself is a security tool and is used in defence-adjacent environments)
- AI Security Specialist (the product scans AI-agent supply chain; AI tools are used to develop it)
- Supply Chain Specialist (published artefacts: NuGet package, Docker image; SHA-pinned actions, pinned dependencies)

Not activated: Cloud Security Specialist (no cloud runtime), Data Protection Specialist (no user data is stored; scan targets are local or operator-supplied).

## Compliance Frameworks In Scope

- **OWASP Agentic AI Top 10 (ASI01-ASI10):** every rule declares an ASI code.
- **OWASP Agentic Skills Top 10 (AST01-AST10):** every rule declares AST codes via `RuleAstMapping`.
- **OWASP MCP Top 10 (MCP01-MCP10):** MCP-protocol rules declare an MCP code via `OwaspMcpMapping`.
- **NCSC Cyber Essentials Plus:** alignment only; no formal certification claimed.

## AI Tools In Use

- **Tier 1 (approved):** Factory Droid (this repository's orchestrator), GitHub Copilot code review on PRs
- **Tier 2 (conditional):** none
- **Tier 3:** Prohibited: any tool that sends repository content to a non-approved endpoint

## Notes

- The scanner must remain fully functional under `--offline`. Any feature that needs network egress is opt-in by flag and refused in offline mode.
- `REPO-STANDARDS.md` governs repository presentation, commit format, branching, and versioning. The kit adoption (release-please, CODEOWNERS, hooks, branch protection) is tracked separately from product releases.
- The v3.0.0 release spec is archived at `_docs/ai/completed/2026-09-20_v3.0-release.md`.
