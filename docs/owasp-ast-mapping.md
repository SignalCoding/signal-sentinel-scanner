# OWASP Agentic Skills Top 10 (AST) mapping

Every Signal Sentinel rule carries both its OWASP Agentic AI Top 10 code
(`ASI01`..`ASI10`) and, where applicable, one or more real **OWASP Agentic
Skills Top 10** codes (`AST01`..`AST10`) as published by the OWASP
Agentic Skills Top 10 project (owasp.org/www-project-agentic-skills-top-10).
AST covers the skill-authoring supply-chain dimension that ASI only
partially addresses.

The authoritative mapping table is in
[`src/SignalSentinel.Core/Models/RuleAstMapping.cs`](../src/SignalSentinel.Core/Models/RuleAstMapping.cs);
the AST code definitions themselves live in
[`src/SignalSentinel.Core/Models/OwaspMapping.cs`](../src/SignalSentinel.Core/Models/OwaspMapping.cs)
(`OwaspAstCodes`).

> **v2.4.1 correction (G12a):** this document had drifted from the code and
> described a different, internally-invented taxonomy under the same
> `AST01`..`AST10` codes. As of v2.4.1 the code's `OwaspAstCodes` labels are
> the source of truth and match the real OWASP project for 9 of 10
> categories; only `AST05` needed a code-level fix (it previously read
> "Unsafe Deserialisation" - now corrected to the real "Untrusted External
> Instructions"). This document has been rewritten to match the corrected
> code exactly. `SS-005` and `SS-016` were remapped away from `AST05` to
> `AST06` (Weak Isolation) as part of the same fix - unsafe deserialisation
> leading to code execution is a sandbox-escape concern, not an
> untrusted-external-instructions one.

## AST categories (summary)

| Code  | Name                            | Summary                                                                                          |
|-------|---------------------------------|----------------------------------------------------------------------------------------------------|
| AST01 | Malicious Skills                | Skill contains a deliberately harmful payload.                                                     |
| AST02 | Supply Chain                    | Skill dependencies are unverified, unpinned, or compromised.                                       |
| AST03 | Over-Privileged                 | Skill declares or uses broader capabilities than necessary.                                        |
| AST04 | Insecure Metadata                | Metadata (description, tags) is inaccurate or contains hidden content.                             |
| AST05 | Untrusted External Instructions | Skill treats content fetched from an untrusted external source as trusted instructions, not data.  |
| AST06 | Weak Isolation                  | Skill escapes intended sandbox (shell, network, filesystem).                                       |
| AST07 | Update Drift                    | Skill integrity cannot be verified across updates.                                                  |
| AST08 | Poor Scanning                   | Sole reliance on a single scanner or regex-only analysis.                                           |
| AST09 | No Governance                   | No change-management, ownership, or review process for skills.                                      |
| AST10 | Cross-Platform Reuse            | Skill mixes incompatible platform semantics unsafely.                                               |

## Rule-to-AST map (v2.5.0)

| Rule ID      | ASI   | AST                  | Notes                                                   |
|--------------|-------|----------------------|----------------------------------------------------------|
| SS-001       | ASI01 | AST01, AST04         | Tool poisoning.                                         |
| SS-002       | ASI02 | AST03                | Overbroad permissions.                                  |
| SS-003       | ASI03 | AST06                | Missing authentication.                                 |
| SS-004       | ASI04 | AST02                | Supply chain integrity.                                 |
| SS-005       | ASI05 | AST01, AST06         | Code execution / unsafe deserialisation (sandbox escape). |
| SS-006       | ASI06 | AST06                | Resource exhaustion on MCP side.                        |
| SS-007       | ASI07 | AST01                | Output-handling issues.                                 |
| SS-008       | ASI09 | AST04                | Sensitive data access.                                  |
| SS-009       | ASI01 | AST04                | Excessive description length.                           |
| SS-010       | ASI02 | AST01, AST03         | Cross-server attack paths.                              |
| SS-011       | ASI01 | AST01, AST04, AST05  | Skill prompt injection - also the closest existing fit for untrusted external instructions. |
| SS-012       | ASI02 | AST03                | Skill scope violation (lemma-aware + case-insensitive). |
| SS-013       | ASI03 | AST01                | Hardcoded secrets inside skills.                        |
| SS-014       | ASI09 | AST01, AST03         | Data exfiltration / network access in skills.           |
| SS-015       | ASI01 | AST04                | Malicious markdown / conditional-trigger patterns.      |
| SS-016       | ASI05 | AST01, AST06         | Malicious bundled scripts (sandbox escape).             |
| SS-017       | ASI02 | AST03                | Skill excessive permissions.                            |
| SS-018       | ASI01 | AST04                | Skill hidden content.                                   |
| SS-019       | ASI03 | AST01, AST04         | Credential hygiene in MCP config.                       |
| SS-020       | ASI03 | AST06                | OAuth 2.1 compliance (behavioural auth probe).          |
| SS-021       | ASI04 | AST02, AST07         | Package provenance.                                     |
| SS-022       | ASI01 | AST01, AST02         | Rug-pull / schema mutation.                             |
| SS-023       | ASI01 | AST01                | Shadow tool typosquat.                                  |
| SS-024       | ASI04 | AST02, AST07         | Skill integrity verification.                           |
| SS-025       | ASI06 | AST03                | Excessive tool response size.                           |
| SS-026       | ASI01 | AST04                | Instructional tool/skill description (hidden agent-directed instructions in metadata). |
| SS-028       | ASI02 | AST03                | Skill write access to identity/memory files.            |
| SS-029       | ASI04 | AST02, AST07         | Unpinned GitHub dependency reference ("SkillJacking").  |
| SS-INFO-001  | ASI10 | AST08                | Non-MCP endpoint detected.                              |
| SS-INFO-003  | ASI10 | AST08                | Untrusted server certificate.                           |
| SS-INFO-004  | ASI04 | AST08                | Legacy MCP protocol version / transport (2026-07-28 spec currency). |

Rules may map to multiple AST categories. Unmapped combinations are intentional
- e.g. `SS-006` is primarily about availability and is not a supply-chain concern;
`SS-INFO-002` (non-public target) has no AST mapping because it is an MCP
reachability notice, not a skill-authoring concern.

## Using AST codes in CI

SARIF output exposes AST codes both in `rule.properties.tags` and in the
per-result `properties.astCodes`. You can filter PR checks on either:

```bash
# Block only on skill-authoring regressions (AST01 or AST03).
sentinel-scan --skills --format sarif --fail-on high
jq '.runs[0].results[] | select(.properties.astCodes? | any(. == "AST01" or . == "AST03"))' report.sarif
```
