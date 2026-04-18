# OWASP Agentic Skills Top 10 (AST) mapping

As of v2.3.0, every Signal Sentinel rule carries both its existing OWASP Agentic
AI Top 10 code (`ASI01`..`ASI10`) and, where applicable, one or more OWASP
Agentic Skills Top 10 codes (`AST01`..`AST10`). AST covers the skill-authoring
supply-chain dimension that ASI only partially addresses.

The authoritative mapping table is in
[`src/SignalSentinel.Core/Models/RuleAstMapping.cs`](../src/SignalSentinel.Core/Models/RuleAstMapping.cs).

## AST categories (summary)

| Code  | Name                            | Summary                                                                        |
|-------|---------------------------------|--------------------------------------------------------------------------------|
| AST01 | Prompt Injection                | Adversary-controlled input changes skill or model behaviour.                    |
| AST02 | Insecure Output Handling        | Skill response is rendered or executed without sanitisation.                    |
| AST03 | Sensitive Capability Misuse     | Skill performs actions outside its declared scope.                              |
| AST04 | Supply Chain / Skill Provenance | Skill distribution lacks integrity or provenance guarantees.                    |
| AST05 | Excessive Agency                | Skill can act with broader privilege than necessary.                            |
| AST06 | Sensitive Data Exposure         | Skill leaks credentials, PII, or tokens in logs or responses.                   |
| AST07 | Insufficient Logging            | Actions aren't auditable after the fact.                                        |
| AST08 | Misconfiguration                | Endpoints, permissions, or transports are wrong by default.                     |
| AST09 | Resource Exhaustion             | Skill or tool response can blow past memory / time bounds.                      |
| AST10 | Unverified Third-Party Integration | Skill talks to unverified external services.                                |

## Rule-to-AST map (v2.3.0)

| Rule ID      | ASI   | AST                  | Notes                                                   |
|--------------|-------|----------------------|---------------------------------------------------------|
| SS-001       | ASI01 | AST01, AST03         | Tool poisoning.                                         |
| SS-002       | ASI02 | AST05                | Overbroad permissions.                                  |
| SS-003       | ASI03 | AST05, AST08         | Missing authentication.                                 |
| SS-004       | ASI04 | AST04                | Supply chain integrity.                                 |
| SS-005       | ASI05 | AST06                | Credential exposure in config.                          |
| SS-006       | ASI06 | AST09                | Resource exhaustion on MCP side.                        |
| SS-007       | ASI07 | AST02                | Output-handling issues.                                 |
| SS-008       | ASI08 | AST08                | Transport misconfig.                                    |
| SS-009       | ASI09 | AST07                | Insufficient logging.                                   |
| SS-010       | ASI10 | AST10                | Unverified third-party integration.                     |
| SS-011       | ASI01 | AST01                | Prompt injection in SKILL.md.                           |
| SS-012       | ASI02 | AST03                | Skill scope violation (now lemma-aware + case-insensitive). |
| SS-013       | ASI05 | AST06                | Hardcoded secrets inside skills.                        |
| SS-014       | ASI10 | AST03, AST10         | Data exfiltration / network access in skills.           |
| SS-015       | ASI08 | AST01, AST02         | Unsafe output rendering in skills.                      |
| SS-016       | ASI01 | AST03                | Malicious markdown / code-block patterns.               |
| SS-017       | ASI01 | AST04                | Malicious bundled scripts.                              |
| SS-018       | ASI04 | AST04                | Supply chain (skill manifest).                          |
| SS-019       | ASI05 | AST06, AST08         | Credential hygiene in MCP config.                       |
| SS-020       | ASI03 | AST05, AST08         | OAuth 2.1 compliance.                                   |
| SS-021       | ASI04 | AST04, AST10         | Package provenance.                                     |
| SS-022       | ASI01 | AST04                | Rug-pull / schema mutation.                             |
| SS-023       | ASI01 | AST04, AST10         | Shadow tool typosquat.                                  |
| SS-024       | ASI04 | AST04                | Skill integrity verification.                           |
| SS-025       | ASI06 | AST09                | Excessive tool response size.                           |
| SS-INFO-001  | ASI10 | AST08                | Non-MCP endpoint detected.                              |

Rules may map to multiple AST categories. Unmapped combinations are intentional
— e.g. SS-006 is primarily about availability and is not a supply-chain concern.

## Using AST codes in CI

SARIF output exposes AST codes both in `rule.properties.tags` and in the
per-result `properties.astCodes`. You can filter PR checks on either:

```bash
# Block only on skill-authoring regressions (AST01 or AST03).
sentinel-scan --skills --format sarif --fail-on high
jq '.runs[0].results[] | select(.properties.astCodes? | any(. == "AST01" or . == "AST03"))' report.sarif
```
