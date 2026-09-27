# Implementation Report: rule-registry-parity

**Date:** 2026-09-27
**Status:** GREEN
**Spec:** _docs/ai/specs/rule-registry-parity.md

## Files Changed

- `src/SignalSentinel.Scanner/Rules/RuleEngine.cs`
- `src/SignalSentinel.Scanner/Program.cs`
- `tests/SignalSentinel.Scanner.Tests/Rules/RuleRegistryParityTests.cs`
- `README.md`
- `CHANGELOG.md`
- `docs/owasp-ast-mapping.md`
- `src/SignalSentinel.Core/Models/OwaspMcpMapping.cs`
- `AGENTS.md`
- `CONTRIBUTING.md`

## What Was Modified

| File | What Changed | Rationale |
| ---- | ------------ | --------- |
| `RuleEngine.cs` | Added static `CatalogueRules()`: `new RuleEngine().Rules` plus `RugPullDetectionRule`, `ShadowToolInjectionRule`, `SkillIntegrityRule`, `ExcessiveResponseRule` (SS-022/023/024/025). Does not change `_rules`/`Rules`, so scan execution is unchanged. | R1 |
| `Program.cs` | `PrintRuleList` now iterates `Rules.RuleEngine.CatalogueRules()` instead of `new Rules.RuleEngine().Rules`. | R1 |
| `RuleRegistryParityTests.cs` | One-line swap: `Rule_IsListedByListRulesCatalogue` now asserts against `RuleEngine.CatalogueRules()` instead of `new RuleEngine().Rules`. No other line touched. | R1 (the documented swap) |
| `README.md` | "22 new rules" -> "15 new rules"; Security Rules section: summary line now "47 security rules (41 detection + 6 informational)"; added the 15 missing rows (SS-030..SS-042, SS-INFO-005, SS-INFO-006) across MCP/Skill/new "Static Surface Rules (v3.0)"/Informational tables, copied from `INSTALLATION_AND_USAGE.md`. No new MCP-vs-Skill totals split introduced. | R2, R3 |
| `CHANGELOG.md` | v3.0.0 entry corrected in place ("Twenty-two" -> "Fifteen") with a footnote dated 2026-09-27 recording the correction (not a silent rewrite). | R2 |
| `docs/owasp-ast-mapping.md` | Added the same 15 rows to the rule-to-AST table (values taken from the already-correct `RuleAstMapping.cs`, which needed no code change). Added a new "Out-of-scope OWASP categories" section covering ASI08/AST09/MCP04/MCP10 with reasons, plus the SS-024/AST09 candidate-exception note marked as not yet decided. | R4, R6 |
| `OwaspMcpMapping.cs` | Added `"SS-023" => MCP03` and `"SS-026" => MCP01` with sibling-rationale comments; added a comment above `_ => null` naming SS-022, SS-025, SS-041, SS-042 as deliberate nulls with reasons. | R6 |
| `AGENTS.md` | Section 6 checklist expanded from 5 to 9 surfaces (constant, AST mapping, MCP mapping w/ reason-if-null, engine/catalogue registration, help+list-rules, README, ast-mapping doc, install guide, test class), naming `RuleRegistryParityTests` as the mechanical check. | R8 |
| `CONTRIBUTING.md` | "Adding a detection rule" renumbered/expanded to the same 9 surfaces (README, doc, install-guide entries added), existing `McpProtocolRules`/`DefaultRules.json` items kept as an "Additionally" list since they're real requirements not in the audit's nine. | R8 |

No rule's detection logic, severity, confidence or default changed anywhere.

## Files Intentionally Not Touched

- `INSTALLATION_AND_USAGE.md` - already complete (the reference copied from); R3/R4 don't ask for changes here.
- `src/SignalSentinel.Core/Models/RuleAstMapping.cs` - already had correct entries for all 15 previously-doc-only rules; no code gap, only a doc gap.
- `ExcessiveDescriptionRuleTests.cs`, other `tests/**` - R5/R7 scope, already delivered by the test-writer; not part of this implement pass.
- `_docs/ai/HANDOVER.md` - was already modified (untracked-from-me) before this task started; left as-is.
- `DefaultRules.json`, `RuleConstants.Rules.McpProtocolRules` - unaffected by this spec's 9-surface audit; CONTRIBUTING.md keeps them as separate "Additionally" items rather than folding them into the 9, per the spec's own R7 surface list.

## Validation

| Command | Exit Code |
| ------- | --------- |
| `dotnet build signal-sentinel.sln -c Release` | 0 (0 warnings) |
| `dotnet test signal-sentinel.sln -c Release --no-build` | 0 (Failed: 0, Passed: 1764, Total: 1764) |
| `SignalSentinel.Scanner.exe --list-rules` | 47 distinct rule ids (48 lines; SS-020 pre-existingly printed twice for two rules sharing that id - not introduced by this change) |
| `grep -rn "22 new rules\|Twenty-two new rules" README.md CHANGELOG.md` | prints nothing (exit 1) |

## Dependencies Added (if any)

- none

## Follow-Up Needed

- Pre-existing, out of this spec's scope: `OAuthComplianceRule` and `MissingAuthProbeRule` both report `Id == "SS-020"`, so `--list-rules` prints 48 lines for 47 distinct ids. Not touched (rule-behaviour/registration change, not a registry-surface gap), but flagged for the owner.
- D2's candidate exception (SS-024 -> AST09) is recorded as an open question in `docs/owasp-ast-mapping.md`, not decided, per spec section 8.
- Website wording correction from spec section 8 is supplied there for the owner's approval; not published by this work.

## Risks and Notes

- `RuleEngine.CatalogueRules()` constructs a throwaway `new RuleEngine()` plus four extra rule instances purely for enumeration (Id/Name/AstCodes/OwaspCode); none are executed, so this has no scan-behaviour or performance impact on real scans.
- `RugPullDetectionRule(null)` is valid: its constructor parameter is `BaselineComparison?`.

## Open Questions Raised During Work

- none
