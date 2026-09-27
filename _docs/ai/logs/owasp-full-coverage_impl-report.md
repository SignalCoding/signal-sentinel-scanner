# Implementation Report: owasp-full-coverage

**Date:** 2026-09-27
**Status:** GREEN
**Spec:** _docs/ai/specs/owasp-full-coverage.md

## Files Changed

- `src/SignalSentinel.Scanner/Rules/CrossServerAttackPathRule.cs` (C1)
- `src/SignalSentinel.Core/Models/RuleAstMapping.cs` (C2, plus the stray AST05/AST10 comment fix)
- `src/SignalSentinel.Core/Models/OwaspMcpMapping.cs` (C3, plus SS-INFO-007 mapping)
- `src/SignalSentinel.Scanner/Rules/McpLoggingCapabilityAbsentRule.cs` (C4, new file)
- `src/SignalSentinel.Core/RuleConstants.cs` (C4 id + McpProtocolRules set)
- `src/SignalSentinel.Scanner/Rules/RuleEngine.cs` (C4 registration)
- `tests/SignalSentinel.Scanner.Tests/Rules/OwaspFullCoverageTests.cs` (C5 exception, only test edit beyond C4)
- `tests/SignalSentinel.Scanner.Tests/Rules/RuleRegistryParityTests.cs` (C6 ripple: 47→48)
- `src/SignalSentinel.Scanner/Program.cs`, `README.md`, `INSTALLATION_AND_USAGE.md`, `SECURITY.md`, `docs/owasp-ast-mapping.md`, `_docs/ai/specs/rule-registry-parity.md` (C6 docs)

## What Was Modified

| File | What Changed | Rationale |
| ---- | ------------ | --------- |
| `CrossServerAttackPathRule.cs` | Added `ASI08` to the Data Exfiltration path's `OwaspCodes` array, with comment | C1 - additive; singular `OwaspCode` untouched (test pins it to ASI02) |
| `RuleAstMapping.cs` | Added `AST09` to `["SS-024"]`; added `["SS-INFO-007"] = [AST08]`; fixed class-doc comment (v2.4.1 aligned AST05's label, not AST10) | C2, C4, and the spec's flagged wrong comment |
| `OwaspMcpMapping.cs` | Added `"SS-041" => MCP04` and `"SS-INFO-007" => MCP10`; trimmed the "deliberate nulls" comment to drop SS-041 | C3, C4 |
| `McpLoggingCapabilityAbsentRule.cs` | New rule SS-INFO-007, modelled on `CapabilitySurfaceRule`: Info, ASI10/MCP10/AST08, fires once per connected server with null `Capabilities.Logging` | C4 |
| `RuleConstants.cs` | Added `McpLoggingCapabilityAbsent = "SS-INFO-007"`; added it to `McpProtocolRules` (same connection/capability dependency as SS-INFO-005, so it is dropped consistently when SS-INFO-001 fires) | C4 |
| `RuleEngine.cs` | Registered `new McpLoggingCapabilityAbsentRule()` next to `CapabilitySurfaceRule` | C4 |
| `OwaspFullCoverageTests.cs` | Added named `DocumentedAstException` (AST10) + reason constant to `EveryAstCategory_IsClaimedByAtLeastOneRule`, printed in the failure message; guard still fails for any other unclaimed category | C5 (spec explicitly authorises this one test edit) |
| `RuleRegistryParityTests.cs` | `AllRuleIds.Count.ShouldBe(47→48)`, informational count `6→7` | C6 ripple, explicitly directed by spec |
| `Program.cs` | Added `SS-INFO-007` line to `--help`'s INFORMATIONAL block | C6 |
| `README.md`, `INSTALLATION_AND_USAGE.md`, `SECURITY.md` | Rule count 47→48 (41+7), added SS-INFO-007 table row(s) | C6 |
| `docs/owasp-ast-mapping.md` | Added SS-INFO-007 row; updated SS-024 row to show AST09; replaced "Out-of-scope OWASP categories" with a coverage statement (10/10 ASI, 9/10 AST, 10/10 MCP) naming which rule claims ASI08/AST09/MCP04/MCP10 and recording AST10 as the documented open gap | C6 + section 5 amendment |
| `_docs/ai/specs/rule-registry-parity.md` | Marked section 8's "Resulting form of words" as superseded; replaced with the section-5-corrected wording (9/10 AST, not blanket coverage) | C6 + section 5 amendment |

## Files Intentionally Not Touched

- `RuleAstMapping.cs`'s other rule entries, `OwaspMcpMapping.cs`'s other cases - no other rule's mapping was touched.
- `SkillIntegrityRule.cs` itself - it has no `AstCodes` override; `RuleEngine.EnrichFinding` falls back to `RuleAstMapping.GetCodes`, which is the authoritative source the C5 guard and C2 test both read, so the rule class needed no change.
- SS-020 dual registration, Markdig deferral - out of scope per spec section 4, unchanged.
- No existing rule's severity, confidence, or detection logic changed.

## Validation

| Command | Result |
| ------- | ------ |
| `dotnet build signal-sentinel.sln -c Release` | 0 Warning(s), 0 Error(s) |
| `dotnet test signal-sentinel.sln -c Release --no-build` | Failed: 0, Passed: 1782, Total: 1782 |
| `--list-rules` | 48 distinct rule ids (SS-020 lists twice - pre-existing dual registration, #86, out of scope) |
| `--remote https://mcp.deepwiki.com/mcp --format json` | Findings incl. exactly one `SS-INFO-007` (Info); ids: SS-002, SS-003, SS-020, SS-INFO-004, SS-INFO-005, SS-INFO-007; grade **C**, score **84** (matches baseline) |
| `--remote https://learn.microsoft.com/api/mcp --format json` | Zero `SS-INFO-007` findings; ids: SS-002, SS-003, SS-005, SS-008, SS-009, SS-020, SS-026, SS-INFO-004, SS-INFO-005; grade **C**, score **71** (matches baseline) |
| `git diff --stat` | 12 files changed, 78 insertions(+), 41 deletions(-) (plus 3 new source/test files listed above, already untracked pre-existing from the red phase) |

## Dependencies Added (if any)

- none

## Follow-Up Needed

- none - all six requirements (C1-C6) implemented and green.

## Risks and Notes

- `McpLoggingCapabilityAbsent` was added to `RuleConstants.Rules.McpProtocolRules` (dropped when SS-INFO-001 fires) for consistency with `CapabilitySurfaceRule`'s identical skip condition; this is a new rule's own set membership, not a change to any existing rule's behaviour, and is not exercised by a specific test but is visible in the live-scan check above (SS-INFO-005 and SS-INFO-007 both fire together on servers that connect).

## Open Questions Raised During Work

- none
