# Test Report: owasp-full-coverage

**Date:** 2026-09-27
**Status:** RED (expected)
**Exit Code:** 1
**Test Command:** `dotnet test signal-sentinel.sln -c Release --no-build`

## Failures (9 new, 0 pre-existing)

- `tests/SignalSentinel.Scanner.Tests/Rules/OwaspFullCoverageTests.cs:51` - C1: attack path `OwaspCodes` missing `ASI08`
- `tests/SignalSentinel.Scanner.Tests/Rules/OwaspFullCoverageTests.cs:72` - C2: `RuleAstMapping.GetCodes("SS-024")` missing `AST09`
- `tests/SignalSentinel.Scanner.Tests/Rules/OwaspFullCoverageTests.cs:93` - C3: `GetCorrespondingMcpCode("SS-041")` returns null, expected `MCP04`
- `tests/SignalSentinel.Scanner.Tests/Rules/OwaspFullCoverageTests.cs:107` - C5 ASI guard: unclaimed `["ASI08"]`
- `tests/SignalSentinel.Scanner.Tests/Rules/OwaspFullCoverageTests.cs:117` - C5 AST guard: unclaimed `["AST09", "AST10"]` (see Open Questions)
- `tests/SignalSentinel.Scanner.Tests/Rules/OwaspFullCoverageTests.cs:127` - C5 MCP guard: unclaimed `["MCP04", "MCP10"]`
- `tests/SignalSentinel.Scanner.Tests/Rules/McpLoggingCapabilityAbsentRuleTests.cs:49,60` (x2 of 3) - C4: `SS-INFO-007` not found in `RuleEngine.CatalogueRules()`
  - `LoggingCapabilityAbsent_ConnectedServerWithoutLogging_FiresOnceAtInfo` also fails the same way (not separately listed above for space)

Full run: `_docs/ai/verify/evidence/owasp-full-coverage.red.testresults.txt` (Failed: 9, Passed: 1766, Total: 1775 = 1764 pre-existing + 11 new).

## Coverage Mapping

| Acceptance Criterion | Test File | Test Name |
| --- | --- | --- |
| C1 ASI08 additive | OwaspFullCoverageTests.cs | `CrossServerAttackPath_DataExfiltrationPath_IncludesAsi08`, `CrossServerAttackPathRule_SingularOwaspCode_RemainsAsi02` (passes today - guards additivity) |
| C2 AST09 additive | OwaspFullCoverageTests.cs | `SkillIntegrityRule_AstMapping_IncludesAst09`, `SkillIntegrityRule_AstMapping_RemainsAdditive` (passes today) |
| C3 MCP04 fill | OwaspFullCoverageTests.cs | `GetCorrespondingMcpCode_ServerSourceSink_ReturnsMcp04` |
| C5 coverage guard (ASI/AST/MCP) | OwaspFullCoverageTests.cs | `EveryAsiCategory_IsClaimedByAtLeastOneRuleOrAttackPath`, `EveryAstCategory_IsClaimedByAtLeastOneRule`, `EveryMcpCategory_IsClaimedByAtLeastOneRule` |
| C4 SS-INFO-007 fires once, Info, connected+no Logging | McpLoggingCapabilityAbsentRuleTests.cs | `LoggingCapabilityAbsent_ConnectedServerWithoutLogging_FiresOnceAtInfo` |
| C4 no fire when Logging present | McpLoggingCapabilityAbsentRuleTests.cs | `LoggingCapabilityAbsent_ConnectedServerWithLogging_NoFindings` |
| C4 no fire when not connected | McpLoggingCapabilityAbsentRuleTests.cs | `LoggingCapabilityAbsent_ServerFailedToConnect_NoFindings` |

## Next Step for Coding Agent

Implement, in `src/`, exactly what the spec's C1-C4 describe:
- Add `ASI08` to the Data Exfiltration attack path's `OwaspCodes` in `CrossServerAttackPathRule.cs` (~line 97). Leave the rule's singular `OwaspCode` as `ASI02`.
- Add `AST09` to `RuleAstMapping.cs`'s `["SS-024"]` entry (keep `AST02`, `AST07`).
- Add `"SS-041" => MCP04` to `OwaspMcpCodes.GetCorrespondingMcpCode`.
- Add new rule `SS-INFO-007` (Info, ASI10/MCP10/AST08 per spec C4), register it in `RuleEngine`'s constructor list so `CatalogueRules()` picks it up, and add its `RuleConstants` entry.
- Wire `RuleAstMapping["SS-INFO-007"] = [AST08]` so it also satisfies the AST guard.
- Update the nine `RuleRegistryParityTests` surfaces (47 -> 48) and docs per spec C6 - that ripple is intentional and untouched by this test-writer pass.

## Open Questions

- **AST10 (Cross-Platform Reuse) is also unclaimed today** - not one of the spec's four named gaps, discovered because the C5 guard derives categories by reflection rather than a hard-coded list of ten (as instructed). `RuleAstMapping.cs` never assigns AST10 to any rule; the one AST10 mention in the file is a comment about a historical AST05 correction, not an assignment. The spec's Acceptance section 3.2 says the guard should "fail if any one of the four new mappings is removed" but doesn't address a fifth pre-existing gap. Flagging for the Delegator/owner: either extend this spec's scope to close AST10 too, or explicitly document it as an accepted 9/10 AST exception before the coding agent runs, since the guard as specified will not go green otherwise.
- Judgement call: did not modify `RuleRegistryParityTests.cs`'s existing `AllRuleIds.Count.ShouldBe(47)` pinned assertion. That ripple (47->48) is explicitly called out in the spec as intentional and owned by the implement phase once `SS-INFO-007`'s `RuleConstants` entry exists; changing it now would either be a no-op (today's count is still 47, unaffected) or would pre-emptively weaken a regression guard I was told not to touch.
- Judgement call: C4 tests never reference a concrete `SS-INFO-007` rule class (doesn't exist yet); they look it up by id via `RuleEngine.CatalogueRules()` and drive it through `IRule`, per the brief's escape valve. All three fail today on the same "rule not found" assertion; once implemented, the same tests exercise real behaviour.
