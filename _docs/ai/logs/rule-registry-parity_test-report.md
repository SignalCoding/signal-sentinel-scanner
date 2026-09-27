# Test Report: rule-registry-parity (R5 + R7 only)

**Date:** 2026-09-27
**Status:** RED (expected)
**Exit Code:** 1
**Test Command:** `dotnet test signal-sentinel.sln -c Release --no-build`

Scope: R5 (SS-009 test class) and R7 (`RuleRegistryParityTests`) only. R1-R4, R6, R8 and
all files under `src/` are untouched.

## Housekeeping

- Removed the untracked, non-compiling `tests/.../Rules/RuleCatalogueTests.cs` (referenced
  `RuleEngine.CatalogueRules()`, which doesn't exist - build was RED at CS0117 before this
  work started). Its intent (assert the catalogue lists SS-022..025) is folded into
  `Rule_IsListedByListRulesCatalogue`, per spec section 7's instruction to fold it in
  rather than keep two overlapping tests.

## Failures (34, exactly the spec's non-doc/non-catalogue-adjacent gaps)

- `Rules/RuleRegistryParityTests.cs:99-101` (`Rule_IsListedByListRulesCatalogue`) - SS-022, SS-023, SS-024, SS-025
- `Rules/RuleRegistryParityTests.cs:119-123` (`Rule_IsListedInReadmeSecurityRulesSection`) - SS-030..SS-042, SS-INFO-005, SS-INFO-006 (15)
- `Rules/RuleRegistryParityTests.cs:129-133` (`Rule_IsListedInAstMappingDoc`) - SS-030..SS-042, SS-INFO-005, SS-INFO-006 (15)

Full tail: `_docs/ai/verify/evidence/rule-registry-parity.red.testresults.txt`.
Green surfaces (0 failures, as the spec's matrix predicts): AST-mapping-in-code (1
documented allow-list exception, SS-INFO-002), `--help` text, `INSTALLATION_AND_USAGE.md`,
test coverage (SS-009 closed by the new `ExcessiveDescriptionRuleTests.cs` in this same
change; SS-019/SS-INFO-006 matched via their `RuleConstants` field name, see below).

Run totals: **Failed: 34, Passed: 1730, Skipped: 0, Total: 1764.** (Baseline count in the
brief was 1,424; HEAD has moved since - all pre-existing tests still pass unchanged.)

## Coverage Mapping

| Acceptance Criterion (spec section 2/5) | Test File | Test Name |
|---|---|---|
| Rule constant exists (47, no dupes) | `RuleRegistryParityTests.cs` | `AuthoritativeList_Contains47DistinctRulesDerivedFromRuleConstants` |
| AST mapping exists / documented exception | `RuleRegistryParityTests.cs` | `Rule_HasAstMapping_OrIsDocumentedAllowListException` |
| `--list-rules` catalogue (R1 defect, 4 missing) | `RuleRegistryParityTests.cs` | `Rule_IsListedByListRulesCatalogue` |
| `--help` lists every rule | `RuleRegistryParityTests.cs` | `Rule_IsListedInHelpText` |
| README rule tables (R3, 15 missing) | `RuleRegistryParityTests.cs` | `Rule_IsListedInReadmeSecurityRulesSection` |
| `docs/owasp-ast-mapping.md` (R4, 15 missing) | `RuleRegistryParityTests.cs` | `Rule_IsListedInAstMappingDoc` |
| `INSTALLATION_AND_USAGE.md` complete | `RuleRegistryParityTests.cs` | `Rule_IsListedInInstallationGuide` |
| Every rule has test coverage (R5, SS-009 gap) | `RuleRegistryParityTests.cs` + `ExcessiveDescriptionRuleTests.cs` | `Rule_HasTestCoverage` |
| SS-009 threshold boundaries (R5) | `ExcessiveDescriptionRuleTests.cs` | `Evaluate_*Threshold*` (7 tests) |

## Judgement Calls

1. **`CatalogueRules()` seam (explicitly flagged as a judgement call in the brief).**
   `RuleEngine.CatalogueRules()` does not exist yet (R1 is out of scope here) and the
   untracked peer-session test referencing it left the build non-compiling. Per the
   brief's escape valve ("if a not-yet-existing API would break the build for every
   other test, assert against the current public surface"), `Rule_IsListedByListRulesCatalogue`
   asserts against `new RuleEngine().Rules` - the exact object `Program.PrintRuleList`
   iterates today. This correctly reproduces the 4-rule gap (SS-022..025 are added as
   `customRules` per-scan in `Program.cs:1020-1023`, never in the engine's own
   constructor list). When R1 lands `CatalogueRules()`, swap the one line.
2. **`--help` surface matched against `Program.cs` source text**, not a live CLI
   invocation: `PrintUsage` is `private`, so `InternalsVisibleTo` doesn't reach it, and
   invoking `Main` end-to-end to capture stdout would run a full scan. Scoped between the
   `MCP SECURITY RULES:` and `For more information:` markers in the raw string literal.
3. **README surface scoped to a heading span** (`### Security Rules` .. `### Supported
   Platforms`), not the whole file. `README.md:27`'s changelog blurb already
   name-checks most (not all - it skips SS-031, SS-INFO-005, SS-INFO-006) of the new
   rules, so a whole-file `Contains` would have undercounted the gap the spec's matrix
   records as 15. Verified this against the file's actual heading structure.
   `docs/owasp-ast-mapping.md` and `INSTALLATION_AND_USAGE.md` had no such stray
   mentions, so those two use a whole-file `Contains` per the spec's "cheap and
   deterministic" instruction.
4. **Test-coverage surface matches rule id OR `RuleConstants` field name.** A pure
   literal-id `Contains` scan produced 2 false negatives the spec itself says are false
   (SS-019 via `CredentialHygieneRuleTests.cs`, SS-INFO-006 via `SkillOsvRulesTests.cs`) -
   both files assert `f.RuleId.ShouldBe(RuleConstants.Rules.CredentialHygiene)` /
   `...SkillDependencySurface` rather than the literal string. Widened the match to
   include the constant field name (reflected alongside the id), which resolved both
   without hand-listing exceptions.
5. **Deleted, not kept, the untracked `RuleCatalogueTests.cs`** (see Housekeeping). It
   was not committed by anyone yet and was actively breaking the build; spec section 7
   explicitly directs folding it in rather than keeping two overlapping tests.
6. **R5 threshold literals.** `ExcessiveDescriptionRule`'s length bands (1000/2000/5000)
   are private consts on the rule itself (`WarningThreshold`/`CriticalThreshold`/
   `ExtremThreshold`), not `RuleConstants.Limits` - there is no matching entry there.
   `ExcessiveDescriptionRuleTests.cs` mirrors the private values as local literals
   (documented in its header comment) since production code is out of scope for this
   task.

## Next Step for Coding Agent

Implement (R1, R3, R4 - not this task's scope, but what turns these 34 red cases green):
- R1: add `RuleEngine.CatalogueRules()` (full registry incl. per-scan rules) and point
  `PrintRuleList` at it. Optionally repoint `Rule_IsListedByListRulesCatalogue` at it too.
- R3: add SS-030..SS-042, SS-INFO-005, SS-INFO-006 to the README "Security Rules" tables.
- R4: add the same 15 rules to `docs/owasp-ast-mapping.md`.

## Open Questions

None. R5's test class passes immediately (coverage, not a red pin), as specified.
