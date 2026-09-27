# Implementation Report: revert-ast09-mapping

**Date:** 2026-09-27
**Status:** GREEN
**Decision:** `_docs/ai/completed/2026-09-27_ast-benchmark-and-ast10-decision.md` section 4

## Files Changed

- `src/SignalSentinel.Core/Models/RuleAstMapping.cs`
- `tests/SignalSentinel.Scanner.Tests/Rules/OwaspFullCoverageTests.cs`
- `docs/owasp-ast-mapping.md`

## What Was Modified

| File | What Changed | Rationale |
| ---- | ------------ | --------- |
| `RuleAstMapping.cs` | `SS-024` returns to `[AST02, AST07]`, dropping `AST09`; comment explains why | AST09 reverted per owner decision |
| `OwaspFullCoverageTests.cs` | C2 tests now pin the *absence* of AST09 on SS-024 (kept the additivity test). `DocumentedAstException` (single const) generalised to `DocumentedAstExceptions` (`Dictionary<string,string>` - CA1859 requires concrete type over `IReadOnlyDictionary`), holding AST09 and AST10 each with its own reason, both printed on failure | Guard must tolerate exactly two named categories, fail on any third |
| `docs/owasp-ast-mapping.md` | SS-024 row drops AST09; coverage statement is 10/10 ASI, 8/10 AST, 10/10 MCP; AST09 and AST10 both documented as open with reasons (AST09 corroborated by the independent `jhkchan/ast10-agent-skills` implementation); added "Suggested website wording" block | Public claim must match reverted mapping |

## Files Intentionally Not Touched

- `README.md`, `SECURITY.md`, `INSTALLATION_AND_USAGE.md`, `CHANGELOG.md` - searched for "10/10", "9/10", "8/10", "AST09", "every category", "all three frameworks"; only found range references (`AST01-AST10`, `ASI01-ASI10 + AST01-AST10 + MCP01-MCP10`), never a coverage-count claim, so nothing overstates and nothing needed changing.
- `src/SignalSentinel.Core/Models/OwaspMapping.cs` - defines the AST09 category constant/description itself; that is taxonomy, not a coverage claim, out of scope.

## Validation

| Command | Exit Code |
| --- | --- |
| `dotnet build signal-sentinel.sln -c Release` | 0 (0 warnings) |
| `dotnet test signal-sentinel.sln -c Release --no-build` | 0 (1782 passed, 0 failed) |
| Guard demonstration (AST05 temporarily dropped from SS-011+SS-032) | Failed as expected, named `AST05`, printed both documented exceptions; restored, `git diff` on the file clean |

## Follow-Up Needed

- none

## Risks and Notes

- none
