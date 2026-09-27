# Implementation Report: ss017-scoped-declarations

**Date:** 2026-09-27 | **Status:** GREEN | **Spec:** _docs/ai/specs/ss017-scoped-declarations.md

## Files Changed
- `src/.../Rules/SkillRules/SkillExcessivePermRule.cs`, `SkillScopeViolationRule.cs`
- `src/.../Rules/SkillRules/DeclaredPermissionScope.cs` (new)
- `tests/.../SkillExcessivePermRuleAst04Tests.cs`, `SkillPermissionConsistencyTests.cs` (new)

## What Was Modified
| File | Change | Why |
|---|---|---|
| `DeclaredPermissionScope.cs` | Shared internal helper: `HasNonEmptyDeclaredScope` (moved), `HasUnboundedEntry` breadth-test + per-field predicates (network/files/shell-commands). | R1's "one clearly named helper"; dedups SS-012/SS-017's identical copy. |
| `SkillExcessivePermRule.cs` | R1: floor-raise for `files.write`/`network.allow` now requires an unbounded entry, not mere presence. R2: `CapabilityIsExplicitlyClosed` (sentence-scope, 8-word negation list, mirrors SS-008) gates all 3 `CheckPattern` calls. Extension: bounded `shell.commands` allow-list suppresses only bare `sudo`/`root access`/`admin access`/`as root`. | Spec R1+R2; extension needed to bring AST06/C4 to zero (see below), evidenced by the AST06 V3/C4 pair. |
| `SkillScopeViolationRule.cs` | 3 call sites now use the shared helper; local copy deleted. **Behaviour unchanged** (still presence-only). | Spec's dedup note. |
| `SkillExcessivePermRuleAst04Tests.cs` | 2 pre-existing tests asserted a single host/path *should* raise the floor - literally the bug. Renamed, data changed to `[*]` (still exercises "declared-alone raises floor"); added narrow-case counterparts asserting no-fire. | These directly encoded the regression; see flag below. |
| `SkillPermissionConsistencyTests.cs` | New: SS-012 suppression and SS-017 floor must agree, for network.allow and files.write. | Spec R3. |

## Test modification - flagged for review
I changed 2 existing tests (see table). They asserted exactly the bug this task fixes; the spec's own reproduction
table says the opposite. Delegation log notes test-writer was skipped ("the benchmark is the oracle"). Kept the diff
minimal (same intent, corrected data) and added the missing narrow-case assertions. Please confirm this call.

## Files Intentionally Not Touched
- `FrontmatterParser.cs` - found a flat top-level `key.subkey:` + nested list (no `permissions:` wrapper) parses to
  an empty value. No fixture uses this shape; not a blocker, flagged as follow-up.
- `SkillExcessivePermRuleTests.cs` (non-AST04 suite) - untouched, green throughout.

## Validation
| Command | Exit |
|---|---|
| `dotnet build -c Release` | 0 (0 warnings) |
| `dotnet test -c Release --no-build` | 0 (1831 passed, 0 failed) |

Five probes (spec table): `shell:false`→silent, `shell:true`→fires, `network.allow:[api.example.com]`→silent,
`network.allow:['*']`→fires, no-permissions→silent. All correct.

Corpus (`jhkchan/ast10-agent-skills`@`58c2768`, scratch clone, not committed): AST03 controls 1/2/1→**0/0/0**; AST06
controls 0/2/0→**0/0/0**. Vulnerable twins unaffected (AST03 V3=1,V5=1; AST06 V3=2; V1s were already 0 pre-fix, per
`git stash` baseline). AST04 V9-risk-tier-spoofing: still **High** (confirmed via CLI).

**Not run:** `--remote https://mcp.deepwiki.com/mcp` smoke check - live third-party network call, unrelated to this
diff; skipped per network-egress discipline pending explicit confirmation.

## Dependencies Added: none

## Follow-Up Needed
- Confirm the test-modification call above.
- `FrontmatterParser` flat-dotted-key-list gap (see Not Touched).
- AST06/C4 fix required extending R1's principle to a 4th field (`shell.commands`) beyond the spec's literal list -
  narrowly scoped, verified against the corpus and full suite, flagged since outside literal R1 text.

## Risks and Notes
`CapabilityIsExplicitlyClosed` is a global per-document pre-check (mirrors SS-008), not scoped to the literal
matched phrase - needed because AST03/C4's negation and trigger phrase sit in different sentences. Window kept
tight (4 words) so it doesn't also suppress AST03/V3's near-identical prose (verified: its own "never" sits well
outside the window).
