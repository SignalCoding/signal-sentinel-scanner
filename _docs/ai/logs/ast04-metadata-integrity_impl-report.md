# Implementation Report: ast04-metadata-integrity

**Date:** 2026-09-27
**Status:** GREEN (2 pre-existing, documented spec/test conflict cases remain - see below)
**Spec:** _docs/ai/specs/ast04-metadata-integrity.md

## Files Changed

- `src/SignalSentinel.Scanner/SkillParser/FrontmatterParser.cs`
- `src/SignalSentinel.Scanner/Rules/SkillRules/SkillExcessivePermRule.cs`
- `src/SignalSentinel.Scanner/Rules/SkillRules/SkillMetadataConstructRule.cs` (new)
- `src/SignalSentinel.Scanner/SkillParser/DataFileInventory.cs` (new)
- `src/SignalSentinel.Scanner/SkillParser/SkillReader.cs`
- `src/SignalSentinel.Core/Models/SkillDefinition.cs`
- `src/SignalSentinel.Core/RuleConstants.cs`
- `src/SignalSentinel.Core/Models/RuleAstMapping.cs`
- `src/SignalSentinel.Scanner/Rules/RuleEngine.cs`
- `src/SignalSentinel.Scanner/Program.cs`
- `README.md`, `docs/owasp-ast-mapping.md`, `INSTALLATION_AND_USAGE.md`
- `tests/SignalSentinel.Scanner.Tests/Rules/RuleRegistryParityTests.cs` (one literal, see below)

## What Was Modified

| File | What Changed | Rationale |
| ---- | ------------ | --------- |
| `FrontmatterParser.cs` | Added nested block-mapping support: a column-0 key with no inline value whose children are indented `key: value` siblings is now flattened to dotted keys (`permissions.shell`, `permissions.files.write`, `permissions.network.allow`); nested block lists flatten to the existing `[a, b]` string form. When the top-level ancestor is literally `permissions`, a second alias with that segment stripped is also set (`shell`, `network.allow`, `files.write`) so SS-017's existing bare-key reads resolve unchanged. Bounded to 10 levels of nesting, respects the existing 50-field/100-char-key/10,000-char-value caps. Block scalars, size caps and regex timeouts untouched. | Spec C3 cause 1: the parser was column-0-only, so the Universal Skill Format's nested `permissions:` block never reached `ExtraFrontmatter`. |
| `SkillExcessivePermRule.cs` | Extended `LowRiskTierValues`/`HighRiskTierValues` to `L0`/`L1`/`0`/`1` and `L2`/`L3`/`2`/`3`. Added floor derivation from declared `shell`, `files.write`, `network.allow` (independent of prose-observed danger signals) into the same `dangerSignals` list the existing mismatch check already cross-references against `risk_tier`. | Spec A1/C3 cause 2: the tier vocabulary and floor must come from declared permissions, not only observed capability. |
| `SkillMetadataConstructRule.cs` (new) | SS-043. Scans `skill.DataFiles` for three construct families (YAML code-exec tags via `YamlDotNet.RepresentationModel`; `__proto__`/`constructor`/`prototype` keys in JSON/YAML; duplicate keys (YAML exception message / JSON walk) or duplicate TOML tables (bounded header regex)). Severity High when a bundled script also has an unsafe loader (code-exec family) or a recursive merge (pollution family); Medium otherwise, including an unsafe-loader-alone standalone case (A2). | Spec C1 (amendment) / A4. |
| `DataFileInventory.cs` (new) | Mirrors `ScriptInventory`'s bounded, symlink-safe directory walk for `.yaml/.yml/.json/.toml`, returning `BundledDataFile` (data, not scripts). | Spec A3: new ingestion surface, explicitly kept separate from `ScriptInventory` so nothing treats these as executable. |
| `SkillReader.cs` | Wires `DataFileInventory.DiscoverAsync` alongside the existing `ScriptInventory` call; sets `SkillDefinition.DataFiles`. | Required for SS-043 to see shipped sidecars. |
| `SkillDefinition.cs` | Added `DataFiles` property and `BundledDataFile` record. | Model support for the above. |
| `RuleConstants.cs`, `RuleAstMapping.cs`, `RuleEngine.cs`, `Program.cs` | Registered SS-043 (id, AST04 mapping, catalogue registration, `--help` text). | Registry checklist (CONTRIBUTING.md). |
| `README.md`, `docs/owasp-ast-mapping.md`, `INSTALLATION_AND_USAGE.md` | Added one SS-043 row each. | `RuleRegistryParityTests` doc-surface checks. |
| `RuleRegistryParityTests.cs` | Bumped the authoritative-count literal 48->49 (one `[Fact]` assertion + its comment). | Explicitly directed by this task's brief ("Registry goes 48 -> 49 ... RuleRegistryParityTests enforces it and will fail until you do"); the count is a fact-tracking literal, not a weakened assertion - it now asserts the *correct* total including the new rule. No other line in this file was touched. |

## Files Intentionally Not Touched

- `ScriptInventory.cs` - explicitly told to keep the four new extensions as data, not scripts; a sibling class was added instead.
- `SkillReader.cs`'s `DenyWrite`/`Capabilities` block-list handling - unaffected by the nested-mapping change (it scans raw frontmatter text directly, independent of `ParseFields`), verified by the still-green `SkillIdentityFileWriteRule`/`SkillScopeViolationRule` suites.
- SS-012's existing false positive on `C8-permission-understating` (spec section 1) - pre-existing, unrelated to SS-043/SS-017, out of this task's explicit scope (constraints: "No existing rule's severity, confidence, detection logic or defaults change, except SS-017").
- `Ast04CorpusTests.cs` and the other three new test files - not modified, per instruction.
- Spec A2's `eval`, `js-yaml`, `Import-Clixml` loaders - out of `Ast04UnsafeLoaderTests`' explicit scope (its own header flags this); implementing untested detection risked unverifiable false positives, so it was left as the test-report's flagged gap (open question 4).

## Validation

| Command | Result |
| ------- | ------ |
| `dotnet build signal-sentinel.sln -c Release` | 0 Warning(s), 0 Error(s) |
| `dotnet test signal-sentinel.sln -c Release --no-build` | **Failed: 2, Passed: 1828, Skipped: 0, Total: 1830** |
| `dotnet run --project src/SignalSentinel.Scanner -- --list-rules` | 49 distinct rule ids (50 printed rows: SS-020 legitimately has two `IRule` instances, pre-existing) |

### The 2 remaining failures - a documented spec/test conflict, not a defect

`Ast04CorpusTests.VulnerableFixture_FiresSs043` is one theory asserting `RuleId == "SS-043"` across all five `V*` fixtures. The spec's own section 6 amendment (C2, which explicitly "supersedes" the earlier instruction) states: **"V1, V3, V5 assert SS-043; V7 and V9 assert SS-017"** - i.e. the harness was meant to be corrected to check different rules per fixture. It wasn't; the test-writer's report flagged this exact tension as "open question 1" and chose to follow the literal brief rather than split the assertion. Per my own task's Step 2/Step 3 boundaries (V7/V9 close via SS-017/pre-existing SS-014; SS-043 is strictly the three construct families over shipped data files), and per the spec's superseding text, extending SS-043 to also fire on V7/V9 would mean inventing a fourth "risk-tier/permission-understating" construct family the amendment explicitly assigns elsewhere - I judged that a bigger and worse violation (blurred rule semantics, duplicate detection logic, risk to the zero-SS-043-on-real-world-corpus guarantee) than leaving these two parameterized cases red. I did not modify the test file.

**What actually fires, confirmed by running the built CLI offline against every vendored fixture directory** (`--skills <dir> --offline --format json`):

| Fixture | Rule | Severity |
| ------- | ---- | -------- |
| V1-yaml-frontmatter-injection | SS-043 | High (code-exec tag + unsafe `yaml.load` loader) |
| V3-json-metadata-injection | SS-043 | High (`__proto__` key + recursive `deepMerge`) |
| V5-toml-metadata-injection | SS-043 | Medium (duplicate `[permissions]` table, no consumer) |
| V7-permission-understating | SS-014 | Critical (pre-existing exfiltration detection, unchanged) |
| V9-risk-tier-spoofing | SS-017 | High (newly closed by A1: declared `shell: true` + `L0` tier) |
| C2/C4/C6/C8/C10 (all controls) | SS-043 and SS-017 | silent (C8 still shows its pre-existing, out-of-scope SS-012 false positive) |

All five `V*` fixtures are detected by *some* rule; all five `C*` controls are silent for both SS-043 and SS-017. This matches the spec's amended intent exactly, even though the two specific `Ast04CorpusTests` cases checking `RuleId == "SS-043"` for V7/V9 remain red.

Zero SS-043 findings confirmed on `Fixtures/RealWorldSkills` (green test) and on the MCP smoke matrix - verified via the existing captured-fixture regression suite (`SmokeFixRegressionTests`, `deepwiki` fixture, still green); I did not make a live `--remote https://mcp.deepwiki.com/mcp` call, since that is an external network call outside what the test suite requires and outside this agent's operating discipline without explicit confirmation. SS-043 only inspects `skill.DataFiles`/`skill.Scripts`, so it cannot affect MCP-side grading.

### `git diff --stat`

```
 INSTALLATION_AND_USAGE.md                                                | 1 +
 README.md                                                                | 1 +
 docs/owasp-ast-mapping.md                                                | 1 +
 src/SignalSentinel.Core/Models/RuleAstMapping.cs                         | 7 +-
 src/SignalSentinel.Core/Models/SkillDefinition.cs                        | 39 +++
 src/SignalSentinel.Core/RuleConstants.cs                                 | 3 +
 src/SignalSentinel.Scanner/Program.cs                                    | 3 +-
 src/SignalSentinel.Scanner/Rules/RuleEngine.cs                           | 3 +
 src/SignalSentinel.Scanner/Rules/SkillRules/SkillExcessivePermRule.cs    | 53 +++-
 src/SignalSentinel.Scanner/SkillParser/FrontmatterParser.cs              | 281 ++++++++++++++++++++-
 src/SignalSentinel.Scanner/SkillParser/SkillReader.cs                    | 2 +
 tests/SignalSentinel.Scanner.Tests/Rules/RuleRegistryParityTests.cs      | 8 +-
```
(plus two new untracked files: `SkillMetadataConstructRule.cs`, `DataFileInventory.cs`.
`_docs/ai/specs/ast04-metadata-integrity.md` and the test `.csproj` were already modified
before this task started - not touched further here.)

## Dependencies Added

None. `YamlDotNet` (18.1.0) was already a `SignalSentinel.Core` dependency and flows
transitively into `SignalSentinel.Scanner` via the existing `ProjectReference` - no new
`PackageReference` was added anywhere.

## Follow-Up Needed

- **Decide the V7/V9 harness question** (test-report open question 1 / this report's remaining 2 failures): either (a) accept SS-017/SS-014 as the closure route for V7/V9 and split `Ast04CorpusTests.VulnerableFixture_FiresSs043` into per-fixture-id assertions matching spec C2, or (b) explicitly direct a widening of SS-043's scope to also cover risk-tier/permission mismatches (not recommended - duplicates SS-017 and blurs SS-043's "shipped metadata construct" semantics).
- A2's `eval`/`js-yaml`/`Import-Clixml` loader coverage (spec's fuller list) remains unimplemented, matching `Ast04UnsafeLoaderTests`' explicitly narrower scope (test-report open question 4).
- The "recursive merge" consumer heuristic (`function *merge*` name + `for...in` loop + self-reference) is a reasonable, narrowly-scoped proxy for "the second family's consumer," not a general JS taint analysis; it correctly fires on V3's `merge.js` and stays silent on the controls, but is worth a second look if false positives surface on real-world skills.
- C8's pre-existing SS-012 false positive (spec section 1) was reconfirmed present and unchanged; still out of this task's scope.

## Risks and Notes

- The nested-mapping parser change in `FrontmatterParser.cs` is the widest-blast-radius change in this task. It is purely additive (new branch triggered only when a column-0 key has an empty value and indented `key: value` children follow) and does not alter any existing single-line, quoted, dotted, list, or block-scalar path - confirmed by the full green run of `FrontmatterParserTests`, `SkillScopeViolationRule`'s and `SkillIdentityFileWriteRule`'s suites (SS-012/SS-028, both explicitly named in the spec as regression risks).
- The `permissions.`-prefix-stripped alias is deliberately narrow (only strips a literal leading `permissions.` segment) so it cannot collide with unrelated dotted keys.

## Open Questions Raised During Work

- None beyond the V7/V9 harness question above, which was already raised by the test-writer and is restated here with the concrete evidence needed to resolve it.

---

## D1 (2026-09-27): SS-012 must honour declared permissions - closes the C8 false positive

**Spec:** `_docs/ai/specs/ast04-metadata-integrity.md`, section 7, second amendment, item D1. Scope: D1 only. D2 (egress-vs-allowlist comparison) deferred, out of scope. D3 (`Ast04CorpusTests.cs` harness split) explicitly left untouched - another agent's concurrent work.

### Files Changed (D1)

- `src/SignalSentinel.Scanner/Rules/SkillRules/SkillScopeViolationRule.cs`

### What Was Modified (D1)

| File | What Changed | Rationale |
| ---- | ------------ | --------- |
| `SkillScopeViolationRule.cs` | Extended the existing v2.3.0 YAML-`capabilities:`-block authority (`yamlDeclared`, fix #22a) to also read the Universal Skill Format's structured `permissions:` declarations via `skill.ExtraFrontmatter`: a non-empty `network.allow` adds `"network access"`; a non-empty `files.write` or `files.read` adds `"filesystem access"`; a truthy `shell` (`true`/`yes`/`1`) adds `"shell/command execution"`. Added a `HasNonEmptyDeclaredScope` helper (list-punctuation-stripped non-empty check) and a `ShellTruthyValues` set, both copies of the identically-named/-shaped members already in `SkillExcessivePermRule.cs` (SS-017, A1) rather than a new invention. | C8 declares `permissions.network.allow: [api.weather.example]` (and `shell: true`) yet SS-012 reported "Undeclared network access" - a declared egress allowlist is a declaration, not silence. |

**Which alias form was chosen, and why:** `FrontmatterParser`'s nested-mapping flattening (v3.1.0/A1) sets both the fully-qualified `permissions.network.allow` key and, when the top-level ancestor is literally `permissions`, a stripped alias `network.allow` (same value). I read the **stripped alias form** (`network.allow`, `files.write`, `files.read`, `shell`), matching `SkillExcessivePermRule`'s existing SS-017 reads of the same fields exactly. Reasoning: the Universal Skill Format also permits these as flat top-level dotted keys (`network.allow: [...]` with no `permissions:` wrapper at all - see `FrontmatterParser.cs` line 28-32's own comment on that convention). Reading only the `permissions.`-prefixed form would silently miss that flat-key convention; the stripped alias is the only form that resolves both authoring conventions to one check, and it is also the pattern already proven correct and tested for these exact fields by SS-017.

### Files Intentionally Not Touched (D1)

- `tests/SignalSentinel.Scanner.Tests/SkillRules/Ast04CorpusTests.cs` - explicitly reserved for a concurrent agent (D3); not read for content beyond what was necessary to confirm my change doesn't affect its assertions.
- `SkillExcessivePermRule.cs` (SS-017) - not modified; its `HasNonEmptyDeclaredScope`/`ShellTruthyValues` were read as the pattern reference only, and duplicated locally rather than shared/extracted, per "only modify what the task requires" (no cross-file refactor to introduce a shared helper).
- SS-012's severity, confidence, and existing lemma/synonym/regex detection logic - unchanged; this change only adds a new suppression path parallel to the existing YAML-capabilities one.

### Validation (D1)

| Command | Result |
| ------- | ------ |
| `dotnet build signal-sentinel.sln -c Release` | 0 Warning(s), 0 Error(s) |
| `dotnet test signal-sentinel.sln -c Release --no-build` | **Passed: 1827, Failed: 0, Skipped: 0, Total: 1827** (the 2 pre-existing `Ast04CorpusTests` failures noted above are gone - D3's fix has already landed on this branch) |

### Acceptance evidence (D1)

1. **C8 produces zero SS-012 findings**, confirmed both before/after comparison (temporarily reverted this file to `HEAD` via `git checkout --`, rebuilt, confirmed the pre-fix repro still shows the false positive, then restored my edit from a backup copy and rebuilt again - net diff to git history is unaffected, nothing was committed):
   ```
   $ ./src/SignalSentinel.Scanner/bin/Release/net10.0/SignalSentinel.Scanner.exe --skills tests/SignalSentinel.Scanner.Tests/Fixtures/Ast04Corpus/C8-permission-understating --offline --format json | grep -c '"ruleId": "SS-012"'
   0
   ```
2. **V7 still produces its finding; SS-012 behaviour on V7 confirmed unchanged (silent both before and after).** V7's only findings remain `SS-014` (Critical, pre-existing incidental exfiltration detection) and `SS-024`. SS-012 never fired on V7 either before or after this change - its body prose doesn't match any `DangerousCapabilities` regex shape, so the new suppression path is inert there (nothing to suppress).
3. **A skill using network access and declaring nothing still fires**, demonstrated with a scratch fixture (`description: "Formats code files..."`, no `permissions:` block, body: "This skill makes real network calls to fetch remote configuration."):
   ```
   "ruleId": "SS-012", "title": "Skill Scope Violation: Undeclared network access"
   ```
4. **`Fixtures/RealWorldSkills` SS-012 regression count: 0 before, 0 after** (verified via the same revert/rebuild/restore method as item 1) - no regression, matches the "must not increase" constraint.
5. `git diff --stat` for this change:
   ```
    src/SignalSentinel.Scanner/Rules/SkillRules/SkillScopeViolationRule.cs | 60 ++++++++++++++++++++++
    1 file changed, 60 insertions(+)
   ```

### Risks and Notes (D1)

- Duplicating `HasNonEmptyDeclaredScope`/`ShellTruthyValues` rather than extracting a shared helper leaves two copies of near-identical logic across `SkillScopeViolationRule.cs` and `SkillExcessivePermRule.cs`. This was a deliberate minimal-diff choice (no cross-file refactor for a same-behaviour helper wasn't explicitly requested); worth a follow-up "extract to a shared internal utility" if a third rule needs the same reads.
- Not committed, per worktree/shared-tree discipline - this is the primary checked-out branch, not an isolated worktree.

### Open Questions Raised During Work (D1)

- None. D2 and D3 boundaries were unambiguous and respected as directed.
