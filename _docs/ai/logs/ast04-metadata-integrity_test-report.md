# Test Report: ast04-metadata-integrity

**Date:** 2026-09-27 | **Status:** RED (expected) | **Exit Code:** 1
**Test Command:** `dotnet test signal-sentinel.sln -c Release --no-build`
Build: 0 Warning(s), 0 Error(s). Run: `Failed: 39, Passed: 1784, Skipped: 0, Total: 1823`.
1782 pre-existing tests all still pass (1784 = 1782 + 2 new-but-currently-passing
guards, see below). Full run:
`_docs/ai/verify/evidence/ast04-metadata-integrity.red.testresults.txt`.

## Vendoring (Part 1)

Cloned `jhkchan/ast10-agent-skills` @ `58c2768`. Copied the ten `fixtures/AST04/*`
dirs verbatim into `Fixtures/Ast04Corpus/`; every file `cmp`-verified byte-identical.
`NOTICE.md` written with provenance/licence/payload notes; csproj glob extended
with `*.yaml`/`*.yml`/`*.toml`/`*.sh`, verified copied to `bin/Release/net10.0/`.
**Correction to the brief:** only V1's payload is `os.system('id')`. V3 is a
`__proto__` key merged by a plain (non-eval) `deepMerge`; V5 is a duplicate
`[permissions]` TOML table with **no bundled script at all**. NOTICE.md records
the corrected per-fixture description.

## Major finding: fixture reality vs. spec A4

| Fixture | Data-file construct | Unsafe loader script | Both halves? |
|---|---|---|---|
| V1 | `!!python/object/apply:os.system` tag | `yaml.load()`, no SafeLoader | **Yes -> High** |
| V3 | `__proto__` key (not an A2/A3-listed construct) | none (plain merge, not yaml/pickle/marshal/eval) | No |
| V5 | duplicate `[permissions]` table | none - no `scripts/` dir | No |
| V7 | none | none (`fetch.sh` is a plain curl) | No |
| V9 | none (`SKILL.md` only) | none | No |

Only V1 matches A4's "both halves -> High". V7/V9 have neither half; their
shape is spec A4's own SS-017 territory ("the risk-tier finding from A1 stays
within SS-017"), not SS-043. This task's Part 2 instruction was nonetheless
explicit: assert SS-043 fires on all five `V*`. `Ast04CorpusTests` follows that
literal instruction (see file header) rather than substituting my own reading -
open question 1. V3/V5 assert only that SS-043 fires (no severity claim); only
V1 asserts High.

Second discovery: fixtures declare permissions in nested YAML block form
(`permissions:\n  shell: true`). `FrontmatterParser.ParseFields` only matches
column-0 keys, so nested scalars aren't surfaced into `ExtraFrontmatter` today -
open question 3.

## Coverage Mapping (spec requirement -> test file)

| Requirement | File |
| --- | --- |
| A4: 5/5 vulnerable fire, 0/5 controls, High-severity band, A5 real-world guard | `Ast04CorpusTests.cs` |
| A1: L0-L3/numeric vocabulary, floor from shell/files.write/network.allow, no-regression guards | `SkillExcessivePermRuleAst04Tests.cs` |
| A2: unsafe loaders fire at Medium; safe loaders never fire | `Ast04UnsafeLoaderTests.cs` |
| A3: data-file read + YAML tags detected; A5 safe-file/doc-example guards | `Ast04DataFileIngestionTests.cs` |

(Full test-name mapping is in each file's test names, which name the criterion
they cover - see "Failing cases" below for the complete list.)

Existing v2.5.0 (G15c) suite `SkillExcessivePermRuleTests.cs` untouched, still green.

## Failing cases (39, all for the right reason)

**(a) 28 cases - `SS-043` not registered** (`GetRule()` throws "rule not found"):
`Ast04CorpusTests` all 14 cases (`VulnerableFixture_FiresSs043` x5,
`ControlFixture_ProducesZeroSs043Findings` x5, `V1_BothHalvesPresent...`,
`V3_FiresSs043`, `V5_FiresSs043`, `RealWorldSkillCorpus_ProducesZeroSs043Findings`);
`Ast04UnsafeLoaderTests` (7); `Ast04DataFileIngestionTests` (7).

**(b) 11 cases - `SkillExcessivePermRule` genuinely lacks the vocabulary/floor**
(`SkillExcessivePermRuleAst04Tests.cs`): `Evaluate_LowFormRiskTierWithDangerSignal_ReturnsHighMismatchFinding`
(L0,0,L1,1 - line 51); `Evaluate_HighFormRiskTierWithDangerSignal_DoesNotFireMismatchOrMissingFindings`
(L2,2,L3,3 - line 77); `Evaluate_L0WithDeclaredShellTrue_ReturnsHighMismatchFinding` (line 97);
`Evaluate_L0WithDeclaredNonEmptyFilesWrite_ReturnsHighMismatchFinding` (line 124);
`Evaluate_L0WithDeclaredNonEmptyNetworkAllow_ReturnsHighMismatchFinding` (line 148).

2 new tests intentionally pass today (not part of the 39):
`Evaluate_L3WithDeclaredShellTrue_DoesNotFireMismatchFinding`,
`Evaluate_L0WithNoDeclaredPermissionsAndNoProseSignal_DoesNotFireRiskTierFindings`
- negative guards on already-correct behaviour, not weak assertions.

## Judgment calls / open questions

1. **V7/V9 check SS-043 in `Ast04CorpusTests`, but spec A4 assigns their
   closure to SS-017.** Followed the brief's literal instruction rather than
   substituting "SS-017 OR SS-043". Delegator should decide: extend SS-043,
   change the corpus test to check both rules, or accept V7/V9 stay red.
2. **V3/V5 severity not asserted High** - not justified by fixture content
   (no A2-shaped unsafe loader in either). See NOTICE.md.
3. **`FrontmatterParser` nested-block scalar gap** may block V7/V9 detection via
   SkillReader even once SS-017/A1 is extended (production code, flagged only).
4. **A2 scope narrowed to the brief's Python-family list**; `eval`, `js-yaml`,
   `Import-Clixml` (spec A2) not covered here.

## Next Step for Coding Agent

Implement SS-043 (AST04/ASI01): register in `RuleEngine.CatalogueRules()`,
`RuleConstants`, `RuleAstMapping`, `--help`/`--list-rules`; bump
`RuleRegistryParityTests` 48->49. Extend ingestion to `.yaml`/`.yml`/`.json`/`.toml`
data files; detect A2 loaders and A3 YAML tags; resolve open questions 1-4
first. Extend `SkillExcessivePermRule` tier vocabulary/floor per A1.

## Red-run tail

```
Failed SignalSentinel.Scanner.Tests.SkillRules.Ast04CorpusTests.RealWorldSkillCorpus_ProducesZeroSs043Findings [105 ms]
  Error Message: Shouldly.ShouldAssertException : rule should not be null but was
Additional Info: SS-043 (Insecure Skill Metadata) is not registered in RuleEngine.CatalogueRules() - implement and register the rule per spec A4.
Failed!  - Failed:    39, Passed:  1784, Skipped:     0, Total:  1823, Duration: 2 s - SignalSentinel.Scanner.Tests.dll (net10.0)
```

Full output: `_docs/ai/verify/evidence/ast04-metadata-integrity.red.testresults.txt`.
