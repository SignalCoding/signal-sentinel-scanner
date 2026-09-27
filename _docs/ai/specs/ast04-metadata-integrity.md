# Spec: AST04 Insecure Metadata - close the detection gap

**Status:** draft for owner approval. **Branch (proposed):** `feat/ast04-metadata-integrity` from `main` @ `5091e7a`.
**Origin:** the benchmark in `_docs/ai/completed/2026-09-27_ast-benchmark-and-ast10-decision.md` found AST04 to be
our weakest category at **1 of 5 vulnerable fixtures detected**, and that single detection is incidental.
**Evidence base:** `jhkchan/ast10-agent-skills` AST04 fixtures, five vulnerable and five matched benign controls.
This is the first new detection in this project specified against real labelled positives *and* negatives.

---

## 1. What we actually miss, and why

| Fixture | Result today | Why |
|---|---|---|
| V1 yaml-frontmatter-injection | missed | payload lives in a shipped `metadata.yaml` sidecar we never read, loaded by an unsafe deserialisation call we do not detect |
| V3 json-metadata-injection | missed | same shape, JSON |
| V5 toml-metadata-injection | missed | same shape, TOML |
| V7 permission-understating | "detected" | fired **SS-014 exfiltration**, which is incidental. We did not detect the metadata problem |
| V9 risk-tier-spoofing | missed | SS-017 does cross-check `risk_tier`, but its vocabulary is `low, minimal, none` and the fixture declares `L0` |
| C8 permission-understating | **false positive** | SS-012 fired on the benign control |

So the honest score is **zero of five detected on their merits**, with one false positive on a control. The headline
"1 of 5" flattered us.

### The two shapes
**Deserialisation (V1, V3, V5).** Deliberately two-part, and the design is good: a code-executing construct in a data
file the package ships, *plus* a bundled script that opts into an unsafe loader. The control ships the same package
shape with neither half. Their own fixture notes that the `SKILL.md` frontmatter is deliberately benign "so the
finding cannot come from the label", which is a direct test of whether a scanner reads past the manifest.

**Self-classification (V7, V9).** The package declares a risk tier below the floor its own declared permissions
imply. V9 declares `risk_tier: L0` alongside `shell: true` and a write scope. The control declares `L3` honestly.

---

## 2. Requirements

### A1 - Risk-tier floor, extend SS-017 *(cheap, do first)*
- Extend `LowRiskTierValues` / `HighRiskTierValues` in `SkillExcessivePermRule` to cover the `L0`..`L3` form, and
  bare numeric `0`..`3`, alongside the existing words. Confirm the full vocabulary against the Universal Skill Format
  rather than guessing.
- Derive the floor from the skill's **declared permissions**, not only body-observed capability: `shell: true`, a
  non-empty `files.write` scope, or a non-empty `network.allow` each raise the implied floor. A declared tier below
  the implied floor is the finding.
- Must not regress the existing v2.5.0 (G15c) behaviour or its tests.
- Closes V9. Expected to also give V7 a principled detection rather than the incidental SS-014 hit.

### A2 - Unsafe deserialisation in bundled scripts
- Detect opt-in unsafe loaders in bundled scripts: `yaml.load` without `SafeLoader`, `yaml.unsafe_load`,
  `pickle.load`/`loads`, `marshal.loads`, `eval` applied to parsed content, and the JS/PowerShell equivalents
  (`js-yaml` `load` with `JSON_SCHEMA` overrides, `Import-Clixml`). Confirm the exact set from the fixtures.
- This is a genuine weakness on its own, independent of whether a payload ships with it.

### A3 - Dangerous constructs in shipped data files *(the largest piece)*
- **New ingestion.** `ScriptInventory` currently reads only `.py`, `.sh`, `.ps1`, `.js`. The payload in these
  fixtures is a `.yaml` sidecar, so the scanner never sees it. Extend ingestion to `.yaml`, `.yml`, `.json`, `.toml`
  shipped inside the skill package, as **data** rather than scripts, with the same size caps and encoding handling.
- Detect code-executing constructs: YAML tags such as `!!python/object/apply`, `!!python/name`, `!!python/module`,
  and the equivalent language-specific escapes in JSON and TOML payloads.

### A4 - The rule
- One new rule, **SS-043 "Insecure Skill Metadata"**, AST code `AST04`, ASI `ASI01`.
  **Note on the id:** an earlier `ss-043-cross-platform-reuse.md` used this number but was superseded before
  implementation, so SS-043 was never allocated to a shipped rule and is free. AGENTS.md's "ids are never reused"
  rule is not breached. Cross-reference both specs so the history is legible.
- **Severity, graduated, in the house style:**
  - **High** when both halves are present: a code-executing construct in a shipped data file *and* an unsafe loader
    in a bundled script.
  - **Medium** for an unsafe loader alone, or a code-executing construct alone.
  - The risk-tier finding from A1 stays within SS-017 at its existing severity.
- Registry count goes 48 -> 49 across all nine surfaces; `RuleRegistryParityTests` enforces it.

### A5 - False-positive guards
- The five **control** fixtures are the oracle: zero findings on all five is an acceptance criterion, not an aspiration.
- `yaml.safe_load`, `json.load` and equivalent safe APIs must never fire. The controls use them explicitly.
- A data file that merely *contains* a string resembling a tag, inside a documentation example, must not fire. Apply
  the same segment discipline used elsewhere, and prefer parsing the data file over regex where practical.
- The existing `Fixtures/RealWorldSkills` corpus must stay at zero SS-043 findings.

---

## 3. Acceptance

1. Build 0 warnings; full suite green.
2. **Against the labelled corpus: 5 of 5 AST04 vulnerable fixtures detected, 0 of 5 controls firing.** Anything less
   is reported rather than rounded up, and the C8 false positive from SS-012 is investigated as part of this work.
3. Zero SS-043 findings across the existing real-world corpus and the MCP smoke matrix.
4. `--list-rules` and `--help` report 49; parity holds across all nine surfaces.
5. The coverage guard is unaffected: AST04 was already claimed, so this changes detection quality, not coverage.

## 4. Scope and sequencing

A1 is small and self-contained and can land alone if the rest is deferred. A3 is the largest piece because it adds a
new file class to ingestion, and it is what the other two depend on for the High band.

**Out of scope:** the false-positive pattern identified in the benchmark, where rules fire on a dangerous capability
rather than its misuse. That is close to the limit of static analysis and the benchmark record explicitly recommends
against chasing it. AST10 and AST09 remain documented open categories.

## 5. Corpus handling

The fixtures are Apache-2.0 and may be vendored, but the repository is itself a collection of agent skills, which is
the threat class this scanner assesses. Before any of it is committed as a fixture it gets a provenance review and a
scan with Sentinel, per the project's third-party doctrine. Until then it stays a scratch-directory measurement set,
and the corpus-derived numbers in acceptance item 2 are reproduced by re-cloning rather than from vendored copies.
