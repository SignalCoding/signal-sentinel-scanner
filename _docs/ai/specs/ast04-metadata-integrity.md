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

---

## 6. Amendment after the red phase (2026-09-27)

Three corrections. The first is the orchestrator's error and is the same failure pattern as the AST10 grep: one
instance inspected, the class assumed.

### C1 - V1, V3 and V5 are three different attacks, not one across three formats
The spec described A2/A3 as unsafe deserialisation in YAML, JSON and TOML. Reading all five fixtures shows:

| Fixture | Actual shape | Consuming operation |
|---|---|---|
| V1 | code-executing YAML tag `!!python/object/apply:os.system` in `metadata.yaml` | `yaml.load` without SafeLoader |
| V3 | **prototype pollution**: a `__proto__` key in shipped JSON | a plain `deepMerge`, no `eval`, no unsafe loader |
| V5 | **parser ambiguity**: a duplicate `[permissions]` TOML table | **no script at all** |

So only V1 has the two-part shape A4 based its High band on. V3's consuming operation is an ordinary merge, and V5
has no consumer: the attack is that different TOML parsers resolve a duplicate table differently, so the file means
one thing to the validator and another to the loader.

**Revised design.** SS-043 becomes **"Dangerous Construct in Shipped Skill Metadata"**, one rule over three construct
families, which is coherent because all three are "the shipped metadata is not what it appears to be":
- **code execution**: `!!python/object/apply`, `!!python/name`, `!!python/module` and equivalents
- **prototype pollution**: `__proto__`, `constructor`, `prototype` as keys in shipped JSON or YAML
- **parser ambiguity**: duplicate keys or duplicate tables in a shipped YAML, JSON or TOML file

Severity: **High** when a consuming operation is also present in a bundled script (an unsafe loader for the first
family, a recursive merge for the second). **Medium** for the construct alone, which is the correct band for V5,
where no consumer ships and the danger is entirely in the ambiguity.

### C2 - V7 and V9 belong to SS-017, not SS-043
The spec assigned risk-tier closure to SS-017, but the test brief asked the corpus harness to assert SS-043 on all
five vulnerable fixtures. The test-writer followed the brief and flagged the contradiction, which was the right call.
**The harness is corrected:** V1, V3, V5 assert SS-043; V7 and V9 assert SS-017. The two-sided acceptance is
unchanged, all five vulnerable fixtures detected by *some* rule and all five controls silent.

### C3 - A1 is materially bigger than a vocabulary fix
Probing the shipped binary directly, a skill declaring a shell permission with a low risk tier produces **no finding
in any declaration form**:

| Form | Result |
|---|---|
| nested `permissions:` block | no finding |
| flat dotted `permissions.shell: true` | no finding |
| `capabilities: [shell, network]` list | no finding |

Two distinct causes, both needing work:
1. **`FrontmatterParser` is line-based and column-0 only.** Nested block mappings never reach `ExtraFrontmatter`.
   The 3.0.1 fix (F1) added block *scalars*, which is a different construct. The Universal Skill Format's nested
   `permissions:` block is therefore invisible to every rule that consumes declared permissions, not only SS-017.
2. **SS-017's cross-check requires an *observed* capability in the body.** A declaration alone never raises the
   implied floor, which is precisely the spoofing case: a package that declares shell access and claims tier L0
   while its body stays bland.

A1 therefore covers: nested-mapping support in `FrontmatterParser`, the `L0`..`L3` and numeric tier vocabulary, and
deriving the floor from declared permissions independently of observed capability. The parser change is the widest
blast radius in this work and must not regress SS-012's YAML-capabilities authority or SS-028's deny_write
escalation, both of which read the same frontmatter.

## 7. Second amendment (2026-09-27, after implementation)

Verified independently against the built binary: **4 of 5 vulnerable fixtures now detected on merit**, up from 0.
V1/V3/V5 via SS-043 (High/High/Medium), V9 via SS-017 (High). Four of five controls silent.

Two items remain, and they are the same fixture pair, which makes the result inverted for that theme: we fire on
the benign twin and catch the vulnerable one only incidentally.

**V7/C8 are "permission understating": the manifest's egress allowlist names one host and the bundled script calls
a different, undeclared endpoint.** The control ships the identical allowlist and identical egress primitives, and
every host it reaches is declared.

### D1 - SS-012 must honour declared permissions *(closes the C8 false positive)*
C8 draws `SS-012 Skill Scope Violation: Undeclared network access` while its manifest declares
`permissions.network.allow` with a host. A declared egress allowlist is a declaration of network access; reporting
it as undeclared is simply wrong. SS-012 already treats the YAML `capabilities:` block as authoritative (v2.3.0
fix #22a); extend that to the nested permission declarations now reachable after Step 1:
- non-empty `permissions.network.allow` declares network access
- non-empty `permissions.files.write` (or `files.read`) declares filesystem access
- `permissions.shell: true` declares shell/command execution

### D2 - Egress allowlist versus actual destinations *(closes V7 on merit)* - **follow-up, not this branch**
Detecting V7 properly means comparing the hosts a bundled script actually reaches against the manifest's
allowlist, and reporting destinations that are not declared. That is a genuinely valuable control and a new
detection rather than an extension, so it gets its own spec, fixtures and false-positive analysis. V7 continues to
be caught incidentally by SS-014 in the meantime, which is recorded rather than counted as a merit detection.

### D3 - Corpus harness assertion
`Ast04CorpusTests.VulnerableFixture_FiresSs043` asserts SS-043 across all five `V*` fixtures, contradicting section
6/C2 which assigns V7 and V9 to SS-017. The implementation is correct and the test is wrong. Split the assertion
per fixture: V1/V3/V5 expect SS-043; V9 expects SS-017; V7 expects a finding from any rule, annotated as
incidental pending D2. Widening SS-043 to cover permission mismatches was explicitly considered and rejected: it
would duplicate SS-017 and conflate two different categories of defect.
