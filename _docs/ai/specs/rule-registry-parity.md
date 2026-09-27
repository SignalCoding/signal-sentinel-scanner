# Spec: rule-registry parity audit and guard

**Status:** draft, awaiting owner approval. Two decisions are required before implementation, in section 4.
**Branch (proposed):** `fix/rule-registry-parity` from `main` @ `945be64`.
**Trigger:** website v3.0.4 cross-check (peer session, handover addendum 2026-09-27) plus the orchestrator's own audit of 2026-09-27.
**Doctrine:** AGENTS.md "Pattern Detection -> Comprehensive Audit". Two whole cohorts of rules were never wired into the
surfaces that describe them. This spec fixes the class and adds the guard, rather than patching the four instances first found.

---

## 1. Why

`--list-rules` printing 43 of 47 rules was reported as a small defect. It is not. Auditing all 47 rules against every
surface the AGENTS.md rule-registry checklist names shows two cohorts that were never completed, and a public claim
the code does not support.

**Cohort A (v2.2.0): SS-022, SS-023, SS-024, SS-025.** Registered per scan at `Program.cs:1020-1023` rather than on
the base engine, so `PrintRuleList` (`Program.cs:1521`), which enumerates a bare `RuleEngine`, never sees them.
Three of the four also have no OWASP MCP code.

**Cohort B (v3.0.0): SS-030..SS-042, SS-INFO-005, SS-INFO-006.** Fifteen rules that reached `--help`,
`INSTALLATION_AND_USAGE.md` and the engine, but never the README rule tables or `docs/owasp-ast-mapping.md`.

**Separately: the "100% OWASP coverage" claim is not currently true.** It appears on the website, not in this repo.
Measured from source on 2026-09-27: ASI08 is used by no rule, AST09 is used by no rule, and MCP04 and MCP10 are
returned by no branch of `GetCorrespondingMcpCode`. Coverage is 9/10, 9/10 and 8/10, not 100%.

---

## 2. Evidence: gap matrix

All 47 rules (the `--help` registry) against each surface. Counts are rules missing from that surface.

| Surface | File | Missing | Rules |
|---|---|---|---|
| Rule constant | `Core/RuleConstants.cs` | 0 | - |
| Engine registration | `Rules/RuleEngine.cs`, `Program.cs` | 0 | - |
| `--help` | `Program.cs` | 0 | - |
| Install guide tables | `INSTALLATION_AND_USAGE.md` | 0 | - |
| AST mapping | `Core/Models/RuleAstMapping.cs` | 1 | SS-INFO-002 (expected: no AST code applies; confirm and document) |
| **`--list-rules`** | `Program.cs:1521` | **4** | SS-022, SS-023, SS-024, SS-025 |
| **README rule tables** | `README.md` ~147-194 | **15** | SS-030..SS-042, SS-INFO-005, SS-INFO-006 |
| **AST mapping doc** | `docs/owasp-ast-mapping.md` | **15** | SS-030..SS-042, SS-INFO-005, SS-INFO-006 |
| **Unit test class** | `tests/**` | **1** | SS-009 (`ExcessiveDescriptionRule`, no test class; exercised only incidentally by fixture regression tests) |
| MCP mapping | `Core/Models/OwaspMcpMapping.cs` | 27 | see section 4, decision D1 |

SS-019 and SS-INFO-006 appeared to lack tests when matched by rule ID; both are in fact covered
(`CredentialHygieneRuleTests.cs`, `SkillOsvRulesTests.cs`). Only SS-009 is genuinely untested.

---

## 3. Requirements

### R1 - `--list-rules` reports every registered rule **[defect]**
- Add `RuleEngine.CatalogueRules()` returning the full registry including the per-scan rules, and have
  `PrintRuleList` use it. Do not change which rules *run* in a scan; this is a reporting fix only.
- The peer session left an untracked red test at `tests/SignalSentinel.Scanner.Tests/Rules/RuleCatalogueTests.cs`.
  Review it, keep it if it asserts the right thing, and fold it into R7 rather than keeping two overlapping tests.
- Acceptance: `--list-rules` prints 47 distinct rule ids; `--help` and `--list-rules` agree exactly.

### R2 - Correct the new-rule count **[published error]**
- `README.md:27` reads "**22 new rules** (47 total)"; `CHANGELOG.md:213` reads "Twenty-two new rules". Both are wrong.
- The correct figure is **15**: SS-030..SS-042 (13) plus SS-INFO-005 and SS-INFO-006. 32 + 15 = 47.
- The CHANGELOG edit amends a released section. Add a brief footnote noting the correction rather than silently
  rewriting history, per the project's treatment of findings as governance artefacts.

### R3 - README rule tables carry all 47
- Add the 15 missing rules to the tables at `README.md` ~147-194, copying from `INSTALLATION_AND_USAGE.md`, which is
  already complete and is the reference.
- State totals as "41 detection + 6 informational". Do **not** publish an MCP-versus-Skill split: SS-026 and SS-036
  apply to both surfaces, so any split double-counts and will not sum to 47.

### R4 - `docs/owasp-ast-mapping.md` carries all 47
- Same 15 additions, same source. This file currently documents 28 rules and stops at SS-029.

### R5 - SS-009 gets a test class
- `ExcessiveDescriptionRule` is the only rule with no unit test. Add one covering the threshold boundary (at, below
  and above `RuleConstants.Limits`), matching the style of its siblings.

### R6 - OWASP coverage: resolve or restate **[owner decision D2]**
- Implement whatever D2 decides. If categories are filled, add the mappings and a test asserting every ASI, AST and
  MCP category is reachable. If they are declared out of scope, record why in `docs/owasp-ast-mapping.md` and supply
  the corrected form of words for the website.

### R7 - Parity guard so this cannot recur **[the point of the exercise]**
- One test, `RuleRegistryParityTests`, driven from the authoritative rule-id list, asserting for every rule:
  a constant exists; an AST mapping exists (with a documented allow-list for deliberate exceptions such as
  SS-INFO-002); the engine registers it; `--help` lists it; `CatalogueRules()` lists it; the README tables contain
  it; `docs/owasp-ast-mapping.md` contains it; `INSTALLATION_AND_USAGE.md` contains it; at least one test file
  references it or its rule class.
- Failures must name the rule and the surface, so the message tells a contributor exactly what they missed.
- Doc surfaces are matched by rule id against the file contents, deliberately cheap and deterministic. A rule added
  without its documentation fails the build, which is the outcome that was missing.

### R8 - Update the checklist to match reality
- The AGENTS.md rule-registry checklist names five surfaces. The audit shows nine that matter. Update it, and
  `CONTRIBUTING.md`, to the full list, and point at `RuleRegistryParityTests` as the mechanical check.

---

## 4. Owner decisions required before implementation

**D1 - MCP Top 10 mapping for six MCP-surface rules.**
`GetCorrespondingMcpCode` returns null for 27 rules. For the 21 skill-only rules that is correct, since the MCP Top 10
describes MCP servers. Six are MCP-surface rules with no code, and two look like omissions by the project's own logic:

| Rule | Name | Suggested | Rationale |
|---|---|---|---|
| SS-023 | Shadow Tool Injection | MCP03 | its sibling SS-036 (Confusable Identifier) maps to MCP03 as "lookalike shadowing"; this is the same attack |
| SS-026 | Instructional Description | MCP01 | its sibling SS-009 (Excessive Description) maps to MCP01; same channel, same abuse |
| SS-022 | Rug Pull / Schema Mutation | MCP03? | arguable: mutation after approval is a discovery-trust failure |
| SS-025 | Excessive Response Size | MCP05? | arguable: data-handling rather than discovery |
| SS-041 | Server Source Dangerous Sink | ? | new surface in v3.0.0; may warrant MCP08 |
| SS-042 | A2A Agent Card | none? | A2A is not MCP; null may well be correct |

Decide which to fill. The orchestrator recommends SS-023 and SS-026 as clear corrections, and treating the rest as a
deliberate, documented null.

**D2 - the "100% OWASP coverage" claim.**
ASI08, AST09, MCP04 and MCP10 are matched by no rule. Three options:
- **(a)** Fill them with new or remapped rules, and keep the claim. Most work, strongest claim.
- **(b)** Declare them out of scope for a static first-pass scanner, document why per category, and restate the claim
  as coverage of the categories a static scanner can assess. **Recommended**, and honest.
- **(c)** Drop the coverage claim from the website and state rule counts only.

This is a marketing claim to a defence and government audience, so it is the owner's call, not the orchestrator's.
Whichever is chosen, the website brief must be corrected: it currently lists the claim as "unchanged, still accurate",
which the audit disproves.

---

## 5. Acceptance

1. `dotnet build -c Release` 0 warnings; `dotnet test -c Release --no-build` all green (1,424 + new).
2. `--list-rules` and `--help` both enumerate the same 47 rule ids.
3. `RuleRegistryParityTests` passes, and is demonstrated to fail when any single surface entry is removed.
4. No occurrence of "22 new rules" or "Twenty-two new rules" remains in the repository.
5. README tables, `docs/owasp-ast-mapping.md` and `INSTALLATION_AND_USAGE.md` each contain all 47 rule ids.
6. D2's outcome is reflected in the repo and the corrected wording handed to the website session.

## 6. Out of scope

Website edits (separate repo; the brief covers them). Markdig #60, held until 2026-10-04. Rubric option C.
No rule's detection behaviour, severity or default changes in this work: it is registry, documentation and test only.

## 7. Working-tree note

At the time of writing, the tree holds two items from the peer session: an uncommitted addendum in
`_docs/ai/HANDOVER.md` dated 2026-09-27, and the untracked `RuleCatalogueTests.cs`. Both should be folded into this
work rather than committed separately, so the branch carries one coherent change.

---

## 8. Rulings (owner instruction "fix", 2026-09-27)

The owner approved implementation without separately answering D1 and D2, so the orchestrator's recommendations
stand and are recorded here. Neither publishes anything: the website wording remains the owner's to approve.

**D1 resolved.** Add two MCP mappings that are corrections by the project's own established logic, and document the
rest as deliberate nulls:
- `SS-023` -> `MCP03` (shadowing, identical rationale to SS-036 which already maps to MCP03)
- `SS-026` -> `MCP01` (description-channel abuse, identical rationale to SS-009 which already maps to MCP01)
- `SS-022`, `SS-025`, `SS-041`, `SS-042` stay null, each with a one-line comment giving the reason. SS-042 in
  particular is A2A, not MCP, so a null is correct rather than merely unfilled.

**D2 resolved: option (b).** The four unmatched categories are out of scope for a static first-pass scanner, and
that is defensible on the category definitions themselves:

| Category | Definition | Why no rule matches |
|---|---|---|
| ASI08 | Cascading Failures - single agent fault propagating via automation | Runtime propagation across a live agent fleet. Not observable from configuration or source. |
| AST09 | No Governance - no change-management, ownership or review process | An organisational property, not a property of the artefact. **Candidate exception below.** |
| MCP04 | Tool Argument Injection - manipulated parameters enabling unintended operations | Runtime parameter manipulation. A static scan sees declared schemas, not calls. |
| MCP10 | Logging Failures - insufficient audit logging of MCP operations | Server-side operational property, not visible to a client that enumerates a server. |

**Candidate exception, flagged for the owner rather than taken.** `SS-024` (Skill Not Signed) and `SS-034` (Skill
Integrity Mismatch) are arguably direct evidence of AST09, since an unsigned skill with no integrity artefact is
the absence of change-management made visible. Mapping `SS-024` to AST09 would close that gap honestly and take
AST coverage to 10/10. The orchestrator has **not** made this change, because adding an OWASP mapping is a
governance claim about the product and the owner may want to make it deliberately. Raise it at the next review.

**Superseded 2026-09-27 by `_docs/ai/specs/owasp-full-coverage.md`.** That spec re-examined the four categories
below and found the scanner already performs each detection; only the mapping was missing. ASI08, AST09, MCP04 and
MCP10 are now claimed (SS-010, SS-024, SS-041 and SS-INFO-007 respectively - see that spec's section 1 table and
`docs/owasp-ast-mapping.md`'s coverage statement). A fifth gap, AST10 (Cross-Platform Reuse), was found during that
work and remains a documented exception because it cannot be closed by remapping.

**Resulting form of words for the website**, replacing the "100% coverage across three OWASP frameworks" claim:

> Every finding maps to the OWASP Agentic AI Top 10, the OWASP Agentic Skills Top 10 and the OWASP MCP Top 10. The
> scanner claims every category in the Agentic AI and MCP frameworks, and nine of ten in Agentic Skills. The
> remaining category, Cross-Platform Reuse, is named in the rule mapping documentation with the reason it is not yet
> covered.

This wording is supplied for the owner's approval. It is not published by this work.
