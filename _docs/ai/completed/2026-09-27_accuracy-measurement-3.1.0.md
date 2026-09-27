# Accuracy measurement for 3.1.0

**Date:** 2026-09-27. **Build:** `main` @ `11da7f8` (49 rules, 1,831 tests, 0 warnings).
**Purpose:** the owner asked how accurate the tool is now. Everything below was measured on this build, not
estimated or carried forward from an earlier run.

## 1. Detection and false positives, labelled adversarial corpus

`jhkchan/ast10-agent-skills` @ `58c2768`, Apache-2.0, 33 deliberately vulnerable fixtures against 33 matched benign
controls built on the same themes. Informational findings excluded; **SS-037 excluded**, because the corpus is
near-identical twins by design so description overlap is the fixture structure, not a fault.

| | 2026-09-27 (before this week's work) | Now |
|---|---|---|
| Vulnerable detected | 19 / 33 (57%) | **24 / 33 (72%)** |
| Controls firing | 11 / 33 (33%) | **9 / 33 (27%)** |

Per category now: AST04 5/5, AST10 3/3, AST01 6/8, AST08 3/4, AST03 2/3, AST05 2/3, AST06 2/3, AST02 1/4.

**AST02 at 1 of 4 is the weakest area and the natural next target.** Its themes are hook commands on session start,
control-plane environment override, folder-open tasks and MCP server spawn: config-time execution paths rather than
content, which the skill rules were not built for.

Remaining false-positive drivers: SS-014 x3, SS-016 x3, SS-011 x2, SS-038, SS-012, SS-035, SS-015 x1 each. Every one
is a rule firing on the presence of a dangerous capability rather than its misuse. The pairs are constructed so both
twins exercise the capability and only one abuses it, which is close to the limit of static analysis and correct
behaviour for a tool whose own scope block calls it a first-pass authoring aid. **Not recommended for remediation.**

**SS-043 fires on zero controls**, and SS-017 no longer appears in this list at all after #93.

## 2. False positives on clean real-world skills

| Corpus | Result |
|---|---|
| Anthropic public skills, 19 | **D / 29**, 38 findings: 23 informational, 10 medium, 4 high, 1 low |
| Own vendored fixtures, 7 | **A / 97**, 8 findings |

All four High findings on the Anthropic corpus are genuine: `subprocess.run(cmd)` and `Popen` building a command
dynamically at runtime in `docx`, `skill-creator` and `webapp-testing`. **Zero false-positive classes remain** on
that corpus; the grade is driven by those four genuine findings plus unsigned-skill informationals.

## 3. Live MCP and A2A matrix

Fourteen targets, run live on this build against the v3.0.2 recorded baselines.

**Thirteen of fourteen unchanged.** The one change is an improvement: `context7` moved C/55 to **C/65** because its
SS-001 tool-poisoning High no longer fires, while its SS-026 instructional-description findings remain. The same
text is now attributed to the rule that describes it rather than double-flagged as poisoning, which is the 3.0.1
pattern shaping working as intended.

## 4. What this does and does not say

It says the tool detects roughly three quarters of a purpose-built adversarial set, produces no false-positive
classes on real-world clean skills, and is stable across a live server matrix.

It does not say the tool is 72% accurate in general. One third-party corpus encodes one author's judgement of what
counts as vulnerable and what counts as benign, its controls are adversarially close to its positives, and 33 pairs
is a small sample. A second independent corpus, ideally Jon's, would materially strengthen the claim.

## 5. Regression found and fixed during this run

Re-running the benchmark surfaced SS-017 as the top false-positive driver with five hits, absent before #92. That
branch derived the risk-tier floor from the *presence* of a declared permission rather than its *breadth*, so a
single enumerated host was penalised like a wildcard, and it contradicted the same branch's SS-012 change which
*rewards* the identical declaration. Fixed in #93 with a consistency test holding the two rules in agreement.

Measuring before claiming is what caught it. The number being quoted beforehand, 57%, was three merges stale.
