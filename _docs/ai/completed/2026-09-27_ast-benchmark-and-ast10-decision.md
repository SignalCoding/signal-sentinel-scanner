# AST benchmark against a third-party labelled corpus, and the AST09/AST10 decisions

**Date:** 2026-09-27. **Operator:** Claude Code (unattended, standing authority).
**Build under test:** `main` @ `de4f140`, v3.1.0-pending, 48 rules, 1,782 tests.
**Purpose:** the owner asked whether AST10 could be closed to reach full OWASP coverage. Rather than build the rule
specified in `ss-043-cross-platform-reuse.md`, this record measures first. The measurement changed the answer.

---

## 1. Corpus provenance

`jhkchan/ast10-agent-skills` @ `58c2768` (2026-08-27). Apache-2.0. Self-described as an "unofficial, independent
community implementation of the OWASP Agentic Skills Top 10 as eleven installable, eval-backed detector skills",
explicitly not an OWASP project. One star at time of use.

**Handled as data, never installed.** The repository is itself a collection of agent skills, which is the exact
threat class this scanner assesses, so it was cloned to a scratch directory and read statically. Nothing from it was
executed, and nothing has been committed into this repository. Under the project's third-party doctrine it would
need a provenance review before any of it were adopted as a fixture.

**Its taxonomy matches ours exactly**, which resolves a concern raised during the harvest: AST08 Poor Scanning,
AST09 No Governance, AST10 Cross-Platform Reuse. The category definitions are not in dispute.

Structure: 78 `SKILL.md` fixtures in matched pairs, `V*` deliberately vulnerable and `C*` a benign counterpart on
the same theme, across AST01-AST06, AST08 and AST10. The authors ship no fixtures for AST07 or AST09.

---

## 2. Benchmark result

Scanned per category with `--skills <dir> --offline`. Informational findings excluded.

| | Count | Result |
|---|---|---|
| Vulnerable fixtures detected | 19 / 33 | **57%** |
| Control fixtures that fired | 11 / 33 | **33%** |

### SS-037 excluded, and why
SS-037 (Cross-Skill Description Overlap) fired 34 times, more than every other rule combined, and its inclusion
would have produced a headline false-positive rate of 63%. That is an artefact of the corpus, not a fault: the
fixtures are deliberately near-identical twins, so overlapping descriptions are the design. Reporting the unadjusted
figure would have been alarming and wrong. SS-037 behaved correctly on input it was never meant to meet.

### The false positives share one shape
Every critical finding on a benign fixture is a rule firing on the presence of a dangerous capability rather than
its misuse: `requests.post`, `curl -fsSL https://`, `.aws/credentials`, an autostart entry. The V/C pairs are
constructed so both twins exercise the capability and only one abuses it, which is close to the limit of static
analysis. This is arguably correct behaviour for a tool whose own scope block calls it a first-pass authoring aid
rather than an audit tool, and it is **not** recommended for remediation.

### The detection gap is the actionable half
Misses concentrate in **AST04 Insecure Metadata: 1 of 5 detected.** YAML, JSON and TOML frontmatter injection,
metadata injection, permission understating and risk-tier spoofing all pass undetected. AST03 is also weak at 1 of 3.
This is a real hole and a better use of effort than anything else in this thread.

---

## 3. Decision: do not build SS-043

`ss-043-cross-platform-reuse.md` is superseded and should not be implemented as written. Three reasons:

1. **The specified rationale does not match reality.** The spec's premise was a safety declaration failing open on a
   foreign host. A harvest of 309 public `SKILL.md` files from 203 repositories found the shape in about eleven
   files across six projects, and inspection showed the genuine cases were something else: a skill running on one
   host that *writes another host's configuration*, which is contamination rather than a void declaration.
2. **A third reading exists.** This corpus implements AST10 as "an encoded payload judged after decoding, at the
   content layer". That is neither the spec's reading nor the harvest's. A category with three defensible readings
   cannot be "covered" in any meaningful sense.
3. **We already pass their version.** Sentinel detected 3 of 3 AST10 vulnerable fixtures with existing obfuscation
   rules and no new code.

The harvest did confirm one design requirement empirically: stripping code fences before counting host markers
reduced marker hits from 182 files to 111, a 39% reduction. Any future rule in this space needs that guard.

---

## 4. Decision required: revert the SS-024 to AST09 mapping

`#87` mapped SS-024 (Skill Not Signed) to AST09 (No Governance) on the orchestrator's recommendation, taking AST
coverage from 8/10 to 9/10. That mapping is now in doubt.

The independent implementation states of AST09: **"No check ships, and none can, every scenario lives in an
organisation, not a package."** They shipped detectors for eight categories and deliberately declined this one.

**The orchestrator now agrees with them.** An unsigned skill with no integrity artefact evidences one missing
control. It does not evidence the absence of change-management, ownership or review, which are properties of the
organisation that produced the skill and are not observable from the artefact. A well-governed team that does not
sign its skills is indistinguishable from an ungoverned one at the package level.

Claiming AST09 on that basis is the same class of over-claim this project spent 3.0.1, 3.0.2 and #86 removing.

**Recommendation: revert it.** Consequences if accepted:
- AST coverage returns to 8/10; ASI stays 10/10 and MCP stays 10/10.
- The coverage guard gains a second documented exception alongside AST10, both named and printed.
- `docs/owasp-ast-mapping.md` and the wording supplied for the website change again.

**Counter-argument, for completeness:** OWASP's own category may be broader than one implementer's reading, and
SS-024 with SS-034 are genuinely governance-adjacent. Keeping the mapping is defensible. It is the owner's call
because it is a public claim about the product.

---

## 5. Next actions

| Item | Owner | Note |
|---|---|---|
| Decide the AST09 mapping | owner | section 4 |
| AST04 metadata injection detection | engineering | 1 of 5; the real gap this benchmark found |
| Adopt this corpus as a benchmark | owner | Apache-2.0 and licence-clean, but needs a provenance review first, and its controls encode one author's judgement |
| SS-043 | closed | spec superseded, do not implement |

Artefacts from this work are in the session scratchpad and are not committed: the 309-file public harvest, the
cloned corpus, and the per-category scan output.
