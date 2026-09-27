# Spec: close the four unmatched OWASP categories

**Status:** approved (owner: "yes", 2026-09-27, answering the assessment that all four gaps are closable honestly).
**Branch (proposed):** `feat/owasp-full-coverage` from `main` @ `457567e`.
**Supersedes:** the "out-of-scope categories" section added to `docs/owasp-ast-mapping.md` by `rule-registry-parity.md`,
and decision D2 option (b) in that spec. This spec takes option (a) instead, because the audit below shows the
detections already exist.

---

## 1. Why, and why this is not a fudge

`rule-registry-parity.md` established that ASI08, AST09, MCP04 and MCP10 are matched by no rule, so coverage is
9/10, 9/10 and 8/10 rather than the "100%" the website claims. That spec documented them as out of scope.

Re-examining each against the code shows that conclusion was too pessimistic. In all four cases **the scanner
already performs the detection**; only the mapping is absent. Three are pure remapping of shipped behaviour. The
fourth needs one small new informational rule over data the scanner already parses.

The point of this work is not to reach a round number. If any of the four had required a stretch, the correct
outcome would be to keep the claim at 9/10 and say so publicly. None does.

| Category | Definition | Existing detection | Change |
|---|---|---|---|
| ASI08 Cascading Failures | single agent fault propagating via automation | SS-010 Cross-Server Attack Path Analysis, which already emits attack paths carrying several OWASP codes | additive |
| AST09 No Governance | no change-management, ownership or review process | SS-024 Skill Not Signed and SS-034 Integrity Mismatch | additive |
| MCP04 Tool Argument Injection | manipulated parameters enabling unintended operations | SS-041 Server Source Dangerous Sink | fills a null |
| MCP10 Logging Failures | insufficient audit logging of MCP operations | `CapabilitySurfaceRule` already parses `caps.Logging` | one new informational rule |

---

## 2. Requirements

### C1 - ASI08 via SS-010 attack paths
- `CrossServerAttackPathRule` emits attack paths with `OwaspCodes = [ASI02, ASI09]` (`CrossServerAttackPathRule.cs:97`).
  Add `ASI08`. An attack path from one server to another is a fault propagating via automation, which is the
  category definition; mapping it to Excessive Permissions alone was always the weaker reading.
- The rule's own single-valued `OwaspCode` stays `ASI02`. This is additive: no existing code is removed, and ASI02
  remains claimed by five other rules regardless.

### C2 - AST09 via SS-024 **[owner-confirmed]**
- `SkillIntegrityRule` (SS-024) currently declares `AstCodes` of AST02, AST07. Add `AST09`.
- Rationale to record in the code comment: a skill shipping with no signature or integrity artefact is the absence
  of change-management and review made observable, which is the category.
- `AstCodes` is already a list, so this is additive. Do not alter SS-024's severity, which is `Info` as of v3.0.2,
  nor its behaviour under `--policy strict`, which pins it to High.

### C3 - MCP04 via SS-041
- Add `"SS-041" => MCP04` to `GetCorrespondingMcpCode`, with a comment giving the rationale: a dangerous sink in
  server source reachable from a tool parameter is tool argument injection.
- SS-041 currently returns null, so this fills a gap rather than moving an existing mapping.

### C4 - MCP10 via a new rule, SS-INFO-007
- New informational rule **SS-INFO-007, "MCP Logging Capability Absent"**. Fires once per **connected** server whose
  `Capabilities.Logging` is null. Severity `Info`. OWASP `ASI10`; MCP code `MCP10`; AST code `AST08`, matching the
  other transport/protocol informational rules. Follow `CapabilitySurfaceRule` for structure and skip conditions.
- Finding text: state that the server does not advertise the MCP `logging` capability, so its operations cannot be
  audited through the protocol, and recommend raising it with the server operator. Do not imply the server keeps no
  logs of its own; the scanner cannot know that, and the finding must not overclaim.
- Skip when the server did not connect, matching every other capability-derived rule.
- **Noise check, done before specifying this:** of four live public servers sampled on 2026-09-27, Microsoft Learn
  and Chainflip advertise `logging`; DeepWiki and Hugging Face do not. A roughly even split means the finding
  discriminates rather than firing on everything. At `Info` it contributes zero to the score.
- `SS-027` remains intentionally unallocated. `SS-INFO-007` is the next free informational id.

### C5 - Coverage guard
- Extend `RuleRegistryParityTests`, or add a sibling, asserting that **every** ASI, AST and MCP category constant is
  claimed by at least one rule. Source the category lists from `OwaspMapping.cs` and `OwaspMcpMapping.cs` rather
  than hard-coding them, so a newly defined category fails the test until a rule claims it.
- Failure message must name the unclaimed category. This is the guard that keeps the restored claim true.

### C6 - Documentation and the rule count
- **The rule count changes from 47 to 48** (41 detection + 7 informational). This ripples to every surface the
  parity test checks, plus `SECURITY.md` and `--help`. The parity test added in #86 will fail until all of them are
  updated, which is the guard working as intended.
- Replace the "Out-of-scope OWASP categories" section in `docs/owasp-ast-mapping.md` with a coverage statement
  recording that all three frameworks are fully claimed, and keep a short note of which rule claims each of the four
  categories this spec closes, so the reasoning survives.
- Revert the hedged website wording in `rule-registry-parity.md` section 8. The replacement is a plain statement:
  every finding maps to the three OWASP frameworks, and every category in all three is claimed by at least one rule.

---

## 3. Acceptance

1. `dotnet build -c Release` 0 warnings; `dotnet test -c Release --no-build` all green.
2. The coverage guard passes, and is demonstrated to fail if any one of the four new mappings is removed.
3. `--list-rules` and `--help` both report 48 distinct rule ids; parity holds across all nine surfaces.
4. A live scan of a server without the logging capability (DeepWiki or Hugging Face) emits exactly one SS-INFO-007
   at Info; a scan of one with it (Microsoft Learn or Chainflip) emits none.
5. Grades and scores for the smoke matrix are unchanged, since Info contributes nothing to the score. Spot-check
   learn, huggingface, chainflip and spacemolt against the recorded baselines.
6. No existing rule's severity, confidence, detection logic or default changes.

## 4. Out of scope

The SS-020 dual registration (`OAuthComplianceRule` and `MissingAuthProbeRule` share an id), noted in #86 and still
open. Markdig #60, held to 2026-10-04. The website edit itself, which is the owner's to approve and lives in the
other repository; this spec only supplies the corrected wording.

---

## 5. Amendment (2026-09-27, after the red phase): a fifth gap, and the limit of this work

The C5 guard, built by reflection over the category constants exactly as specified, surfaced a gap the orchestrator's
original audit missed: **AST10 "Cross-Platform Reuse" is also unclaimed.** Verified independently by stripping
comments from `RuleAstMapping.cs`: only AST01..AST08 are ever assigned.

The earlier audit reported AST09 as the sole AST gap because its grep matched `AST10` inside a documentation
comment. This is the second time in this work that a comment-polluted grep produced a wrong answer, and it is the
argument for the reflection-based guard over any text search.

**Corrected coverage as at 2026-09-27:** ASI 9/10 (missing ASI08), AST **8/10** (missing AST09 **and AST10**),
MCP 8/10 (missing MCP04, MCP10).

### AST10 is genuinely out of reach for this branch
"Skill mixes incompatible platform semantics unsafely" is not detected by any shipped rule, and unlike the other
four it cannot be closed by a mapping. It would need a new detection designed from scratch. That is feasible in
principle, since the scanner already understands the platform config shapes for Claude, Cursor, Gemini, OpenCode,
GitHub and Factory, so a skill hard-coding one platform's conventions while presenting as neutral, or mixing
several, is a real and observable signal. But it needs its own spec, fixtures and false-positive analysis, which is
exactly the care the previous two specs earned the hard way.

**Decision for this branch: close the four, and record AST10 as a single documented exception.**
- C5's guard gains one explicit, named exception for AST10 carrying the reason above. The failure message must
  print the exception and its justification, so the exception is visible rather than silent, and the guard still
  fails for any *other* category that becomes unclaimed.
- Do not invent a rule to claim AST10 in this branch. Forcing a mapping to reach a round number is the precise
  failure this project spent two releases removing.

### Consequent correction to the public claim
The wording supplied in `rule-registry-parity.md` section 8 and in this spec's C6 must **not** assert blanket
coverage. The accurate statement is:

> Every finding maps to the OWASP Agentic AI Top 10, the OWASP Agentic Skills Top 10 and the OWASP MCP Top 10.
> The scanner claims every category in the Agentic AI and MCP frameworks, and nine of ten in Agentic Skills. The
> remaining category, Cross-Platform Reuse, is named in the rule mapping documentation with the reason it is not
> yet covered.

C6 is amended accordingly: `docs/owasp-ast-mapping.md` states coverage as 10/10 ASI, 9/10 AST, 10/10 MCP, names
AST10 as the open gap, and records cross-platform reuse detection as candidate future work.

### Also found: a wrong comment
`RuleAstMapping.cs:15` reads "corrected in v2.4.1 (G12a) to align AST05 with its real OWASP AST10 definition
(\"Untrusted External Instructions\")". The reference to AST10 is wrong; the v2.5.0 correction aligned **AST05's**
label. The category definitions in `OwaspMapping.cs` are internally consistent and were not affected. Fix the
comment as part of C6.
