# <Product name>: Phase <n> Specification

<!-- The engineering spec Claude Code builds from. It is derived from the signed Requirements
Register and Clarifications Addendum, cites them by ID, and is the ONLY source of criteria for
the completion contract: `scripts/spec-to-contract.sh _docs/ai/specs/<this file> --apply` reads
Section 4 and opens every task group and criterion FAIL-first (gated halves BLOCKED).

Machine-read syntax (Section 4 only):
  ### TG-<nn> - <title> [ui] [risk: low|medium|high]   tags optional; ui = UI-behavioural; risk defaults to medium
  - **P<n>-<AREA>-C<k>** [R-<AREA>-<i>, ...] {<evidence classes>}: <EARS text>
  - **P<n>-<AREA>-C<k>-<GATE>** [R-...] {live | gate: <TOKEN> | item: O<j>}: <the gated half>
Evidence classes: test, http, screenshot, live, log. Gate tokens: EXTERNAL-SERVICE, DEPLOY,
LABELLED-DATA, SIGN-OFF, PHASE-<n>-ENTRY. Everything else in this file is prose for people.
After approval a criterion changes only through scripts/new-addendum.sh. -->

| | |
|---|---|
| File | `_docs/ai/specs/<product>-phase-<n>.spec.md` |
| Version | 1.0 |
| Date | <YYYY-MM-DD> |
| Status | draft / approved <date> / in-flight / completed |
| Baseline | Requirements Register v<x.y> (signed <date>), Proposal v<x.y> (signed <date>), Clarifications Addendum <n> (signed <date>); copies in `_docs/ai/specs/baseline/` |
| Verification | Every criterion below carries a stable ID and appears in `_docs/ai/verify/verify-results.json` with a status and evidence (`scripts/verify-gate.sh`); changes after approval only by addendum (`_docs/ai/specs/ADDENDA.md`) |

## 1. Purpose and scope

<One paragraph: what a user can do at the end of this phase, in the register's words. Elapsed
estimate and the entry condition. Where a decision below supersedes register wording, Section 3
says so and the register's amended row is the home.>

## 2. Decision log

<!-- Decisions from the clarifications addendum, by ID, one line each: what was decided, not the
discussion. New decisions during the build go through scripts/log-decision.sh and, when they
change a criterion, through an addendum. -->

| ID | Decision | Register rows |
|---|---|---|
| D<n> | <...> | R-XXX-n |

## 3. Supersessions

<!-- Drift reference for the evaluator: an agent implementing the ORIGINAL wording is off-spec. -->

| Was (register or proposal text) | Now | By |
|---|---|---|
| <original wording> | <amended wording> | D<n> / Addendum <n> |

## 4. Task groups and acceptance criteria

<!-- One task group per functional area, three to eight criteria, ordered by data dependency
(Section 8). Each criterion: one EARS claim, its register rows, its evidence classes. A criterion
whose register row has an external need is two bullets: the local half and the gated half. -->

### TG-<nn> - <Area name>

- **P<n>-<AREA>-C1** [R-<AREA>-1] {test}: When <trigger>, the system shall <response>.
- **P<n>-<AREA>-C2** [R-<AREA>-1] {test, http}: If <condition>, then the system shall reject <input> with <observable result>.
- **P<n>-<AREA>-C3** [R-<AREA>-2] {test, screenshot}: While <state>, the system shall <response>.
- **P<n>-<AREA>-C4** [R-<AREA>-3] {test}: When <trigger>, the system shall <the half provable on the build machine, e.g. through the configured stub transport with real signature verification>.
- **P<n>-<AREA>-C4-EXTERNAL** [R-<AREA>-3] {live | gate: EXTERNAL-SERVICE | item: O<j>}: When <the live service> is configured, the system shall <the half provable only against it>.

### TG-<nn> - <Area name> [ui]

- **P<n>-<AREA>-C1** [R-<AREA>-n] {test, screenshot, live}: When <screen> loads, it shall show <...>.

### TG-<nn> - Identity and access [risk: high]

- **P<n>-IDN-C1** [R-IDN-1] {test, http}: When a user signs in, ... (high risk: the loop adds finding verification and a security review before PASS)

### TG-<nn> - Phase <n> sign-off

- **P<n>-EXIT-C1** [R-EXIT-1] {log}: When every task group under this spec reports complete (all criteria PASS, or BLOCKED with an agreed disposition), the phase sign-off document generated from the contract shall be signed by both parties.
- **P<n>-EXIT-C2** [R-EXIT-2] {log | gate: PHASE-<n+1>-ENTRY | item: O<j>}: Before any Phase <n+1> build starts, the Phase <n+1> spec shall be authored from a requirements walkthrough with the customer.
- **P<n>-EXIT-C3** [R-EXIT-3] {log}: Before the first implementation task group opens, the register and clarifications shall be signed, or the owner's proceed-at-risk instruction shall be recorded with `scripts/log-decision.sh`.

## 5. Non-goals

<!-- Drift reference: an agent producing any of these is off-spec. Every register Won't row for
this phase, one line each, with the decision or phase that parks it. -->

- No <...> (R-XXX-n, Phase 2).
- No <...> (D<n>).

## 6. Open items

<!-- From the register's Section 4, with the criteria they gate. Doubles as the kickoff agenda. -->

| ID | Item | Owner | Blocks | Needed by |
|---|---|---|---|---|
| O<j> | <...> | <...> | P<n>-<AREA>-C4-EXTERNAL | <date or task group> |

## 7. Dependencies and risks

<Lead-time items that are waiting, not coding. Internal risks and their mitigations in order.>

## 8. Build order (non-binding)

<Suggested task-group sequence by data dependency: tenancy and identity first; the entities every
feature reads next; the value loop; features over the established data; hardening throughout
with a pass before UAT; the deployment apparatus as soon as anything deploys; sign-off last. Agents
may parallelise within a task group and never open a group whose upstream data model is unbuilt.>

## Addenda

Changes after approval: `_docs/ai/specs/ADDENDA.md` (register) and the numbered addendum files
beside this one. This section is a pointer; the register is the home.
