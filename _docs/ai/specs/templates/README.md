# Spec kit

The documents a project signs before it is built, in the order they are produced, and the rules
that tie them to the completion contract. One home for each rule; the templates point here.

| Step | Document | Template | Produced by | Signed by |
|---|---|---|---|---|
| 0 | Intake notes (requirement candidates, decisions needed, open items) | none: working notes | `spec-authoring` skill, Step 0 | nobody |
| 1 | Requirements Register | `requirements-register.template.md` | Step 1 | customer and supplier |
| 2 | Proposal | `proposal.template.md` | Step 2 | customer and supplier |
| 3 | Clarifications Addendum (decisions after the proposal, before the build) | `clarifications-addendum.template.md` | Step 3 | customer and supplier |
| 4 | Phase spec (the engineering spec Claude Code builds from) | `phase-spec.template.md` | Step 4 | supplier (approved status) |
| 4 | Completion contract (`_docs/ai/verify/verify-results.json`) | generated | `scripts/spec-to-contract.sh --apply` | nobody: it is operated |
| during | Spec addendum (any change to a criterion after approval) | `spec-addendum.template.md` | `scripts/new-addendum.sh` | the owner named in its authorization block |
| during | Addenda register (`_docs/ai/specs/ADDENDA.md`) | `ADDENDA.template.md` | delivered by bootstrap; rows appended by `new-addendum.sh` | nobody |
| end | Phase sign-off | `phase-signoff.template.md` | Step 6 | customer and supplier |

Feature-level specs inside a phase use `templates/_shared/spec.template.md`; a phase spec is the
contract-level document that owns many task groups.

## Identifiers

- Register rows: `R-<AREA>-<n>` (`R-IDN-3`). AREA is a three or four letter code chosen once per
  functional area and reused by the spec. Never renumbered; a withdrawn row keeps its ID and gains
  a status.
- Criteria: `P<phase>-<AREA>-C<n>` (`P1-IDN-C3`). Sub-clause split: a letter suffix (`P1-IDN-C3a`).
  Externally gated half: a gate suffix naming what the build machine lacks
  (`P1-IDN-C3-EXTERNAL`, `-DEPLOY`, `-AZURE`, `-STRIPE`, `-LABELLED-DATA`), opened BLOCKED with the
  open item in its disposition. Every criterion cites the register rows it realises
  (`[R-IDN-3]`); a criterion citing no row is unregistered and the gate says so.
- Task groups: `TG-<nn>` with an optional letter (`TG-10B`); `new-task-group.sh` refuses a reuse.
- Decisions: `D<n>` in the clarifications addendum and the spec's decision log. Open items: `O<n>`.
  Addenda: `A<n>`, allocated only by `scripts/new-addendum.sh` from `ADDENDA.md`.

## Rules the templates enforce

1. **The register is self-contained.** Every row carries the requirement's own words. A spec never
   points at a document outside the repository; the signed baseline (proposal, register,
   clarifications) is placed in `_docs/ai/specs/baseline/` at bootstrap.
2. **External need is answered when the criterion is written.** For each criterion: what does the
   build machine need that it does not have (a live service, client data, a deployed environment,
   a third-party account)? Anything at all makes it two criteria from the start, the local half and
   the gated half, with the open item that clears the gate named in both.
3. **Evidence class is fixed when the criterion is written.** test, http, screenshot, live, log
   (`_docs/ai/verify/EVIDENCE-RULES.md` owns what each proves). The register carries it and
   `spec-to-contract.sh` writes it into the contract row.
4. **One task group per functional area, three to eight criteria.** Nine or more splits by
   sub-area. Order by data dependency; hardening throughout; the deployment apparatus as soon as
   anything deploys; sign-off last, scoped to every task group under the spec, never a range.
   Each group carries a risk tier (`[risk: low|medium|high]`, default medium): low is small
   documentation, refactoring or an obvious fix; high is authentication, authorisation, payments,
   migrations, shared infrastructure, destructive operations or a significant architecture
   change. The tier decides the loop shape (delegation-routing) and what the gate requires.
5. **One statement, one home.** The register row is the home of a requirement's current wording;
   the proposal, the spec and the decision log cite it. A stack commitment (framework, hosting,
   render mode, region) is a register row, so a deviation is an addendum, not a surprise.
6. **A change after approval is an addendum first.** Authorization block (who, when, in what
   words) before the change; criteria touched named; the test change in the same change set;
   `set-criterion.sh --addendum` on each affected row. Numbers come from the register file only.
7. **Before signature, three passes that have not seen the build:** an alignment review of the
   whole application against the spec by fresh-context readers; a record audit (does every PASS
   correspond to code that exists and evidence captured against the current tree); the user guide
   written from the shipped product, where every sentence that has to say "this does not work the
   way you would expect" is a defect or an addendum. The sign-off lists open items with owners.
