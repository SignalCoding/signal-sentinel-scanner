# <Product name>: Phase <n> Sign-Off

<!-- The sign-off artefact for P<n>-EXIT-C1. Sections 3, 4 and 7 are generated from
`_docs/ai/verify/verify-results.json`, `_docs/ai/specs/ADDENDA.md` and the register's open items;
do not write them by hand. The customer signs with every BLOCKED edge, known gap and open item
visible. The scope is every task group under the spec, never a range. Produce the customer .docx
from this file; this file stays the canon. -->

| | |
|---|---|
| Product | <Product name> (<Customer Ltd>) |
| Spec | `_docs/ai/specs/<product>-phase-<n>.spec.md` plus addenda A1 to A<k> (`_docs/ai/specs/ADDENDA.md`) |
| Baseline | Requirements Register v<x.y>, Proposal v<x.y>, Clarifications Addendum <n>, all signed |
| Supplier | <Supplier Ltd> |
| Prepared | <date>; revised <date> after <the pre-signature passes in Section 8> |
| Status | DRAFT until both signatures in Section 9 |

## 1. Completion summary

- <k> task groups under the spec, each closed by a fresh-context evaluator verdict of PASS.
- Contract state: <n> PASS, <n> BLOCKED with recorded dispositions (Section 4), <n> FAIL (this
  sign-off criterion only).
- Independent alignment review of the whole application against the spec on <date>: <aligned /
  partial / drift counts>; non-goal violations: <0>; supersessions followed: <all>.
- Automated tests green: <count>; vulnerable dependencies: <0>; analyser suppressions: <0>.
- Security: STRIDE review per task group; no unremediated Critical or High findings; live headers
  and TLS evidenced on the hosted environment.

## 2. Scope delivered

| Area | Task group(s) | Register rows |
|---|---|---|
| <...> | TG-<nn> | R-XXX-1 to R-XXX-n |
| Delivered beyond the signed baseline (by addendum) | TG-<nn> | A<k> |

## 3. Task-group completion register (generated)

| TG | Title | Criteria | Evaluator verdict |
|---|---|---|---|
| TG-<nn> | <...> | <n> PASS, <n> BLOCKED | PASS (<date>) |

## 4. Deferred edges: the BLOCKED criteria (generated)

Every BLOCKED item waits on an external dependency or a governance event named in its
disposition; none is undelivered logic. Dispositions state current facts as at this revision.

| Criterion | Gate | Waits on | Owner | Current position |
|---|---|---|---|---|
| <P<n>-XXX-Cn-EXTERNAL> | EXTERNAL-SERVICE | O<j> | <customer name> | <...> |

## 5. Quality and security posture

<Tests by suite with the evidence file; supply-chain state; security reviews per task group and
per addendum; the crown-jewel controls and who confirmed them; live posture and any residual.>

## 6. Known gaps carried into this sign-off

<!-- From the alignment review and the record audit (Section 8). The customer signs with these
visible. Each is a scoped follow-up, none a wrong-direction build. -->

- <criterion>: <what is thinner than specified>, <follow-up and where it is tracked>.

## 7. Open items at sign-off (generated from the register)

| ID | Item | Owner | Blocks | Position |
|---|---|---|---|---|
| O<j> | <...> | <...> | <criteria> | <open / met on <date>> |

## 8. Pre-signature passes

| Pass | Date | Result | Record |
|---|---|---|---|
| Alignment review of the whole application against the spec by fresh-context readers | | | `_docs/ai/reviews/spec-alignment-<date>/` |
| Record audit: every PASS matches code that exists and evidence captured against the current tree | | | Addendum A<k> |
| User guide written from the shipped product; every "does not work as you would expect" sentence became a defect or an addendum | | | Addendum A<k> |

## 9. Governance conditions

- Register and clarifications signed on <date>, or the owner's proceed-at-risk instruction recorded
  on <date> (`_docs/ai/decision-log.md`).
- Statements the customer asked for: <e.g. the product is commercially inert until the payment
  provider is adopted; what shipped beyond the baseline and why>.
- Phase <n+1> entry: spec authored from a requirements walkthrough before any build (P<n>-EXIT-C2).

## 10. Signature

By signing, the parties confirm Phase <n> is delivered per the spec and its addenda, subject to
the deferred edges in Section 4, the known gaps in Section 6 and the open items in Section 7.

| Party | Name | Role | Signature | Date |
|---|---|---|---|---|
| <Customer Ltd> | | | | |
| <Supplier Ltd> | | | | |

_Signature is a human act performed outside the repository. P<n>-EXIT-C1 moves to PASS on the
signed copy as evidence, never before._
