# Requirements Register: <Product name>

<!-- The signed list of what will be built. Every row is self-contained (its own words, not a
pointer), carries a stable ID that the proposal and the phase spec cite, and names the three
things the build needs to know before it starts: whether it is Will / Should / Won't, what the
build machine lacks to prove it, and what kind of evidence proves it. Rules: spec-kit/README.md.
Produce the customer copy (.docx) from this file; this file stays the canon. -->

| | |
|---|---|
| Customer | <Customer Ltd>, <signatory name and role> |
| Supplier | <Supplier Ltd>, <signatory name and role> |
| Version | 1.0 |
| Date | <YYYY-MM-DD> |
| Status | Draft / Issued for signature / Signed <date> |
| Supersedes | none / Register v<x.y> (changes listed in Section 5) |

## 1. Signature

By signing, both parties agree that Section 3 is the complete list of requirements for the
phases named in Section 2, that "Won't" rows are outside this engagement, and that any later
change to a row is made by a numbered Clarifications Addendum or Spec Addendum signed or
authorised in the same way, never by editing this document.

| Party | Name | Role | Signature | Date |
|---|---|---|---|---|
| <Customer Ltd> | | | | |
| <Supplier Ltd> | | | | |

## 2. Phases and reading guide

| Phase | Scope in one sentence | Target elapsed time | Entry condition |
|---|---|---|---|
| 1 | <what a paying customer can do at the end of Phase 1> | <n> months from start | This register and the proposal signed |
| 2 | <what Phase 2 adds> | re-estimated at Phase 2 scoping | Phase 1 signed off; Phase 2 spec approved |

**Will / Should / Won't.** Will: delivered in the phase named, evidenced and signed off. Should:
delivered in that phase if time allows, otherwise moved to the next phase by addendum, never
silently dropped. Won't: not in this engagement; listed so nobody assumes it.

**External need.** What the supplier's build machine cannot reach and the customer or a third party
must provide before the row can be fully proven: `none`, `service: <name>` (a live API or tenant),
`client data: <what>` (sample documents, seed lists, sign-off of a configuration), `deployed
environment` (the row can only be proven on the hosted system), `account: <who opens it>`. A row
with any external need is built as two criteria: the local half, proven on the build machine, and
the gated half, proven when the need is met. The open item that clears it is in Section 4.

**Evidence class.** What the supplier will show for the row: `test` (an automated test run),
`http` (a request and response capture), `screenshot` (a rendered screen, including the
non-happy path), `live` (a capture from the deployed environment), `log` (background processing).
Several may apply.

## 3. Requirements

<!-- One table per functional area. AREA code: three or four capitals, chosen once, reused by the
spec's criterion IDs. Keep the statement in the customer's language and the acceptance line as the
sentence the customer would read to agree it is done. -->

### 3.1 <Area name> (AREA: <XXX>)

| ID | Requirement | Will / Should / Won't | Phase | External need | Evidence | Acceptance |
|---|---|---|---|---|---|---|
| R-<XXX>-1 | <The system shall ... in the customer's words> | Will | 1 | none | test, screenshot | <Done when ...> |
| R-<XXX>-2 | <...> | Will | 1 | service: <name> (O<n>) | test, live | <Done when ...; the live half when O<n> is met> |
| R-<XXX>-3 | <...> | Should | 1 | none | http | <...> |
| R-<XXX>-4 | <...> | Won't | - | - | - | Not in this engagement |

### 3.2 <Area name> (AREA: <XXX>)

| ID | Requirement | Will / Should / Won't | Phase | External need | Evidence | Acceptance |
|---|---|---|---|---|---|---|
| | | | | | | |

### 3.n Platform and stack commitments (AREA: FND)

<!-- Framework, hosting, data residency, render mode, identity providers, payment provider.
These are rows because a change to any of them is a change the customer should see. -->

| ID | Requirement | Will / Should / Won't | Phase | External need | Evidence | Acceptance |
|---|---|---|---|---|---|---|
| R-FND-1 | The system shall be built on <stack> and hosted on <platform> in <region>, with <fallback region> as the only alternative without a written amendment | Will | 1 | account: <who> (O<n>) | log, live | Provisioning region recorded as evidence |

## 4. Open items

<!-- Everything a row waits on that is not code. Owner, what it blocks, and the date it is needed
by for the phase plan to hold. This table doubles as the kickoff walkthrough agenda. -->

| ID | Item | Owner | Blocks | Needed by |
|---|---|---|---|---|
| O1 | <e.g. labelled sample documents for extraction training> | <customer name> | R-<XXX>-2 (gated half) | <date or "before TG-nn opens"> |
| O2 | <e.g. third-party account opened under the customer's ownership> | <customer name> | R-<YYY>-n | |

## 5. Changes since the previous version

| Register version | Date | Change | Authorised by |
|---|---|---|---|
| 1.0 | <date> | Initial issue | |

## 6. Sign-off status (completed at phase end)

<!-- Filled from the completion contract at sign-off; do not fill by hand before then. -->

| ID | Status | Evidence or disposition |
|---|---|---|
| R-<XXX>-1 | Delivered | P1-<XXX>-C1 PASS |
| R-<XXX>-2 | Delivered (local) / Blocked (gate: O1) | P1-<XXX>-C2 PASS; P1-<XXX>-C2-LABELLED-DATA BLOCKED |
| R-<XXX>-3 | Moved to Phase 2 (Addendum A<n>) | |
