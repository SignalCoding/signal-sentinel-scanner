# <Product name>: Proposal for <Customer Ltd>

<!-- Two parts. Part 1 is for the people who decide and sign: what they get, when, for how much,
and what they must provide. Part 2 is for the people who will own the system: how it is built,
secured and run. Requirements are NOT restated here; every feature line cites its register row
(R-<AREA>-<n>) and the register is the home of the wording. Produce the customer .docx from this
file; this file stays the canon. Rules: spec-kit/README.md. -->

| | |
|---|---|
| Prepared for | <Customer Ltd>, <name, role> |
| Prepared by | <Supplier Ltd>, <name, role> |
| Version | 1.0 |
| Date | <YYYY-MM-DD> |
| Status | Draft / Issued / Signed <date> |
| Reads with | Requirements Register v<x.y> (the signed list of requirements) |

## Version history

| Version | Date | Change | Author |
|---|---|---|---|
| 1.0 | <date> | First issue | |

# Part 1: the engagement

## 1. Summary

<!-- Five to eight sentences a decision-maker can read alone: the problem, what the first phase
delivers for whom, when, the price shape, and the one or two things the customer must provide
for the plan to hold. -->

## 2. What you asked for, and what we propose

<!-- One row per question in the customer's brief, in their order. Answer each in one or two
sentences and point at the register rows that carry the detail. This is where the consultation
record (briefing document, meeting notes, scoping documents) is answered rather than repeated. -->

| Your question | Our answer | Register rows |
|---|---|---|
| <e.g. What is feasible at MVP and what comes later?> | <...> | Section 3 and the register's Phase column |
| <e.g. Can all the sponsorship tiers be delivered as defined?> | <...> | R-MKT-1 to R-MKT-5 |
| <e.g. What AI capability is realistic, and what will it never do without consent?> | <...> | R-SGE-1 to R-SGE-4; Won't rows R-SGE-7, R-SGE-8 |
| <e.g. How will security and permissions be managed?> | <...> | Part 2, Sections 10 and 11 |
| <e.g. Who owns the IP?> | <...> | Section 9 |

## 3. Scope by phase

<!-- Will / Should / Won't per phase, by area, citing register rows. Won't rows are listed so
nobody assumes them. -->

### Phase 1: <name>

| Area | Will (register rows) | Should | Won't in this phase |
|---|---|---|---|
| <Area> | R-<XXX>-1, -2, -5 | R-<XXX>-3 | R-<XXX>-4 (Phase 2) |

### Phase 2: <name>

| Area | Will | Should | Won't |
|---|---|---|---|
| | | | |

### Not in this engagement

<Register Won't rows with no phase, one line each with the reason: regulated activity needing a
separate review, separately funded, out of the problem the customer brought.>

## 4. How each phase is accepted

<!-- The completion contract in customer language: how a requirement becomes "done", what the
customer sees, and what sign-off means. -->

1. Every register row becomes one or more acceptance criteria with a permanent ID in the phase
   spec. Each criterion starts as FAIL and moves to PASS only on evidence of the class the register
   names for it (a test run, a captured request, a screenshot, a capture from the hosted system).
2. A criterion that depends on something outside the build (an account, sample data, the hosted
   environment) is split into a local half and a gated half; the gated half shows as BLOCKED with
   the open item it waits on, so nothing waits silently.
3. Every task group is judged by an independent, read-only evaluator that has not seen the build,
   and no claim of completion is made while any criterion is FAIL.
4. Phase sign-off is a document generated from the contract, listing every criterion, every
   BLOCKED edge with its owner, every known gap and every open item. The customer signs with all
   of it visible.

## 5. Deliverables

| Deliverable | Phase | Form |
|---|---|---|
| Hosted application (UAT then Live) | 1 | URLs, with the access described in Section 6 |
| Source code repository | 1 | Repository under the customer's ownership (Section 9) |
| Requirements Register, proposal, clarifications addendum (signed) | 1 | Signed PDF and the repository copies |
| Phase spec, completion contract and evidence | 1 | In the repository: `_docs/ai/specs/`, `_docs/ai/verify/` |
| Phase sign-off document | 1 | Signed PDF |
| User guide written from the shipped product | 1 | Document |
| Phase 2 spec from a requirements walkthrough | before Phase 2 | Document |

## 6. UAT and Live

| | UAT | Live |
|---|---|---|
| Purpose | Customer preview and testing; feedback captured in the product | Real customers and real data |
| Data | Test or anonymised only; cleared on request | Opened only after Phase 1 sign-off and the customer's written cutover request; contains no UAT data |
| Deployment | Automatic on every merge to the main branch | Manually approved release |
| Banner | Persistent "UAT" marking on every screen | none |

## 7. Release cadence

<!-- State the figures here (they are transcribed into the repository's release-management
document) rather than "per our usual practice": a reviewer with only the repository must be able
to read them. -->

| Stage | Cadence | Approval |
|---|---|---|
| UAT releases | <e.g. on every merge; at least weekly during build> | automatic |
| Live releases | <e.g. fortnightly during Phase 1, then monthly> | customer-approved |
| Hotfixes | <e.g. within one working day of confirmation> | supplier, customer informed |

## 8. Timescales and what we need from you

| Milestone | Target | Depends on |
|---|---|---|
| Register, proposal and clarifications signed | <date> | both parties |
| Build start | <date> | signatures above; open items O<n>, O<n> |
| UAT available | <date> | hosting account (O<n>) |
| Phase 1 sign-off | <date> | all open items in the register's Section 4 |

Open items and owners: the Requirements Register, Section 4. Each is a lead-time item, not
coding, and the dates above assume the "Needed by" dates there are met.

## 9. Commercial terms

<!-- Price shape (fixed per phase, or time and materials with a cap), payment milestones, what is
included in support, IP and source ownership, third-party costs the customer pays directly
(hosting, AI services, payment provider fees), and what a change of scope costs. -->

| Item | Terms |
|---|---|
| Phase 1 price | |
| Payment milestones | |
| Phase 2 | estimated at Phase 2 scoping, not committed here |
| Hosting and third-party services | paid by the customer directly on accounts the customer owns |
| Intellectual property | All code, design and architecture produced for this engagement are owned by <Customer Ltd> on payment; the supplier retains its pre-existing tooling and libraries, listed in Section 13 |
| Source code | Repository under the customer's ownership from day one; third-party dependencies disclosed in the repository manifest |
| Change of scope | By numbered addendum, priced before it starts |

# Part 2: the system

## 10. System elements

<!-- One table of the moving parts, each with its home. The stack rows cite the register's FND
rows so a change is visible. -->

| Element | Choice | Register row |
|---|---|---|
| Application framework | <...> | R-FND-1 |
| Hosting and region | <...>, fallback <...> | R-FND-1 |
| Data store | <...> | R-FND-2 |
| Identity | <...> | R-IDN-1 |
| File storage | <...> | |
| AI services | <...>, behind a single input-sanitising boundary | R-SGE-n |
| Payments | <...> | R-BIL-n |
| Email | <...> | R-REM-n |
| Edge / CDN | <...> | R-SEC-n |

## 11. Roles and access

| Role | Who | Can | Cannot |
|---|---|---|---|
| <System Administrator> | supplier staff | | |
| <Owner> | customer | | |
| <Administrator> | customer staff | | |
| <User> | customer staff | | |
| <Feedback User> | UAT testers | | |

## 12. Security and compliance commitments

<!-- These rows are transcribed into the project's `_docs/ai/configuration.md` at bootstrap,
row for row. Pick the level, name the reason. -->

| Gate | Selection | Why |
|---|---|---|
| Security posture | PUBLIC / INTERNAL / RESTRICTED / CONFIDENTIAL | <data classes handled> |
| AI governance | BASIC / ENHANCED / STRICT | <how AI-generated code is marked and reviewed> |
| Deployment | <platform standard> | |
| Compliance | <UK GDPR; OWASP Top 10; Cyber Essentials; sector rules> | |
| Team experience | <level> | |

Standards applied: <security headers and TLS grade evidenced at deployment; dependency cooldown;
secrets never in the repository; audit log of every change; data residency; penetration test
timing>.

## 13. Tooling and assurance

<The supplier's delivery method in one paragraph: specification first, failing tests before code,
evidence before claims, independent evaluation, every AI-assisted change tagged and reviewed. The
pre-existing tooling the supplier retains (Section 9) is named here.>

## 14. Terms and conditions

<Reference to the supplier's standard terms, or the terms themselves.>

## 15. Signature

| Party | Name | Role | Signature | Date |
|---|---|---|---|---|
| <Customer Ltd> | | | | |
| <Supplier Ltd> | | | | |
