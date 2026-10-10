# Spec Addendum A{{N}}: {{SUBJECT}}

<!-- Created by scripts/new-addendum.sh, which allocated the number and appended the register
row. Fill the authorization block FIRST: an addendum records a human decision, and the decision
comes before the change (a criterion's text or status is never edited and then explained). The
test change travels in the same change set; `scripts/set-criterion.sh <TG> <ID> --addendum
{{DATE}}` is run on every criterion named below. Rules: the spec kit README in the library. -->

## Authorization block

- **Requested by / authorised:** <name>, {{DATE}}, in these words: "<the instruction as given>".
- **Why an addendum:** <what the approved spec said, what is now true or wanted, and why that is a
  change to a criterion rather than an implementation detail. Name the class: new requirement /
  reworded criterion / split into local and gated halves / descoped to a later phase / correction
  of a record that overstated the build / defect in delivered behaviour.>
- **Authorization implications:** <new roles, permissions or endpoints, or "none">.
- **Data implications:** <schema or migration, data moved or deleted, or "none">.
- **Hosting implications:** <render mode, region, services, or "none">.

## Decisions

<!-- One heading per decision. State the decision, then the criteria it creates or changes with
their full new wording. Register rows cited in brackets. -->

### 1. <Decision title> ({{CRITERIA}})

<The decision in two or three sentences, with the evidence that prompted it (a review finding, a
defect seen, an owner instruction).>

- **<P1-XXX-Cn>** [R-XXX-n] {<evidence classes>}: <new or amended EARS text>. (was: "<old text>")
- **<P1-XXX-Cn-GATE>** [R-XXX-n] {live | gate: <TOKEN> | item: O<n>}: <the gated half>.

## Criteria touched

| Criterion | Task group | Change | Status after | Test change (same change set) |
|---|---|---|---|---|
| <P1-XXX-Cn> | TG-<nn> | reworded / added / split / descoped / reopened | FAIL / BLOCKED (<TOKEN>) / unchanged | `<path to test>` red run `<evidence file>` |

## Register effect

| Register row | Effect |
|---|---|
| R-XXX-n | wording stands / amended by this addendum / moved to Phase <n> |

## Out of scope, deliberately

<What this addendum does not change, so nobody reads it as broader than it is.>

## Recorded

- `scripts/set-criterion.sh <TG-nn> <ID> --addendum {{DATE}}` for each criterion above.
- Register row appended to `_docs/ai/specs/ADDENDA.md` by `scripts/new-addendum.sh`.
- Decision logged: `scripts/log-decision.sh "A{{N}}: <one line>"`.
