# Spec addenda register

The single index of every change to an approved spec's criteria. Numbers are allocated here and
only here, by `scripts/new-addendum.sh` (it appends the row and creates the addendum file from
`spec-addendum.template.md`); a number is never reused and a row is never deleted. A withdrawn
addendum keeps its row with status `withdrawn by A<n>`. Every row names the criteria it touches
and where the human authorisation is recorded; `scripts/verify-gate.sh` prints
`[UNREGISTERED-CRITERION]` for any contract criterion named in no spec or addendum file.

| ID | Date | Subject | Criteria touched | Authorised by | File |
|---|---|---|---|---|---|
