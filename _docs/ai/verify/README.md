# Verification Contract

The completion source of truth: scripts write `verify-results.json`, hooks and the gate validate
it, prose is never evidence. Capture craft: `EVIDENCE-RULES.md`. Test categories:
`.claude/rules/testing.md`. Gate sequence: `gate-sequence`. Example: `verify-results.example.json`.

## Contract shape

```json
{ "spec": "<slug>.md",
  "noTaskGroupsExemption": { "gate": "BOOTSTRAP", "note": "<why no spec yet>", "reviewBy": "YYYY-MM-DD" },
  "taskGroups": [ { "id": "TG-01", "title": "<title>", "startedAt": "<ISO-8601>", "ui": true,
    "risk": "medium", "baseCommit": "<sha at open>", "redBaseline": "TG-01.red.testresults.txt",
    "allowTestChange": "<brief reference, when a spec-mandated test change is allowed>", "criteria": [
      { "id": "FEAT-C1", "text": "<EARS>", "status": "FAIL", "evidence": [],
        "evidenceClass": ["test", "http"], "register": ["R-FEAT-1"] },
      { "id": "FEAT-C2", "text": "<EARS>", "status": "PASS", "addendumAt": "YYYY-MM-DD",
        "evidence": ["FEAT-C2.testresults.txt", "FEAT-C2.live.png"] },
      { "id": "FEAT-C3-DEPLOY", "text": "<EARS>", "status": "BLOCKED", "evidence": [], "gate": "DEPLOY",
        "disposition": "<reason; plan; the exact question that unblocks it>" } ] } ] }
```

Optional: `noTaskGroupsExemption`, `ui`, `risk` (low | medium | high, default medium: the loop
shape, see `delegation-routing`), `allowTestChange`, `addendumAt`, `evidenceClass`, `register`.
`redBaseline` is a filename or `{"exempt": "<reason>"}`; `baseCommit` is the evaluator's default
base; `evidenceClass` (test, http, screenshot, live, log) and `register` come from the phase spec
via `spec-to-contract.sh`. A gated part is split off: `<ID>` PASS, `<ID>-<GATE>` BLOCKED.

## Statuses and gate tokens

- `FAIL`, `PASS` and `BLOCKED` are the only statuses; criteria are created FAIL. PASS needs at
  least one evidence file that exists, is non-empty, matches the allowed names and (locally)
  postdates `startedAt`. Enforced by `verify-gate.sh` and the `set-criterion.sh` transaction.
- BLOCKED needs `gate` from `EXTERNAL-SERVICE`, `DEPLOY`, `LABELLED-DATA`, `SIGN-OFF`,
  `PHASE-<n>-ENTRY` and a non-empty `disposition`: the reason, the plan and the exact question
  that unblocks it (`SIGN-OFF` names the owner). BLOCKED never fails the gate; it is counted in
  every summary and listed with `--verbose`. `BOOTSTRAP` is the exemption token only.

## Evidence files

- Allowed names: `<ID>.png`, `<ID>.log`, `<ID>.testresults.txt`, `<ID>.http.txt`,
  `<ID>.uatresults.txt`; a qualifier before the extension is fine (`<ID>-denied.png`); plain
  names inside `evidence/` only; a PASS holds one file of each class in `evidenceClass`
  (`[EVIDENCE-CLASS]`). One run per file: a `*.testresults.txt` is one invocation with one totals
  line, written with `>` never `>>` (`run-evaluator.sh` pre-flight). `CHECK-<name>.*` files are
  written by `check.sh` and cite the declared checks.
- ui groups (`"ui": true`): once any criterion is PASS, one PASS criterion cites a
  `*.uatresults.txt` and one a deployed capture (`<ID>.live.png`, `.live.http.txt`, `.live.log`),
  unless a criterion is BLOCKED on `DEPLOY`. Process logs: `_docs/ai/logs/`.

## Declared checks

`checks.env` declares the commands a close must pass (`TEST="npm test"`, `BUILD`, `LINT`,
`TYPECHECK`, `DEPENDENCY_CHECK`, `BOOT_PROBE=<url>`; a stack default is delivered, never
overwritten). `scripts/check.sh <NAME> | --all | --list` runs one quietly: full output to
`_docs/ai/logs/check-<name>-<stamp>.log`, a summary of two to a few lines on stdout (`PASS: 417
tests (vitest)` or `FAIL: 1 of 5` plus the failing lines and the log path), evidence
`evidence/CHECK-<name>.*`, and `checks-state.json` (commit, time, per-check status). The runner reads
the log; the orchestrator reads the summary.

## Red baseline and test integrity

- Each task group records `redBaseline`: `<TG>.red.testresults.txt`, the failing run captured
  BEFORE implementation (`set-criterion.sh --red`), or `{"exempt": "<reason>"}` (`--red-exempt`,
  printed `[RED-EXEMPT]` at every run). Red is committed on its own before green: PASS criteria
  with no baseline FAIL; a baseline missing, empty, before `startedAt` or not before the earliest
  PASS evidence FAILS; red and green uncommitted together print `[RED-ORDER-UNVERIFIABLE]`;
  uncommitted in CI prints `[CI]`. A `# red-reason` line per failing test (`EVIDENCE-RULES.md`).
- `[TEST-MODIFIED]`: a test-path file present at the red-baseline commit and modified or deleted
  since (committed or working tree) fails a group with PASS criteria (Core Doctrine #3). The
  allowance is `set-criterion.sh --allow-test-change <TG> "<reference>"` (an addendum sets it),
  printed `[TEST-CHANGE-ALLOWED]` at every run.

## What a close requires

A group with criteria and no FAIL row is a completion claim. Then, besides the evidence rules:
`[CHECKS]` every check in `checks.env` is PASS at HEAD or HEAD^ (any ancestor in CI) and no
application file is newer than the run, else the names and the fix (`verify-gate.sh --run` runs
them first); `[NO-CHECKS]` prints once when nothing is declared; `[RISK]` a high-risk group has a
`_docs/ai/logs/*_security-report.md` written since it opened. The last PASS of a group is set
after the checks and the review, not before: the transaction refuses it otherwise.

## startedAt and addendumAt

- `startedAt` (written at open) anchors every ordering check; PASS criteria without it FAIL.
- `addendumAt` (`set-criterion.sh <TG> <ID> --addendum <YYYY-MM-DD>`): a spec addendum changed
  the criterion; `[ADDENDUM-UNAPPLIED]` prints until a test-path file changes at or after it.

## No vacuous gate

- Zero recorded criteria plus application code in the change set FAILS the gate. Application
  code is any path under a prefix in `app-code-paths` (repo-relative; test paths excluded).
  The change set: staged files at pre-commit, the PR range in CI (`VERIFY_GATE_DIFF_RANGE`),
  else the working tree plus untracked files. Without git the guard prints `[SKIPPED]`.
- The only override is the dated `noTaskGroupsExemption` (`gate` `BOOTSTRAP`, `note`,
  `reviewBy`; bootstrap seeds 14 days); it prints `[BOOTSTRAP]` while criteria are zero and
  FAILS once `reviewBy` passes. Remedy: `new-task-group.sh` then `add-criteria.sh`.

## Where the gate runs and what it prints

Tier A: the PreToolUse hook on any write to `verify-results.json` (`--file`, content only).
Tier B: the `set-criterion.sh` transaction, the Stop hook, the pre-commit hook
(`install-git-hooks.sh`). Tier C: CI on push and pull request. Output: one line by default
(`verify-gate: PASS (...)`); `--verbose` adds every BLOCKED row. Failures and the loud notes
(`[RED-EXEMPT]`, `[BOOTSTRAP]`, `[RED-ORDER-UNVERIFIABLE]`, `[ADDENDUM-UNAPPLIED]`,
`[TEST-CHANGE-ALLOWED]`, `[NO-CHECKS]`, `[UNREGISTERED-CRITERION]`, `[CI]`, `[SKIPPED]`) always print.

## Gate state

`gate-state.json` records each gate's `status` (`PASS`, `FAIL`, `NA`, `EXEMPT`, `PENDING`),
`artefact`, `timestamp`, and `note` + `reviewBy` for EXEMPT. `verify-gate.sh --gates` validates
it; `new-task-group.sh` refuses until Gate 8 is PASS or EXEMPT.

## Scripts

All under `scripts/`; evidence arguments are relative to `evidence/`.

- `new-task-group.sh <TG> "<title>" [--ui] [--risk low|medium|high] [--no-gates "<reason>"]`:
  opens a group (`startedAt`, `baseCommit`, `redBaseline: null`); refuses a reused ID.
- `spec-to-contract.sh <phase-spec> [--apply] [--tg <TG>]`: opens a phase spec's task groups
  (`[ui]`, `[risk: ...]` tags) and criteria FAIL-first (dry run by default; gated halves BLOCKED;
  idempotent; a malformed criterion refuses the whole spec). `new-addendum.sh "<subject>"
  [--criteria "<IDs>"] [--by "<who>"]`: next number, file, register row.
- `add-criteria.sh <TG> <ID> "<EARS text>" ...`: appends FAIL-first; refuses duplicates.
- `set-criterion.sh <TG> <ID> PASS <evidence>... | FAIL | BLOCKED <GATE> "<disposition>" |
  --addendum <date>`; `--red <TG> <file> | --red-exempt <TG> "<reason>"`: transactional (the gate
  runs on the result, the file is restored on a violation). Metadata, no transaction:
  `--risk <TG> <tier>`, `--allow-test-change <TG> "<reference>"`.
- `check.sh <NAME> | --all | --list`; `verify-gate.sh [--run] [--tg <TG>] [--file <path>]
  [--gates] [--verbose]`.
- `run-evaluator.sh <TG> <spec> [base-ref] [end-ref] [--double] [--skip-preflight]
  [--verify-findings | --no-verify-findings]`: next section.
- `archive-spec.sh <spec>`: gate, deltas merged into `SYSTEM-SPEC.md`, records moved to
  `_docs/ai/completed/`. `run-converge.sh`: fresh-context sweep, integration branch only.
- `log-decision.sh "<decision>" [--owner-pending]`; `log-delegation.sh <slug> <phase> <agent>
  <model> "<why>" [--tokens in out] [--class] [--effort] [--retries] [--elapsed]` (ledger row with
  any of those); `repo-map.sh`.

## Evaluator

- Runs when every criterion in a group is PASS or BLOCKED, as a separate `claude -p` process with
  no builder context, read-only (`--tools Read,Grep,Glob`, no MCP, `--restricted` on CLI
  2.1.248+), on `EVALUATOR_MODEL` from `_docs/ai/models.env` (a family alias; the resolved ID is
  recorded). Pre-flight before any token: `verify-gate.sh --tg` passes and no cited test file
  holds two runs (`--skip-preflight` bypasses loudly). Images go by path for the Read tool.
- The verdict is a structured object validated by the CLI against `verdict.schema.json`
  (verdict, one status per criterion, findings as file:line with severity). Written:
  `verdicts/<TG>-verdict.json`, the rendered `<TG>-verdict.md` (`VERDICT:` line, per-criterion
  lines, findings), one line per run in `<TG>-verdict.history.log`. A text answer, a schema
  failure or a CLI error leaves `verdicts/<TG>-verdict.failed-<epoch>.log` and no verdict.
- Finding verification (default on for `risk: high`, `--verify-findings` otherwise): a second
  restricted pass re-opens each BLOCKING finding; CONFIRMED stands, every finding UNCONFIRMED
  lifts a NEEDS_WORK to PASS with the basis printed; a verdict missing an in-scope criterion is
  NEEDS_WORK (exit 3). `--double` exits 0 only when both runs agree. Three consecutive NEEDS_WORK
  verdicts halt work and escalate.
