# _docs/ai/ - AI Governance Artefacts

This directory holds the governance evidence for AI-assisted development on this project. Everything in here (except `_scratch/` at the project root) is committed to version control.

## Structure

```
_docs/ai/
├── README.md                    # this file
├── configuration.md             # project's governance posture (output of startup-configuration skill)
├── SYSTEM-SPEC.md               # living spec: capabilities the system has (merged by archive-spec.sh)
├── repo-map.md                  # where things live (generated block refreshed by repo-map.sh)
├── decision-log.md              # numbered decisions; OWNER-PENDING marks open items
├── models.env                   # model families (EVALUATOR_MODEL=opus; the verdict records the resolved ID)
├── ai-code-register.md          # AI code audit log (Comprehensive/Regulatory governance only)
├── specs/                       # active specs awaiting or in implementation
│   ├── <slug>.md                   # feature spec, or <product>-phase-<n>.spec.md (spec-to-contract.sh reads it)
│   ├── <slug>.addendum-A<n>-*.md   # spec addenda (created by new-addendum.sh)
│   ├── ADDENDA.md                  # addenda register: the only place addendum numbers come from
│   ├── baseline/                   # the signed register, proposal and clarifications
│   └── templates/                  # the spec kit (library-owned, refreshed): register, proposal, phase spec, sign-off
├── completed/                   # archived specs, their task groups and evidence
│   ├── <slug>.md
│   ├── <slug>-verify-results.json
│   └── <slug>-evidence/
├── lessons/                     # lessons carried between projects
├── verify/                      # completion contract (source of truth)
│   ├── README.md                   # the contract reference: shape, statuses, gate, scripts
│   ├── EVIDENCE-RULES.md           # how a capture earns its place as evidence
│   ├── verify-results.json         # task groups and criteria (written by scripts/ only)
│   ├── gate-state.json             # Gate 0 to 8 status
│   ├── app-code-paths              # application prefixes the vacuous-gate guard watches
│   ├── checks.env                  # the checks a close must pass (scripts/check.sh runs them quietly)
│   ├── checks-state.json           # last run per check: commit, time, status (written by check.sh)
│   ├── verdict.schema.json         # the evaluator's structured verdict (library-owned, refreshed)
│   ├── evidence/                   # criterion evidence files; CHECK-<name>.* from check.sh
│   └── verdicts/                   # <TG>-verdict.md, <TG>-verdict.json, <TG>-verdict.history.log
└── logs/                        # per-feature reports and process logs
    ├── <slug>_test-report.md       # test-writer output
    ├── <slug>_impl-report.md       # coding-agent output
    ├── <slug>_security-report.md   # security-reviewer output
    ├── <slug>_delegation.md        # reasoned delegation log (log-delegation.sh)
    ├── delegation-ledger.log       # delegation ledger (hook + log-delegation.sh --tokens/--class/--retries)
    ├── check-<name>-<stamp>.log    # full output of each declared check (check.sh)
    └── tool-audit.log              # secrets-guard hook audit (gitignored)
```

## Why This Exists

Under ISO 42001 (AI Management System) and NIST AI RMF, AI-assisted development requires:

- Documented intent (the spec)
- Documented behaviour validation (the test report)
- Documented risk assessment (the security report)
- Documented change record (the git commit)

Together these form the evidence package per change. This directory is where that evidence lives.

For most governance levels (Basic, Enhanced, Standard) this evidence is sufficient. For Comprehensive or Regulatory governance, also maintain `ai-code-register.md` as a running log.

## What Gets Committed

Everything here except `tool-audit.log`. The `.gitignore` excludes `_scratch/` (project-root scratch) and `_docs/ai/logs/tool-audit.log` only. Reports and specs are intentionally committed because they are the audit trail.

## Workflow

1. **Spec** lives in `specs/` while it's being worked; its task groups and criteria live in
   `verify/verify-results.json` (rules: `verify/README.md`, capture craft: `verify/EVIDENCE-RULES.md`)
2. **Reports** accumulate in `logs/` as the four-phase loop runs
3. **Completed spec** moves to `completed/` at archive time (`scripts/archive-spec.sh`), together
   with its task groups and evidence

Reports stay in `logs/` permanently. They're the historical record of what was done and how.

## Cleanup

Periodically (quarterly) review `completed/` and confirm:

- Every archived spec has its three reports in `logs/`
- No archived spec has unaddressed Critical or High security findings
- The configuration is still current

Write a quarterly governance summary to `_docs/ai/governance/<YYYY>-Q<n>.md` if applicable.
