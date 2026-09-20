# _docs/ai/ - AI Governance Artefacts

This directory holds the governance evidence for AI-assisted development on this project. Everything in here (except `_scratch/` at the project root) is committed to version control.

## Structure

```
_docs/ai/
├── README.md                    # this file
├── configuration.md             # project's governance posture (output of startup-configuration skill)
├── ai-code-register.md          # AI code audit log (Comprehensive/Regulatory governance only)
├── specs/                       # active specs awaiting or in implementation
│   └── <slug>.md
├── completed/                   # archived specs (one per completed feature)
│   └── YYYY-MM-DD_<slug>.md
└── logs/                        # per-feature reports
    ├── <slug>_test-report.md       # test-writer output
    ├── <slug>_impl-report.md       # coding-agent output
    ├── <slug>_security-report.md   # security-reviewer output
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

1. **Spec** lives in `specs/` while it's being worked
2. **Reports** accumulate in `logs/` as the four-phase loop runs
3. **Completed spec** moves to `completed/` with a date prefix at archive time

Reports stay in `logs/` permanently. They're the historical record of what was done and how.

## Cleanup

Periodically (quarterly) review `completed/` and confirm:

- Every archived spec has its three reports in `logs/`
- No archived spec has unaddressed Critical or High security findings
- The configuration is still current

Write a quarterly governance summary to `_docs/ai/governance/<YYYY>-Q<n>.md` if applicable.
