# Repo Map - where things live

Second retrieval stop after `_docs/ai/SYSTEM-SPEC.md` (Core Doctrine #12): a lookup beats a
hunt. The hand-written part below is maintained by the orchestrator whenever a task group adds
or moves a directory of consequence (same change, never a follow-up - Core Doctrine #14). The
generated block at the end is refreshed by `bash scripts/repo-map.sh` and never edited by hand.

## Entry points

| What | Where |
|---|---|
| Operating manual | `CLAUDE.md` (imports `CONSTITUTION.md`; `AGENTS.md` is a pointer) |
| Living spec (capabilities the system has) | `_docs/ai/SYSTEM-SPEC.md` |
| Active specs / completed specs | `_docs/ai/specs/` / `_docs/ai/completed/` |
| Completion contract and evidence | `_docs/ai/verify/verify-results.json`, `_docs/ai/verify/evidence/`; rules: `_docs/ai/verify/README.md`, capture craft: `_docs/ai/verify/EVIDENCE-RULES.md` |
| Gate state, model families, app-code paths, declared checks | `_docs/ai/verify/gate-state.json`, `_docs/ai/models.env`, `_docs/ai/verify/app-code-paths`, `_docs/ai/verify/checks.env` (+ `checks-state.json`) |
| Decisions and open items | `_docs/ai/decision-log.md` (`grep -n OWNER-PENDING`) |
| Delegation records | `_docs/ai/logs/<slug>_delegation.md`, `_docs/ai/logs/delegation-ledger.log` |
| Lessons carried between projects | `_docs/ai/lessons/` |
| Session metrics (if installed) | `_docs/ai/metrics/` |

## Where the code lives (fill in at Gate 5 - Architecture Foundation)

| Concern | Path | Notes |
|---|---|---|
| Application entry | TODO | |
| Domain / services | TODO | |
| Persistence / migrations | TODO | |
| UI / pages / components | TODO | |
| Tests (unit / integration / e2e) | TODO | which suite runs where |
| Configuration and secrets policy | TODO | never in the repo |
| CI / deploy | `.github/workflows/` | ci.yml runs the evidence gate |

## Conventions worth knowing before searching

- TODO: naming, layering, the one place cross-cutting primitives live (CONSTITUTION #3).

<!-- REPO-MAP:GENERATED:BEGIN -->
(run `bash scripts/repo-map.sh` to fill this block: top-level and second-level directories with file counts)
<!-- REPO-MAP:GENERATED:END -->
