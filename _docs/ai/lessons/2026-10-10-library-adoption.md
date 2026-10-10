# Lesson: two guards that only fire on a template's own apparatus, found while adopting library v3.3.0

**Date:** 2026-10-10. **Trigger:** adopting master library v3.3.0 into an existing, shipped project
(bootstrap commit `05297df`, existing-project mode, `dotnet-blazor-azure` template). Record:
`_docs/ai/completed/2026-10-10_bootstrap-conflicts.md`; decisions 2 and 3 in `_docs/ai/decision-log.md`.

Both findings below are **library defects, raised here rather than worked around**, per Core Doctrine
#11 (never edit the master library from a project session) and CONSTITUTION #28.

---

## 1. The version-drift guard flagged the library's own script header comments

### What happened

`release-management`'s drift check exists to enforce one `<Version>` literal per repository: every other
version-shaped string in the repo is a defect, because a stale one misleads. On the first run after
bootstrap it reported hits that were not product versions at all - the *library's own* delivered
apparatus describes itself in its headers (`# v3.0.0 - appends the next numbered entry...`,
`# Lineage: v1.8.1-cc (Python engine, BLOCKED), v1.10.0 ...`, the `(v2.8.0 repo-standards ...)` comment
in the template's `Directory.Build.props`), and those strings look exactly like drift.

### Why it matters

The guard was correct in mechanism and wrong in scope. A project-owned version literal is drift; an
apparatus file stating which library release delivered it is provenance, and provenance is the thing
that makes `bootstrap.sh --refresh-hooks` auditable. Left as-is the guard produces noise on every run
in every bootstrapped project, and a guard that cries wolf gets ignored - which is worse than not
having it, because the real drift it exists to catch then slips through.

### Resolution

`VersionDriftTests` (`tests/SignalSentinel.Scanner.Tests/Release/VersionDriftTests.cs`, landed in the
bootstrap commit `05297df`) excludes the library-owned layer by directory segment - `scripts`,
`.claude`, `_docs`, `docs`, `tests`, plus `bin`/`obj`/`.git` - and by filename: `CLAUDE.md`,
`CONSTITUTION.md`, `CHANGELOG.md`, `SECURITY.md`, `.release-please-manifest.json`. What remains in
scope is project-owned surface: product source, packaging metadata, Dockerfiles, workflows. The
exclusion is not an ad-hoc allowlist - it is MIGRATION.md's existing two-layer ownership boundary,
reused, which is why it should generalise to every bootstrapped project.

### For the master library

The exclusion belongs in the `release-management` skill, not in each project. Any project bootstrapped
from v3.3.0 or earlier will hit this on its first drift run.

---

## 2. `dotnet format` drift had never been caught, because CI never ran the format check

### What happened

`dotnet format --verify-no-changes` is named in the manual's Project table, is declared as `LINT` in
`_docs/ai/verify/checks.env`, and is run by `scripts/check.sh`. It is not run by **any** workflow in
`.github/workflows/` - `ci.yml` has five jobs (pr-title, build, security, code-quality, docker-build)
and none of them calls it. Format drift had accumulated in three files, unnoticed through five
releases, because nothing on the merge path ever asked. The three were
`src/SignalSentinel.Core/SkillParser/DependencyExtractor.cs`,
`tests/.../Osv/OsvClientResponseTests.cs` and `tests/.../SkillRules/SkillOsvRulesTests.cs`,
all reformatted in `05297df`.

### Why it matters

This is the gap between a *declared* check and an *enforced* one, and it is invisible by construction:
the check passes locally whenever someone happens to run it, and the only place it would reliably run
is the one place it was missing. A check that lives solely in a local script is a suggestion. CI is the
verifier (Gate 0.5 phase 2 says exactly this), and a declared check absent from CI is the same class of
defect as a documented rule with no test behind it.

It is also the mirror image of a lesson this project already learned the hard way: a guard over the
parts does not guard the summary (`RuleRegistryParityTests` passed while three files stated the wrong
rule total). Here, a guard existed and simply was never wired to the gate.

### Resolution

Drift cleared - `scripts/check.sh --all` now reports four PASS (TEST 1834 tests, BUILD, LINT,
DEPENDENCY_CHECK) and the evidence is committed under `_docs/ai/verify/evidence/CHECK-*`. The
evidence-gate step is now in `ci.yml`'s `build` job, so the completion contract is checked on every PR.

**Still open:** the format check itself is not yet a CI job. `check.sh --all` covers it locally and at
the gate, but nothing blocks a PR on it. Recorded as follow-up rather than claimed as fixed.

### For the master library

The template's `ci.yml` should run the declared checks from `checks.env` rather than hard-coding a
subset, so that declaring a check is the same act as enforcing it. As it stands a project can declare
four checks and have CI enforce two, with nothing reporting the discrepancy.

---

## Cost and the general shape

Neither defect cost a release; both were found inside one adoption session, which is the cheap end.
What they share is that the guard and the thing guarded were owned by different layers - the drift
guard was authored against project files and met apparatus files; the format check was authored into a
project script and never reached the project's CI. **When a library delivers both a rule and the
machinery that enforces it, the seam between them is where the rule stops applying,** and that seam is
invisible from inside either layer alone. It shows up on adoption, which is the only moment both layers
move at once - so adoption is worth treating as a review opportunity, not just a migration chore.
