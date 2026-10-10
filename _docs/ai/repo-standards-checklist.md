# Repository Standards Checklist (Gate 0.5)

Delivered by `bootstrap.sh` (library v3.0.0) as the Gate 0.5 artefact. Walk it once per repository,
tick each line with the evidence named, then record Gate 0.5 as PASS in `_docs/ai/verify/gate-state.json`
with `artefact: _docs/ai/repo-standards-checklist.md`. The `repo-standards` skill holds the how;
this file holds the what and the proof. Items that a client owns (org policy, runners, billing)
are recorded as `BLOCKED SIGN-OFF` with the owner named, never silently skipped.

## Phase 0 - the remote exists before feature work

| # | Item | Evidence (paste a URL, command output line, or screenshot name) | Done |
|---|------|------------------------------------------------------------------|------|
| 0.1 | GitHub repository created under the correct owner (org for client work, never a personal account) | repo URL | [ ] |
| 0.2 | Default branch is `main` (rename from `master` if the host created it) | `git remote show origin` shows `HEAD branch: main` | [ ] |
| 0.3 | Local `origin` set and the bootstrap commit pushed (`git push -u origin main`) | `git rev-parse --abbrev-ref @{u}` = `origin/main` | [ ] |
| 0.4 | Visibility matches the engagement (private unless the client says otherwise) | settings screenshot or `gh repo view --json visibility` | [ ] |

## Phase 1 - protection and hygiene (before the first PR)

| # | Item | Evidence | Done |
|---|------|----------|------|
| 1.1 | Branch protection on `main`: PR required, 1 review, status checks required (CI + PR title), linear history, no force-push, no deletion | `gh api repos/:owner/:repo/branches/main/protection` or ruleset screenshot | [ ] |
| 1.2 | Secret scanning + push protection ON; Dependabot alerts + security updates ON (alerts are OFF by default on a new private repo: `gh api -X PUT repos/<owner>/<repo>/vulnerability-alerts`, then `gh api repos/<owner>/<repo>/vulnerability-alerts` must answer 204, not 404) | settings screenshot or the 204 | [ ] |
| 1.3 | `gitleaks` (or the host's push protection) blocks a test secret on push | one refused push, then reverted | [ ] |
| 1.4 | Signed commits required, or the decision not to require them recorded (`_docs/ai/decision-log.md`) | ruleset line or decision entry number | [ ] |
| 1.5 | CODEOWNERS, PR template, issue templates present (template ships them) | `ls .github/` | [ ] |
| 1.6 | `release-please` workflow present and its first run created (or skipped with reason) | Actions run URL | [ ] |
| 1.7 | Actions pinned to commit SHAs (package-supply-chain-safety) or the pinning task logged | grep of `uses:` lines | [ ] |

## Phase 2 - CI is the verifier (first PR)

| # | Item | Evidence | Done |
|---|------|----------|------|
| 2.1 | `ci.yml` real commands replaced (no `CHANGEME`), full suite + coverage + build run in CI | first green run URL | [ ] |
| 2.2 | Evidence gate step present in CI (`scripts/verify-gate.sh`) and green | run log line `verify-gate: PASS` | [ ] |
| 2.3 | Coverage upload (Codecov) and quality gate (Sonar) tokens set, or their skip lines visible in the run | run summary | [ ] |
| 2.4 | PR title check enforces Conventional Commits; commit-msg hook installed locally (`scripts/install-git-hooks.sh`) | one rejected title, one rejected local commit | [ ] |
| 2.5 | Private runner / org-level policy needs recorded (`BLOCKED SIGN-OFF` with owner) if the client mandates them | decision-log entry | [ ] |

## Push cadence (standing rule, checked every session start)

- Every task-group close and every session end pushes (`git push`); the session-start hook
  announces unpushed commits older than a day and a branch with no upstream.
- Work lands on `type/short-kebab` branches through small squash-merged PRs; `main` is never
  committed to directly once protection is on.

## Sign-off

| Field | Value |
|-------|-------|
| Walked by | |
| Date | |
| Gate 0.5 status | PASS / BLOCKED SIGN-OFF (owner: ) |
| Notes | |
