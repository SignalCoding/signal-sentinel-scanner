# REPO-STANDARDS.md - GitHub setup and lifecycle runbook (v1.0, 2026-09-05)

**Audience: the AI agent (Claude Code or Factory Droid) working in this project, and the
human operator where marked `[HUMAN]`.** Drop this file into a new project's root (or point
the agent at it in the opening prompt) BEFORE the first commit. It runs alongside the
AIAgent Master Library bootstrap until this is embedded in the orchestration system itself.

Two sources of truth, never restated here:
- **Files** come from the library kit: `KIT = C:\Sites\_AIAgent\templates\_shared\repo-standards\`
  (`/c/Sites/_AIAgent/templates/_shared/repo-standards/` in Git Bash). COPY them - never
  regenerate, paraphrase, or "improve" them. They are fixture-tested per library release.
- **Doctrine detail** lives in the library skill `repo-standards` (SKILL.md + references).
  If the skill is synced (`~/.claude/skills/repo-standards/` or Droid equivalent), it fires
  on its own triggers; this runbook is the project-local enforcement of the same rules.

If this project was bootstrapped from a library template (v2.8.0+), Phase 1 is already done
by the template - verify instead of copying, then continue from Phase 2.

---

## Phase 0 - Repo creation (once, before any code)

1. `[HUMAN]` The repo lives in the **Signal Coding GitHub org** (not a personal account) -
   rulesets on private repos require the paid Team plan, which the org carries.
2. Agent: create the repo and local clone:
   ```bash
   gh repo create signalcoding/<repo-name> --private --clone
   cd <repo-name>
   git config core.autocrlf false     # .gitattributes owns EOL; autocrlf causes drift
   ```
3. Signed commits `[HUMAN, once per machine]`: SSH signing must exist BEFORE the ruleset
   requires it:
   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/id_ed25519.pub
   git config --global commit.gpgsign true
   # then upload id_ed25519.pub to GitHub as a SIGNING key (Settings > SSH and GPG keys)
   ```
   Do this on BOTH machines (desktop + laptop). Skip the ruleset's signed-commit rule until
   both are done, else nothing can merge.

## Phase 1 - Install the kit files (once)

Copy from `$KIT` into the repo root, then fill placeholders:

```bash
KIT=/c/Sites/_AIAgent/templates/_shared/repo-standards
cp "$KIT"/{CONTRIBUTING.md,SECURITY.md,.editorconfig,.gitattributes,codecov.yml,release-please-config.json,.release-please-manifest.json} .
mkdir -p .github/workflows .github/ISSUE_TEMPLATE
cp "$KIT"/.github/CODEOWNERS "$KIT"/.github/PULL_REQUEST_TEMPLATE.md .github/
cp "$KIT"/.github/ISSUE_TEMPLATE/*.yml .github/ISSUE_TEMPLATE/
cp "$KIT"/.github/workflows/{pr-title.yml,release-please.yml} .github/workflows/
# ONE of, by stack:
cp "$KIT"/.github/workflows/ci-dotnet.yml  .github/workflows/ci.yml   # .NET
cp "$KIT"/.github/workflows/ci-node.yml    .github/workflows/ci.yml   # Node/Next/RN
cp "$KIT"/.github/workflows/ci-generic.yml .github/workflows/ci.yml   # anything else
# Node stacks also: cp "$KIT"/commitlint.config.js .
# non-.NET also:    cp "$KIT"/sonar-project.properties .
```

Then, in order:
1. Replace every `CHANGEME` (grep for it): `OWNER/REPO` badges, CODEOWNERS handle,
   SECURITY.md contact, `.sln` name in the .NET CI, Sonar key/org. Merge the badge block
   from `$KIT/README.template.md` into README.md. `release-please-config.json`: keep
   `release-type: node` for package.json stacks, `simple` otherwise; .NET adds the
   `Directory.Build.props` xpath extra-file and a `<Version>` property (the ONE hand-edited
   version in the repo - version literals anywhere else are a defect).
2. Set `.release-please-manifest.json` to the true current version. New project: `0.1.0`.
   Anything already in production or depended on: `1.0.0`.
3. Install hooks: `bash scripts/install-git-hooks.sh` if the project has the library
   scripts; otherwise copy that script from any library template's `scripts/` and run it.
   It installs the verify-gate pre-commit AND the Conventional Commits commit-msg gate.
4. First commit (conventional, like every commit after it):
   ```bash
   git add -A && git commit -m "chore: repository standards baseline" && git push -u origin main
   git tag v$(cat .release-please-manifest.json | grep -o '[0-9.]*') && git push --tags
   ```
5. `[HUMAN]` Secrets and services: sign into Codecov and SonarQube Cloud with GitHub, add
   the repo to each, then `gh secret set CODECOV_TOKEN` and `gh secret set SONAR_TOKEN`.
6. `[HUMAN or agent via gh]` Branch protection: apply `$KIT/docs/branch-protection.md`
   exactly (ruleset on `main`: PR required, required checks, linear history, conversation
   resolution, no force push/deletion, NO admin bypass; squash-merge only, default message =
   PR title+description; auto-delete head branches; secret scanning + push protection ON).
   Add "require signed commits" only after Phase 0 step 3 is done on both machines.
7. On the FIRST green CI run: pin every action to its commit SHA and verify SHA-vs-tag
   (`gh api repos/<owner>/<action>/git/refs/tags/<tag>`) per package-supply-chain-safety.

**Verification gate for Phase 1** - all must be true before feature work starts:
`grep -rn CHANGEME .` returns nothing; a test commit with message `bad message` is REJECTED
locally; a direct `git push` to main is REJECTED by GitHub; `gh pr checks` on a trial PR
shows ci, lint-title and codecov checks; the trial PR can only be squash-merged.

## Phase 2 - Every task, for the life of the project

1. **Never commit to main.** Branch `type/short-kebab` (`feat/magic-link-login`,
   `fix/client-404`). One logical change per branch; target under 300 changed lines.
2. **Every commit message is Conventional Commits 1.0.0**: `type(scope)!: lower-case
   imperative, <=72 chars, no trailing full stop`. Types: feat, fix, docs, style, refactor,
   perf, test, build, ci, chore, revert. `!` + `BREAKING CHANGE:` footer for incompatible
   changes. Keep provenance trailers (Co-authored-by, AI attribution) - they are footers.
   The hook enforces this; do not fight the hook, fix the message.
3. **Open a PR early** (draft is fine), title in conventional format (it becomes the squash
   commit on main), template filled in: what, why, how tested, checklist. New/changed code
   ships with tests; patch coverage >= 80%.
4. **CI is the verifier - the agent is not.** Run only the TARGETED test file locally with a
   short reporter (`dotnet test --logger "console;verbosity=minimal"` / `vitest run
   --reporter=dot`). The full suite, lint, format, coverage and Sonar run in Actions. Read
   results with `gh pr checks <n>` and `gh run view <id> --log-failed | tail -60` - never
   the whole log, never pasted wholesale into context.
5. **Never do work a machine already owns**: formatting (hooks/CI), dependency bumps
   (Dependabot), version numbers and CHANGELOG.md (release-please - NEVER hand-edited),
   commit-message rejection (hook). Never weaken coverage excludes, quality-gate settings,
   ruleset rules or hook logic to get green - surface the failure to the human instead.
6. **Merge = squash, checks green, conversations resolved.** Delete the branch. If the
   Sonar quality gate or codecov/patch fails, fix the code or the tests - not the gate.

## Phase 3 - Releases (automatic; do not improvise)

release-please watches main. After any `feat:`/`fix:` lands it opens/updates a release PR
carrying the version bump and CHANGELOG. Merging that PR creates the `vX.Y.Z` tag and the
GitHub Release. `fix` -> PATCH, `feat` -> MINOR, breaking -> MAJOR. If the proposed bump
looks wrong, the COMMITS were mislabelled - fix forward with a correcting commit, never by
editing the release PR. Before any manual release action, run the pre-flight: remote tag
exists, Release published, registry/artefact shows the version (release-management Rule 3).

## Standing constraints (whole lifecycle)

- Defence-adjacent or production-deploy jobs do not run on public shared runners - flag to
  the human for a private runner pool before adding such a workflow.
- Never commit secrets or `.env`; push protection is a backstop, not the control.
- Lockfiles and generated output stay `linguist-generated -diff` (`.gitattributes`) - do not
  remove those lines, and do not read lockfiles into context.
- This file and the kit files are governance: the agent may not edit them except on explicit
  human instruction. Kit improvements go through the library's release procedure, not here.
- If the `repo-standards` skill is available, defer to it where this file is silent.

## Provenance

Consolidated 2026-09-05 from: the Joe review sessions (Conventional Commits, semver,
Codecov, SonarQube; rulesets, signed commits, squash merge, org/plan, Terraform-managed
governance - the latter parked for the library), the agent-economy analysis, and AIAgent
Master Library v2.8.0 (`repo-standards` skill, `templates/_shared/repo-standards/`).
Supersedes the standalone kit at `C:\Sites\_repo-standards-kit_1` - delete that folder once
this file is in use; the kit files' canonical home is the library path above.
