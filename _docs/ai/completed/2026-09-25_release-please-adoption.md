# Spec: adopt release-please (replaces PR #36; closes handover 5.1 item 3)

**Status:** approved (owner: "yes please to all three", 2026-09-25). **Branch:** `ci/release-please` from `main` @ `8e8486c`.
**Skills:** `release-management` Rules 1-2 (SSOT + release-please with a pre-existing publish workflow), `package-supply-chain-safety` (actions SHA-pinned, tag-verified, >14 days), `repo-standards` (PR-title gate).
**Why:** 3.0.1 and 3.0.2 each needed ten hand-edited version literals across nine files. PR #36 (2026-07-30, external) proposed the right shape but is stale against three releases; this PR re-implements it on current `main` and #36 is closed with thanks, linking here.

## Design (decisions made)

1. **release-please-action** `googleapis/release-please-action@45996ed1f6d02564a971a2fa1b5860e934307cf7 # v5.0.0`
   (tag verified 2026-09-25, published 2026-04-22, 156 days). Runs on every push to `main`, opens/updates a
   release PR, and on merge of that PR creates the tag and a **draft** GitHub Release carrying the changelog.
2. **Config `release-please-config.json`:** `release-type: simple`, `package-name: signal-sentinel-scanner`,
   `include-component-in-tag: false` (tags stay `vX.Y.Z`), `draft: true`, `force-tag-creation: true`,
   `bootstrap-sha: d3a4af702a1de190dec98ba5f2aacd7e83009582` (the v3.0.2 commit), changelog sections:
   feat=Features, fix=Bug Fixes, perf=Performance, deps=Dependencies, docs=Documentation, revert=Reverts;
   refactor/test/build/ci/chore hidden. `extra-files` (each carries an `x-release-please-version` marker):
   `Directory.Build.props`, `deploy/docker/Dockerfile.scanner`, `hooks/.pre-commit-hooks.yaml`, `README.md`,
   `INSTALLATION_AND_USAGE.md`, and `{ "type": "json", "path": "src/SignalSentinel.Scanner/DefaultRules.json", "jsonpath": "$.version" }`.
   **Manifest** `.release-please-manifest.json`: `{ ".": "3.0.2" }`.
3. **Markers:** every version literal in the extra-files gets the inline annotation
   `# x-release-please-version` (yaml/Dockerfile), `<!-- x-release-please-version -->` (markdown), or the
   `<Version>3.0.2</Version><!-- x-release-please-version -->` form in `Directory.Build.props`. Markdown lines
   with several occurrences use the block form `<!-- x-release-please-start-version -->` / `<!-- x-release-please-end -->`.
4. **`SignalSentinel.Scanner.csproj` `PackageReleaseNotes`** stops carrying hand-written per-version prose and
   becomes `See https://github.com/SignalCoding/signal-sentinel-scanner/releases/tag/v$(Version) and CHANGELOG.md`
   (derived from the MSBuild `Version`; no literal). The existing v3.0.0-v3.0.2 blocks are removed; they live in
   CHANGELOG.md and the GitHub Releases.
5. **`SECURITY.md`** version bullets are prose history, not the current version: leave as is (no marker).
6. **`.github/workflows/release-please.yml`** (new): `on: push: branches: [main]`, `permissions: {}` at top,
   job `release-please` with `contents: write`, `pull-requests: write`, `issues: write`; outputs
   `release_created`, `version`, `tag_name`. Job `publish` runs only when `release_created == 'true'` and calls
   `./.github/workflows/release.yml` via `workflow_call` with inputs `version` and `tag`, `secrets: inherit`,
   and the permission ceiling `contents: write, packages: write, security-events: write, actions: read`.
   Concurrency group `release-please-${{ github.ref }}`, `cancel-in-progress: false`.
7. **`.github/workflows/release.yml`** becomes dual-trigger: `on: workflow_call: inputs: {version, tag}` AND the
   existing `push: tags: ['v*']` (human tag path kept). Every job derives `VERSION`/`TAG` from
   `inputs.version || ${GITHUB_REF#refs/tags/v}` (one `resolve` job with outputs; other jobs `needs` it). The
   `Create Release` step (`softprops/action-gh-release`, already at v3.0.3 SHA) updates the draft release
   release-please created: `tag_name: <tag>`, `draft: false`, `append_body: true`, our install block as `body`,
   `files` unchanged, NO `generate_release_notes`. On the human-tag path there is no draft; `softprops` creates
   the release as today (same step works for both).
8. **PR-title gate** (repo-standards): new job in `ci.yml` using
   `amannn/action-semantic-pull-request@48f256284bd46cdaab1048c3721360e808335d50 # v6.1.1` (tag verified
   2026-09-25, published 2025-08-22) on `pull_request` `opened|edited|synchronize`, `permissions: pull-requests: read`,
   allowed types `feat fix perf deps docs refactor test build ci chore revert`, scopes optional. Squash-merge uses
   the PR title as the commit subject, so this is the commit-lint gate.
9. **Version drift guard** (Rule 1): new test `tests/.../Release/VersionDriftTests.cs`: walks the repo (excluding
   `bin/obj`, `.git`, `_docs`, `docs/`, `tests/`, `CHANGELOG.md`, `RELEASE_NOTES_*.md`, `SECURITY.md`) for
   `\b3\.\d+\.\d+\b` literals and asserts every hit is on a line carrying an `x-release-please` marker or inside a
   start/end block, or is in an allowlisted dependency pin (`PackageReference`, `uses:`). Fails naming file:line.
10. **`CHANGELOG.md`:** remove the manual `## [Unreleased]` section (its `deps:` commit is conventional and will be
    regenerated by release-please into 3.0.3); keep everything from `## [3.0.2]` down untouched.
11. **Docs:** `CONTRIBUTING.md` (or README "Releasing" section if CONTRIBUTING has none) gets a short "Releasing"
    paragraph: conventional PR titles drive the version; merge the release PR to tag; verify artefacts afterwards.
    `_docs/ai/HANDOVER.md` section 6 "Release" bullet is updated by the orchestrator, not the agent.

## Acceptance
- `dotnet build -c Release` 0 warnings; `dotnet test -c Release --no-build` all green (1424 + VersionDriftTests).
- `git grep -n -E "\b3\.0\.2\b"` outside the excluded paths shows only annotated lines.
- Both workflow files parse (`actionlint` if available, else a YAML load in Python) and CI on the PR is green,
  including the new PR-title job on this PR's own conventional title.
- Repo setting required before the first release PR can be opened: Settings -> Actions -> General ->
  "Allow GitHub Actions to create and approve pull requests" (currently `can_approve_pull_request_reviews=false`;
  owner UI action, recorded in the PR body).
- First expected release PR after merge: `chore(main): release 3.0.3` with a Dependencies section from #73.

## As implemented (2026-09-25)

- Items 2-11 done; 1425/1425; 0 warnings. Extra: `.gitignore` gained `!tests/SignalSentinel.Scanner.Tests/Release/` because the generic `[Rr]elease/` ignore swallowed the new test folder; `VersionDriftTests` walks a text-extension allowlist (checked-in binaries under `artifacts/` and `scan-results/` contain embedded version strings) and allowlists `.release-please-manifest.json`; `ci.yml` `pull_request.types` now includes `edited` so title edits re-lint (side effect: full CI re-runs on title edits). `docs/owasp-ast-mapping.md` has no version literal, so its absence from extra-files is correct.
- Owner action before the first release PR can open: Settings -> Actions -> General -> "Allow GitHub Actions to create and approve pull requests".
