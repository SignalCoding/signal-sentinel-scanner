# Implementation Report: release-please-adoption

**Date:** 2026-09-25 | **Status:** GREEN
**Spec:** _docs/ai/specs/release-please-adoption.md (design items 2-11)
## Files Changed
New: `release-please.yml`, `release-please-config.json`,
`.release-please-manifest.json`, `tests/.../Release/VersionDriftTests.cs`.
Modified: `release.yml`, `ci.yml`, `Directory.Build.props`,
`Dockerfile.scanner`, `.pre-commit-hooks.yaml`, `README.md`,
`INSTALLATION_AND_USAGE.md`, `SignalSentinel.Scanner.csproj`, `CHANGELOG.md`,
`CONTRIBUTING.md`, `.gitignore`.
## What Was Modified
- Config/manifest new per item 2 (verbatim below).
- `release-please.yml`: `release-please` job (SHA `45996ed1...` v5.0.0) +
  `publish` job -> `release.yml` via `workflow_call` (item 6).
- `release.yml`: dual-trigger (`workflow_call` + `push:tags`); new `resolve`
  job outputs `version`/`tag`; nuget/docker/release jobs `needs: [...,resolve]`,
  read `needs.resolve.outputs.*`; per-job extract-version steps removed;
  `Create Release` gained `tag_name`,`append_body:true`, dropped
  `generate_release_notes` (item 7).
- `ci.yml`: new `pr-title` job (`amannn/...` SHA `48f25628...` v6.1.1);
  `pull_request.types: [opened,edited,synchronize]` (item 8).
- Six extra-files annotated (marker table below, item 3).
- csproj `PackageReleaseNotes` -> single derived line (item 4).
- `CHANGELOG.md`: deleted only `## [Unreleased]` (item 10).
- `CONTRIBUTING.md`: added "Releasing" paragraph (item 11).
- `VersionDriftTests.cs`: new test, walks repo for `\b3\.\d+\.\d+\b` (item 9).
  Verified red-then-green: removed `Directory.Build.props` marker -> failed
  naming that line; restored -> 1425/1425 green.
- `.gitignore`: `!tests/SignalSentinel.Scanner.Tests/Release/` added - the
  pre-existing `[Rr]elease/` rule silently ignored the mandated test dir.
## Files Intentionally Not Touched
`SECURITY.md` (item 5, prose history); `docs/`/`_docs/`/pre-existing tests
(spec exclusions); `src/**/*.cs` dev comments mentioning `v3.0.2` (no `\b`
before `3` after `v`, not literals); `docs/owasp-ast-mapping.md` (not in this
spec's six-file list - flagged below).
## Validation
Build: 0 Warnings/Errors. Tests: 1425 passed, 0 failed. `--list-rules` clean.
`git grep \b3\.0\.2\b` (acceptance excludes): 20 lines, all annotated/exempt.
YAML `safe_load` x3: `yaml ok`; actionlint not on PATH.
## Final `release-please-config.json`
Content below is semantically identical to the repo-root file, reflowed to fit
the line budget (the actual file is pretty-printed, 2-space indent, 38 lines).
```json
{
  "$schema": "https://raw.githubusercontent.com/googleapis/release-please/main/schemas/config.json",
  "bootstrap-sha": "d3a4af702a1de190dec98ba5f2aacd7e83009582", "include-component-in-tag": false,
  "draft": true, "force-tag-creation": true,
  "changelog-sections": [
    { "type": "feat", "section": "Features" }, { "type": "fix", "section": "Bug Fixes" },
    { "type": "perf", "section": "Performance" }, { "type": "deps", "section": "Dependencies" },
    { "type": "docs", "section": "Documentation" }, { "type": "revert", "section": "Reverts" },
    { "type": "refactor", "section": "Code Refactoring", "hidden": true }, { "type": "test", "section": "Tests", "hidden": true },
    { "type": "build", "section": "Build System", "hidden": true }, { "type": "ci", "section": "Continuous Integration", "hidden": true },
    { "type": "chore", "section": "Miscellaneous", "hidden": true }
  ],
  "packages": { ".": { "release-type": "simple", "package-name": "signal-sentinel-scanner",
    "extra-files": [ "Directory.Build.props", "deploy/docker/Dockerfile.scanner", "hooks/.pre-commit-hooks.yaml",
      "README.md", "INSTALLATION_AND_USAGE.md",
      { "type": "json", "path": "src/SignalSentinel.Scanner/DefaultRules.json", "jsonpath": "$.version" } ] } }
}
```
## Marker Placement (file:line, form)
Directory.Build.props:15 inline | Dockerfile.scanner:90-92 block |
pre-commit-hooks.yaml:7 inline | README.md:6 inline, 74-80 block |
INSTALLATION_AND_USAGE.md:3,99,117,462,497 inline;
54-58,89-93,106-110,147-155,158-165,175-181,191-196,264-272,314-332,666-672
block; 703 inline | DefaultRules.json:2 none (jsonpath `$.version`).
## Dependencies Added
none
## Follow-Up Needed
- Owner: enable "Allow GitHub Actions to create and approve pull requests"
  before the first release PR can open (recorded in spec).
- Widened `pull_request.types` means build/security/code-quality/docker-build
  also re-run on PR-title-only edits (GHA has no per-job `on:`).
- `docs/owasp-ast-mapping.md`'s `v3.0.0` heading unannotated (outside the
  spec's six-file list) - confirm intentional.
## Risks and Notes
- Drift test uses an extension allowlist to avoid false positives from
  checked-in binaries (`artifacts/*.nupkg`, `*.tgz`, `*.pdf`) - beyond spec's
  literal wording, a deliberate scoping choice.
- Not committed (shared tree; orchestrator commits after verification).
## Open Questions Raised During Work
none
