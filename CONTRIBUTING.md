# Contributing to Signal Sentinel Scanner

Thank you for your interest. This document covers how to build, test, and submit
changes. Security vulnerabilities must **not** be reported here; see
[SECURITY.md](SECURITY.md).

## Prerequisites

- .NET SDK matching `global.json` (currently 10.0.401). The SDK pin uses
  `rollForward: latestPatch`, so any 10.0.4xx patch will work.
- Git with SSH commit signing configured (commits to this repository are signed).

## Build and test

```bash
dotnet build signal-sentinel.sln -c Release
dotnet test  signal-sentinel.sln -c Release --no-build
```

The build treats warnings as errors and runs the full .NET analyser set
(`AnalysisLevel=latest-all`, `AnalysisMode=All`). A change that introduces a warning
will fail CI.

## Branching and pull requests

- Never commit directly to `main`. Branch from `main` (or from the active
  `release/*` branch when one is open) and open a pull request.
- Keep pull requests focused. One rule, one fix, or one feature per PR.
- CI must be green before merge. Pull requests are squash-merged.
- Delete the branch after merge.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <summary, imperative, max 72 chars>

<optional body explaining why, not what>
```

Types in use: `feat`, `fix`, `build`, `ci`, `docs`, `test`, `refactor`, `chore`.
Breaking changes carry a `!` after the type/scope or a `BREAKING CHANGE:` footer.

## Adding a detection rule

Every rule needs all of the following or CI's rule-registry tests will fail. A
2026-09-27 audit found two whole cohorts of rules that had reached some of these
surfaces but not others (`_docs/ai/specs/rule-registry-parity.md`); the checklist
below is the corrected, complete version, and `RuleRegistryParityTests`
(`tests/SignalSentinel.Scanner.Tests/Rules/RuleRegistryParityTests.cs`) is the
mechanical check that fails the build, naming the rule and the surface, if any of
1-9 is missed:

1. A constant in `src/SignalSentinel.Core/RuleConstants.cs`.
2. An entry in `src/SignalSentinel.Core/Models/RuleAstMapping.cs` (OWASP AST codes),
   or a documented allow-list exception (e.g. `SS-INFO-002`).
3. An entry in `OwaspMapping` / `OwaspMcpMapping` where the rule has an MCP mapping.
   This mapping is nullable - not every rule has an MCP Top 10 code - but a null
   must carry a one-line reason comment rather than be a silent omission.
4. Registration in `src/SignalSentinel.Scanner/Rules/RuleEngine.cs` (or, for a rule
   that must be wired in per-scan rather than in the constructor, inclusion in
   `RuleEngine.CatalogueRules()` as well).
5. A line in the `--help` text and the `--list-rules` (`RuleEngine.CatalogueRules()`)
   output (`Program.cs`).
6. An entry in the README.md "Security Rules" tables.
7. An entry in `docs/owasp-ast-mapping.md`.
8. An entry in `INSTALLATION_AND_USAGE.md`.
9. A test class under `tests/SignalSentinel.Scanner.Tests/` with at least one
   positive, one negative, and one edge case.

Additionally:

- If the rule depends on MCP protocol exchange, add it to
  `RuleConstants.Rules.McpProtocolRules` so SS-INFO-001 can suppress it correctly.
- Add an entry in `src/SignalSentinel.Scanner/DefaultRules.json` (the shipped rule
  registry) with matching id, name, owaspCode and astCodes.

Rule IDs are allocated sequentially (`SS-0NN`) or as `SS-INFO-0NN` for informational
rules that do not affect the grade.

## Dependencies

- Pin exact versions. No floating ranges (`2.*`).
- New packages go through a 14-day quarantine before adoption unless they are
  first-party Microsoft security servicing releases.
- The build fails on any NuGet advisory (`NU1901`-`NU1904`) because warnings are errors.

## Versioning

The version lives in one place: `<Version>` in `Directory.Build.props`. Do not add
version literals elsewhere; derive them at build time or reference the assembly version.

## Releasing

Versioning and tagging are owned by [release-please](https://github.com/googleapis/release-please),
driven by Conventional Commit PR titles (squash-merge uses the PR title as the commit
subject, so the PR title is what matters). On every push to `main`, release-please
opens or updates a `chore(main): release X.Y.Z` pull request that bumps the version
everywhere (`Directory.Build.props` and the other `extra-files` in
`release-please-config.json`) and rewrites `CHANGELOG.md`. Merge that PR to create the
tag and the GitHub Release, which triggers `.github/workflows/release.yml` to publish
the NuGet packages and the GHCR Docker image. After a release, verify the NuGet
listing, the GHCR tag and the GitHub Release artefacts before considering it done.

## Licence

By contributing you agree that your contributions are licensed under the
Apache License 2.0, the same as the project.
