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

Every rule needs all of the following or CI's rule-registry tests will fail:

1. A constant in `src/SignalSentinel.Core/RuleConstants.cs`.
2. An entry in `src/SignalSentinel.Core/Models/RuleAstMapping.cs` (OWASP AST codes).
3. An entry in `OwaspMapping` / `OwaspMcpMapping` where the rule has an MCP mapping.
4. Registration in `src/SignalSentinel.Scanner/Rules/RuleEngine.cs`.
5. A line in the `--help` text and the `--list-rules` output (`Program.cs`).
6. A test class under `tests/SignalSentinel.Scanner.Tests/` with at least one
   positive, one negative, and one edge case.
7. If the rule depends on MCP protocol exchange, add it to
   `RuleConstants.Rules.McpProtocolRules` so SS-INFO-001 can suppress it correctly.
8. An entry in `src/SignalSentinel.Scanner/DefaultRules.json` (the shipped rule
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

## Licence

By contributing you agree that your contributions are licensed under the
Apache License 2.0, the same as the project.
