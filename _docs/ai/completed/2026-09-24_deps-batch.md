# Spec: dependency batch 2026-09-24 (Dependabot queue, quarantine-checked)

**Status:** approved (owner: "proceed", 2026-09-24). **Branch:** `deps/batch-2026-09-24` from `main` @ `87f17a9`.
**Skill:** `package-supply-chain-safety` (14-day quarantine; Microsoft first-party exempt; actions SHA-pinned and tag-verified).
**Mechanism:** one hand-applied batch on `main`; Dependabot auto-closes its PRs once `main` carries the versions.

## Audit (2026-09-24)

| Dependabot PR | Package | From -> To | Published | Age | Decision |
| --- | --- | --- | --- | --- | --- |
| #60 | Markdig (NuGet) | 0.38.0 -> 1.4.0 (major) | 2026-09-20 | 4d | **DEFER** - quarantined until 2026-10-04; segmentation depends on it; take alone with the corpus test as the net |
| #59 | FsCheck.Xunit | 3.3.4 -> 3.4.0 | 2026-08-20 | 35d | take |
| #53 | Microsoft.CodeAnalysis.NetAnalyzers | 10.0.201 -> 10.0.401 | 2026-09-08 | 16d | take (first-party exempt anyway); both csproj |
| #34 | YamlDotNet | 16.3.0 -> 18.1.0 (major) | 2026-06-26 | 90d | take - v18 breaking change is only for `ITypeInspector` implementers; we use `DeserializerBuilder` in `SigmaRuleLoader` only |
| #29 | coverlet.collector | 8.0.1 -> 10.0.1 | 2026-05-18 | 129d | take (test-only) |
| #58 | actions/checkout | v4 -> v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1` | 2026-07-17 | 69d | take; Node 24 runtime, GitHub-hosted runners only |
| #57 | docker/metadata-action | v5 -> v6.2.0 `dc802804100637a589fabce1cb79ff13a1411302` | 2026-07-02 | 84d | take; Node 24 |
| #56 | docker/login-action | v4.1.0 -> v4.6.0 `dbcb813823bdd20940b903addbd779551569679f` | 2026-07-29 | 57d | take |
| #20 | softprops/action-gh-release | v1 -> v3.0.3 `efb35369e0ad2afab669f228072c1b0d510eae64` | 2026-08-30 | 25d | take; v3 = Node 24; inputs `name`/`body`/`files` unchanged |
| #19 | actions/download-artifact | v4 -> v8.0.1 `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | 2026-03-11 | 197d | take; v5 path change affects downloads *by ID* only (we download by name); v8 errors on digest mismatch (desired) |

All five action SHAs were verified against the upstream tag refs on 2026-09-24 (`gh api repos/<owner>/<repo>/git/ref/tags/<tag>`, annotated tags dereferenced). `actions/upload-artifact` stays at v4 (no PR; compatible with download-artifact v8).

## Changes
1. `src/SignalSentinel.Core/SignalSentinel.Core.csproj`: NetAnalyzers 10.0.401; YamlDotNet 18.1.0.
2. `src/SignalSentinel.Scanner/SignalSentinel.Scanner.csproj`: NetAnalyzers 10.0.401.
3. `tests/SignalSentinel.Scanner.Tests/SignalSentinel.Scanner.Tests.csproj`: FsCheck.Xunit 3.4.0; coverlet.collector 10.0.1.
4. `.github/workflows/ci.yml` and `.github/workflows/release.yml`: every `actions/checkout@...` -> `3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`; in `release.yml` also `docker/metadata-action@dc802804100637a589fabce1cb79ff13a1411302 # v6.2.0`, `docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4.6.0`, `actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1`, `softprops/action-gh-release@efb35369e0ad2afab669f228072c1b0d510eae64 # v3.0.3`. Comments carry the real version (Dependabot's `# v4` comment on the checkout bump is wrong).
5. `CHANGELOG.md`: `## [Unreleased]` section above `[3.0.2]` with a **Dependencies** list (one line per bump, Markdig deferred noted).
6. Not changed: Markdig, upload-artifact, setup-dotnet, build-push-action, setup-buildx-action, trivy-action, codeql upload-sarif.

## Acceptance
- `dotnet restore` succeeds; `dotnet build -c Release` 0 warnings (NetAnalyzers 10.0.401 may surface new analyzer rules: fix at the source with the narrowest change, never `<NoWarn>`; report each new rule id).
- `dotnet test -c Release --no-build` 1424/1424 (Sigma YAML tests exercise YamlDotNet 18; FsCheck properties exercise 3.4.0).
- `dotnet list signal-sentinel.sln package --vulnerable --include-transitive` reports nothing.
- CI green on the PR (ci.yml exercises the checkout bump; release.yml action bumps are exercised at the next tag).

## As implemented (2026-09-24)

- All changes applied as specified; no new analyzer rules surfaced; YamlDotNet 18 compiled with no source changes; 1424/1424; no vulnerable packages. Markdig #60 deferred to 2026-10-04.
