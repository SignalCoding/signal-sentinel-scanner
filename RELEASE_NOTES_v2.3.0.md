# Signal Sentinel Scanner v2.3.0

**Release date:** 2026-04-18
**Positioning:** first-pass authoring aid for MCP operators and skill authors.

## Headline features

- `.sentinel-suppressions.json` — accept specific findings with a justification, approver and expiry; retained in every report format for audit trail.
- Confidence-aware triage — `--min-confidence <f>` hard filter and `--triage` demotion mode ([rubric](docs/confidence-rubric.md)).
- Scan history + `sentinel-scan diff <baseline.json> <current.json>` attributing grade changes to the rules that caused them.
- Per-environment baselines and `--save-history`, `--environment`, `--complementary-tools` flags.
- `SS-INFO-001` non-MCP endpoint detection. When the target is a React SPA / Traefik catch-all / anything non-JSON-RPC, the scanner emits an informational finding instead of a misleading Grade A, and auto-suppresses every MCP-protocol rule (SS-001..010, SS-019..025) for that target so the report is internally consistent.
- Case-insensitive, lemma-aware SS-012 with an extended synonym table (`disk`, `volume`, `mount`, `/proc`, `/sys`, `/dev`, `procfs`, `sysfs`).
- YAML `capabilities:` block is authoritative for SS-012. Declare `capabilities: [read-filesystem, shell_command_execution, network]` in skill frontmatter and SS-012 will trust it over prose heuristics.
- Suppressed scans display a **technical-debt exposure banner** — "if these N suppression(s) were removed, your grade would be X (Y/100) instead of Z (W/100)" — in Markdown and HTML. Suppressions cannot be used to hide risk.
- Pre-commit hook integrations for [pre-commit.com](https://pre-commit.com), [lefthook](https://github.com/evilmartians/lefthook) and [husky](https://typicode.github.io/husky/) under `hooks/`.

## Quality bar

- 254 tests passing (up from 195 in v2.2.0).
- 0 warnings, 0 errors with `TreatWarningsAsErrors`.
- `dotnet format` clean.
- SARIF v2.1.0 output validated against GitHub Code Scanning.

## Backward compatibility

- v2.2 baselines load without conversion.
- Scoring rubric version remains `1.0`; a v2.2 user's CI gate on `grade < B` does not flip on unchanged input.
- `.sentinel-suppressions.json` is opt-in; if absent, scan behaviour is unchanged from v2.2.0.

## Upgrade

```bash
dotnet tool update -g SignalSentinel.Scanner
# or
docker pull ghcr.io/signalcoding/signal-sentinel-scanner:2.3.0
```

## Links

- [BACKLOG_V2.3.0.md](BACKLOG_V2.3.0.md) — full item list with acceptance criteria
- [docs/confidence-rubric.md](docs/confidence-rubric.md) — how `--min-confidence` and `--triage` interact with each rule
- [docs/owasp-ast-mapping.md](docs/owasp-ast-mapping.md) — AST01-AST10 coverage table
- [ROADMAP_V3.0.md](ROADMAP_V3.0.md) — strategic pivot deferred to v3.0

## Acknowledgements

Thanks to the early operator teams for two rounds of live scanning and the
comprehensive product feedback that drove the four late-breaking credibility
fixes in this release.
