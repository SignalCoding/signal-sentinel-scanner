# Handover: Signal Sentinel Scanner (Droid → Claude Code)

**Written:** 2026-09-21 by Droid (Factory), superseding the 2026-09-20 version. Owner: Durgan Cooper.
**Repo:** `C:\sites\sentinel-scanner` → `https://github.com/SignalCoding/signal-sentinel-scanner.git`, default branch `main`, currently `b5f30bc`.
**Read in this order:** `AGENTS.md` (operating manual; Claude Code has no `CLAUDE.md` in this repo, treat `AGENTS.md` as it), `_docs/ai/configuration.md`, this file, then the documents in section 3 as needed.

The owner granted standing authority to work unattended: create branches, open PRs, merge when CI is green, self-validate when no validator sub-agent is available. Tags were a human-only action until the owner said "push" on 2026-09-21; treat any future tag as human-only again unless told otherwise. Never force-push or rewrite `main`. Never touch the untracked `.claude/` and `docs/archive/` directories (owner's).

---

## 1. State of the project (one paragraph)

**v3.0.0 is released.** Tag `v3.0.0` points at `b5f30bc`. Release workflow run `35568532190` succeeded in all four jobs. Verified artefacts: GitHub Release `Signal Sentinel v3.0.0` (not draft, both `.nupkg` attached); NuGet.org `SignalSentinel.Scanner` 3.0.0 and `SignalSentinel.Core` 3.0.0 (installed locally via `dotnet tool install --global`, `sentinel-scan --version` → `Signal Sentinel Scanner v3.0.0`); GHCR `ghcr.io/signalcoding/signal-sentinel-scanner:3.0.0` and `:latest` pushed (multi-arch, 18 min build). 47 rules, **1183 tests**, build 0 warnings / 0 errors. `main` is clean; there is no open feature branch of ours.

## 2. What happened, in order

| Step | Commit / PR | Result |
| --- | --- | --- |
| v3.0.0 release (WP1–WP14) | PRs #37–#50 → `release/v3.0`; v2.5.1 hotfix merged in (#52 `5b23aae`); release PR #51 `--merge` → `main` `ceee019` | 22 new rules, 5 flags, rubric v2.0.0, Markdown segmentation |
| Dependabot rebase outcome recorded | #54 `b0d7327` | spec archived: `_docs/ai/completed/2026-09-20_v3.0-release.md` |
| Pre-tag smoke test | #55 `3e5587f` | 12 defects D1–D12 found against live servers and DVMCP lab; tag withheld |
| Smoke fixes D1–D7, D10, D12 | #61 `883083c` | HF D/22→C/63, Chainflip F/0→C/81, 401 targets → Inconclusive, legacy SSE detected, arg errors exit 2, +40 tests |
| Post-merge re-test of `main` | none (verification only) | full matrix matched; found two CLI quirks |
| CLI quirks | #62 `b5f30bc` | `--version` no longer dumps usage; unknown `--format` exits 2; +12 tests |
| Tag + release | `v3.0.0` → `b5f30bc` | shipped, artefacts verified (section 1) |

## 3. Documents that hold the detail

| Document | What it is |
| --- | --- |
| `_docs/ai/completed/2026-09-20_v3.0-release.md` | Release spec WP1–WP14 with "As implemented" notes, Dependabot outcome table |
| `_docs/ai/completed/2026-09-20_v3.0.0-smoke-test.md` | Smoke test: targets, grades, D1–D12 with file:line; **section 5** = re-run after fixes (before/after tables) |
| `_docs/ai/completed/2026-09-20_v3.0.0-smoke-fixes.md` | Fix spec with "As implemented" deviations (D7 405/404 only, D5 `\b` approach, D6 classifier algorithm, fixture scope) |
| `_docs/ai/completed/2026-09-19_bootstrap-conflicts.md` | Earlier bootstrap conflict record |
| `CHANGELOG.md` `[3.0.0]` | User-facing Added/Changed/Fixed/Security for everything above |
| `docs/keyword-rules.md` | Retained/pruned keyword list for the skill rules (v2.5.1 FP work) |
| `_docs/ai/lessons/README.md` | Lessons directory (empty apart from README; see section 9 for candidates) |

## 4. Architecture notes you will need

- **Solution:** `src/SignalSentinel.Core` (models, `McpProtocol`, `Security/InjectionPatterns.cs`, scoring rubric JSON), `src/SignalSentinel.Scanner` (CLI `Program.cs`, `McpClient/`, `Rules/`, `Scoring/`, `Config/`, report generators), `tests/SignalSentinel.Scanner.Tests` (xunit 2.9.3, Shouldly, NSubstitute, FsCheck; `InternalsVisibleTo` granted). .NET 10, C# 14, `TreatWarningsAsErrors`, analyzers strict (see section 6).
- **CLI flow:** `Program.Main` → `ParseArguments` (now `internal static`; returns `null` for `--help`, `ScanConfig.VersionPrinted` for `--version`, `ScanConfig.InvalidArguments` for any rejected option → exit 2) → policy resolution → enumeration (`ToolEnumerator` over `McpConnection`) → rules (`IRule` implementations in `Rules/`) → `SeverityScorer` (rubric v2.0.0) → report generator (json/markdown/html/sarif).
- **MCP client (`McpClient/McpConnection.cs`):** Streamable HTTP (POST JSON-RPC, SSE unwrap), stdio, WebSocket. `InitializeAsync` requests `McpProtocolVersions.Current` (2026-07-28), retries once with `Fallback` (2025-06-18) on `InvalidOperationException` starting `MCP error:`; stores the sanitised negotiated version and sends `MCP-Protocol-Version`. `CreateHttpPost(json)`/`CaptureSessionId(response)` are the single place session headers are handled. `IsLegacySseEndpointAsync` probes GET with `Accept: text/event-stream` after a 405/404 on `initialize` and throws `LegacySseEndpointException(postStatusCode)`; `NonMcpEndpointException` for HTML/non-JSON.
- **Enumeration → rules:** `ServerEnumeration` carries `ConnectionSuccessful`, `ConnectionError`, `LegacySseEvidence`, tools/resources/prompts, server instructions, unsolicited requests, protocol error bodies. Rules that care about unconnected servers (`LegacyMcpProtocolRule`, `OAuthComplianceRule`, `NonMcpEndpointRule`) check evidence before the `!ConnectionSuccessful` skip.
- **Grading:** `evaluableServers` counts only connected servers plus server-source and agent-card surfaces; zero evaluable → `Inconclusive` / 0 with text "no server connected and no skills were scanned…". Findings are retained.
- **SS-008 (`Rules/SensitiveDataRule.cs`):** `ClassifyCredentialAccess(name, description)` is the heart. Name match (separators → spaces) → Critical; negated credential noun in any sentence → no finding; disclosure verb ≤5 words before / ≤3 after the noun → Critical (0.9, evidence = sentence); consumption context → skip; else High (0.7). PII requires person word + store word in one sentence. Keyword sets at the top of the file.
- **SS-031 (`Rules/ResourcePoisoningRule.cs`):** `CredentialMaterial` regex → High "Resource Advertises Credential Material"; `SensitivityLabel` → Medium "Resource Marked Confidential or Restricted"; pre-existing `SensitiveFileUri` name check → Critical.
- **Network policy:** `RemoteUrlPolicy` blocks loopback/RFC1918/link-local unless `--allow-private`; `OfflineGuard` is a process-wide static that tests must `Reset()` in `[Collection("OfflineGuardSerial")]`.
- **Fixtures:** `tests/.../Fixtures/RemoteToolLists/{learn,huggingface,chainflip,deepwiki}.json` are real `tools/list` captures, copied to output by the csproj `<None Include="Fixtures\**\*.json">`. Add more real-world captures here when tuning rules; the regression tests assert "no SS-008 Critical, no SS-001" on clean servers.

## 5. Open items

### 5.1 For the owner (need GitHub UI or a decision)

1. **GHCR package is private.** Anonymous `docker manifest inspect ghcr.io/signalcoding/signal-sentinel-scanner:3.0.0` → `unauthorized`; same for `2.5.0`, `2.5.1`, `latest`, so it has never been public. README/INSTALLATION docs advertise `docker pull`. Fix: GitHub → Packages → `signal-sentinel-scanner` → Package settings → Change visibility → Public. Not doable from the local `gh` token (lacks `read:packages`).
2. **Dependabot PRs open on `main`:** #60 Markdig 0.38→1.4.0 (major, review the Markdown segmentation tests), #59 FsCheck.Xunit 3.4.0, #58 actions/checkout 7.0.1, #57 docker/metadata-action 6.2.0, #56 docker/login-action 4.6.0, #53 NetAnalyzers 10.0.401, #34 YamlDotNet 16→18 (major), #29 coverlet 10.0.1, #20 action-gh-release 1→3, #19 download-artifact 8.0.1. Dependabot self-closed the codeql-action v4 PRs (#35, #33, #18); re-trigger via Insights → Dependency graph → Dependabot → "Check for updates". Package-supply-chain rule: 14-day quarantine on brand-new versions; Microsoft first-party is exempt.
3. **PR #36 "feat: Release Please Implementation"** from `thejoeker12` (2026-07-30, 14 files incl. `Program.cs`, `release.yml`, `Directory.Build.props`). Well-intentioned, now badly stale against v3.0.0 (no checks reported, mergeability unknown). Decide: close with thanks and adopt release-please in a fresh PR following the `release-management` skill, or ask the author to rebase. Do not merge as-is.
4. **Jon's feedback** (65-skill corpus, pre-2.5.1: Grade F, 584 findings, ~489 FPs): skill-side FPs were addressed in v2.5.1; the MCP tool-description FP class (SS-008/SS-001 substring matching) is fixed in 3.0.0 (D5/D6). Offer him a re-run against 3.0.0 and, ideally, get his corpus as fixtures.
5. GitHub repo description → roadmap positioning.

### 5.2 Ready-to-do engineering (3.0.x patch material, each small)

| Item | Where | Notes |
| --- | --- | --- |
| Release workflow Trivy upload warning "Resource not accessible by integration" | `.github/workflows/release.yml` `publish-docker` job | add `permissions: security-events: write, contents: read, packages: write`; also bump `github/codeql-action/upload-sarif` v3→v4 (v3 deprecated Dec 2026) |
| `.gitignore:30 [Ll]ogs/` ignores `_docs/ai/logs/` | `.gitignore` | AGENTS.md says logs are governance artefacts under version control; one-line `!_docs/ai/logs/` |
| Roundtable `set-thread-visibility` SS-008 High "Sensitive Data Marker" on `private` | `SensitiveDataRule` markers | `private` as an enum value in a schema is not a sensitivity marker; check schema-value context |
| D8: SS-020 metadata quality | `AuthProbeService`, `OAuthComplianceRule` | 401 + `WWW-Authenticate: Bearer` is an MCP auth challenge even when body is `text/plain` (GitHub Copilot); distinguish resolvable / 404 / missing `resource_metadata` |
| D9: SS-042 text leaks exception type | `Rules/AgentCardRule` (SS-042) | map `JsonReaderException` → "response was not JSON" |
| D11: stdio immediate exit reported as timeout | `McpConnection` stdio path | surface exit code + stderr tail; related to the EOF hot-loop item |
| Full legacy HTTP+SSE transport | `McpConnection` | GET stream → `endpoint` event → POST `/messages/?session_id=`; would let DVMCP `/sse` be scanned instead of just detected |
| `-o report.markdown` rejected ("Invalid output path") | `Program.ValidatePath` allow-list | `.md` works; decide whether to add `.markdown` |
| Rubric: 12 Highs at score 0 still grade C | `Scoring/scoring-rubric-v2.0.0.json` grade rules | only Critical moves to D/F; rubric owner decision, needs FsCheck monotonicity tests kept green |

### 5.3 Older backlog (from the release review, not started)

Markdown evidence backtick escaping; `McpConnection` `GetInt32`→`TryGetInt32`; `0.0.0.0/8` in `RemoteUrlPolicy`; exact NuGet pins for non-test packages; `SanitizeErrorMessage` path/quote mangling; `ScanContext.Policy` seam; N-skills duplicate OSV queries; OSV status counts; `Servers Scanned` stat; same-line segment sort; `tests/**/*.md text eol=lf` in `.gitattributes`; EXFIL-005 magic-string id; `node` fence alias; `{}` rubric claiming "2.0.0".

## 6. Repo conventions (learned the hard way)

- **Commits:** Conventional Commits, one logical change per commit. Trailer used so far: `Co-authored-by: factory-droid[bot] <138933559+factory-droid[bot]@users.noreply.github.com>`. Switch to Claude's trailer going forward; ask the owner if continuity matters. Write the message to `.git/COMMIT_MSG_<slug>.txt` and `git commit -F` (PowerShell mangles multi-line `-m`).
- **PRs:** `gh pr create --base main --body-file .git/PR_BODY_<slug>.md`; CI takes ~2.5–4 min; `gh pr checks <n>`; merge with `gh pr merge <n> --squash --delete-branch --subject "type(scope): title (#n)"`. CI = Build & Test ×3 OS, Code Quality, Security Scan, Docker Build Test, CodeQL ×5. Branch protection requires all green.
- **Release:** pushing a `v*` tag runs `.github/workflows/release.yml` (Build & Test → NuGet + GHCR in parallel → GitHub Release). The v2.5.1 run had **failed**; always verify artefacts after a release (NuGet flat-container index, `gh release view`, `docker manifest inspect`), don't trust the tick. Version must agree in: `Directory.Build.props`, both `.csproj` `PackageReleaseNotes`, `deploy/docker/Dockerfile.scanner` `ARG VERSION`, `README.md` badge, `INSTALLATION_AND_USAGE.md`, `CHANGELOG.md`, `hooks/.pre-commit-hooks.yaml` `rev:`. `release/v3.0` branch exists at `5b23aae`; for 3.0.x patches either branch from `main` (simplest, nothing else is on `main` yet) or fast-forward `release/v3.0` first. Decide with the owner before the first patch.
- **Stage named files only** (`git add <paths>`). Untracked `.claude/` and `docs/archive/` are the owner's.
- **Build/test:** `dotnet build -c Release` must be 0 warnings; `dotnet test -c Release --no-build` ~1 min, 1183 tests. Binary: `src\SignalSentinel.Scanner\bin\Release\net10.0\SignalSentinel.Scanner.exe`.
- **Analyzer rules that will bite you in tests:** CA2007 → `.ConfigureAwait(true)` on every await, `await using (x.ConfigureAwait(true)) { }`; CA1031 → catch specific exceptions; CA1054/CA1056 → don't name string params `url`/`uri`; CA1859 → concrete types; CA1812 → no unused private classes; CA1307 → `StringComparison.Ordinal`; CS9007 raw-string gotchas → concatenate.
- **PowerShell gotchas:** `$args` is reserved; `${name}:` for interpolation before a colon; `Out-String` before `.Substring`; capture `$LASTEXITCODE` before any pipeline; multi-step `-replace` chains and regex-over-file edits mangle CRLF, use the editor; `git grep` excludes need `':(exclude)_docs'`; PowerShell `curl` is `Invoke-WebRequest`, use `curl.exe`.
- **Docs discipline (AGENTS.md):** spec in `_docs/ai/specs/` → archive to `_docs/ai/completed/<date>_<slug>.md` with "As implemented" notes on completion. CHANGELOG is Keep a Changelog; the next version gets a new `## [3.0.1]` section.

## 7. How to reproduce the smoke matrix

Scratch dir `%TEMP%\v3-smoke\` (contains `final-*.json` from the 2026-09-21 re-test, the `dvmcp` clone with `mcp>=1.6,<2` pinned, and `dvmcp-stdio.json`; may not survive). Docker image `dvmcp:latest` is built locally; no container is running.

- **Public, no auth (`--remote <url>`):** `https://learn.microsoft.com/api/mcp` C/71, `https://mcp.deepwiki.com/mcp` C/84, `https://huggingface.co/mcp` C/63, `https://gitmcp.io/docs` C/87 (slow, ~21 s), `https://mcp.context7.com/mcp` C/55, `https://chainflip-broker.io/mcp` C/81, `https://mcp.roundtable.now/mcp` C/67, `https://game.spacemolt.com/mcp` F/0 (220 tools, genuine). Remaining Highs are SS-003 no-auth (genuine for public servers) plus per-server genuine items listed in the smoke record §5.1. INFO-004 evidence shows the server's real `protocolVersion`.
- **OAuth 401 (`--remote`):** `https://mcp.linear.app/mcp`, `https://mcp.notion.com/mcp`, `https://mcp.asana.com/mcp`, `https://mcp-server.egnyte.com/mcp`, `https://mcp.sentry.dev/mcp`, `https://mcp.atlassian.com/v1/mcp` → Inconclusive/0 + SS-020 Info. `https://api.githubcopilot.com/mcp/` → Inconclusive/0 + SS-INFO-001 (D8).
- **A2A (`--agent-card`):** `https://www.agentcard.net` A/97 SS-042 Medium; `https://agent2agent.info` A/100 SS-042 Info.
- **DVMCP lab:** `docker run -d --name dvmcp -p 127.0.0.1:9001-9010:9001-9010 dvmcp`. Legacy SSE `--remote http://127.0.0.1:900N/sse --allow-private` (N=1–4,6–9) → Inconclusive/0 + SS-INFO-004 Medium + SS-INFO-002. Stdio `--config %TEMP%\v3-smoke\dvmcp-stdio.json` → F/0, 90 findings, 44 attack paths, 9/10 connected (ch5 `combined_server` fails to import under mcp 1.x, reported as timeout = D11), ~37 s. Source `--server-source <clone>\challenges --offline` → C/0, SS-041 ×12. Each stdio server is `docker exec -i dvmcp python -c "import sys; sys.path.insert(0,'/app/challenges/<tier>/<challengeN>'); import server; server.mcp.run(transport='stdio')"` (easy 1–3, medium 4–7, hard 8–10). `docker rm -f dvmcp` afterwards.
- **Refusals (all exit 2, one error line, no usage):** `--remote <url> --offline`; `--skills <dir> --osv --offline`; `--agent-card <url> --offline`; `--remote http://127.0.0.1:9001/mcp` (no `--allow-private`); `--bogus-flag`; `--remote not-a-url`; `--format text`.
- **CLI:** `--version` → one line, exit 0; `--help` → usage, exit 0; `--format` json/markdown/md/html/sarif; `-o` extension must match the allow-list (`.md` not `.markdown`).
- JSON report shape for scripting: `grade`, `score`, `findings[] {ruleId, severity, title, serverName, toolName, evidence}`, `servers[] {name, connectionSuccessful, connectionError, toolCount, transport, sourceConfig}`, `attackPaths[]`.

## 8. Decisions already made (don't re-litigate)

- Request `Current` in `initialize` with one `Fallback` retry; SS-INFO-004 reflects the server's ceiling.
- D7 is detection-only in 3.0.x unless a user needs legacy SSE servers scanned.
- Findings for unreachable / 401 / non-MCP / legacy-SSE servers stay in the report; only the grade becomes Inconclusive.
- SS-008 Critical requires a disclosure verb next to a credential noun in a non-negated sentence; plain mention is High. DVMCP ch2 `search_company_database` being High (not Critical) is accepted because SS-001 also fires on it.
- Real-world `tools/list` captures are the regression corpus for rule tuning; synthetic strings alone are not enough.
- Grade thresholds/weights are unchanged from v2; the rubric file makes them auditable, not different.
- Smoke records live in `_docs/ai/completed/`, not `_docs/ai/logs/` (gitignored, see 5.2).

## 9. Lessons worth writing up (`_docs/ai/lessons/`)

1. Context-blind substring matching in security rules produces FP-driven grades (Jon's corpus, HF, Chainflip). Fix pattern: sentence scope + negation + disclosure verb + real-world fixtures.
2. A client that hard-codes a protocol version makes every server look legacy; always request current and record what the server answers.
3. A scan that connects to nothing must not grade A. "Inconclusive" needs to be a first-class outcome in every output format.
4. Verify release artefacts after every tag; the workflow tick is not proof (v2.5.1 failed silently; GHCR has been private all along).
5. Test the CLI's first-run surface (`--version`, `--help`, bad args) explicitly; nobody had, and `--version` dumped 130 lines for several releases.

---

## Update 2026-09-22 (Claude Code session, appended; sections above describe the 2026-09-21 state)

**v3.0.1 is released.** Tag `v3.0.1` -> `8432246`. Release run `35762771277` succeeded in all four jobs. Verified:
GitHub Release published with both `.nupkg`; NuGet `SignalSentinel.Scanner` and `SignalSentinel.Core` 3.0.1 live;
global tool updated (`sentinel-scan --version` -> v3.0.1). GHCR `:3.0.1` pushed but the package is still private
(5.1 item 1 unchanged). 47 rules, **1390 tests**, 0 warnings.

| Step | PR / commit | Result |
| --- | --- | --- |
| Post-release validation of v3.0.0 | none (record `_docs/ai/completed/2026-09-21_v3.0.0-skill-corpus-smoke.md`) | MCP matrix matched the baseline exactly; Anthropic public skills corpus (19 skills) graded F/0 with 4 Critical, all false positives |
| Skill-rule false-positive fix (F1-F15) | #64 `7bdf018` | corpus F/0 -> C, 0 Critical; YAML block scalars; SS-018 segmentation; SS-011/014/015/016 shaped; real-world skill fixtures + `RealWorldSkillCorpusTests`; +207 tests |
| .NET 10.0.401 regex miscompile | in #64 | `(?:X){n,m}?` makes Compiled/GeneratedRegex return fabricated matches (interpreted engine: none) and `Matches()` never advances; four patterns rewritten, `RegexEngineIntegrityTests` guard; INJECTION-002's instance had shipped in 3.0.0 |
| Security review of #64 | `_docs/ai/logs/v3.0.1-skill-false-positives_security-report.md` | PASS WITH NOTES; all three Medium items fixed in-branch (IMPORTANT: newline bypass, Markdown evidence escaping, F8 docs) |
| Version bump | #65 `8432246` | ten locations, drift grep empty, spec `_docs/ai/completed/2026-09-22_v3.0.1-release.md` |
| `.gitignore` | in #64 | `!_docs/ai/logs/` so governance logs are tracked (5.2 item done) |

**Lesson recorded:** `_docs/ai/lessons/2026-09-21_skill-rules-need-real-world-corpus.md` (context-blind rules fixed
token-by-token against one corpus; no real-world skill fixture existed; plus the engine-bug addendum).

### Open items after this update

For the owner:
1. **GHCR visibility** (unchanged, 5.1 item 1).
2. **Trivy SARIF upload warning** (5.2 row 1) still present in run `35762771277`. The fix is ready but was blocked by
   the Claude Code permission classifier as a CI permission grant: in `.github/workflows/release.yml` job
   `publish-docker`, add `security-events: write` under `permissions:`, and bump
   `github/codeql-action/upload-sarif` to v4 at commit `1c5b675653bb5c22dbe9b12b556ec555138e09fd` (the `v4` tag,
   dereferenced 2026-09-22). Apply by hand or allow the edit.
3. **Upstream bug report** to `dotnet/runtime` for the regex miscompile; minimal repro in the security report addendum.
4. **Jon's corpus re-run** is now meaningful (3.0.1); ask for the corpus as fixtures under `Fixtures/RealWorldSkills/`.
5. Dependabot PRs and PR #36 as listed in 5.1 (unchanged).

Engineering backlog additions (3.0.x / 3.1):
- SS-012 scope-violation noise on real skills (11 Medium on the Anthropic corpus): body mentions of `http`/`api`/`web`
  count as "network access"; consider Prose-only + verb-shaped capability detection.
- Rubric: the corpus grades C at score 0 (5.2 last row applies).
- `SkillScriptPayloadRuleTests.Evaluate_WithProcessExecution_ReturnsHigh` is misnamed (asserts title only; literal
  commands are now Medium).
- SS-024 "no signature" x19 Medium on every unsigned corpus; consider Info until signing is common.
- F11 blind spot: decode in one script, dynamic exec in another script of the same skill is not linked.

### Conventions confirmed this session
- Commit trailer is now `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` plus a `Claude-Session:` line.
- Delegation ran in `auto` mode under the standing authority above; every decision is in
  `_docs/ai/logs/*_delegation.md`. Merges of #64/#65 and the `v3.0.1` tag were explicit owner instructions.
- `_docs/ai/logs/.gitkeep` is untracked and harmless; ignore or delete.

---

## Update 2026-09-24 (Claude Code session, appended)

**`main` carries unreleased 3.0.2 changes** (version literals still 3.0.1; no tag). Suite **1424 tests**, 0 warnings.

| Step | PR / commit | Result |
| --- | --- | --- |
| Trivy SARIF upload permission + `upload-sarif` v4 pin | #67 `855dcfc` | 5.2 row 1 done; takes effect on the next tag push |
| SS-012 verb+target shapes, SS-024 -> Info, grade honours score band | #68 `22e0f1f` | Anthropic corpus C/0 (49) -> **D/29 (38, 23 Info)**, zero SS-012; spec `_docs/ai/completed/2026-09-24_v3.0.2-skill-noise.md` |
| Security review of #68 | `_docs/ai/logs/v3.0.2-skill-noise_security-report.md` | PASS WITH NOTES; both findings fixed in-branch: `strict` preset now pins SS-024 to High via `severityOverrides` (overrides replace bumps, they do not chain); SS-012 shapes accept verb conjugations |

**Owner rulings recorded:** grade/score consistency = option B (grade never better than score band; a Critical-free
scan under 50 grades D). Option C (per-unit score normalisation, rubric 2.1.0) is the first 3.1 design item.

### Open items after this update
1. **Tag 3.0.2** when ready: bump the ten version locations (precedent #65), then tag; verify artefacts afterwards.
2. **GHCR visibility** (unchanged, owner UI action).
3. Upstream dotnet/runtime regex report; Jon's corpus as fixtures; Dependabot queue; PR #36 decision (all unchanged).
4. Backlog: rubric option C; SS-016 High on `subprocess.run(cmd)` dynamic calls is the corpus's remaining grade driver
   (4 Highs = 40 points) and is genuine per F13, but the weights are a rubric question; misnamed
   `Evaluate_WithProcessExecution_ReturnsHigh`; F11 split-file blind spot; SS-012 accepted narrowings
   (`read|create|copy`, singular `file`, `script(s)`, `at https://`) may need revisiting on a second corpus.

**Addendum 2026-09-24 (later):** `v3.0.2` released. Tag on `d3a4af7` (#70), release run `35968459433` all four jobs green; verified GitHub Release (both `.nupkg`), NuGet 3.0.2 for Scanner and Core, `sentinel-scan --version` -> v3.0.2; the Trivy SARIF upload ran without the permission warning (#67 effective). GHCR `:3.0.2` pushed, package still private. Open item 1 above is done; items 2-4 unchanged.

**Addendum 2026-09-24 (GHCR):** package is now public. Root cause of 5.1 item 1 was the organisation policy (Settings -> Packages -> Package creation had only Private ticked), which greys out Public in the package dialog; the owner enabled Public at org level, then the package visibility was switched to Public. Verified anonymously: manifests for 3.0.2, latest, 3.0.1 (4 platforms each), `docker pull` + `--version` run. Open owner items: upstream regex bug report, Jon corpus, Dependabot queue, PR #36.

**Addendum 2026-09-24 (dependencies):** Dependabot queue cleared by batch PR #73 (`ff088b5`): NetAnalyzers 10.0.401, YamlDotNet 18.1.0, FsCheck.Xunit 3.4.0, coverlet.collector 10.0.1, and SHA-verified actions/checkout v7.0.1, docker/metadata-action v6.2.0, docker/login-action v4.6.0, actions/download-artifact v8.0.1, softprops/action-gh-release v3.0.3. Nine Dependabot PRs closed as superseded. **Still open: #60 Markdig 0.38 -> 1.4.0**, quarantined until 2026-10-04 (published 2026-09-20); take it alone with `RealWorldSkillCorpusTests` and `SegmentationRegressionTests` as the net. The `release.yml` action bumps are first exercised at the next tag: verify artefacts after 3.0.3 as usual. Audit table: `_docs/ai/completed/2026-09-24_deps-batch.md`. 5.1 item 2 is now closed except Markdig.

**Addendum 2026-09-25:** release-please adopted (#75 `5cc9b41`, spec `_docs/ai/completed/2026-09-25_release-please-adoption.md`). Section 6 "Release" above is superseded: conventional PR titles (linted in CI) drive the version; on each push to `main` the bot opens/updates `chore(main): release X.Y.Z`; merging it tags, drafts the release and runs `release.yml` via `workflow_call`; a human `git push origin vX.Y.Z` still works. `VersionDriftTests` fails on any unmarked version literal, so never hand-edit versions again. **Owner action required once:** Settings -> Actions -> General -> "Allow GitHub Actions to create and approve pull requests" (currently off; the first bot run after #75 cannot open its PR until then). PR #36 closed with thanks (5.1 item 3 done). Regex miscompile reported upstream as dotnet/runtime #134655 (5.1 follow-up done). Jon re-run email drafted for the owner to send (5.1 item 4 pending his reply). Remaining owner items: Markdig #60 after 2026-10-04; rubric option C as a 3.1 design item.

**Addendum 2026-09-25 (release pipeline live):** 3.0.3 and 3.0.4 released. The bot pipeline needed two fixes found on 3.0.3 (#80: Docker tags derived from the resolved version, plus `workflow_dispatch(version, tag)` to re-publish an existing tag; #82: GitHub Release published with `gh release upload/edit` because `softprops/action-gh-release` v3 returns 403 on an existing release, upstream softprops/action-gh-release#836). 3.0.3 was completed by hand; 3.0.4 (#81) ran end to end with no manual step: tag, NuGet, GHCR `:3.0.4`, published release with the install block appended to the bot changelog.

**Operating the pipeline (read this before the next release):**
1. Merge conventional PRs to `main`; the bot keeps `chore(main): release X.Y.Z` up to date.
2. **A bot PR gets no CI checks until a human closes and reopens it** (events from `GITHUB_TOKEN` do not trigger workflows). `gh pr close N && gh pr reopen N`, wait for green, then squash-merge with the PR title as subject.
3. Merging it tags and publishes automatically. Verify afterwards as usual: `gh release view vX.Y.Z`, NuGet index, `docker manifest inspect`.
4. If publish fails after the tag exists: fix the workflow on `main`, then `gh workflow run release.yml --ref main -f version=X.Y.Z -f tag=vX.Y.Z` to re-publish that tag.
5. Org setting "Allow GitHub Actions to create and approve pull requests" is now on (org level; the repo-level box is governed by it).

Open: Markdig #60 after 2026-10-04; rubric option C (3.1 design); Jon corpus (email sent 2026-09-25, awaiting reply); dotnet/runtime #134655 (filed).

**Addendum 2026-09-25 (upstream regex bug, triaged):** the area owner for `System.Text.RegularExpressions` replied
to dotnet/runtime#134655 the same day: our case is fixed by dotnet/runtime#129628, "Fix compiled/source-generated
lazy loop stack unwinding when giving up at max iteration", which closed dotnet/runtime#129511. Its summary matches
both symptoms we saw, the `IndexOutOfRangeException` and the incorrect match, when backtracking out of a lazy loop
that reached its upper bound.

**The fix is .NET 11 only.** It merged to `main` on 2026-06-19 under milestone 11.0-preview6, and there is no
backport in `release/10.0` (checked every PR into that branch on 2026-09-25). We target `net10.0` and ship on SDK
10.0.401, so the bug is live for us and for every consumer of the tool and the image.

**Therefore: do not revert the workaround.** The explicit-optional-group rewrites in `InjectionPatterns.cs`, the
`RegexEngineIntegrityTests` hygiene guard (no `){n,m}?` in any shipped pattern) and its engine-consistency companion
stay until this project moves to .NET 11, regardless of the upstream issue being closed as a duplicate. A comment
asking whether the fix will be serviced into .NET 10 is on the issue; if the answer is yes, the guards can relax
only once the servicing release is the minimum supported SDK.
