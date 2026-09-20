# Handover: Signal Sentinel Scanner v3.0.0 (Droid → Claude Code)

**Written:** 2026-09-20 by Droid (Factory). Owner: Durgan Cooper.
**Repo:** `C:\sites\sentinel-scanner` → `https://github.com/SignalCoding/signal-sentinel-scanner.git`, default branch `main`.
**Read next:** `AGENTS.md` (operating manual), `_docs/ai/configuration.md`, this file, then the two documents in section 2.

The owner has granted standing authority to work unattended: create branches, open PRs, merge them when CI is green, and self-validate when no validator sub-agent is available. Never push tags (human task). Never force-push or rewrite `main`.

---

## 1. Where the project is

- **v3.0.0 is complete and merged to `main`** (`ceee019` release merge; `b0d7327` docs; `3e5587f` smoke record). 47 rules, **1131 tests**, build 0 warnings / 0 errors. `--version` prints `v3.0.0 (rubric v2.0.0)`.
- **Tag `v3.0.0` has NOT been pushed.** The owner decided to fix the smoke-test defects first (section 3) and ship them inside 3.0.0.
- `release/v3.0` branch exists at `5b23aae` for 3.0.x patches (not needed while 3.0.0 is untagged; patches go straight to `main`).
- Spec and work-package history for the whole release: `_docs/ai/completed/2026-09-20_v3.0-release.md` (WP1–WP14 with "As implemented" notes and the Dependabot outcome table).

## 2. Documents you must read

1. `_docs/ai/completed/2026-09-20_v3.0.0-smoke-test.md` – the pre-tag smoke test: targets, grades, and **defects D1–D12** with file:line and proposed fixes.
2. `_docs/ai/specs/v3.0.0-smoke-fixes.md` – the approved spec for fixing D1–D7, D10, D12 (D8, D9, D11 deferred). Work item table with files and tests.

## 3. Current task: smoke-fix branch `fix/v3-smoke-defects`

Branch created from `main` @ `3e5587f`. Target: one PR to `main`, merge when CI green, then re-run the smoke matrix and update the smoke record, then archive the spec to `_docs/ai/completed/2026-09-20_v3.0.0-smoke-fixes.md`.

### 3.1 Status per work item (update this table as you go)

| Id | Item | Status | Notes |
| --- | --- | --- | --- |
| D1 | Client requests `McpProtocolVersions.Current`, fallback retry | **in progress** | `McpTransport.cs`: `Fallback = "2025-06-18"` constant added. `McpConnection.InitializeAsync` (~line 561) still hard-codes `"2024-11-05"`. |
| D2 | `--remote` → `StreamableHttp` | pending | `Program.cs` ~line 910: `McpTransportType.Http` → `StreamableHttp`. |
| D3 | Notifications carry `Mcp-Session-Id` | pending | `McpConnection.SendNotificationAsync` ~line 643 posts directly; factor a `CreateHttpPost(json)` used by `SendHttpRequestAsync` (~line 878) too. |
| D4 | Inconclusive when zero servers connected | pending | `Program.cs` ~line 1219 `evaluableServers = serverEnumerations.Count + …` → count `ConnectionSuccessful` only. Update `SeverityScorer.GetGradeDescription` Inconclusive text. |
| D7 | Detect legacy HTTP+SSE endpoint | pending | Design: in `SendHttpRequestAsync`, when `initialize` gets 405/404, GET same URL with `Accept: text/event-stream`, `ResponseHeadersRead`, dispose immediately; if content-type is `text/event-stream` throw new `LegacySseEndpointException` (new file next to `NonMcpEndpointException.cs`). `ToolEnumerator.EnumerateServerAsync` catches it → `ServerEnumeration.LegacySseEvidence` (new record). `LegacyMcpProtocolRule` emits **Medium** "Legacy HTTP+SSE Endpoint Not Scanned" for it (rule currently `continue`s on `!ConnectionSuccessful`; add the evidence branch before that). |
| D12 | Arg errors exit 2, no help dump | pending | `Program.ParseArguments` returns `null` for both `--help/--version` and errors. Plan: add `bool ArgumentError` to `Config/ScanConfig.cs`, a static sentinel `InvalidArguments`, replace every error-path `return null;` in `ParseArguments` (all except lines ~157 `--help` and ~161 `--version`) with `return InvalidArguments;`; in `Main`: `if (config.ArgumentError) return 2;`. Post-loop private-address refusals (~556–573) included. |
| D5 | INJECTION-001 defensive phrasing | pending | `src/SignalSentinel.Core/Security/InjectionPatterns.cs:103`. Don't match `never returns/reveals/sends/exposes …` (third-person negated). Keep imperative "NEVER return the system prompt". |
| D6 | SS-008 tightening | pending | `src/SignalSentinel.Scanner/Rules/SensitiveDataRule.cs`. (a) bare `token` needs qualifier; (b) Critical only with disclosure verb in same non-negated sentence, else High; (c) PII: drop `user`, `client`, `account`, `query`, `read`. Learn matched on "user's query"; HF `hf_whoami` on "credential"; Chainflip on "token". |
| D10 | Resources advertising credentials | pending | `Rules/ResourcePoisoningRule.cs`. Apply sensitivity/credential keywords to resource name/URI/description; URI segments `credentials|secrets|passwords|tokens` → High. DVMCP ch1/ch4 `internal://credentials` must fire. |
| Fixtures | Regression corpus from live `tools/list` | pending | Capture Learn, HF, Chainflip, DeepWiki tool lists as JSON under `tests/SignalSentinel.Scanner.Tests/Fixtures/RemoteToolLists/`; DVMCP ch2/6/8 via stdio. Assert clean servers get no Critical / grade ≥ B; DVMCP keeps its Criticals. |
| Validation | build, tests, smoke re-run, record, CHANGELOG | pending | See section 5. |

### 3.2 Things already decided (don't re-litigate)

- Request `Current` (2026-07-28) in `initialize`; a compliant server answers with its own highest version, so SS-INFO-004 then reflects the *server's* ceiling. If the server returns a JSON-RPC error to `initialize`, retry once with `Fallback`. Send `MCP-Protocol-Version: <negotiated>` on later HTTP requests.
- D7 is detection only for 3.0.0. Full legacy SSE transport (GET stream, `endpoint` event, POST `/messages/?session_id=`) is a follow-up.
- Findings for unreachable / 401 / non-MCP / legacy-SSE servers stay in the report; only the grade changes to Inconclusive.
- Do not touch `.gitignore` in this PR (note: `[Ll]ogs/` on line 30 also ignores `_docs/ai/logs/`, which AGENTS.md says should be versioned; separate one-line PR).

## 4. Repo conventions (learned the hard way)

- **Commits:** Conventional Commits, one logical change per commit, trailer `Co-authored-by: factory-droid[bot] <138933559+factory-droid[bot]@users.noreply.github.com>` (keep it for continuity or switch to Claude's; ask owner). Write the message to `.git/COMMIT_MSG_<slug>.txt` and `git commit -F` (PowerShell mangles multi-line `-m`).
- **PRs:** `gh pr create --base main --body-file .git/PR_BODY_<slug>.md`; wait ~2.5 min; `gh pr checks <n>`; merge with `gh pr merge <n> --squash --delete-branch --subject "type(scope): title (#n)"` for feature/docs branches. (The release itself used `--merge` to keep history.) CI: Build & Test ×3 OS, Code Quality, Security Scan, Docker Build Test, CodeQL ×3.
- **Stage named files only** (`git add <paths>`); untracked `.claude/` and `docs/archive/` are the owner's, leave them alone.
- **PowerShell gotchas:** `$args` is reserved (don't use as a variable); pipe to `Out-String` before `.Substring`; `$LASTEXITCODE` before any pipeline; `git grep` excludes need `':(exclude)_docs'`.
- **Build/test:** `dotnet build -c Release` (must be 0 warnings, `TreatWarningsAsErrors` on), `dotnet test` (~1131 tests, ~1 min). Test project has `InternalsVisibleTo`; packages xunit 2.9.3, Shouldly, NSubstitute 5.3, FsCheck. No HTTP fake-server helper exists yet; use `System.Net.HttpListener` on loopback if you need one (remember `OfflineGuard`).
- **Files that must agree on the version** (release-management rule): `Directory.Build.props`, both `.csproj` (`PackageReleaseNotes`), `deploy/docker/Dockerfile.scanner` label, `README.md` badge, `INSTALLATION_AND_USAGE.md`, `CHANGELOG.md`, `hooks/.pre-commit-hooks.yaml` `rev:`. Currently all 3.0.0.
- **CHANGELOG.md** follows Keep a Changelog; add fix entries under `[3.0.0]` (unreleased tag) rather than a new version.
- Binary after build: `src\SignalSentinel.Scanner\bin\Release\net10.0\SignalSentinel.Scanner.exe`.

## 5. How to reproduce the smoke matrix

Scratch dir `%TEMP%\v3-smoke\` (may not survive). Helper: `scan-remote.ps1` runs `SignalSentinel.Scanner.exe --remote <url> --format json -o <file>` and prints exit/grade/finding ids.

- Public: `https://learn.microsoft.com/api/mcp`, `https://mcp.deepwiki.com/mcp`, `https://huggingface.co/mcp`, `https://gitmcp.io/docs`, `https://mcp.context7.com/mcp`, Chainflip, Roundtable, SpaceMolt (stateful; exposes D3).
- OAuth 401: `https://mcp.linear.app/mcp`, Notion, Asana, Egnyte, Sentry, Atlassian, `https://api.githubcopilot.com/mcp/`.
- A2A: `--agent-card https://www.agentcard.net`, `https://agent2agent.info`.
- DVMCP lab: clone `https://github.com/harishsg993010/damn-vulnerable-MCP-server` to `%TEMP%\v3-smoke\dvmcp`; pin `mcp>=1.6,<2` in `requirements.txt` (upstream is unpinned and breaks on mcp 2.x); `docker build -t dvmcp .`; `docker run -d --name dvmcp -p 127.0.0.1:9001-9010:9001-9010 dvmcp`. Legacy SSE endpoints `http://127.0.0.1:900N/sse` (N=1..9) need `--allow-private`. Stdio config: each server is `docker exec -i dvmcp python -c "import sys; sys.path.insert(0,'/app/challenges/<tier>/<challengeN>'); import server; server.mcp.run(transport='stdio')"` (tiers: easy 1–3, medium 4–7, hard 8–10; challenge 5 uses `combined_server` and fails to import under mcp 1.x). Source scan: `--server-source <clone>\challenges --offline` → expect SS-041 ×12.
- Offline refusals: `--remote … --offline`, `--skills … --osv --offline`, `--agent-card <url> --offline` all exit 2; `--remote http://127.0.0.1:9001/mcp` without `--allow-private` should exit 2 after D12.
- Expected after fixes: no SS-INFO-004 on Learn/DeepWiki (they answer 2025-06-18 — still < Current, so SS-INFO-004 *will* still fire but now truthfully; check wording), SpaceMolt connects, HF/Chainflip no SS-008 Critical, DVMCP `/sse` targets → Inconclusive + Medium legacy-SSE finding, DVMCP ch1/ch4 resources flagged.

## 6. Human follow-ups (owner)

1. Push tag `v3.0.0` once the smoke fixes are merged and the matrix re-run is clean.
2. Seven green Dependabot PRs on `main`: #53 (NetAnalyzers 10.0.401), #34 (YamlDotNet 16→18, runtime, review), #29, #21, #20, #19, #17. Dependabot self-closed #35, #33, #18 (codeql-action v4; `release.yml:188` still uses `upload-sarif`) — re-trigger via Insights → Dependency graph → Dependabot → "Check for updates".
3. Jon's feedback (65-skill corpus): v2.5.1 addressed the skill-rule FPs; the MCP tool-description rules (SS-008, SS-001) are being fixed in this branch. Offer him a re-run afterwards.
4. GitHub repo description → roadmap positioning.

## 7. Backlog (not started)

Parse errors exit 0 (fixed by D12 if done); Markdown evidence backtick escaping; `McpConnection` `GetInt32`→`TryGetInt32`; stdio EOF hot loop and "timeout" reported for immediate exit (D11); `0.0.0.0/8` in `RemoteUrlPolicy`; exact NuGet pins; `SanitizeErrorMessage` path/quote mangling; `ScanContext.Policy` seam; N-skills duplicate OSV queries; OSV status counts; `Servers Scanned` stat; same-line segment sort; `tests/**/*.md text eol=lf`; EXFIL-005 magic-string id; `node` fence alias; `{}` rubric claiming "2.0.0"; rubric grades C at score 0 with many Highs; SS-020 metadata quality (D8); SS-042 exception type in text (D9); full legacy HTTP+SSE transport.
