# Changelog

All notable changes to Signal Sentinel Scanner are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-09-20

v3.0.0 bundles the Review #1 hardening fixes, all fourteen items from the external
research report (Tiers 1-3), and ROADMAP Theme 1 (accuracy). Twenty-two new rules
(SS-030..SS-042, SS-INFO-005, SS-INFO-006), five new scan flags, a versioned scoring
rubric, and a markdown-aware segmentation pass that materially reduces false
positives on skill documents.

### Added

- **MCP surface coverage (SS-030..SS-033, SS-INFO-005)**: injection scanning of prompt
  and resource descriptions, server `instructions` (including cross-server steering
  directives), unsolicited server-initiated requests (`sampling/*` Critical,
  `elicitation/*`/`roots/*` High), and a per-server capability summary
  (`tools.listChanged`, `experimental`, `completions`, ...). Enumeration now captures
  server instructions, unsolicited requests (declined with JSON-RPC -32601 where the
  transport allows), and protocol error bodies for rule input.
- **Skill forensics (SS-034, SS-035)**: `SHA256SUMS` verification and `skill.oms.sig`
  recognition, plus a bounded magic-byte file-artefact walk flagging mismatched or
  hidden binaries, archives, double extensions, orphan `.pyc`, and executable-bit files.
  Script inventory now covers `.rb .pl .php .lua .bat .cmd .zsh .vbs`.
- **Homoglyph and shadowing detection (SS-036, SS-037)**: UTS #39-style confusable
  analysis of tool/prompt/resource/server/skill names (skeleton collisions, invisible
  characters, disallowed script mixing) and pairwise description-overlap detection for
  marketplace-skill impersonation.
- **Fetch-to-exec taint (SS-038)**: line-oriented pipeline analysis over Bash, Zsh,
  PowerShell, Python, JS/TS and fenced code blocks - direct and base64-encoded
  curl-to-shell flows (Critical) and variable-mediated flows (High), including
  embedded-payload flows with no network source.
- **Skill dependency vulnerability lookup (SS-039, SS-INFO-006, `--osv`)**: opt-in
  osv.dev querybatch for pinned pip/npm/manifest dependencies with CVSS-banded
  severity and CVE-alias dedup; an Info finding lists the unchecked surface when
  `--osv` is absent, offline, or fails. Refused under `--offline`.
- **Tier-3 surfaces (SS-040..SS-042)**: error-channel/result-channel injection
  heuristics (including captured JSON-RPC error bodies), `--server-source <dir>`
  static pass over MCP server JS/TS/Python for dangerous sinks near tool
  registrations, and `--agent-card <url|path>` A2A Agent Card evaluation. Claude Code
  hook configurations (`SessionStart`/`PreToolUse` etc.) are parsed as a scan surface.
- **Policy presets (`--policy`)**: `default`, `strict` (supply-chain rules one band
  up, fail-on medium) and `defence` (everything one band up, fail-on low, implies
  `--offline`), or a JSON file with `severityOverrides`, `disabledRules`,
  `bumpOneBand`, `bumpAllOneBand`, `failOn`, `minConfidence`, `offline`.
- **Discovery breadth**: Claude Code (`~/.claude.json`, `.mcp.json`), Gemini CLI,
  OpenCode, VS Code / Copilot, Copilot for JetBrains, Amazon Q and `.cursor/mcp.json`
  config shapes; skill discovery across `.gemini`, `.opencode`, `.github`, `.factory`,
  `.agents` and the Claude plugin cache.
- **Scoring rubric v2.0.0 (`--rubric`)**: deductions, grade rules and grade thresholds
  now live in an embedded, versioned, validated rubric file
  (`Scoring/scoring-rubric-v2.0.0.json`); `--rubric <path>` substitutes a custom
  rubric (invalid rubrics fail closed, exit 2). `RubricVersion` is emitted in every
  report. Weights are unchanged from v2 - the rubric makes them auditable, not
  different. Monotonicity is locked by FsCheck property tests.
- **`--allow-private`**: permits `--remote` targets on loopback/RFC1918/link-local
  addresses; the SSRF block stays on by default and SS-INFO-002 still discloses the
  posture. DNS rebinding remains a documented residual.
- `CONTRIBUTING.md` (build, test, Conventional Commits, branch/PR flow).

### Changed

- **Markdown-aware segmentation (skill rules)**: skill documents are parsed into
  frontmatter/prose/fenced-code/inline-code/link/HTML segments (Markdig) and each
  skill rule evaluates only the segments where its signal is meaningful. Injection
  payloads inside code examples, credential references in inline code, and capability
  words in fenced examples no longer fire. **`SS-026` skill-side now evaluates
  frontmatter only** - instructional phrasing in the skill *body* is normal and no
  longer reported; the MCP tool-description side is unchanged.
- **Keyword pruning**: `when the user asks/says/mentions ...` was removed from the
  SS-015 conditional-trigger pattern (canonical routing phrasing), and prose-level
  `fetch(` no longer fires SS-014 - a new `EXFIL-005` pattern fires only inside
  js/ts-family fenced code blocks and bundled scripts. See
  [docs/keyword-rules.md](docs/keyword-rules.md) for the full retained/pruned list.
- **`enabled: false` is honoured in every discovered config shape** (WP8): disabled
  server entries are now skipped rather than scanned. If your CI relied on scanning
  disabled entries, re-enable them or pass explicit configs.
- Report `RubricVersion` moves from `1.0` to `2.0.0`.
- Test-only dependencies pinned to exact versions; dead strong-naming block removed
  from `Directory.Build.props`.
- **Grade `Inconclusive` when nothing was assessed**: a scan where no server
  connected (HTTP 401, transport failure, legacy SSE endpoint) and no skills were
  scanned now grades Inconclusive / 0 instead of A / 100. Findings that were still
  produced (SS-020, SS-INFO-*) are retained.
- **`--remote http(s)://` is reported as `StreamableHttp`** rather than the legacy
  `Http` transport, matching what the client actually speaks.
- **Argument and policy rejections exit 2** (was 0 with the full help text). Covers
  every `ParseArguments` error path, including the `--remote` private-address
  refusal without `--allow-private`. `--format` with an unknown value is now one of
  those rejections rather than a silent fall-back to Markdown.
- **`--version` prints the version line only** (it used to be followed by the full
  usage text).

### Fixed

Pre-tag smoke test against live MCP servers and the DVMCP lab
(`_docs/ai/completed/2026-09-20_v3.0.0-smoke-test.md`) surfaced the following:

- **`initialize` requested `2024-11-05`** so every server echoed it back and
  SS-INFO-004 "negotiated legacy version" fired on all of them. The client now
  requests the current protocol version, retries once with `2025-06-18` on a
  protocol-level rejection, and records the server's actual ceiling.
- **`notifications/initialized` was sent without `Mcp-Session-Id`**, so stateful
  Streamable HTTP servers rejected `tools/list` with "Session not initialized".
  Notifications now use the same request builder as requests.
- **Legacy HTTP+SSE endpoints (`GET /sse`) were reported as "Non-MCP" and graded
  A / 100.** The client now detects `text/event-stream` on GET after a 405/404 on
  POST and reports SS-INFO-004 Medium "Legacy HTTP+SSE Endpoint Not Scanned" with
  an Inconclusive grade. Full legacy SSE transport is not implemented in 3.0.0.
- **SS-001 (INJECTION-001) matched defensive prose** such as "never returns
  credential values": the modal-verb alternative now requires a word boundary.
- **SS-008 Credential/PII Access false positives** on clean public servers (Hugging
  Face `hf_whoami`, Chainflip swap tools, Learn `microsoft_docs_search`). The rule
  is now sentence-scoped: explicit negation ("never returns credentials") suppresses
  it, a disclosure verb next to a credential noun is Critical, "API key is
  optional"-style consumption context is skipped, and PII requires a person word
  and a store word in the same sentence. `query`, `read`, `user` and `account` were
  dropped as bare keywords. Live `tools/list` captures from four public servers are
  kept as regression fixtures.
- **SS-031 ignored resources that advertise credentials** by name, URI or
  description (`internal://credentials`, "DO NOT SHARE"). New High "Resource
  Advertises Credential Material" and Medium "Resource Marked Confidential or
  Restricted" findings; DVMCP challenges 1, 3, 4 and 10 are now flagged.

### Security

- Review #1 hardening batch: SSRF default-block retained behind explicit
  `--allow-private`, supported-versions table corrected (3.0.x supported, 2.5.x
  security fixes only), `openclaw-*` scan artefacts and packed `*.nupkg` excluded
  from git.

## [2.5.1] - 2026-08-11

(back-filled summary; full notes in `RELEASE_NOTES_v2.5.1.md`)

False-positive remediation patch for the skill-scanning rules, informed by a
real-world review of 65 production Claude skills. Regex/logic tightenings only; no
rule removed. Each fix ships with a false-positive regression test and a
genuine-intent counterpart.

- Bare `.env` mentions no longer fire `CredentialPatterns.SecretFileAccess` /
  `InjectionPatterns.SensitiveFileAccess`; an access verb or call is required.
- `#!` shebang lines are stripped before `SS-016` script-payload matching.
- `SS-018` flags only `<meta http-equiv>`, not ordinary `<meta>` tags.
- Bare "exfiltrate"/"siphon"/"smuggle" join the object+destination-gated verb list.
- `.profile` and siblings require a non-word lookbehind (no `resp.profile` match).
- `Function(` requires a non-word lookbehind (no `someFunction(` match); the
  Dynamic Code Execution finding now populates `Evidence`.
- Hidden-content zero-width detection requires a cluster of 2+ characters.

## [2.5.0] - 2026-08-02

(back-filled summary; v2.5.0 predates this changelog)

- MCP 2026-07-28 spec currency: `SS-INFO-004` flags older `protocolVersion`
  negotiations and legacy HTTP+SSE-only servers; `SS-020` discloses the RFC 9207 /
  DCR→CIMD verification gap.
- `SS-029` Skill Unpinned Dependency Reference - floating-branch and unpinned
  `git+https://` dependency references (the "SkillJacking" vector).
- Universal Skill Format fields: `risk_tier` recognition on `SS-017` and
  `permissions.deny_write` recognition on `SS-028`.
- Fixed dotted-key frontmatter parsing (`network.allow`, `permissions.deny_write`).

[3.0.0]: https://github.com/SignalCoding/signal-sentinel-scanner/compare/v2.5.1...v3.0.0
[2.5.1]: https://github.com/SignalCoding/signal-sentinel-scanner/compare/v2.5.0...v2.5.1
[2.5.0]: https://github.com/SignalCoding/signal-sentinel-scanner/releases/tag/v2.5.0
