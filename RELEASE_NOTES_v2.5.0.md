# Signal Sentinel Scanner v2.5.0

**Release date:** 2026-07-28
**Positioning:** first-pass authoring aid for MCP operators and skill authors.
**Theme:** MCP specification currency, skill supply-chain verification, and Universal Skill Format field recognition.

> **Note on scope:** this is the first public release since v2.3.0. v2.4.0
> and v2.4.1 were completed but never pushed to `origin/main` or tagged as
> GitHub releases - this document folds all three releases' changes together
> so the public changelog has no gap. See `RELEASE_NOTES_v2.4.0.md`,
> `BACKLOG_V2.4.1.md`, and `BACKLOG_V2.5.0.md` for the detailed per-release
> backlogs.

## Headline changes in v2.5.0

The Model Context Protocol published specification revision `2026-07-28` -
the biggest MCP revision since launch - on the same day this release's
research pass ran. It retires the `initialize`/`initialized` handshake and
`Mcp-Session-Id` session header in favour of a stateless protocol core, adds
Multi Round-Trip Requests, formally deprecates the legacy HTTP+SSE transport
(12-month backward-compatibility window), and hardens OAuth authorization
(RFC 9207 issuer validation, Client ID Metadata Documents replacing Dynamic
Client Registration). v2.5.0 makes the scanner aware of this shift.

Separately, Air Security's July 2026 "SkillJacking" research documented 925
published skills resting on take-able dependencies (deleted GitHub accounts,
expired domains), reaching an estimated 134K agents - including a skills.sh
skill with 11,483 installs hijacked after its upstream account was deleted
and re-registered by an attacker. v2.5.0 pulls the core detection for this
forward from the v3.0 roadmap into a shipped rule.

### MCP 2026-07-28 specification tracking

- **`SS-INFO-004` Legacy MCP Protocol / Transport** (new, Info) - flags
  servers negotiating a `protocolVersion` older than the current
  specification, or reached over the deprecated legacy HTTP+SSE transport.
  A currency notice, not a vulnerability: both keep working through the
  spec's 12-month deprecation window.
- **`SS-020` OAuth Compliance** extended with an advisory finding disclosing
  that the scanner's behavioural auth probe confirms Bearer enforcement but
  does not verify RFC 9207 issuer validation or the DCR→CIMD migration -
  those require an OAuth metadata discovery round-trip the scanner does not
  perform.

### Skill supply-chain: unpinned dependency detection (SkillJacking)

- **`SS-029` Skill Unpinned Dependency Reference** (new, Medium) - detects
  skill instructions or bundled scripts that reference a GitHub dependency
  by a floating branch (`main`/`master`/`head`/`develop`/`dev`/`latest`/
  `trunk`) or an unpinned `git+https://github.com/...` install URL, instead
  of a pinned tag, release, or commit SHA. Covers `github.com` references;
  ETag/change-detection and non-GitHub hosts remain a v3.1.0 target.

### Universal Skill Format field recognition

- **`risk_tier`** - `SS-017` (Skill Excessive Permissions) now cross-checks a
  skill's self-declared risk tier against what it actually observed. A
  `risk_tier: low` skill that also requests unrestricted filesystem/network/
  shell access, or an unconstrained boolean network grant, now produces a
  High-severity "Risk Tier Understated" finding. A skill with no `risk_tier`
  declared at all that exhibits the same signals produces an Info-severity
  nudge to declare one.
- **`permissions.deny_write`** - `SS-028` (Skill Identity/Memory File Write
  Access) now escalates from High to **Critical** when the identity file it
  detected a write to is also listed under the skill's own `deny_write`
  declaration - a direct self-contradiction, not just an undocumented
  capability.
- Fixed a pre-existing `FrontmatterParser` bug where dotted frontmatter keys
  (`network.allow`, `permissions.deny_write`) silently failed to parse from
  real `SKILL.md` files, because the key-matching regex's character class
  excluded `.`. The rule logic that checks for these fields (`SS-017` since
  v2.4.1, `SS-028` in this release) was already correct; the parser simply
  never fed it the data.

## v2.4.1 recap (not previously released)

- **`Inconclusive` grade** for scans with zero scannable surface (zero
  servers, zero skills), replacing a misleading `Grade A`.
- **`SS-INFO-003` Untrusted Server Certificate** (new, Info) - distinguishes
  a TLS handshake failing due to certificate validation from a generic
  connectivity failure, and translates common .NET TLS/connection exception
  text into operator-actionable language.
- **`SS-028` Skill Identity/Memory File Write Access** (new, High) - detects
  skills that write to agent identity/memory files (`AGENTS.md`, `CLAUDE.md`,
  `MEMORY.md`, `SOUL.md`), the persistence technique behind the ClawHavoc
  malicious-skill campaign (Jan-Feb 2026, 1,184 malicious skills).
- **`SS-INFO-001`** extended to also fire on 404-without-JSON-RPC responses
  (not just HTML-200), and the auth probe no longer emits a finding when the
  probe itself failed to complete (`StatusCode == 0`).
- **`SS-026`** extended to evaluate skill frontmatter descriptions and body
  text, not just MCP tool descriptions.
- **`SS-024`** recognises inline `signature`/`content_hash` frontmatter for
  integrity verification; **`SS-017`** recognises a boolean `network:` grant
  as strictly worse than a declared `network.allow` domain allowlist.
- **Canonical skill identity** (`SkillDefinition.CanonicalSkillName`,
  `Finding.CanonicalSkillName`) so `SuppressionManager` and `ScopeManager`
  can no longer disagree about which skill a rule fired on.
- **`ScanResult.SuppressionDelta`** and **`ScanStatistics.ServersProbed`**
  scan-statistics additions.
- Corrected the OWASP Agentic Skills Top 10 `AST05` label in
  `OwaspMapping.cs` to match the real published taxonomy ("Untrusted
  External Instructions", not the previously-invented "Unsafe
  Deserialisation") - see `docs/owasp-ast-mapping.md`.

## Quality bar

- 422 tests passing (up from 395 in v2.4.1, 366 in v2.4.0, 254 in v2.3.0).
- 0 warnings, 0 errors with `TreatWarningsAsErrors`.
- 32 security rules total (up from 27 in v2.4.0).

## Backward compatibility

- No operator-visible breaks. Scoring rubric unchanged; CI gates from prior
  releases continue to behave the same way on identical input.
- Suppression and scope file schemas unchanged.
- JSON / SARIF / Markdown / HTML report shapes remain backwards compatible.
  New optional fields are additive:
  - `Finding.CanonicalSkillName` (nullable string).
  - `ScanResult.SuppressionDelta`, `ScanStatistics.ServersProbed`.
  - `SkillDefinition.DenyWrite` (empty list when not declared).
  - `SecurityGrade.Inconclusive` (new enum member; existing consumers that
    switch exhaustively on `SecurityGrade` should add a case for it).

## Upgrade

```bash
dotnet tool update --global SignalSentinel.Scanner
```

## Example

A skill frontmatter declaring both new Universal Skill Format fields:

```yaml
---
name: read-only-reporter
description: Reads project files and generates a status report
risk_tier: low
network.allow: [api.example.com]
permissions.deny_write: [AGENTS.md, MEMORY.md]
---
```

```bash
sentinel-scan --skills ./skills --format markdown -o scan.md
```
