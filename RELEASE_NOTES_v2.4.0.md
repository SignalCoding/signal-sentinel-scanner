# Signal Sentinel Scanner v2.4.0

**Release date:** 2026-04-20
**Positioning:** first-pass authoring aid for MCP operators and skill authors.
**Theme:** context-aware detection, behavioural probes, and orchestrator-agnostic scope.

## Headline changes

v2.4.0 expands the scanner's semantic reach across both MCP and skill rule
families. With the v2.3 lemma table and YAML-authoritative capability blocks
in place, the rule engine can now ask richer questions: does this tool
description *name a privilege-escalation primitive*, or merely mention the
word "system"? Does it describe an *agent-memory write*, or report *host RAM
usage*? Does a skill *instruct the agent to exfiltrate data*, or merely
mention HTTP?

v2.4.0 also closes a long-standing trust gap: until now, the scanner ran
every rule against every skill and MCP server it could find, even when most
of those targets were disabled at the orchestrator. A library with many
skills on disk but only a handful enabled would produce a failing grade
dominated by findings the agent could never execute. v2.4.0 introduces an
orchestrator-agnostic scope model so grades reflect real attack surface.

### Orchestrator-agnostic scope

- New `.sentinel-scope.json` file (schema v1.0) declares which skills and MCP
  servers are live attack surface at your orchestrator. The scanner does not
  parse orchestrator-native configuration of any vendor; any orchestrator, CI
  pipeline, or human can produce the file.
- Matching CLI flags: `--scope <path>`, `--include-skills <csv>`,
  `--exclude-skills <csv>`, `--include-servers <csv>`, `--exclude-servers
  <csv>`. CLI flags override per-selector when both are supplied.
- Out-of-scope findings are *tagged* `dormant`, not dropped. They still appear
  in every report format under a dedicated "Dormant (not attack surface)"
  section so reviewers can audit why a finding was demoted, but they do not
  contribute to the grade or the summary statistics.
- The scope disclosure block now shows
  `source`, `in-scope` / `dormant` skill counts, and `in-scope` / `dormant`
  server counts.

### Pattern-discipline pass on skill and tool rules

Every phrase-based detector was audited against a representative production
sample of agent skills. The rules that misfired on descriptive prose were
tightened so each finding has a single canonical owner and clear intent:

| Pattern | v2.3.x behaviour | v2.4.0 behaviour |
| --- | --- | --- |
| `InjectionPatterns.InstructionInjection` (SS-001, SS-011) | Fired on bare `MUST`, `ALWAYS`, `IMPORTANT`, `NEVER` + whitespace. | Requires canonical injection phrasing: `IMPORTANT:` labels, override-intent verbs + target noun, modals + override-intent verb, `SYSTEM PROMPT:` markers, role-hijack phrases. |
| `InjectionPatterns.DataExfiltration` (SS-011, SS-014) | Fired on bare `https://`, `fetch(`, `curl`, `POST to`. | Requires an outbound verb + data-object + `to / via / through / at` target, or a network fetcher within 80 characters of an explicit `https?://` URL. |
| `InjectionPatterns.PrivilegeEscalation` (SS-001, SS-011) | Fired on bare nouns `privilege` and `elevate`. | Requires a canonical escalation verb (`sudo`, `as root`, `become root`, `gain root`) or a pinned noun phrase (`elevate privileges`, `privilege escalation`). |
| `ExfiltrationPatterns.HttpDataSend` (SS-014) | Fired on bare `POST to`, `upload to`, `PUT to`. | Requires a data-object before the `to`, or an explicit `https?://` URL immediately after. |
| `SkillObfuscationRule.ConditionalTrigger` (SS-015) | Fired on `if the user says`, `only when`, `only if` - normal skill routing. | Requires a covert-action verb within 120 characters of the trigger phrase (`silently`, `secretly`, `bypass`, `exfiltrate`, `ignore previous`, `do not mention`). |
| `SkillExcessivePermRule.UnrestrictedNetwork` (SS-017) | Fired on bare `any url`, `any endpoint` in descriptive prose. | Requires a request / grant / declaration context (`requires unrestricted network`) or a YAML-style declared-capability form (`network: unrestricted`). |

On the representative production sample this cut the finding count on the
enabled-skills subset by roughly 77% (all remaining findings legitimate) and
lifted the grade from failing to passing.

### Existing v2.4.0 content retained

- **SS-INFO-002 Non-Public Target notice** - surfaces an informational
  finding when the scanner is pointed at a loopback, RFC 1918, link-local, or
  non-public-hostname target. Makes the scope of a scan explicit, and
  automatically exempts transport-posture rules (SS-020) that only make
  sense against a public endpoint.
- **SS-026 Instructional Tool Description** - Medium-severity rule that
  catches tool descriptions written to drive the agent (`you must call this
  first`, `ignore all previous instructions`, `before using any other tool`)
  rather than describe the tool. Both a tool-poisoning signature and a
  skill-authoring anti-pattern.
- **SS-020 behavioural auth probe** - the scanner sends one deliberate
  unauthenticated MCP `initialize` request and classifies the server as
  `enforced` (401 + `WWW-Authenticate: Bearer`), `open` (2xx without auth),
  or `unclear`. Behavioural posture replaces config introspection, so auth
  configured via the v2.3.1 `headers: { Authorization: Bearer ... }` field
  is now recognised alongside `env`-based credentials.
- **Stale suppression detection** - `.sentinel-suppressions.json` entries
  whose `expiresOn` has passed, or which no longer match any finding in the
  current scan, are reported as warnings. Keeps the suppression list honest.

## Detector upgrades

| Rule | Upgrade |
| --- | --- |
| SS-008 Sensitive Data | Distinguishes public TLS material (certificate, CA bundle, public key) from secret credential material (private key, password, API key, bearer / access / refresh token, client secret, vault secret). Tools like `tls_expiry` and `get_certificate` are now correctly classified. |
| SS-002 Overbroad Permissions | Phrase-based privilege-escalation detector. Recognises `root access`, `sudo`, `su -`, `setuid`, `admin privilege`, `privilege escalation`, `elevated token`, `runas administrator`, `root shell`, `impersonate`. |
| SS-005 Code Execution | Phrase-based code-execution detector. Recognises concrete primitives (`eval(`, `exec(`, `Runtime.exec`, `Process.Start`, `os.system`, `subprocess.`, `shell -c`, `bash -c`, `PowerShell -Command`, `cmd.exe /c`) and `runs arbitrary code` phrasing. |
| SS-006 Memory Write | Agent-memory vocabulary (long-term memory, conversation history, episodic / semantic memory, working memory, knowledge base) distinguished from host-resource vocabulary (memory usage, `/proc/meminfo`, heap, swap). Vector store coverage extended to Chroma, FAISS, Pinecone, Weaviate, Qdrant, Milvus, pgvector. |

## Quality bar

- 366 tests passing (up from 315 in the v2.4.0 RC; up from 254 in v2.3.0).
- Includes 16 new scope-manager tests and a substantial skill-pattern-accuracy
  regression suite that locks in the observed production false-positive
  kills so they cannot regress.
- 0 warnings, 0 errors with `TreatWarningsAsErrors`.
- 27 security rules total (was 26).

## Backward compatibility

- No operator-visible breaks. Scoring rubric unchanged; CI gates from v2.3
  continue to behave the same way on identical input.
- Suppression file schema unchanged (`version: "1.0"`).
- JSON / SARIF / Markdown / HTML report shapes remain backwards compatible.
  New optional fields are additive and nullable:
  - `Finding.Scope` (nullable string; `"dormant"` when out of scope).
  - `ScanScope.ScopeSource`, `ScanScope.InScopeSkills`,
    `ScanScope.DormantSkills`, `ScanScope.InScopeServers`,
    `ScanScope.DormantServers` (empty / null when no scope configured).

## Upgrade

```bash
dotnet tool update --global SignalSentinel.Scanner
```

## Example

Declare scope for an orchestrator with an allowlist of enabled skills:

```json
{
  "version": "1.0",
  "source": "my-orchestrator",
  "skills": {
    "include": [
      "skill-one",
      "skill-two",
      "skill-three"
    ]
  }
}
```

```bash
sentinel-scan --skills ./skills --scope ./.sentinel-scope.json \
  --environment prod --output scan.md
```
