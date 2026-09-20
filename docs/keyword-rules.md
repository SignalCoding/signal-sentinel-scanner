# Keyword Rules (v3.0.0)

Signal Sentinel's detection is pattern-based, not keyword-based: every rule
requires a *shaped* match (an imperative plus a dangerous verb, a covert verb
near a conditional trigger, a URL adjacent to an outbound verb). A small number
of single-token signals remain because they are the canonical spelling of the
attack. This document is the canonical list of those keyword-level signals, the
tokens deliberately pruned, and the industry reference the list was checked
against.

## Retained keyword-level signals

| Token / phrase | Rule | Why it stays |
|---|---|---|
| `ignore (all|any|previous) instructions` | SS-011, SS-012, SS-017 | Canonical prompt-injection payload; near-zero benign use in executable surfaces. |
| Emphasis label `IMPORTANT:` | SS-011 (via `InstructionInjection`) | Label form (all-caps word + colon) heading an instruction is the injection convention. The bare sentence "Important to understand the context." (no colon) does not fire. |
| `system prompt:` / `system:` label | SS-011 | Persona-override convention. |
| `sudo` + privilege verb, `run as root`, `gain root` | SS-011 (`PrivilegeEscalation`) | Privilege escalation in executable text is almost never benign. |
| `without asking/telling/notifying/...` | SS-011, SS-012, SS-017 | Covert-action framing; descriptive prose does not use it. |
| Conditional + covert verb within 120 chars (`if the user says ... silently ...`) | SS-015 (`ConditionalTrigger`) | The two-clause shape is the signal, not either keyword alone. |
| `curl ... -d`, `wget --post`, `requests.post`, `Invoke-WebRequest -Method Post` | SS-014 (`EXFIL-002`) | Concrete outbound-send commands, not keyword mentions. |
| `fetch('https://...')` inside js/ts fenced code or bundled scripts | SS-014 (`EXFIL-005`) | An executable fetch to an external URL is a real call site. |

## Pruned tokens (v3.0.0, WP12)

| Token / phrase | Removed from | Rationale |
|---|---|---|
| `when the user asks/says/mentions ...` | SS-015 `ConditionalTrigger` alternation | Canonical routing phrasing used across every orchestrator's platform skill descriptions; fired on ordinary skills even with the covert-verb requirement. |
| `fetch(` in prose / markdown body | SS-014 `NetworkUtilSend` | Describing an API call in prose is normal documentation. The pattern now lives in `EXFIL-005` and is evaluated only inside js/ts-family fenced code blocks (`js`, `jsx`, `mjs`, `cjs`, `ts`, `tsx`, `mts`, `cts` and their long forms) and bundled scripts, using the v3.0.0 document segments. |
| bare `must` / `should` / `always` / `never` | SS-011 (tightened in v2.4.0) | Modal verbs are documentation tone. They only fire when combined with a dangerous verb in the same clause (`MUST override`, `ALWAYS execute`). This predates v3.0.0 and is recorded here for completeness. |
| bare `fetch` / `curl` / URL tokens | SS-011/SS-014 (tightened in v2.4.0) | A bare URL or tool name is not an exfiltration signal; the outbound-verb patterns require an adjacent URL or send flag. Also predates v3.0.0. |

## Industry reference and its current status

ROADMAP v3.0 (T1.3) originally targeted alignment with the token set from
Snyk's agent-scan "Dangerous Words" risk indicator (the pre-0.5.x issue-code
list: `important`, `crucial`, `critical`, `vital`, `urgent`, `ignore`,
`disregard`, `override`, `bypass`).

**That reference has been withdrawn upstream.** Snyk removed the Dangerous
Words risk from Agent Scan in PR #479 ("feat: remove Dangerous Words risk from
Agent Scan", commit `692440b8`, September 2026); the current agent-scan issue
codes no longer include it. The upstream rationale matches our production
experience: single-word emphasis tokens are too noisy to act on.

### Deviation from the original alignment plan

Because the reference was retracted, v3.0.0 does **not** add the
`CRUCIAL:` / `CRITICAL:` / `VITAL:` / `URGENT:` emphasis-label alternatives to
`InstructionInjection`. Adding four new High-severity keyword labels would
expand the false-positive surface immediately after v3.0.0's segmentation work
(WP10) reduced it, in pursuit of a heuristic its originator has since deleted.
The existing `IMPORTANT:` label match is retained: it was already in place, is
case-insensitive, requires the colon (label form), and has produced no
false-positive reports.

The pruning half of T1.3 is implemented as planned: `when the user asks`,
prose-level `fetch(`, and bare `must` (already absent since v2.4.0) no longer
fire anywhere.

## Invariants locked by tests

`tests/SignalSentinel.Scanner.Tests/SkillRules/SkillPatternAccuracyTests.cs`
and `tests/SignalSentinel.Scanner.Tests/SharedPatterns/` encode every row
above as executable cases (production-observed false positives stay silent;
canonical payloads keep firing). Any change to these tokens must update both
the tests and this document.
