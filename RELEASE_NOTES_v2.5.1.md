# Signal Sentinel Scanner v2.5.1

**Release date:** 2026-08-11
**Positioning:** false-positive remediation patch for the Agent Skill scanning rules.
**Theme:** regex/logic precision fixes, informed by a real-world review of 65 production Claude skills.

## Background

A real-world review ran Signal Sentinel Scanner offline against 65 production Claude
skills (60 from a private skills repository, 5 personal). The scan produced **Grade F,
584 findings, 84 Critical** - but after manual review, **none of the 584 findings were
an actual vulnerability**. Of the 584:

- 489 were false positives (injection, exfiltration, credential, hidden-content, and
  obfuscation categories).
- 65 were accurate and useful (missing skill-integrity artifacts, which led the reviewer
  to discover 5 skills that were outside version control entirely).
- 30 were accurate and intentional (9 scheduled-task/persistence findings, 21
  subprocess-use findings) - correctly-behaving true positives that required human
  confirmation of intent, exactly as designed.

Every specific technical claim in the report was independently verified against the
rule source before any fix was written - each has an exact, confirmed root cause. The
reviewer also confirmed that `--min-confidence` tuning could not have filtered these
findings: they were all scored 0.85-0.9, above any reasonable confidence threshold.
Confidence-based filtering is not a substitute for rule precision; this release fixes
the rules themselves.

## Fixes

- **Bare `.env` filename mentions** (`CredentialPatterns.SecretFileAccess`,
  `InjectionPatterns.SensitiveFileAccess`) - 52 of 56 credential-access findings in the
  review were the literal string `.env` mentioned in documentation prose ("store your
  key in a `.env` file"), not an actual file access. Both patterns now require an
  access verb or call (`cat`/`source`/`read`/`load_dotenv(`/`dotenv.config(`/etc.).
  These are two separate detection paths over the same skill content and both carried
  the identical bug.
- **Shebang lines matching file-system-traversal** (`SkillScriptPayloadRule.
  FileSystemTraversal`) - 170 of 240 script-payload findings were bare
  `#!/usr/bin/env ...` shebang lines matching the traversal check's bare `/usr/`
  fragment. The shebang line is now stripped before pattern matching (it is never
  itself meaningful evidence for any of the script-payload checks).
- **Bare `<meta>` tag flagged as dangerous HTML** (`SkillHiddenContentRule.
  DangerousHtmlTag`) - `<meta charset="UTF-8">` and similar ordinary tags were flagged
  Critical. Only `<meta http-equiv>` (a genuine hidden-redirect/refresh vector) is now
  flagged; it has its own dedicated check.
- **Bare "exfiltrate"/"siphon"/"smuggle"** (`InjectionPatterns.DataExfiltration`) - a
  skill's own anti-exfiltration guidance was flagged Critical for containing the word
  "Exfiltrate" with no surrounding context. These verbs are now folded into the same
  object+destination-gated verb list as every other outbound verb in the pattern.
- **`.profile` matching inside property access** (`SkillScriptPayloadRule.
  PersistenceMechanism`) - `resp.profile` (a JS property access) matched the
  persistence-mechanism check's `.profile` fragment with no word boundary. A negative
  lookbehind now requires the dotfile name not be preceded by a word character.
- **`Function(` matching inside ordinary identifiers** (`ObfuscationPatterns.
  DynamicExecution`) - `someFunction(x)` matched the bare `Function(` alternative with
  no eval/exec/Function-constructor actually present. A negative lookbehind now
  excludes matches preceded by a word character. The "Dynamic Code Execution" finding
  in `SkillScriptPayloadRule` also never populated its `Evidence` field at all - fixed
  alongside the regex.
- **Single zero-width character matching legitimate emoji** (`InjectionPatterns.
  HiddenContent`) - a lone zero-width joiner (common in ordinary emoji ZWJ sequences)
  was flagged as hidden content. The pattern now requires a cluster of 2+ consecutive
  zero-width characters, matching the already-correct threshold used elsewhere in the
  codebase (`ObfuscationPatterns.ZeroWidthCharClusters`).

All fixes are regex/logic tightenings against existing rules; no rules were removed and
no detection capability for real attack patterns was intentionally given up. Each fix
ships with regression tests encoding the exact reported scenario (both the false
positive and a genuine-intent counterpart that must still fire).

## Quality bar

- 452 tests passing (up from 422 in v2.5.0), including 25 new regression tests locking
  in this release's false-positive kills.
- 0 warnings, 0 errors with `TreatWarningsAsErrors`.
- 32 security rules total (unchanged from v2.5.0 - this is a precision patch, not a
  feature release).

## Backward compatibility

- No operator-visible breaks to report shapes, CLI flags, or schemas.
- Scans against skills that genuinely exhibit the fixed patterns (real `.env` access,
  real exfiltration intent, real dynamic code execution, etc.) continue to produce the
  same findings; only the false-positive-prone bare-substring matches were removed.
- A small number of existing tests were updated where they asserted the old,
  overly-broad behaviour as a passing case (e.g. bare `.env` matching, a single
  zero-width character firing); their inputs were adjusted to the corrected contract.

## Upgrade

```bash
dotnet tool update --global SignalSentinel.Scanner
```

## Acknowledgements

Thank you to the real-world reviewer who ran the scanner against 65 production skills,
reported the false-positive rate candidly rather than silently working around it, and
offered raw JSON output plus the same 65-skill corpus as an independent regression
baseline. That corpus request is being followed up on separately from this release.
