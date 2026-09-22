# Lesson: skill rules were tuned token-by-token against one corpus and never re-validated on another

**Date:** 2026-09-21. **Trigger:** post-release validation of v3.0.0 against Anthropic's public skills repo (19 skills) graded **F / 0 with 4 Critical**, every Critical a false positive. Record: `_docs/ai/completed/2026-09-21_v3.0.0-skill-corpus-smoke.md`.

## What went wrong

Jon's 65-skill review (pre-2.5.1) produced ~489 false positives. v2.5.1 and v3.0.0 (WP10/WP12) fixed the
specific tokens that corpus surfaced - bare `.env`, shebangs, `<meta>`, `fetch(` in prose, "when the user
asks" - each with a regression test. Those fixes hold. But the underlying rules (SS-011, SS-014, SS-015,
SS-016, SS-018) remained context-blind substring matches, so a different real-world corpus tripped different
tokens of the same class: `in**put file to**`, "API-key" in prose, `IMPORTANT:` alone, `/tmp/`, `<script>`
inside a fenced example, `RegExp.exec(`. Two plain bugs also surfaced (no YAML block-scalar parsing in
`FrontmatterParser`; the SS-018 zero-width finding fired on HTML comments) because no real SKILL.md had ever
gone through those code paths in a test.

## Cost

Three fix batches (2.5.1, WP10, WP12) across multiple sessions, then a fourth (3.0.1) immediately after a
major release; the product shipped 3.0.0 grading its own reference corpus F.

## Root cause

1. The pattern-shaped defect (context-blind matching) was fixed incrementally per reported token instead of
   comprehensively per rule. AGENTS.md "Pattern Detection -> Comprehensive Audit" already forbids this; it was
   applied to SS-008 on the MCP side (sentence scope + negation + disclosure verb + real captures, D5/D6) but
   not carried across to the skill rules.
2. The MCP side got real-world regression fixtures (`Fixtures/RemoteToolLists/`); the skill side had only
   synthetic strings. The v3.0.0 smoke test scanned live MCP servers, DVMCP, and agent cards, but ran
   `--skills` only to confirm a refusal.
3. "Offer Jon a re-run" stayed an open handover item, so the fix was assumed, not measured.

## The rule that would have prevented it

- **Every detection surface gets a real-world clean corpus as a committed regression fixture**, asserting
  "no Critical / no FP-class finding", before its rules are declared fixed. Synthetic strings prove the
  pattern compiles; only third-party content proves the pattern is shaped.
- **When one rule is found to be context-blind, audit every sibling rule for the same property in the same
  pass** (grep for `SafeIsMatch` over raw content; list every rule not using `SegmentFilter`; list every
  regex verb alternative without `\b`). Fix as one batch, tracked "fixed X of Y".
- **A smoke test is not complete until every scan mode has scanned a real target**: `--remote`, `--config`,
  `--skills`, `--server-source`, `--agent-card`.

## Master-library candidates

- Add "real-world corpus fixture per detection surface" to the security-scanner template's rule-registry
  checklist (next to "constant, mapping, registration, help line, test class").
- Add "every scan mode against a real target" to the pre-tag smoke checklist.

## Addendum (same day): the shipped regex engine is not the engine you tested

During VERIFY of the 3.0.1 fixes, one finding survived that the source pattern could not produce. Root cause is a
.NET 10.0.401 regex bug: a lazy bounded loop over a group (`(?:\w+\s+){0,2}?`) makes `RegexOptions.Compiled` and
the `[GeneratedRegex]` source generator (what the scanner ships) return a bogus 419-char match, or throw
`IndexOutOfRangeException`, on text where the interpreted and NonBacktracking engines correctly find nothing. Four
such constructs were in `InjectionPatterns.cs`; one had shipped in v3.0.0. Regex-level unit tests did not catch it
because the trigger is text-dependent and the synthetic strings never hit it. Only the real-world corpus did.

Rules added to the test suite, and worth promoting:

- **Pattern hygiene guard:** no shipped pattern may contain `){n,m}?`; write explicit optional groups instead.
- **Engine consistency guard:** for every shipped pattern and every real-world fixture, the generated regex and
  `new Regex(pattern.ToString(), options)` must return identical match sets. Cheap, deterministic, and it turns an
  engine miscompile into a red test instead of a false positive in a customer's report.
- File an upstream report with the minimal repro (owner action; `dotnet/runtime`).
