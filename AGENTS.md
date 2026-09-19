# AGENTS.md - Signal Sentinel Scanner Operating Manual

**Project:** Signal Sentinel Scanner
**Stack:** .NET 10 / C# 14 console CLI (MCP + Agent Skill security scanner)
**Last Updated:** 2026-09-19
**Owner:** Signal Coding Limited

This file is the project's operating manual for any AI agent operating in this repository. The orchestrator loads it at session start. Sub-agents inherit its rules. If anything in this file conflicts with a user instruction, surface the conflict before proceeding.

The substance of how this project's AI development is governed lives in the master library at `C:\Sites\_AIAgent\` (synced to `~/.factory/`). This file declares which of those skills are active and adds project-specific rules.

---

## 1. Active Skills (Master Library)

This project uses the following skills from the master library:

- `startup-configuration` - completed; see `_docs/ai/configuration.md`
- `gate-sequence` - active before every new feature spec
- `ai-code-governance` - active on every AI-touching commit
- `owasp-2025-compliance` - active before every merge to main
- `security-headers` - active before every production deploy
- `package-supply-chain-safety` - active whenever dependencies change
- `safe-database-operations` - active for any DB schema or bulk data change
- `perspective-alignment` - continuous (every 10/25/50 messages)
- `delegation-routing` - active on every sub-agent delegation (model selection + confirmation)
- `dotnet-stack-enforcement` - active (project is .NET 10 / C# 14)

---

## 2. Active Droids (Master Library)

- `test-writer` - red-first TDD
- `coding-agent` - minimum-green implementation, structured closing report
- `security-reviewer` - STRIDE + OWASP 2025 + compliance pass

Project-specific droid overrides (if any) live in `.factory/droids/` and take precedence.

---

## 3. Working Discipline (Applies to Every Task)

These rules apply to every change made in this repository. They are not project-specific; they are universal.

- **Only modify files, functions, and lines of code directly related to the current task.** Do not refactor, rename, reorganise, reformat, or "improve" anything not explicitly requested. If something else needs fixing, note it as follow-up.
- **Before any significant content change** (rewriting sections, removing logic, restructuring flow, changing approach): stop, describe what's about to change and why, wait for confirmation.
- **Before deleting any file, overwriting existing code, dropping records, or removing dependencies:** stop, list what will be affected, ask for explicit confirmation. Only proceed after the user says yes in the current message.
- **Always pause for explicit confirmation** before: deploying to any environment, running migrations, sending any external API call, or executing any command with irreversible side effects.
- **Never send, post, publish, share, or schedule** anything on the user's behalf without explicit confirmation in the current message. This includes emails, calendar invites, document shares, deploys, or any action outside the conversation.
- **For architecture decisions, complex debugging, or non-trivial features:** work through the problem step by step before writing code. Show reasoning. Identify uncertainty. Then implement.
- **Always ask, do not assume.** If something is unclear, ask before writing a single line. Never make silent assumptions about intent or architecture.
- **Simplest solution first.** Implement the simplest thing that could work. Do not add abstractions or flexibility that were not explicitly requested.
- **Do not touch unrelated code.** If a file or function is not directly part of the current task, do not modify it.
- **Flag uncertainty explicitly.** Confidence without certainty causes more damage than admitting a gap.

The coding-agent droid closes every task with a structured report: Files Changed, What Was Modified, Files Intentionally Not Touched, Follow-Up Needed. The orchestrator verifies this report exists before declaring work complete.

---

## 4. Core Rule: The Orchestrator Never Writes Code

The general-purpose agent is a planner and reviewer. It does not edit source files. All code changes are made by sub-agents.

If the orchestrator finds itself reaching for `Edit`, `Create`, or `ApplyPatch`, it stops and delegates instead.

---

## 5. The Four-Phase Loop

```
SPEC -> TEST (red) -> IMPLEMENT (green) -> VERIFY -> COMPLETE
```

| Phase     | Actor                 | Output                                  | Stops When                |
| --------- | --------------------- | --------------------------------------- | ------------------------- |
| Spec      | Orchestrator          | `_docs/ai/specs/<topic>.md`             | User approves the spec    |
| Test      | test-writer droid     | Failing tests + `_test-report.md`       | Tests exit non-zero (red) |
| Implement | coding-agent droid    | Code changes + `_impl-report.md`        | All checks exit zero      |
| Verify    | Orchestrator          | Verification commit                     | Reports cleanly synthesise|
| Complete  | Orchestrator          | Spec moved to `_docs/ai/completed/`     | Spec archived             |

Skipping the red phase is not allowed. Implementation without failing tests is not allowed.

Each delegation step goes through the Delegation Routing protocol in Section 5.5 below.

---

## 5.5 Delegation Routing & Model Selection (Mandatory)

The orchestrator never delegates silently. Before each sub-agent invocation, it classifies the work, proposes a specific droid (base or variant) with reasoning, and waits for user confirmation. This gives visibility, audit trail, and override opportunity at every delegation point.

Factory DROID does not support runtime model override at sub-agent invocation (verified in v1.4.0 release testing). Model selection is therefore physical: each variant in `~/.factory/droids/` has its own pinned model. The orchestrator proposes a droid by name, not a model parameter.

### Default Behaviour

Before calling any sub-agent, the orchestrator states:

```
I'm about to delegate this to <droid-name>.

  Classification: <type>, <surface area>, <risk level>, <complexity>, <diff size>
  Proposed droid: <droid-name>
  Underlying model: <model from droid's YAML>
  Reason: <one sentence>

  Confirm to proceed, or use one of:
    'use opus'           - upgrade to the <base>-opus variant
    'use cheap'          - downgrade to the <base>-cheap variant
    'use security'       - use coding-agent-security variant (implement phase only)
    'use <droid-name>'   - specific droid override
    'auto'               - skip confirmation for the rest of this session
    'explain'            - more detail on the classification
    'cancel'             - stop the delegation
```

### Variant Library (Pre-Built)

The master library ships these variants in `~/.factory/droids/`:

| Variant                      | Model         | Use For                                              |
| ---------------------------- | ------------- | ---------------------------------------------------- |
| test-writer-opus             | Opus 4.7      | Novel + cross-cutting, or auth/crypto test design    |
| test-writer-cheap            | Haiku 4.5     | Mechanical, small, isolated test generation          |
| coding-agent-opus            | Opus 4.7      | Novel + cross-cutting, or novel + high risk          |
| coding-agent-security        | Sonnet 4.6    | Auth, crypto, payment, PII, COMPREHENSIVE+ posture   |
| coding-agent-cheap           | Haiku 4.5     | Mechanical refactors, renames, format conversions    |
| security-reviewer-opus       | Opus 4.7      | CONFIDENTIAL+ posture, cross-cutting auth/crypto     |

The base droids (test-writer, coding-agent, security-reviewer) remain the defaults for everything else. The full routing table and detailed selection logic live in `~/.factory/skills/delegation-routing/SKILL.md`.

### Session Modes

The user can set the verbosity of delegation routing at any point:

- `confirm` (default) - every delegation requires explicit confirmation
- `auto` - orchestrator follows the routing rules without confirmation (used after the first 1-2 successful delegations when the user trusts the routing for the rest of the session)
- `verbose` - orchestrator explains the full classification reasoning before each delegation

The mode resets to `confirm` at the start of every new session.

### Audit Trail

Every delegation decision is logged to `_docs/ai/logs/<task-slug>_delegation.md`:

```
Phase: <test|implement|security-review> | Proposed: <droid-name> | Actual: <droid-name> | User: <confirm|override|auto>
Underlying model: <model from droid's YAML>
Classification: <one-line summary>
Reason for proposal: <one-line justification>
```

This creates an audit trail of droid choices (and therefore model choices) alongside the spec/test/impl/security reports.

### Custom Variants For Specific Projects

If a project needs a model combination not in the master library variants (e.g. all three sub-agents on Opus for a high-stakes client, or GLM-5 BYOK across the board for a cost-sensitive prototype), create the variant in the project's `.factory/droids/<name>.md`. Factory uses the project version when names match, and distinct variant names appear as separate sub-agents in `/droids`. See `droids/README.md` in the master library for the file structure.

---

## 6. Stack: .NET 10 / C# 14 CLI

- Solution: `signal-sentinel.sln`; projects `src/SignalSentinel.Core` (models, patterns,
  protocol types), `src/SignalSentinel.Scanner` (CLI, rules, MCP client, reports),
  `tests/SignalSentinel.Scanner.Tests` (xUnit + Shouldly + NSubstitute).
- SDK pinned in `global.json`; `Directory.Build.props` sets `TreatWarningsAsErrors`,
  `AnalysisLevel=latest-all`, `AnalysisMode=All`. Any analyser warning fails the build.
- No web framework, no database, no EF Core. The `safe-database-operations` skill does not
  apply. `security-headers` applies only to the Gateway product, not this repository.
- Network egress is a first-class security concern: every outbound call must respect
  `--offline` (`OfflineGuard`) and the SSRF policy in `Config/RemoteUrlPolicy.cs`.
- Regexes must use `RuleConstants.Limits.RegexTimeoutMs` (or `SafeIsMatch`) to bound
  evaluation time on hostile input.

### Validation commands

```bash
dotnet build signal-sentinel.sln -c Release
dotnet test  signal-sentinel.sln -c Release --no-build
dotnet run --project src/SignalSentinel.Scanner -- --list-rules
```

### Rule registry checklist

A new rule is complete only when: constant in `RuleConstants`, `RuleAstMapping` entry,
`RuleEngine` registration, `--help` and `--list-rules` lines, and a test class. See
`CONTRIBUTING.md`.

---

## 7. Project-Specific Rules

- Findings are governance artefacts: never weaken a rule's default severity without a
  CHANGELOG entry and a migration note.
- Scan output must never include secrets or raw untrusted content beyond
  `RuleConstants.Limits.MaxEvidenceLength` characters of sanitised evidence.
- Every new outbound network feature is opt-in by flag and refused under `--offline`.
- Rule IDs are never reused. `SS-027` is intentionally unallocated.
- Versioning follows `REPO-STANDARDS.md`: one `<Version>` literal in `Directory.Build.props`.

---

## 8. Governance Anchors

See `_docs/ai/configuration.md` for the canonical posture. Summary:

- **Security Posture:** RESTRICTED (defence-adjacent tooling; no public runners for sensitive workflows)
- **AI Governance Level:** ENHANCED (spec/test/impl reports kept per change)
- **Deployment:** NuGet global tool + Docker image via GitHub Actions on tag
- **Compliance Frameworks In Scope:** OWASP ASI Top 10, OWASP AST Top 10, OWASP MCP Top 10; NCSC Cyber Essentials Plus alignment
- **Team Experience:** SENIOR

Every spec, test report, implementation report, security report, and delegation log is a governance artefact and is kept under version control in `_docs/ai/`.

---

## 9. Communication Cadence

**Proactive updates** - status after each significant milestone.

Always pause for: technology decisions, architecture pattern choices, security implementation approaches, scope changes, non-obvious trade-offs.

---

## 10. Delegation Quick Reference

```bash
# Write a spec (orchestrator via Specification Mode)
# Approve and move to working location:
mv .factory/docs/<date>-<slug>.md _docs/ai/specs/<slug>.md

# Generate failing tests (orchestrator will propose model + confirm)
droid exec --agent test-writer --auto medium -f _docs/ai/specs/<slug>.md

# Implement to pass tests (orchestrator will propose model + confirm)
droid exec --agent coding-agent --auto medium -f _docs/ai/specs/<slug>.md

# Security review the change (orchestrator will propose model + confirm)
droid exec --agent security-reviewer --auto low -f _docs/ai/specs/<slug>.md

# Verify (run validation commands from section 6)

# Commit (orchestrator, not sub-agents)
git add . && git commit -m "feat(<scope>): <summary>

Spec: _docs/ai/completed/<date>_<slug>.md
Test-report: _docs/ai/logs/<slug>_test-report.md
Impl-report: _docs/ai/logs/<slug>_impl-report.md
Security-report: _docs/ai/logs/<slug>_security-report.md
Delegation-log: _docs/ai/logs/<slug>_delegation.md

Co-authored-by: factory-droid[bot] <138933559+factory-droid[bot]@users.noreply.github.com>"

# Archive
mv _docs/ai/specs/<slug>.md _docs/ai/completed/$(date +%Y-%m-%d)_<slug>.md
```

---

**Operating Principle:** Master library defines the methodology. This file defines what's specific to Signal Sentinel Scanner. The file system holds the memory. Predictable, auditable, repeatable.

---

## Working Discipline Additions (v1.6.1, harvest 2026-06)

### Pattern Detection → Comprehensive Audit (framework doctrine)

When a defect is found that is pattern-shaped (an architectural pattern, styling convention, or security issue that could exist wherever the pattern was repeated): STOP incremental fixing immediately.

1. Audit the ENTIRE codebase for the pattern (grep + parallel subagents)
2. Catalogue all instances before fixing any
3. Fix comprehensively in one pass; track "fixed X of Y"
4. Build/validate after each batch, not only at the end

Incremental fixing of a pattern-shaped defect cost a real project four separate fix batches across multiple sessions. Never again.

### Parallel Subagent Batching (numbers earned from real use)

For 10+ repetitive units of work: 5-10 parallel subagents (diminishing returns beyond 10), 2-4 units per agent, cheapest adequate model (`coding-agent-cheap` for mechanical transforms), orchestrator consolidates reports, full build + integration check at the end.

### Build Frequently

Build after: every new service/component, every 2-3 refactored files, every interface or DI-registration change, and before marking any task complete. If the build fails, stop and fix before proceeding - errors compound.

### Architectural Conformance In VERIFY

The VERIFY phase explicitly checks the diff against this file's stack conventions before commit. Conformance is a checklist item, not an assumption.

### Lessons Loop

Any fix costing more than one session, or any pattern-shaped defect found in 3+ places, gets an entry in `_docs/ai/lessons/` before the work is complete, and is flagged for master-library review at the next retrospective.

---

## Untrusted Input To LLMs (v1.6.3, framework doctrine)

Applies to ANY project that sends external or user-supplied data to a language model (CV text, scraped content, uploaded documents, form free-text, third-party API responses). This is a live vulnerability class - prompt injection - and it is easy to introduce by accident when concatenating input into a prompt.

Mandatory rules:

1. **Instructions in the system field only.** Never place task instructions in the same field as untrusted content where the model cannot tell them apart.
2. **Wrap untrusted input in explicit data delimiters**, e.g. XML tags: `<cv_text>...</cv_text>`. The model is told to treat everything inside as data, never as instructions.
3. **Sanitise before inclusion.** Strip or neutralise delimiter-breaking sequences; have a single `SanitizeAiInput()`-style chokepoint rather than ad-hoc handling per call site.
4. **Validate everything the model returns** that will be used programmatically. Returned codes, enum values, IDs, and categories are validated against the authoritative catalogue before use - never trusted blindly.
5. **Never log raw model responses** for inputs that may contain sensitive or injected content. Log token counts and metadata, not bodies.
6. **Treat the model as an untrusted boundary in both directions:** untrusted input goes in sanitised and delimited; output comes out validated before it touches your data or control flow.

Any service that sends external data to an LLM routes to the security-sensitive coding agent and gets a security-reviewer pass before merge.
