# CLAUDE.md - Signal Sentinel Scanner

@CONSTITUTION.md

**Stack:** .NET 10 LTS + C# 14 console CLI - MCP and Agent Skill security scanner
**Last Updated:** 2026-10-10
**Tool counterpart:** `AGENTS.md` is a pointer to this file - one manual per project.
**Template Source:** master library `templates/dotnet-blazor-azure/` (version: `_docs/ai/.aiagent-library-version`)

One statement, one home (Core Doctrine #17). This file holds what is specific to this project and
the Core Doctrine. Everything else is read from its owner when needed: the completion contract from
`_docs/ai/verify/README.md`, delegation from the `delegation-routing` skill, the gates from
`gate-sequence`, stack rules from `.claude/rules/` (auto-loaded by path), agent conduct from
`.claude/agents/`, operator notes from the library's `adapters/claude-code/field-notes.md`.

## Session Start

1. `_docs/ai/configuration.md` - placeholders present -> walk the Configuration Gates (`startup-configuration`).
2. `_docs/architecture-starter.md`, `_docs/ai/specs/` (active spec), `_docs/ai/lessons/`.
3. Announce framework activation.
4. `dotnet --version` shows 10.x and `--list-rules` runs: this CLI's equivalent of serving one
   request (CONSTITUTION #21).

## Project

| | |
|---|---|
| Test | `dotnet test signal-sentinel.sln -c Release` (VSTest host - filter with `--filter "Category=X"`) |
| Compile / Build | `dotnet build signal-sentinel.sln -c Release` - exits zero before any completion claim |
| Lint / Format | `dotnet format --verify-no-changes` |
| Rule inventory | `dotnet run --project src/SignalSentinel.Scanner -- --list-rules` |
| Vulnerable packages | `dotnet list package --vulnerable` |
| Declared checks | `scripts/check.sh --all` - TEST, BUILD, LINT, DEPENDENCY_CHECK |
| Evidence gate | `scripts/verify-gate.sh` |
| Release | release-please on merge to `main`; NuGet global tool + GHCR image on tag |

Posture, governance level, deployment, compliance scope and owner: `_docs/ai/configuration.md`
(the only home; do not restate them here).

All library skills apply; `dotnet-stack-enforcement` and `release-management` are active,
`repo-standards` runs on every commit and PR. `safe-database-operations` and `security-headers`
do not apply: this repository has no database and no web surface.

### Project-Specific Rules

- Findings are governance artefacts: never weaken a rule's default severity without a CHANGELOG
  entry and a migration note.
- Scan output never carries secrets or raw untrusted content beyond
  `RuleConstants.Limits.MaxEvidenceLength` characters of sanitised evidence.
- Every outbound network feature is opt-in by flag and refused under `--offline`.
- Rule IDs are never reused. `SS-027` is intentionally unallocated.
- A new rule is complete only when all six exist: constant in `RuleConstants`, `RuleAstMapping`
  entry, `RuleEngine` registration, `--help` line, `--list-rules` line, test class.
  `RuleRegistryParityTests` guards the set and `RuleTotalsProseTests` the stated totals; a guard
  over the parts does not guard the summary. See `CONTRIBUTING.md`.
- Coverage claims name their gap rather than rounding up: AST10 Cross-Platform Reuse is unclaimed
  and printed as an exception by the coverage guard. Never force a mapping to reach a round number.

## Stack

- .NET 10 LTS and C# 14 only; SDK pinned in `global.json`. .NET 9, 7 and 6 are prohibited.
- Projects: `src/SignalSentinel.Core` (models, patterns, protocol types),
  `src/SignalSentinel.Scanner` (CLI, rules, MCP client, reports),
  `tests/SignalSentinel.Scanner.Tests` (xUnit + Shouldly + NSubstitute + FsCheck).
- `Directory.Build.props` sets `TreatWarningsAsErrors`, `AnalysisLevel=latest-all` and
  `AnalysisMode=All`, and holds the one `<Version>` literal release-please rewrites. Any analyser
  warning fails the build.
- No web framework, no database, no EF Core, no Azure resource. CONSTITUTION clauses that
  presuppose them are inert here, not waived; see `_docs/ai/decision-log.md`.
- Network egress is a first-class security concern: every outbound call respects `--offline`
  (`OfflineGuard`) and the SSRF policy in `Config/RemoteUrlPolicy.cs`.
- Every regex is bounded by `RuleConstants.Limits.RegexTimeoutMs` (or `SafeIsMatch`); hostile
  input is the normal case, not the edge case. `(?:X){n,m}?` is forbidden under Compiled and
  GeneratedRegex on net10.0 (dotnet/runtime#134655, fixed in .NET 11 only, no backport) -
  `RegexEngineIntegrityTests` guards it.
- `.editorconfig` never sets `end_of_line` or `trim_trailing_whitespace`; `.gitattributes` owns
  line endings.
- Completeness and parity claims come from reflection, the compiler or a parser, never from a text
  search over source: a grep matches comments and string literals and has twice reported a rule or
  category as covered when it was not.
- Specs add: the affected `.csproj` files, the rule-registry checklist above wherever a rule
  changes, and for any detection change a two-sided acceptance criterion - vulnerable fixtures
  detected AND matched benign controls silent, each measured.

## Working Discipline

- Touch only the files the task needs; the closing report names what was intentionally left alone.
- Confirm before any delete, deploy, data migration or state-changing external call; never send,
  publish or post on the user's behalf.
- Ask when a spec is silent; the simplest solution that meets the spec wins; "verified" means a
  command ran and its output is in the evidence folder.
- Build after every new component, every 2-3 refactored files, every interface or DI change, and
  before marking anything complete. Errors compound.
- A pattern-shaped defect (one that could exist wherever the pattern was repeated) stops incremental
  fixing: audit the whole codebase, catalogue every instance, fix in one pass, build per batch.
- Any fix costing more than a session, or a pattern found in three or more places, becomes a
  `_docs/ai/lessons/` entry before the work is called complete.
- Pause for: technology and architecture choices, security approaches, scope changes, non-obvious
  trade-offs. Status after each milestone. `perspective-alignment` at task-group start and phase exits.

## Scripts (the contract is operated, not described)

```bash
scripts/new-task-group.sh <TG> "<title>" [--ui]          # open FAIL-first; spec-to-contract.sh <spec> --apply opens a whole phase
scripts/add-criteria.sh <TG> <ID> "<EARS>"...             # criteria, never by hand
scripts/set-criterion.sh --red <TG> <file>                # red baseline - commit on its own first
scripts/set-criterion.sh <TG> <ID> PASS <evidence>... | FAIL | BLOCKED <GATE> "<disposition>"
scripts/verify-gate.sh [--run|--verbose|--gates]          # checks first (--run); exit 0 before any claim
scripts/run-evaluator.sh <TG> <spec>                      # all PASS -> fresh-context verdict
scripts/log-decision.sh "<decision>" [--owner-pending]    # scripts/log-delegation.sh <slug> <phase> <agent> <model> "<why>" [--tokens in out]
scripts/archive-spec.sh _docs/ai/specs/<slug>.md          # all PASS; merges capability deltas
scripts/repo-map.sh                                       # where things live -> _docs/ai/repo-map.md
```

Commits are the orchestrator's (Conventional Commits, `type/short-kebab` branch; pre-commit gate via
`scripts/install-git-hooks.sh`), with the spec, test, implementation, security and delegation
artefacts (`_docs/ai/logs/`) named in the body. Evidence: `_docs/ai/verify/evidence/`; application
paths the gate watches: `_docs/ai/verify/app-code-paths`; ADRs: `_docs/adr/`; model pins:
`_docs/ai/models.env`; session metrics (opt-in): `/metrics report`.

<!-- Maintainers: the block between the CORE-DOCTRINE markers is byte-identical across the library's
     seven template manuals (the fixture harness diffs it against templates/generic/CLAUDE.md, the canon)
     and bootstrap.sh --refresh-hooks replaces it in a live project. Edit it in the canon only. This
     comment is stripped before Claude reads the file. -->
<!-- CORE-DOCTRINE:BEGIN -->
## Core Doctrine

1. Spec first: no implementation without an approved spec whose EARS criteria carry stable IDs and are recorded FAIL-first in the completion contract before any implementation delegation.
2. Red before green: a witnessed failing run is recorded and committed on its own before implementation; the gate refuses PASS without it.
3. Minimum green: the smallest diff that satisfies the spec, no opportunistic refactors; the implementer never modifies tests except an additive, spec-mandated change named in the brief.
4. Evidence before claims: no completion claim without `scripts/verify-gate.sh` exit 0. Evidence is files, one run per file; status changes only through `scripts/set-criterion.sh`; BLOCKED carries a recognised gate token and a disposition; ui groups carry one deployed-environment capture (`<ID>.live.*`).
5. Fresh-context verdict: the evaluator never shares context with the builder; its PASS names every criterion, and a verdict that cites no criterion is NEEDS_WORK.
6. Every delegation carries the five-field brief (objective; output format and size; tool and source guidance; out of scope; environment and safety) and is logged.
7. Security-sensitive paths route to coding-agent-security, or carry a written opt-out.
8. No new dependency under 14 days old: native cooldown first, the safe-install wrapper where configuration cannot reach.
9. Every spec declares ADDED, MODIFIED and REMOVED capabilities; archiving merges them into `_docs/ai/SYSTEM-SPEC.md` and refuses an ungated archive.
10. Converge periodically: the whole codebase is re-judged against the living spec and CONSTITUTION in fresh context on the integration branch; findings become briefs, never silent fixes.
11. Never edit the master library from a project session; a local fix to delivered apparatus is a lessons record, and `bootstrap.sh --refresh-hooks` restores the library version.
12. Retrieval: `_docs/ai/SYSTEM-SPEC.md` and `_docs/ai/repo-map.md` first; semantic search may locate, only deterministic retrieval (grep, glob, compiler) may assert; sub-agents return file:line chunks, not pointers.
13. Turn ceiling over compaction: on context pressure stop, write the distillate to a file and resume fresh from it; a governed run that auto-compacts is reported DEGRADED, and secrets and active criteria IDs are re-read from their files afterwards.
14. One home per question: where have we been, git log and `_docs/ai/lessons/`; what is outstanding, OWNER-PENDING in `_docs/ai/decision-log.md` and gate state; what is next, the active spec. A change that makes a statement stale fixes that statement in the same change.
15. Repo standards are the norm: remote, protected `main` and secret scanning before feature work (Gate 0.5); every task-group close and session end pushes; Conventional Commits on `type/short-kebab` branches through small squash-merged PRs; versions and CHANGELOG by release-please; every deterministic check runs in CI and is read with `gh pr checks`, never by pasting logs; never do work a hook, Dependabot or release-please owns.
16. No vacuous gate: application code against a contract with zero criteria fails the gate; the only override is a dated `noTaskGroupsExemption` (gate BOOTSTRAP, with reviewBy), printed at every gate run.
17. One statement, one home: a rule lives in the file that owns it and is pointed to from everywhere else; a rule restated is a defect, a rule a hook or script enforces is stated once as "enforced by", and history lives in the CHANGELOG and lessons, never in an operative file.
<!-- CORE-DOCTRINE:END -->
