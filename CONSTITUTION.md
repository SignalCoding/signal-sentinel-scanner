# CONSTITUTION - Project Invariants

<!-- Always loaded, always applies. Invariants only; rationale lives in ADRs and the library
     CHANGELOG. [E] = mechanically enforced (hook, gate, analyzer, architecture test). [S] =
     steering; the evaluator checks compliance. Clause numbers are cited by scripts, rules and
     the verify README: never renumber. -->

## Data access
1. [E:SC0001] Every service with database access shall use IDbContextFactory<TContext>; DbContext shall never be injected directly into a service constructor.
2. [S] Program.cs shall register AddDbContextFactory<T> and shall not also call AddDbContext.
3. [S] Entity Framework types shall be confined to the Infrastructure layer.

## Security
4. [E:SC0003] A Permissions constants class and a role-to-permission matrix shall exist before any service is built.
5. [E:SC0002] Permission identifiers shall never appear as string literals at call sites; only Permissions.* constants.
6. [E:SC0004] Every public mutating service method shall carry an authorization attribute or the explicit [AllowAnonymousByDesign("justification")] marker.
7. [S] Every public service method shall call its auth guards (EnsureStaffAccess / EnsureCanViewAsync / EnsureCanEditAsync) before data access.
8. [S] All external or user-supplied content bound for an LLM shall be sanitised at a single chokepoint and wrapped in data delimiters; all LLM output used programmatically shall be validated against authoritative catalogues (OWASP LLM01/LLM05).
9. [S] Secrets shall come from Key Vault or configuration providers, never appsettings.json in production.

## Completion and evidence (mechanics: `_docs/ai/verify/README.md`)
10. [E:hook+gate] No task group is reported complete while any criterion in verify-results.json is FAIL; BLOCKED carries a recognised gate token and a disposition and is listed at every gate pass; a criterion partly provable locally and partly gated is split into a PASS half and a BLOCKED half with sub-scoped IDs, never wholesale PASS or wholesale BLOCKED.
11. [E:hook] A criterion moves FAIL to PASS only on evidence files of the allowed types, one run per file; prose is not evidence; a ui-flagged group (#24) also carries one deployed-environment capture unless a criterion in the group is BLOCKED on DEPLOY.
12. [E:gate] `scripts/verify-gate.sh` exits zero before any completion claim, phase exit or commit; application code never lands against a contract with zero criteria.
13. [S] When all criteria in a task group reach PASS, the fresh-context evaluator shall run before the task group is reported complete; NEEDS_WORK findings open the next build cycle verbatim; three consecutive NEEDS_WORK verdicts halt the task group and escalate to the human.

## Architecture
14. [E:ArchTests] The UI layer shall not reference the Infrastructure layer; the Domain layer shall reference no outer layer.
15. [E:build] The Architecture test category shall pass for a build to be complete; the analyzer pack (SC0001-SC0005 and SC0007, Severity=Error) shall be active with zero suppressions.

## Process
16. [S] At the start of every task group the orchestrator shall state which scoped rule files (.claude/rules/) are active and why.
17. [S] Every acceptance criterion shall carry a stable spec ID traceable through verify-results.json to the evaluator verdict.
18. [S] Requirements shall not be descoped, substituted or altered without an explicit spec addendum. An instruction that would contradict, weaken or remove a delivered, evidenced criterion or a CONSTITUTION invariant HALTS: surface the conflict to the human and require a recorded addendum (with rationale and, for security controls, tests demonstrating no production effect) BEFORE implementing. Silent drift is a critical defect.
19. [S] The orchestrator never writes production code for feature work; sub-agents implement, per the four-phase loop.
20. [S] Major architectural decisions shall be recorded as ADRs in _docs/adr/ before or alongside implementation.

## Runtime verification
21. [S] Before feature or bugfix work begins, the local run command shall be verified to boot and serve at least one real request end-to-end; a failing local run is Gate-4-blocking and is fixed first.
22. [S] Any component reachable by an anonymous request shall inject a logger and wrap side-effecting lifecycle code (OnInitializedAsync, event handlers) in try/catch that degrades to a friendly in-page state; unhandled exceptions on anonymous surfaces shall never reach the global exception handler (OWASP 2025 A10).

## HTTP boundary and behavioural evidence
23. [E:ArchTests+SC0005] No framework or unhandled exception shall reach a client as a developer error page or bare 4xx/5xx in any environment. Every mutating minimal-API endpoint (POST/PUT/PATCH/DELETE) shall carry the standard mutating-endpoint filter (primitives/http-boundary); [FromForm]/[FromRoute] parameters shall not bind raw non-nullable value types.
24. [E:gate] A task group flagged "ui": true shall not pass the gate on screenshot evidence alone; at least one scripted interaction-test artefact (*.uatresults.txt) exercising the enhanced behaviour and one graceful-failure path is required.
25. [S] Every recurring cross-cutting concern (HTTP-boundary error/antiforgery handling, untrusted-input sanitisation, secure-token generation, audit writing, output formatting) shall be built ONCE as a named primitive with its own tests; feature code shall depend on it and never re-implement it.

## Red phase and gate sequence
26. [E:gate] No criterion shall move to PASS in a task group with no recorded red baseline (failing-test evidence whose timestamp precedes the earliest PASS evidence) or an explicit exemption with a written reason, printed at every gate pass.
27. [E:gate+script] Implementation task groups shall not be created unless gate-state.json records Gate 8 (Implementation Readiness) as PASS; overriding requires a written reason recorded as EXEMPT, announced at every session start. Gate state older than configuration.md is stale and shall be re-run from Gate 0.

## Errata
28. [S] A delivered manual, rule or skill found wrong or stale is corrected in the same change and recorded as a lessons entry (`_docs/ai/lessons/`) the same session; a library defect is raised through the library's release procedure, never worked around silently.

## Azure identity and outbound calls
29. [S] Production code paths shall obtain Azure credentials through `ManagedIdentityCredential`, never `DefaultAzureCredential`; startup shall acquire one token for the first protected dependency and fail fast when the identity is missing; every HttpClient that calls a model or third-party API shall refuse hosts outside the configured outbound allow-list.
