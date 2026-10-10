---
paths: ["**/tests/**", "**/*Tests*.cs", "**/*.Tests/**", "**/fixtures/**"]
---
# Scoped Rule: Testing (Mandated Categories and the Auth-Test Matrix) - Blazor Server

Pass this list to `test-writer` with every red phase. Red-first, criterion traceability and
evidence mechanics: `_docs/ai/verify/README.md` and `EVIDENCE-RULES.md`.

## Mandated categories (red phase, from the first service onward)
1. **Concurrent service calls:** several services via `Task.WhenAll` (simulating interactive
   rendering) with no `InvalidOperationException: A second operation was started`.
2. **Concurrent page loads:** `WebApplicationFactory` firing 5+ parallel GETs across pages.
3. **Unit tests per service** with a mocked `IDbContextFactory`; the mock sets up
   `CreateDbContextAsync`, not only `CreateDbContext`.
4. **Architecture tests** (`tests/Architecture.Tests`, Category=Architecture): never skipped or
   filtered out; a build is incomplete until they pass (CONSTITUTION #14-15).
5. **Progressive-enhancement and graceful-failure interaction test** for any rendered UI with
   client-side behaviour: a bUnit render-and-act test asserting the resulting DOM including
   computed visibility, and/or a headless browser smoke that exercises the enhancement and one
   malformed-input path (empty form value, stale antiforgery token). Output goes to evidence as
   `*.uatresults.txt`; the group is `--ui` (CONSTITUTION #24). Prove the test has teeth once:
   remove the `[hidden]` reset and watch it fail. Any available driver; the artefact is the
   requirement.
6. **Role-permission matrix regression:** one test class asserts the SEEDED grants equal the
   documented matrix grant by grant, driven from one table mirroring `_docs/security-contract.md`
   (`Assert.Contains(Permissions.Vendors.Create, grantsFor("ComplianceManager"))`). It fails when
   either side changes alone.
7. **Property-based tests** (FsCheck) for services with real logic (parsers, calculators, state
   machines, permission resolution): an invariant, round-trip, idempotence or alternative-oracle
   property. Not required for pure CRUD mapping.
8. **Concurrency:** wherever two actors can touch one record, a control can be pressed twice or a
   call may be retried, one test runs the real parallel case (`Task.WhenAll` against a
   Testcontainers or SQLite-backed `IDbContextFactory`, never a mocked lock or `SemaphoreSlim`)
   and asserts one row, one dispatch, one side effect; the loser gets a defined outcome
   (`DbUpdateConcurrencyException` handled, unique-index violation mapped to a domain error).
   Double POSTs hold the antiforgery token constant. The red fails on the concurrency assertion,
   not on a fixture reusing an identity.
9. **Dead links and broken references:** a route-table test scans `Components/` and `Pages/` for
   `href=`, `<NavLink href`, `NavigationManager.NavigateTo(` and redirect targets, normalises route
   parameters, and fails when no `@page` directive or mapped endpoint matches; referenced `wwwroot`
   assets exist; every `IConfiguration` key or options property the change reads is present in the
   example appsettings or Key Vault manifest.
10. **LLM adversarial corpus** for any task group touching a model call, prompt template,
    sanitiser or output validator: one test iterates every case of
    `tests/fixtures/llm-input-adversarial.md` (from the library's `templates/_shared/fixtures/`)
    through `ISanitizeAiInput`, asserting no live delimiter, cap respected, controls stripped,
    confusables handled per policy, then asserts the output validator rejects out-of-catalogue
    values. Benign look-alikes (a CV saying "system administrator", a ticket quoting angle
    brackets) must survive intact. Never mocks the sanitiser. Evidence is named
    `<TG-ID>-llm-adversarial-<sha256-12>.testresults.txt` (corpus hash prefix; a corpus change
    invalidates the old evidence by name). Project cases are appended, never substituted.

**100x wall-clock rule (categories 8-10):** a test exceeding 100x the median unit test's
wall-clock is an integration test (`Category=Integration`, excluded from the unit run). Any timed
bound is at least 100x the measured cost, with a comment saying so; prefer structural assertions.

## Static state and background services
- Process-wide static or singleton state a test can mutate exposes `ResetForTests()` and runs in a
  `[Collection(DisableParallelization = true)]`, reset in the fixture or constructor.
- A hosted service started in a test is stopped (awaited `StopAsync`) before any shared resource it
  uses is disposed; disposing the container only signals cancellation.
- Inject `TimeProvider` instead of real timers.

## Mandated auth tests (every service with authorization)
- Read-only role calling a mutating method -> throws Unauthorized.
- Non-owner of the same role against another owner's entity -> throws.
- External user type (Candidate, ClientContact) calling any method -> throws (EnsureStaffAccess).
- Privileged role calling a viewAll method -> succeeds. Unauthenticated caller -> throws.
- Direct-API probes, not through the UI: unauthenticated `HttpClient` request -> denied;
  cross-tenant request (a real user, another tenant's id) -> denied; client-side-gate bypass (call the
  endpoint the disabled button would call) -> denied.
- Agent sessions against live data use READ-ONLY database credentials.

## Evidence conventions
- `[Trait("Criterion", "FEAT-C3")]` on at least one test per criterion ID.
- Never pass `--nologo` or `-v` on a command whose output is cited; the totals line and exit
  status are the evidence (capture per `_docs/ai/verify/EVIDENCE-RULES.md`).
