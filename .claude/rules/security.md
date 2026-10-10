---
paths: ["**/*Service.cs", "**/Services/**", "**/admin/**", "**/Auth/**", "**/Identity/**", "**/Permissions*.cs", "**/Program.cs"]
---
# Scoped Rule: Security (Auth Contract, Secrets, Single Chokepoint)

## The auth contract (before the FIRST service; CONSTITUTION #4-7)
- Create `src/<Project>.Application/Common/Permissions.cs`: one nested static class per resource,
  every permission code a `const string` (`View = "<resource>.view"`, `ViewAll`, `Edit`, `Delete`).
  A permission string literal at a call site does not compile (SC0002, SC0003).
- Record the role-to-permission matrix in `_docs/security-contract.md` (or
  `_docs/ai/configuration.md`) and the contract as an ADR in `_docs/adr/`.
- Every service guards every public method before data access: inject `ICurrentUserService` and
  the authorization service; `EnsureStaffAccess()` at entry (throw for external user types);
  `EnsureCanViewAsync(entity)` allows Admin, the `*.viewAll` holder or the owner;
  `EnsureCanEditAsync(entity)` denies read-only roles, then the same test.
- New services follow the canonical template in `_docs/architecture-starter.md` Section 13
  (constructor: factory + `ICurrentUserService` + `IActivityLogger` + `ILogger`; per-method
  context; authorization before data access; activity log on mutations; `CancellationToken`
  everywhere); the cheapest adequate model stamps them out from it.
- Reject any service that skips its guards or hardcodes a permission string.

## Standing routing (not advisory)
- `coding-agent-security` by default for anything under `Services/`, any page under `/admin`,
  any auth-flow change, ASP.NET Identity or authorization-policy work, EF migrations on user-data
  tables, and Bicep that adds attack surface; opting down to `coding-agent` needs a written reason.
- Auth-flow changes also get the strongest model and a post-commit `security-reviewer` pass.
- Any code that sends external data to a model: `.claude/rules/llm-input.md`.

## Secrets and change hygiene (CONSTITUTION #9)
- Production secrets come from Key Vault or a configuration provider, never `appsettings.json`;
  local development uses User Secrets.
- Every AI-touched file is secrets-scanned at generation time (secrets-guard in session; the
  pre-merge scan is the backstop). A committed secret is already leaked: rotate it.
- Diff size is a security control: split a large agent diff, or route it to
  `coding-agent-security` plus a `security-reviewer` pass.
- Pin CI actions and container images by digest, never by mutable tag
  (`package-supply-chain-safety`).

## Claims-cache staleness
- Permission claims are baked into the auth cookie at sign-in (claims-principal factory) and
  revalidated on the security-stamp interval; a live role or permission change is invisible to a
  signed-in session until re-auth. Document the interval in the project's security notes and pair
  every live permission change with "log out and back in" guidance.
- Page-level role checks and handler-level permission-claim checks are different mechanisms: a
  reachable page with a denied action is this staleness, not a data defect.

## Single chokepoint per cross-cutting concern (CONSTITUTION #25)
- One named primitive, with its own tests, per recurring concern: HTTP-boundary error and
  antiforgery handling (`MutatingFormEndpointFilter`), LLM-bound input sanitisation
  (`ISanitizeAiInput`), secure-token generation (one CSPRNG generator), audit writing
  (`IActivityLogger`), output formatting (one chokepoint, with a recompute path when its output is
  persisted; see `persistence.md`).
- Copy-pasted cross-cutting logic is a review finding: "extract to a primitive".

## Evidence
- Task groups touching auth produce evidence of a DENIED request or render for an unauthorised
  role (screenshot or http capture), not only the happy path.
