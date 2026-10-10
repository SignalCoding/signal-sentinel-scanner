---
paths: ["**/Controllers/**", "**/Endpoints/**", "**/*Endpoint*.cs", "**/Middleware/**", "**/*Middleware*.cs", "**/*Filter*.cs", "**/Program.cs", "**/primitives/http-boundary/**"]
---
# Scoped Rule: HTTP Boundary (Headers, Mutating Endpoints, Anonymous Surfaces)

## Security headers (Blazor Server)
- Set in middleware for every response: `Strict-Transport-Security: max-age=31536000;
  includeSubDomains`; `X-Frame-Options: DENY`; `X-Content-Type-Options: nosniff`;
  `Referrer-Policy: strict-origin-when-cross-origin`.
- CSP: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'
  'unsafe-inline'; connect-src 'self' wss:` (WebAssembly needs `wasm-unsafe-eval`, scoped CSS is
  inline, SignalR uses WebSockets).
- Verify with SecurityHeaders.com after deploy; target Grade A or A+ (`security-headers` skill).

## Mutating endpoints (CONSTITUTION #23)
- Never bind a raw non-nullable value type on `[FromForm]` / `[FromRoute]`: binding throws before
  the handler body runs. Bind `string?`, `TryParse`, redirect gracefully on failure. Enforced by
  SC0005; `[BindingValidatedByDesign("reason")]` is the audited escape hatch.
- Services throw `OpaqueServiceException` carrying a stable machine code; endpoints read the code
  and issue a `?error=<code>` redirect that a page renders as a friendly alert. GUIDs, timestamps
  and stack detail never reach the browser (CWE-209).
- Antiforgery is validated in middleware and read from `IAntiforgeryValidationFeature` in the
  filter, redirecting on a stale token instead of letting the implicit check throw.
- All three compose in `MutatingFormEndpointFilter` (`primitives/http-boundary/`, copied into the
  Web project at bootstrap). Every POST/PUT/PATCH/DELETE minimal-API endpoint attaches it with
  `.AddMutatingFormFilter()` on the route group; the `BoundaryRules` architecture test fails the
  build listing any mutating route without it. Never re-implement these per endpoint.

## Anonymous and unauthenticated surfaces (CONSTITUTION #22)
- Every page or endpoint reachable without authentication (invite acceptance, public forms,
  password reset, registration) injects `ILogger`.
- Wrap the full lifecycle body in try/catch, including the rate-limit check and lookup query, not
  only the mutating command.
- Under repeated or concurrent hits the surface degrades to an explicit, logged, friendly in-page
  state; it never produces the generic `/Error` page or a raw 500 (OWASP 2025 A10).

## Rate limiter and singleton state
- A lock guarding in-memory state in a registered singleton is scoped per instance, never a
  `static readonly` lock shared across the app. Review every `lock` inside a singleton for whether
  the lock object's scope matches the state it protects.
