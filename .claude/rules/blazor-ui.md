---
paths: ["**/*.razor", "**/*.razor.cs", "**/Components/**", "**/Pages/**", "**/wwwroot/**"]
---
# Scoped Rule: Blazor UI

## Hosting and structure
- The hosting model is an ADR: Blazor Server (default for line-of-business), WebAssembly
  (offline-first), Auto (hybrid). Never Blazor for a static marketing site.
- Razor components live in `Components/` or feature-grouped subfolders; state via cascading
  parameters, `Microsoft.AspNetCore.Components.StateManagement` for complex cases.
- Before building pages: global CSS utilities (or Tailwind tokens), a reusable component set, one
  template page. Pages use only the component set.

## Component rules
- Components are thin: data access through injected services; never a DbContext in a component.
- No `async void`; components holding timers or subscriptions implement `IAsyncDisposable`.
- User-supplied content renders encoded; `MarkupString` needs an ADR-recorded justification.
- Raw exception text never reaches the UI; failures render a friendly state.
- A control whose endpoint needs a prior step or selection is `disabled` or not rendered until the
  precondition holds, with an inline hint; the endpoint still handles the missing precondition
  (`MutatingFormEndpointFilter`). Interaction tests assert the disabled state.

## Prerendering (interactive render modes)
- `@rendermode InteractiveServer` prerenders: `OnInitializedAsync` runs once in the static SSR pass
  and again when the circuit connects, and an exception in the prerender pass surfaces as the
  generic error page. Any page with a rate limiter, mutating command or other non-idempotent side
  effect in a lifecycle method sets `@rendermode @(new InteractiveServerRenderMode(prerender:
  false))` explicitly. Pure read display may keep prerendering.
- Check this on every anonymous or rate-limited page at review; advisory text alone did not hold.

## Razor expression heuristic (SC0006)
- Razor treats `word@identifier.identifier` as literal text, so `v@policy.CurrentVersion` renders
  literally. Wrap member access in parentheses: `v@(policy.CurrentVersion)`.
- The `StaticAssetRules` architecture test sweeps `.razor` files for
  `[a-zA-Z]@[a-zA-Z_]\w*\.[A-Z]\w*` and fails the build listing file:line; suppress a genuine
  email address with `@* sc0006:allow *@` on the same line. Lower-case member access
  (`@item.count`) is not swept: keep interpolated members PascalCase or wrap them in `@(...)`.

## Static SSR with enhanced navigation
- Enhanced navigation DOM-patches the next page and does not re-execute `<script>` tags in the
  swapped content. Initialise client-side enhancement through the page-lifecycle events
  (`afterWebStarted` / enhanced-load), event delegation on a stable root, or an explicit re-init
  hook; never a one-shot `<script>` that assumes a full load.
- Every JS enhancement degrades to a usable state with JS disabled or not yet run ("all fields
  visible" is acceptable; a blank form is not). Server-side validation never depends on it.
- The base stylesheet includes `[hidden] { display: none !important; }` (author rules such as
  `label { display: block }` otherwise defeat `element.hidden`); enforced by
  `StaticAssetRules.HiddenAttributeCssResetPresent`. Interaction tests for conditional visibility
  assert computed `display: none`, not the attribute.

## Audits and evidence
- A "gate every control" or "audit every call site" pass over a component starts by enumerating the
  write surface with a search (every `Mediator.Send(new <Command>...)` / dispatch site), then
  verifies each entry; the grep list is the evidence artefact.
- UI-affecting task groups produce `*.png` evidence including at least one non-happy-path state
  (empty, denied or error); groups with client-side behaviour are `--ui` and carry the interaction
  test of `.claude/rules/testing.md` (`*.uatresults.txt`).
