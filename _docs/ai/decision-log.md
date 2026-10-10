# Decision Log

One numbered list, monotonically increasing, never renumbered, never deleted (v2.7.0
convention, adopted from an external collaborator's field-tested workflow). Every deviation
and judgment call gets an entry: WHAT was decided, WHY, and what EVIDENCE backs it. A
decision later reversed gets a NEW entry pointing back at the old one - history stays intact.

Items waiting on the human carry the greppable marker `OWNER-PENDING` in their entry;
`grep -n "OWNER-PENDING" _docs/ai/decision-log.md` is the authoritative open-items list.
When an item resolves, rewrite the marker to `was OWNER-PENDING` so history reads cleanly
without counting as open.

ADR-class decisions (architecture) still get full ADRs; this log is for everything smaller
that would otherwise live only in a session transcript.

---

1. (seed) Decision log adopted at bootstrap. Evidence: this file.
2. (2026-10-10) Library v3.3.0 template analyzer ItemGroup NOT wired into Directory.Build.props; the SC pack, Roslynator and Meziantou are all deferred. Why: Measured, not assumed. (1) The six SC rules raise ZERO diagnostics on this codebase: they target DbContext injection, a permissions matrix, mutating-service authorization and FromForm/FromRoute binding, none of which exist in a console CLI. (2) Wiring the pack breaks CI: it ships without AnalyzerReleases.{Shipped,Unshipped}.md, so under its own EnforceExtendedAnalyzerRules it emits 6x RS2008 + 1x RS1037, and the code-quality job's command-line -p:TreatWarningsAsErrors=true overrides any project-level relaxation. (3) Roslynator + Meziantou raise 206 errors on product code, none defects: 108x MA0048 file-per-type on grouped DTOs, 58x MA0023 regex ExplicitCapture, rest string-comparison and method-length preferences. Fixing (2) means authoring files into delivered apparatus, which doctrine #11 forbids from a project session. Evidence: _docs/ai/completed/2026-10-10_bootstrap-conflicts.md Resolutions row for Directory.Build.props; build verified 0 warnings 0 errors both plain and under CI flags. OWNER-PENDING
3. (2026-10-10) CONSTITUTION.md delivered by the dotnet-blazor-azure template retains clauses that presuppose a web/EF/Azure stack this product does not have (IDbContextFactory, Permissions matrix, Blazor hosting, HTTP boundary, ArchTests layering, Managed Identity). Why: The clauses are inert here rather than waived: there is no DbContext, no web surface and no Azure resource to violate them. Rewriting CONSTITUTION numbering was outside the adoption scope and #18 requires an addendum, not a silent edit. CLAUDE.md's Stack section states the inertness so no session treats them as satisfied-by-compliance. Evidence: CLAUDE.md ## Stack bullet; CONSTITUTION.md clauses 1-9, 14-15, 22-25, 29. OWNER-PENDING
4. (2026-10-10) The gitleaks workflow delivered by library v3.3.0 cannot pass on this repository: gitleaks-action@v2 requires a paid GITLEAKS_LICENSE secret for organisation-owned repos. Why: Pre-existing and library-delivered, not caused by the adoption branch: .github/workflows/gitleaks.yml arrived in bootstrap commit 05297df and already failed on main at 2026-10-10T14:31:28Z with 'is an organization. License key is required.' This also blocks Gate 0.5 item 1.3 (gitleaks blocks a test secret on push), which cannot be evidenced until the secret exists. Options for the owner: buy a licence and add the secret, pin the action to a pre-breaking-change version, or replace it with GitHub-native secret scanning plus push protection, which is free on public repos and is already item 1.2 of the same checklist and currently disabled. Evidence: gh run view 38062662425 --log-failed; gh run list --workflow=gitleaks.yml shows failure on main before the branch existed. OWNER-PENDING
