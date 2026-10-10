---
paths: ["**/*Service.cs", "**/Data/**", "**/*Repository.cs", "**/*DbContext*.cs", "**/Migrations/**", "**/*Seeder*.cs", "**/*Reconcil*.cs"]
---
# Scoped Rule: Persistence (EF Core 10 / Blazor Server)

## IDbContextFactory (CONSTITUTION #1-2; enforced by SC0001 and SC0007)
- Every service with database access takes `IDbContextFactory<TContext>`; every async method opens
  its own context: `using var db = await _contextFactory.CreateDbContextAsync(ct);`.
- `Program.cs` registers `AddDbContextFactory<ApplicationDbContext>(...)` and never also
  `AddDbContext`; never `AddScoped<TInterface>(sp => sp.GetRequiredService<TContext>())`.
- Background and hosted services use the same pattern. Never cache a DbContext on a field; never
  share a context across parallel operations.
- A startup check that scans the service collection for a scoped context registration can
  false-positive (`AddDbContextFactory` may register the context type itself); SC0001 is the
  reliable guard, so verify any extra runtime guard against a known-good factory-only setup first.

## Query rules (reject in review)
- No nested queries against the context inside `.Select()` projections.
- No multiple `await db...` calls inside one object initializer; sequentialise them.
- No `SaveChangesAsync()` inside loops: batch-load, mutate in memory, save once.
- `AsNoTracking()` for read-only queries.
- Correct and incorrect examples: `_docs/architecture-starter.md` Section 12.

## Persisted derived data
- A fix to a formatting, humanisation or derivation chokepoint whose output is persisted or cached
  ships with an idempotent recompute or reseed path (or a documented migration).
- Verify such a fix against freshly derived data, never pre-existing dev rows; before filing a
  defect, trace that the current logic could produce the observed output.

## Silent-by-design steps
- A seed, reconcile or migration step that catches all exceptions and logs a warning fails
  silently. It is done only when confirmed by read-back against the real target: a log excerpt
  showing completion, or a targeted read query showing the rows or grants materialised (`*.log` /
  `*.http.txt` evidence). A healthy app plus a green deploy is not that evidence.
- New reconcilers follow the established idempotent pattern and name their read-back check in the
  criterion.

## EF Core 10
- Vector search: `SqlVector<float>` with `[Column(TypeName = "vector(1536)")]` (SQL Server 2025 or
  Azure SQL Database). Native JSON columns; named query filters; `ExecuteUpdateAsync` for bulk
  JSON updates.
- Repository plus Unit of Work, scoped to the DbContext.
- Migrations: `dotnet ef migrations add <Name>`, review with `dotnet ef migrations script` before
  `dotnet ef database update`; generated, reviewed and committed in the same task group as the
  model change that caused them.
