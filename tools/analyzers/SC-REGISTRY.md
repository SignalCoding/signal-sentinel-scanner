# SC Identifier Registry

The `SC` identifier space spans **two enforcement mechanisms**: Roslyn analyzers (this pack,
`tools/analyzers/SignalCoding.Analyzers/`) and architecture-test sweeps
(`tests/Architecture.Tests/`). Neither mechanism can see the other's ids, so this file is the
single central registry (added v1.11.1, external review finding).

**Rule: a new SC id is claimed HERE first** - add its row to the table below *before* writing the
analyzer or test that uses it. One row per id. The next free id is the lowest number with no row.

| Id | Mechanism | File | Severity | Since | Description |
|--------|-----------|------|----------|-------|-------------|
| SC0001 | Roslyn analyzer | `tools/analyzers/SignalCoding.Analyzers/SC0001DbContextDirectInjectionAnalyzer.cs` | Error | v1.7.0 | *Service classes (and, since v1.11.0, MediatR handlers) must not inject DbContext directly; use IDbContextFactory<T>. |
| SC0002 | Roslyn analyzer | `tools/analyzers/SignalCoding.Analyzers/SC0002MagicStringPermissionAnalyzer.cs` | Error | v1.7.0 | Permission identifiers must not be string literals; reference the Permissions constants class. |
| SC0003 | Roslyn analyzer | `tools/analyzers/SignalCoding.Analyzers/SC0003PermissionsClassExistsAnalyzer.cs` | Error | v1.7.0 | If authorization is in use, a static Permissions class must exist in the compilation or its references (referenced assemblies searched since v1.11.1). |
| SC0004 | Roslyn analyzer | `tools/analyzers/SignalCoding.Analyzers/SC0004UnauthorizedMutatingServiceAnalyzer.cs` | Error | v1.7.0 | Public mutating service methods need [Authorize] or an [AllowAnonymousByDesign] justification. |
| SC0005 | Roslyn analyzer | `tools/analyzers/SignalCoding.Analyzers/SC0005RawValueTypeBindingAnalyzer.cs` | Error (Warning in v1.10.0) | v1.10.0 | [FromForm]/[FromRoute] parameters must not be raw non-nullable value types; bool excluded since v1.11.1 (checkbox semantics). |
| SC0006 | Architecture-test sweep | `tests/Architecture.Tests/StaticAssetRules.cs` | Test failure (mandatory "Architecture" category) | v1.10.0 | Razor email heuristic: text like `support@Company.Domain` in markup is swallowed as an implicit Razor expression. Implemented as a file-system sweep **deliberately** - `.razor` files are invisible to Roslyn C# analyzers. |
| SC0007 | Roslyn analyzer | `tools/analyzers/SignalCoding.Analyzers/SC0007ScopedDbContextUnwrapRegistrationAnalyzer.cs` | Error | v1.11.0 | AddScoped<TInterface>(sp => sp.GetRequiredService<TContext>()) hands out a captive scoped DbContext behind an interface, undoing IDbContextFactory. |

Next free id: **SC0008**.

Notes:
- Roslyn-analyzer rows are additionally backstopped by the `WarningsAsErrors` list in
  `Directory.Build.props` (SC0001-SC0005;SC0007 since v1.11.1) - keep that list in sync when a
  new analyzer row is added at Error.
- Do not reuse a retired id; mark its row "retired vX.Y.Z" instead of deleting it.
