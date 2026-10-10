---
paths: ["**/*.cs", "**/*.csproj", "**/*.props", "**/Directory.Packages.props"]
---
# Scoped Rule: .NET 10 and C# 14 Conventions

## Build controls
- Warnings are errors: CI builds with `-warnaserror` and `Directory.Build.props` sets
  `TreatWarningsAsErrors`. No analyzer suppression, SC rules and MA0025 included (CONSTITUTION #15).
- Red-phase stubs throw `NotSupportedException` with the criterion ID in the message, never
  `NotImplementedException` (MA0025 breaks the build before the failing test can be witnessed).
- The analyzer pack (`tools/analyzers/`, SC0001-SC0005 and SC0007) and `tests/Architecture.Tests`
  are wired through `Directory.Build.props` and always active; keep the analyzer list there in
  sync with `tools/analyzers/SC-REGISTRY.md`.
- `SonarAnalyzer.CSharp` may be added in `Directory.Build.props` (`PrivateAssets="all"`) for
  RESTRICTED and higher postures.
- CI merge gates are deterministic checks only (analyzers, format, tests); agent-based review is
  local VERIFY depth, never the blocking gate.

## Language and runtime
- Target .NET 10 LTS, C# 14. Minimum acceptable .NET 8 LTS; .NET 9, 7 and 6 are prohibited.
- Prefer C# 14 idioms: the `field` keyword for backing-field access, extension blocks,
  null-conditional assignment (`customer?.Address = x`), `Span<T>` / `ReadOnlySpan<T>`, partial
  constructors and events.
- `CancellationToken` on every async public method, passed through to EF and HTTP calls.
- No `async void` outside event handlers.
