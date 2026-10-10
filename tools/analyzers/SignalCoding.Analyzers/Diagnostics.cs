using Microsoft.CodeAnalysis;

namespace SignalCoding.Analyzers
{
    /// <summary>
    /// Diagnostic descriptors for the SignalCoding rule pack (v1.7.0; SC0005 added v1.10.0;
    /// SC0001 widened to MediatR handlers, SC0007 added, and SC0005 promoted to Error in v1.11.0;
    /// v1.11.1: SC0003 searches referenced assemblies, SC0005 excludes bool).
    /// SC0001-SC0005 and SC0007 ship at Severity=Error with zero suppressions permitted
    /// (Decisions Log Q4). SC0005's one-release Warning grace period ended with v1.11.0.
    /// The SC identifier space is registered in tools/analyzers/SC-REGISTRY.md - claim new ids
    /// there first (SC0006 is NOT free: it is the Razor sweep in Architecture.Tests).
    /// </summary>
    internal static class Diagnostics
    {
        private const string Category = "SignalCoding.Architecture";

        internal static readonly DiagnosticDescriptor SC0001 = new DiagnosticDescriptor(
            id: "SC0001",
            title: "Service must not inject DbContext directly",
            messageFormat: "'{0}' injects '{1}' directly; inject IDbContextFactory<{1}> and create short-lived contexts (Blazor Server requirement, CONSTITUTION #1)",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Error,
            isEnabledByDefault: true,
            description: "Blazor Server services must use IDbContextFactory<T>. Direct DbContext injection causes captive-dependency and threading defects. Origin: harvested failure class 1 (2026-06). Scope widened in v1.11.0: in addition to *Service classes, classes implementing MediatR.IRequestHandler<T> / IRequestHandler<T,R> are checked (FortisISO incident - handlers consumed a scoped DbContext missed by the *Service name heuristic).");

        internal static readonly DiagnosticDescriptor SC0002 = new DiagnosticDescriptor(
            id: "SC0002",
            title: "Permission identifiers must not be string literals",
            messageFormat: "String literal passed to '{0}'; reference the Permissions constants class instead (CONSTITUTION #3)",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Error,
            isEnabledByDefault: true,
            description: "Magic-string permission codes defeat auditability and refactoring. All permission identifiers live in the Permissions constants class. Origin: harvested failure class 2 (2026-06).");

        internal static readonly DiagnosticDescriptor SC0003 = new DiagnosticDescriptor(
            id: "SC0003",
            title: "Permissions constants class is missing",
            messageFormat: "Authorization is in use but no static 'Permissions' class exists in this compilation or its referenced assemblies; create it (in the Application project) before building services (Security Contract Bootstrap, CONSTITUTION #4)",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Error,
            isEnabledByDefault: true,
            description: "The Security Contract Bootstrap requires a Permissions constants class and role matrix before any service is built.");

        internal static readonly DiagnosticDescriptor SC0004 = new DiagnosticDescriptor(
            id: "SC0004",
            title: "Public mutating service method lacks authorization",
            messageFormat: "'{0}.{1}' is a public mutating method with no [Authorize] and no [AllowAnonymousByDesign] justification (CONSTITUTION #5)",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Error,
            isEnabledByDefault: true,
            description: "Every public mutating method on a service must be authorized, or carry an explicit, greppable exemption with a justification. Origin: a prior production build shipped services with no authorization.");

        // SC0005 shipped at Warning in v1.10.0 to give existing bootstrapped projects one release
        // of grace to migrate raw value-type bindings. Promotion to Error done in v1.11.0 as
        // scheduled. The WarningsAsErrors backstop in Directory.Build.props (application
        // template, outside this analyzers tree) lists SC0005 and SC0007 alongside
        // SC0001-SC0004 since v1.11.1; with defaultSeverity=Error that backstop is
        // belt-and-braces only - it protects against a project lowering the severity in
        // .editorconfig.
        internal static readonly DiagnosticDescriptor SC0005 = new DiagnosticDescriptor(
            id: "SC0005",
            title: "[FromForm]/[FromRoute] parameter must not be a raw non-nullable value type",
            messageFormat: "[FromForm]/[FromRoute] parameter '{0}' is a non-nullable value type; an empty or malformed submission throws a raw binding exception before the handler runs. Bind string? (or {1}?) and parse explicitly, redirecting gracefully on failure.",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Error,
            isEnabledByDefault: true,
            description: "Minimal-API and controller model binding throws a raw binding exception (an unstyled 400/500 to the user) when a non-nullable value type receives an empty or malformed form/route value, before any handler code can recover. Bind a nullable type and parse explicitly, or justify with [BindingValidatedByDesign]. Pairs with the http-boundary MutatingFormEndpointFilter primitive. Origin: findings 3.2. Promoted from Warning to Error in v1.11.0 (scheduled one-release grace period ended).");

        // Added v1.11.0 (FortisISO incident, root cause): an interface-wrapped scoped DbContext
        // registration - AddScoped<TInterface>(sp => sp.GetRequiredService<TContext>()) - hands
        // consumers a captive scoped DbContext behind an interface, silently undoing the
        // AddDbContextFactory<TContext> lifetime discipline, and is invisible to SC0001 at the
        // injection site (interface types cannot be checked for DbContext derivation there).
        internal static readonly DiagnosticDescriptor SC0007 = new DiagnosticDescriptor(
            id: "SC0007",
            title: "Scoped interface registration undoes DbContextFactory",
            messageFormat: "AddScoped registration of '{0}' resolves '{1}' (a DbContext) from the container; this hands consumers a captive scoped DbContext behind an interface and undoes IDbContextFactory<{1}> (Blazor Server requirement, CONSTITUTION #1)",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Error,
            isEnabledByDefault: true,
            description: "A scoped service registration whose factory merely unwraps a DbContext-derived type from the provider re-creates the captive-dependency hazard that AddDbContextFactory exists to prevent, while hiding the DbContext behind an interface that SC0001 cannot see through. Resolve contexts via IDbContextFactory<T> at the point of use instead. Origin: FortisISO live incident (2026-08).");
    }
}
