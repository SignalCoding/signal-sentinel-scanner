using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SignalCoding.Analyzers
{
    /// <summary>
    /// SC0004: public methods on *Service classes whose names begin with a mutating prefix must
    /// carry an authorization attribute (any attribute whose name starts with "Authorize") on the
    /// method or its containing type, or the explicit [AllowAnonymousByDesign("...")] exemption.
    /// Mutating prefixes: Create, Add, Update, Set, Delete, Remove, Save, Archive, Import, Approve.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class SC0004UnauthorizedMutatingServiceAnalyzer : DiagnosticAnalyzer
    {
        private static readonly string[] MutatingPrefixes =
        {
            "Create", "Add", "Update", "Set", "Delete", "Remove", "Save", "Archive", "Import", "Approve"
        };

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
            => ImmutableArray.Create(Diagnostics.SC0004);

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterSymbolAction(AnalyzeNamedType, SymbolKind.NamedType);
        }

        private static void AnalyzeNamedType(SymbolAnalysisContext context)
        {
            var type = (INamedTypeSymbol)context.Symbol;
            if (type.TypeKind != TypeKind.Class) return;
            if (!type.Name.EndsWith("Service", StringComparison.Ordinal)) return;
            if (HasAuthorizationAttribute(type) || HasByDesignExemption(type)) return;

            foreach (var method in type.GetMembers().OfType<IMethodSymbol>())
            {
                if (method.MethodKind != MethodKind.Ordinary) continue;
                if (method.DeclaredAccessibility != Accessibility.Public) continue;
                if (!MutatingPrefixes.Any(p => method.Name.StartsWith(p, StringComparison.Ordinal))) continue;
                if (HasAuthorizationAttribute(method) || HasByDesignExemption(method)) continue;

                context.ReportDiagnostic(Diagnostic.Create(
                    Diagnostics.SC0004,
                    method.Locations.Length > 0 ? method.Locations[0] : type.Locations[0],
                    type.Name,
                    method.Name));
            }
        }

        private static bool HasAuthorizationAttribute(ISymbol symbol)
            => symbol.GetAttributes().Any(a =>
                a.AttributeClass?.Name.StartsWith("Authorize", StringComparison.Ordinal) == true);

        private static bool HasByDesignExemption(ISymbol symbol)
            => symbol.GetAttributes().Any(a =>
                a.AttributeClass?.Name == "AllowAnonymousByDesignAttribute" ||
                a.AttributeClass?.Name == "AllowAnonymousByDesign");
    }
}
