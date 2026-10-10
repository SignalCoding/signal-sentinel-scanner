using System;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SignalCoding.Analyzers
{
    /// <summary>
    /// SC0001: constructors of in-scope classes must not take a parameter deriving from
    /// Microsoft.EntityFrameworkCore.DbContext. Inject IDbContextFactory&lt;T&gt; instead.
    /// Heuristic scope: types whose name ends with "Service", plus (v1.11.0, FortisISO incident)
    /// classes implementing MediatR.IRequestHandler&lt;T&gt; or IRequestHandler&lt;T,R&gt; -
    /// matched structurally by the implemented interface's original-definition full name, so no
    /// MediatR package reference is required at analyzer compile time. Widen further via ADR.
    /// Companion rule SC0007 catches the interface-wrapped scoped registration this injection-site
    /// check cannot see through.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class SC0001DbContextDirectInjectionAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
            => ImmutableArray.Create(Diagnostics.SC0001);

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
            if (!type.Name.EndsWith("Service", StringComparison.Ordinal) &&
                !ImplementsMediatRRequestHandler(type))
            {
                return;
            }

            foreach (var ctor in type.InstanceConstructors)
            {
                foreach (var parameter in ctor.Parameters)
                {
                    if (DerivesFromDbContext(parameter.Type))
                    {
                        context.ReportDiagnostic(Diagnostic.Create(
                            Diagnostics.SC0001,
                            parameter.Locations.Length > 0 ? parameter.Locations[0] : ctor.Locations[0],
                            type.Name,
                            parameter.Type.Name));
                    }
                }
            }
        }

        /// <summary>
        /// (v1.11.0) True when the class implements MediatR's IRequestHandler&lt;T&gt; or
        /// IRequestHandler&lt;T,R&gt;. Matched by the original definition's full name string
        /// ("MediatR.IRequestHandler`1/`2") so the analyzer needs no MediatR package reference.
        /// </summary>
        private static bool ImplementsMediatRRequestHandler(INamedTypeSymbol type)
        {
            foreach (var iface in type.AllInterfaces)
            {
                var definition = iface.ConstructedFrom ?? iface.OriginalDefinition;
                if (definition == null) continue;
                if (definition.Name != "IRequestHandler") continue;
                if (definition.Arity != 1 && definition.Arity != 2) continue;
                if (definition.ContainingNamespace?.ToDisplayString() == "MediatR") return true;
            }
            return false;
        }

        private static bool DerivesFromDbContext(ITypeSymbol type)
        {
            for (var current = type as INamedTypeSymbol; current != null; current = current.BaseType)
            {
                if (current.Name == "DbContext" &&
                    current.ContainingNamespace?.ToDisplayString() == "Microsoft.EntityFrameworkCore")
                {
                    return true;
                }
            }
            return false;
        }
    }
}
