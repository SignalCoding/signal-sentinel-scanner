using System;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SignalCoding.Analyzers
{
    /// <summary>
    /// SC0003: if authorization is in use anywhere (an [Authorize] attribute with arguments, or a
    /// *Permission* invocation), a static class named "Permissions" must exist in the current
    /// compilation OR in a referenced assembly. Under the mandated Clean Architecture layering
    /// the Permissions class lives in the Application project while Infrastructure/UI are
    /// separate compilations that merely reference it, so searching only the current compilation
    /// (the pre-v1.11.1 behaviour) fired a false Error in every project except Application.
    /// The diagnostic still fires when NO compilation in the reference closure has the class.
    /// Reports at the first consuming site found. (Security Contract Bootstrap enforcement.)
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class SC0003PermissionsClassExistsAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
            => ImmutableArray.Create(Diagnostics.SC0003);

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();

            context.RegisterCompilationStartAction(startContext =>
            {
                var usageLocations = new ConcurrentBag<Location>();

                startContext.RegisterSyntaxNodeAction(nodeContext =>
                {
                    var attribute = (AttributeSyntax)nodeContext.Node;
                    var name = attribute.Name.ToString();
                    if ((name == "Authorize" || name == "AuthorizeAttribute" ||
                         name.EndsWith(".Authorize", StringComparison.Ordinal)) &&
                        attribute.ArgumentList != null &&
                        attribute.ArgumentList.Arguments.Count > 0)
                    {
                        usageLocations.Add(attribute.GetLocation());
                    }
                }, SyntaxKind.Attribute);

                startContext.RegisterSyntaxNodeAction(nodeContext =>
                {
                    var invocation = (InvocationExpressionSyntax)nodeContext.Node;
                    string memberName = invocation.Expression switch
                    {
                        MemberAccessExpressionSyntax m => m.Name.Identifier.Text,
                        IdentifierNameSyntax i => i.Identifier.Text,
                        _ => string.Empty
                    };
                    if (memberName.IndexOf("Permission", StringComparison.Ordinal) >= 0)
                    {
                        usageLocations.Add(invocation.GetLocation());
                    }
                }, SyntaxKind.InvocationExpression);

                startContext.RegisterCompilationEndAction(endContext =>
                {
                    if (usageLocations.IsEmpty) return;

                    if (!PermissionsClassExists(endContext.Compilation))
                    {
                        var first = usageLocations
                            .OrderBy(l => l.SourceTree?.FilePath, StringComparer.Ordinal)
                            .ThenBy(l => l.SourceSpan.Start)
                            .First();
                        endContext.ReportDiagnostic(Diagnostic.Create(Diagnostics.SC0003, first));
                    }
                });
            });
        }

        private static bool PermissionsClassExists(Compilation compilation)
        {
            // Current compilation: any static class named "Permissions" (any namespace,
            // including nested types - GetSymbolsWithName covers both).
            if (compilation.GetSymbolsWithName("Permissions", SymbolFilter.Type)
                .OfType<INamedTypeSymbol>()
                .Any(t => t.TypeKind == TypeKind.Class && t.IsStatic))
            {
                return true;
            }

            // Referenced assemblies (v1.11.1 cross-compilation fix): under Clean Architecture
            // the Permissions class lives in the Application project; Infrastructure/UI compile
            // separately and see it only through a reference. MSBuild passes the transitive
            // project-reference closure to the compiler, so walking the direct
            // ReferencedAssemblySymbols covers the whole closure. Only PUBLIC matches count
            // here: a non-public type in another assembly is not consumable by this one, so it
            // cannot satisfy the Security Contract Bootstrap.
            foreach (var assembly in compilation.SourceModule.ReferencedAssemblySymbols)
            {
                if (ContainsPublicStaticPermissionsClass(assembly.GlobalNamespace))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsPublicStaticPermissionsClass(INamespaceSymbol ns)
        {
            if (ns.GetTypeMembers("Permissions").Any(t =>
                    t.TypeKind == TypeKind.Class &&
                    t.IsStatic &&
                    t.DeclaredAccessibility == Accessibility.Public))
            {
                return true;
            }

            foreach (var child in ns.GetNamespaceMembers())
            {
                if (ContainsPublicStaticPermissionsClass(child))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
