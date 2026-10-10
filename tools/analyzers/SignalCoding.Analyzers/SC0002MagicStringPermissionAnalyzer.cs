using System;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SignalCoding.Analyzers
{
    /// <summary>
    /// SC0002: string literals must not be passed to permission/authorization APIs.
    /// Heuristics (widen via ADR):
    ///  - any invocation whose member name contains "Permission" with a string-literal argument
    ///  - any [Authorize] attribute with a string-literal argument (positional or Policy=/Roles=)
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class SC0002MagicStringPermissionAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
            => ImmutableArray.Create(Diagnostics.SC0002);

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
            context.RegisterSyntaxNodeAction(AnalyzeAttribute, SyntaxKind.Attribute);
        }

        private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
        {
            var invocation = (InvocationExpressionSyntax)context.Node;
            string memberName = invocation.Expression switch
            {
                MemberAccessExpressionSyntax m => m.Name.Identifier.Text,
                IdentifierNameSyntax i => i.Identifier.Text,
                _ => string.Empty
            };
            if (memberName.IndexOf("Permission", StringComparison.Ordinal) < 0) return;
            if (invocation.ArgumentList == null) return;

            foreach (var arg in invocation.ArgumentList.Arguments)
            {
                if (arg.Expression is LiteralExpressionSyntax literal &&
                    literal.IsKind(SyntaxKind.StringLiteralExpression))
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        Diagnostics.SC0002, literal.GetLocation(), memberName));
                }
            }
        }

        private static void AnalyzeAttribute(SyntaxNodeAnalysisContext context)
        {
            var attribute = (AttributeSyntax)context.Node;
            var name = attribute.Name.ToString();
            if (name != "Authorize" && name != "AuthorizeAttribute" &&
                !name.EndsWith(".Authorize", StringComparison.Ordinal)) return;
            if (attribute.ArgumentList == null) return;

            foreach (var arg in attribute.ArgumentList.Arguments)
            {
                if (arg.Expression is LiteralExpressionSyntax literal &&
                    literal.IsKind(SyntaxKind.StringLiteralExpression))
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        Diagnostics.SC0002, literal.GetLocation(), "[Authorize]"));
                }
            }
        }
    }
}
