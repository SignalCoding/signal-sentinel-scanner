using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace SignalCoding.Analyzers
{
    /// <summary>
    /// SC0005: [FromForm]/[FromRoute] parameters of route-handler delegates (lambdas or method
    /// groups passed to MapGet/MapPost/MapPut/MapPatch/MapDelete) and controller actions must not
    /// be non-nullable value types. Model binding throws a raw exception for an empty or malformed
    /// submission BEFORE the handler runs, so no in-handler recovery is possible. Bind string?
    /// (or T?) and parse explicitly. Excluded: string, bool (checkbox semantics - see
    /// IsRawNonNullableValueType), IFormFile, IFormFileCollection, CancellationToken,
    /// HttpContext, [FromServices] parameters, and Nullable&lt;T&gt;.
    /// Escape hatch: [BindingValidatedByDesign("reason")] on the parameter.
    /// NOTE: shipped at Warning in v1.10.0 for a one-release grace period; promoted to Error in
    /// v1.11.0 as scheduled (see Diagnostics.SC0005 comment). bool excluded in v1.11.1.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class SC0005RawValueTypeBindingAnalyzer : DiagnosticAnalyzer
    {
        private static readonly string[] MapMethods =
        {
            "MapGet", "MapPost", "MapPut", "MapPatch", "MapDelete"
        };

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
            => ImmutableArray.Create(Diagnostics.SC0005);

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
            context.RegisterSymbolAction(AnalyzeNamedType, SymbolKind.NamedType);
        }

        /// <summary>Route-handler delegates: lambdas/method groups passed to Map* invocations.</summary>
        private static void AnalyzeInvocation(OperationAnalysisContext context)
        {
            var invocation = (IInvocationOperation)context.Operation;
            if (!MapMethods.Contains(invocation.TargetMethod.Name)) return;

            foreach (var argument in invocation.Arguments)
            {
                foreach (var parameter in GetDelegateParameters(argument.Value))
                {
                    CheckParameter(parameter, context.ReportDiagnostic);
                }
            }
        }

        /// <summary>Controller actions: public ordinary methods on *Controller classes.</summary>
        private static void AnalyzeNamedType(SymbolAnalysisContext context)
        {
            var type = (INamedTypeSymbol)context.Symbol;
            if (type.TypeKind != TypeKind.Class) return;
            if (!IsController(type)) return;

            foreach (var method in type.GetMembers().OfType<IMethodSymbol>())
            {
                if (method.MethodKind != MethodKind.Ordinary) continue;
                if (method.DeclaredAccessibility != Accessibility.Public) continue;

                foreach (var parameter in method.Parameters)
                {
                    CheckParameter(parameter, context.ReportDiagnostic);
                }
            }
        }

        private static ImmutableArray<IParameterSymbol> GetDelegateParameters(IOperation operation)
        {
            // Unwrap implicit/explicit conversions (lambda -> System.Delegate goes through one).
            while (operation is IConversionOperation conversion)
            {
                operation = conversion.Operand;
            }

            if (operation is IDelegateCreationOperation delegateCreation)
            {
                operation = delegateCreation.Target;
            }

            return operation switch
            {
                IAnonymousFunctionOperation lambda => lambda.Symbol.Parameters,
                IMethodReferenceOperation methodGroup => methodGroup.Method.Parameters,
                _ => ImmutableArray<IParameterSymbol>.Empty,
            };
        }

        private static void CheckParameter(IParameterSymbol parameter, Action<Diagnostic> report)
        {
            if (HasAttribute(parameter, "FromServices")) return;
            if (HasByDesignExemption(parameter)) return;
            if (!HasAttribute(parameter, "FromForm") && !HasAttribute(parameter, "FromRoute")) return;
            if (!IsRawNonNullableValueType(parameter.Type)) return;

            report(Diagnostic.Create(
                Diagnostics.SC0005,
                parameter.Locations.Length > 0 ? parameter.Locations[0] : Location.None,
                parameter.Name,
                parameter.Type.Name));
        }

        private static bool IsRawNonNullableValueType(ITypeSymbol type)
        {
            // Reference types (string, IFormFile, IFormFileCollection, HttpContext, complex
            // [FromForm] model classes) are never raw value-type bindings.
            if (!type.IsValueType) return false;

            // Nullable<T> binds null on empty submission instead of throwing.
            if (type.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T) return false;

            // bool is excluded (v1.11.1, external review): an unchecked HTML checkbox OMITS the
            // field from the form submission entirely and binding yields false - the
            // present-but-empty hazard this rule guards against does not apply the same way.
            // (bool? already passes via the Nullable<T> exclusion above.)
            if (type.SpecialType == SpecialType.System_Boolean) return false;

            // CancellationToken is framework-supplied, never model-bound.
            if (type.Name == "CancellationToken" &&
                type.ContainingNamespace?.ToDisplayString() == "System.Threading")
            {
                return false;
            }

            return true;
        }

        private static bool IsController(INamedTypeSymbol type)
        {
            if (type.Name.EndsWith("Controller", StringComparison.Ordinal)) return true;
            for (var current = type.BaseType; current != null; current = current.BaseType)
            {
                if (current.Name == "ControllerBase" || current.Name == "Controller") return true;
            }
            return false;
        }

        private static bool HasAttribute(ISymbol symbol, string shortName)
            => symbol.GetAttributes().Any(a =>
                a.AttributeClass?.Name == shortName ||
                a.AttributeClass?.Name == shortName + "Attribute");

        private static bool HasByDesignExemption(ISymbol symbol)
            => symbol.GetAttributes().Any(a =>
                a.AttributeClass?.Name == "BindingValidatedByDesignAttribute" ||
                a.AttributeClass?.Name == "BindingValidatedByDesign");
    }
}
