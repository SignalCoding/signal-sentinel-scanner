using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace SignalCoding.Analyzers
{
    /// <summary>
    /// SC0007 (added v1.11.0, FortisISO incident root cause): flags an AddScoped registration
    /// whose factory lambda body is a single GetRequiredService call resolving a type that
    /// derives from Microsoft.EntityFrameworkCore.DbContext, e.g.
    ///
    ///     services.AddScoped&lt;IReportingContext&gt;(sp =&gt; sp.GetRequiredService&lt;AppDbContext&gt;());
    ///
    /// Such a registration hands consumers a captive scoped DbContext behind an interface,
    /// silently undoing AddDbContextFactory&lt;TContext&gt;, and is invisible to SC0001 at the
    /// injection site because the injected interface cannot be checked for DbContext derivation.
    ///
    /// DELIBERATE OVER-APPROXIMATION: the ideal rule fires only when TContext is ALSO registered
    /// via AddDbContextFactory&lt;TContext&gt; in the same compilation. Correlating two independent
    /// invocations reliably in one pass is impractical here (registrations may live in different
    /// methods, partial classes, or extension helpers), so this rule flags the unwrap shape
    /// unconditionally: a scoped registration whose factory merely re-resolves a DbContext is a
    /// captive-context hazard whether or not a factory registration exists. If a project has a
    /// genuinely justified case, suppress explicitly and greppably at the call site with
    /// #pragma warning disable SC0007 or [SuppressMessage("SignalCoding.Architecture", "SC0007",
    /// Justification = "...")] - every suppression is an audit item.
    ///
    /// Matched by name/shape (AddScoped + GetRequiredService, generic or typeof-based) so the
    /// analyzer needs no Microsoft.Extensions.DependencyInjection package reference at compile
    /// time. Casts and conversions around the GetRequiredService call are unwrapped.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class SC0007ScopedDbContextUnwrapRegistrationAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
            => ImmutableArray.Create(Diagnostics.SC0007);

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
        }

        private static void AnalyzeInvocation(OperationAnalysisContext context)
        {
            var invocation = (IInvocationOperation)context.Operation;
            if (invocation.TargetMethod.Name != "AddScoped") return;

            foreach (var argument in invocation.Arguments)
            {
                var lambda = UnwrapToLambda(argument.Value);
                if (lambda == null) continue;

                var resolvedContext = GetSingleDbContextResolution(lambda);
                if (resolvedContext == null) continue;

                context.ReportDiagnostic(Diagnostic.Create(
                    Diagnostics.SC0007,
                    invocation.Syntax.GetLocation(),
                    GetRegisteredServiceName(invocation, resolvedContext),
                    resolvedContext.Name));
            }
        }

        /// <summary>The service type the registration exposes: AddScoped's first type argument
        /// when generic, otherwise the resolved context type itself.</summary>
        private static string GetRegisteredServiceName(IInvocationOperation invocation, ITypeSymbol fallback)
        {
            var typeArguments = invocation.TargetMethod.TypeArguments;
            return typeArguments.Length > 0 ? typeArguments[0].Name : fallback.Name;
        }

        private static IAnonymousFunctionOperation? UnwrapToLambda(IOperation operation)
        {
            while (operation is IConversionOperation conversion)
            {
                operation = conversion.Operand;
            }
            if (operation is IDelegateCreationOperation delegateCreation)
            {
                operation = delegateCreation.Target;
            }
            return operation as IAnonymousFunctionOperation;
        }

        /// <summary>
        /// If the lambda body is a single expression (or single return) that is a
        /// GetRequiredService call resolving a DbContext-derived type - via a generic type
        /// argument or a typeof(...) argument - returns that context type; otherwise null.
        /// </summary>
        private static ITypeSymbol? GetSingleDbContextResolution(IAnonymousFunctionOperation lambda)
        {
            var body = lambda.Body;
            if (body == null) return null;

            IOperation? returned = null;
            foreach (var statement in body.Operations)
            {
                if (statement.IsImplicit && statement is IReturnOperation { ReturnedValue: null })
                {
                    continue; // trailing implicit return emitted for expression lambdas
                }
                if (returned != null) return null; // more than one statement: not the unwrap shape
                returned = statement switch
                {
                    IReturnOperation returnOperation => returnOperation.ReturnedValue,
                    IExpressionStatementOperation expressionStatement => expressionStatement.Operation,
                    _ => null,
                };
                if (returned == null) return null;
            }
            if (returned == null) return null;

            // Unwrap implicit reference conversions and explicit casts (TInterface)sp.GetRequiredService(...)
            while (returned is IConversionOperation conversion)
            {
                returned = conversion.Operand;
            }

            if (returned is not IInvocationOperation resolve) return null;
            if (resolve.TargetMethod.Name != "GetRequiredService") return null;

            // Generic form: sp.GetRequiredService<TContext>()
            if (resolve.TargetMethod.TypeArguments.Length == 1)
            {
                var typeArgument = resolve.TargetMethod.TypeArguments[0];
                return DerivesFromDbContext(typeArgument) ? typeArgument : null;
            }

            // Non-generic form: sp.GetRequiredService(typeof(TContext))
            foreach (var resolveArgument in resolve.Arguments)
            {
                if (resolveArgument.Value is ITypeOfOperation typeOf &&
                    DerivesFromDbContext(typeOf.TypeOperand))
                {
                    return typeOf.TypeOperand;
                }
            }
            return null;
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
