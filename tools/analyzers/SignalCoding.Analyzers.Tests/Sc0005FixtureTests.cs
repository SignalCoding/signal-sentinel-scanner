// v1.10.0 fixtures for SC0005 (raw value-type binding at the HTTP boundary).
// Known-bad encodes the findings 3.2 failure: [FromForm] Guid throws a raw binding exception
// on an empty/malformed submission before the handler runs.
// NOTE: SC0005 is asserted at Error severity since its scheduled v1.11.0 promotion
// (see Diagnostics.SC0005); it shipped at Warning for its one-release grace period in v1.10.0.
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Testing;
using SignalCoding.Analyzers;
using Xunit;

namespace SignalCoding.Analyzers.Tests
{
    // Stub types stand in for ASP.NET Core binding metadata so tests need no framework packages.
    internal static class Sc0005Stubs
    {
        public const string Common = @"
namespace Microsoft.AspNetCore.Mvc
{
    [System.AttributeUsage(System.AttributeTargets.Parameter | System.AttributeTargets.Property)]
    public class FromFormAttribute : System.Attribute { }
    [System.AttributeUsage(System.AttributeTargets.Parameter | System.AttributeTargets.Property)]
    public class FromRouteAttribute : System.Attribute { }
    [System.AttributeUsage(System.AttributeTargets.Parameter)]
    public class FromServicesAttribute : System.Attribute { }
}
namespace Microsoft.AspNetCore.Http
{
    public interface IFormFile { }
    public interface IFormFileCollection { }
    public class HttpContext { }
}
namespace SignalCoding.Annotations
{
    [System.AttributeUsage(System.AttributeTargets.Parameter)]
    public sealed class BindingValidatedByDesignAttribute : System.Attribute
    { public BindingValidatedByDesignAttribute(string justification) { } }
}
public static class Endpoints
{
    public static void MapGet(string pattern, System.Delegate handler) { }
    public static void MapPost(string pattern, System.Delegate handler) { }
}
";
    }

    public class Sc0005Tests
    {
        [Fact]
        public async Task KnownBad_FromFormGuid_Fails()
        {
            const string source = Sc0005Stubs.Common + @"
public class Wireup
{
    public void Configure()
    {
        Endpoints.MapPost(""/invoices/archive"", ([Microsoft.AspNetCore.Mvc.FromForm] System.Guid {|#0:id|}) => { });
    }
}";
            var test = new CSharpAnalyzerTest<SC0005RawValueTypeBindingAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0005", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("id", "Guid"));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownBad_FromRouteInt_MethodGroup_Fails()
        {
            const string source = Sc0005Stubs.Common + @"
public class Wireup
{
    public static string Handler([Microsoft.AspNetCore.Mvc.FromRoute] int {|#0:id|}) => """";
    public void Configure()
    {
        Endpoints.MapGet(""/invoices/{id}"", Handler);
    }
}";
            var test = new CSharpAnalyzerTest<SC0005RawValueTypeBindingAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0005", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("id", "Int32"));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownGood_NullableAndExcludedParameters_Pass()
        {
            // string?, Guid?, IFormFile, [FromServices], CancellationToken: all clean.
            const string source = "#nullable enable" + Sc0005Stubs.Common + @"
public class Clock { }
public class Wireup
{
    public void Configure()
    {
        Endpoints.MapPost(""/a"", ([Microsoft.AspNetCore.Mvc.FromForm] string? id) => { });
        Endpoints.MapPost(""/b"", ([Microsoft.AspNetCore.Mvc.FromForm] System.Guid? id) => { });
        Endpoints.MapPost(""/c"", (Microsoft.AspNetCore.Http.IFormFile file) => { });
        Endpoints.MapPost(""/d"", ([Microsoft.AspNetCore.Mvc.FromServices] Clock clock) => { });
        Endpoints.MapPost(""/e"", (System.Threading.CancellationToken ct) => { });
        Endpoints.MapPost(""/f"", (Microsoft.AspNetCore.Http.HttpContext ctx) => { });
    }
}";
            await new CSharpAnalyzerTest<SC0005RawValueTypeBindingAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }

        [Fact]
        public async Task KnownGood_FromFormBool_Checkbox_Passes()
        {
            // v1.11.1 (external review): [FromForm] bool is NOT the SC0005 hazard. An unchecked
            // HTML checkbox OMITS the field from the submission entirely and binding yields
            // false rather than throwing, so the present-but-empty failure mode does not apply.
            // (bool? was already excluded via Nullable<T>.)
            const string source = Sc0005Stubs.Common + @"
public class Wireup
{
    public void Configure()
    {
        Endpoints.MapPost(""/signup"", ([Microsoft.AspNetCore.Mvc.FromForm] bool consent) => { });
    }
}";
            await new CSharpAnalyzerTest<SC0005RawValueTypeBindingAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }

        [Fact]
        public async Task KnownGood_ExplicitByDesignExemption_Passes()
        {
            const string source = Sc0005Stubs.Common + @"
public class Wireup
{
    public void Configure()
    {
        Endpoints.MapPost(""/tenants/{tenantId}"",
            ([Microsoft.AspNetCore.Mvc.FromRoute]
             [SignalCoding.Annotations.BindingValidatedByDesign(""Route constraint {tenantId:guid} guarantees a parseable value - see ADR-0014"")]
             System.Guid tenantId) => { });
    }
}";
            await new CSharpAnalyzerTest<SC0005RawValueTypeBindingAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }

        [Fact]
        public async Task KnownGood_ComplexFormModelClass_NoFalsePositive()
        {
            // A complex [FromForm] model (reference type) is the sanctioned pattern; the value-type
            // properties INSIDE it bind through the model binder's settable-property path, not the
            // raw parameter path. Zero diagnostics expected.
            const string source = Sc0005Stubs.Common + @"
public class InvoiceForm
{
    public System.Guid InvoiceId { get; set; }
    public int Quantity { get; set; }
    public string Reference { get; set; }
}
public class Wireup
{
    public void Configure()
    {
        Endpoints.MapPost(""/invoices"", ([Microsoft.AspNetCore.Mvc.FromForm] InvoiceForm form) => { });
    }
}";
            await new CSharpAnalyzerTest<SC0005RawValueTypeBindingAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }

        [Fact]
        public async Task KnownBad_ControllerAction_FromFormGuid_Fails()
        {
            const string source = Sc0005Stubs.Common + @"
public class InvoiceController
{
    public string Archive([Microsoft.AspNetCore.Mvc.FromForm] System.Guid {|#0:id|}) => """";
}";
            var test = new CSharpAnalyzerTest<SC0005RawValueTypeBindingAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0005", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("id", "Guid"));
            await test.RunAsync();
        }
    }
}
