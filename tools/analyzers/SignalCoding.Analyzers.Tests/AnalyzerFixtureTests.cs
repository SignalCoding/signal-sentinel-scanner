// WP3 mandatory fixtures (spec 5.4): each rule has known-bad and known-good samples.
// The four known-bad samples encode harvested gap patterns from prior production builds (anonymised).
// A rule is NOT complete until its known-bad fixture fails and its known-good fixture passes.
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Testing;
using SignalCoding.Analyzers;
using Xunit;

namespace SignalCoding.Analyzers.Tests
{
    // Stub types stand in for EF Core / ASP.NET metadata so tests need no framework packages.
    internal static class Stubs
    {
        public const string Common = @"
namespace Microsoft.EntityFrameworkCore { public class DbContext { } }
namespace Microsoft.AspNetCore.Authorization
{
    public class AuthorizeAttribute : System.Attribute
    {
        public AuthorizeAttribute() { } public AuthorizeAttribute(string policy) { }
        public string Policy { get; set; } public string Roles { get; set; }
    }
}
namespace SignalCoding.Annotations
{
    [System.AttributeUsage(System.AttributeTargets.Method | System.AttributeTargets.Class)]
    public sealed class AllowAnonymousByDesignAttribute : System.Attribute
    { public AllowAnonymousByDesignAttribute(string justification) { } }
}
";

        // v1.11.0: MediatR surface for the widened SC0001 scope. Name/namespace shape is all the
        // analyzer matches on, so a two-interface stub suffices - no MediatR package needed.
        public const string MediatR = @"
namespace MediatR
{
    public interface IRequestHandler<TRequest> { }
    public interface IRequestHandler<TRequest, TResponse> { }
}
";
    }

    public class Sc0001Tests
    {
        [Fact]
        public async Task KnownBad_DirectDbContextInjection_Fails()
        {
            const string source = Stubs.Common + @"
public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext { }
public class InvoiceService
{
    private readonly AppDbContext _db;
    public InvoiceService(AppDbContext {|#0:db|}) { _db = db; }
}";
            var test = new CSharpAnalyzerTest<SC0001DbContextDirectInjectionAnalyzer, DefaultVerifier>
            {
                TestCode = source,
            };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0001", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("InvoiceService", "AppDbContext"));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownGood_FactoryInjection_Passes()
        {
            const string source = Stubs.Common + @"
public interface IDbContextFactory<T> { T CreateDbContext(); }
public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext { }
public class InvoiceService
{
    private readonly IDbContextFactory<AppDbContext> _factory;
    public InvoiceService(IDbContextFactory<AppDbContext> factory) { _factory = factory; }
}";
            await new CSharpAnalyzerTest<SC0001DbContextDirectInjectionAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }

        // v1.11.0 (FortisISO incident): a MediatR handler injecting a DbContext-derived type
        // directly must fire SC0001 even though its name does not end in "Service" - this exact
        // shape was missed by the v1.10.x name heuristic in production.
        [Fact]
        public async Task KnownBad_MediatRHandler_DirectDbContextInjection_Fails()
        {
            const string source = Stubs.Common + Stubs.MediatR + @"
public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext { }
public class ArchiveInvoiceCommand { }
public class ArchiveInvoiceCommandHandler : MediatR.IRequestHandler<ArchiveInvoiceCommand>
{
    private readonly AppDbContext _db;
    public ArchiveInvoiceCommandHandler(AppDbContext {|#0:db|}) { _db = db; }
}";
            var test = new CSharpAnalyzerTest<SC0001DbContextDirectInjectionAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0001", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("ArchiveInvoiceCommandHandler", "AppDbContext"));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownBad_MediatRHandlerWithResponse_DirectDbContextInjection_Fails()
        {
            const string source = Stubs.Common + Stubs.MediatR + @"
public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext { }
public class GetInvoiceQuery { }
public class GetInvoiceQueryHandler : MediatR.IRequestHandler<GetInvoiceQuery, string>
{
    private readonly AppDbContext _db;
    public GetInvoiceQueryHandler(AppDbContext {|#0:db|}) { _db = db; }
}";
            var test = new CSharpAnalyzerTest<SC0001DbContextDirectInjectionAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0001", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("GetInvoiceQueryHandler", "AppDbContext"));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownGood_MediatRHandler_FactoryInjection_Passes()
        {
            const string source = Stubs.Common + Stubs.MediatR + @"
public interface IDbContextFactory<T> { T CreateDbContext(); }
public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext { }
public class ArchiveInvoiceCommand { }
public class ArchiveInvoiceCommandHandler : MediatR.IRequestHandler<ArchiveInvoiceCommand>
{
    private readonly IDbContextFactory<AppDbContext> _factory;
    public ArchiveInvoiceCommandHandler(IDbContextFactory<AppDbContext> factory) { _factory = factory; }
}";
            await new CSharpAnalyzerTest<SC0001DbContextDirectInjectionAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }

        // A handler injecting an INTERFACE that happens to wrap a scoped DbContext is deliberately
        // NOT an SC0001 case: an interface type cannot be checked for DbContext derivation at the
        // injection site. The registration itself is the defect and fires SC0007 (see Sc0007Tests).
        [Fact]
        public async Task KnownGood_MediatRHandler_InterfaceInjection_NoSc0001()
        {
            const string source = Stubs.Common + Stubs.MediatR + @"
public interface IReportingContext { }
public class ArchiveInvoiceCommand { }
public class ArchiveInvoiceCommandHandler : MediatR.IRequestHandler<ArchiveInvoiceCommand>
{
    private readonly IReportingContext _context;
    public ArchiveInvoiceCommandHandler(IReportingContext context) { _context = context; }
}";
            await new CSharpAnalyzerTest<SC0001DbContextDirectInjectionAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }
    }

    public class Sc0002Tests
    {
        [Fact]
        public async Task KnownBad_MagicStringPermission_Fails()
        {
            const string source = Stubs.Common + @"
public class Gate { public static bool HasPermission(string code) => true; }
public class ReportService
{
    public void Run() { Gate.HasPermission({|#0:""RPT.VIEW""|}); }
}";
            var test = new CSharpAnalyzerTest<SC0002MagicStringPermissionAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0002", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("HasPermission"));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownGood_ConstantsClassReference_Passes()
        {
            const string source = Stubs.Common + @"
public static class Permissions { public const string ReportView = ""RPT.VIEW""; }
public class Gate { public static bool HasPermission(string code) => true; }
public class ReportService
{
    public void Run() { Gate.HasPermission(Permissions.ReportView); }
}";
            await new CSharpAnalyzerTest<SC0002MagicStringPermissionAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }
    }

    public class Sc0003Tests
    {
        [Fact]
        public async Task KnownBad_AuthorizationInUseButNoPermissionsClass_Fails()
        {
            const string source = Stubs.Common + @"
public class Gate { public static bool HasPermission(string code) => true; }
public class UserService
{
    public void Run() { {|#0:Gate.HasPermission(""U.EDIT"")|}; }
}";
            var test = new CSharpAnalyzerTest<SC0003PermissionsClassExistsAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0003", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownGood_PermissionsClassPresent_Passes()
        {
            const string source = Stubs.Common + @"
public static class Permissions { public const string UserEdit = ""U.EDIT""; }
public class Gate { public static bool HasPermission(string code) => true; }
public class UserService
{
    public void Run() { Gate.HasPermission(Permissions.UserEdit); }
}";
            await new CSharpAnalyzerTest<SC0003PermissionsClassExistsAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }

        // v1.11.1 (external review, cross-compilation false positive): under the mandated Clean
        // Architecture layering the Permissions class lives in the Application project, while
        // Infrastructure/UI are SEPARATE compilations that reference it. SC0003 must find the
        // class through the reference, not only in the current compilation. Cross-compilation is
        // modelled here with the testing framework's AdditionalProjects (built as a second
        // project and consumed via a project reference); the same case is also asserted against
        // a real emitted MetadataReference in the behavioural verification driver, which is the
        // authoritative check if this harness's project-reference plumbing ever differs.
        [Fact]
        public async Task KnownGood_PermissionsClassInReferencedCompilation_Passes()
        {
            const string source = Stubs.Common + @"
public class Gate { public static bool HasPermission(string code) => true; }
public class UserService
{
    public void Run() { Gate.HasPermission(MyApp.Application.Permissions.UserEdit); }
}";
            var test = new CSharpAnalyzerTest<SC0003PermissionsClassExistsAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.TestState.AdditionalProjects["Application"].Sources.Add(("Permissions.cs", @"
namespace MyApp.Application
{
    public static class Permissions { public const string UserEdit = ""U.EDIT""; }
}"));
            test.TestState.AdditionalProjectReferences.Add("Application");
            await test.RunAsync();
        }
    }

    public class Sc0004Tests
    {
        [Fact]
        public async Task KnownBad_UnauthorizedMutatingMethod_Fails()
        {
            const string source = Stubs.Common + @"
public class OrderService
{
    public void {|#0:DeleteOrder|}(int id) { }
}";
            var test = new CSharpAnalyzerTest<SC0004UnauthorizedMutatingServiceAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0004", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("OrderService", "DeleteOrder"));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownGood_AuthorizedMethod_Passes()
        {
            // Attributes fully qualified: a using directive cannot follow the stub namespace
            // declarations in the concatenated compilation unit (CS1529).
            const string source = Stubs.Common + @"
public class OrderService
{
    [Microsoft.AspNetCore.Authorization.Authorize]
    public void DeleteOrder(int id) { }
}";
            await new CSharpAnalyzerTest<SC0004UnauthorizedMutatingServiceAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }

        [Fact]
        public async Task KnownGood_ExplicitByDesignExemption_Passes()
        {
            const string source = Stubs.Common + @"
public class SignupService
{
    [SignalCoding.Annotations.AllowAnonymousByDesign(""Public self-registration endpoint - see ADR-0009"")]
    public void CreateAccount(string email) { }
}";
            await new CSharpAnalyzerTest<SC0004UnauthorizedMutatingServiceAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }
    }
}
