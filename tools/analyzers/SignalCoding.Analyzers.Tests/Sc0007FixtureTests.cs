// v1.11.0 fixtures for SC0007 (scoped interface registration undoing DbContextFactory).
// Known-bad encodes the FortisISO incident root cause: AddScoped<TInterface>(sp =>
// sp.GetRequiredService<TContext>()) hands MediatR handlers (and anything else injecting the
// interface) a captive scoped DbContext that SC0001 cannot see at the injection site.
// NOTE: SC0007 deliberately over-approximates - it fires on the unwrap shape whether or not
// AddDbContextFactory<TContext> is present in the compilation (see the analyzer header comment);
// the known-bad fixtures therefore include one scenario with the factory registration and one
// without. App code sits in a namespace with an inner using directive: a top-level using cannot
// follow the stub namespace declarations in the concatenated compilation unit (CS1529).
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Testing;
using SignalCoding.Analyzers;
using Xunit;

namespace SignalCoding.Analyzers.Tests
{
    // Stub types stand in for EF Core / Microsoft.Extensions.DependencyInjection so tests need
    // no framework packages - the analyzer matches by name/shape only.
    internal static class Sc0007Stubs
    {
        public const string Common = @"
namespace Microsoft.EntityFrameworkCore
{
    public class DbContext { }
    public interface IDbContextFactory<TContext> where TContext : DbContext
    { TContext CreateDbContext(); }
}
namespace Microsoft.Extensions.DependencyInjection
{
    public interface IServiceCollection { }
    public static class ServiceCollectionServiceExtensions
    {
        public static IServiceCollection AddScoped<TService>(this IServiceCollection services, System.Func<System.IServiceProvider, TService> implementationFactory) where TService : class => services;
        public static IServiceCollection AddScoped<TService, TImplementation>(this IServiceCollection services) where TService : class where TImplementation : class, TService => services;
        public static IServiceCollection AddDbContextFactory<TContext>(this IServiceCollection services) where TContext : Microsoft.EntityFrameworkCore.DbContext => services;
    }
    public static class ServiceProviderServiceExtensions
    {
        public static T GetRequiredService<T>(this System.IServiceProvider provider) => default!;
        public static object GetRequiredService(this System.IServiceProvider provider, System.Type serviceType) => null!;
    }
}
";
    }

    public class Sc0007Tests
    {
        [Fact]
        public async Task KnownBad_ScopedInterfaceUnwrapAlongsideFactory_Fails()
        {
            const string source = Sc0007Stubs.Common + @"
namespace App
{
    using Microsoft.Extensions.DependencyInjection;
    public interface IReportingContext { }
    public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext, IReportingContext { }
    public class Wireup
    {
        public void Configure(IServiceCollection services)
        {
            services.AddDbContextFactory<AppDbContext>();
            {|#0:services.AddScoped<IReportingContext>(sp => sp.GetRequiredService<AppDbContext>())|};
        }
    }
}";
            var test = new CSharpAnalyzerTest<SC0007ScopedDbContextUnwrapRegistrationAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0007", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("IReportingContext", "AppDbContext"));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownBad_ScopedUnwrap_NoFactoryRegistration_Fails()
        {
            // Deliberate over-approximation: fires even without AddDbContextFactory in sight.
            const string source = Sc0007Stubs.Common + @"
namespace App
{
    using Microsoft.Extensions.DependencyInjection;
    public interface IReportingContext { }
    public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext, IReportingContext { }
    public class Wireup
    {
        public void Configure(IServiceCollection services)
        {
            {|#0:services.AddScoped<IReportingContext>(sp => sp.GetRequiredService<AppDbContext>())|};
        }
    }
}";
            var test = new CSharpAnalyzerTest<SC0007ScopedDbContextUnwrapRegistrationAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0007", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("IReportingContext", "AppDbContext"));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownBad_ScopedUnwrap_NonGenericTypeofResolution_Fails()
        {
            const string source = Sc0007Stubs.Common + @"
namespace App
{
    using Microsoft.Extensions.DependencyInjection;
    public interface IReportingContext { }
    public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext, IReportingContext { }
    public class Wireup
    {
        public void Configure(IServiceCollection services)
        {
            {|#0:services.AddScoped<IReportingContext>(sp => (IReportingContext)sp.GetRequiredService(typeof(AppDbContext)))|};
        }
    }
}";
            var test = new CSharpAnalyzerTest<SC0007ScopedDbContextUnwrapRegistrationAnalyzer, DefaultVerifier>
            { TestCode = source };
            test.ExpectedDiagnostics.Add(new DiagnosticResult("SC0007", Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
                .WithLocation(0).WithArguments("IReportingContext", "AppDbContext"));
            await test.RunAsync();
        }

        [Fact]
        public async Task KnownGood_ScopedNormalServiceInterface_Passes()
        {
            // AddScoped of an ordinary service - by implementation type or by factory resolving a
            // non-DbContext type - is the sanctioned pattern and must stay clean.
            const string source = Sc0007Stubs.Common + @"
namespace App
{
    using Microsoft.Extensions.DependencyInjection;
    public interface IClock { }
    public class SystemClock : IClock { }
    public class Wireup
    {
        public void Configure(IServiceCollection services)
        {
            services.AddScoped<IClock, SystemClock>();
            services.AddScoped<IClock>(sp => new SystemClock());
            services.AddScoped<IClock>(sp => sp.GetRequiredService<SystemClock>());
        }
    }
}";
            await new CSharpAnalyzerTest<SC0007ScopedDbContextUnwrapRegistrationAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }

        [Fact]
        public async Task KnownGood_AddDbContextFactoryAlone_Passes()
        {
            const string source = Sc0007Stubs.Common + @"
namespace App
{
    using Microsoft.Extensions.DependencyInjection;
    public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext { }
    public class Wireup
    {
        public void Configure(IServiceCollection services)
        {
            services.AddDbContextFactory<AppDbContext>();
        }
    }
}";
            await new CSharpAnalyzerTest<SC0007ScopedDbContextUnwrapRegistrationAnalyzer, DefaultVerifier>
            { TestCode = source }.RunAsync();
        }
    }
}
