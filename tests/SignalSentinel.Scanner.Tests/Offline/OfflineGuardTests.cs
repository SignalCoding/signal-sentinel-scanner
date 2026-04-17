using Shouldly;
using SignalSentinel.Scanner.Offline;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Offline;

// OfflineGuard is process-global static state; serialise tests to prevent cross-test leakage.
[Collection("OfflineGuardSerial")]
public class OfflineGuardTests : IDisposable
{
    public OfflineGuardTests()
    {
        OfflineGuard.Reset();
    }

    public void Dispose()
    {
        OfflineGuard.Reset();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void EnsureAllowed_Disabled_DoesNotThrow()
    {
        OfflineGuard.IsOffline.ShouldBeFalse();
        Should.NotThrow(() => OfflineGuard.EnsureAllowed("HTTP GET"));
    }

    [Fact]
    public void EnsureAllowed_Enabled_Throws()
    {
        OfflineGuard.Enable();
        OfflineGuard.IsOffline.ShouldBeTrue();

        var ex = Should.Throw<OfflineViolationException>(() => OfflineGuard.EnsureAllowed("HTTP GET"));
        ex.Operation.ShouldBe("HTTP GET");
        ex.Message.ShouldContain("HTTP GET");
    }

    [Fact]
    public void Reset_RestoresAllowedState()
    {
        OfflineGuard.Enable();
        OfflineGuard.Reset();

        OfflineGuard.IsOffline.ShouldBeFalse();
        Should.NotThrow(() => OfflineGuard.EnsureAllowed("HTTP GET"));
    }

    [Fact]
    public void Enable_Idempotent()
    {
        OfflineGuard.Enable();
        OfflineGuard.Enable();

        OfflineGuard.IsOffline.ShouldBeTrue();
    }
}

[CollectionDefinition("OfflineGuardSerial", DisableParallelization = true)]
public sealed class OfflineGuardCollection
{
}
