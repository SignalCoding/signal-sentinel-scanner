// -----------------------------------------------------------------------
// <copyright file="PolicyStrictPresetTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// v3.0.2 (N6): security review Finding 1 (High). After N2 dropped SS-024 "Skill Not
// Signed" to Info severity, the `strict` preset's `bumpOneBand` list only raises it
// one band (Info -> Low), which sits below `strict`'s own `failOn: medium` - so an
// unsigned skill silently stops failing CI under `--policy strict`, defeating the
// preset's purpose. `default` and `defence` are unaffected controls.
// Spec: _docs/ai/completed/2026-09-24_v3.0.2-skill-noise.md section 8, N6.

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Policy;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Policy;

public class PolicyStrictPresetTests
{
    private static Finding MakeUnsignedSkillFinding() => new()
    {
        RuleId = "SS-024",
        OwaspCode = "ASI04",
        Severity = Severity.Info,
        Title = "Skill Not Signed: sample",
        Description = "generated",
        Remediation = "generated",
        ServerName = "sample"
    };

    [Fact]
    public void N6_Strict_UnsignedSkillFinding_ResultsInHighSeverity()
    {
        PolicyLoader.TryResolve("strict", out var policy, out _).ShouldBeTrue();
        var resolved = policy.ShouldNotBeNull();

        var result = PolicyApplier.Apply([MakeUnsignedSkillFinding()], resolved);

        result[0].Severity.ShouldBe(Severity.High);
    }

    [Fact]
    public void N6_Strict_UnsignedSkillFinding_MeetsFailOnThreshold()
    {
        PolicyLoader.TryResolve("strict", out var policy, out _).ShouldBeTrue();
        var resolved = policy.ShouldNotBeNull();

        var result = PolicyApplier.Apply([MakeUnsignedSkillFinding()], resolved);

        // Same comparison Program.cs uses to decide CI exit code: any finding whose
        // severity is at or above the resolved fail-on threshold breaches.
        var failOn = resolved.FailOn.ShouldNotBeNull();
        var breached = result.Any(f => f.Severity >= failOn);

        breached.ShouldBeTrue();
    }

    [Fact]
    public void N6_Default_UnsignedSkillFinding_StaysInfo()
    {
        PolicyLoader.TryResolve("default", out var policy, out _).ShouldBeTrue();
        var resolved = policy.ShouldNotBeNull();

        var result = PolicyApplier.Apply([MakeUnsignedSkillFinding()], resolved);

        result[0].Severity.ShouldBe(Severity.Info);
    }

    [Fact]
    public void N6_Defence_UnsignedSkillFinding_BumpsToLowOnly()
    {
        PolicyLoader.TryResolve("defence", out var policy, out _).ShouldBeTrue();
        var resolved = policy.ShouldNotBeNull();

        var result = PolicyApplier.Apply([MakeUnsignedSkillFinding()], resolved);

        // defence has no SS-024-specific override - bumpAllOneBand only, one band.
        result[0].Severity.ShouldBe(Severity.Low);
    }
}
