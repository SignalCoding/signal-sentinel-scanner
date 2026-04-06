// -----------------------------------------------------------------------
// <copyright file="CredentialPatternsTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Security;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SharedPatterns;

public class CredentialPatternsTests
{
    [Theory]
    [InlineData("$ANTHROPIC_API_KEY")]
    [InlineData("$OPENAI_API_KEY")]
    [InlineData("$AWS_SECRET_ACCESS_KEY")]
    [InlineData("$GITHUB_TOKEN")]
    [InlineData("$STRIPE_SECRET_KEY")]
    public void WellKnownApiKeyVars_DetectsKnownVars(string input)
    {
        CredentialPatterns.WellKnownApiKeyVars().IsMatch(input).ShouldBeTrue();
    }

    [Theory]
    [InlineData("~/.ssh/id_rsa")]
    [InlineData("~/.ssh/id_ed25519")]
    [InlineData(".ssh/authorized_keys")]
    public void SshKeyAccess_DetectsSshFiles(string input)
    {
        CredentialPatterns.SshKeyAccess().IsMatch(input).ShouldBeTrue();
    }

    [Theory]
    [InlineData(".env")]
    [InlineData(".env.local")]
    [InlineData(".aws/credentials")]
    [InlineData(".kube/config")]
    [InlineData("service_account_key.json")]
    public void SecretFileAccess_DetectsSecretFiles(string input)
    {
        CredentialPatterns.SecretFileAccess().IsMatch(input).ShouldBeTrue();
    }

    [Theory]
    [InlineData("sk-abcdefghijklmnopqrstuvwxyz")]
    [InlineData("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")]
    [InlineData("AKIAIOSFODNN7EXAMPLE")]
    public void HardcodedSecrets_DetectsKnownPatterns(string input)
    {
        CredentialPatterns.HardcodedSecrets().IsMatch(input).ShouldBeTrue();
    }

    [Fact]
    public void WellKnownApiKeyVars_AllowsNormalText()
    {
        CredentialPatterns.WellKnownApiKeyVars().IsMatch("Hello world").ShouldBeFalse();
    }

    [Fact]
    public void AllPatterns_HasExpectedCount()
    {
        CredentialPatterns.AllPatterns.Count.ShouldBe(5);
    }
}
