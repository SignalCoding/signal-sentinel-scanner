// -----------------------------------------------------------------------
// <copyright file="IntegrityVerifierChecksumTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Security.Cryptography;
using System.Text;
using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillParser;

public class IntegrityVerifierChecksumTests
{
    private static string Sha256Hex(string content) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    [Fact]
    public void ParseChecksumLine_GnuFormat_ParsesHexAndPath()
    {
        var hex = new string('a', 64);

        var parsed = IntegrityVerifier.ParseChecksumLine($"{hex}  scripts/run.sh");

        parsed.ShouldNotBeNull();
        parsed.Value.Hex.ShouldBe(hex);
        parsed.Value.Path.ShouldBe(Path.Combine("scripts", "run.sh"));
    }

    [Fact]
    public void ParseChecksumLine_BinaryMarkerAndDotSlash_Stripped()
    {
        var hex = new string('B', 64);

        var parsed = IntegrityVerifier.ParseChecksumLine($"{hex} *./SKILL.md");

        parsed.ShouldNotBeNull();
        parsed.Value.Hex.ShouldBe(new string('b', 64));
        parsed.Value.Path.ShouldBe("SKILL.md");
    }

    [Fact]
    public void ParseChecksumLine_BsdFormat_Parses()
    {
        var hex = new string('c', 64);

        var parsed = IntegrityVerifier.ParseChecksumLine($"SHA256 (SKILL.md) = {hex}");

        parsed.ShouldNotBeNull();
        parsed.Value.Path.ShouldBe("SKILL.md");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("# comment")]
    [InlineData("notahash  file.txt")]
    [InlineData("abcdef  file.txt")]
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz  file.txt")]
    public void ParseChecksumLine_Malformed_ReturnsNull(string line)
    {
        IntegrityVerifier.ParseChecksumLine(line).ShouldBeNull();
    }

    [Fact]
    public void ParseChecksumLine_HexOnlyNoPath_ReturnsNull()
    {
        IntegrityVerifier.ParseChecksumLine(new string('a', 64) + "  ").ShouldBeNull();
    }

    [Fact]
    public void Verify_ManifestWithMatchMismatchMissingInvalid_ReportsEach()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"integrity-cs-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(dir, "scripts"));
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# skill");
            File.WriteAllText(Path.Combine(dir, "scripts", "run.sh"), "echo hi");

            var manifest =
                $"{Sha256Hex("# skill")}  SKILL.md\n" +
                $"{new string('0', 64)}  scripts/run.sh\n" +
                $"{new string('1', 64)}  scripts/missing.py\n" +
                $"{new string('2', 64)}  ../../etc/passwd\n" +
                "# trailing comment\n";
            File.WriteAllText(Path.Combine(dir, "SHA256SUMS"), manifest);

            var report = IntegrityVerifier.Verify(new SkillDefinition
            {
                Name = "t",
                InstructionsBody = string.Empty,
                RawContent = "# skill",
                FilePath = Path.Combine(dir, "SKILL.md")
            });

            report.SignaturePresent.ShouldBeTrue();
            report.ChecksumResults.Count.ShouldBe(4);
            report.ChecksumResults.ShouldContain(r => r.RelativePath == "SKILL.md" && r.Status == ChecksumStatus.Match);
            report.ChecksumResults.ShouldContain(r => r.RelativePath.EndsWith("run.sh", StringComparison.Ordinal) && r.Status == ChecksumStatus.Mismatch && r.Actual == Sha256Hex("echo hi"));
            report.ChecksumResults.ShouldContain(r => r.RelativePath.EndsWith("missing.py", StringComparison.Ordinal) && r.Status == ChecksumStatus.Missing);
            report.ChecksumResults.ShouldContain(r => r.RelativePath.EndsWith("passwd", StringComparison.Ordinal) && r.Status == ChecksumStatus.Invalid);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Verify_AbsoluteAndRootedPaths_ReportedInvalid()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"integrity-abs-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# skill");
            var manifest =
                $"{new string('a', 64)}  /etc/passwd\n" +
                $"{new string('b', 64)}  C:/Windows/System32/config/SAM\n" +
                $"{new string('c', 64)}  \\\\server\\share\\file\n";
            File.WriteAllText(Path.Combine(dir, "SHA256SUMS"), manifest);

            var report = IntegrityVerifier.Verify(new SkillDefinition
            {
                Name = "t",
                InstructionsBody = string.Empty,
                RawContent = "# skill",
                FilePath = Path.Combine(dir, "SKILL.md")
            });

            report.ChecksumResults.Count.ShouldBe(3);
            report.ChecksumResults.ShouldNotContain(r => r.Status == ChecksumStatus.Match || r.Status == ChecksumStatus.Mismatch);
            report.ChecksumResults[0].Status.ShouldBe(ChecksumStatus.Invalid); // /etc/passwd is rooted everywhere
            report.ChecksumResults[2].Status.ShouldBe(ChecksumStatus.Invalid); // UNC / double-slash is rooted everywhere
            if (OperatingSystem.IsWindows())
            {
                report.ChecksumResults[1].Status.ShouldBe(ChecksumStatus.Invalid); // drive letter only rooted on Windows
            }
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Verify_DuplicateEntries_HashedOnceAndBothReported()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"integrity-dup-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# skill");
            var good = Sha256Hex("# skill");
            File.WriteAllText(Path.Combine(dir, "SHA256SUMS"), $"{good}  SKILL.md\n{new string('0', 64)}  ./SKILL.md\n");

            var report = IntegrityVerifier.Verify(new SkillDefinition
            {
                Name = "t",
                InstructionsBody = string.Empty,
                RawContent = "# skill",
                FilePath = Path.Combine(dir, "SKILL.md")
            });

            report.ChecksumResults.Count.ShouldBe(2);
            report.ChecksumResults[0].Status.ShouldBe(ChecksumStatus.Match);
            report.ChecksumResults[1].Status.ShouldBe(ChecksumStatus.Mismatch);
            report.ChecksumResults[1].Actual.ShouldBe(good);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Verify_PresenceOnly_SkipsHashing()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"integrity-presence-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# skill");
            File.WriteAllText(Path.Combine(dir, "checksums.sha256"), $"{new string('0', 64)}  SKILL.md\n");

            var report = IntegrityVerifier.Verify(new SkillDefinition
            {
                Name = "t",
                InstructionsBody = string.Empty,
                RawContent = "# skill",
                FilePath = Path.Combine(dir, "SKILL.md")
            }, verifyChecksums: false);

            report.SignaturePresent.ShouldBeTrue();
            report.SignatureFileName.ShouldBe("checksums.sha256");
            report.ChecksumResults.ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void ParseChecksumLine_GnuEscapedPrefix_Stripped()
    {
        var hex = new string('d', 64);

        var parsed = IntegrityVerifier.ParseChecksumLine($"\\{hex}  weird name.txt");

        parsed.ShouldNotBeNull();
        parsed.Value.Path.ShouldBe("weird name.txt");
    }

    [Fact]
    public void Verify_OmsSignature_CountsAsSignaturePresent()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"integrity-oms-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# skill");
            File.WriteAllText(Path.Combine(dir, "my-skill.oms.sig"), "sig");

            var report = IntegrityVerifier.Verify(new SkillDefinition
            {
                Name = "t",
                InstructionsBody = string.Empty,
                RawContent = "# skill",
                FilePath = Path.Combine(dir, "SKILL.md")
            });

            report.SignaturePresent.ShouldBeTrue();
            report.SignatureFileName.ShouldBe("my-skill.oms.sig");
            report.ChecksumResults.ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Verify_NoManifest_ChecksumResultsEmpty()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"integrity-none-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# skill");

            var report = IntegrityVerifier.Verify(new SkillDefinition
            {
                Name = "t",
                InstructionsBody = string.Empty,
                RawContent = "# skill",
                FilePath = Path.Combine(dir, "SKILL.md")
            });

            report.SignaturePresent.ShouldBeFalse();
            report.ChecksumResults.ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
