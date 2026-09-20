// -----------------------------------------------------------------------
// <copyright file="SkillForensicsRulesTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Security.Cryptography;
using System.Text;
using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

/// <summary>
/// v3.0.0 WP3: SS-034 (integrity mismatch) and SS-035 (suspicious artefacts).
/// </summary>
public class SkillForensicsRulesTests
{
    // ---------------------------------------------------------------- SS-034

    [Fact]
    public async Task IntegrityMismatch_NoManifest_NoFindings()
    {
        var dir = TempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# s");
            var ctx = Context(Skill(dir));

            var findings = await new SkillIntegrityMismatchRule().EvaluateAsync(ctx);

            findings.ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task IntegrityMismatch_AllMatch_NoFindings()
    {
        var dir = TempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# s");
            File.WriteAllText(Path.Combine(dir, "SHA256SUMS"), $"{Hex("# s")}  SKILL.md\n");
            var ctx = Context(Skill(dir));

            var findings = await new SkillIntegrityMismatchRule().EvaluateAsync(ctx);

            findings.ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task IntegrityMismatch_Mismatch_FiresHigh()
    {
        var dir = TempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# tampered");
            File.WriteAllText(Path.Combine(dir, "SHA256SUMS"), $"{Hex("# original")}  SKILL.md\n");
            var ctx = Context(Skill(dir));

            var findings = (await new SkillIntegrityMismatchRule().EvaluateAsync(ctx)).ToList();

            findings.Count.ShouldBe(1);
            findings[0].RuleId.ShouldBe("SS-034");
            findings[0].Severity.ShouldBe(Severity.High);
            findings[0].Source.ShouldBe(FindingSource.Skill);
            var evidence = findings[0].Evidence;
            evidence.ShouldNotBeNull();
            evidence.ShouldContain("SKILL.md");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task IntegrityMismatch_MissingAndInvalid_FireMediumAndLow()
    {
        var dir = TempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# s");
            File.WriteAllText(Path.Combine(dir, "SHA256SUMS"),
                $"{Hex("# s")}  SKILL.md\n" +
                $"{new string('0', 64)}  gone.py\n" +
                $"{new string('1', 64)}  ../escape.txt\n");
            var ctx = Context(Skill(dir));

            var findings = (await new SkillIntegrityMismatchRule().EvaluateAsync(ctx)).ToList();

            findings.Count.ShouldBe(2);
            findings.ShouldContain(f => f.Severity == Severity.Medium && f.Title.Contains("Missing"));
            findings.ShouldContain(f => f.Severity == Severity.Low && f.Title.Contains("Unverifiable"));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    // ---------------------------------------------------------------- SS-035

    [Fact]
    public async Task SuspiciousArtefact_CleanPackage_NoFindings()
    {
        var ctx = Context(SkillWith(
            A("SKILL.md", ".md", FileArtefactKind.Unknown),
            A("scripts/run.py", ".py", FileArtefactKind.Shebang),
            A(".gitignore", ".gitignore", FileArtefactKind.Unknown, hidden: true),
            A(".github/workflows/ci.yml", ".yml", FileArtefactKind.Unknown),
            A("scripts/__pycache__/run.cpython-312.pyc", ".pyc", FileArtefactKind.PythonBytecode)));

        var findings = await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task SuspiciousArtefact_MagicContradictsExtension_FiresHigh()
    {
        var ctx = Context(SkillWith(A("docs/README.md", ".md", FileArtefactKind.PortableExecutable)));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].RuleId.ShouldBe("SS-035");
        findings[0].Severity.ShouldBe(Severity.High);
        findings[0].Title.ShouldContain("Contradicts Extension");
    }

    [Theory]
    [InlineData("tool.exe", ".exe", FileArtefactKind.PortableExecutable)]
    [InlineData("bin/helper", "", FileArtefactKind.Elf)]
    [InlineData("lib/native.dylib", ".dylib", FileArtefactKind.MachO)]
    [InlineData("payload.bin", ".bin", FileArtefactKind.Elf)]
    public async Task SuspiciousArtefact_ExecutableBinary_FiresHigh(string path, string ext, FileArtefactKind kind)
    {
        var ctx = Context(SkillWith(A(path, ext, kind)));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.High);
        findings[0].Title.ShouldContain("Executable Binary");
    }

    [Theory]
    [InlineData("README.md.exe")]
    [InlineData("invoice.pdf.bat")]
    [InlineData("notes.txt.js")]
    public async Task SuspiciousArtefact_DoubleExtension_FiresHigh(string name)
    {
        var ctx = Context(SkillWith(A(name, Path.GetExtension(name), FileArtefactKind.Unknown)));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.High);
        findings[0].Title.ShouldContain("Double Extension");
    }

    [Fact]
    public async Task SuspiciousArtefact_LegitimateDottedName_NotDoubleExtension()
    {
        var ctx = Context(SkillWith(A("jquery.min.js", ".js", FileArtefactKind.Unknown)));

        var findings = await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("vendor.zip", ".zip", FileArtefactKind.Zip)]
    [InlineData("data.tar.gz", ".gz", FileArtefactKind.Gzip)]
    [InlineData("pkg.whl", ".whl", FileArtefactKind.Zip)]
    public async Task SuspiciousArtefact_Archive_FiresMedium(string path, string ext, FileArtefactKind kind)
    {
        var ctx = Context(SkillWith(A(path, ext, kind)));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Medium);
        findings[0].Title.ShouldContain("Archive");
    }

    [Fact]
    public async Task SuspiciousArtefact_OrphanPyc_FiresMedium()
    {
        var ctx = Context(SkillWith(A("lib/secret.pyc", ".pyc", FileArtefactKind.PythonBytecode)));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Medium);
        findings[0].Title.ShouldContain("Without Source");
    }

    [Fact]
    public async Task SuspiciousArtefact_PycWithSiblingSource_NoFinding()
    {
        var ctx = Context(SkillWith(
            A("lib/mod.py", ".py", FileArtefactKind.Unknown),
            A("lib/mod.pyc", ".pyc", FileArtefactKind.PythonBytecode)));

        var findings = await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task SuspiciousArtefact_JavaClass_FiresMedium()
    {
        var ctx = Context(SkillWith(A("Helper.class", ".class", FileArtefactKind.JavaClass)));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Medium);
    }

    [Fact]
    public async Task SuspiciousArtefact_HiddenUnlisted_FiresLow()
    {
        var ctx = Context(SkillWith(A(".stage2", ".stage2", FileArtefactKind.Unknown, hidden: true)));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Low);
        findings[0].Title.ShouldContain("Hidden");
    }

    [Fact]
    public async Task SuspiciousArtefact_OpaqueBinWithUnknownMagic_FiresMedium()
    {
        var ctx = Context(SkillWith(A("model.bin", ".bin", FileArtefactKind.Unknown)));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Medium);
        findings[0].Title.ShouldContain("Opaque");
    }

    [Fact]
    public async Task SuspiciousArtefact_ExecutableBitNoTypeNoExtension_FiresMedium()
    {
        var artefact = A("bin/run", "", FileArtefactKind.Unknown) with { IsExecutable = true };
        var ctx = Context(SkillWith(artefact));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Medium);
        findings[0].Title.ShouldContain("Executable Permission");
    }

    [Fact]
    public async Task SuspiciousArtefact_ShebangScriptWithExecutableBit_NoFinding()
    {
        var artefact = A("bin/run", "", FileArtefactKind.Shebang) with { IsExecutable = true };
        var ctx = Context(SkillWith(artefact));

        var findings = await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task SuspiciousArtefact_FileUnderHiddenDirectory_FiresLow()
    {
        var ctx = Context(SkillWith(A(".cache/run.sh", ".sh", FileArtefactKind.Unknown)));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Low);
        findings[0].Title.ShouldContain("Hidden");
    }

    [Fact]
    public async Task SuspiciousArtefact_HiddenBinary_ReportsHighNotLow()
    {
        var ctx = Context(SkillWith(A(".cache", ".cache", FileArtefactKind.Elf, hidden: true)));

        var findings = (await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.High);
    }

    [Fact]
    public async Task SuspiciousArtefact_NoArtefacts_NoFindings()
    {
        var ctx = Context(SkillWith());

        var findings = await new SkillSuspiciousArtefactRule().EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    // ---------------------------------------------------------------- helpers

    private static string Hex(string content) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"skill-forensics-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static SkillDefinition Skill(string dir) => new()
    {
        Name = "t",
        InstructionsBody = string.Empty,
        RawContent = "# s",
        FilePath = Path.Combine(dir, "SKILL.md")
    };

    private static SkillDefinition SkillWith(params FileArtefact[] artefacts) => new()
    {
        Name = "t",
        InstructionsBody = string.Empty,
        RawContent = "# s",
        FilePath = Path.Combine(Path.GetTempPath(), "virtual", "SKILL.md"),
        Artefacts = artefacts
    };

    private static FileArtefact A(string path, string ext, FileArtefactKind kind, bool hidden = false)
    {
        ArgumentNullException.ThrowIfNull(path);
        return new FileArtefact
        {
            RelativePath = path.Replace('/', Path.DirectorySeparatorChar),
            Extension = ext,
            Kind = kind,
            Size = 10,
            IsHidden = hidden
        };
    }

    private static ScanContext Context(SkillDefinition skill) => new() { Servers = [], Skills = [skill] };
}
