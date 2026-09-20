// -----------------------------------------------------------------------
// <copyright file="FileForensicsTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillParser;

public class FileForensicsTests
{
    [Theory]
    [InlineData(new byte[] { 0x4D, 0x5A, 0x90, 0x00 }, FileArtefactKind.Unknown)]
    [InlineData(new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x02 }, FileArtefactKind.Elf)]
    [InlineData(new byte[] { 0xFE, 0xED, 0xFA, 0xCF }, FileArtefactKind.MachO)]
    [InlineData(new byte[] { 0xCF, 0xFA, 0xED, 0xFE }, FileArtefactKind.MachO)]
    [InlineData(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02 }, FileArtefactKind.MachO)]
    [InlineData(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x41 }, FileArtefactKind.JavaClass)]
    [InlineData(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34 }, FileArtefactKind.JavaClass)]
    [InlineData(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x2D }, FileArtefactKind.JavaClass)]
    [InlineData(new byte[] { 0xCB, 0x0D, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0x00 }, FileArtefactKind.PythonBytecode)]
    [InlineData(new byte[] { 0x58, 0x0D, 0x0D, 0x0A, 0x54, 0x68, 0x69, 0x73 }, FileArtefactKind.Unknown)]
    [InlineData(new byte[] { 0x58, 0x0D, 0x0D, 0x0A }, FileArtefactKind.Unknown)]
    [InlineData(new byte[] { 0x50, 0x4B, 0x03, 0x04 }, FileArtefactKind.Zip)]
    [InlineData(new byte[] { 0x1F, 0x8B, 0x08 }, FileArtefactKind.Gzip)]
    [InlineData(new byte[] { 0x42, 0x5A, 0x68, 0x39 }, FileArtefactKind.Bzip2)]
    [InlineData(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }, FileArtefactKind.Xz)]
    [InlineData(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }, FileArtefactKind.SevenZip)]
    [InlineData(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 }, FileArtefactKind.Rar)]
    [InlineData(new byte[] { 0xCB, 0x0D, 0x0D, 0x0A, 0x00 }, FileArtefactKind.Unknown)]
    [InlineData(new byte[] { 0x23, 0x21, 0x2F, 0x62, 0x69, 0x6E }, FileArtefactKind.Shebang)]
    [InlineData(new byte[] { 0x23, 0x20, 0x48, 0x65 }, FileArtefactKind.Unknown)]
    [InlineData(new byte[] { 0x7B }, FileArtefactKind.Unknown)]
    [InlineData(new byte[0], FileArtefactKind.Unknown)]
    public void Classify_KnownMagic_ReturnsKind(byte[] header, FileArtefactKind expected)
    {
        FileForensics.Classify(header).ShouldBe(expected);
    }

    [Fact]
    public void Classify_MzWithPlausibleLfanew_IsPortableExecutable()
    {
        var header = new byte[64];
        header[0] = (byte)'M';
        header[1] = (byte)'Z';
        header[0x3C] = 0x80; // e_lfanew = 0x80

        FileForensics.Classify(header).ShouldBe(FileArtefactKind.PortableExecutable);
    }

    [Fact]
    public void Classify_TextStartingWithMz_IsUnknown()
    {
        var header = System.Text.Encoding.ASCII.GetBytes("MZ is a prefix that appears in ordinary prose sometimes, honestly.");
        header.Length.ShouldBeGreaterThanOrEqualTo(64);

        FileForensics.Classify(header.AsSpan(0, 64)).ShouldBe(FileArtefactKind.Unknown);
    }

    [Fact]
    public async Task AnalyseAsync_WalksRecursively_SkipsExcludedDirs_ClassifiesEachFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"forensics-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(dir, "scripts"));
        Directory.CreateDirectory(Path.Combine(dir, "node_modules", "x"));
        try
        {
            File.WriteAllText(Path.Combine(dir, "SKILL.md"), "# hi");
            var pe = new byte[128];
            pe[0] = (byte)'M';
            pe[1] = (byte)'Z';
            pe[0x3C] = 0x80;
            File.WriteAllBytes(Path.Combine(dir, "scripts", "helper.md"), pe);
            File.WriteAllText(Path.Combine(dir, ".hidden"), "x");
            File.WriteAllText(Path.Combine(dir, "node_modules", "x", "index.js"), "module.exports = 1;");

            var artefacts = await FileForensics.AnalyseAsync(dir);

            artefacts.Count.ShouldBe(3);
            artefacts.ShouldContain(a => a.RelativePath == "SKILL.md" && a.Kind == FileArtefactKind.Unknown && a.Extension == ".md");
            artefacts.ShouldContain(a => a.RelativePath.EndsWith("helper.md", StringComparison.Ordinal) && a.Kind == FileArtefactKind.PortableExecutable);
            artefacts.ShouldContain(a => a.RelativePath == ".hidden" && a.IsHidden);
            artefacts.ShouldNotContain(a => a.RelativePath.Contains("node_modules", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task AnalyseAsync_MissingDirectory_ReturnsEmpty()
    {
        var result = await FileForensics.AnalyseAsync(Path.Combine(Path.GetTempPath(), $"nope-{Guid.NewGuid():N}"));
        result.ShouldBeEmpty();
    }

    [Fact]
    public async Task AnalyseAsync_RespectsFileCap()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"forensics-cap-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            for (var i = 0; i < FileForensics.MaxFiles + 20; i++)
            {
                File.WriteAllText(Path.Combine(dir, $"f{i}.txt"), "x");
            }

            var artefacts = await FileForensics.AnalyseAsync(dir);

            artefacts.Count.ShouldBe(FileForensics.MaxFiles);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
