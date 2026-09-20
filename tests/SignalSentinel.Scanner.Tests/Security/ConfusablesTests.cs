// -----------------------------------------------------------------------
// <copyright file="ConfusablesTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Security;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Security;

/// <summary>
/// v3.0.0 WP4: Unicode confusable skeleton and script analysis.
/// </summary>
public class ConfusablesTests
{
    [Theory]
    [InlineData("read_file", "read_file")]
    [InlineData("ReadFile", "readfile")]
    [InlineData("get-weather-v2", "get-weather-v2")]
    [InlineData("server.tools.list", "server.tools.list")]
    public void Analyse_PlainAscii_NotSuspicious(string identifier, string expectedSkeleton)
    {
        var a = Confusables.Analyse(identifier);

        a.IsAscii.ShouldBeTrue();
        a.IsSuspicious.ShouldBeFalse();
        a.HasLookalikes.ShouldBeFalse();
        a.Invisibles.ShouldBeEmpty();
        a.Skeleton.ShouldBe(expectedSkeleton);
    }

    [Fact]
    public void Analyse_CyrillicE_SharesSkeletonWithAscii()
    {
        var ascii = Confusables.Analyse("read_file");
        var homoglyph = Confusables.Analyse("r\u0435ad_file"); // Cyrillic е

        homoglyph.Skeleton.ShouldBe(ascii.Skeleton);
        homoglyph.IsAscii.ShouldBeFalse();
        homoglyph.HasLookalikes.ShouldBeTrue();
        homoglyph.IsMixedScript.ShouldBeTrue();
        homoglyph.Scripts.ShouldBe(["Cyrillic", "Latin"]);
        homoglyph.IsSuspicious.ShouldBeTrue();
    }

    [Fact]
    public void Analyse_WholeScriptCyrillic_IsWholeScriptConfusable()
    {
        // "аррӏе" - every letter Cyrillic, every letter a Latin lookalike.
        var a = Confusables.Analyse("\u0430\u0440\u0440\u04CF\u0435");

        a.Skeleton.ShouldBe("apple");
        a.IsMixedScript.ShouldBeFalse();
        a.IsWholeScriptConfusable.ShouldBeTrue();
        a.IsSuspicious.ShouldBeTrue();
    }

    [Fact]
    public void Analyse_ZeroWidthSpace_RecordedAsInvisibleAndStripped()
    {
        var a = Confusables.Analyse("read\u200Bfile");

        a.Invisibles.ShouldBe(["U+200B"]);
        a.Skeleton.ShouldBe("readfile");
        a.IsSuspicious.ShouldBeTrue();
    }

    [Fact]
    public void Analyse_BidiOverride_RecordedAsInvisible()
    {
        var a = Confusables.Analyse("safe\u202Eelif");

        a.Invisibles.ShouldContain("U+202E");
        a.IsSuspicious.ShouldBeTrue();
    }

    [Fact]
    public void Analyse_FullwidthLatin_FoldsToAsciiAndFlagsLookalikes()
    {
        var a = Confusables.Analyse("\uFF52\uFF45\uFF41\uFF44"); // ｒｅａｄ

        a.Skeleton.ShouldBe("read");
        a.IsAscii.ShouldBeFalse();
        a.HasLookalikes.ShouldBeTrue();
        a.IsWholeScriptConfusable.ShouldBeTrue();
    }

    [Fact]
    public void Analyse_MathematicalBold_FoldsToAscii()
    {
        // 𝐫𝐞𝐚𝐝 (U+1D42B U+1D41E U+1D41A U+1D41D)
        var a = Confusables.Analyse("\U0001D42B\U0001D41E\U0001D41A\U0001D41D");

        a.Skeleton.ShouldBe("read");
        a.IsWholeScriptConfusable.ShouldBeTrue();
    }

    [Fact]
    public void Analyse_GreekOmicron_FoldsToO()
    {
        var a = Confusables.Analyse("t\u03BFol"); // Greek ο

        a.Skeleton.ShouldBe("tool");
        a.IsMixedScript.ShouldBeTrue();
        a.Scripts.ShouldContain("Greek");
    }

    [Fact]
    public void Analyse_LatinWithHan_IsAllowedCombination()
    {
        var a = Confusables.Analyse("translate_\u7FFB\u8A33"); // 翻訳

        a.IsAscii.ShouldBeFalse();
        a.Scripts.ShouldBe(["Han", "Latin"]);
        a.IsMixedScript.ShouldBeFalse();
        a.IsWholeScriptConfusable.ShouldBeFalse();
        a.IsSuspicious.ShouldBeFalse();
    }

    [Fact]
    public void Analyse_PureJapanese_NotSuspicious()
    {
        var a = Confusables.Analyse("\u3066\u3059\u3068\u30C4\u30FC\u30EB"); // てすとツール

        a.IsMixedScript.ShouldBeFalse();
        a.IsSuspicious.ShouldBeFalse();
    }

    [Fact]
    public void Analyse_AccentedLatin_NotSuspicious()
    {
        var a = Confusables.Analyse("r\u00E9sum\u00E9_parser");

        a.Scripts.ShouldBe(["Latin"]);
        a.IsMixedScript.ShouldBeFalse();
        a.IsWholeScriptConfusable.ShouldBeFalse();
        a.IsSuspicious.ShouldBeFalse();
    }

    [Fact]
    public void Analyse_CaseDiffersOnly_SameSkeleton()
    {
        Confusables.Skeleton("ReadFile").ShouldBe(Confusables.Skeleton("readfile"));
    }

    [Fact]
    public void Analyse_DashVariants_FoldToHyphen()
    {
        Confusables.Skeleton("get\u2013weather").ShouldBe("get-weather");
    }

    [Fact]
    public void Analyse_Empty_ReturnsEmptySkeleton()
    {
        var a = Confusables.Analyse(string.Empty);

        a.Skeleton.ShouldBe(string.Empty);
        a.IsAscii.ShouldBeTrue();
        a.IsSuspicious.ShouldBeFalse();
    }

    [Fact]
    public void Analyse_Null_Throws()
    {
        Should.Throw<ArgumentNullException>(() => Confusables.Analyse(null!));
    }

    [Fact]
    public void Analyse_DigitsAndPunctuation_NotCountedAsScript()
    {
        var a = Confusables.Analyse("v2_0-beta.3");

        a.Scripts.ShouldBe(["Latin"]);
    }
}
