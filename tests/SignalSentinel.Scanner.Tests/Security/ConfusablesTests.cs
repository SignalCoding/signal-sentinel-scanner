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

    [Theory]
    [InlineData("s\u0131ralama")]   // Turkish dotless i
    [InlineData("acme\u2122")]      // ™
    [InlineData("web\u00B2")]       // ²
    [InlineData("loading\u2026")]   // …
    [InlineData("\u00B5service")]   // µ
    public void Analyse_LatinOnlyFoldables_NotWholeScriptConfusable(string identifier)
    {
        var a = Confusables.Analyse(identifier);

        a.IsAscii.ShouldBeFalse();
        a.Scripts.ShouldBe(["Latin"]);
        a.IsWholeScriptConfusable.ShouldBeFalse();
        a.IsSuspicious.ShouldBeFalse();
    }

    [Fact]
    public void Analyse_LetterlikeSingleLetterClone_IsStylistic()
    {
        var a = Confusables.Analyse("fi\u2113e"); // ℓ

        a.Skeleton.ShouldBe("file");
        a.HasStylisticLookalikes.ShouldBeTrue();
        a.IsWholeScriptConfusable.ShouldBeTrue();
        a.IsSingleForeignScriptWord.ShouldBeFalse();
    }

    [Fact]
    public void Analyse_SingleScriptCyrillicWordOfLookalikes_FlaggedAsForeignWord()
    {
        var a = Confusables.Analyse("\u0440\u0435\u0441\u0443\u0440\u0441"); // ресурс

        a.Skeleton.ShouldBe("pecypc");
        a.IsWholeScriptConfusable.ShouldBeTrue();
        a.IsSingleForeignScriptWord.ShouldBeTrue();
    }

    [Fact]
    public void Analyse_CyrillicWordWithNonLookalikes_NotSuspicious()
    {
        var a = Confusables.Analyse("\u043F\u043E\u0438\u0441\u043A"); // поиск

        a.IsWholeScriptConfusable.ShouldBeFalse();
        a.IsSuspicious.ShouldBeFalse();
    }

    [Theory]
    [InlineData("read_file\uFE0F", "U+FE0F")]
    [InlineData("read_file\U000E0100", "U+E0100")]
    [InlineData("read_file\u180B", "U+180B")]
    [InlineData("read_file\u0085", "U+0085")]
    [InlineData("read_file\u2028", "U+2028")]
    public void Analyse_HiddenTrailingCharacters_RecordedAsInvisible(string identifier, string expected)
    {
        var a = Confusables.Analyse(identifier);

        a.Invisibles.ShouldBe([expected]);
        a.Skeleton.ShouldBe("read_file");
    }

    [Fact]
    public void Analyse_VariationSelectorAfterEmoji_NotInvisible()
    {
        var a = Confusables.Analyse("\u2714\uFE0Fdeploy");

        a.Invisibles.ShouldBeEmpty();
        a.IsSuspicious.ShouldBeFalse();
    }

    [Fact]
    public void Analyse_ZwjInEmojiSequence_NotInvisible()
    {
        var a = Confusables.Analyse("\U0001F468\u200D\U0001F4BBdev");

        a.Invisibles.ShouldBeEmpty();
    }

    [Fact]
    public void Analyse_ZwnjBetweenArabicLetters_NotInvisible()
    {
        var a = Confusables.Analyse("\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645");

        a.Invisibles.ShouldBeEmpty();
        a.Scripts.ShouldBe(["Arabic"]);
    }

    [Fact]
    public void Analyse_ZwjBetweenLatinLetters_Invisible()
    {
        var a = Confusables.Analyse("read\u200Dfile");

        a.Invisibles.ShouldBe(["U+200D"]);
    }

    [Theory]
    [InlineData("\u0628\u062D\u062B_search", "Arabic")]   // بحث
    [InlineData("\u05D7\u05D9\u05E4\u05D5\u05E9_search", "Hebrew")] // חיפוש
    [InlineData("\u0E04\u0E49\u0E19\u0E2B\u0E32_search", "Thai")] // ค้นหา
    public void Analyse_LatinPlusNonLookalikeScript_Allowed(string identifier, string other)
    {
        var a = Confusables.Analyse(identifier);

        a.Scripts.ShouldContain(other);
        a.Scripts.ShouldContain("Latin");
        a.IsMixedScript.ShouldBeFalse();
    }

    [Theory]
    [InlineData("read_fil\U00010304")] // Old Italic 𐌄
    [InlineData("\uA4E3ead_file")]     // Lisu ꓣ
    [InlineData("\u16B1ead")]          // Runic ᚱ
    [InlineData("\U00010400pple")]     // Deseret 𐐀
    [InlineData("\u13A0pple")]         // Cherokee Ꭺ
    [InlineData("\u0578ame")]          // Armenian ո
    public void Analyse_LatinPlusExcludedOrLookalikeScript_IsMixedScript(string identifier)
    {
        var a = Confusables.Analyse(identifier);

        a.IsMixedScript.ShouldBeTrue();
        a.IsSuspicious.ShouldBeTrue();
    }

    [Fact]
    public void Analyse_PureGreekWithLunateSigma_NotMixedScript()
    {
        var a = Confusables.Analyse("\u03F2\u03BF\u03C6\u03B9\u03B1"); // ϲοφια

        a.Scripts.ShouldBe(["Greek"]);
        a.IsMixedScript.ShouldBeFalse();
        a.Skeleton.ShouldBe("co\u03C6ia");
    }

    [Fact]
    public void Analyse_LunateSigmaInLatinName_MixedScriptAndFolds()
    {
        var a = Confusables.Analyse("\u03F9onfig"); // Ϲonfig

        a.Skeleton.ShouldBe("config");
        a.Scripts.ShouldBe(["Greek", "Latin"]);
        a.IsMixedScript.ShouldBeTrue();
    }

    [Theory]
    [InlineData("read_file\uE005", "U+E005")]
    [InlineData("read_file\U000F0000", "U+F0000")]
    public void Analyse_PrivateUseCharacter_Invisible(string identifier, string expected)
    {
        var a = Confusables.Analyse(identifier);

        a.Invisibles.ShouldBe([expected]);
        a.Skeleton.ShouldBe("read_file");
    }

    [Theory]
    [InlineData("read_file\u2800", "U+2800")]
    [InlineData("read_file\u2800\uFE0F", "U+2800")]
    public void Analyse_BrailleBlank_InvisibleAndDoesNotLegitimiseSelector(string identifier, string first)
    {
        var a = Confusables.Analyse(identifier);

        a.Invisibles.ShouldNotBeEmpty();
        a.Invisibles[0].ShouldBe(first);
        a.Skeleton.ShouldBe("read_file");
    }

    [Theory]
    [InlineData("hawai\u02BBi")]      // okina
    [InlineData("\u043E\u0431\u02BC\u0454\u043A\u0442")] // обʼєкт
    [InlineData("\u4EBA\u3005")]      // 人々
    public void Analyse_ModifierLettersAndIterationMarks_NotMixedScript(string identifier)
    {
        var a = Confusables.Analyse(identifier);

        a.IsMixedScript.ShouldBeFalse();
    }

    [Theory]
    [InlineData("fi\u04C0e", "file")]   // capital palochka
    [InlineData("\u0475ault", "vault")] // ѵ
    [InlineData("deplo\u04AF", "deploy")] // ү
    [InlineData("\u03F9onfig", "config")] // Ϲ
    [InlineData("cop\u03B3", "copy")]   // γ
    [InlineData("fi\u01C0e", "file")]   // ǀ dental click
    [InlineData("\u0237son", "json")]   // ȷ
    public void Analyse_AdditionalLookalikes_FoldToTarget(string identifier, string skeleton)
    {
        Confusables.Skeleton(identifier).ShouldBe(skeleton);
    }

    [Fact]
    public void CaseFoldKey_FoldsCaseAndCanonicalFormButNotCompatibility()
    {
        Confusables.CaseFoldKey("\u0420\u0435\u0441\u0443\u0440\u0441").ShouldBe(Confusables.CaseFoldKey("\u0440\u0435\u0441\u0443\u0440\u0441"));
        Confusables.CaseFoldKey("caf\u00E9").ShouldBe(Confusables.CaseFoldKey("cafe\u0301"));
        Confusables.CaseFoldKey("\uFF52\uFF45\uFF41\uFF44").ShouldNotBe(Confusables.CaseFoldKey("read"));
    }

    [Theory]
    [InlineData("abc\uD800")]
    [InlineData("\uDFFFabc")]
    [InlineData("a\uD800\uDFFF\uD800b")]
    public void Analyse_LoneSurrogates_DoesNotThrow(string identifier)
    {
        Should.NotThrow(() => Confusables.Analyse(identifier));
        Should.NotThrow(() => Confusables.CaseFoldKey(identifier));
    }
}
