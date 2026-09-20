// -----------------------------------------------------------------------
// <copyright file="Confusables.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Globalization;
using System.Text;

namespace SignalSentinel.Core.Security;

/// <summary>
/// Result of analysing one identifier with <see cref="Confusables.Analyse"/>.
/// </summary>
public sealed record ConfusableAnalysis
{
    /// <summary>Original identifier.</summary>
    public required string Original { get; init; }

    /// <summary>
    /// Lower-cased, NFKC-normalised, lookalike-folded, invisible-stripped form.
    /// Two identifiers with the same skeleton look alike to a human.
    /// </summary>
    public required string Skeleton { get; init; }

    /// <summary>True when every character is printable ASCII.</summary>
    public required bool IsAscii { get; init; }

    /// <summary>Invisible/format code points present, as U+XXXX strings.</summary>
    public required IReadOnlyList<string> Invisibles { get; init; }

    /// <summary>Distinct scripts of the letters present (excluding Common).</summary>
    public required IReadOnlyList<string> Scripts { get; init; }

    /// <summary>True when the scripts present are not an allowed combination.</summary>
    public required bool IsMixedScript { get; init; }

    /// <summary>
    /// True when at least one non-ASCII character folded to an ASCII letter or digit,
    /// i.e. the identifier contains Latin lookalikes.
    /// </summary>
    public required bool HasLookalikes { get; init; }

    /// <summary>
    /// True when the identifier is not ASCII but its skeleton is entirely ASCII: every
    /// non-ASCII character was a Latin lookalike. This is the classic whole-script
    /// homoglyph, e.g. Cyrillic "аррӏе" for "apple".
    /// </summary>
    public bool IsWholeScriptConfusable => !IsAscii && HasLookalikes && Skeleton.All(c => c < 0x80);

    /// <summary>True when anything about the identifier warrants a look.</summary>
    public bool IsSuspicious => Invisibles.Count > 0 || IsMixedScript || IsWholeScriptConfusable;
}

/// <summary>
/// Unicode confusable analysis for identifiers (tool, prompt, resource, server and
/// skill names), in the spirit of UTS #39. Curated rather than the full confusables
/// table: it covers the lookalikes that actually show up in homoglyph attacks on
/// Latin-script identifiers, plus the invisible and bidi-control characters used to
/// hide or reorder text.
/// </summary>
public static class Confusables
{
    /// <summary>
    /// Single-codepoint lookalikes that map onto a Latin letter or digit.
    /// </summary>
    private static readonly Dictionary<int, char> LookalikeMap = BuildLookalikeMap();

    /// <summary>
    /// Zero-width, joiner, bidi-control and other format characters that render as
    /// nothing and are never legitimate inside an identifier.
    /// </summary>
    private static readonly HashSet<int> InvisibleCodePoints =
    [
        0x00AD, // soft hyphen
        0x034F, // combining grapheme joiner
        0x061C, // Arabic letter mark
        0x115F, 0x1160, // Hangul fillers
        0x17B4, 0x17B5, // Khmer inherent vowels
        0x180E, // Mongolian vowel separator
        0x200B, 0x200C, 0x200D, 0x200E, 0x200F, // ZWSP, ZWNJ, ZWJ, LRM, RLM
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // LRE, RLE, PDF, LRO, RLO
        0x2060, 0x2061, 0x2062, 0x2063, 0x2064, // WJ, function application, invisible times/separator/plus
        0x2066, 0x2067, 0x2068, 0x2069, // LRI, RLI, FSI, PDI
        0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F, // deprecated format chars
        0x3164, // Hangul filler
        0xFEFF, // BOM / ZWNBSP
        0xFFA0, // halfwidth Hangul filler
        0x1D173, 0x1D174, 0x1D175, 0x1D176, 0x1D177, 0x1D178, 0x1D179, 0x1D17A, // musical format chars
        0xE0001 // language tag
    ];

    /// <summary>
    /// Script combinations UTS #39 "Highly Restrictive" treats as legitimate in one
    /// identifier. Anything else with two or more scripts is mixed-script.
    /// </summary>
    private static readonly string[][] AllowedScriptCombinations =
    [
        ["Latin", "Han", "Hiragana", "Katakana"],
        ["Latin", "Han", "Hangul"],
        ["Latin", "Han", "Bopomofo"]
    ];

    /// <summary>
    /// Analyses an identifier.
    /// </summary>
    public static ConfusableAnalysis Analyse(string identifier)
    {
        ArgumentNullException.ThrowIfNull(identifier);

        var invisibles = new List<string>();
        var scripts = new HashSet<string>(StringComparer.Ordinal);
        var skeleton = new StringBuilder(identifier.Length);

        // ASCII-ness is judged on the original string. NFKC folds fullwidth letters,
        // mathematical alphanumerics and ligatures to plain ASCII, which is exactly the
        // lookalike behaviour this analysis must not hide.
        var nonAsciiOriginal = CountNonAscii(identifier);
        var isAscii = nonAsciiOriginal == 0;

        string normalised;
        try
        {
            normalised = identifier.Normalize(NormalizationForm.FormKC);
        }
        catch (ArgumentException)
        {
            // Invalid surrogate pairs; analyse the raw string instead.
            normalised = identifier;
        }

        var hasLookalikes = CountNonAscii(normalised) < nonAsciiOriginal;

        foreach (var rune in normalised.EnumerateRunes())
        {
            var cp = rune.Value;

            if (InvisibleCodePoints.Contains(cp) || Rune.GetUnicodeCategory(rune) == UnicodeCategory.Format)
            {
                invisibles.Add($"U+{cp:X4}");
                continue;
            }

            if (LookalikeMap.TryGetValue(cp, out var folded))
            {
                if (cp > 0x7F)
                {
                    hasLookalikes = true;
                }

                skeleton.Append(char.ToLowerInvariant(folded));
                var script = ScriptOf(cp);
                if (script is not null)
                {
                    scripts.Add(script);
                }

                continue;
            }

            var s = ScriptOf(cp);
            if (s is not null)
            {
                scripts.Add(s);
            }

            skeleton.Append(Rune.ToLowerInvariant(rune).ToString());
        }

        var scriptList = scripts.OrderBy(x => x, StringComparer.Ordinal).ToList();

        return new ConfusableAnalysis
        {
            Original = identifier,
            Skeleton = skeleton.ToString(),
            IsAscii = isAscii,
            Invisibles = invisibles,
            Scripts = scriptList,
            IsMixedScript = scriptList.Count > 1 && !IsAllowedCombination(scriptList),
            HasLookalikes = hasLookalikes
        };
    }

    /// <summary>
    /// Convenience: the skeleton alone.
    /// </summary>
    public static string Skeleton(string identifier) => Analyse(identifier).Skeleton;

    private static int CountNonAscii(string value)
    {
        var count = 0;
        foreach (var rune in value.EnumerateRunes())
        {
            if (rune.Value is > 0x7E or < 0x20)
            {
                count++;
            }
        }

        return count;
    }

    private static bool IsAllowedCombination(IReadOnlyList<string> scripts)
    {
        foreach (var combo in AllowedScriptCombinations)
        {
            if (scripts.All(s => Array.IndexOf(combo, s) >= 0))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Coarse script classification for letters; null for digits, punctuation,
    /// whitespace and anything else "Common".
    /// </summary>
    internal static string? ScriptOf(int cp)
    {
        if (cp is >= 0x41 and <= 0x5A or >= 0x61 and <= 0x7A)
        {
            return "Latin";
        }

        if (cp < 0x80)
        {
            return null;
        }

        return cp switch
        {
            >= 0x00C0 and <= 0x024F => cp is 0x00D7 or 0x00F7 ? null : "Latin",
            >= 0x1E00 and <= 0x1EFF => "Latin",
            >= 0x2C60 and <= 0x2C7F => "Latin",
            >= 0xA720 and <= 0xA7FF => "Latin",
            >= 0xFF21 and <= 0xFF3A => "Latin",
            >= 0xFF41 and <= 0xFF5A => "Latin",
            >= 0x1D400 and <= 0x1D7CB => "Latin", // mathematical alphanumerics (letters)
            >= 0x0370 and <= 0x03FF => "Greek",
            >= 0x1F00 and <= 0x1FFF => "Greek",
            >= 0x0400 and <= 0x052F => "Cyrillic",
            >= 0x2DE0 and <= 0x2DFF => "Cyrillic",
            >= 0xA640 and <= 0xA69F => "Cyrillic",
            >= 0x0530 and <= 0x058F => "Armenian",
            >= 0x0590 and <= 0x05FF => "Hebrew",
            >= 0x0600 and <= 0x06FF => "Arabic",
            >= 0x0750 and <= 0x077F => "Arabic",
            >= 0x0900 and <= 0x097F => "Devanagari",
            >= 0x0E00 and <= 0x0E7F => "Thai",
            >= 0x10A0 and <= 0x10FF => "Georgian",
            >= 0x1100 and <= 0x11FF => "Hangul",
            >= 0xAC00 and <= 0xD7AF => "Hangul",
            >= 0x3130 and <= 0x318F => "Hangul",
            >= 0x13A0 and <= 0x13FF => "Cherokee",
            >= 0x3040 and <= 0x309F => "Hiragana",
            >= 0x30A0 and <= 0x30FF => "Katakana",
            >= 0x31F0 and <= 0x31FF => "Katakana",
            >= 0xFF66 and <= 0xFF9F => "Katakana",
            >= 0x3100 and <= 0x312F => "Bopomofo",
            >= 0x31A0 and <= 0x31BF => "Bopomofo",
            >= 0x3400 and <= 0x4DBF => "Han",
            >= 0x4E00 and <= 0x9FFF => "Han",
            >= 0xF900 and <= 0xFAFF => "Han",
            >= 0x20000 and <= 0x2FA1F => "Han",
            >= 0x2C00 and <= 0x2C5F => "Glagolitic",
            >= 0x10300 and <= 0x1032F => "Old Italic",
            >= 0x1680 and <= 0x169F => "Ogham",
            >= 0x16A0 and <= 0x16FF => "Runic",
            _ => IsLetterCodePoint(cp) ? "Other" : null
        };
    }

    private static bool IsLetterCodePoint(int cp)
    {
        if (!Rune.IsValid(cp))
        {
            return false;
        }

        var cat = Rune.GetUnicodeCategory(new Rune(cp));
        return cat is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter
            or UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter;
    }

    private static Dictionary<int, char> BuildLookalikeMap()
    {
        var map = new Dictionary<int, char>();

        void Add(string lookalikes, char target)
        {
            foreach (var rune in lookalikes.EnumerateRunes())
            {
                map[rune.Value] = target;
            }
        }

        // ASCII identity for letters and digits so the map can be consulted uniformly.
        for (var c = 'a'; c <= 'z'; c++)
        {
            map[c] = c;
            map[char.ToUpperInvariant(c)] = c;
        }

        for (var c = '0'; c <= '9'; c++)
        {
            map[c] = c;
        }

        // Cyrillic lower-case lookalikes.
        Add("а", 'a'); Add("е", 'e'); Add("о", 'o'); Add("р", 'p'); Add("с", 'c'); Add("у", 'y');
        Add("х", 'x'); Add("і", 'i'); Add("ј", 'j'); Add("ѕ", 's'); Add("һ", 'h'); Add("ԛ", 'q');
        Add("ԝ", 'w'); Add("ԁ", 'd'); Add("ӏ", 'l'); Add("ⅼ", 'l'); Add("ո", 'n'); Add("ց", 'g');
        Add("ҫ", 'c'); Add("ӓ", 'a'); Add("ё", 'e'); Add("ї", 'i'); Add("ў", 'y'); Add("ӱ", 'y');

        // Cyrillic upper-case lookalikes.
        Add("А", 'a'); Add("В", 'b'); Add("Е", 'e'); Add("К", 'k'); Add("М", 'm'); Add("Н", 'h');
        Add("О", 'o'); Add("Р", 'p'); Add("С", 'c'); Add("Т", 't'); Add("Х", 'x'); Add("Ѵ", 'v');
        Add("Ӏ", 'l'); Add("Ј", 'j'); Add("Ѕ", 's'); Add("І", 'i'); Add("Ԍ", 'g'); Add("Ԛ", 'q');
        Add("Ԝ", 'w'); Add("Ү", 'y'); Add("Ғ", 'f');

        // Greek.
        Add("α", 'a'); Add("ο", 'o'); Add("ν", 'v'); Add("ρ", 'p'); Add("ι", 'i'); Add("κ", 'k');
        Add("τ", 't'); Add("υ", 'u'); Add("ϲ", 'c'); Add("ϳ", 'j'); Add("ϱ", 'p'); Add("ⲟ", 'o');
        Add("Α", 'a'); Add("Β", 'b'); Add("Ε", 'e'); Add("Ζ", 'z'); Add("Η", 'h'); Add("Ι", 'i');
        Add("Κ", 'k'); Add("Μ", 'm'); Add("Ν", 'n'); Add("Ο", 'o'); Add("Ρ", 'p'); Add("Τ", 't');
        Add("Υ", 'y'); Add("Χ", 'x');

        // Armenian, Cherokee and other well-known singletons.
        Add("ա", 'w'); Add("գ", 'q'); Add("հ", 'h'); Add("օ", 'o'); Add("ս", 'u'); Add("ք", 'p');
        Add("Ꭺ", 'a'); Add("Ꭰ", 'd'); Add("Ꭼ", 'e'); Add("Ꮋ", 'h'); Add("Ꭻ", 'j'); Add("Ꮶ", 'k');
        Add("Ꮮ", 'l'); Add("Ꮇ", 'm'); Add("Ꮲ", 'p'); Add("Ꮪ", 's'); Add("Ꭲ", 't'); Add("Ꮩ", 'v');
        Add("Ꮃ", 'w'); Add("Ꮓ", 'z'); Add("Ᏼ", 'b'); Add("Ꮯ", 'c'); Add("Ꮐ", 'g');
        Add("ɑ", 'a'); Add("ɡ", 'g'); Add("ı", 'i'); Add("ɩ", 'i'); Add("ⅰ", 'i'); Add("ℓ", 'l');
        Add("ⅾ", 'd'); Add("ⅿ", 'm'); Add("ⅴ", 'v'); Add("ⅹ", 'x'); Add("ℂ", 'c'); Add("ℍ", 'h');
        Add("ℕ", 'n'); Add("ℙ", 'p'); Add("ℚ", 'q'); Add("ℝ", 'r'); Add("ℤ", 'z'); Add("ℬ", 'b');
        Add("ℰ", 'e'); Add("ℱ", 'f'); Add("ℳ", 'm'); Add("ℛ", 'r'); Add("ℒ", 'l'); Add("ℐ", 'i');
        Add("ℯ", 'e'); Add("ℊ", 'g'); Add("ℴ", 'o');

        // Digit lookalikes.
        Add("Ο", '0'); Add("О", '0'); Add("о", '0'); Add("૦", '0'); Add("०", '0'); Add("೦", '0');
        Add("１", '1'); Add("Ⅰ", '1'); Add("ⅼ", '1'); Add("Ӏ", '1');
        Add("Ƨ", '2'); Add("Ꝛ", '2'); Add("Ʒ", '3'); Add("Ȣ", '8');

        // Fullwidth ASCII (U+FF01..U+FF5E) folds to ASCII by offset.
        for (var cp = 0xFF01; cp <= 0xFF5E; cp++)
        {
            var ascii = (char)(cp - 0xFF01 + 0x21);
            if (char.IsAsciiLetterOrDigit(ascii))
            {
                map[cp] = char.ToLowerInvariant(ascii);
            }
        }

        // Mathematical alphanumeric symbols (U+1D400..U+1D6A3): 13 styles x 52 letters.
        for (var cp = 0x1D400; cp <= 0x1D6A3; cp++)
        {
            var index = (cp - 0x1D400) % 52;
            var ascii = index < 26 ? (char)('a' + index) : (char)('a' + index - 26);
            map[cp] = ascii;
        }

        // Mathematical digits (U+1D7CE..U+1D7FF): 5 styles x 10 digits.
        for (var cp = 0x1D7CE; cp <= 0x1D7FF; cp++)
        {
            map[cp] = (char)('0' + (cp - 0x1D7CE) % 10);
        }

        // A handful of ASCII-range and Latin-1 lookalikes that fold visually.
        map['|'] = 'l';
        map['\u00A0'] = ' ';
        map['\u2010'] = '-'; map['\u2011'] = '-'; map['\u2012'] = '-'; map['\u2013'] = '-'; map['\u2014'] = '-';
        map['\u2212'] = '-'; map['\u02D7'] = '-';
        map['\u2024'] = '.'; map['\u3002'] = '.';
        map['\uFF3F'] = '_'; map['\u2017'] = '_';

        // The digit lookalikes above must not override letter mappings for the same
        // codepoint when both apply; prefer letters (a homoglyph "o" is more common than "0").
        map[0x039F] = 'o'; map[0x041E] = 'o'; map[0x043E] = 'o';
        map[0x04CF] = 'l'; map[0x217C] = 'l';

        return map;
    }
}
