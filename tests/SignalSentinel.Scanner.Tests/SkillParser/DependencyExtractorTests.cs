using System;
using System.IO;
using System.Linq;
using Shouldly;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillParser;

public class DependencyExtractorTests
{
    [Theory]
    [InlineData("pip install requests==2.31.0", "requests", "2.31.0")]
    [InlineData("pip3 install flask==3.0.0", "flask", "3.0.0")]
    [InlineData("Run: pip install requests[security]==2.31.0 --upgrade", "requests", "2.31.0")]
    [InlineData("PIP INSTALL Django==4.2", "django", "4.2")]
    public void Text_PipPinned_Queried(string text, string name, string version)
    {
        var deps = DependencyExtractor.ExtractFromText("skill", text);

        deps.Count.ShouldBe(1);
        deps[0].Name.ShouldBe(name);
        deps[0].Version.ShouldBe(version);
        deps[0].Ecosystem.ShouldBe("PyPI");
    }

    [Theory]
    [InlineData("pip install requests", "requests")]
    [InlineData("pip install requests>=2.0", "requests")]
    [InlineData("pip install requests[security]", "requests")]
    public void Text_PipUnpinnedOrRanged_RecordedWithoutVersion(string text, string name)
    {
        var deps = DependencyExtractor.ExtractFromText("skill", text);

        deps.Count.ShouldBe(1);
        deps[0].Name.ShouldBe(name);
        deps[0].Version.ShouldBeNull();
    }

    [Theory]
    [InlineData("npm install lodash@4.17.20", "lodash", "4.17.20")]
    [InlineData("npm i @scope/pkg@1.2.3", "@scope/pkg", "1.2.3")]
    [InlineData("npm install left-pad@1.3.0 express@4.18.2", "left-pad", "1.3.0")]
    public void Text_NpmPinned_Queried(string text, string name, string version)
    {
        var deps = DependencyExtractor.ExtractFromText("skill", text);

        deps.ShouldContain(d => d.Name == name && d.Version == version && d.Ecosystem == "npm");
    }

    [Theory]
    [InlineData("npm install lodash", "lodash")]
    [InlineData("npm install lodash@^4.17.0", "lodash")]
    [InlineData("npm install @scope/pkg@latest", "@scope/pkg")]
    public void Text_NpmUnpinnedOrRanged_RecordedWithoutVersion(string text, string name)
    {
        var deps = DependencyExtractor.ExtractFromText("skill", text);

        deps.Count.ShouldBe(1);
        deps[0].Name.ShouldBe(name);
        deps[0].Version.ShouldBeNull();
    }

    [Fact]
    public void Text_InstallFlags_NotRecordedAsPackages()
    {
        var deps = DependencyExtractor.ExtractFromText("skill", "pip install --upgrade --quiet requests==2.0.0");

        deps.Count.ShouldBe(1);
        deps[0].Name.ShouldBe("requests");
    }

    [Fact]
    public void Text_NoInstalls_ReturnsEmpty()
    {
        DependencyExtractor.ExtractFromText("skill", "Just prose about pipelines.").ShouldBeEmpty();
        DependencyExtractor.ExtractFromText("skill", null).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("pip install ==")]
    [InlineData("pip install >=")]
    [InlineData("pip install [")]
    [InlineData("npm install @")]
    [InlineData("npm install @1.2.3")]
    [InlineData("pip install 2.31.0")]
    public void Text_OperatorOnlyOrNamelessTokens_NeverThrowAndRecordNothing(string text)
    {
        var deps = Should.NotThrow(() => DependencyExtractor.ExtractFromText("skill", text));

        deps.ShouldBeEmpty();
    }

    [Fact]
    public void Text_SpacedPep508Operator_ParsesAsOnePin()
    {
        var deps = DependencyExtractor.ExtractFromText("skill", "pip install requests == 2.31.0");

        deps.Count.ShouldBe(1);
        deps[0].Name.ShouldBe("requests");
        deps[0].Version.ShouldBe("2.31.0");
    }

    [Theory]
    [InlineData("pip install -r requirements.txt")]
    [InlineData("pip install --requirement requirements.txt")]
    [InlineData("pip install -e .")]
    [InlineData("pip install -i https://pypi.example/simple")]
    [InlineData("npm install ./local-path")]
    [InlineData("npm install ../sibling")]
    [InlineData("npm install git+https://github.com/x/y.git")]
    [InlineData("npm install file:../local")]
    [InlineData("npm install https://example.com/pkg.tgz")]
    public void Text_FlagValuesPathsAndUrls_NotRecordedAsPackages(string text)
    {
        DependencyExtractor.ExtractFromText("skill", text).ShouldBeEmpty();
    }

    [Fact]
    public void Text_FlagValueSkipped_FollowingPackageStillRecorded()
    {
        var deps = DependencyExtractor.ExtractFromText("skill", "pip install -r requirements.txt requests==1.0");

        deps.Count.ShouldBe(1);
        deps[0].Name.ShouldBe("requests");
        deps[0].Version.ShouldBe("1.0");
    }

    [Fact]
    public void Text_InlineCodeBackticks_StrippedFromVersion()
    {
        var deps = DependencyExtractor.ExtractFromText("skill", "Run `pip install requests==2.0.0` first.");

        deps.Count.ShouldBe(1);
        deps[0].Version.ShouldBe("2.0.0");
    }

    [Theory]
    [InlineData("pip install pkg===1.0", "pkg")]
    [InlineData("npm install pkg@1.x", "pkg")]
    [InlineData("npm install pkg@1.2.x", "pkg")]
    [InlineData("pip install pkg==1.*", "pkg")]
    public void Text_NonExactVersions_RecordedUnpinned(string text, string name)
    {
        var deps = DependencyExtractor.ExtractFromText("skill", text);

        deps.Count.ShouldBe(1);
        deps[0].Name.ShouldBe(name);
        deps[0].Version.ShouldBeNull();
    }

    [Fact]
    public void Text_PythonModulePipAndNpmAdd_Recognised()
    {
        var deps = DependencyExtractor.ExtractFromText(
            "skill", "python -m pip install requests==2.31.0\nnpm add lodash@4.17.21");

        deps.ShouldContain(d => d.Name == "requests" && d.Version == "2.31.0");
        deps.ShouldContain(d => d.Name == "lodash" && d.Version == "4.17.21");
    }

    [Fact]
    public void RequirementsTxt_PinsCommentsMarkersExtras()
    {
        const string content = """
            # comment line
            requests==2.31.0
            flask==3.0.0  # inline comment
            django>=4.0
            click[extra]==8.1.0 ; python_version >= "3.10"
            -r other-requirements.txt
            numpy
            """;

        var deps = DependencyExtractor.ParseRequirementsTxt("skill", "requirements.txt", content);

        deps.ShouldContain(d => d.Name == "requests" && d.Version == "2.31.0");
        deps.ShouldContain(d => d.Name == "flask" && d.Version == "3.0.0");
        deps.ShouldContain(d => d.Name == "click" && d.Version == "8.1.0");
        deps.ShouldContain(d => d.Name == "django" && d.Version == null);
        deps.ShouldContain(d => d.Name == "numpy" && d.Version == null);
        deps.Count.ShouldBe(5);
    }

    [Fact]
    public void PackageJson_ExactVersionsQueried_RangesRecorded()
    {
        const string content = """
            {
              "dependencies": { "lodash": "4.17.21", "react": "^18.2.0" },
              "devDependencies": { "jest": "29.5.0" }
            }
            """;

        var deps = DependencyExtractor.ParsePackageJson("skill", "package.json", content);

        deps.Count.ShouldBe(3);
        deps.ShouldContain(d => d.Name == "lodash" && d.Version == "4.17.21");
        deps.ShouldContain(d => d.Name == "jest" && d.Version == "29.5.0");
        deps.ShouldContain(d => d.Name == "react" && d.Version == null);
    }

    [Fact]
    public void RequirementsTxt_HashOptionsAndOperatorOnlyLines()
    {
        const string content = """
            requests==2.0 --hash=sha256:abc
            ==
            flask == 3.0.0
            >=1.0
            """;

        var deps = Should.NotThrow(() => DependencyExtractor.ParseRequirementsTxt("skill", "requirements.txt", content));

        deps.Count.ShouldBe(2);
        deps.ShouldContain(d => d.Name == "requests" && d.Version == "2.0");
        deps.ShouldContain(d => d.Name == "flask" && d.Version == "3.0.0");
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("[1, 2]")]
    [InlineData("null")]
    [InlineData("\"text\"")]
    [InlineData("""{ "dependencies": [ "lodash" ] }""")]
    [InlineData("""{ "dependencies": { "": "1.0.0", "-bad": "1.0.0", "2.0": "1.0.0" } }""")]
    public void PackageJson_MalformedOrImplausible_ReturnsEmptyWithoutThrowing(string content)
    {
        Should.NotThrow(() => DependencyExtractor.ParsePackageJson("skill", "package.json", content))
            .ShouldBeEmpty();
    }

    [Fact]
    public void PackageJson_NonStringVersion_RecordedUnpinned()
    {
        var deps = DependencyExtractor.ParsePackageJson(
            "skill", "package.json", """{ "dependencies": { "lodash": 4, "react": null } }""");

        deps.Count.ShouldBe(2);
        deps.ShouldAllBe(d => d.Version == null);
    }

    [Fact]
    public void PyprojectToml_CrlfLineEndings_Parsed()
    {
        const string content = "[project]\r\nname = 'x'\r\ndependencies = [\r\n  \"requests==2.31.0\",\r\n]\r\n\r\n[tool.x]\r\ndependencies = [\"nope==1\"]\r\n";

        var deps = DependencyExtractor.ParsePyprojectToml("skill", "pyproject.toml", content);

        deps.Count.ShouldBe(1);
        deps[0].Name.ShouldBe("requests");
        deps[0].Version.ShouldBe("2.31.0");
    }

    [Fact]
    public void Text_NonAsciiName_NotRecorded()
    {
        DependencyExtractor.ExtractFromText("skill", "pip install rëquests==2.0").ShouldBeEmpty();
    }

    [Fact]
    public void PyprojectToml_ExtrasBracketsDoNotTruncateArray()
    {
        const string content = """
            [project]
            name = "demo"
            keywords = ["one", "two"]
            dependencies = [
                "pkg[extra]==1.0",
                "after==2.0",
                "==",
            ]

            [tool.other]
            dependencies = ["ignored==9.9"]
            """;

        var deps = Should.NotThrow(() => DependencyExtractor.ParsePyprojectToml("skill", "pyproject.toml", content));

        deps.Count.ShouldBe(2);
        deps.ShouldContain(d => d.Name == "pkg" && d.Version == "1.0");
        deps.ShouldContain(d => d.Name == "after" && d.Version == "2.0");
    }

    [Fact]
    public void PyprojectToml_ProjectDependencies_ExactPinsAndRanges()
    {
        const string content = """
            [build-system]
            requires = ["setuptools"]

            [project]
            name = "demo"
            dependencies = [
                "requests==2.31.0",
                'click>=8.1',
                "rich",
            ]
            """;

        var deps = DependencyExtractor.ParsePyprojectToml("skill", "pyproject.toml", content);

        deps.Count.ShouldBe(3);
        deps.ShouldContain(d => d.Name == "requests" && d.Version == "2.31.0");
        deps.ShouldContain(d => d.Name == "click" && d.Version == null);
        deps.ShouldContain(d => d.Name == "rich" && d.Version == null);
    }

    [Fact]
    public void Extract_ReadsManifestsFromAdditionalFiles()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"sentinel-dep-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var manifest = Path.Combine(dir, "requirements.txt");
            File.WriteAllText(manifest, "requests==2.31.0\n");

            var skill = TestSkills.MakeSkill("manifest-skill", "nothing here");
            skill = skill with { FilePath = Path.Combine(dir, "SKILL.md"), AdditionalFiles = [manifest] };

            var deps = DependencyExtractor.Extract(skill);

            deps.Count.ShouldBe(1);
            deps[0].Name.ShouldBe("requests");
            deps[0].Version.ShouldBe("2.31.0");
            deps[0].Source.ShouldBe("requirements.txt");

            // A rooted path outside the skill directory is refused just like a relative one.
            var elsewhere = skill with { FilePath = Path.Combine(dir, "sub", "SKILL.md") };
            Directory.CreateDirectory(Path.Combine(dir, "sub"));

            DependencyExtractor.Extract(elsewhere).ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Extract_BareFileNames_ResolveAgainstSkillDirectoryNotCwd()
    {
        var skillDir = Path.Combine(Path.GetTempPath(), $"sentinel-dep-{Guid.NewGuid():N}");
        Directory.CreateDirectory(skillDir);
        try
        {
            File.WriteAllText(Path.Combine(skillDir, "requirements.txt"), "bundled==1.0.0\n");
            var skillWithManifest = TestSkills.MakeSkill("skill", "no deps") with
            {
                FilePath = Path.Combine(skillDir, "SKILL.md"),
                AdditionalFiles = ["requirements.txt"]
            };

            var deps = DependencyExtractor.Extract(skillWithManifest);

            deps.Count.ShouldBe(1);
            deps[0].Name.ShouldBe("bundled");

            // A skill whose directory holds no manifest must not pick one up from elsewhere.
            var emptyDir = Path.Combine(skillDir, "empty");
            Directory.CreateDirectory(emptyDir);
            var skillWithout = skillWithManifest with { FilePath = Path.Combine(emptyDir, "SKILL.md") };

            DependencyExtractor.Extract(skillWithout).ShouldBeEmpty();

            // Traversal out of the skill directory is refused.
            var traversing = skillWithout with { AdditionalFiles = [Path.Combine("..", "requirements.txt")] };

            DependencyExtractor.Extract(traversing).ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(skillDir, recursive: true);
        }
    }

    [Fact]
    public void Extract_NoFilePath_NeverFallsBackToCwd()
    {
        var skill = TestSkills.MakeSkill("skill", "no deps") with
        {
            FilePath = string.Empty,
            AdditionalFiles = ["requirements.txt", "package.json"]
        };

        DependencyExtractor.Extract(skill).ShouldBeEmpty();
    }

    [Fact]
    public void Extract_IgnoresUnknownAndMissingFiles()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"sentinel-dep-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var readme = Path.Combine(dir, "README.md");
            File.WriteAllText(readme, "pip install requests==2.31.0 but only in prose files");
            var missing = Path.Combine(dir, "package.json");

            var skill = TestSkills.MakeSkill("skill", "no deps") with
            {
                AdditionalFiles = [readme, missing]
            };

            DependencyExtractor.Extract(skill).ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
