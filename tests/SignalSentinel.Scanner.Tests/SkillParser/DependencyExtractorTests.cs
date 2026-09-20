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
    public void PackageJson_Malformed_ReturnsEmpty()
    {
        DependencyExtractor.ParsePackageJson("skill", "package.json", "{ not json").ShouldBeEmpty();
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
            skill = skill with { AdditionalFiles = [manifest] };

            var deps = DependencyExtractor.Extract(skill);

            deps.Count.ShouldBe(1);
            deps[0].Name.ShouldBe("requests");
            deps[0].Version.ShouldBe("2.31.0");
            deps[0].Source.ShouldBe("requirements.txt");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
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
