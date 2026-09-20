// -----------------------------------------------------------------------
// <copyright file="ServerSourceAnalyzerTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.ServerSource;
using Xunit;

namespace SignalSentinel.Scanner.Tests.ServerSource;

/// <summary>v3.0.0 WP9: <see cref="ServerSourceAnalyzer"/> registration detection, sink families and walk bounds.</summary>
public class ServerSourceAnalyzerTests
{
    private const string JsToolServer = """
        import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
        import { exec } from "node:child_process";
        const server = new McpServer({ name: "demo" });
        server.tool("run", { cmd: z.string() }, async ({ cmd }) => {
          // exec(cmd) would be dangerous
          const out = exec(`ls ${cmd}`);
          return { content: [{ type: "text", text: out }] };
        });
        """;

    private const string PyToolServer = """
        from mcp.server.fastmcp import FastMCP
        import subprocess
        mcp = FastMCP("demo")

        @mcp.tool()
        def run(cmd: str) -> str:
            # subprocess.run(cmd, shell=True) is the bad way
            return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
        """;

    // ------------------------------------------------------------- RegistersTools

    [Theory]
    [InlineData("server.tool(\"x\", {}, async () => {})")]
    [InlineData("server.registerTool('x', {}, handler)")]
    [InlineData("server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }))")]
    [InlineData("if (req.method === 'tools/call') { }")]
    [InlineData("import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';")]
    public void RegistersTools_JsRegistrationForms_Detected(string content)
    {
        ServerSourceAnalyzer.RegistersTools(content, isPython: false).ShouldBeTrue();
    }

    [Theory]
    [InlineData("const tool = require('./tool');\nmodule.exports = { tool };")]
    [InlineData("function tools() { return []; }")]
    [InlineData("const x = obj.tool;")]
    [InlineData("const path = 'tools/listing';")]
    public void RegistersTools_JsUnrelatedText_NotDetected(string content)
    {
        ServerSourceAnalyzer.RegistersTools(content, isPython: false).ShouldBeFalse();
    }

    [Theory]
    [InlineData("@mcp.tool()\ndef f(): pass")]
    [InlineData("@server.list_tools()\nasync def f(): pass")]
    [InlineData("@app.call_tool\nasync def f(): pass")]
    [InlineData("from mcp.server import Server")]
    [InlineData("import mcp\n")]
    [InlineData("mcp = FastMCP('x')")]
    public void RegistersTools_PythonRegistrationForms_Detected(string content)
    {
        ServerSourceAnalyzer.RegistersTools(content, isPython: true).ShouldBeTrue();
    }

    [Theory]
    [InlineData("import mcpx\n")]
    [InlineData("def tool(): pass")]
    [InlineData("x = mcp.tool")]
    [InlineData("from mcpserverlib import thing")]
    public void RegistersTools_PythonUnrelatedText_NotDetected(string content)
    {
        ServerSourceAnalyzer.RegistersTools(content, isPython: true).ShouldBeFalse();
    }

    // ------------------------------------------------------------- FindSinks (JS)

    [Fact]
    public void FindSinks_JsExecWithImport_Flagged_CommentSkipped()
    {
        var sinks = ServerSourceAnalyzer.FindSinks(JsToolServer, "index.js", isPython: false);

        sinks.Count.ShouldBe(1);
        sinks[0].Kind.ShouldBe("child_process.exec");
        sinks[0].Line.ShouldBe(6);
        sinks[0].Severity.ShouldBe(Severity.High);
        sinks[0].RelativePath.ShouldBe("index.js");
        sinks[0].Snippet.ShouldBe("const out = exec(`ls ${cmd}`);");
    }

    [Fact]
    public void FindSinks_JsExecWithoutChildProcessImport_NotFlagged()
    {
        const string content = """
            server.tool("x", {}, async () => {
              const result = await db.exec("SELECT 1");
              return execFile(result);
            });
            """;

        var sinks = ServerSourceAnalyzer.FindSinks(content, "a.js", isPython: false);

        sinks.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("const { spawn } = require('child_process');\nspawn('sh', ['-c', cmd], { shell: true });", "child_process.spawn(shell)")]
    [InlineData("const v = eval(userInput);", "eval")]
    [InlineData("const fn = new Function('a', body);", "new Function")]
    [InlineData("vm.runInNewContext(code, sandbox);", "vm.runIn*Context")]
    [InlineData("fs.writeFileSync(path.join(os.homedir(), '.bashrc'), payload);", "write under home")]
    [InlineData("fs.appendFile(process.env.HOME + '/.zshrc', line, cb);", "write under home")]
    [InlineData("fs.writeFile(`~/.config/claude/settings.json`, data);", "write under home")]
    public void FindSinks_JsFamilies_Flagged(string content, string kind)
    {
        var sinks = ServerSourceAnalyzer.FindSinks(content, "a.js", isPython: false);

        sinks.ShouldContain(s => s.Kind == kind);
    }

    [Theory]
    [InlineData("const v = obj.eval(x);")] // member call, not global eval
    [InlineData("const v = $eval(x);")]
    [InlineData("fs.writeFileSync(path.join(workspace, 'out.txt'), data);")]
    [InlineData("const { spawn } = require('child_process');\nspawn('ls', ['-l']);")]
    [InlineData("// eval(x) commented out")]
    [InlineData("/* new Function('x') */")]
    [InlineData(" * eval(x) in a doc comment")]
    public void FindSinks_JsBenign_NotFlagged(string content)
    {
        var sinks = ServerSourceAnalyzer.FindSinks(content, "a.js", isPython: false);

        sinks.ShouldBeEmpty();
    }

    // ------------------------------------------------------------- FindSinks (Python)

    [Fact]
    public void FindSinks_PySubprocessShell_Flagged_CommentSkipped()
    {
        var sinks = ServerSourceAnalyzer.FindSinks(PyToolServer, "server.py", isPython: true);

        sinks.Count.ShouldBe(1);
        sinks[0].Kind.ShouldBe("subprocess shell=True");
        sinks[0].Line.ShouldBe(8);
        sinks[0].Severity.ShouldBe(Severity.High);
    }

    [Theory]
    [InlineData("os.system(cmd)", "os.system / os.popen")]
    [InlineData("out = os.popen(cmd).read()", "os.system / os.popen")]
    [InlineData("os.execvp(prog, args)", "os.system / os.popen")]
    [InlineData("obj = pickle.loads(blob)", "pickle.load")]
    [InlineData("obj = dill.load(f)", "pickle.load")]
    [InlineData("db = shelve.open(p)\nx = shelve.load(f)", "pickle.load")]
    [InlineData("result = eval(expr)", "eval / exec")]
    [InlineData("exec(code)", "eval / exec")]
    [InlineData("cfg = yaml.load(text)", "yaml.load (unsafe loader)")]
    [InlineData("cfg = yaml.load(text, Loader=yaml.Loader)", "yaml.load (unsafe loader)")]
    [InlineData("open(os.path.expanduser('~/.bashrc'), 'a').write(line)", "write under home")]
    [InlineData("open(Path.home() / '.ssh' / 'authorized_keys', 'a').write(key)", "write under home")]
    [InlineData("Path(os.path.expanduser('~/.zshrc')).write_text(payload)", "write under home")]
    [InlineData("open(os.environ['HOME'] + '/.profile', mode='w')", "write under home")]
    public void FindSinks_PyFamilies_Flagged(string content, string kind)
    {
        var sinks = ServerSourceAnalyzer.FindSinks(content, "a.py", isPython: true);

        sinks.ShouldContain(s => s.Kind == kind);
    }

    [Theory]
    [InlineData("subprocess.run(['ls', '-l'], check=True)")]
    [InlineData("cfg = yaml.load(text, Loader=yaml.SafeLoader)")]
    [InlineData("cfg = yaml.safe_load(text)")]
    [InlineData("obj.eval(x)")]
    [InlineData("self.exec(x)")]
    [InlineData("literal_eval(x)")]
    [InlineData("open(os.path.expanduser('~/.bashrc')).read()")]
    [InlineData("open(os.path.join(workspace, 'out.txt'), 'w')")]
    [InlineData("# os.system(cmd)")]
    [InlineData("    # exec(code) in an indented comment")]
    public void FindSinks_PyBenign_NotFlagged(string content)
    {
        var sinks = ServerSourceAnalyzer.FindSinks(content, "a.py", isPython: true);

        sinks.ShouldBeEmpty();
    }

    [Fact]
    public void FindSinks_SnippetTruncated_ControlCharsStripped()
    {
        var longLine = "eval(" + new string('x', 400) + ")\t\u0007";

        var sinks = ServerSourceAnalyzer.FindSinks(longLine, "a.js", isPython: false);

        sinks.Count.ShouldBe(1);
        sinks[0].Snippet.Length.ShouldBe(160);
        sinks[0].Snippet.ShouldEndWith("...");
        sinks[0].Snippet.ShouldNotContain("\u0007");
    }

    [Fact]
    public void FindSinks_OrderedByLine()
    {
        const string content = "os.system(a)\nx = 1\neval(b)\npickle.loads(c)";

        var sinks = ServerSourceAnalyzer.FindSinks(content, "a.py", isPython: true);

        sinks.Select(s => s.Line).ShouldBe([1, 3, 4]);
    }

    // ------------------------------------------------------------- AnalyseAsync

    [Fact]
    public async Task AnalyseAsync_MissingDirectory_Throws()
    {
        var missing = Path.Combine(Path.GetTempPath(), "ss-missing-" + Guid.NewGuid().ToString("N"));

        await Should.ThrowAsync<DirectoryNotFoundException>(() => ServerSourceAnalyzer.AnalyseAsync(missing));
    }

    [Fact]
    public async Task AnalyseAsync_EmptyOrWhitespace_Throws()
    {
        await Should.ThrowAsync<ArgumentException>(() => ServerSourceAnalyzer.AnalyseAsync("  "));
    }

    [Fact]
    public async Task AnalyseAsync_OnlyToolFilesContributeSinks()
    {
        using var tree = new TempTree();
        tree.Write("src/index.js", JsToolServer);
        tree.Write("src/helper.js", "const { exec } = require('child_process');\nexec('ls');"); // sink, no tool registration
        tree.Write("py/server.py", PyToolServer);
        tree.Write("py/util.py", "import os\nos.system('ls')"); // sink, no tool registration
        tree.Write("README.md", "eval(x) os.system(y)");

        var analysis = await ServerSourceAnalyzer.AnalyseAsync(tree.Root);

        analysis.FilesScanned.ShouldBe(4);
        analysis.ToolFiles.ShouldBe(2);
        analysis.Truncated.ShouldBeFalse();
        analysis.Sinks.Count.ShouldBe(2);
        analysis.Sinks.ShouldContain(s => s.RelativePath == "src/index.js" && s.Kind == "child_process.exec");
        analysis.Sinks.ShouldContain(s => s.RelativePath == "py/server.py" && s.Kind == "subprocess shell=True");
        analysis.DisplayName.ShouldBe(new DirectoryInfo(tree.Root).Name);
    }

    [Fact]
    public async Task AnalyseAsync_SkipsVendorDotDirsDeclarationsMinifiedAndEmpty()
    {
        using var tree = new TempTree();
        tree.Write("node_modules/dep/index.js", JsToolServer);
        tree.Write(".git/hooks/x.js", JsToolServer);
        tree.Write(".venv/lib/site.py", PyToolServer);
        tree.Write("types/index.d.ts", JsToolServer);
        tree.Write("dist/bundle.min.js", JsToolServer);
        tree.Write("src/empty.js", string.Empty);
        tree.Write("src/real.ts", JsToolServer);

        var analysis = await ServerSourceAnalyzer.AnalyseAsync(tree.Root);

        analysis.FilesScanned.ShouldBe(1);
        analysis.ToolFiles.ShouldBe(1);
        analysis.Sinks.Count.ShouldBe(1);
        analysis.Sinks[0].RelativePath.ShouldBe("src/real.ts");
    }

    [Fact]
    public async Task AnalyseAsync_OversizedFile_Skipped()
    {
        using var tree = new TempTree();
        var padding = new string('/', (int)ServerSourceAnalyzer.MaxFileBytes + 16);
        tree.Write("src/huge.js", JsToolServer + "\n" + padding);
        tree.Write("src/ok.js", JsToolServer);

        var analysis = await ServerSourceAnalyzer.AnalyseAsync(tree.Root);

        analysis.FilesScanned.ShouldBe(1);
        analysis.Sinks.Count.ShouldBe(1);
        analysis.Sinks[0].RelativePath.ShouldBe("src/ok.js");
    }

    [Fact]
    public async Task AnalyseAsync_SinkCap_SetsTruncated()
    {
        // SafeMatches caps each pattern at 100 hits, so three families are needed to exceed the run cap.
        using var tree = new TempTree();
        var lines = string.Join('\n', Enumerable.Repeat("eval(x); new Function(y); vm.runInNewContext(z);", 110));
        tree.Write("index.js", "server.tool('x', {}, h);\n" + lines);

        var analysis = await ServerSourceAnalyzer.AnalyseAsync(tree.Root);

        analysis.Sinks.Count.ShouldBe(ServerSourceAnalyzer.MaxSinks);
        analysis.Truncated.ShouldBeTrue();
    }

    [Fact]
    public async Task AnalyseAsync_Cancelled_Throws()
    {
        using var tree = new TempTree();
        tree.Write("index.js", JsToolServer);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Should.ThrowAsync<OperationCanceledException>(() => ServerSourceAnalyzer.AnalyseAsync(tree.Root, cts.Token));
    }

    [Fact]
    public async Task AnalyseAsync_RelativePathsUseForwardSlashes()
    {
        using var tree = new TempTree();
        tree.Write("a/b/c/index.js", JsToolServer);

        var analysis = await ServerSourceAnalyzer.AnalyseAsync(tree.Root);

        analysis.Sinks.Count.ShouldBe(1);
        analysis.Sinks[0].RelativePath.ShouldBe("a/b/c/index.js");
    }

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), "ss-src-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public void Write(string relativePath, string content)
        {
            var full = Path.Combine(Root, relativePath.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, content);
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
