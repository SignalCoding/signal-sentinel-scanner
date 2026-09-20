// -----------------------------------------------------------------------
// <copyright file="AgentCardReaderTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Net;
using System.Text.Json;
using Shouldly;
using SignalSentinel.Scanner.AgentCard;
using SignalSentinel.Scanner.Offline;
using Xunit;

namespace SignalSentinel.Scanner.Tests.AgentCard;

/// <summary>v3.0.0 WP9: <see cref="AgentCardReader"/> URL handling, parsing and bounded loading.</summary>
[Collection("OfflineGuardSerial")]
public class AgentCardReaderTests : IDisposable
{
    private const string FullCard = """
        {
          "name": "Travel Agent",
          "description": "Books travel.",
          "url": "https://travel.example/a2a",
          "securitySchemes": { "bearer": { "type": "http", "scheme": "bearer" } },
          "skills": [
            { "id": "book", "name": "Book Flight", "description": "Books a flight." },
            { "id": "cancel", "description": "Cancels a booking." },
            "not-an-object",
            { "name": 42 }
          ]
        }
        """;

    public AgentCardReaderTests()
    {
        OfflineGuard.Reset();
    }

    public void Dispose()
    {
        OfflineGuard.Reset();
        GC.SuppressFinalize(this);
    }

    // ------------------------------------------------------------- IsUrl / ExpandWellKnown

    [Theory]
    [InlineData("https://agent.example", true)]
    [InlineData("http://agent.example/card.json", true)]
    [InlineData("HTTPS://AGENT.EXAMPLE/", true)]
    [InlineData("ftp://agent.example/card.json", false)]
    [InlineData("file:///tmp/card.json", false)]
    [InlineData("C:\\cards\\agent.json", false)]
    [InlineData("./agent.json", false)]
    [InlineData("agent.json", false)]
    public void IsUrl_ClassifiesTargets(string target, bool expected)
    {
        AgentCardReader.IsUrl(target).ShouldBe(expected);
    }

    [Theory]
    [InlineData("https://agent.example", "https://agent.example/.well-known/agent.json")]
    [InlineData("https://agent.example/", "https://agent.example/.well-known/agent.json")]
    [InlineData("https://agent.example:8443", "https://agent.example:8443/.well-known/agent.json")]
    [InlineData("https://agent.example/cards/a.json", "https://agent.example/cards/a.json")]
    [InlineData("https://agent.example/?v=1", "https://agent.example/?v=1")]
    [InlineData("not a url", "not a url")]
    public void ExpandWellKnown_AppendsOnlyToBareOrigin(string target, string expected)
    {
        AgentCardReader.ExpandWellKnown(target).ShouldBe(expected);
    }

    // ------------------------------------------------------------- Parse

    [Fact]
    public void Parse_FullCard_ExtractsFields()
    {
        var card = AgentCardReader.Parse(FullCard, "https://travel.example/.well-known/agent.json", fromNetwork: true);

        card.Status.ShouldBe(AgentCardStatus.Loaded);
        card.FromNetwork.ShouldBeTrue();
        card.DisplayName.ShouldBe("Travel Agent");
        card.Description.ShouldBe("Books travel.");
        card.EndpointUrl.ShouldBe("https://travel.example/a2a");
        card.DeclaresSecurityScheme.ShouldBeTrue();
        card.SecuritySchemesEmpty.ShouldBeFalse();
        card.Skills.Count.ShouldBe(3);
        card.Skills[0].ShouldBe(new AgentCardSkill("Book Flight", "Books a flight."));
        card.Skills[1].ShouldBe(new AgentCardSkill("cancel", "Cancels a booking."));
        card.Skills[2].Name.ShouldBe("skill-3");
        card.Skills[2].Description.ShouldBeNull();
    }

    [Fact]
    public void Parse_EmptySecuritySchemesObject_FlaggedEmpty()
    {
        var card = AgentCardReader.Parse("""{ "name": "a", "securitySchemes": {} }""", "/c.json", fromNetwork: false);

        card.DeclaresSecurityScheme.ShouldBeFalse();
        card.SecuritySchemesEmpty.ShouldBeTrue();
    }

    [Fact]
    public void Parse_EmptySecuritySchemesArray_FlaggedEmpty()
    {
        var card = AgentCardReader.Parse("""{ "name": "a", "securitySchemes": [] }""", "/c.json", fromNetwork: false);

        card.DeclaresSecurityScheme.ShouldBeFalse();
        card.SecuritySchemesEmpty.ShouldBeTrue();
    }

    [Fact]
    public void Parse_SecuritySchemesArrayWithEntry_Declares()
    {
        var card = AgentCardReader.Parse("""{ "securitySchemes": [ { "type": "apiKey" } ] }""", "/c.json", fromNetwork: false);

        card.DeclaresSecurityScheme.ShouldBeTrue();
    }

    [Fact]
    public void Parse_LegacyAuthenticationSchemes_Declares()
    {
        var card = AgentCardReader.Parse(
            """{ "name": "a", "authentication": { "schemes": ["Bearer"] } }""", "/c.json", fromNetwork: false);

        card.DeclaresSecurityScheme.ShouldBeTrue();
        card.SecuritySchemesEmpty.ShouldBeFalse();
    }

    [Fact]
    public void Parse_LegacyAuthenticationEmpty_DoesNotDeclare()
    {
        var card = AgentCardReader.Parse(
            """{ "name": "a", "authentication": { "schemes": [] } }""", "/c.json", fromNetwork: false);

        card.DeclaresSecurityScheme.ShouldBeFalse();
        card.SecuritySchemesEmpty.ShouldBeFalse();
    }

    [Fact]
    public void Parse_NoSecurityDeclaration_AbsentNotEmpty()
    {
        var card = AgentCardReader.Parse("""{ "name": "a" }""", "/c.json", fromNetwork: false);

        card.DeclaresSecurityScheme.ShouldBeFalse();
        card.SecuritySchemesEmpty.ShouldBeFalse();
    }

    [Fact]
    public void Parse_MissingName_FallsBackToHostOrFile()
    {
        AgentCardReader.Parse("{}", "https://agent.example/.well-known/agent.json", fromNetwork: true)
            .DisplayName.ShouldBe("agent.example");
        AgentCardReader.Parse("{}", Path.Combine("cards", "agent.json"), fromNetwork: false)
            .DisplayName.ShouldBe("agent.json");
    }

    [Fact]
    public void Parse_NonStringFields_Ignored()
    {
        var card = AgentCardReader.Parse(
            """{ "name": ["x"], "description": 1, "url": null, "skills": "nope", "securitySchemes": "bearer" }""",
            "/c.json", fromNetwork: false);

        card.Status.ShouldBe(AgentCardStatus.Loaded);
        card.Description.ShouldBeNull();
        card.EndpointUrl.ShouldBeNull();
        card.Skills.ShouldBeEmpty();
        card.DeclaresSecurityScheme.ShouldBeFalse();
        card.SecuritySchemesEmpty.ShouldBeFalse();
    }

    [Fact]
    public void Parse_RootNotObject_Failed()
    {
        var card = AgentCardReader.Parse("[1,2,3]", "/c.json", fromNetwork: false);

        card.Status.ShouldBe(AgentCardStatus.Failed);
        card.FailureReason.ShouldBe("NotAJsonObject");
    }

    [Fact]
    public void Parse_MalformedJson_Throws()
    {
        Should.Throw<JsonException>(() => AgentCardReader.Parse("{ not json", "/c.json", fromNetwork: false));
    }

    [Fact]
    public void Parse_SkillsCappedAt100_NamesTruncated()
    {
        var skills = string.Join(',', Enumerable.Range(0, 150).Select(i =>
            $$$"""{ "name": "{{{new string('n', 300)}}}{{{i}}}" }"""));
        var card = AgentCardReader.Parse($$"""{ "skills": [{{skills}}] }""", "/c.json", fromNetwork: false);

        card.Skills.Count.ShouldBe(100);
        card.Skills.ShouldAllBe(s => s.Name.Length == 200);
    }

    // ------------------------------------------------------------- LoadAsync (file)

    [Fact]
    public async Task LoadAsync_LocalFile_Loaded()
    {
        var path = WriteTemp(FullCard);
        try
        {
            var card = await AgentCardReader.LoadAsync(path);

            card.Status.ShouldBe(AgentCardStatus.Loaded);
            card.FromNetwork.ShouldBeFalse();
            card.Source.ShouldBe(Path.GetFullPath(path));
            card.DisplayName.ShouldBe("Travel Agent");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_LocalFile_WorksOffline()
    {
        OfflineGuard.Enable();
        var path = WriteTemp("""{ "name": "offline" }""");
        try
        {
            var card = await AgentCardReader.LoadAsync(path);

            card.Status.ShouldBe(AgentCardStatus.Loaded);
            card.DisplayName.ShouldBe("offline");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_MissingFile_Failed()
    {
        var path = Path.Combine(Path.GetTempPath(), "ss-card-missing-" + Guid.NewGuid().ToString("N") + ".json");

        var card = await AgentCardReader.LoadAsync(path);

        card.Status.ShouldBe(AgentCardStatus.Failed);
        card.FailureReason.ShouldBe("FileNotFound");
        card.FromNetwork.ShouldBeFalse();
    }

    [Fact]
    public async Task LoadAsync_EmptyFile_Failed()
    {
        var path = WriteTemp(string.Empty);
        try
        {
            var card = await AgentCardReader.LoadAsync(path);

            card.Status.ShouldBe(AgentCardStatus.Failed);
            card.FailureReason.ShouldBe("FileSizeOutOfBounds");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_MalformedFile_FailedNotThrown()
    {
        var path = WriteTemp("{ nope");
        try
        {
            var card = await AgentCardReader.LoadAsync(path);

            card.Status.ShouldBe(AgentCardStatus.Failed);
            card.FailureReason.ShouldStartWith("Json"); // JsonReaderException is internal to System.Text.Json
        }
        finally
        {
            File.Delete(path);
        }
    }

    // ------------------------------------------------------------- LoadAsync (network)

    [Fact]
    public async Task LoadAsync_Url_ExpandsWellKnownAndParses()
    {
        using var handler = new ScriptedHandler(_ => Json(FullCard));
        using var http = new HttpClient(handler);

        var card = await AgentCardReader.LoadAsync("https://travel.example", http, CancellationToken.None);

        card.Status.ShouldBe(AgentCardStatus.Loaded);
        card.FromNetwork.ShouldBeTrue();
        card.Source.ShouldBe("https://travel.example/.well-known/agent.json");
        handler.Requests.ShouldBe(["https://travel.example/.well-known/agent.json"]);
    }

    [Fact]
    public async Task LoadAsync_Url_Offline_FailedWithoutRequest()
    {
        OfflineGuard.Enable();
        using var handler = new ScriptedHandler(_ => Json(FullCard));
        using var http = new HttpClient(handler);

        var card = await AgentCardReader.LoadAsync("https://travel.example", http, CancellationToken.None);

        card.Status.ShouldBe(AgentCardStatus.Failed);
        card.FailureReason.ShouldBe(nameof(OfflineViolationException));
        handler.Requests.ShouldBeEmpty();
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.Found)] // redirects are not followed and count as failure
    public async Task LoadAsync_Url_NonSuccess_Failed(HttpStatusCode status)
    {
        using var handler = new ScriptedHandler(_ => new HttpResponseMessage(status));
        using var http = new HttpClient(handler);

        var card = await AgentCardReader.LoadAsync("https://travel.example/card.json", http, CancellationToken.None);

        card.Status.ShouldBe(AgentCardStatus.Failed);
        card.FailureReason.ShouldBe(nameof(HttpRequestException));
        card.DisplayName.ShouldBe("travel.example");
    }

    [Fact]
    public async Task LoadAsync_Url_MalformedBody_Failed()
    {
        using var handler = new ScriptedHandler(_ => Json("<html>"));
        using var http = new HttpClient(handler);

        var card = await AgentCardReader.LoadAsync("https://travel.example/card.json", http, CancellationToken.None);

        card.Status.ShouldBe(AgentCardStatus.Failed);
        card.FailureReason.ShouldStartWith("Json"); // JsonReaderException is internal to System.Text.Json
    }

    [Fact]
    public async Task LoadAsync_Url_OversizedDeclaredLength_Failed()
    {
        using var handler = new ScriptedHandler(_ =>
        {
            var response = Json("{}");
            response.Content.Headers.ContentLength = AgentCardReader.MaxCardBytes + 1;
            return response;
        });
        using var http = new HttpClient(handler);

        var card = await AgentCardReader.LoadAsync("https://travel.example/card.json", http, CancellationToken.None);

        card.Status.ShouldBe(AgentCardStatus.Failed);
        card.FailureReason.ShouldBe(nameof(InvalidDataException));
    }

    [Fact]
    public async Task LoadAsync_Url_OversizedStreamedBody_Failed()
    {
        var body = "{ \"description\": \"" + new string('a', (int)AgentCardReader.MaxCardBytes + 64) + "\" }";
        using var handler = new ScriptedHandler(_ =>
        {
            var response = Json(body);
            response.Content.Headers.ContentLength = null;
            return response;
        });
        using var http = new HttpClient(handler);

        var card = await AgentCardReader.LoadAsync("https://travel.example/card.json", http, CancellationToken.None);

        card.Status.ShouldBe(AgentCardStatus.Failed);
        card.FailureReason.ShouldBe(nameof(InvalidDataException));
    }

    [Fact]
    public async Task LoadAsync_Url_OperatorCancellation_Propagates()
    {
        using var handler = new ScriptedHandler(_ => throw new TaskCanceledException());
        using var http = new HttpClient(handler);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Should.ThrowAsync<OperationCanceledException>(
            () => AgentCardReader.LoadAsync("https://travel.example/card.json", http, cts.Token));
    }

    [Fact]
    public async Task LoadAsync_Url_HttpTimeout_IsFailureNotCancellation()
    {
        using var handler = new ScriptedHandler(_ => throw new TaskCanceledException("timeout"));
        using var http = new HttpClient(handler);

        var card = await AgentCardReader.LoadAsync("https://travel.example/card.json", http, CancellationToken.None);

        card.Status.ShouldBe(AgentCardStatus.Failed);
        card.FailureReason.ShouldBe(nameof(TaskCanceledException));
    }

    // ------------------------------------------------------------- helpers

    private static string WriteTemp(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), "ss-card-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, content);
        return path;
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };

    private sealed class ScriptedHandler(Func<HttpRequestMessage, HttpResponseMessage> script) : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri?.ToString() ?? string.Empty);
            return Task.FromResult(script(request));
        }
    }
}
