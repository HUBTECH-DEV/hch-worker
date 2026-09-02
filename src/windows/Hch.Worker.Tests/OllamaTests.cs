using System.Net;
using System.Text;
using System.Text.Json;
using Hch.Worker.Core;
using Hch.Worker.Ollama;

namespace Hch.Worker.Tests;

public sealed class OllamaTests
{
    [Fact]
    public async Task StreamingResponseReportsMaterialProgressAndReturnsJson()
    {
        var ndjson = string.Join('\n',
        [
            "{\"message\":{\"content\":\"{\\\"title\\\":\\\"Conteudo\\\",\"},\"done\":false}",
            "{\"message\":{\"content\":\"\\\"excerpt\\\":\\\"Resumo editorial bastante longo\\\",\\\"paragraphs\\\":[\\\"Texto final\\\"]}\"},\"done\":false}",
            "{\"message\":{\"content\":\"\"},\"done\":true,\"done_reason\":\"stop\"}",
            string.Empty,
        ]);
        using var client = new HttpClient(new StaticHandler(HttpStatusCode.OK, ndjson));
        var sut = new OllamaChatClient(
            client,
            new Uri("http://127.0.0.1:11434/"),
            new TestOllamaEndpointGuard());
        var updates = new List<OllamaProgress>();
        using var input = JsonDocument.Parse("{\"operation\":\"generate\"}");

        var result = await sut.GenerateJsonAsync(
            Plan(),
            "Sistema",
            input.RootElement,
            1,
            update => { updates.Add(update); return ValueTask.CompletedTask; });

        Assert.Equal("Conteudo", result.Content.GetProperty("title").GetString());
        Assert.Equal("stop", result.DoneReason);
        Assert.Equal(["responding", "responding", "finalizing"], updates.Select(x => x.Phase));
        Assert.True(updates[1].ContentBytes > updates[0].ContentBytes);
        Assert.All(updates, update => Assert.NotNull(update.Percent));
        Assert.True(updates[1].Percent >= updates[0].Percent);
        Assert.Equal(100d, updates[^1].Percent);
    }

    [Fact]
    public async Task TerminalEventIsRequired()
    {
        using var client = new HttpClient(new StaticHandler(
            HttpStatusCode.OK,
            "{\"message\":{\"content\":\"{}\"},\"done\":false}\n"));
        var sut = new OllamaChatClient(
            client,
            new Uri("http://localhost:11434/"),
            new TestOllamaEndpointGuard());
        using var input = JsonDocument.Parse("{}");

        var error = await Assert.ThrowsAsync<WorkerJobException>(() =>
            sut.GenerateJsonAsync(Plan(), "Sistema", input.RootElement, 1));

        Assert.Equal("generator-output-terminal-missing", error.Code);
    }

    [Fact]
    public void RemoteOllamaEndpointIsRejected()
    {
        using var client = new HttpClient(new StaticHandler(HttpStatusCode.OK, string.Empty));
        var error = Assert.Throws<WorkerJobException>(() =>
            new OllamaChatClient(
                client,
                new Uri("http://192.168.1.10:11434/"),
                new TestOllamaEndpointGuard()));
        Assert.Equal("local-generator-url-refused", error.Code);
    }

    [Fact]
    public void ModelPolicyNeverFallsBackSilently()
    {
        var policy = new SignedModelPolicy(
            new string('a', 64),
            new Dictionary<EditorialContentKind, OllamaGenerationPlan>
            {
                [EditorialContentKind.News] = Plan(),
            });

        Assert.Equal("qwen2.5:7b", policy.Select(EditorialContentKind.News).Model);
        var error = Assert.Throws<WorkerJobException>(() => policy.Select(EditorialContentKind.Article));
        Assert.Equal("ollama-model-policy-missing", error.Code);
    }

    [Fact]
    public void DraftIsSanitizedAndAlwaysPendingReview()
    {
        using var candidate = JsonDocument.Parse(
            "{\"title\":\"Titulo <b>seguro</b>\",\"excerpt\":\"Um resumo suficientemente longo para validar.\",\"paragraphs\":[\"**Texto** editorial\"]}");
        var draft = EditorialDraftBuilder.Build(
            candidate.RootElement,
            EditorialContentKind.News,
            "qwen2.5:7b",
            new string('b', 64),
            new string('c', 64));

        Assert.Equal("pending-editorial-review", draft.ReviewStatus);
        Assert.DoesNotContain('<', draft.Title);
        Assert.EndsWith("[S1]", draft.Paragraphs[0].Text);
    }

    private static OllamaGenerationPlan Plan() => new(
        "qwen2.5:7b",
        0.2,
        8_192,
        2_048,
        30,
        30,
        15,
        4);

    private sealed class StaticHandler(HttpStatusCode statusCode, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => Task.FromResult(new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/x-ndjson"),
            });
    }
}
