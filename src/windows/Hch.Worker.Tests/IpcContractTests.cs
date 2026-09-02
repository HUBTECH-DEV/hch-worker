using System.Text.Json;
using Hch.Worker.IPC.Contracts;

namespace Hch.Worker.Tests;

public sealed class IpcContractTests
{
    [Fact]
    public void PipeNameRejectsFreeFormPaths()
    {
        Assert.Equal("Hch.Worker.Control.v2.node-01", IpcProtocol.PipeName("node-01"));
        Assert.Throws<ArgumentException>(() => IpcProtocol.PipeName("node/../../pipe"));
        Assert.Throws<ArgumentException>(() => IpcProtocol.PipeName("node with spaces"));
    }

    [Fact]
    public async Task FramingRoundTripsOneBoundedMessage()
    {
        await using var stream = new MemoryStream();
        var request = IpcRequest.Create(IpcCommand.Pause, EmptyPayload.Value);
        await IpcFraming.WriteAsync(stream, request);
        stream.Position = 0;

        var restored = await IpcFraming.ReadAsync<IpcRequest>(stream);

        Assert.Equal(request.RequestId, restored.RequestId);
        Assert.Equal(IpcCommand.Pause, restored.Command);
    }

    [Fact]
    public async Task FramingRejectsOversizedDeclaredLengthBeforeAllocation()
    {
        await using var stream = new MemoryStream(BitConverter.GetBytes(IpcProtocol.MaximumFrameBytes + 1));
        var error = await Assert.ThrowsAsync<IpcContractException>(() =>
            IpcFraming.ReadAsync<IpcRequest>(stream));
        Assert.Equal("ipc-frame-size-invalid", error.Code);
    }

    [Fact]
    public void UnknownPayloadFieldsAreRejected()
    {
        var payload = JsonSerializer.Deserialize<JsonElement>("""
            {"value":4,"script":"malicious.ps1"}
            """);

        var error = Assert.Throws<IpcContractException>(() =>
            IpcValidation.Payload<SetMaxConcurrentJobsPayload>(payload));
        Assert.Equal("ipc-payload-invalid", error.Code);
    }

    [Fact]
    public void RequestRequiresCurrentVersionUuidAndBoundedTimestamp()
    {
        var now = DateTimeOffset.Parse("2026-09-01T12:00:00Z");
        var valid = IpcRequest.Create(IpcCommand.Start, EmptyPayload.Value, now);
        Assert.Same(valid, IpcValidation.Request(valid, now));

        var wrongVersion = valid with { Version = 1 };
        Assert.Equal(
            "ipc-version-unsupported",
            Assert.Throws<IpcContractException>(() => IpcValidation.Request(wrongVersion, now)).Code);

        var expired = valid with { CreatedAt = now.AddMinutes(-6) };
        Assert.Equal(
            "ipc-request-expired",
            Assert.Throws<IpcContractException>(() => IpcValidation.Request(expired, now)).Code);
    }

    [Fact]
    public void ContractContainsNoPasswordPrivateKeyOrShellFields()
    {
        var contractTypes = typeof(IpcRequest).Assembly.GetExportedTypes();
        var forbidden = new[] { "password", "privatekey", "shell", "scriptpath", "executable" };
        foreach (var property in contractTypes.SelectMany(static type => type.GetProperties()))
        {
            Assert.DoesNotContain(
                forbidden,
                value => property.Name.Contains(value, StringComparison.OrdinalIgnoreCase));
        }
    }
}
