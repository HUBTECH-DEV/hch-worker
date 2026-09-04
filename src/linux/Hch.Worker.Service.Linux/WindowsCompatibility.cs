using System.Net;
using System.Net.Sockets;
using Hch.Worker.Linux;
using Hch.Worker.Ollama;

// These adapters deliberately preserve the established Service source API so
// the Windows host remains unchanged while the platform-neutral seam is moved
// into a later refactor.
namespace Hch.Worker.Windows;

public sealed record WindowsServiceStatus(string State, bool Available, string? UnavailableReason = null);

public interface IWindowsServiceStateProvider
{
    WindowsServiceStatus Collect(string serviceName, int expectedProcessId);
}

public sealed class WindowsServiceStateProvider : IWindowsServiceStateProvider
{
    public static WindowsServiceStateProvider Instance { get; } = new();

    public WindowsServiceStatus Collect(string serviceName, int expectedProcessId)
    {
        var status = new LinuxServiceStateProvider().Collect(expectedProcessId);
        return new WindowsServiceStatus(status.State, true);
    }
}

public sealed record WindowsTelemetrySnapshot(
    DateTimeOffset CapturedAt,
    int ProcessId,
    double? ProcessCpuPercent,
    double? SystemCpuPercent,
    long? ProcessWorkingSetBytes,
    long? ProcessPeakWorkingSetBytes,
    ulong? TotalMemoryBytes,
    ulong? AvailableMemoryBytes,
    ulong? ProcessReadBytes,
    ulong? ProcessWriteBytes,
    long? NetworkReceivedBytes,
    long? NetworkSentBytes,
    double? GpuPercent,
    ulong? VramUsedBytes,
    string? GpuName = null,
    ulong? VramTotalBytes = null,
    int AuxiliaryProcessCount = 0);

public interface IAuxiliaryProcessCountProvider
{
    int Collect();
}

public sealed class WindowsTelemetryCollector : IDisposable
{
    private readonly LinuxTelemetryCollector inner = new();
    private readonly IAuxiliaryProcessCountProvider? auxiliary;

    public WindowsTelemetryCollector(IAuxiliaryProcessCountProvider? auxiliaryProcessProvider = null) =>
        auxiliary = auxiliaryProcessProvider;

    public WindowsTelemetrySnapshot Collect()
    {
        LinuxTelemetrySnapshot value = inner.CollectAsync(auxiliary?.Collect() ?? 0)
            .AsTask().GetAwaiter().GetResult();
        return new WindowsTelemetrySnapshot(
            value.CapturedAt, value.ProcessId, value.ProcessCpuPercent,
            value.SystemCpuPercent, value.ProcessWorkingSetBytes,
            value.ProcessPeakWorkingSetBytes, value.TotalMemoryBytes,
            value.AvailableMemoryBytes, value.ProcessReadBytes,
            value.ProcessWriteBytes, value.NetworkReceivedBytes,
            value.NetworkSentBytes, value.GpuPercent, value.VramUsedBytes,
            value.GpuName, value.VramTotalBytes, value.AuxiliaryProcessCount);
    }

    public void Dispose() => inner.Dispose();
}

public sealed class WindowsOllamaEndpointGuard : IOllamaEndpointGuard, IAuxiliaryProcessCountProvider
{
    private readonly Uri endpoint;
    private readonly LinuxOllamaEndpointGuard inner = new();

    public WindowsOllamaEndpointGuard(Uri ollamaBaseUri, string? ownerSid, string workerServiceName = "HchWorker") =>
        endpoint = ollamaBaseUri;

    public ValueTask EnsureTrustedAsync(Uri baseUri, CancellationToken cancellationToken) =>
        inner.EnsureTrustedAsync(baseUri, cancellationToken);

    public async ValueTask<Stream> ConnectAuthenticatedAsync(
        DnsEndPoint requested,
        CancellationToken cancellationToken)
    {
        if (!requested.Host.Equals(endpoint.Host, StringComparison.OrdinalIgnoreCase)
            || requested.Port != endpoint.Port)
        {
            throw new OllamaEndpointTrustException("ollama-endpoint-origin-mismatch");
        }

        await inner.EnsureTrustedAsync(endpoint, cancellationToken).ConfigureAwait(false);
        IPAddress[] addresses = await Dns.GetHostAddressesAsync(requested.Host, cancellationToken)
            .ConfigureAwait(false);
        IPAddress address = addresses.FirstOrDefault(IPAddress.IsLoopback)
            ?? throw new OllamaEndpointTrustException("ollama-endpoint-resolution-invalid");
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, requested.Port), cancellationToken)
                .ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public int Collect() => 0;
}

public sealed class WindowsLegacyWorkerCutoverGuard
{
    private readonly LinuxLegacyWorkerCutoverGuard inner;

    public WindowsLegacyWorkerCutoverGuard(string nodeId) => inner = new(nodeId);

    public async Task EnsureExclusiveAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await inner.EnsureExclusiveAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (LinuxLegacyWorkerCutoverException error)
        {
            throw new Hch.Worker.Core.WorkerControlException(error.Code, error.Message);
        }
    }
}
