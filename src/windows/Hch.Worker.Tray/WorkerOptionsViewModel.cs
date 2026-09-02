using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using Hch.Worker.IPC.Contracts;

namespace Hch.Worker.Tray;

public sealed class WorkerOptionsViewModel(NamedPipeWorkerClient client) : INotifyPropertyChanged
{
    private WorkerSnapshotPayload? _snapshot;
    private string _statusMessage = "Conectando ao serviço…";
    private bool _busy;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<JobProgressView> ActiveWork { get; } = [];

    public WorkerSnapshotPayload? Snapshot
    {
        get => _snapshot;
        private set
        {
            _snapshot = value;
            OnPropertyChanged();
            NotifyDerivedProperties();
        }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set { _statusMessage = value; OnPropertyChanged(); }
    }

    public bool Busy
    {
        get => _busy;
        private set { _busy = value; OnPropertyChanged(); NotifyDerivedProperties(); }
    }

    public string WorkerTitle => Snapshot is null ? "HCH Worker" : Snapshot.WorkerName;
    public string VersionText => Snapshot is null ? "versão 4.0.0" : $"versão {Snapshot.InstalledVersion}";
    public string StateText => Snapshot?.OperationalState ?? "Não disponível";
    public string ServiceText => Snapshot?.ServiceState ?? "Não disponível";
    public string CapacityText => Snapshot is null
        ? "—"
        : $"{Snapshot.ActiveJobs}/{Snapshot.GrantedCapacity}";
    public string CapacityDetail => Snapshot is null
        ? "Solicitada — · livre —"
        : $"Solicitada {Snapshot.MaxConcurrentJobs} · concedida {Snapshot.GrantedCapacity} · livre {Snapshot.AvailableSlots}";
    public string QueueText => Snapshot?.QueueDepth.ToString(CultureInfo.InvariantCulture) ?? "—";
    public string CompletedText => Snapshot?.CompletedJobs.ToString(CultureInfo.InvariantCulture) ?? "—";
    public string FailedText => Snapshot?.FailedJobs.ToString(CultureInfo.InvariantCulture) ?? "—";
    public string RetryText => Snapshot?.RetryJobs.ToString(CultureInfo.InvariantCulture) ?? "—";
    public string WorkerCpuText => Metric(Snapshot?.Resources.WorkerCpuPercent, "%", "F1");
    public string SystemCpuText => Metric(Snapshot?.Resources.SystemCpuPercent, "%", "F1");
    public string MemoryText => Bytes(Snapshot?.Resources.WorkingSetBytes);
    public string AverageMemoryText => Bytes(Snapshot?.Resources.AverageWorkingSetBytes);
    public string PeakMemoryText => Bytes(Snapshot?.Resources.PeakWorkingSetBytes);
    public string GpuText => Metric(Snapshot?.Resources.GpuPercent, "%", "F1");
    public string VramText => Bytes(Snapshot?.Resources.VramUsedBytes);
    public string NetworkText => Snapshot is null
        ? "Não disponível"
        : $"↓ {Bytes(Snapshot.Resources.NetworkReceivedBytes)}  ↑ {Bytes(Snapshot.Resources.NetworkSentBytes)}";
    public string DiskText => Snapshot is null
        ? "Não disponível"
        : $"L {Bytes(Snapshot.Resources.DiskReadBytes)}  E {Bytes(Snapshot.Resources.DiskWrittenBytes)}";
    public string UptimeText => Snapshot is null
        ? "Não disponível"
        : TimeSpan.FromSeconds(Snapshot.Resources.UptimeSeconds).ToString("d'.'hh':'mm':'ss", CultureInfo.InvariantCulture);
    public string OllamaText => Snapshot is null
        ? "Não disponível"
        : Snapshot.OllamaAvailable
            ? $"Disponível · {Snapshot.OllamaModel ?? "modelo não informado"}"
            : "Não disponível";
    public string HeartbeatText => Snapshot?.LastHeartbeatAt is { } heartbeat
        ? $"{FormatAge(DateTimeOffset.UtcNow - heartbeat)} atrás"
        : "Não recebido";
    public string LatencyText => Snapshot?.OrchestratorLatencyMilliseconds is { } latency
        ? $"{latency} ms"
        : "Não disponível";
    public string TrustText => Snapshot?.TrustStatus ?? "Não disponível";
    public string ManifestText => Snapshot is null
        ? "Não disponível"
        : $"{Snapshot.ManifestStatus} · sequência {Snapshot.ManifestSequence?.ToString(CultureInfo.InvariantCulture) ?? "—"}";
    public string UpdateText => Snapshot is null
        ? "Não disponível"
        : Snapshot.UpdateAvailable
            ? Snapshot.UpdateCompatible
                ? $"{Snapshot.AvailableVersion} disponível · compatível"
                : $"{Snapshot.AvailableVersion} disponível · requer parada"
            : "Atualizado";
    public string ServicesText => "1 serviço Windows instalado";
    public string ProcessesText => Snapshot is null
        ? "N processos auxiliares ativos"
        : $"{Snapshot.Resources.AuxiliaryProcessCount} processos auxiliares ativos";
    public string JobsText => Snapshot is null
        ? "X/Y trabalhos em execução"
        : $"{Snapshot.ActiveJobs}/{Snapshot.GrantedCapacity} trabalhos em execução";
    public bool CanStart => !Busy && Snapshot is { Ready: true } &&
        Snapshot.OperationalState is not "Running" and not "Stopping" and not "Updating";
    public bool CanPause => !Busy && Snapshot?.OperationalState is "Running";
    public bool CanStop => !Busy && Snapshot?.OperationalState is "Running" or "Pausing" or "Paused";
    public bool NeedsOnboarding => Snapshot is null || !Snapshot.Ready ||
        Snapshot.TrustStatus is not "ready" and not "trusted";

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var snapshot = await client.GetSnapshotAsync(cancellationToken).ConfigureAwait(true);
            Snapshot = snapshot;
            ReplaceActiveWork(snapshot.ActiveWork);
            StatusMessage = snapshot.LastSanitizedErrorCode is null
                ? "Estado sincronizado com o serviço."
                : $"Atenção: {snapshot.LastSanitizedErrorCode}";
        }
        catch (Exception error) when (error is IOException or TimeoutException or IpcContractException or WorkerControlClientException)
        {
            StatusMessage = "Serviço indisponível. O tray permanece aberto e tentará novamente.";
        }
    }

    public Task StartAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync(token => client.StartAsync(token), "Worker iniciado.", cancellationToken);

    public Task PauseAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync(token => client.PauseAsync(token), "Pausa solicitada; trabalhos ativos continuarão.", cancellationToken);

    public Task StopAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync(token => client.StopAsync(token), "Parada solicitada e sendo reconciliada.", cancellationToken);

    public Task SetParallelismAsync(int value, CancellationToken cancellationToken = default) =>
        ExecuteAsync(token => client.SetMaxConcurrentJobsAsync(value, token),
            value == 0 ? "Paralelismo zero: Worker pausado." : $"Paralelismo solicitado: {value}.",
            cancellationToken);

    public Task SetClaimBatchSizeAsync(int value, CancellationToken cancellationToken = default) =>
        ExecuteAsync(token => client.SetClaimBatchSizeAsync(value, token),
            $"Tamanho máximo de claim definido como {value}.", cancellationToken);

    private async Task ExecuteAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        string successMessage,
        CancellationToken cancellationToken)
    {
        Busy = true;
        try
        {
            _ = await operation(cancellationToken).ConfigureAwait(true);
            StatusMessage = successMessage;
            await RefreshAsync(cancellationToken).ConfigureAwait(true);
        }
        catch (WorkerControlClientException error)
        {
            StatusMessage = $"Comando recusado: {error.Code}";
        }
        catch (Exception error) when (error is IOException or TimeoutException or IpcContractException)
        {
            StatusMessage = "Não foi possível comunicar com o serviço.";
        }
        finally
        {
            Busy = false;
        }
    }

    private void ReplaceActiveWork(IReadOnlyList<JobProgressPayload> values)
    {
        ActiveWork.Clear();
        foreach (var value in values)
        {
            ActiveWork.Add(new JobProgressView(value));
        }
    }

    private static string Metric(MetricPayload<double>? metric, string suffix, string format) =>
        metric is { Available: true, Value: { } value }
            ? value.ToString(format, CultureInfo.CurrentCulture) + suffix
            : "Não disponível";

    private static string Bytes(MetricPayload<long>? metric) => metric is { Available: true, Value: { } value }
        ? FormatBytes(value)
        : "Não disponível";

    private static string FormatBytes(long value)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
        var size = Math.Max(0, value);
        var unit = 0;
        var display = (double)size;
        while (display >= 1024 && unit < units.Length - 1)
        {
            display /= 1024;
            unit++;
        }

        return $"{display:F1} {units[unit]}";
    }

    private static string FormatAge(TimeSpan age) => age.TotalSeconds < 60
        ? $"{Math.Max(0, (int)age.TotalSeconds)} s"
        : age.TotalMinutes < 60
            ? $"{(int)age.TotalMinutes} min"
            : $"{(int)age.TotalHours} h";

    private void NotifyDerivedProperties()
    {
        foreach (var property in new[]
        {
            nameof(WorkerTitle), nameof(VersionText), nameof(StateText), nameof(ServiceText),
            nameof(CapacityText), nameof(CapacityDetail), nameof(QueueText), nameof(CompletedText),
            nameof(FailedText), nameof(RetryText), nameof(WorkerCpuText), nameof(SystemCpuText),
            nameof(MemoryText), nameof(AverageMemoryText), nameof(PeakMemoryText), nameof(GpuText),
            nameof(VramText), nameof(NetworkText), nameof(DiskText), nameof(UptimeText), nameof(OllamaText),
            nameof(HeartbeatText), nameof(LatencyText), nameof(TrustText), nameof(ManifestText),
            nameof(UpdateText), nameof(ServicesText), nameof(ProcessesText), nameof(JobsText),
            nameof(CanStart), nameof(CanPause), nameof(CanStop), nameof(NeedsOnboarding),
        })
        {
            OnPropertyChanged(property);
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public sealed record JobProgressView(JobProgressPayload Value)
{
    public string AssignmentId => Value.AssignmentId;
    public string Phase => Value.Phase;
    public int Attempt => Value.Attempt;
    public long ContentBytes => Value.ContentBytes;
    public double ItemPercent => Math.Clamp(Value.Percent ?? 0, 0, 100);
    public string ItemPercentText => Value.Percent is { } percent ? $"{percent:F0}%" : "—";
    public double BatchPercent => Value.BatchTotal > 0
        ? Math.Clamp(Value.ItemIndex * 100d / Value.BatchTotal, 0, 100)
        : 0;
    public string BatchText => Value.BatchTotal > 0
        ? $"{Value.ItemIndex}/{Value.BatchTotal}"
        : "—/—";
}
