using System.ComponentModel;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;

namespace Hch.Worker.Tray;

public partial class MainWindow : Window
{
    private readonly NamedPipeWorkerClient _client;
    private readonly WorkerOptionsViewModel _viewModel;
    private readonly DispatcherTimer _refreshTimer;
    private bool _allowClose;

    public MainWindow()
        : this(new NamedPipeWorkerClient(TrayConfiguration.ResolveNodeId()))
    {
    }

    public MainWindow(NamedPipeWorkerClient client)
    {
        _client = client;
        _viewModel = new WorkerOptionsViewModel(client);
        InitializeComponent();
        DataContext = _viewModel;
        _refreshTimer = new DispatcherTimer(TimeSpan.FromSeconds(2), DispatcherPriority.Background, RefreshTimer_Tick, Dispatcher);
        Loaded += MainWindow_Loaded;
    }

    public WorkerOptionsViewModel ViewModel => _viewModel;

    public void CloseForApplicationExit()
    {
        _allowClose = true;
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_allowClose)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        _refreshTimer.Stop();
        base.OnClosing(e);
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        _refreshTimer.Start();
        await _viewModel.RefreshAsync().ConfigureAwait(true);
    }

    private async void RefreshTimer_Tick(object? sender, EventArgs e) =>
        await _viewModel.RefreshAsync().ConfigureAwait(true);

    private async void Start_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.StartAsync().ConfigureAwait(true);

    private async void Pause_Click(object sender, RoutedEventArgs e) =>
        await _viewModel.PauseAsync().ConfigureAwait(true);

    private async void Stop_Click(object sender, RoutedEventArgs e)
    {
        var answer = System.Windows.MessageBox.Show(
            this,
            "Stop cancela os trabalhos ativos e relata operator-stop-requested ao orquestrador. Deseja continuar?",
            "Parar HCH Worker",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning,
            System.Windows.MessageBoxResult.No);
        if (answer == System.Windows.MessageBoxResult.Yes)
        {
            await _viewModel.StopAsync().ConfigureAwait(true);
        }
    }

    private void Onboarding_Click(object sender, RoutedEventArgs e)
    {
        var onboarding = new OnboardingWindow(_client)
        {
            Owner = this,
        };
        _ = onboarding.ShowDialog();
    }

    private async void ApplyParallelism_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(ParallelismInput.Text, out var value) || value is < 0 or > 64)
        {
            System.Windows.MessageBox.Show(this, "Informe um número entre 0 e 64.", "Paralelismo inválido", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            return;
        }

        await _viewModel.SetParallelismAsync(value).ConfigureAwait(true);
    }

    private async void ApplyBatch_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(BatchInput.Text, out var value) || value is < 1 or > 64)
        {
            System.Windows.MessageBox.Show(this, "Informe um número entre 1 e 64.", "Claim inválido", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            return;
        }

        await _viewModel.SetClaimBatchSizeAsync(value).ConfigureAwait(true);
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadLogsAsync().ConfigureAwait(true);

    private void CopyLog_Click(object sender, RoutedEventArgs e)
    {
        if (LogsList.SelectedItem is string selected)
        {
            System.Windows.Clipboard.SetText(selected);
        }
    }

    private async void ExportLog_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var logs = await _client.ReadSanitizedLogsAsync().ConfigureAwait(true);
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Exportar diagnóstico sanitizado",
                FileName = $"hch-worker-diagnostic-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.json",
                DefaultExt = ".json",
                Filter = "JSON (*.json)|*.json",
                AddExtension = true,
            };
            if (dialog.ShowDialog(this) == true)
            {
                await File.WriteAllTextAsync(
                    dialog.FileName,
                    JsonSerializer.Serialize(logs, new JsonSerializerOptions { WriteIndented = true }))
                    .ConfigureAwait(true);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or TimeoutException)
        {
            System.Windows.MessageBox.Show(this, "Não foi possível exportar o diagnóstico sanitizado.", "Exportação", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
        }
    }

    private async Task LoadLogsAsync()
    {
        try
        {
            var logs = await _client.ReadSanitizedLogsAsync().ConfigureAwait(true);
            LogsList.Items.Clear();
            foreach (var entry in logs.Entries)
            {
                LogsList.Items.Add($"{entry.Timestamp:O} [{entry.Level}] {entry.EventCode}: {entry.Message}");
            }
        }
        catch (Exception error) when (error is IOException or TimeoutException)
        {
            LogsList.Items.Clear();
            LogsList.Items.Add("Logs indisponíveis enquanto o serviço não responde.");
        }
    }
}
