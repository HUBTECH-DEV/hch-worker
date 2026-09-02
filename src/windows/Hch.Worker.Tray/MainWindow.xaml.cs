using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using Hch.Worker.IPC.Contracts;
using Microsoft.Win32;

namespace Hch.Worker.Tray;

public partial class MainWindow : Window
{
    private readonly NamedPipeWorkerClient _client;
    private readonly WorkerOptionsViewModel _viewModel;
    private readonly DispatcherTimer _refreshTimer;
    private IReadOnlyList<SanitizedLogEntryPayload> _allLogs = [];
    private IReadOnlyList<SanitizedLogEntryPayload> _visibleLogs = [];
    private bool _allowClose;
    private bool _settingThemeSelector;
    private bool _updatingLogLevels;

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
        TrayThemeManager.ThemeChanged += ThemeManager_ThemeChanged;
        InitializeThemeSelector();
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
        TrayThemeManager.ThemeChanged -= ThemeManager_ThemeChanged;
        base.OnClosing(e);
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        _refreshTimer.Start();
        await _viewModel.RefreshAsync().ConfigureAwait(true);
        UpdateThemeStatus();
    }

    private async void RefreshTimer_Tick(object? sender, EventArgs e) =>
        _ = await _viewModel.TryRefreshAsync().ConfigureAwait(true);

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

    private async void Navigation_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Navigation.SelectedIndex == 5)
        {
            await LoadLogsAsync().ConfigureAwait(true);
        }
    }

    private void LogFilter_Changed(object sender, EventArgs e)
    {
        if (!_updatingLogLevels)
        {
            ApplyLogFilter();
        }
    }

    private void CopyLog_Click(object sender, RoutedEventArgs e)
    {
        if (LogsList.SelectedItems.Count == 0)
        {
            return;
        }

        try
        {
            string selected = string.Join(Environment.NewLine, LogsList.SelectedItems.Cast<string>());
            System.Windows.Clipboard.SetText(selected);
            _viewModel.ReportStatus($"{LogsList.SelectedItems.Count} entrada(s) copiada(s).");
        }
        catch (ExternalException)
        {
            _viewModel.ReportStatus("A área de transferência está ocupada. Tente novamente.");
        }
    }

    private async void ExportLog_Click(object sender, RoutedEventArgs e)
    {
        try
        {
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
                    JsonSerializer.Serialize(
                        new SanitizedLogsPayload(_visibleLogs),
                        new JsonSerializerOptions { WriteIndented = true }))
                    .ConfigureAwait(true);
                _viewModel.ReportStatus($"{_visibleLogs.Count} entrada(s) visível(is) exportada(s).");
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            System.Windows.MessageBox.Show(this, "Não foi possível exportar o diagnóstico sanitizado.", "Exportação", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
        }
    }

    private async Task LoadLogsAsync()
    {
        try
        {
            var logs = await _client.ReadSanitizedLogsAsync().ConfigureAwait(true);
            _allLogs = logs.Entries;
            UpdateLogLevels();
            ApplyLogFilter();
            _viewModel.ReportStatus($"{_allLogs.Count} entrada(s) sanitizada(s) recebida(s).");
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or TimeoutException or IpcContractException or WorkerControlClientException)
        {
            _allLogs = [];
            _visibleLogs = [];
            LogsList.ItemsSource = new[] { "Logs indisponíveis enquanto o serviço não responde." };
            LogCountText.Text = "Indisponível";
            _viewModel.ReportStatus("Logs indisponíveis enquanto o serviço não responde.");
        }
    }

    private void ApplyLogFilter()
    {
        if (LogsList is null || LogSearchInput is null || LogLevelFilter is null || LogCountText is null)
        {
            return;
        }

        string? level = (LogLevelFilter.SelectedItem as ComboBoxItem)?.Tag as string;
        _visibleLogs = TrayUiLogFilter.Apply(_allLogs, LogSearchInput.Text, level);
        LogsList.ItemsSource = _visibleLogs.Select(TrayUiLogFilter.DisplayText).ToArray();
        LogCountText.Text = $"{_visibleLogs.Count}/{_allLogs.Count}";
    }

    private void UpdateLogLevels()
    {
        string? selected = (LogLevelFilter.SelectedItem as ComboBoxItem)?.Tag as string;
        _updatingLogLevels = true;
        try
        {
            LogLevelFilter.Items.Clear();
            LogLevelFilter.Items.Add(new ComboBoxItem { Content = "Todos os níveis", Tag = string.Empty });
            foreach (string level in _allLogs.Select(entry => entry.Level).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.CurrentCultureIgnoreCase))
            {
                LogLevelFilter.Items.Add(new ComboBoxItem { Content = level, Tag = level });
            }

            LogLevelFilter.SelectedItem = LogLevelFilter.Items.Cast<ComboBoxItem>()
                .FirstOrDefault(item => string.Equals(item.Tag as string, selected, StringComparison.OrdinalIgnoreCase))
                ?? LogLevelFilter.Items[0];
        }
        finally
        {
            _updatingLogLevels = false;
        }
    }

    private void InitializeThemeSelector()
    {
        _settingThemeSelector = true;
        try
        {
            ThemeSelector.SelectedItem = ThemeSelector.Items.Cast<ComboBoxItem>()
                .First(item => string.Equals(item.Tag as string, TrayThemeManager.Preference.ToString(), StringComparison.Ordinal));
        }
        finally
        {
            _settingThemeSelector = false;
        }

        UpdateThemeStatus();
    }

    private void ThemeSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_settingThemeSelector
            || ThemeSelector.SelectedItem is not ComboBoxItem item
            || !Enum.TryParse(item.Tag as string, ignoreCase: false, out TrayThemePreference preference))
        {
            return;
        }

        TrayThemeManager.SetPreference(preference);
    }

    private void ThemeManager_ThemeChanged(object? sender, EventArgs e) => UpdateThemeStatus();

    private void UpdateThemeStatus()
    {
        if (ThemeStatusText is not null)
        {
            ThemeStatusText.Text = $"Em uso: {TrayThemeManager.ActiveThemeDescription}.";
        }
    }

    private async void Window_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            Hide();
            e.Handled = true;
            return;
        }

        if (e.Key == Key.F5)
        {
            if (Navigation.SelectedIndex == 5)
            {
                await LoadLogsAsync().ConfigureAwait(true);
            }
            else
            {
                await _viewModel.RefreshAsync().ConfigureAwait(true);
            }

            e.Handled = true;
            return;
        }

        if (e.Key == Key.F && Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
        {
            Navigation.SelectedIndex = 5;
            _ = LogSearchInput.Focus();
            e.Handled = true;
        }
    }
}
