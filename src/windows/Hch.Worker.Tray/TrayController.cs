using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Threading;
using Hch.Worker.IPC.Contracts;
using WinForms = System.Windows.Forms;

namespace Hch.Worker.Tray;

internal sealed class TrayController : IDisposable
{
    private readonly NamedPipeWorkerClient client;
    private readonly MainWindow optionsWindow;
    private readonly WinForms.NotifyIcon notifyIcon;
    private readonly WinForms.ToolStripMenuItem startItem;
    private readonly WinForms.ToolStripMenuItem pauseResumeItem;
    private readonly WinForms.ToolStripMenuItem stopItem;
    private readonly DispatcherTimer refreshTimer;
    private Icon? currentIcon;
    private WorkerSnapshotPayload? snapshot;
    private bool onboardingVisible;
    private bool disposed;

    public TrayController()
    {
        client = new NamedPipeWorkerClient(TrayConfiguration.ResolveNodeId());
        optionsWindow = new MainWindow(client);

        startItem = new WinForms.ToolStripMenuItem("Start", null, async (_, _) => await RunCommandAsync(client.StartAsync));
        pauseResumeItem = new WinForms.ToolStripMenuItem("Pause", null, async (_, _) => await PauseOrResumeAsync());
        stopItem = new WinForms.ToolStripMenuItem("Stop", null, async (_, _) => await StopAsync());
        var optionsItem = new WinForms.ToolStripMenuItem("Options", null, (_, _) => ShowOptions());
        var exitTrayItem = new WinForms.ToolStripMenuItem("Fechar somente o tray", null, (_, _) => ExitTray());

        var menu = new WinForms.ContextMenuStrip();
        menu.Items.AddRange([
            startItem,
            pauseResumeItem,
            stopItem,
            new WinForms.ToolStripSeparator(),
            optionsItem,
            new WinForms.ToolStripSeparator(),
            exitTrayItem,
        ]);

        notifyIcon = new WinForms.NotifyIcon
        {
            ContextMenuStrip = menu,
            Text = "HCH Worker · conectando",
            Visible = false,
        };
        notifyIcon.DoubleClick += (_, _) => ShowOptions();

        refreshTimer = new DispatcherTimer(
            TimeSpan.FromSeconds(5),
            DispatcherPriority.Background,
            async (_, _) => await RefreshAsync(),
            System.Windows.Application.Current.Dispatcher);
    }

    public async Task StartAsync()
    {
        ThrowIfDisposed();
        SetIcon(TrayGlyph.Attention, updateAvailable: false);
        notifyIcon.Visible = true;
        await RefreshAsync().ConfigureAwait(true);
        refreshTimer.Start();
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        refreshTimer.Stop();
        notifyIcon.Visible = false;
        notifyIcon.Dispose();
        currentIcon?.Dispose();
        optionsWindow.CloseForApplicationExit();
    }

    private async Task RefreshAsync()
    {
        try
        {
            snapshot = await client.GetSnapshotAsync().ConfigureAwait(true);
            UpdatePresentation(snapshot);
            if ((!snapshot.Ready || snapshot.TrustStatus is not "ready" and not "trusted") && !onboardingVisible)
            {
                _ = System.Windows.Application.Current.Dispatcher.BeginInvoke(ShowOnboarding);
            }
        }
        catch (Exception error) when (error is IOException or TimeoutException or IpcContractException or WorkerControlClientException)
        {
            snapshot = null;
            startItem.Enabled = false;
            pauseResumeItem.Enabled = false;
            stopItem.Enabled = false;
            notifyIcon.Text = "HCH Worker · serviço indisponível";
            SetIcon(TrayGlyph.Attention, updateAvailable: false);
        }
    }

    private void UpdatePresentation(WorkerSnapshotPayload value)
    {
        bool running = string.Equals(value.OperationalState, "Running", StringComparison.OrdinalIgnoreCase);
        bool paused = value.OperationalState is "Paused" or "Pausing";
        bool changing = value.OperationalState is "Stopping" or "Updating";

        startItem.Enabled = value.Ready && !running && !changing;
        pauseResumeItem.Text = running ? "Pause" : "Resume";
        pauseResumeItem.Enabled = value.Ready && (running || paused) && !changing;
        stopItem.Enabled = value.Ready && !changing && value.OperationalState is "Running" or "Pausing" or "Paused";

        TrayGlyph glyph = !value.Ready || value.ServiceState is not "Running"
            ? TrayGlyph.Attention
            : running
                ? TrayGlyph.Running
                : paused
                    ? TrayGlyph.Paused
                    : TrayGlyph.Stopped;
        SetIcon(glyph, value.UpdateAvailable);

        string heartbeat = value.LastHeartbeatAt is { } observed
            ? FormatAge(DateTimeOffset.UtcNow - observed)
            : "sem heartbeat";
        string tooltip = $"{value.WorkerName} · {value.OperationalState} · {value.ActiveJobs}/{value.GrantedCapacity} · {heartbeat}";
        notifyIcon.Text = tooltip.Length <= 63 ? tooltip : tooltip[..63];
    }

    private async Task PauseOrResumeAsync()
    {
        if (snapshot?.OperationalState is "Running")
        {
            await RunCommandAsync(client.PauseAsync).ConfigureAwait(true);
        }
        else
        {
            await RunCommandAsync(client.StartAsync).ConfigureAwait(true);
        }
    }

    private async Task StopAsync()
    {
        var answer = System.Windows.MessageBox.Show(
            optionsWindow.IsVisible ? optionsWindow : null,
            "Stop cancela os trabalhos ativos, relata operator-stop-requested ao orquestrador e aguarda reconciliação. Deseja continuar?",
            "Parar HCH Worker",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning,
            System.Windows.MessageBoxResult.No);
        if (answer == System.Windows.MessageBoxResult.Yes)
        {
            await RunCommandAsync(client.StopAsync).ConfigureAwait(true);
        }
    }

    private async Task RunCommandAsync(Func<CancellationToken, Task<CommandAcceptedPayload>> command)
    {
        startItem.Enabled = false;
        pauseResumeItem.Enabled = false;
        stopItem.Enabled = false;
        try
        {
            _ = await command(CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception error) when (error is IOException or TimeoutException or IpcContractException or WorkerControlClientException)
        {
            notifyIcon.ShowBalloonTip(
                4_000,
                "HCH Worker",
                "O serviço não aceitou o comando. Abra Options para consultar o estado sanitizado.",
                WinForms.ToolTipIcon.Warning);
        }
        finally
        {
            await RefreshAsync().ConfigureAwait(true);
        }
    }

    private void ShowOptions()
    {
        ThrowIfDisposed();
        if (!optionsWindow.IsVisible)
        {
            optionsWindow.Show();
        }

        if (optionsWindow.WindowState == System.Windows.WindowState.Minimized)
        {
            optionsWindow.WindowState = System.Windows.WindowState.Normal;
        }

        _ = optionsWindow.Activate();
    }

    private void ShowOnboarding()
    {
        if (disposed || onboardingVisible)
        {
            return;
        }

        ShowOptions();
        onboardingVisible = true;
        var onboarding = new OnboardingWindow(client)
        {
            Owner = optionsWindow,
        };
        onboarding.Closed += (_, _) => onboardingVisible = false;
        _ = onboarding.ShowDialog();
    }

    private void ExitTray()
    {
        Dispose();
        System.Windows.Application.Current.Shutdown();
    }

    private void SetIcon(TrayGlyph glyph, bool updateAvailable)
    {
        Icon next = TrayIconFactory.Create(glyph, updateAvailable);
        Icon? previous = currentIcon;
        currentIcon = next;
        notifyIcon.Icon = next;
        previous?.Dispose();
    }

    private static string FormatAge(TimeSpan age) => age.TotalSeconds < 60
        ? $"{Math.Max(0, (int)age.TotalSeconds)} s"
        : age.TotalMinutes < 60
            ? $"{(int)age.TotalMinutes} min"
            : $"{(int)age.TotalHours} h";

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed, this);
}

internal enum TrayGlyph
{
    Running,
    Paused,
    Stopped,
    Attention,
}

internal static class TrayIconFactory
{
    public static Icon Create(TrayGlyph glyph, bool updateAvailable)
    {
        using var bitmap = new Bitmap(32, 32, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        using (Graphics graphics = Graphics.FromImage(bitmap))
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.Clear(Color.Transparent);
            using var background = new SolidBrush(Color.FromArgb(21, 94, 239));
            graphics.FillRoundedRectangle(background, new RectangleF(2, 2, 28, 28), 7);

            using var mark = new SolidBrush(Color.White);
            switch (glyph)
            {
                case TrayGlyph.Running:
                    graphics.FillPolygon(mark, [new PointF(12, 9), new PointF(24, 16), new PointF(12, 23)]);
                    break;
                case TrayGlyph.Paused:
                    graphics.FillRectangle(mark, 10, 9, 4, 14);
                    graphics.FillRectangle(mark, 18, 9, 4, 14);
                    break;
                case TrayGlyph.Stopped:
                    graphics.FillRectangle(mark, 10, 10, 12, 12);
                    break;
                case TrayGlyph.Attention:
                    graphics.FillPolygon(mark, [new PointF(16, 7), new PointF(25, 24), new PointF(7, 24)]);
                    using (var ink = new SolidBrush(Color.FromArgb(21, 94, 239)))
                    {
                        graphics.FillRectangle(ink, 15, 12, 2, 7);
                        graphics.FillEllipse(ink, 15, 21, 2, 2);
                    }
                    break;
            }

            if (updateAvailable)
            {
                using var update = new SolidBrush(Color.FromArgb(255, 166, 0));
                using var outline = new Pen(Color.White, 1.5f);
                graphics.FillEllipse(update, 22, 1, 9, 9);
                graphics.DrawEllipse(outline, 22, 1, 9, 9);
            }
        }

        IntPtr handle = bitmap.GetHicon();
        try
        {
            using Icon borrowed = Icon.FromHandle(handle);
            return (Icon)borrowed.Clone();
        }
        finally
        {
            _ = DestroyIcon(handle);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);

    private static void FillRoundedRectangle(this Graphics graphics, Brush brush, RectangleF bounds, float radius)
    {
        using var path = new GraphicsPath();
        float diameter = radius * 2;
        path.AddArc(bounds.Left, bounds.Top, diameter, diameter, 180, 90);
        path.AddArc(bounds.Right - diameter, bounds.Top, diameter, diameter, 270, 90);
        path.AddArc(bounds.Right - diameter, bounds.Bottom - diameter, diameter, diameter, 0, 90);
        path.AddArc(bounds.Left, bounds.Bottom - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        graphics.FillPath(brush, path);
    }
}
