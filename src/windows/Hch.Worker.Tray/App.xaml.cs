using System.Security.Principal;

namespace Hch.Worker.Tray;

public partial class App : System.Windows.Application
{
    private Mutex? _singleInstance;
    private TrayController? _controller;

    protected override async void OnStartup(System.Windows.StartupEventArgs e)
    {
        base.OnStartup(e);
        var sid = WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName;
        var mutexName = $"Local\\Hch.Worker.Tray.v4-{sid.Replace('\\', '-')}";
        _singleInstance = new Mutex(initiallyOwned: true, mutexName, out var created);
        if (!created)
        {
            Shutdown();
            return;
        }

        _controller = new TrayController();
        await _controller.StartAsync().ConfigureAwait(true);
    }

    protected override void OnExit(System.Windows.ExitEventArgs e)
    {
        _controller?.Dispose();
        _singleInstance?.Dispose();
        base.OnExit(e);
    }
}
