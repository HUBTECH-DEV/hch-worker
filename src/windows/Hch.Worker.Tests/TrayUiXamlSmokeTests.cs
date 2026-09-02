using Hch.Worker.Tray;

namespace Hch.Worker.Tests;

public sealed class TrayUiXamlSmokeTests
{
    [Fact]
    public void Windows_LoadResourcesAndMeasureAtMinimumSupportedSize()
    {
        Exception? failure = null;
        var completed = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            App? application = null;
            MainWindow? mainWindow = null;
            OnboardingWindow? onboardingWindow = null;
            try
            {
                application = new App();
                application.InitializeComponent();

                mainWindow = new MainWindow();
                Measure(mainWindow, 680, 520);

                onboardingWindow = new OnboardingWindow(new NamedPipeWorkerClient("ui-smoke-node"));
                Measure(onboardingWindow, 640, 520);
            }
            catch (Exception error)
            {
                failure = error;
            }
            finally
            {
                onboardingWindow?.Close();
                mainWindow?.CloseForApplicationExit();
                application?.Shutdown();
                completed.Set();
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        Assert.True(completed.Wait(TimeSpan.FromSeconds(15)), "WPF UI smoke test timed out.");
        thread.Join();
        Assert.Null(failure);
    }

    private static void Measure(System.Windows.Window window, double width, double height)
    {
        var size = new System.Windows.Size(width, height);
        var content = Assert.IsAssignableFrom<System.Windows.FrameworkElement>(window.Content);
        content.Measure(size);
        content.Arrange(new System.Windows.Rect(size));
        content.UpdateLayout();

        Assert.True(content.DesiredSize.Width > 0);
        Assert.True(content.DesiredSize.Height > 0);
    }
}
