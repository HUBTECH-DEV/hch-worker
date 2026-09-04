using Hch.Worker.Service;

if (!OperatingSystem.IsLinux())
{
    throw new PlatformNotSupportedException("hch-worker-linux-host-required");
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<WorkerRuntimeFactory>();
builder.Services.AddHostedService<Worker>();

await builder.Build().RunAsync().ConfigureAwait(false);
