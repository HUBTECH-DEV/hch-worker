using Hch.Worker.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = Worker.ServiceName);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<WorkerRuntimeFactory>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
