using Vantrel.Security.Service;
using Microsoft.Extensions.Hosting.WindowsServices;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "Vantrel Security");
if (!WindowsServiceHelpers.IsWindowsService())
{
    builder.Logging.ClearProviders();
    builder.Logging.AddConsole();
}
builder.Services.AddSingleton<ServiceStatusStore>();
builder.Services.AddHostedService<HeartbeatWorker>();
builder.Services.AddHostedService<StatusPipeWorker>();

var host = builder.Build();
await host.RunAsync();
