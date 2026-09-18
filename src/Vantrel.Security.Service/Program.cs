using Vantrel.Security.Service;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging.EventLog;
using Vantrel.Security.Core;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = StatusProtocol.ServiceName);
builder.Logging.ClearProviders();
if (OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService())
{
    builder.Logging.AddEventLog(settings =>
    {
        settings.LogName = "Application";
        settings.SourceName = StatusProtocol.ServiceName;
    });
    builder.Logging.AddFilter<EventLogLoggerProvider>(null, LogLevel.Information);
}
else
{
    builder.Logging.AddConsole();
}
builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(5));
builder.Services.AddSingleton<ServiceStatusStore>();
builder.Services.AddSingleton<SystemHealthStore>();
builder.Services.AddSingleton<ActivityStore>();
builder.Services.AddSingleton<ScanCapabilityStore>();
builder.Services.AddSingleton<ComponentInspectionStore>();
builder.Services.AddSingleton<ScanCapabilitySource>();
builder.Services.AddSingleton<ComponentInspectionSource>();
builder.Services.AddSingleton<Vantrel.Security.Infrastructure.WindowsSecurityCenterHealthSource>();
builder.Services.AddSingleton<WindowsSystemHealthSource>();
builder.Services.AddHostedService<HeartbeatWorker>();
builder.Services.AddHostedService<SystemHealthWorker>();
builder.Services.AddHostedService<ScanCapabilityWorker>();
builder.Services.AddHostedService<ComponentInspectionWorker>();
builder.Services.AddHostedService<StatusPipeWorker>();

var host = builder.Build();
await host.RunAsync();
