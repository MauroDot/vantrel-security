using Vantrel.Security.Service;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging.EventLog;
using Vantrel.Security.Core;

var builder = Host.CreateApplicationBuilder(args);
var isWindowsService = OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService();
if (isWindowsService) builder.Services.AddSingleton<IHostLifetime>(provider => new RecoveryWindowsServiceLifetime(
    provider.GetRequiredService<IHostApplicationLifetime>(), provider.GetRequiredService<RecoveryStartupAdmission>(), StatusProtocol.ServiceName));
builder.Logging.ClearProviders();
if (isWindowsService)
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
builder.Services.AddSingleton<ComponentIntegrityStore>();
builder.Services.AddSingleton<TrustedManifestIntegrityStore>();
builder.Services.AddSingleton<TrustedManifestIntegrityHistoryStore>();
builder.Services.AddSingleton<ReleasePolicyStore>();
builder.Services.AddSingleton<ReleaseProvenanceStore>();
builder.Services.AddSingleton<UpdateTransactionStore>();
builder.Services.AddSingleton<UpdateTransactionJournalStore>();
builder.Services.AddSingleton<ScmRecoveryStartArgumentSource>();
builder.Services.AddSingleton<IRecoveryStartArgumentSource>(provider => provider.GetRequiredService<ScmRecoveryStartArgumentSource>());
builder.Services.AddSingleton<RecoveryStartupAdmission>();
builder.Services.AddSingleton<CommandAuditStore>();
builder.Services.AddSingleton<CommandRequestRegistry>();
builder.Services.AddSingleton<CommandRejectionLogLimiter>();
builder.Services.AddSingleton<ScanCapabilitySource>();
builder.Services.AddSingleton<ComponentInspectionSource>();
builder.Services.AddSingleton<ComponentIntegritySource>();
builder.Services.AddSingleton<TrustedManifestIntegritySource>();
builder.Services.AddSingleton<ReleaseProvenanceSource>();
builder.Services.AddSingleton<TrustedManifestRefreshCoordinator>();
builder.Services.AddSingleton<Vantrel.Security.Infrastructure.WindowsSecurityCenterHealthSource>();
builder.Services.AddSingleton<WindowsSystemHealthSource>();
builder.Services.AddHostedService<HeartbeatWorker>();
builder.Services.AddHostedService<SystemHealthWorker>();
builder.Services.AddHostedService<ScanCapabilityWorker>();
builder.Services.AddHostedService<ComponentInspectionWorker>();
builder.Services.AddHostedService<ComponentIntegrityWorker>();
builder.Services.AddHostedService<TrustedManifestIntegrityWorker>();
builder.Services.AddHostedService<ReleaseProvenanceWorker>();
builder.Services.AddHostedService<UpdateTransactionStatusWorker>();
builder.Services.AddHostedService<UpdateTransactionPolicyCommitWorker>();
builder.Services.AddHostedService<CommandPipeWorker>();
builder.Services.AddHostedService<StatusPipeWorker>();

var host = builder.Build();
await host.RunAsync();
