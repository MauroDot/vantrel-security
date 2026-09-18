using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;

namespace Vantrel.Security.Desktop;

public partial class App : Application
{
    private IHost? _host;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        try
        {
            var builder = Host.CreateApplicationBuilder(e.Args);
            builder.Services.AddSingleton<ISecurityServiceStatusClient, NamedPipeStatusClient>();
            builder.Services.AddSingleton<ISystemHealthClient>(services =>
                (ISystemHealthClient)services.GetRequiredService<ISecurityServiceStatusClient>());
            builder.Services.AddSingleton<IActivityClient>(services =>
                (IActivityClient)services.GetRequiredService<ISecurityServiceStatusClient>());
            builder.Services.AddSingleton<IScanCapabilityClient>(services =>
                (IScanCapabilityClient)services.GetRequiredService<ISecurityServiceStatusClient>());
            builder.Services.AddSingleton<IComponentInspectionClient>(services =>
                (IComponentInspectionClient)services.GetRequiredService<ISecurityServiceStatusClient>());
            builder.Services.AddSingleton<IComponentIntegrityClient>(services =>
                (IComponentIntegrityClient)services.GetRequiredService<ISecurityServiceStatusClient>());
            builder.Services.AddSingleton<MainWindow>();
            _host = builder.Build();
            await _host.StartAsync();
            _host.Services.GetRequiredService<ILogger<App>>().LogInformation("Desktop application started");
            MainWindow = _host.Services.GetRequiredService<MainWindow>();
            MainWindow.Show();
        }
        catch (Exception error)
        {
            MessageBox.Show($"Vantrel Security could not start: {error.Message}", "Startup error",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_host is not null)
        {
            _host.StopAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
            _host.Dispose();
        }
        base.OnExit(e);
    }
}
