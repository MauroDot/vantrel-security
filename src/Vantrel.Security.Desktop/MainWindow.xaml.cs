using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Extensions.Logging;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;

namespace Vantrel.Security.Desktop;

public partial class MainWindow : Window
{
    private readonly ISecurityServiceStatusClient _client;
    private readonly ILogger<MainWindow> _logger;
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(10) };
    private CancellationTokenSource? _refreshCancellation;

    public MainWindow(ISecurityServiceStatusClient client, ILogger<MainWindow> logger)
    {
        _client = client;
        _logger = logger;
        InitializeComponent();
        VersionText.Text = typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "Unknown";
        _refreshTimer.Tick += async (_, _) => await RefreshStatusAsync();
        Loaded += async (_, _) =>
        {
            _refreshTimer.Start();
            await RefreshStatusAsync();
        };
        Closed += (_, _) =>
        {
            _refreshTimer.Stop();
            _refreshCancellation?.Cancel();
        };
    }

    private async Task RefreshStatusAsync()
    {
        _refreshCancellation?.Cancel();
        _refreshCancellation?.Dispose();
        var cancellation = new CancellationTokenSource();
        _refreshCancellation = cancellation;
        try
        {
            var status = await _client.GetStatusAsync(cancellation.Token);
            if (cancellation.IsCancellationRequested) return;
            ServiceStatusText.Text = status is null ? "Disconnected" : "Connected";
            ServiceVersionText.Text = status is null ? "Service version: —" : $"Service version: {status.Version}";
            ProtectionStatusText.Text = status?.Protection == ProtectionState.Protected ? "Protected" : "Unavailable";
            HeartbeatText.Text = status is null
                ? "Heartbeat unavailable until the status connection succeeds."
                : $"Last heartbeat: {status.HeartbeatAtUtc.ToLocalTime():g}  ·  Uptime: {status.UptimeAt(DateTimeOffset.UtcNow):hh\\:mm\\:ss}";
            var diagnostic = (_client as IStatusConnectionDiagnostics)?.LastDiagnostic;
            ServiceDiagnosticText.Text = status is null && diagnostic is not null
                ? $"Connection detail: {diagnostic}" : string.Empty;
            ServiceDiagnosticText.Visibility = status is null && diagnostic is not null
                ? Visibility.Visible : Visibility.Collapsed;
            _logger.LogInformation("Service status query completed: {Connected}", status is not null);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception error)
        {
            ServiceStatusText.Text = "Disconnected";
            ServiceVersionText.Text = "Service version: —";
            ProtectionStatusText.Text = "Unavailable";
            HeartbeatText.Text = "Status could not be read.";
            ServiceDiagnosticText.Text = $"Connection detail: UnexpectedFailure at DesktopRefresh; exception={error.GetType().FullName}; HRESULT={error.HResult:X8}";
            ServiceDiagnosticText.Visibility = Visibility.Visible;
            _logger.LogError(error, "Unexpected service status error");
        }
    }

    private void NavigationChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SectionList.SelectedItem is not ListBoxItem item || SectionTitle is null) return;
        var section = item.Content?.ToString() ?? "Dashboard";
        SectionTitle.Text = section;
        DashboardPanel.Visibility = section == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        PlaceholderPanel.Visibility = section == "Dashboard" ? Visibility.Collapsed : Visibility.Visible;
        PlaceholderText.Text = $"{section} will be available in a future release.";
    }
}
