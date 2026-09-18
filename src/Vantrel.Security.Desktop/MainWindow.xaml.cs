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
    private readonly ISystemHealthClient _healthClient;
    private readonly ILogger<MainWindow> _logger;
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(10) };
    private CancellationTokenSource? _refreshCancellation;

    public MainWindow(ISecurityServiceStatusClient client, ISystemHealthClient healthClient,
        ILogger<MainWindow> logger)
    {
        _client = client;
        _healthClient = healthClient;
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
            if (SystemHealthPanel.Visibility == Visibility.Visible)
            {
                var health = status is null ? null : await _healthClient.GetSystemHealthAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderSystemHealth(health, status is not null);
            }
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
            if (SystemHealthPanel.Visibility == Visibility.Visible) RenderSystemHealth(null, false);
            _logger.LogError(error, "Unexpected service status error");
        }
    }

    private void RenderSystemHealth(SystemHealthSnapshot? health, bool connected)
    {
        var state = SystemHealthPresentation.State(health, connected, DateTimeOffset.UtcNow);
        HealthStateText.Text = state switch
        {
            SystemHealthDisplayState.Disconnected => "Disconnected — service unavailable",
            SystemHealthDisplayState.Unavailable => "Unavailable — no health sample",
            SystemHealthDisplayState.Stale => "Stale — last sample is over two minutes old",
            SystemHealthDisplayState.Partial => "Partial data — some values unavailable",
            _ => "Current sample"
        };
        var diagnostic = (_client as IStatusConnectionDiagnostics)?.LastDiagnostic;
        HealthDiagnosticText.Text = diagnostic is null ? string.Empty : $"Connection detail: {diagnostic}";
        HealthDiagnosticText.Visibility =
            (state is SystemHealthDisplayState.Disconnected or SystemHealthDisplayState.Unavailable) &&
            diagnostic is not null
            ? Visibility.Visible : Visibility.Collapsed;
        // Never show old values as current after a service disconnect.
        var visible = connected ? health : null;
        HealthSampleText.Text = visible is null ? "Sample: unavailable" :
            $"Sample: {visible.CollectedAtUtc.ToLocalTime():g}";
        HealthWindowsText.Text = $"Windows version/build: {visible?.WindowsVersion ?? "Unavailable"}";
        HealthUptimeText.Text = visible?.SystemUptimeSeconds is long seconds
            ? $"Elapsed since system start: {seconds / 86400}d {(seconds % 86400) / 3600}h {(seconds % 3600) / 60}m"
            : "Elapsed since system start: Unavailable";
        HealthDiskText.Text = visible?.SystemVolumeTotalBytes is long total &&
            visible.SystemVolumeFreeBytes is long free
            ? $"Windows system volume: {free / 1073741824d:F1} GiB free of {total / 1073741824d:F1} GiB"
            : "Windows system volume: Unavailable";
    }

    private async void NavigationChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SectionList.SelectedItem is not ListBoxItem item || SectionTitle is null) return;
        var section = item.Content?.ToString() ?? "Dashboard";
        SectionTitle.Text = section;
        DashboardPanel.Visibility = section == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        SystemHealthPanel.Visibility = section == "System Health" ? Visibility.Visible : Visibility.Collapsed;
        PlaceholderPanel.Visibility = section is "Dashboard" or "System Health" ? Visibility.Collapsed : Visibility.Visible;
        PlaceholderText.Text = $"{section} will be available in a future release.";
        if (section == "System Health") await RefreshStatusAsync();
    }
}
