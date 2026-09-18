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
    private readonly IActivityClient _activityClient;
    private readonly IScanCapabilityClient _scanCapabilityClient;
    private readonly ILogger<MainWindow> _logger;
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(10) };
    private CancellationTokenSource? _refreshCancellation;
    private bool _activityWasDisconnected;
    private bool _scanWasDisconnected;

    public MainWindow(ISecurityServiceStatusClient client, ISystemHealthClient healthClient,
        IActivityClient activityClient, IScanCapabilityClient scanCapabilityClient,
        ILogger<MainWindow> logger)
    {
        _client = client;
        _healthClient = healthClient;
        _activityClient = activityClient;
        _scanCapabilityClient = scanCapabilityClient;
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
            if (status is null) _activityWasDisconnected = true;
            if (ActivityPanel.Visibility == Visibility.Visible)
            {
                var activity = status is null ? null : await _activityClient.GetActivityAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderActivity(activity, status is not null);
            }
            if (status is null) _scanWasDisconnected = true;
            if (ScanPanel.Visibility == Visibility.Visible)
            {
                var capability = status is null ? null :
                    await _scanCapabilityClient.GetScanCapabilityAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderScanCapability(capability, status is not null);
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
            _activityWasDisconnected = true;
            if (ActivityPanel.Visibility == Visibility.Visible) RenderActivity(null, false);
            _scanWasDisconnected = true;
            if (ScanPanel.Visibility == Visibility.Visible) RenderScanCapability(null, false);
            _logger.LogError(error, "Unexpected service status error");
        }
    }

    private void RenderScanCapability(ScanCapabilitySnapshot? capability, bool connected)
    {
        var state = ScanCapabilityPresentation.State(capability, connected, DateTimeOffset.UtcNow,
            _scanWasDisconnected);
        ScanStateText.Text = state switch
        {
            ScanCapabilityDisplayState.Disconnected => "Disconnected - service unavailable",
            ScanCapabilityDisplayState.Unavailable => "Unavailable - scan capability could not be read",
            ScanCapabilityDisplayState.Stale => "Stale - last capability sample is over two minutes old",
            ScanCapabilityDisplayState.Recovered => "Recovered - current scan capability",
            _ => "Current scan capability"
        };
        if (state == ScanCapabilityDisplayState.Disconnected) _scanWasDisconnected = true;
        else if (state is ScanCapabilityDisplayState.Current or ScanCapabilityDisplayState.Recovered)
            _scanWasDisconnected = false;
        var visible = connected ? capability : null;
        ScanSampleText.Text = visible is null ? "Sample: unavailable" :
            $"Sample: {visible.SampledAtUtc.ToLocalTime():G}";
        ScanPolicyText.Text = visible is null ? "Policy revision: unavailable" :
            $"Policy revision: {visible.PolicyRevision}";
        ScanCapabilityText.Text = visible is null ? string.Empty :
            "Scanning is not enabled. No file scan is running. Client-supplied targets and scheduled fixed targets are not accepted or configured.";
    }

    private void RenderActivity(ActivitySnapshot? activity, bool connected)
    {
        var state = ActivityPresentation.State(activity, connected, DateTimeOffset.UtcNow,
            _activityWasDisconnected);
        ActivityStateText.Text = state switch
        {
            ActivityDisplayState.Disconnected => "Disconnected - service unavailable",
            ActivityDisplayState.Unavailable => "Unavailable - no Activity sample or unsupported service",
            ActivityDisplayState.Stale => "Stale - last sample is over two minutes old",
            ActivityDisplayState.Empty => "No observed changes since service start",
            ActivityDisplayState.Recovered => "Recovered - current observations from the service",
            _ => "Current observations"
        };
        if (state == ActivityDisplayState.Disconnected) _activityWasDisconnected = true;
        else if (state is ActivityDisplayState.Current or ActivityDisplayState.Recovered)
            _activityWasDisconnected = false;
        // A disconnected desktop must not retain observations as current evidence.
        var visible = connected ? activity : null;
        ActivitySessionText.Text = visible is null ? "Service start: unavailable" :
            $"Service start: {visible.ServiceStartedAtUtc.ToLocalTime():G}";
        ActivitySampleText.Text = visible is null ? "Sampled through: unavailable" :
            $"Sampled through: {visible.SampledThroughUtc.ToLocalTime():G}";
        ActivityEntries.ItemsSource = visible?.Entries.Select(FormatObservation).ToArray() ?? [];
    }

    private static string FormatObservation(ActivityObservation entry)
    {
        var category = entry.Category == ActivityCategory.Antivirus
            ? "Windows-reported antivirus health" : "Windows-reported firewall health";
        var current = FormatObservedHealth(entry.CurrentState);
        var description = entry.IsInitial
            ? $"Initial observation: {current}"
            : $"Observed change: {FormatObservedHealth(entry.PreviousState!.Value)} to {current}";
        return $"{category} - {description} - observed at {entry.ObservedAtUtc.ToLocalTime():G}";
    }

    private static string FormatObservedHealth(ObservedHealth health) => health switch
    {
        ObservedHealth.Good => "Good",
        ObservedHealth.NotMonitored => "Not monitored",
        ObservedHealth.Poor => "Poor",
        ObservedHealth.Snoozed => "Snoozed",
        _ => "Unavailable"
    };

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
        HealthAntivirusText.Text = $"Windows-reported antivirus health: {visible?.AntivirusHealth switch
        {
            WindowsAntivirusHealth.Good => "Good",
            WindowsAntivirusHealth.NotMonitored => "Not monitored",
            WindowsAntivirusHealth.Poor => "Poor",
            WindowsAntivirusHealth.Snoozed => "Snoozed",
            _ => "Unavailable"
        }}";
        HealthFirewallText.Text = $"Windows-reported firewall health: {visible?.FirewallHealth switch
        {
            WindowsFirewallHealth.Good => "Good",
            WindowsFirewallHealth.NotMonitored => "Not monitored",
            WindowsFirewallHealth.Poor => "Poor",
            WindowsFirewallHealth.Snoozed => "Snoozed",
            _ => "Unavailable"
        }}";
    }

    private async void NavigationChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SectionList.SelectedItem is not ListBoxItem item || SectionTitle is null) return;
        var section = item.Content?.ToString() ?? "Dashboard";
        SectionTitle.Text = section;
        DashboardPanel.Visibility = section == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        ScanPanel.Visibility = section == "Scan" ? Visibility.Visible : Visibility.Collapsed;
        SystemHealthPanel.Visibility = section == "System Health" ? Visibility.Visible : Visibility.Collapsed;
        ActivityPanel.Visibility = section == "Activity" ? Visibility.Visible : Visibility.Collapsed;
        PlaceholderPanel.Visibility = section is "Dashboard" or "Scan" or "System Health" or "Activity" ? Visibility.Collapsed : Visibility.Visible;
        PlaceholderText.Text = $"{section} will be available in a future release.";
        if (section is "Scan" or "System Health" or "Activity") await RefreshStatusAsync();
    }
}
