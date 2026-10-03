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
    private readonly IComponentInspectionClient _componentInspectionClient;
    private readonly IComponentIntegrityClient _componentIntegrityClient;
    private readonly ITrustedManifestIntegrityClient _trustedManifestIntegrityClient;
    private readonly IIntegrityRefreshAuditClient _integrityRefreshAuditClient;
    private readonly ITrustedManifestIntegrityHistoryClient _trustedManifestIntegrityHistoryClient;
    private readonly IReleaseProvenanceClient _releaseProvenanceClient;
    private readonly IUpdateTransactionClient _updateTransactionClient;
    private readonly ITrustedManifestRefreshCommandClient _trustedManifestRefreshCommandClient;
    private readonly IWindowsSecurityProviderInventorySource _providerInventorySource = new WindowsSecurityProviderInventorySource();
    private readonly ProtectionProviderInventorySession _providerInventorySession = new();
    private readonly IWindowsFirewallProfileObservationSource _firewallProfileObservationSource = new WindowsFirewallProfileObservationSource();
    private readonly NetworkFirewallProfileObservationSession _firewallProfileObservationSession = new();
    private readonly WindowsSecurityHandoff _windowsSecurityHandoff = new();
    private readonly ILogger<MainWindow> _logger;
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(10) };
    private CancellationTokenSource? _refreshCancellation;
    private bool _activityWasDisconnected;
    private bool _scanWasDisconnected;
    private bool _inspectionWasDisconnected;
    private bool _integrityWasDisconnected;
    private bool _trustedManifestWasDisconnected;
    private bool _integrityRefreshAuditWasDisconnected;
    private bool _trustedManifestHistoryWasDisconnected;
    private bool _releaseProvenanceWasDisconnected;
    private bool _updateTransactionWasDisconnected;
    private DateTimeOffset? _trustedManifestHistoryServiceStartedAtUtc;
    private bool _statusConnected;
    private TrustedManifestIntegritySnapshot? _lastTrustedManifestSnapshot;
    private readonly TrustedManifestRefreshRequestState _trustedManifestRefresh = new();
    private CancellationTokenSource? _trustedManifestRefreshCancellation;
    private readonly LocalFileInspectionCoordinator _fileInspectionCoordinator = new();
    private readonly LocalFileFingerprintInspector _fileFingerprintInspector;
    private readonly LocalFileFingerprintComparisonInspector _fileFingerprintComparisonInspector;
    private readonly LocalFolderFingerprintInventoryInspector _folderFingerprintInventoryInspector;
    private readonly AuthenticodePublisherInspector _authenticodePublisherInspector;
    private readonly WindowsSignatureInspector _windowsSignatureInspector;
    private CancellationTokenSource? _fileInspectionCancellation;
    private CancellationTokenSource? _fileComparisonCancellation;
    private CancellationTokenSource? _folderInventoryCancellation;
    private CancellationTokenSource? _publisherInspectionCancellation;
    private CancellationTokenSource? _windowsSignatureInspectionCancellation;

    public MainWindow(ISecurityServiceStatusClient client, ISystemHealthClient healthClient,
        IActivityClient activityClient, IScanCapabilityClient scanCapabilityClient, IComponentInspectionClient componentInspectionClient, IComponentIntegrityClient componentIntegrityClient, ITrustedManifestIntegrityClient trustedManifestIntegrityClient, IIntegrityRefreshAuditClient integrityRefreshAuditClient, ITrustedManifestIntegrityHistoryClient trustedManifestIntegrityHistoryClient, IReleaseProvenanceClient releaseProvenanceClient, ITrustedManifestRefreshCommandClient trustedManifestRefreshCommandClient,
        IUpdateTransactionClient updateTransactionClient, ILogger<MainWindow> logger)
    {
        _client = client;
        _healthClient = healthClient;
        _activityClient = activityClient;
        _scanCapabilityClient = scanCapabilityClient;
        _componentInspectionClient = componentInspectionClient;
        _componentIntegrityClient = componentIntegrityClient;
        _trustedManifestIntegrityClient = trustedManifestIntegrityClient;
        _integrityRefreshAuditClient = integrityRefreshAuditClient;
        _trustedManifestIntegrityHistoryClient = trustedManifestIntegrityHistoryClient;
        _releaseProvenanceClient = releaseProvenanceClient;
        _updateTransactionClient = updateTransactionClient;
        _trustedManifestRefreshCommandClient = trustedManifestRefreshCommandClient;
        _logger = logger;
        _fileFingerprintInspector = new LocalFileFingerprintInspector(coordinator: _fileInspectionCoordinator);
        _fileFingerprintComparisonInspector = new LocalFileFingerprintComparisonInspector(_fileInspectionCoordinator);
        _folderFingerprintInventoryInspector = new LocalFolderFingerprintInventoryInspector(_fileInspectionCoordinator);
        _authenticodePublisherInspector = new AuthenticodePublisherInspector(coordinator: _fileInspectionCoordinator);
        _windowsSignatureInspector = new WindowsSignatureInspector(coordinator: _fileInspectionCoordinator);
        InitializeComponent();
        RenderFileInspection(FileFingerprintInspectionPresentation.Initial());
        RenderFileFingerprintComparison(FileFingerprintComparisonPresentation.Initial());
        RenderFolderFingerprintInventory(FolderFingerprintInventoryPresentation.Initial());
        RenderPublisherInspection(AuthenticodePublisherInspectionPresentation.Initial());
        RenderWindowsSignatureInspection(WindowsSignatureInspectionPresentation.Initial());
        RenderProtectionProviderInventory(WindowsSecurityProviderInventoryPresentation.Initial());
        RenderNetworkFirewallProfiles(WindowsFirewallProfileObservationPresentation.Initial());
        RenderWindowsSecurityHandoff(WindowsSecurityHandoffPresentation.Initial());
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
            _trustedManifestRefreshCancellation?.Cancel();
            _fileInspectionCancellation?.Cancel();
            _fileComparisonCancellation?.Cancel();
            _folderInventoryCancellation?.Cancel();
            _publisherInspectionCancellation?.Cancel();
            _windowsSignatureInspectionCancellation?.Cancel();
            _providerInventorySession.Clear();
            _firewallProfileObservationSession.Clear();
        };
    }

    private async Task RefreshStatusAsync()
    {
        RenderNetworkFirewallProfiles(WindowsFirewallProfileObservationPresentation.Create(
            _firewallProfileObservationSession.Snapshot, DateTimeOffset.UtcNow));
        _refreshCancellation?.Cancel();
        _refreshCancellation?.Dispose();
        var cancellation = new CancellationTokenSource();
        _refreshCancellation = cancellation;
        try
        {
            var status = await _client.GetStatusAsync(cancellation.Token);
            if (cancellation.IsCancellationRequested) return;
            _statusConnected = status is not null;
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
            if (status is null) _inspectionWasDisconnected = true;
            if (status is null) _integrityWasDisconnected = true;
            if (status is null) _trustedManifestWasDisconnected = true;
            if (status is null) _integrityRefreshAuditWasDisconnected = true;
            if (status is null) _trustedManifestHistoryWasDisconnected = true;
            if (status is null) _releaseProvenanceWasDisconnected = true;
            if (status is null) _updateTransactionWasDisconnected = true;
            if (status is null && _trustedManifestRefresh.IsInFlight)
            {
                _trustedManifestRefreshCancellation?.Cancel();
                _trustedManifestRefresh.Complete();
                RefreshIntegrityStatusText.Text = "Refresh stopped because the service disconnected.";
            }
            if (ScanPanel.Visibility == Visibility.Visible)
            {
                var capability = status is null ? null :
                    await _scanCapabilityClient.GetScanCapabilityAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderScanCapability(capability, status is not null);
            }
            if (InstallationPanel.Visibility == Visibility.Visible)
            {
                var inspection = status is null ? null : await _componentInspectionClient.GetComponentInspectionAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderComponentInspection(inspection, status is not null);
                var integrity = status is null ? null : await _componentIntegrityClient.GetComponentIntegrityAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderComponentIntegrity(integrity, status is not null);
                var trustedManifest = status is null ? null : await _trustedManifestIntegrityClient.GetTrustedManifestIntegrityAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                if (trustedManifest is not null) _lastTrustedManifestSnapshot = trustedManifest;
                if (_trustedManifestRefresh.HasNewerStatusSnapshot(trustedManifest))
                {
                    _trustedManifestRefresh.Complete();
                    _trustedManifestRefreshCancellation?.Cancel();
                    RefreshIntegrityStatusText.Text = "Refresh completed from a newer service sample.";
                }
                RenderTrustedManifestIntegrity(trustedManifest, status is not null);
                var releaseProvenance = status is null ? null : await _releaseProvenanceClient.GetReleaseProvenanceAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderReleaseProvenance(releaseProvenance, status is not null);
                var updateTransaction = status is null ? null : await _updateTransactionClient.GetUpdateStatusAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderUpdateTransaction(updateTransaction, status is not null);
                var refreshAudit = status is null ? null : await _integrityRefreshAuditClient.GetIntegrityRefreshAuditAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderIntegrityRefreshAudit(refreshAudit, status is not null);
                var history = status is null ? null : await _trustedManifestIntegrityHistoryClient.GetTrustedManifestIntegrityHistoryAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderTrustedManifestIntegrityHistory(history, status is not null);
                UpdateRefreshIntegrityControl();
            }
            if (ProtectionPanel.Visibility == Visibility.Visible)
            {
                var health = status is null ? null : await _healthClient.GetSystemHealthAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                var trustedManifest = status is null ? null : await _trustedManifestIntegrityClient.GetTrustedManifestIntegrityAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                var releaseProvenance = status is null ? null : await _releaseProvenanceClient.GetReleaseProvenanceAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                var updateTransaction = status is null ? null : await _updateTransactionClient.GetUpdateStatusAsync(cancellation.Token);
                if (cancellation.IsCancellationRequested) return;
                RenderProtectionOverview(status, health, trustedManifest, releaseProvenance, updateTransaction);
            }
            _logger.LogInformation("Service status query completed: {Connected}", status is not null);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception error)
        {
            ServiceStatusText.Text = "Disconnected";
            _statusConnected = false;
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
            if (InstallationPanel.Visibility == Visibility.Visible) RenderComponentInspection(null, false);
            if (InstallationPanel.Visibility == Visibility.Visible) RenderComponentIntegrity(null, false);
            if (InstallationPanel.Visibility == Visibility.Visible) RenderTrustedManifestIntegrity(null, false);
            if (InstallationPanel.Visibility == Visibility.Visible) RenderReleaseProvenance(null, false);
            if (InstallationPanel.Visibility == Visibility.Visible) RenderIntegrityRefreshAudit(null, false);
            if (InstallationPanel.Visibility == Visibility.Visible) RenderTrustedManifestIntegrityHistory(null, false);
            if (ProtectionPanel.Visibility == Visibility.Visible) RenderProtectionOverview(null, null, null, null, null);
            if (_trustedManifestRefresh.IsInFlight)
            {
                _trustedManifestRefreshCancellation?.Cancel();
                _trustedManifestRefresh.Complete();
                RefreshIntegrityStatusText.Text = "Refresh stopped because the service disconnected.";
            }
            UpdateRefreshIntegrityControl();
            _logger.LogError(error, "Unexpected service status error");
        }
    }

    private void RenderComponentIntegrity(ComponentIntegritySnapshot? integrity, bool connected)
    {
        var state = ComponentIntegrityPresentation.State(integrity, connected, DateTimeOffset.UtcNow, _integrityWasDisconnected);
        IntegrityStateText.Text = state switch { ComponentIntegrityDisplayState.Disconnected => "Disconnected - service unavailable", ComponentIntegrityDisplayState.Unavailable => "Unavailable - component integrity could not be read", ComponentIntegrityDisplayState.Stale => "Stale - last integrity sample is over 30 minutes old", ComponentIntegrityDisplayState.Recovered => "Recovered - current component integrity", _ => "Current component integrity" };
        if (state == ComponentIntegrityDisplayState.Disconnected) _integrityWasDisconnected = true; else if (state is ComponentIntegrityDisplayState.Current or ComponentIntegrityDisplayState.Recovered) _integrityWasDisconnected = false;
        IntegritySampleText.Text = integrity is null || !connected ? "Sample: unavailable" : $"Sample: {integrity.SampledAtUtc.ToLocalTime():G}";
        IntegrityValueText.Text = integrity?.Evaluation switch { ComponentIntegrityEvaluation.Match => "Match - the observed Vantrel Core component matches the reference compiled into this Service build.", ComponentIntegrityEvaluation.Mismatch => "Mismatch - the observed Vantrel Core component does not match the reference compiled into this Service build.", _ => $"Unavailable: {integrity?.ObservationReason.ToString() ?? "Unavailable"}" };
    }

    private void RenderTrustedManifestIntegrity(TrustedManifestIntegritySnapshot? integrity, bool connected)
    {
        var state = TrustedManifestIntegrityPresentation.State(integrity, connected, DateTimeOffset.UtcNow, _trustedManifestWasDisconnected);
        TrustedManifestStateText.Text = state switch { TrustedManifestIntegrityDisplayState.Disconnected => "Disconnected - service unavailable", TrustedManifestIntegrityDisplayState.Unavailable => "Unavailable - signed installation integrity could not be read", TrustedManifestIntegrityDisplayState.Stale => "Stale - last signed integrity sample is over 30 minutes old", TrustedManifestIntegrityDisplayState.Recovered => "Recovered - current signed installation integrity", _ => "Current signed installation integrity" };
        if (state == TrustedManifestIntegrityDisplayState.Disconnected) _trustedManifestWasDisconnected = true; else if (state is TrustedManifestIntegrityDisplayState.Current or TrustedManifestIntegrityDisplayState.Recovered) _trustedManifestWasDisconnected = false;
        var value = connected ? integrity : null;
        TrustedManifestSampleText.Text = value is null ? "Sample: unavailable" : $"Sample: {value.SampledAtUtc.ToLocalTime():G}";
        TrustedManifestValueText.Text = value switch
        {
            { SignatureState: TrustedManifestSignatureState.Valid, Evaluation: TrustedManifestInstallationEvaluation.AllMatch } => "Manifest authentication: Valid. All seven fixed installed components match the signed manifest.",
            { SignatureState: TrustedManifestSignatureState.Valid, Evaluation: TrustedManifestInstallationEvaluation.ComponentMismatch } => $"Manifest authentication: Valid. Component mismatch: {value.MismatchedComponent}.",
            { SignatureState: TrustedManifestSignatureState.Valid, Evaluation: TrustedManifestInstallationEvaluation.ObservationUnavailable } => $"Manifest authentication: Valid. Component observation unavailable: {value.ObservationReason}.",
            { SignatureState: TrustedManifestSignatureState.SignatureInvalid } => "Manifest authentication: Signature invalid. No component comparison was accepted.",
            { SignatureState: TrustedManifestSignatureState.ManifestMalformed } => "Manifest authentication: Manifest malformed. No component comparison was accepted.",
            { SignatureState: TrustedManifestSignatureState.UnsupportedSchema } => "Manifest authentication: Unsupported schema. No component comparison was accepted.",
            _ => "Manifest authentication: unavailable."
        };
    }

    private void RenderReleaseProvenance(ReleaseProvenanceSnapshot? provenance, bool connected)
    {
        var presentation = ReleaseProvenanceDesktopPresentation.Create(provenance, connected, DateTimeOffset.UtcNow,
            _releaseProvenanceWasDisconnected);
        ReleaseProvenanceStateText.Text = presentation.StateText;
        ReleaseProvenanceSampleText.Text = presentation.SampleText;
        ReleaseProvenanceValueText.Text = presentation.ValueText;
        if (presentation.DisplayState == ReleaseProvenanceDisplayState.Disconnected)
            _releaseProvenanceWasDisconnected = true;
        else if (presentation.DisplayState is ReleaseProvenanceDisplayState.Current or ReleaseProvenanceDisplayState.Recovered)
            _releaseProvenanceWasDisconnected = false;
    }
    private void RenderUpdateTransaction(UpdateTransactionSnapshot? transaction, bool connected)
    {
        var presentation = UpdateTransactionDesktopPresentation.Create(transaction, connected, DateTimeOffset.UtcNow, _updateTransactionWasDisconnected);
        UpdateTransactionStateText.Text = presentation.StateText;
        UpdateTransactionSampleText.Text = presentation.SampleText;
        UpdateTransactionValueText.Text = presentation.ValueText;
        if (presentation.State == UpdateTransactionDisplayState.Disconnected) _updateTransactionWasDisconnected = true;
        else if (presentation.State is UpdateTransactionDisplayState.Current or UpdateTransactionDisplayState.Recovered) _updateTransactionWasDisconnected = false;
    }

    private void RenderProtectionOverview(SecurityServiceStatus? service, SystemHealthSnapshot? health,
        TrustedManifestIntegritySnapshot? installation, ReleaseProvenanceSnapshot? provenance, UpdateTransactionSnapshot? update)
    {
        var presentation = ProtectionOverviewPresentation.Create(service, health, installation, provenance, update,
            service is not null, DateTimeOffset.UtcNow, _trustedManifestWasDisconnected,
            _releaseProvenanceWasDisconnected, _updateTransactionWasDisconnected);
        ProtectionOverviewNoticeText.Text = presentation.NoticeText;
        ProtectionServiceText.Text = presentation.ServiceText;
        ProtectionAntivirusText.Text = presentation.AntivirusText;
        ProtectionFirewallText.Text = presentation.FirewallText;
        ProtectionInstallationText.Text = presentation.InstallationText;
        ProtectionProvenanceText.Text = presentation.ProvenanceText;
        ProtectionUpdateText.Text = presentation.UpdateText;
        RenderProtectionProviderInventory(WindowsSecurityProviderInventoryPresentation.Create(_providerInventorySession.Snapshot, DateTimeOffset.UtcNow));
        if (presentation.InstallationState == TrustedManifestIntegrityDisplayState.Disconnected)
            _trustedManifestWasDisconnected = true;
        else if (presentation.InstallationState is TrustedManifestIntegrityDisplayState.Current or TrustedManifestIntegrityDisplayState.Recovered)
            _trustedManifestWasDisconnected = false;
        if (presentation.ProvenanceState == ReleaseProvenanceDisplayState.Disconnected)
            _releaseProvenanceWasDisconnected = true;
        else if (presentation.ProvenanceState is ReleaseProvenanceDisplayState.Current or ReleaseProvenanceDisplayState.Recovered)
            _releaseProvenanceWasDisconnected = false;
        if (presentation.UpdateState == UpdateTransactionDisplayState.Disconnected)
            _updateTransactionWasDisconnected = true;
        else if (presentation.UpdateState is UpdateTransactionDisplayState.Current or UpdateTransactionDisplayState.Recovered)
            _updateTransactionWasDisconnected = false;
    }

    private void RenderProtectionProviderInventory(WindowsSecurityProviderInventoryPresentation presentation)
    {
        ProtectionProviderInventoryNoticeText.Text = presentation.NoticeText;
        ProtectionProviderInventoryStateText.Text = presentation.StateText;
        ProtectionProviderInventoryEntries.ItemsSource = presentation.EntryText;
    }

    private void OpenProtectionProviderInventory()
    {
        RenderProtectionProviderInventory(WindowsSecurityProviderInventoryPresentation.Initial());
        _ = CollectProtectionProviderInventoryAsync();
    }

    private async Task CollectProtectionProviderInventoryAsync()
    {
        var snapshot = await _providerInventorySession.OpenAsync(_providerInventorySource);
        if (snapshot is not null && _providerInventorySession.IsCurrent(snapshot))
            RenderProtectionProviderInventory(WindowsSecurityProviderInventoryPresentation.Create(snapshot, DateTimeOffset.UtcNow));
    }

    private void RenderNetworkFirewallProfiles(WindowsFirewallProfileObservationPresentation presentation)
    {
        NetworkFirewallProfileNoticeText.Text = presentation.NoticeText;
        NetworkFirewallProfileStateText.Text = presentation.StateText;
        NetworkFirewallProfileEntries.ItemsSource = presentation.ProfileText;
    }

    private void OpenNetworkFirewallProfiles()
    {
        RenderNetworkFirewallProfiles(WindowsFirewallProfileObservationPresentation.Initial());
        _ = CollectNetworkFirewallProfilesAsync();
    }

    private async Task CollectNetworkFirewallProfilesAsync()
    {
        var snapshot = await _firewallProfileObservationSession.OpenAsync(_firewallProfileObservationSource);
        if (snapshot is not null && _firewallProfileObservationSession.IsCurrent(snapshot))
            RenderNetworkFirewallProfiles(WindowsFirewallProfileObservationPresentation.Create(snapshot, DateTimeOffset.UtcNow));
    }

    private void RenderIntegrityRefreshAudit(IntegrityRefreshAuditSnapshot? audit, bool connected)
    {
        var state = IntegrityRefreshAuditPresentation.State(audit, connected, _integrityRefreshAuditWasDisconnected);
        IntegrityRefreshAuditStateText.Text = state switch
        {
            IntegrityRefreshAuditDisplayState.Disconnected => "Disconnected - service unavailable",
            IntegrityRefreshAuditDisplayState.Unavailable => "Unavailable - integrity refresh activity could not be read",
            IntegrityRefreshAuditDisplayState.Empty => "No authorized integrity refresh activity in this service session",
            IntegrityRefreshAuditDisplayState.Recovered => "Recovered - current integrity refresh activity",
            _ => "Current integrity refresh activity"
        };
        if (state == IntegrityRefreshAuditDisplayState.Disconnected) _integrityRefreshAuditWasDisconnected = true;
        else if (state is IntegrityRefreshAuditDisplayState.Current or IntegrityRefreshAuditDisplayState.Recovered or IntegrityRefreshAuditDisplayState.Empty)
            _integrityRefreshAuditWasDisconnected = false;
        var visible = connected ? audit : null;
        IntegrityRefreshAuditSessionText.Text = visible is null ? "Current service session only: unavailable" :
            $"Current service session only. Service start: {visible.ServiceStartedAtUtc.ToLocalTime():G}";
        IntegrityRefreshAuditEntries.ItemsSource = visible?.Entries.Select(FormatIntegrityRefreshAudit).ToArray() ?? [];
    }

    private static string FormatIntegrityRefreshAudit(IntegrityRefreshAuditRecord entry) =>
        $"Integrity refresh {entry.Outcome} - {entry.OccurredAtUtc.ToLocalTime():G}";

    private void RenderTrustedManifestIntegrityHistory(TrustedManifestIntegrityHistorySnapshot? history, bool connected)
    {
        var reset = history is not null && _trustedManifestHistoryServiceStartedAtUtc is { } previous &&
            previous != history.ServiceStartedAtUtc;
        var state = TrustedManifestIntegrityHistoryPresentation.State(history, connected, _trustedManifestHistoryWasDisconnected, reset);
        TrustedManifestHistoryStateText.Text = state switch
        {
            TrustedManifestIntegrityHistoryDisplayState.Disconnected => "Disconnected - service unavailable",
            TrustedManifestIntegrityHistoryDisplayState.Unavailable => "Unavailable - signed installation integrity history could not be read",
            TrustedManifestIntegrityHistoryDisplayState.Empty => "No signed installation integrity history in this service session",
            TrustedManifestIntegrityHistoryDisplayState.Recovered => "Recovered - current signed installation integrity history",
            TrustedManifestIntegrityHistoryDisplayState.Reset => "Reset - new service session has no prior history",
            _ => "Current signed installation integrity history"
        };
        if (history is not null) _trustedManifestHistoryServiceStartedAtUtc = history.ServiceStartedAtUtc;
        if (state == TrustedManifestIntegrityHistoryDisplayState.Disconnected) _trustedManifestHistoryWasDisconnected = true;
        else if (state is not TrustedManifestIntegrityHistoryDisplayState.Unavailable) _trustedManifestHistoryWasDisconnected = false;
        var visible = connected ? history : null;
        TrustedManifestHistorySessionText.Text = visible is null ? "Current service session only: unavailable" :
            $"Current service session only. Service start: {visible.ServiceStartedAtUtc.ToLocalTime():G}";
        TrustedManifestHistoryEntries.ItemsSource = visible?.Entries.Select(entry =>
            $"{entry.SampledAtUtc.ToLocalTime():G} - {entry.SignatureState} / {entry.Evaluation}").ToArray() ?? [];
    }

    private async void RefreshIntegrityClicked(object sender, RoutedEventArgs e)
    {
        if (!_trustedManifestRefresh.TryBegin(_statusConnected, _lastTrustedManifestSnapshot, out var requestId) || requestId is null) return;
        _trustedManifestRefreshCancellation?.Cancel();
        _trustedManifestRefreshCancellation?.Dispose();
        _trustedManifestRefreshCancellation = new CancellationTokenSource();
        var cancellation = _trustedManifestRefreshCancellation;
        RefreshIntegrityStatusText.Text = "Refreshing…";
        UpdateRefreshIntegrityControl();
        try
        {
            var response = await _trustedManifestRefreshCommandClient.RefreshTrustedManifestIntegrityAsync(requestId, cancellation.Token);
            if (cancellation.IsCancellationRequested) return;
            if (response is null)
            {
                EndRefresh("Refresh request was unavailable; the last service sample remains displayed.");
                return;
            }
            if (response.Result is not (CommandResult.Accepted or CommandResult.AlreadyInProgress))
            {
                EndRefresh(response.Result switch
                {
                    CommandResult.Duplicate => "Refresh request was already recorded; no completion was inferred.",
                    CommandResult.Rejected => "Refresh request was not accepted; the last service sample remains displayed.",
                    _ => "Refresh request was unavailable; the last service sample remains displayed."
                });
                return;
            }
            RefreshIntegrityStatusText.Text = "Refreshing… waiting for a newer service sample.";
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(TrustedManifestRefreshRequestState.TimeoutSeconds));
            while (!timeout.IsCancellationRequested)
            {
                var status = await _client.GetStatusAsync(timeout.Token);
                if (status is null)
                {
                    _statusConnected = false;
                    EndRefresh("Refresh stopped because the service disconnected.");
                    return;
                }
                var snapshot = await _trustedManifestIntegrityClient.GetTrustedManifestIntegrityAsync(timeout.Token);
                if (_trustedManifestRefresh.HasNewerStatusSnapshot(snapshot))
                {
                    _lastTrustedManifestSnapshot = snapshot;
                    _trustedManifestRefresh.Complete();
                    RenderTrustedManifestIntegrity(snapshot, true);
                    RefreshIntegrityStatusText.Text = "Refresh completed from a newer service sample.";
                    UpdateRefreshIntegrityControl();
                    return;
                }
                await Task.Delay(TrustedManifestRefreshRequestState.PollMilliseconds, timeout.Token);
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            if (_trustedManifestRefresh.IsInFlight)
                EndRefresh("Refresh was cancelled; the last service sample remains displayed.");
        }
        catch (OperationCanceledException)
        {
            EndRefresh("Refresh did not complete within the expected time; the last service sample remains displayed.");
        }
        catch (Exception)
        {
            EndRefresh("Refresh request was unavailable; the last service sample remains displayed.");
        }
    }

    private void EndRefresh(string message)
    {
        _trustedManifestRefresh.Complete();
        RefreshIntegrityStatusText.Text = message;
        UpdateRefreshIntegrityControl();
    }

    private void UpdateRefreshIntegrityControl()
    {
        var presentation = TrustedManifestRefreshControlPresentation.Create(
            _statusConnected, _trustedManifestRefresh.IsInFlight, RefreshIntegrityStatusText.Text);
        RefreshIntegrityButton.IsEnabled = presentation.IsEnabled;
        RefreshIntegrityStatusText.Text = presentation.StatusText;
    }

    private void RenderComponentInspection(ComponentInspectionSnapshot? inspection, bool connected)
    {
        var state = ComponentInspectionPresentation.State(inspection, connected, DateTimeOffset.UtcNow, _inspectionWasDisconnected);
        InspectionStateText.Text = state switch { ComponentInspectionDisplayState.Disconnected => "Disconnected - service unavailable", ComponentInspectionDisplayState.Unavailable => "Unavailable - component inspection could not be read", ComponentInspectionDisplayState.Stale => "Stale - last observation is over 30 minutes old", ComponentInspectionDisplayState.Recovered => "Recovered - current component observation", _ => "Current component observation" };
        if (state == ComponentInspectionDisplayState.Disconnected) _inspectionWasDisconnected = true; else if (state is ComponentInspectionDisplayState.Current or ComponentInspectionDisplayState.Recovered) _inspectionWasDisconnected = false;
        var value = connected ? inspection : null;
        InspectionSampleText.Text = value is null ? "Sample: unavailable" : $"Sample: {value.SampledAtUtc.ToLocalTime():G}";
        InspectionValueText.Text = value?.Outcome == ComponentInspectionOutcome.Observed ? $"Observed SHA-256: {value.Hash} ({value.ObservedByteLength:N0} bytes)" : $"Observation: {value?.Reason.ToString() ?? "Unavailable"}";
    }

    private void RenderWindowsSecurityHandoff(WindowsSecurityHandoffPresentation presentation)
    {
        WindowsSecurityHandoffNoticeText.Text = presentation.NoticeText;
        WindowsSecurityHandoffStateText.Text = presentation.StateText;
    }

    private void OpenWindowsSecurityClicked(object sender, RoutedEventArgs e) =>
        RenderWindowsSecurityHandoff(_windowsSecurityHandoff.Open());

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

    private void RenderFileInspection(FileFingerprintInspectionPresentation presentation)
    {
        FileInspectionNoticeText.Text = presentation.NoticeText;
        FileInspectionStateText.Text = presentation.StateText;
        FileInspectionResultPanel.Visibility = presentation.HasCompletedFingerprint ? Visibility.Visible : Visibility.Collapsed;
        FileInspectionNameText.Text = presentation.FileName ?? string.Empty;
        FileInspectionByteCountText.Text = presentation.ByteLength?.ToString("N0") ?? string.Empty;
        FileInspectionFingerprintText.Text = presentation.Sha256 ?? string.Empty;
    }

    private void RenderPublisherInspection(AuthenticodePublisherInspectionPresentation presentation)
    {
        PublisherInspectionNoticeText.Text = presentation.NoticeText;
        PublisherInspectionStateText.Text = presentation.StateText;
        PublisherInspectionResultPanel.Visibility = presentation.HasResult ? Visibility.Visible : Visibility.Collapsed;
        PublisherInspectionNameText.Text = presentation.FileName ?? string.Empty;
        PublisherInspectionByteCountText.Text = presentation.ByteLength?.ToString("N0") ?? string.Empty;
        PublisherInspectionSignerText.Text = presentation.DeclaredSignerSubject ?? "No declared embedded signer subject was available.";
    }

    private void RenderWindowsSignatureInspection(WindowsSignatureInspectionPresentation presentation)
    {
        WindowsSignatureInspectionNoticeText.Text = presentation.NoticeText;
        WindowsSignatureInspectionStateText.Text = presentation.StateText;
        WindowsSignatureInspectionResultPanel.Visibility = presentation.HasResult ? Visibility.Visible : Visibility.Collapsed;
        WindowsSignatureInspectionNameText.Text = presentation.FileName ?? string.Empty;
        WindowsSignatureInspectionByteCountText.Text = presentation.ByteLength?.ToString("N0") ?? string.Empty;
        WindowsSignatureInspectionEmbeddedText.Text = presentation.EmbeddedStateText ?? string.Empty;
        WindowsSignatureInspectionSignerText.Text = presentation.DeclaredEmbeddedSignerSubject ?? "No declared embedded signer subject was available.";
        WindowsSignatureInspectionCatalogText.Text = presentation.CatalogStateText ?? string.Empty;
    }

    private void RenderFileFingerprintComparison(FileFingerprintComparisonPresentation presentation)
    {
        FileComparisonNoticeText.Text = presentation.NoticeText;
        FileComparisonStateText.Text = presentation.StateText;
    }

    private void RenderFolderFingerprintInventory(FolderFingerprintInventoryPresentation presentation)
    {
        FolderInventoryNoticeText.Text = presentation.NoticeText;
        FolderInventoryStateText.Text = presentation.StateText;
        FolderInventoryEntries.ItemsSource = presentation.EntryText;
    }

    private string? ChooseLocalFile(string title)
    {
        var picker = new Microsoft.Win32.OpenFileDialog
        {
            CheckFileExists = true,
            Multiselect = false,
            Title = title
        };
        return picker.ShowDialog(this) == true ? picker.FileName : null;
    }

    private string? ChooseLocalFolder(string title)
    {
        var picker = new Microsoft.Win32.OpenFolderDialog { Title = title, Multiselect = false };
        return picker.ShowDialog(this) == true ? picker.FolderName : null;
    }

    private void SetFileInspectionActionsEnabled(bool enabled)
    {
        ChooseFileForInspectionButton.IsEnabled = enabled;
        ChooseFileForComparisonButton.IsEnabled = enabled;
        ChooseFolderForInventoryButton.IsEnabled = enabled;
        ChooseFileForPublisherInspectionButton.IsEnabled = enabled;
        ChooseFileForWindowsSignatureInspectionButton.IsEnabled = enabled;
    }

    private async void ChooseFileForInspectionClicked(object sender, RoutedEventArgs e)
    {
        var selectedPath = ChooseLocalFile("Choose a file for fingerprint inspection");
        if (selectedPath is null) return;

        _fileInspectionCancellation?.Cancel();
        _fileInspectionCancellation?.Dispose();
        var cancellation = new CancellationTokenSource();
        _fileInspectionCancellation = cancellation;
        SetFileInspectionActionsEnabled(false);
        RenderFileInspection(FileFingerprintInspectionPresentation.InProgress());
        try
        {
            var result = await _fileFingerprintInspector.InspectAsync(selectedPath, cancellation.Token);
            if (!cancellation.IsCancellationRequested)
                RenderFileInspection(FileFingerprintInspectionPresentation.Create(result));
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            RenderFileInspection(FileFingerprintInspectionPresentation.Cancelled());
        }
        finally
        {
            if (ReferenceEquals(_fileInspectionCancellation, cancellation))
                SetFileInspectionActionsEnabled(true);
        }
    }

    private async void ChooseFileForPublisherInspectionClicked(object sender, RoutedEventArgs e)
    {
        var selectedPath = ChooseLocalFile("Choose a file for embedded Authenticode publisher inspection");
        if (selectedPath is null) return;

        _publisherInspectionCancellation?.Cancel();
        _publisherInspectionCancellation?.Dispose();
        var cancellation = new CancellationTokenSource();
        _publisherInspectionCancellation = cancellation;
        SetFileInspectionActionsEnabled(false);
        RenderPublisherInspection(AuthenticodePublisherInspectionPresentation.InProgress());
        try
        {
            var result = await _authenticodePublisherInspector.InspectAsync(selectedPath, cancellation.Token);
            if (!cancellation.IsCancellationRequested)
                RenderPublisherInspection(AuthenticodePublisherInspectionPresentation.Create(result));
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            RenderPublisherInspection(AuthenticodePublisherInspectionPresentation.Cancelled());
        }
        finally
        {
            if (ReferenceEquals(_publisherInspectionCancellation, cancellation))
                SetFileInspectionActionsEnabled(true);
        }
    }

    private async void ChooseFileForWindowsSignatureInspectionClicked(object sender, RoutedEventArgs e)
    {
        var selectedPath = ChooseLocalFile("Choose a file for Windows signature inspection");
        if (selectedPath is null) return;

        _windowsSignatureInspectionCancellation?.Cancel();
        _windowsSignatureInspectionCancellation?.Dispose();
        var cancellation = new CancellationTokenSource();
        _windowsSignatureInspectionCancellation = cancellation;
        SetFileInspectionActionsEnabled(false);
        RenderWindowsSignatureInspection(WindowsSignatureInspectionPresentation.InProgress());
        try
        {
            var result = await _windowsSignatureInspector.InspectAsync(selectedPath, cancellation.Token);
            if (!cancellation.IsCancellationRequested)
                RenderWindowsSignatureInspection(WindowsSignatureInspectionPresentation.Create(result));
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            RenderWindowsSignatureInspection(WindowsSignatureInspectionPresentation.Cancelled());
        }
        finally
        {
            if (ReferenceEquals(_windowsSignatureInspectionCancellation, cancellation))
                SetFileInspectionActionsEnabled(true);
        }
    }

    private async void ChooseFileForComparisonClicked(object sender, RoutedEventArgs e)
    {
        if (!ExpectedSha256Value.TryParse(ExpectedSha256TextBox.Text, out var expected))
        {
            RenderFileFingerprintComparison(FileFingerprintComparisonPresentation.Create(
                FileFingerprintComparisonResult.From(FileFingerprintComparisonOutcome.InvalidExpectedValue)));
            return;
        }

        var selectedPath = ChooseLocalFile("Choose a file for SHA-256 comparison");
        if (selectedPath is null) return;

        // The input is used only by this operation and is never rendered in its result.
        ExpectedSha256TextBox.Clear();
        _fileComparisonCancellation?.Cancel();
        _fileComparisonCancellation?.Dispose();
        var cancellation = new CancellationTokenSource();
        _fileComparisonCancellation = cancellation;
        SetFileInspectionActionsEnabled(false);
        RenderFileFingerprintComparison(FileFingerprintComparisonPresentation.InProgress());
        try
        {
            var result = await _fileFingerprintComparisonInspector.CompareAsync(selectedPath, expected, cancellation.Token);
            if (!cancellation.IsCancellationRequested)
                RenderFileFingerprintComparison(FileFingerprintComparisonPresentation.Create(result));
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            RenderFileFingerprintComparison(FileFingerprintComparisonPresentation.Cancelled());
        }
        finally
        {
            if (ReferenceEquals(_fileComparisonCancellation, cancellation))
                SetFileInspectionActionsEnabled(true);
        }
    }

    private async void ChooseFolderForInventoryClicked(object sender, RoutedEventArgs e)
    {
        var selectedPath = ChooseLocalFolder("Choose a folder for fingerprint inventory");
        if (selectedPath is null) return;

        _folderInventoryCancellation?.Cancel();
        _folderInventoryCancellation?.Dispose();
        var cancellation = new CancellationTokenSource();
        _folderInventoryCancellation = cancellation;
        SetFileInspectionActionsEnabled(false);
        RenderFolderFingerprintInventory(FolderFingerprintInventoryPresentation.InProgress());
        try
        {
            var result = await _folderFingerprintInventoryInspector.InspectAsync(selectedPath, cancellation.Token);
            if (!cancellation.IsCancellationRequested)
                RenderFolderFingerprintInventory(FolderFingerprintInventoryPresentation.Create(result));
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            RenderFolderFingerprintInventory(FolderFingerprintInventoryPresentation.Cancelled());
        }
        finally
        {
            if (ReferenceEquals(_folderInventoryCancellation, cancellation))
                SetFileInspectionActionsEnabled(true);
        }
    }

    private async void NavigationChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SectionList.SelectedItem is not ListBoxItem item || SectionTitle is null) return;
        var section = item.Content?.ToString() ?? "Dashboard";
        SectionTitle.Text = section;
        DashboardPanel.Visibility = section == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        ScanPanel.Visibility = section == "Scan" ? Visibility.Visible : Visibility.Collapsed;
        FileInspectionPanel.Visibility = section == "File inspection" ? Visibility.Visible : Visibility.Collapsed;
        if (section != "File inspection")
        {
            _folderInventoryCancellation?.Cancel();
            RenderFolderFingerprintInventory(FolderFingerprintInventoryPresentation.Initial());
        }
        InstallationPanel.Visibility = section == "Installation" ? Visibility.Visible : Visibility.Collapsed;
        ProtectionPanel.Visibility = section == "Protection" ? Visibility.Visible : Visibility.Collapsed;
        if (section == "Protection")
        {
            OpenProtectionProviderInventory();
        }
        else
        {
            _providerInventorySession.Clear();
            RenderProtectionProviderInventory(WindowsSecurityProviderInventoryPresentation.Initial());
        }
        NetworkPanel.Visibility = section == "Network" ? Visibility.Visible : Visibility.Collapsed;
        if (section == "Network")
        {
            OpenNetworkFirewallProfiles();
        }
        else
        {
            _firewallProfileObservationSession.Clear();
            RenderNetworkFirewallProfiles(WindowsFirewallProfileObservationPresentation.Initial());
        }
        SystemHealthPanel.Visibility = section == "System Health" ? Visibility.Visible : Visibility.Collapsed;
        ActivityPanel.Visibility = section == "Activity" ? Visibility.Visible : Visibility.Collapsed;
        PlaceholderPanel.Visibility = DesktopSectionNavigation.IsWorkspace(section) ? Visibility.Collapsed : Visibility.Visible;
        PlaceholderText.Text = $"{section} will be available in a future release.";
        if (DesktopSectionNavigation.RequiresStatusRefresh(section)) await RefreshStatusAsync();
    }
}
