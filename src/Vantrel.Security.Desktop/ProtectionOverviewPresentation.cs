using Vantrel.Security.Core;

namespace Vantrel.Security.Desktop;

internal sealed record ProtectionOverviewPresentation(
    string NoticeText,
    string ServiceText,
    string AntivirusText,
    string FirewallText,
    string InstallationText,
    string ProvenanceText,
    string UpdateText,
    TrustedManifestIntegrityDisplayState InstallationState,
    ReleaseProvenanceDisplayState ProvenanceState,
    UpdateTransactionDisplayState UpdateState)
{
    internal const string Notice = "Vantrel active protection is unavailable in this build. This page summarizes observed system-security and Vantrel installation status.";

    internal static ProtectionOverviewPresentation Create(SecurityServiceStatus? service, SystemHealthSnapshot? health,
        TrustedManifestIntegritySnapshot? installation, ReleaseProvenanceSnapshot? provenance,
        UpdateTransactionSnapshot? update, bool connected, DateTimeOffset now,
        bool installationWasDisconnected = false, bool provenanceWasDisconnected = false,
        bool updateWasDisconnected = false)
    {
        var healthState = SystemHealthPresentation.State(health, connected, now);
        var installationState = TrustedManifestIntegrityPresentation.State(installation, connected, now, installationWasDisconnected);
        var provenanceState = ReleaseProvenancePresentation.State(provenance, connected, now, provenanceWasDisconnected);
        var updateState = UpdateTransactionPresentation.State(update, connected, now, updateWasDisconnected);
        return new ProtectionOverviewPresentation(
            Notice,
            service is null ? "Disconnected - service connection is unavailable." :
                $"Connected - service heartbeat: {service.HeartbeatAtUtc.ToLocalTime():g}; uptime: {service.UptimeAt(now):hh\\:mm\\:ss}.",
            FormatHealth(healthState, "Windows-reported aggregate antivirus category", health?.AntivirusHealth?.ToString() ?? "Unavailable"),
            FormatHealth(healthState, "Windows-reported aggregate firewall category", health?.FirewallHealth?.ToString() ?? "Unavailable"),
            Format(installationState, "Signed installation integrity", installation is null ? "Unavailable" :
                $"signature {installation.SignatureState}; evaluation {installation.Evaluation}"),
            Format(provenanceState, "Signed release provenance and local policy", provenance is null ? "Unavailable" :
                $"signature {provenance.MetadataSignatureState}; manifest binding {provenance.ManifestBindingState}; policy {provenance.PolicyDecision}"),
            Format(updateState, "Offline update transaction and recovery state", update is null ? "Unavailable" :
                $"phase {update.Phase}; result {update.LastResult}"),
            installationState, provenanceState, updateState);
    }

    private static string FormatHealth(SystemHealthDisplayState state, string source, string value) =>
        $"{Prefix(state)} - {source}: {value}.";

    private static string Format<TState>(TState state, string source, string value) where TState : struct, Enum =>
        $"{Prefix(state)} - {source}: {value}.";

    private static string Prefix<TState>(TState state) where TState : struct, Enum => state.ToString() switch
    {
        "Disconnected" => "Disconnected",
        "Unavailable" => "Unavailable",
        "Stale" => "Stale",
        "Recovered" => "Recovered",
        "Partial" => "Partial",
        _ => "Current"
    };
}
