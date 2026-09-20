using System.Collections.Immutable;

namespace Vantrel.Security.Core;

/// <summary>Minimal, session-scoped record of a published signed-installation evaluation.</summary>
public sealed record TrustedManifestIntegrityHistoryRecord(DateTimeOffset SampledAtUtc,
    TrustedManifestSignatureState SignatureState, TrustedManifestInstallationEvaluation Evaluation);

/// <summary>Immutable newest-first history of published signed-installation evaluations.</summary>
public sealed record TrustedManifestIntegrityHistorySnapshot(DateTimeOffset ServiceStartedAtUtc,
    DateTimeOffset CapturedAtUtc, ImmutableArray<TrustedManifestIntegrityHistoryRecord> Entries);

public enum TrustedManifestIntegrityHistoryDisplayState { Disconnected, Unavailable, Empty, Current, Recovered, Reset }

public static class TrustedManifestIntegrityHistoryPresentation
{
    public static TrustedManifestIntegrityHistoryDisplayState State(TrustedManifestIntegrityHistorySnapshot? value,
        bool connected, bool wasDisconnected = false, bool sessionChanged = false) =>
        !connected ? TrustedManifestIntegrityHistoryDisplayState.Disconnected :
        value is null ? TrustedManifestIntegrityHistoryDisplayState.Unavailable :
        sessionChanged ? TrustedManifestIntegrityHistoryDisplayState.Reset :
        value.Entries.Length == 0 ? TrustedManifestIntegrityHistoryDisplayState.Empty :
        wasDisconnected ? TrustedManifestIntegrityHistoryDisplayState.Recovered :
        TrustedManifestIntegrityHistoryDisplayState.Current;
}

public interface ITrustedManifestIntegrityHistoryClient
{
    Task<TrustedManifestIntegrityHistorySnapshot?> GetTrustedManifestIntegrityHistoryAsync(CancellationToken cancellationToken);
}
