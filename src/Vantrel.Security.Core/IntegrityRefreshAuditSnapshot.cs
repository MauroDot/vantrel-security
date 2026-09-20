using System.Collections.Immutable;

namespace Vantrel.Security.Core;

/// <summary>Safe, session-scoped projection of authorized integrity-refresh lifecycle records.</summary>
public enum IntegrityRefreshAuditCommandKind { RefreshTrustedManifestIntegrity }
public enum IntegrityRefreshAuditOutcome { Accepted, AlreadyInProgress, Duplicate, RateLimited, Completed, Failed, Cancelled }

public sealed record IntegrityRefreshAuditRecord(IntegrityRefreshAuditCommandKind Command,
    CommandCallerClassification Caller, IntegrityRefreshAuditOutcome Outcome, DateTimeOffset OccurredAtUtc);

public sealed record IntegrityRefreshAuditSnapshot(DateTimeOffset ServiceStartedAtUtc,
    DateTimeOffset CapturedAtUtc, ImmutableArray<IntegrityRefreshAuditRecord> Entries);

public enum IntegrityRefreshAuditDisplayState { Disconnected, Unavailable, Empty, Current, Recovered }

public static class IntegrityRefreshAuditPresentation
{
    public static IntegrityRefreshAuditDisplayState State(IntegrityRefreshAuditSnapshot? value, bool connected,
        bool wasDisconnected = false) => !connected ? IntegrityRefreshAuditDisplayState.Disconnected :
        value is null ? IntegrityRefreshAuditDisplayState.Unavailable : value.Entries.Length == 0 ?
        IntegrityRefreshAuditDisplayState.Empty : wasDisconnected ? IntegrityRefreshAuditDisplayState.Recovered :
        IntegrityRefreshAuditDisplayState.Current;
}

public interface IIntegrityRefreshAuditClient
{
    Task<IntegrityRefreshAuditSnapshot?> GetIntegrityRefreshAuditAsync(CancellationToken cancellationToken);
}
