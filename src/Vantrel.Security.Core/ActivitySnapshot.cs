using System.Collections.Immutable;

namespace Vantrel.Security.Core;

public enum ActivityCategory { Antivirus, Firewall }

public enum ObservedHealth { Unavailable, Good, NotMonitored, Poor, Snoozed }
public enum ActivityObservationKind { Initial, Change }

/// <summary>An initial observation has no previous state. Times are sample times, not transition times.</summary>
public sealed record ActivityObservation(ActivityCategory Category, ActivityObservationKind Kind,
    ObservedHealth? PreviousState,
    ObservedHealth CurrentState, DateTimeOffset ObservedAtUtc)
{
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsInitial => Kind == ActivityObservationKind.Initial;
}

/// <summary>Bounded, memory-only Windows-reported category observations for one service process.</summary>
public sealed record ActivitySnapshot(DateTimeOffset ServiceStartedAtUtc, DateTimeOffset SampledThroughUtc,
    ImmutableArray<ActivityObservation> Entries);

public enum ActivityDisplayState { Disconnected, Unavailable, Stale, Empty, Current, Recovered }

public static class ActivityPresentation
{
    public static ActivityDisplayState State(ActivitySnapshot? snapshot, bool connected, DateTimeOffset now,
        bool wasDisconnected = false)
    {
        if (!connected) return ActivityDisplayState.Disconnected;
        if (snapshot is null) return ActivityDisplayState.Unavailable;
        if (now - snapshot.SampledThroughUtc > TimeSpan.FromMinutes(2)) return ActivityDisplayState.Stale;
        if (snapshot.Entries.IsDefaultOrEmpty) return ActivityDisplayState.Empty;
        return wasDisconnected ? ActivityDisplayState.Recovered : ActivityDisplayState.Current;
    }
}

public interface IActivityClient
{
    Task<ActivitySnapshot?> GetActivityAsync(CancellationToken cancellationToken);
}
