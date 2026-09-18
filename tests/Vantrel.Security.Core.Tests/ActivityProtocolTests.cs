using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class ActivityProtocolTests
{
    private static readonly DateTimeOffset Started = DateTimeOffset.UtcNow.AddMinutes(-5);
    private static readonly DateTimeOffset Sampled = DateTimeOffset.UtcNow.AddMinutes(-1);

    [TestMethod]
    public void Fixed_request_is_version_one_and_rejects_parameters()
    {
        Assert.AreEqual(StatusProtocol.RequestKind.Activity,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateActivityRequest()));
        foreach (var request in new[]
        {
            "{\"ProtocolVersion\":1,\"Type\":\"get_activity\",\"Category\":0}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_activity\",\"Path\":\"C:\\\\Windows\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_activity\",\"Type\":\"get_activity\"}",
            "{\"ProtocolVersion\":2,\"Type\":\"get_activity\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"execute\"}"
        }) Assert.AreEqual(StatusProtocol.RequestKind.Invalid,
            StatusProtocol.ReadRequestKind(Encoding.UTF8.GetBytes(request)));
        Assert.AreEqual(StatusProtocol.RequestKind.Invalid,
            StatusProtocol.ReadRequestKind(new byte[StatusProtocol.MaximumMessageBytes + 1]));
        Assert.AreEqual(StatusProtocol.RequestKind.Status,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateRequest()));
        Assert.AreEqual(StatusProtocol.RequestKind.SystemHealth,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateSystemHealthRequest()));
    }

    [TestMethod]
    public void Typed_response_preserves_initial_and_change_observations()
    {
        var snapshot = Snapshot(new ActivityObservation(ActivityCategory.Antivirus,
            ActivityObservationKind.Initial, null, ObservedHealth.Unavailable, Started),
            new ActivityObservation(ActivityCategory.Firewall, ActivityObservationKind.Change,
                ObservedHealth.Poor, ObservedHealth.Good, Sampled));
        var encoded = StatusProtocol.CreateActivityResponse(snapshot);
        Assert.IsTrue(StatusProtocol.TryReadActivityResponse(encoded, out var decoded, out var failure));
        Assert.AreEqual(StatusResponseFailure.None, failure);
        Assert.IsNotNull(decoded);
        Assert.AreEqual(snapshot.ServiceStartedAtUtc, decoded.ServiceStartedAtUtc);
        Assert.AreEqual(snapshot.SampledThroughUtc, decoded.SampledThroughUtc);
        CollectionAssert.AreEqual(snapshot.Entries.ToArray(), decoded.Entries.ToArray());
        Assert.IsTrue(decoded.Entries[0].IsInitial);
        Assert.IsFalse(decoded.Entries[1].IsInitial);
    }

    [TestMethod]
    public void Every_supported_state_and_maximum_history_fit_in_frame()
    {
        var states = Enum.GetValues<ObservedHealth>();
        var entries = Enumerable.Range(0, 12).Select(index => new ActivityObservation(
            index % 2 == 0 ? ActivityCategory.Antivirus : ActivityCategory.Firewall,
            ActivityObservationKind.Change, states[(index + 1) % states.Length],
            states[index % states.Length], Sampled))
            .ToArray();
        var encoded = StatusProtocol.CreateActivityResponse(Snapshot(entries));
        Assert.IsTrue(encoded.Length <= StatusProtocol.MaximumMessageBytes, $"Frame was {encoded.Length} bytes.");
        Assert.IsTrue(StatusProtocol.TryReadActivityResponse(encoded, out var parsed, out _));
        Assert.AreEqual(12, parsed!.Entries.Length);
    }

    [TestMethod]
    public void Response_rejects_unknown_values_invalid_transitions_and_extra_fields()
    {
        var valid = new ActivityObservation(ActivityCategory.Firewall, ActivityObservationKind.Initial,
            null, ObservedHealth.Good, Sampled);
        foreach (var invalid in new[]
        {
            valid with { Category = (ActivityCategory)99 },
            valid with { Kind = (ActivityObservationKind)99 },
            valid with { CurrentState = (ObservedHealth)99 },
            valid with { PreviousState = ObservedHealth.Good },
            valid with { Kind = ActivityObservationKind.Change },
            valid with { Kind = ActivityObservationKind.Change, PreviousState = ObservedHealth.Good },
            valid with { ObservedAtUtc = Sampled.AddMinutes(1) }
        })
        {
            Assert.IsFalse(StatusProtocol.TryReadActivityResponse(
                StatusProtocol.CreateActivityResponse(Snapshot(invalid)), out _, out var failure));
            Assert.AreEqual(StatusResponseFailure.InvalidActivity, failure);
        }
        var response = Encoding.UTF8.GetString(StatusProtocol.CreateActivityResponse(Snapshot(valid)));
        Assert.IsFalse(StatusProtocol.TryReadActivityResponse(
            Encoding.UTF8.GetBytes(response.Replace("\"Kind\":0", "\"Kind\":0,\"Path\":\"x\"")),
            out _, out var extra));
        Assert.AreEqual(StatusResponseFailure.InvalidActivity, extra);
        Assert.IsFalse(StatusProtocol.TryReadActivityResponse(
            Encoding.UTF8.GetBytes(response.Replace("\"PreviousState\":null,", "")),
            out _, out var missing));
        Assert.AreEqual(StatusResponseFailure.InvalidActivity, missing);
    }

    [TestMethod]
    public void Response_rejects_malformed_oversized_wrong_type_and_over_capacity()
    {
        Assert.IsFalse(StatusProtocol.TryReadActivityResponse(Encoding.UTF8.GetBytes("not json"), out _,
            out var malformed));
        Assert.AreEqual(StatusResponseFailure.MalformedJson, malformed);
        Assert.IsFalse(StatusProtocol.TryReadActivityResponse(new byte[4097], out _, out var oversized));
        Assert.AreEqual(StatusResponseFailure.Oversized, oversized);
        var valid = StatusProtocol.CreateActivityResponse(Snapshot());
        using var document = JsonDocument.Parse(valid);
        var wrongType = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(valid).Replace(
            "\"Type\":\"activity\"", "\"Type\":\"status\""));
        Assert.IsFalse(StatusProtocol.TryReadActivityResponse(wrongType, out _, out var wrong));
        Assert.AreEqual(StatusResponseFailure.UnexpectedType, wrong);
        var tooMany = Enumerable.Range(0, 13).Select(_ => new ActivityObservation(ActivityCategory.Antivirus,
            ActivityObservationKind.Initial, null, ObservedHealth.Good, Sampled)).ToArray();
        Assert.IsFalse(StatusProtocol.TryReadActivityResponse(
            StatusProtocol.CreateActivityResponse(Snapshot(tooMany)), out _, out var capacity));
        Assert.AreEqual(StatusResponseFailure.InvalidActivity, capacity);
    }

    [TestMethod]
    public void Presentation_distinguishes_disconnected_unavailable_empty_stale_and_current()
    {
        var now = DateTimeOffset.UtcNow;
        var current = new ActivitySnapshot(now.AddMinutes(-1), now, ImmutableArray<ActivityObservation>.Empty);
        Assert.AreEqual(ActivityDisplayState.Disconnected, ActivityPresentation.State(current, false, now));
        Assert.AreEqual(ActivityDisplayState.Unavailable, ActivityPresentation.State(null, true, now));
        Assert.AreEqual(ActivityDisplayState.Empty, ActivityPresentation.State(current, true, now));
        Assert.AreEqual(ActivityDisplayState.Stale, ActivityPresentation.State(
            current with { SampledThroughUtc = now.AddMinutes(-3) }, true, now));
        Assert.AreEqual(ActivityDisplayState.Current, ActivityPresentation.State(Snapshot(
            new ActivityObservation(ActivityCategory.Antivirus, ActivityObservationKind.Initial,
                null, ObservedHealth.Good, Sampled)), true, now));
        Assert.AreEqual(ActivityDisplayState.Recovered, ActivityPresentation.State(Snapshot(
            new ActivityObservation(ActivityCategory.Antivirus, ActivityObservationKind.Initial,
                null, ObservedHealth.Good, Sampled)), true, now, wasDisconnected: true));
    }

    private static ActivitySnapshot Snapshot(params ActivityObservation[] entries) =>
        new(Started, Sampled, entries.ToImmutableArray());
}
