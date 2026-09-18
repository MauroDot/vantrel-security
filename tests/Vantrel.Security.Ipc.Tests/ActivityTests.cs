using Microsoft.Extensions.Logging.Abstractions;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class ActivityTests
{
    [TestMethod]
    public void First_sample_records_both_initial_observations_including_unavailable()
    {
        var status = new ServiceStatusStore();
        var store = new ActivityStore(status);
        Assert.IsNull(store.Snapshot());
        var sampled = DateTimeOffset.UtcNow;
        store.Update(Sample(sampled, null, WindowsFirewallHealth.Good));
        var result = store.Snapshot();
        Assert.IsNotNull(result);
        Assert.AreEqual(status.Snapshot().StartedAtUtc, result.ServiceStartedAtUtc);
        Assert.AreEqual(sampled, result.SampledThroughUtc);
        Assert.AreEqual(2, result.Entries.Length);
        Assert.AreEqual(ActivityCategory.Firewall, result.Entries[0].Category);
        Assert.AreEqual(ObservedHealth.Good, result.Entries[0].CurrentState);
        Assert.AreEqual(ActivityCategory.Antivirus, result.Entries[1].Category);
        Assert.AreEqual(ObservedHealth.Unavailable, result.Entries[1].CurrentState);
        Assert.IsTrue(result.Entries.All(entry => entry.IsInitial && entry.PreviousState is null &&
            entry.ObservedAtUtc == sampled));
    }

    [TestMethod]
    public void Changes_only_are_newest_first_and_evict_after_twelve_entries()
    {
        var store = new ActivityStore(new ServiceStatusStore());
        var start = DateTimeOffset.UtcNow;
        store.Update(Sample(start, WindowsAntivirusHealth.Good, WindowsFirewallHealth.Good));
        store.Update(Sample(start.AddSeconds(1), WindowsAntivirusHealth.Good, WindowsFirewallHealth.Good));
        Assert.AreEqual(2, store.Snapshot()!.Entries.Length);
        Assert.AreEqual(start.AddSeconds(1), store.Snapshot()!.SampledThroughUtc);
        store.Update(Sample(start.AddSeconds(2), WindowsAntivirusHealth.Poor, WindowsFirewallHealth.Good));
        var changed = store.Snapshot()!.Entries[0];
        Assert.AreEqual(ActivityObservationKind.Change, changed.Kind);
        Assert.AreEqual(ObservedHealth.Good, changed.PreviousState);
        Assert.AreEqual(ObservedHealth.Poor, changed.CurrentState);
        Assert.AreEqual(start.AddSeconds(2), changed.ObservedAtUtc);
        for (var index = 3; index < 17; index++)
            store.Update(Sample(start.AddSeconds(index), index % 2 == 0
                ? WindowsAntivirusHealth.Poor : WindowsAntivirusHealth.Good, WindowsFirewallHealth.Good));
        var result = store.Snapshot()!;
        Assert.AreEqual(12, result.Entries.Length);
        Assert.AreEqual(start.AddSeconds(16), result.SampledThroughUtc);
        Assert.AreEqual(start.AddSeconds(16), result.Entries[0].ObservedAtUtc);
        Assert.IsTrue(result.Entries.All(entry => entry.Kind == ActivityObservationKind.Change));
        for (var index = 1; index < result.Entries.Length; index++)
            Assert.IsTrue(result.Entries[index - 1].ObservedAtUtc > result.Entries[index].ObservedAtUtc);
    }

    [TestMethod]
    public void Every_documented_state_and_unavailable_are_distinct_observations()
    {
        var store = new ActivityStore(new ServiceStatusStore());
        var start = DateTimeOffset.UtcNow;
        WindowsAntivirusHealth?[] states = [WindowsAntivirusHealth.Good,
            WindowsAntivirusHealth.NotMonitored, WindowsAntivirusHealth.Poor,
            WindowsAntivirusHealth.Snoozed, null];
        for (var index = 0; index < states.Length; index++)
            store.Update(Sample(start.AddSeconds(index), states[index], null));
        var entries = store.Snapshot()!.Entries;
        Assert.AreEqual(6, entries.Length); // Two initial, then four antivirus changes.
        Assert.AreEqual(ObservedHealth.Unavailable, entries[0].CurrentState);
        Assert.AreEqual(ObservedHealth.Snoozed, entries[0].PreviousState);
        Assert.AreEqual(ObservedHealth.Snoozed, entries[1].CurrentState);
        Assert.AreEqual(ObservedHealth.Poor, entries[2].CurrentState);
        Assert.AreEqual(ObservedHealth.NotMonitored, entries[3].CurrentState);
        Assert.AreEqual(ObservedHealth.Good, entries[5].CurrentState);
    }

    [TestMethod]
    public async Task Snapshots_are_immutable_during_concurrent_reads_and_reset_with_new_store()
    {
        var start = DateTimeOffset.UtcNow;
        var first = new ActivityStore(new ServiceStatusStore());
        first.Update(Sample(start, null, null));
        var original = first.Snapshot()!;
        var readers = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            for (var count = 0; count < 500; count++)
            {
                var current = first.Snapshot()!;
                Assert.IsTrue(current.Entries.Length is >= 2 and <= 12);
            }
        })).ToArray();
        for (var index = 1; index < 20; index++)
            first.Update(Sample(start.AddSeconds(index), index % 2 == 0
                ? WindowsAntivirusHealth.Good : WindowsAntivirusHealth.Poor, null));
        await Task.WhenAll(readers);
        Assert.AreEqual(2, original.Entries.Length);
        Assert.AreEqual(ObservedHealth.Unavailable, original.Entries[0].CurrentState);
        var restarted = new ActivityStore(new ServiceStatusStore());
        Assert.IsNull(restarted.Snapshot());
        restarted.Update(Sample(DateTimeOffset.UtcNow, WindowsAntivirusHealth.Good, null));
        Assert.AreEqual(2, restarted.Snapshot()!.Entries.Length);
        Assert.IsTrue(restarted.Snapshot()!.Entries.All(entry => entry.IsInitial));
    }

    [TestMethod]
    public async Task Sampling_worker_updates_health_and_activity_outside_pipe()
    {
        var health = new SystemHealthStore();
        var activity = new ActivityStore(new ServiceStatusStore());
        var source = new WindowsSystemHealthSource(() => "10.0.1.0", () => 10,
            () => (100, 50), () => WindowsAntivirusHealth.Good,
            () => WindowsFirewallHealth.Good);
        using var worker = new SystemHealthWorker(health, activity, source,
            NullLogger<SystemHealthWorker>.Instance);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            while (activity.Snapshot() is null) await Task.Delay(10, timeout.Token);
            Assert.AreEqual(2, activity.Snapshot()!.Entries.Length);
            Assert.AreEqual(health.Snapshot().CollectedAtUtc, activity.Snapshot()!.SampledThroughUtc);
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    private static SystemHealthSnapshot Sample(DateTimeOffset time, WindowsAntivirusHealth? antivirus,
        WindowsFirewallHealth? firewall) => new(time, "10.0.1.0", 10, 100, 50, antivirus, firewall);
}
