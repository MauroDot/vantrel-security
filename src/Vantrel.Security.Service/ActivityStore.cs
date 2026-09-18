using System.Collections.Immutable;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public sealed class ActivityStore(ServiceStatusStore statusStore)
{
    private readonly object _gate = new();
    private readonly DateTimeOffset _startedAtUtc = statusStore.Snapshot().StartedAtUtc;
    private ActivitySnapshot? _snapshot;
    private ObservedHealth _antivirus;
    private ObservedHealth _firewall;

    public ActivitySnapshot? Snapshot() => Volatile.Read(ref _snapshot);

    public void Update(SystemHealthSnapshot sample)
    {
        lock (_gate)
        {
            var previous = _snapshot;
            var entries = previous?.Entries.ToList() ?? [];
            var antivirus = Map(sample.AntivirusHealth);
            var firewall = Map(sample.FirewallHealth);
            if (previous is null || _antivirus != antivirus)
                entries.Insert(0, new ActivityObservation(ActivityCategory.Antivirus,
                    previous is null ? ActivityObservationKind.Initial : ActivityObservationKind.Change,
                    previous is null ? null : _antivirus, antivirus, sample.CollectedAtUtc));
            if (previous is null || _firewall != firewall)
                entries.Insert(0, new ActivityObservation(ActivityCategory.Firewall,
                    previous is null ? ActivityObservationKind.Initial : ActivityObservationKind.Change,
                    previous is null ? null : _firewall, firewall, sample.CollectedAtUtc));
            if (entries.Count > 12) entries.RemoveRange(12, entries.Count - 12);
            _antivirus = antivirus;
            _firewall = firewall;
            Volatile.Write(ref _snapshot, new ActivitySnapshot(_startedAtUtc,
                sample.CollectedAtUtc, entries.ToImmutableArray()));
        }
    }

    private static ObservedHealth Map(WindowsAntivirusHealth? health) => health switch
    {
        WindowsAntivirusHealth.Good => ObservedHealth.Good,
        WindowsAntivirusHealth.NotMonitored => ObservedHealth.NotMonitored,
        WindowsAntivirusHealth.Poor => ObservedHealth.Poor,
        WindowsAntivirusHealth.Snoozed => ObservedHealth.Snoozed,
        _ => ObservedHealth.Unavailable
    };

    private static ObservedHealth Map(WindowsFirewallHealth? health) => health switch
    {
        WindowsFirewallHealth.Good => ObservedHealth.Good,
        WindowsFirewallHealth.NotMonitored => ObservedHealth.NotMonitored,
        WindowsFirewallHealth.Poor => ObservedHealth.Poor,
        WindowsFirewallHealth.Snoozed => ObservedHealth.Snoozed,
        _ => ObservedHealth.Unavailable
    };
}
