using System.Collections.Immutable;
using Vantrel.Security.Core;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class IntegrityRefreshAuditPresentationTests
{
    [TestMethod]
    public void Presentation_distinguishes_empty_current_disconnected_unavailable_and_recovered_states()
    {
        var empty = Snapshot([]);
        Assert.AreEqual(IntegrityRefreshAuditDisplayState.Empty, IntegrityRefreshAuditPresentation.State(empty, true));
        Assert.AreEqual(IntegrityRefreshAuditDisplayState.Unavailable, IntegrityRefreshAuditPresentation.State(null, true));
        Assert.AreEqual(IntegrityRefreshAuditDisplayState.Disconnected, IntegrityRefreshAuditPresentation.State(empty, false));
        Assert.AreEqual(IntegrityRefreshAuditDisplayState.Recovered, IntegrityRefreshAuditPresentation.State(Snapshot([Entry()]), true, true));
        Assert.AreEqual(IntegrityRefreshAuditDisplayState.Current, IntegrityRefreshAuditPresentation.State(Snapshot([Entry()]), true));
    }

    [TestMethod]
    public void New_service_session_has_no_entries_and_audit_entry_has_no_command_input_or_integrity_truth()
    {
        var reset = Snapshot([]);
        Assert.AreEqual(0, reset.Entries.Length);
        var entry = Entry();
        Assert.AreEqual(IntegrityRefreshAuditCommandKind.RefreshTrustedManifestIntegrity, entry.Command);
        Assert.AreEqual(CommandCallerClassification.InteractiveUser, entry.Caller);
        Assert.AreEqual(IntegrityRefreshAuditOutcome.Completed, entry.Outcome);
        Assert.IsTrue(typeof(IntegrityRefreshAuditRecord).GetProperties().Select(property => property.Name)
            .OrderBy(name => name).SequenceEqual(new[] { "Caller", "Command", "OccurredAtUtc", "Outcome" }));
    }

    private static IntegrityRefreshAuditSnapshot Snapshot(ImmutableArray<IntegrityRefreshAuditRecord> entries)
    {
        var now = DateTimeOffset.UtcNow;
        return new IntegrityRefreshAuditSnapshot(now.AddMinutes(-1), now, entries);
    }

    private static IntegrityRefreshAuditRecord Entry() => new(IntegrityRefreshAuditCommandKind.RefreshTrustedManifestIntegrity,
        CommandCallerClassification.InteractiveUser, IntegrityRefreshAuditOutcome.Completed, DateTimeOffset.UtcNow);
}
