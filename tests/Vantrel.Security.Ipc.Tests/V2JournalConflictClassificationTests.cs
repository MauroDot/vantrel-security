using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class V2JournalConflictClassificationTests
{
    private const string PriorHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string TargetHash = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string Id = "0123456789abcdef0123456789abcdef";
    private const string BackupId = "fedcba9876543210fedcba9876543210";
    private static readonly DateTimeOffset Updated = new(2026, 10, 12, 0, 0, 0, TimeSpan.Zero);

    [DataTestMethod]
    [DataRow(1, 1, 0)]
    [DataRow(0, 1, 1)]
    [DataRow(1, 0, 2)]
    [DataRow(0, 0, 3)]
    [DataRow(3, 1, 3)]
    [DataRow(1, 3, 3)]
    [DataRow(2, 1, 3)]
    [DataRow(1, 2, 3)]
    public void Every_valid_and_unavailable_pair_has_one_closed_classification(
        int historical, int v2, int expected)
    {
        Assert.AreEqual((V1V2JournalPresence)expected, V1V2JournalConflictClassifier.Classify(
            Historical((JournalReadState)historical), V2((V2JournalReadState)v2)));
    }

    [TestMethod]
    public void Inconsistent_store_observations_are_never_treated_as_absence()
    {
        var absentWithJournal = new JournalReadResult(HistoricalJournal(),
            UpdateTransactionJournalParseFailure.Unavailable, JournalReadState.Absent);
        var presentWithoutJournal = new V2JournalReadResult(null,
            UpdateTransactionJournalParseFailure.None, V2JournalReadState.Present);
        var missingWithJournal = new V2JournalReadResult(V2Journal(),
            UpdateTransactionJournalParseFailure.Unavailable, V2JournalReadState.MissingInfrastructure);

        Assert.AreEqual(V1V2JournalPresence.ConflictOrUnavailable,
            V1V2JournalConflictClassifier.Classify(absentWithJournal, V2(V2JournalReadState.Absent)));
        Assert.AreEqual(V1V2JournalPresence.ConflictOrUnavailable,
            V1V2JournalConflictClassifier.Classify(Historical(JournalReadState.Absent), presentWithoutJournal));
        Assert.AreEqual(V1V2JournalPresence.ConflictOrUnavailable,
            V1V2JournalConflictClassifier.Classify(Historical(JournalReadState.Absent), missingWithJournal));
    }

    private static JournalReadResult Historical(JournalReadState state) => state switch
    {
        JournalReadState.Present => new(HistoricalJournal(), UpdateTransactionJournalParseFailure.None, state),
        JournalReadState.Invalid => new(null, UpdateTransactionJournalParseFailure.Malformed, state),
        _ => new(null, UpdateTransactionJournalParseFailure.Unavailable, state)
    };

    private static V2JournalReadResult V2(V2JournalReadState state) => state switch
    {
        V2JournalReadState.Present => new(V2Journal(), UpdateTransactionJournalParseFailure.None, state),
        V2JournalReadState.Invalid => new(null, UpdateTransactionJournalParseFailure.Malformed, state),
        _ => new(null, UpdateTransactionJournalParseFailure.Unavailable, state)
    };

    private static UpdateTransactionJournal HistoricalJournal() => new(
        Id, 1, PriorHash, 2, TargetHash, UpdateTransactionPhase.Prepared, BackupId, Updated);

    private static V2UpdateTransactionJournal V2Journal() => new(
        Id, new(ReleaseGeneration.V2, 1, PriorHash), new(ReleaseGeneration.V2, 2, TargetHash),
        V2UpdateTransactionPhase.Admitted, BackupId, Updated);
}
