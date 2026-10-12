using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class V2UpdateTransactionProtocolTests
{
    private const string TransactionId = "0123456789abcdef0123456789abcdef";
    private const string BackupId = "fedcba9876543210fedcba9876543210";
    private const string Nonce = "v2-00112233445566778899aabbccddeeff";
    private const string HistoricalNonce = "00112233445566778899aabbccddeeff";
    private const string PredecessorHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string TargetHash = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private static readonly DateTimeOffset Timestamp = new(2026, 10, 12, 15, 30, 0, TimeSpan.Zero);
    private static readonly UTF8Encoding Utf8 = new(false, true);

    [TestMethod]
    public void Journal_has_exact_canonical_v3_bytes_and_round_trips()
    {
        var journal = Sample();
        var expected = $"schema=vantrel-update-transaction-v3\n" +
            $"transaction-id={TransactionId}\n" +
            $"backup-id={BackupId}\n" +
            "predecessor-generation=v2\n" +
            "predecessor-release-sequence=7\n" +
            $"predecessor-manifest-sha256={PredecessorHash}\n" +
            "target-generation=v2\n" +
            "target-release-sequence=8\n" +
            $"target-manifest-sha256={TargetHash}\n" +
            "phase=Admitted\n" +
            "updated-at-utc=2026-10-12T15:30:00Z\n" +
            "recovery-start-nonce=\n";

        var bytes = V2UpdateTransactionJournalCodec.Serialize(journal);
        CollectionAssert.AreEqual(Utf8.GetBytes(expected), bytes);
        Assert.IsTrue(V2UpdateTransactionJournalCodec.TryParse(bytes, out var parsed, out var failure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.None, failure);
        Assert.AreEqual(journal, parsed);
        CollectionAssert.AreEqual(bytes, V2UpdateTransactionJournalCodec.Serialize(parsed!));
    }

    [TestMethod]
    public void Every_phase_is_canonical_and_nonce_is_scoped_to_authorization()
    {
        foreach (var phase in Enum.GetValues<V2UpdateTransactionPhase>())
        {
            var journal = Sample() with
            {
                Phase = phase,
                RecoveryStartNonce = phase == V2UpdateTransactionPhase.RollbackRestartAuthorized ? Nonce : null
            };
            var bytes = V2UpdateTransactionJournalCodec.Serialize(journal);
            Assert.IsTrue(V2UpdateTransactionJournalCodec.TryParse(bytes, out var parsed, out var failure), phase.ToString());
            Assert.AreEqual(UpdateTransactionJournalParseFailure.None, failure);
            Assert.AreEqual(journal, parsed);
        }

        Assert.ThrowsException<ArgumentException>(() => V2UpdateTransactionJournalCodec.Serialize(
            Sample() with { RecoveryStartNonce = Nonce }));
        Assert.ThrowsException<ArgumentException>(() => V2UpdateTransactionJournalCodec.Serialize(
            Sample() with { Phase = V2UpdateTransactionPhase.RollbackRestartAuthorized }));
    }

    [TestMethod]
    public void Journal_rejects_invalid_identifiers_generations_sequences_hashes_and_times()
    {
        var valid = Sample();
        var invalid = new[]
        {
            valid with { TransactionId = TransactionId.ToUpperInvariant() },
            valid with { BackupId = "abc" },
            valid with { Predecessor = valid.Predecessor with { Generation = ReleaseGeneration.V1 } },
            valid with { Target = valid.Target with { Generation = ReleaseGeneration.V1 } },
            valid with { Predecessor = valid.Predecessor with { ReleaseSequence = 0 } },
            valid with { Target = valid.Target with { ReleaseSequence = 7 } },
            valid with { Target = valid.Target with { ReleaseSequence = 6 } },
            valid with { Target = valid.Target with { ManifestSha256 = TargetHash.ToLowerInvariant() } },
            valid with { UpdatedAtUtc = Timestamp.AddTicks(1) },
            valid with { UpdatedAtUtc = Timestamp.ToOffset(TimeSpan.FromHours(-5)) },
            valid with { Phase = (V2UpdateTransactionPhase)int.MaxValue }
        };
        foreach (var journal in invalid)
            Assert.ThrowsException<ArgumentException>(() => V2UpdateTransactionJournalCodec.Serialize(journal));
    }

    [TestMethod]
    public void Parser_rejects_noncanonical_framing_and_values()
    {
        var canonical = Utf8.GetString(V2UpdateTransactionJournalCodec.Serialize(Sample()));
        var malformed = new[]
        {
            canonical.Replace("transaction-id=", "transaction-id=0"),
            canonical.Replace("backup-id=", "backup-id=0"),
            canonical.Replace("predecessor-generation=v2", "predecessor-generation=v1"),
            canonical.Replace("target-generation=v2", "target-generation=v1"),
            canonical.Replace("predecessor-release-sequence=7", "predecessor-release-sequence=07"),
            canonical.Replace("target-release-sequence=8", "target-release-sequence=7"),
            canonical.Replace("target-release-sequence=8", "target-release-sequence=18446744073709551616"),
            canonical.Replace("target-manifest-sha256=" + TargetHash, "target-manifest-sha256=" + TargetHash.ToLowerInvariant()),
            canonical.Replace("phase=Admitted", "phase=admitted"),
            canonical.Replace("phase=Admitted", "phase=0"),
            canonical.Replace("phase=Admitted", "phase=RollbackRestartAuthorized"),
            canonical.Replace("recovery-start-nonce=\n", "recovery-start-nonce=" + Nonce + "\n"),
            canonical.Replace("updated-at-utc=2026-10-12T15:30:00Z", "updated-at-utc=2026-10-12T10:30:00-05:00"),
            canonical.Replace("updated-at-utc=2026-10-12T15:30:00Z", "updated-at-utc=2026-10-12T15:30:00.000Z"),
            canonical.Replace("updated-at-utc=2026-10-12T15:30:00Z", "updated-at-utc=2026-02-30T15:30:00Z"),
            canonical.Replace("updated-at-utc=2026-10-12T15:30:00Z", "updated-at-utc=2026-10-12T25:30:00Z"),
            canonical.Replace("\n", "\r\n"),
            canonical[..^1],
            canonical + "\0",
            canonical + "extra=value\n",
            canonical.Replace("backup-id=" + BackupId + "\n", string.Empty),
            canonical.Replace("backup-id=" + BackupId + "\n", "backup-id=" + BackupId + "\nbackup-id=" + BackupId + "\n"),
            "\ufeff" + canonical,
            canonical.Replace("transaction-id=" + TransactionId + "\nbackup-id=" + BackupId,
                "backup-id=" + BackupId + "\ntransaction-id=" + TransactionId)
        };
        foreach (var text in malformed)
        {
            Assert.IsFalse(V2UpdateTransactionJournalCodec.TryParse(Utf8.GetBytes(text), out var parsed, out var failure), text);
            Assert.IsNull(parsed);
            Assert.AreEqual(UpdateTransactionJournalParseFailure.Malformed, failure);
        }

        Assert.IsFalse(V2UpdateTransactionJournalCodec.TryParse([0xC3, 0x28], out _, out var utf8Failure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Malformed, utf8Failure);
        Assert.IsFalse(V2UpdateTransactionJournalCodec.TryParse(new byte[V2UpdateTransactionJournalCodec.MaximumBytes + 1], out _, out var sizeFailure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Malformed, sizeFailure);
        Assert.IsFalse(V2UpdateTransactionJournalCodec.TryParse([], out _, out var absentFailure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Unavailable, absentFailure);
    }

    [TestMethod]
    public void Parser_treats_other_transaction_schemas_as_unsupported()
    {
        var historicalJournal = new UpdateTransactionJournal(TransactionId, 7, PredecessorHash, 8,
            TargetHash, UpdateTransactionPhase.Prepared, BackupId, Timestamp);
        var historicalBytes = UpdateTransactionJournalCodec.Serialize(historicalJournal);
        Assert.IsTrue(UpdateTransactionJournalCodec.TryParse(historicalBytes, out var historicalRoundTrip, out var validHistoricalFailure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.None, validHistoricalFailure);
        Assert.AreEqual(historicalJournal, historicalRoundTrip);
        Assert.IsFalse(V2UpdateTransactionJournalCodec.TryParse(historicalBytes, out var rejectedHistorical, out var v2Failure));
        Assert.IsNull(rejectedHistorical);
        Assert.AreEqual(UpdateTransactionJournalParseFailure.UnsupportedSchema, v2Failure);

        var canonical = Utf8.GetString(V2UpdateTransactionJournalCodec.Serialize(Sample()));
        foreach (var schema in new[] { UpdateTransactionJournalCodec.Schema, UpdateTransactionJournalCodec.LegacySchema, "future-schema" })
        {
            var text = canonical.Replace(V2UpdateTransactionJournalCodec.Schema, schema);
            Assert.IsFalse(V2UpdateTransactionJournalCodec.TryParse(Utf8.GetBytes(text), out _, out var failure));
            Assert.AreEqual(UpdateTransactionJournalParseFailure.UnsupportedSchema, failure);
        }

        var v2JournalBytes = V2UpdateTransactionJournalCodec.Serialize(Sample());
        Assert.IsTrue(V2UpdateTransactionJournalCodec.TryParse(v2JournalBytes, out var v2RoundTrip, out var validV2Failure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.None, validV2Failure);
        Assert.AreEqual(Sample(), v2RoundTrip);
        Assert.IsFalse(UpdateTransactionJournalCodec.TryParse(v2JournalBytes, out var historical, out var historicalFailure));
        Assert.IsNull(historical);
        Assert.AreEqual(UpdateTransactionJournalParseFailure.UnsupportedSchema, historicalFailure);
    }

    [TestMethod]
    public void Recovery_nonces_are_generation_separated_in_both_codecs()
    {
        Assert.IsTrue(V2UpdateTransactionJournalCodec.IsNonce(Nonce));
        Assert.IsFalse(UpdateTransactionJournalCodec.IsNonce(Nonce));
        Assert.IsTrue(UpdateTransactionJournalCodec.IsNonce(HistoricalNonce));
        Assert.IsFalse(V2UpdateTransactionJournalCodec.IsNonce(HistoricalNonce));

        var v2Authorized = Sample() with
        {
            Phase = V2UpdateTransactionPhase.RollbackRestartAuthorized,
            RecoveryStartNonce = Nonce
        };
        var v2Bytes = V2UpdateTransactionJournalCodec.Serialize(v2Authorized);
        Assert.IsTrue(V2UpdateTransactionJournalCodec.TryParse(v2Bytes, out var parsedV2, out _));
        Assert.AreEqual(v2Authorized, parsedV2);
        var v2WithHistoricalNonce = Utf8.GetBytes(Utf8.GetString(v2Bytes).Replace(Nonce, HistoricalNonce));
        Assert.IsFalse(V2UpdateTransactionJournalCodec.TryParse(v2WithHistoricalNonce, out _, out var v2Failure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Malformed, v2Failure);

        var historicalAuthorized = new UpdateTransactionJournal(TransactionId, 7, PredecessorHash, 8, TargetHash,
            UpdateTransactionPhase.RollbackRestartAuthorized, BackupId, Timestamp, HistoricalNonce);
        var historicalBytes = UpdateTransactionJournalCodec.Serialize(historicalAuthorized);
        Assert.IsTrue(UpdateTransactionJournalCodec.TryParse(historicalBytes, out var parsedHistorical, out _));
        Assert.AreEqual(historicalAuthorized, parsedHistorical);
        var historicalWithV2Nonce = Utf8.GetBytes(Utf8.GetString(historicalBytes).Replace(HistoricalNonce, Nonce));
        Assert.IsFalse(UpdateTransactionJournalCodec.TryParse(historicalWithV2Nonce, out _, out var historicalFailure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Malformed, historicalFailure);
    }

    [TestMethod]
    public void Phase_graph_has_only_the_specified_forward_and_rollback_edges()
    {
        var forward = new[]
        {
            V2UpdateTransactionPhase.Admitted, V2UpdateTransactionPhase.PrivateReady,
            V2UpdateTransactionPhase.BackupReady, V2UpdateTransactionPhase.TargetReady,
            V2UpdateTransactionPhase.StopPending, V2UpdateTransactionPhase.Stopped,
            V2UpdateTransactionPhase.DetachPending, V2UpdateTransactionPhase.PredecessorDetached,
            V2UpdateTransactionPhase.ActivatePending, V2UpdateTransactionPhase.TargetActive,
            V2UpdateTransactionPhase.StartPending, V2UpdateTransactionPhase.TargetStarted,
            V2UpdateTransactionPhase.TargetHealthy, V2UpdateTransactionPhase.PolicyCommitPending,
            V2UpdateTransactionPhase.PolicyCommitted, V2UpdateTransactionPhase.Completed
        };
        var rollback = new[]
        {
            V2UpdateTransactionPhase.RollbackRequired, V2UpdateTransactionPhase.RollbackStopPending,
            V2UpdateTransactionPhase.RollbackStopped, V2UpdateTransactionPhase.RollbackTargetDetachPending,
            V2UpdateTransactionPhase.RollbackTargetDetached, V2UpdateTransactionPhase.RollbackPredecessorRestorePending,
            V2UpdateTransactionPhase.RollbackPredecessorRestored, V2UpdateTransactionPhase.RollbackRestartAuthorized,
            V2UpdateTransactionPhase.RollbackRestartConsumed, V2UpdateTransactionPhase.PredecessorHealthy,
            V2UpdateTransactionPhase.RolledBack
        };
        var edges = new HashSet<(V2UpdateTransactionPhase, V2UpdateTransactionPhase)>();
        AddLinearEdges(forward, edges);
        AddLinearEdges(rollback, edges);
        foreach (var phase in forward[4..13]) edges.Add((phase, V2UpdateTransactionPhase.RollbackRequired));
        foreach (var from in Enum.GetValues<V2UpdateTransactionPhase>())
            foreach (var to in Enum.GetValues<V2UpdateTransactionPhase>())
                Assert.AreEqual(edges.Contains((from, to)), V2UpdateTransactionStateMachine.CanTransition(from, to), $"{from} -> {to}");
        Assert.IsFalse(V2UpdateTransactionStateMachine.CanTransition(V2UpdateTransactionPhase.PolicyCommitPending,
            V2UpdateTransactionPhase.RollbackRequired));
        Assert.IsFalse(V2UpdateTransactionStateMachine.CanTransition(V2UpdateTransactionPhase.PolicyCommitted,
            V2UpdateTransactionPhase.RollbackRequired));
    }

    [TestMethod]
    public void Transition_requires_authorization_nonce_and_consumption_removes_it()
    {
        var admitted = Sample();
        var privateReady = V2UpdateTransactionStateMachine.Transition(admitted,
            V2UpdateTransactionPhase.PrivateReady, Timestamp.AddSeconds(1));
        Assert.AreEqual(admitted.TransactionId, privateReady.TransactionId);
        Assert.AreEqual(admitted.BackupId, privateReady.BackupId);
        Assert.AreEqual(admitted.Predecessor, privateReady.Predecessor);
        Assert.AreEqual(admitted.Target, privateReady.Target);
        Assert.AreEqual(Timestamp.AddSeconds(1), privateReady.UpdatedAtUtc);

        var restored = Sample() with { Phase = V2UpdateTransactionPhase.RollbackPredecessorRestored };
        Assert.ThrowsException<ArgumentException>(() => V2UpdateTransactionStateMachine.Transition(restored,
            V2UpdateTransactionPhase.RollbackRestartAuthorized, Timestamp.AddSeconds(1)));
        var authorized = V2UpdateTransactionStateMachine.Transition(restored,
            V2UpdateTransactionPhase.RollbackRestartAuthorized, Timestamp.AddSeconds(1), Nonce);
        Assert.AreEqual(Nonce, authorized.RecoveryStartNonce);
        var consumed = V2UpdateTransactionStateMachine.Transition(authorized,
            V2UpdateTransactionPhase.RollbackRestartConsumed, Timestamp.AddSeconds(2));
        Assert.IsNull(consumed.RecoveryStartNonce);
        Assert.ThrowsException<ArgumentException>(() => V2UpdateTransactionStateMachine.Transition(consumed,
            V2UpdateTransactionPhase.PredecessorHealthy, Timestamp.AddSeconds(3), Nonce));
        Assert.ThrowsException<InvalidOperationException>(() => V2UpdateTransactionStateMachine.Transition(
            Sample() with { Phase = V2UpdateTransactionPhase.PolicyCommitted },
            V2UpdateTransactionPhase.RollbackRequired, Timestamp.AddSeconds(1)));
        Assert.IsTrue(V2UpdateTransactionStateMachine.CanTransition(V2UpdateTransactionPhase.PolicyCommitPending,
            V2UpdateTransactionPhase.PolicyCommitted));
        Assert.ThrowsException<InvalidOperationException>(() => V2UpdateTransactionStateMachine.Transition(
            Sample() with { Phase = V2UpdateTransactionPhase.PolicyCommitPending },
            V2UpdateTransactionPhase.PolicyCommitted, Timestamp.AddSeconds(1)));
        Assert.ThrowsException<ArgumentException>(() => V2UpdateTransactionStateMachine.Transition(
            Sample(), V2UpdateTransactionPhase.PrivateReady, Timestamp.ToOffset(TimeSpan.FromHours(-5))));
        Assert.ThrowsException<ArgumentException>(() => V2UpdateTransactionStateMachine.Transition(
            Sample(), V2UpdateTransactionPhase.PrivateReady, Timestamp.AddSeconds(-1)));
    }

    private static V2UpdateTransactionJournal Sample() => new(TransactionId,
        new ReleaseIdentity(ReleaseGeneration.V2, 7, PredecessorHash),
        new ReleaseIdentity(ReleaseGeneration.V2, 8, TargetHash),
        V2UpdateTransactionPhase.Admitted, BackupId, Timestamp);

    private static void AddLinearEdges(V2UpdateTransactionPhase[] path,
        HashSet<(V2UpdateTransactionPhase, V2UpdateTransactionPhase)> edges)
    {
        for (var index = 1; index < path.Length; index++) edges.Add((path[index - 1], path[index]));
    }
}
