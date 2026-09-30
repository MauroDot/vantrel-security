using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class UpdateTransactionProtocolTests
{
    private const string Prior = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string Target = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    [TestMethod]
    public void Journal_round_trips_only_canonical_bounded_fields()
    {
        var value = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", 1, Prior, 2, Target,
            UpdateTransactionPhase.PostVerified, "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 9, 21, 12, 0, 0, TimeSpan.Zero));
        var bytes = UpdateTransactionJournalCodec.Serialize(value);
        Assert.IsTrue(UpdateTransactionJournalCodec.TryParse(bytes, out var parsed, out var failure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.None, failure);
        Assert.AreEqual(value, parsed);
    }

    [DataTestMethod]
    [DataRow("transaction-id=not-an-id")]
    [DataRow("phase=Unknown")]
    [DataRow("extra=x")]
    public void Journal_rejects_noncanonical_or_unknown_content(string replacement)
    {
        var value = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", 1, Prior, 2, Target,
            UpdateTransactionPhase.Verified, "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 9, 21, 12, 0, 0, TimeSpan.Zero));
        var text = System.Text.Encoding.UTF8.GetString(UpdateTransactionJournalCodec.Serialize(value));
        if (replacement == "extra=x") text = text.TrimEnd('\n') + "\nextra=x\n";
        else text = text.Replace(replacement.StartsWith("transaction") ? "transaction-id=0123456789abcdef0123456789abcdef" : "phase=Verified", replacement, StringComparison.Ordinal);
        Assert.IsFalse(UpdateTransactionJournalCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(text), out _, out var failure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Malformed, failure);
    }

    [TestMethod]
    public void Update_status_is_parameter_free_and_bounded()
    {
        var request = StatusProtocol.CreateUpdateStatusRequest();
        Assert.AreEqual(StatusProtocol.RequestKind.UpdateStatus, StatusProtocol.ReadRequestKind(request));
        Assert.AreEqual(StatusProtocol.RequestKind.Invalid, StatusProtocol.ReadRequestKind(System.Text.Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"get_update_status\",\"extra\":true}")));
        var snapshot = new UpdateTransactionSnapshot(DateTimeOffset.UtcNow, UpdateTransactionPhase.Verified, true, 1, 2, UpdateTransactionResult.CandidateVerified);
        var response = StatusProtocol.CreateUpdateStatusResponse(snapshot);
        Assert.IsTrue(response.Length < StatusProtocol.MaximumMessageBytes);
        Assert.IsTrue(StatusProtocol.TryReadUpdateStatusResponse(response, out var parsed, out var failure));
        Assert.AreEqual(StatusResponseFailure.None, failure);
        Assert.AreEqual(snapshot, parsed);
    }

    [TestMethod]
    public void Worst_case_update_status_has_substantial_frame_headroom()
    {
        var maximum = 0;
        foreach (var phase in Enum.GetValues<UpdateTransactionPhase>())
        foreach (var result in Enum.GetValues<UpdateTransactionResult>())
        {
            var response = StatusProtocol.CreateUpdateStatusResponse(new UpdateTransactionSnapshot(
                DateTimeOffset.MaxValue, phase, phase == UpdateTransactionPhase.Verified, ulong.MaxValue, ulong.MaxValue, result));
            maximum = Math.Max(maximum, response.Length);
        }
        Assert.AreEqual(267, maximum, "The protocol bound is deliberate and must change only with an explicit framing review.");
        Assert.AreEqual(3829, StatusProtocol.MaximumMessageBytes - maximum);
    }

    [TestMethod]
    public void Idle_update_status_cannot_claim_candidate()
    {
        var snapshot = new UpdateTransactionSnapshot(DateTimeOffset.UtcNow, UpdateTransactionPhase.Idle, true, 1, 2, UpdateTransactionResult.None);
        Assert.IsFalse(StatusProtocol.TryReadUpdateStatusResponse(StatusProtocol.CreateUpdateStatusResponse(snapshot), out _, out var failure));
        Assert.AreEqual(StatusResponseFailure.InvalidUpdateTransaction, failure);
    }

    [TestMethod]
    public void Journal_transitions_are_closed_and_cannot_skip_verification_or_policy_boundaries()
    {
        var journal = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", 1, Prior, 2, Target,
            UpdateTransactionPhase.Prepared, "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 9, 21, 12, 0, 0, TimeSpan.Zero));
        Assert.IsTrue(UpdateTransactionStateMachine.CanTransition(UpdateTransactionPhase.Prepared, UpdateTransactionPhase.Verified));
        Assert.IsFalse(UpdateTransactionStateMachine.CanTransition(UpdateTransactionPhase.Prepared, UpdateTransactionPhase.Replaced));
        Assert.ThrowsException<InvalidOperationException>(() => UpdateTransactionStateMachine.Transition(journal, UpdateTransactionPhase.PolicyCommitted, journal.UpdatedAtUtc));
        var verified = UpdateTransactionStateMachine.Transition(journal, UpdateTransactionPhase.Verified, journal.UpdatedAtUtc);
        Assert.AreEqual(UpdateTransactionPhase.Verified, verified.Phase);
    }
}
