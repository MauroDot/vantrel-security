using System.Globalization;
using System.Text;

namespace Vantrel.Security.Core;

public enum V2UpdateTransactionPhase
{
    Admitted,
    PrivateReady,
    BackupReady,
    TargetReady,
    StopPending,
    Stopped,
    DetachPending,
    PredecessorDetached,
    ActivatePending,
    TargetActive,
    StartPending,
    TargetStarted,
    TargetHealthy,
    PolicyCommitPending,
    PolicyCommitted,
    Completed,
    RollbackRequired,
    RollbackStopPending,
    RollbackStopped,
    RollbackTargetDetachPending,
    RollbackTargetDetached,
    RollbackPredecessorRestorePending,
    RollbackPredecessorRestored,
    RollbackRestartAuthorized,
    RollbackRestartConsumed,
    PredecessorHealthy,
    RolledBack
}

/// <summary>Durable V2 to V2 update state. Physical locations are derived by trusted service code.</summary>
public sealed record V2UpdateTransactionJournal(
    string TransactionId,
    ReleaseIdentity Predecessor,
    ReleaseIdentity Target,
    V2UpdateTransactionPhase Phase,
    string BackupId,
    DateTimeOffset UpdatedAtUtc,
    string? RecoveryStartNonce = null);

/// <summary>Closed V2 transaction graph; policy commitment has no automatic downgrade path.</summary>
public static class V2UpdateTransactionStateMachine
{
    // This describes phase ordering only. In particular, a true result for the
    // PolicyCommitPending -> PolicyCommitted edge is not policy-commit authority:
    // Transition and the store reject that edge until a durable proof-bearing
    // handoff is implemented in a later task.
    public static bool CanTransition(V2UpdateTransactionPhase from, V2UpdateTransactionPhase to) => (from, to) switch
    {
        (V2UpdateTransactionPhase.Admitted, V2UpdateTransactionPhase.PrivateReady) => true,
        (V2UpdateTransactionPhase.PrivateReady, V2UpdateTransactionPhase.BackupReady) => true,
        (V2UpdateTransactionPhase.BackupReady, V2UpdateTransactionPhase.TargetReady) => true,
        (V2UpdateTransactionPhase.TargetReady, V2UpdateTransactionPhase.StopPending) => true,
        (V2UpdateTransactionPhase.StopPending, V2UpdateTransactionPhase.Stopped) => true,
        (V2UpdateTransactionPhase.Stopped, V2UpdateTransactionPhase.DetachPending) => true,
        (V2UpdateTransactionPhase.DetachPending, V2UpdateTransactionPhase.PredecessorDetached) => true,
        (V2UpdateTransactionPhase.PredecessorDetached, V2UpdateTransactionPhase.ActivatePending) => true,
        (V2UpdateTransactionPhase.ActivatePending, V2UpdateTransactionPhase.TargetActive) => true,
        (V2UpdateTransactionPhase.TargetActive, V2UpdateTransactionPhase.StartPending) => true,
        (V2UpdateTransactionPhase.StartPending, V2UpdateTransactionPhase.TargetStarted) => true,
        (V2UpdateTransactionPhase.TargetStarted, V2UpdateTransactionPhase.TargetHealthy) => true,
        (V2UpdateTransactionPhase.TargetHealthy, V2UpdateTransactionPhase.PolicyCommitPending) => true,
        (V2UpdateTransactionPhase.PolicyCommitPending, V2UpdateTransactionPhase.PolicyCommitted) => true,
        (V2UpdateTransactionPhase.PolicyCommitted, V2UpdateTransactionPhase.Completed) => true,
        (V2UpdateTransactionPhase.StopPending or V2UpdateTransactionPhase.Stopped or
            V2UpdateTransactionPhase.DetachPending or V2UpdateTransactionPhase.PredecessorDetached or
            V2UpdateTransactionPhase.ActivatePending or V2UpdateTransactionPhase.TargetActive or
            V2UpdateTransactionPhase.StartPending or V2UpdateTransactionPhase.TargetStarted or
            V2UpdateTransactionPhase.TargetHealthy, V2UpdateTransactionPhase.RollbackRequired) => true,
        (V2UpdateTransactionPhase.RollbackRequired, V2UpdateTransactionPhase.RollbackStopPending) => true,
        (V2UpdateTransactionPhase.RollbackStopPending, V2UpdateTransactionPhase.RollbackStopped) => true,
        (V2UpdateTransactionPhase.RollbackStopped, V2UpdateTransactionPhase.RollbackTargetDetachPending) => true,
        (V2UpdateTransactionPhase.RollbackTargetDetachPending, V2UpdateTransactionPhase.RollbackTargetDetached) => true,
        (V2UpdateTransactionPhase.RollbackTargetDetached, V2UpdateTransactionPhase.RollbackPredecessorRestorePending) => true,
        (V2UpdateTransactionPhase.RollbackPredecessorRestorePending, V2UpdateTransactionPhase.RollbackPredecessorRestored) => true,
        (V2UpdateTransactionPhase.RollbackPredecessorRestored, V2UpdateTransactionPhase.RollbackRestartAuthorized) => true,
        (V2UpdateTransactionPhase.RollbackRestartAuthorized, V2UpdateTransactionPhase.RollbackRestartConsumed) => true,
        (V2UpdateTransactionPhase.RollbackRestartConsumed, V2UpdateTransactionPhase.PredecessorHealthy) => true,
        (V2UpdateTransactionPhase.PredecessorHealthy, V2UpdateTransactionPhase.RolledBack) => true,
        _ => false
    };

    public static V2UpdateTransactionJournal Transition(V2UpdateTransactionJournal journal,
        V2UpdateTransactionPhase target, DateTimeOffset now, string? recoveryStartNonce = null)
    {
        ArgumentNullException.ThrowIfNull(journal);
        _ = V2UpdateTransactionJournalCodec.Serialize(journal);
        if (!CanTransition(journal.Phase, target))
            throw new InvalidOperationException("Illegal V2 update transaction phase transition.");
        if (journal.Phase == V2UpdateTransactionPhase.PolicyCommitPending &&
            target == V2UpdateTransactionPhase.PolicyCommitted)
            throw new InvalidOperationException("Target policy commitment requires durable policy proof.");
        if (now.Offset != TimeSpan.Zero || now.Ticks % TimeSpan.TicksPerSecond != 0 ||
            now < journal.UpdatedAtUtc)
            throw new ArgumentException("Transition time must be nondecreasing whole-second UTC.", nameof(now));
        if (target == V2UpdateTransactionPhase.RollbackRestartAuthorized
            ? !V2UpdateTransactionJournalCodec.IsNonce(recoveryStartNonce)
            : recoveryStartNonce is not null)
            throw new ArgumentException("Recovery nonce is valid only when authorizing rollback restart.", nameof(recoveryStartNonce));
        return journal with
        {
            Phase = target,
            UpdatedAtUtc = now,
            RecoveryStartNonce = recoveryStartNonce
        };
    }
}

/// <summary>Strict canonical wire format for a V2 to V2 update transaction.</summary>
public static class V2UpdateTransactionJournalCodec
{
    public const int MaximumBytes = 2048;
    public const string Schema = "vantrel-update-transaction-v3";
    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static byte[] Serialize(V2UpdateTransactionJournal value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!IsValid(value)) throw new ArgumentException("Invalid V2 update transaction journal.", nameof(value));

        var text = $"schema={Schema}\n" +
            $"transaction-id={value.TransactionId}\n" +
            $"backup-id={value.BackupId}\n" +
            "predecessor-generation=v2\n" +
            $"predecessor-release-sequence={value.Predecessor.ReleaseSequence.ToString(CultureInfo.InvariantCulture)}\n" +
            $"predecessor-manifest-sha256={value.Predecessor.ManifestSha256}\n" +
            "target-generation=v2\n" +
            $"target-release-sequence={value.Target.ReleaseSequence.ToString(CultureInfo.InvariantCulture)}\n" +
            $"target-manifest-sha256={value.Target.ManifestSha256}\n" +
            $"phase={value.Phase}\n" +
            $"updated-at-utc={value.UpdatedAtUtc.ToString(TimestampFormat, CultureInfo.InvariantCulture)}\n" +
            $"recovery-start-nonce={value.RecoveryStartNonce ?? string.Empty}\n";
        var bytes = Utf8.GetBytes(text);
        if (bytes.Length > MaximumBytes) throw new ArgumentException("V2 update transaction journal exceeds the size limit.", nameof(value));
        return bytes;
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out V2UpdateTransactionJournal? journal,
        out UpdateTransactionJournalParseFailure failure)
    {
        journal = null;
        if (bytes.IsEmpty) { failure = UpdateTransactionJournalParseFailure.Unavailable; return false; }
        if (bytes.Length > MaximumBytes || HasBom(bytes) || bytes.IndexOf((byte)'\r') >= 0)
        { failure = UpdateTransactionJournalParseFailure.Malformed; return false; }

        string text;
        try { text = Utf8.GetString(bytes); }
        catch (DecoderFallbackException) { failure = UpdateTransactionJournalParseFailure.Malformed; return false; }
        var lines = text.Split('\n');
        if (!text.EndsWith('\n') || lines[^1].Length != 0)
        { failure = UpdateTransactionJournalParseFailure.Malformed; return false; }
        if (lines[0] != "schema=" + Schema)
        {
            failure = lines[0].StartsWith("schema=", StringComparison.Ordinal)
                ? UpdateTransactionJournalParseFailure.UnsupportedSchema : UpdateTransactionJournalParseFailure.Malformed;
            return false;
        }
        if (lines.Length != 13 ||
            !Field(lines[1], "transaction-id", out var transactionId) || !IsId(transactionId) ||
            !Field(lines[2], "backup-id", out var backupId) || !IsId(backupId) ||
            lines[3] != "predecessor-generation=v2" ||
            !Field(lines[4], "predecessor-release-sequence", out var predecessorSequenceText) || !Sequence(predecessorSequenceText, out var predecessorSequence) ||
            !Field(lines[5], "predecessor-manifest-sha256", out var predecessorHash) || !IsUpperHash(predecessorHash) ||
            lines[6] != "target-generation=v2" ||
            !Field(lines[7], "target-release-sequence", out var targetSequenceText) || !Sequence(targetSequenceText, out var targetSequence) ||
            !Field(lines[8], "target-manifest-sha256", out var targetHash) || !IsUpperHash(targetHash) ||
            !Field(lines[9], "phase", out var phaseText) || !Enum.TryParse<V2UpdateTransactionPhase>(phaseText, false, out var phase) ||
            !Enum.IsDefined(phase) ||
            !Field(lines[10], "updated-at-utc", out var updatedText) ||
            !DateTimeOffset.TryParseExact(updatedText, TimestampFormat, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var updated) ||
            updated.ToString(TimestampFormat, CultureInfo.InvariantCulture) != updatedText ||
            !Field(lines[11], "recovery-start-nonce", out var nonce))
        { failure = UpdateTransactionJournalParseFailure.Malformed; return false; }

        var parsed = new V2UpdateTransactionJournal(transactionId,
            new ReleaseIdentity(ReleaseGeneration.V2, predecessorSequence, predecessorHash),
            new ReleaseIdentity(ReleaseGeneration.V2, targetSequence, targetHash),
            phase, backupId, updated, nonce.Length == 0 ? null : nonce);
        if (!IsValid(parsed) || !bytes.SequenceEqual(Serialize(parsed)))
        { failure = UpdateTransactionJournalParseFailure.Malformed; return false; }
        journal = parsed;
        failure = UpdateTransactionJournalParseFailure.None;
        return true;
    }

    public static bool IsId(string? value) => value is { Length: 32 } &&
        value.All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    public static bool IsNonce(string? value) => value is { Length: 35 } &&
        value.StartsWith("v2-", StringComparison.Ordinal) && IsId(value[3..]);

    private static bool IsValid(V2UpdateTransactionJournal value) =>
        IsId(value.TransactionId) && IsId(value.BackupId) &&
        value.Predecessor is { IsValid: true, Generation: ReleaseGeneration.V2 } &&
        value.Target is { IsValid: true, Generation: ReleaseGeneration.V2 } &&
        value.Target.ReleaseSequence > value.Predecessor.ReleaseSequence &&
        value.UpdatedAtUtc.Offset == TimeSpan.Zero &&
        value.UpdatedAtUtc.Ticks % TimeSpan.TicksPerSecond == 0 &&
        Enum.IsDefined(value.Phase) &&
        (value.Phase == V2UpdateTransactionPhase.RollbackRestartAuthorized
            ? IsNonce(value.RecoveryStartNonce) : value.RecoveryStartNonce is null);

    private static bool Field(string line, string name, out string value)
    {
        var prefix = name + "=";
        if (!line.StartsWith(prefix, StringComparison.Ordinal)) { value = string.Empty; return false; }
        value = line[prefix.Length..];
        return true;
    }

    private static bool Sequence(string value, out ulong sequence)
    {
        sequence = 0;
        return value.Length > 0 && value[0] is >= '1' and <= '9' &&
            value.All(static c => c is >= '0' and <= '9') &&
            ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out sequence);
    }

    private static bool IsUpperHash(string? value) => value is { Length: 64 } &&
        value.All(static c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool HasBom(ReadOnlySpan<byte> bytes) => bytes.Length >= 3 &&
        bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
}
