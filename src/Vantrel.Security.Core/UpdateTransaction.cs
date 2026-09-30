using System.Globalization;
using System.Text;

namespace Vantrel.Security.Core;

public enum UpdateTransactionPhase
{
    Idle,
    Prepared,
    Verified,
    ServiceStopped,
    Replaced,
    Restarted,
    PostVerified,
    PolicyCommitted,
    Completed,
    RollbackRequired,
    RolledBack,
    Failed
}

public enum UpdateTransactionResult
{
    None,
    CandidateVerified,
    CandidateRejected,
    Completed,
    RolledBack,
    Failed,
    RecoveryRequired,
    PolicyUnavailable
}

/// <summary>Bounded read-only update state. It intentionally contains no path, hash, journal, or exception data.</summary>
public sealed record UpdateTransactionSnapshot(
    DateTimeOffset SampledAtUtc,
    UpdateTransactionPhase Phase,
    bool VerifiedStagedCandidatePresent,
    ulong? CurrentReleaseSequence,
    ulong? TargetReleaseSequence,
    UpdateTransactionResult LastResult);

public enum UpdateTransactionDisplayState { Disconnected, Unavailable, Stale, Current, Recovered }

public static class UpdateTransactionPresentation
{
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(30);
    public static UpdateTransactionDisplayState State(UpdateTransactionSnapshot? value, bool connected, DateTimeOffset now,
        bool wasDisconnected = false) => !connected ? UpdateTransactionDisplayState.Disconnected : value is null ? UpdateTransactionDisplayState.Unavailable :
        now - value.SampledAtUtc > StaleAfter ? UpdateTransactionDisplayState.Stale : wasDisconnected ? UpdateTransactionDisplayState.Recovered : UpdateTransactionDisplayState.Current;
}

public interface IUpdateTransactionClient
{
    Task<UpdateTransactionSnapshot?> GetUpdateStatusAsync(CancellationToken cancellationToken);
}

/// <summary>Strict durable state for a fixed offline update transaction. All locations are derived by trusted service/tooling code.</summary>
public sealed record UpdateTransactionJournal(
    string TransactionId,
    ulong PriorReleaseSequence,
    string PriorManifestSha256,
    ulong TargetReleaseSequence,
    string TargetManifestSha256,
    UpdateTransactionPhase Phase,
    string BackupId,
    DateTimeOffset UpdatedAtUtc);

public enum UpdateTransactionJournalParseFailure { None, Unavailable, Malformed, UnsupportedSchema }

/// <summary>Closed durable transaction transitions. Callers cannot skip a verification or policy boundary.</summary>
public static class UpdateTransactionStateMachine
{
    public static bool CanTransition(UpdateTransactionPhase from, UpdateTransactionPhase to) => (from, to) switch
    {
        (UpdateTransactionPhase.Prepared, UpdateTransactionPhase.Verified) => true,
        (UpdateTransactionPhase.Verified, UpdateTransactionPhase.ServiceStopped) => true,
        (UpdateTransactionPhase.ServiceStopped, UpdateTransactionPhase.Replaced) => true,
        (UpdateTransactionPhase.Replaced, UpdateTransactionPhase.Restarted) => true,
        (UpdateTransactionPhase.Restarted, UpdateTransactionPhase.PostVerified) => true,
        (UpdateTransactionPhase.PostVerified, UpdateTransactionPhase.PolicyCommitted) => true,
        (UpdateTransactionPhase.PolicyCommitted, UpdateTransactionPhase.Completed) => true,
        (UpdateTransactionPhase.Prepared or UpdateTransactionPhase.Verified or UpdateTransactionPhase.ServiceStopped or UpdateTransactionPhase.Replaced or UpdateTransactionPhase.Restarted or UpdateTransactionPhase.PostVerified, UpdateTransactionPhase.RollbackRequired) => true,
        (UpdateTransactionPhase.RollbackRequired, UpdateTransactionPhase.RolledBack) => true,
        (UpdateTransactionPhase.Prepared or UpdateTransactionPhase.Verified or UpdateTransactionPhase.ServiceStopped or UpdateTransactionPhase.Replaced or UpdateTransactionPhase.Restarted or UpdateTransactionPhase.PostVerified or UpdateTransactionPhase.PolicyCommitted, UpdateTransactionPhase.Failed) => true,
        (UpdateTransactionPhase.RolledBack or UpdateTransactionPhase.Completed or UpdateTransactionPhase.Failed, UpdateTransactionPhase.Failed) => false,
        _ => false
    };

    public static UpdateTransactionJournal Transition(UpdateTransactionJournal journal, UpdateTransactionPhase target, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(journal);
        if (!CanTransition(journal.Phase, target)) throw new InvalidOperationException("Illegal update transaction phase transition.");
        if (now.Offset != TimeSpan.Zero || now.Ticks % TimeSpan.TicksPerSecond != 0) throw new ArgumentException("Transition time must be whole-second UTC.", nameof(now));
        return journal with { Phase = target, UpdatedAtUtc = now };
    }
}

public static class UpdateTransactionJournalCodec
{
    public const int MaximumBytes = 2048;
    public const string Schema = "vantrel-update-transaction-v1";
    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static byte[] Serialize(UpdateTransactionJournal value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!IsId(value.TransactionId) || !IsId(value.BackupId) || value.PriorReleaseSequence == 0 || value.TargetReleaseSequence == 0 ||
            !IsUpperHash(value.PriorManifestSha256) || !IsUpperHash(value.TargetManifestSha256) || value.UpdatedAtUtc.Offset != TimeSpan.Zero ||
            value.UpdatedAtUtc.Ticks % TimeSpan.TicksPerSecond != 0 || value.Phase == UpdateTransactionPhase.Idle || !Enum.IsDefined(value.Phase))
            throw new ArgumentException("Invalid bounded update transaction journal.", nameof(value));
        var text = $"schema={Schema}\ntransaction-id={value.TransactionId}\nprior-release-sequence={value.PriorReleaseSequence.ToString(CultureInfo.InvariantCulture)}\nprior-manifest-sha256={value.PriorManifestSha256}\ntarget-release-sequence={value.TargetReleaseSequence.ToString(CultureInfo.InvariantCulture)}\ntarget-manifest-sha256={value.TargetManifestSha256}\nphase={value.Phase}\nbackup-id={value.BackupId}\nupdated-at-utc={value.UpdatedAtUtc.ToString(TimestampFormat, CultureInfo.InvariantCulture)}\n";
        return Utf8.GetBytes(text);
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out UpdateTransactionJournal? journal, out UpdateTransactionJournalParseFailure failure)
    {
        journal = null;
        if (bytes.Length == 0) { failure = UpdateTransactionJournalParseFailure.Unavailable; return false; }
        if (bytes.Length > MaximumBytes || HasBom(bytes) || bytes.IndexOf((byte)'\r') >= 0) { failure = UpdateTransactionJournalParseFailure.Malformed; return false; }
        string text;
        try { text = Utf8.GetString(bytes); } catch (DecoderFallbackException) { failure = UpdateTransactionJournalParseFailure.Malformed; return false; }
        var lines = text.Split('\n');
        if (!text.EndsWith('\n') || lines.Length != 10 || lines[^1].Length != 0)
        { failure = UpdateTransactionJournalParseFailure.Malformed; return false; }
        if (lines[0] != "schema=" + Schema)
        { failure = lines[0].StartsWith("schema=", StringComparison.Ordinal) ? UpdateTransactionJournalParseFailure.UnsupportedSchema : UpdateTransactionJournalParseFailure.Malformed; return false; }
        if (!Field(lines[1], "transaction-id", out var transactionId) || !IsId(transactionId) ||
            !Field(lines[2], "prior-release-sequence", out var priorText) || !Sequence(priorText, out var prior) ||
            !Field(lines[3], "prior-manifest-sha256", out var priorHash) || !IsUpperHash(priorHash) ||
            !Field(lines[4], "target-release-sequence", out var targetText) || !Sequence(targetText, out var target) ||
            !Field(lines[5], "target-manifest-sha256", out var targetHash) || !IsUpperHash(targetHash) ||
            !Field(lines[6], "phase", out var phaseText) || !Enum.TryParse<UpdateTransactionPhase>(phaseText, false, out var phase) || !Enum.IsDefined(phase) || phase == UpdateTransactionPhase.Idle ||
            !Field(lines[7], "backup-id", out var backupId) || !IsId(backupId) ||
            !Field(lines[8], "updated-at-utc", out var updatedText) || !DateTimeOffset.TryParseExact(updatedText, TimestampFormat, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var updated) || updated.ToString(TimestampFormat, CultureInfo.InvariantCulture) != updatedText)
        { failure = UpdateTransactionJournalParseFailure.Malformed; return false; }
        var parsed = new UpdateTransactionJournal(transactionId, prior, priorHash, target, targetHash, phase, backupId, updated);
        if (!bytes.SequenceEqual(Serialize(parsed))) { failure = UpdateTransactionJournalParseFailure.Malformed; return false; }
        journal = parsed; failure = UpdateTransactionJournalParseFailure.None; return true;
    }

    public static bool IsId(string? value) => value is { Length: 32 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool Field(string line, string name, out string value) { var prefix = name + "="; if (!line.StartsWith(prefix, StringComparison.Ordinal)) { value = string.Empty; return false; } value = line[prefix.Length..]; return true; }
    private static bool Sequence(string value, out ulong sequence)
    {
        sequence = 0;
        return value.Length > 0 && value[0] is >= '1' and <= '9' && value.All(c => c is >= '0' and <= '9') &&
            ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out sequence);
    }
    private static bool IsUpperHash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool HasBom(ReadOnlySpan<byte> bytes) => bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
}
