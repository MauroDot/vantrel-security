using System.Collections.Immutable;
using System.IO.Pipes;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public sealed class CommandAuditStore
{
    private readonly object _gate = new();
    private readonly Func<DateTimeOffset> _clock;
    private ImmutableArray<CommandAuditEntry> _entries = [];
    public CommandAuditStore() : this(() => DateTimeOffset.UtcNow) { }
    internal CommandAuditStore(Func<DateTimeOffset> clock) { _clock = clock; }
    public ImmutableArray<CommandAuditEntry> Snapshot() { lock (_gate) return _entries; }
    public void Add(string? id, CommandCallerClassification caller, CommandAuditOutcome outcome)
    {
        var entry = new CommandAuditEntry(id, caller, outcome, _clock());
        lock (_gate) _entries = _entries.Insert(0, entry).Take(32).ToImmutableArray();
    }
}

public static class CommandCallerAuthorizer
{
    private static readonly SecurityIdentifier Interactive = new(WellKnownSidType.InteractiveSid, null);
    private static readonly SecurityIdentifier Anonymous = new(WellKnownSidType.AnonymousSid, null);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier LocalService = new(WellKnownSidType.LocalServiceSid, null);
    private static readonly SecurityIdentifier NetworkService = new(WellKnownSidType.NetworkServiceSid, null);

    public static CommandCallerClassification Classify(NamedPipeServerStream pipe)
    {
        CommandCallerClassification result = CommandCallerClassification.Unknown;
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            result = ClassifyIdentity(identity.User, identity.Groups);
        });
        return result;
    }
    internal static CommandCallerClassification ClassifyIdentity(SecurityIdentifier? user, IdentityReferenceCollection? groups) =>
        user is null || user == Anonymous ? CommandCallerClassification.Anonymous :
        user == LocalSystem || user == LocalService || user == NetworkService ? CommandCallerClassification.ServiceIdentity :
        groups?.Contains(Interactive) == true ? CommandCallerClassification.InteractiveUser : CommandCallerClassification.NonInteractive;
    public static bool Authorized(CommandCallerClassification caller) => caller == CommandCallerClassification.InteractiveUser;
}


public sealed class CommandRequestRegistry
{
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _ids = new(StringComparer.Ordinal);
    private readonly Queue<DateTimeOffset> _accepted = new();
    private readonly Func<DateTimeOffset> _clock;
    public CommandRequestRegistry() : this(() => DateTimeOffset.UtcNow) { }
    internal CommandRequestRegistry(Func<DateTimeOffset> clock) { _clock = clock; }
    public CommandResult Admit(string id, bool refreshBusy)
    {
        lock (_gate)
        {
            var now = _clock(); var cutoff = now.AddMinutes(-10);
            foreach (var stale in _ids.Where(pair => pair.Value < cutoff).Select(pair => pair.Key).ToArray()) _ids.Remove(stale);
            while (_accepted.TryPeek(out var accepted) && accepted < cutoff) _accepted.Dequeue();
            if (_ids.ContainsKey(id)) return CommandResult.Duplicate;
            if (_accepted.Count >= 12) return CommandResult.Rejected;
            if (refreshBusy) return CommandResult.AlreadyInProgress;
            if (_ids.Count >= 64) _ids.Remove(_ids.OrderBy(pair => pair.Value).First().Key);
            _ids[id] = now; _accepted.Enqueue(now); return CommandResult.Accepted;
        }
    }
    internal CommandResult AdmitAndReserve(string id, Func<bool> tryReserve)
    {
        lock (_gate)
        {
            var now = _clock(); var cutoff = now.AddMinutes(-10);
            foreach (var stale in _ids.Where(pair => pair.Value < cutoff).Select(pair => pair.Key).ToArray()) _ids.Remove(stale);
            while (_accepted.TryPeek(out var accepted) && accepted < cutoff) _accepted.Dequeue();
            if (_ids.ContainsKey(id)) return CommandResult.Duplicate;
            if (_accepted.Count >= 12) return CommandResult.Rejected;
            if (!tryReserve()) return CommandResult.AlreadyInProgress;
            if (_ids.Count >= 64) _ids.Remove(_ids.OrderBy(pair => pair.Value).First().Key);
            _ids[id] = now; _accepted.Enqueue(now); return CommandResult.Accepted;
        }
    }
    public void Forget(string id) { lock (_gate) _ids.Remove(id); }
}

public sealed class CommandRejectionLogLimiter
{
    private readonly object _gate = new();
    private readonly Func<DateTimeOffset> _clock;
    private readonly Dictionary<string, DateTimeOffset> _last = new(StringComparer.Ordinal);
    public CommandRejectionLogLimiter() : this(() => DateTimeOffset.UtcNow) { }
    internal CommandRejectionLogLimiter(Func<DateTimeOffset> clock) { _clock = clock; }
    public bool ShouldLog(string fixedReason)
    {
        lock (_gate)
        {
            var now = _clock();
            if (_last.TryGetValue(fixedReason, out var previous) && now - previous < TimeSpan.FromMinutes(1)) return false;
            _last[fixedReason] = now; return true;
        }
    }
}
