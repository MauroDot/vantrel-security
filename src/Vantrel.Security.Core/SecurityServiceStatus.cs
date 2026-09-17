namespace Vantrel.Security.Core;

public enum ProtectionState
{
    Unavailable = 0,
    Protected = 1
}

public sealed record ApplicationVersion(int Major, int Minor, int Patch)
{
    public override string ToString() => $"{Major}.{Minor}.{Patch}";
}

public sealed record SecurityServiceStatus(
    ProtectionState Protection,
    ApplicationVersion Version,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset HeartbeatAtUtc)
{
    public TimeSpan UptimeAt(DateTimeOffset now) => now >= StartedAtUtc ? now - StartedAtUtc : TimeSpan.Zero;
}

public interface ISecurityServiceStatusClient
{
    Task<SecurityServiceStatus?> GetStatusAsync(CancellationToken cancellationToken);
}
