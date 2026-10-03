using System.Collections.Immutable;
using System.Runtime.InteropServices;

namespace Vantrel.Security.Desktop;

internal enum WindowsFirewallProfile { Domain, Private, Public }
internal enum WindowsFirewallProfileActivity { Active, NotActive, Unknown }
internal enum WindowsFirewallLocalState { Enabled, Disabled, Unknown, Unavailable, NotObserved }
internal enum WindowsFirewallProfileObservationState { Current, Empty, Partial, Unavailable }

internal sealed record WindowsFirewallProfileObservation(
    WindowsFirewallProfile Profile,
    WindowsFirewallProfileActivity Activity,
    WindowsFirewallLocalState LocalState);

internal sealed record WindowsFirewallProfileObservationSnapshot(
    DateTimeOffset ObservedAtUtc,
    WindowsFirewallProfileObservationState State,
    ImmutableArray<WindowsFirewallProfileObservation> Profiles);

internal interface IWindowsFirewallProfileObservationSource
{
    WindowsFirewallProfileObservationSnapshot Collect();
}

internal sealed record WindowsFirewallProfileNativeSnapshot(
    bool Available,
    int ActiveProfileMask,
    bool Partial,
    ImmutableArray<WindowsFirewallLocalState> ProfileStates)
{
    internal static WindowsFirewallProfileNativeSnapshot Unavailable() => new(false, 0, false, []);
}

internal interface IWindowsFirewallProfileNativeReader
{
    WindowsFirewallProfileNativeSnapshot Read();
}

internal sealed class WindowsFirewallProfileObservationSource : IWindowsFirewallProfileObservationSource
{
    internal const int DomainProfileBit = 0x1;
    internal const int PrivateProfileBit = 0x2;
    internal const int PublicProfileBit = 0x4;
    private const int KnownProfileBits = DomainProfileBit | PrivateProfileBit | PublicProfileBit;
    private readonly IWindowsFirewallProfileNativeReader _native;
    private readonly Func<DateTimeOffset> _clock;

    internal WindowsFirewallProfileObservationSource(IWindowsFirewallProfileNativeReader? native = null,
        Func<DateTimeOffset>? clock = null)
    {
        _native = native ?? new WindowsFirewallProfileNativeReader();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public WindowsFirewallProfileObservationSnapshot Collect()
    {
        WindowsFirewallProfileNativeSnapshot native;
        try { native = _native.Read(); }
        catch (Exception error) when (IsRecoverableFailure(error)) { native = WindowsFirewallProfileNativeSnapshot.Unavailable(); }

        if (!native.Available || native.ProfileStates.Length != 3)
            return Unavailable(_clock());

        var partial = native.Partial || (native.ActiveProfileMask & ~KnownProfileBits) != 0;
        var profiles = ImmutableArray.CreateBuilder<WindowsFirewallProfileObservation>(3);
        foreach (var (profile, bit, index) in ProfileDefinitions)
        {
            var active = (native.ActiveProfileMask & bit) != 0;
            var state = native.ProfileStates[index];
            if (!active)
                profiles.Add(new(profile, WindowsFirewallProfileActivity.NotActive, WindowsFirewallLocalState.NotObserved));
            else
            {
                if (state is WindowsFirewallLocalState.NotObserved) state = WindowsFirewallLocalState.Unknown;
                if (state is WindowsFirewallLocalState.Unknown or WindowsFirewallLocalState.Unavailable) partial = true;
                profiles.Add(new(profile, WindowsFirewallProfileActivity.Active, state));
            }
        }

        var resultState = native.ActiveProfileMask == 0 ? WindowsFirewallProfileObservationState.Empty :
            partial ? WindowsFirewallProfileObservationState.Partial : WindowsFirewallProfileObservationState.Current;
        return new(_clock(), resultState, profiles.ToImmutable());
    }

    internal static WindowsFirewallProfileObservationSnapshot Unavailable(DateTimeOffset observedAtUtc) => new(observedAtUtc,
        WindowsFirewallProfileObservationState.Unavailable,
        [
            new(WindowsFirewallProfile.Domain, WindowsFirewallProfileActivity.Unknown, WindowsFirewallLocalState.Unavailable),
            new(WindowsFirewallProfile.Private, WindowsFirewallProfileActivity.Unknown, WindowsFirewallLocalState.Unavailable),
            new(WindowsFirewallProfile.Public, WindowsFirewallProfileActivity.Unknown, WindowsFirewallLocalState.Unavailable)
        ]);

    internal static readonly (WindowsFirewallProfile Profile, int Bit, int Index)[] ProfileDefinitions =
    [
        (WindowsFirewallProfile.Domain, DomainProfileBit, 0),
        (WindowsFirewallProfile.Private, PrivateProfileBit, 1),
        (WindowsFirewallProfile.Public, PublicProfileBit, 2)
    ];

    private static bool IsRecoverableFailure(Exception error) => error is not OutOfMemoryException and not StackOverflowException and not AccessViolationException;
}

internal interface IWindowsFirewallPolicyFactory
{
    IWindowsFirewallPolicy Create();
}

internal interface IWindowsFirewallPolicy : IDisposable
{
    bool TryGetCurrentProfileTypes(out int profileMask);
    bool TryGetFirewallEnabled(int profileBit, out short enabled);
}

internal sealed class WindowsFirewallProfileNativeReader : IWindowsFirewallProfileNativeReader
{
    private readonly IWindowsFirewallPolicyFactory _factory;
    private readonly Func<bool> _isSupported;

    internal WindowsFirewallProfileNativeReader(IWindowsFirewallPolicyFactory? factory = null, Func<bool>? isSupported = null)
    {
        _factory = factory ?? new WindowsFirewallPolicyComFactory();
        _isSupported = isSupported ?? OperatingSystem.IsWindows;
    }

    public WindowsFirewallProfileNativeSnapshot Read()
    {
        if (!_isSupported()) return WindowsFirewallProfileNativeSnapshot.Unavailable();
        try
        {
            using var policy = _factory.Create();
            if (!policy.TryGetCurrentProfileTypes(out var mask)) return WindowsFirewallProfileNativeSnapshot.Unavailable();

            var partial = false;
            var states = ImmutableArray.CreateBuilder<WindowsFirewallLocalState>(3);
            foreach (var (_, bit, _) in WindowsFirewallProfileObservationSource.ProfileDefinitions)
            {
                if ((mask & bit) == 0)
                {
                    states.Add(WindowsFirewallLocalState.NotObserved);
                    continue;
                }

                if (!policy.TryGetFirewallEnabled(bit, out var enabled))
                {
                    states.Add(WindowsFirewallLocalState.Unavailable);
                    partial = true;
                }
                else if (enabled == -1) states.Add(WindowsFirewallLocalState.Enabled);
                else if (enabled == 0) states.Add(WindowsFirewallLocalState.Disabled);
                else
                {
                    states.Add(WindowsFirewallLocalState.Unknown);
                    partial = true;
                }
            }
            return new(true, mask, partial, states.ToImmutable());
        }
        catch (Exception error) when (IsRecoverableFailure(error))
        {
            return WindowsFirewallProfileNativeSnapshot.Unavailable();
        }
    }

    private static bool IsRecoverableFailure(Exception error) => error is not OutOfMemoryException and not StackOverflowException and not AccessViolationException;
}

internal sealed class WindowsFirewallPolicyComFactory : IWindowsFirewallPolicyFactory
{
    public IWindowsFirewallPolicy Create() => new WindowsFirewallPolicyCom(
        (INetFwPolicy2Native)new NetFwPolicy2ComClass());
}

internal sealed class WindowsFirewallPolicyCom(INetFwPolicy2Native native) : IWindowsFirewallPolicy
{
    private INetFwPolicy2Native? _native = native;

    public bool TryGetCurrentProfileTypes(out int profileMask)
    {
        profileMask = 0;
        return _native is not null && _native.GetCurrentProfileTypes(out profileMask) == 0;
    }

    public bool TryGetFirewallEnabled(int profileBit, out short enabled)
    {
        enabled = 0;
        return _native is not null && _native.GetFirewallEnabled(profileBit, out enabled) == 0;
    }

    public void Dispose()
    {
        var native = Interlocked.Exchange(ref _native, null);
        if (native is not null && Marshal.IsComObject(native)) Marshal.FinalReleaseComObject(native);
    }
}

[ComImport, Guid("98325047-C671-4174-8D81-DEFCD3F03186"), InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
internal interface INetFwPolicy2Native
{
    [DispId(1), PreserveSig] int GetCurrentProfileTypes(out int profileTypesBitmask);
    [DispId(2), PreserveSig] int GetFirewallEnabled(int profileType, out short enabled);
}

[ComImport, Guid("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD")]
internal class NetFwPolicy2ComClass;

internal sealed class NetworkFirewallProfileObservationSession
{
    private readonly object _sync = new();
    private long _generation;
    private WindowsFirewallProfileObservationSnapshot? _snapshot;

    internal WindowsFirewallProfileObservationSnapshot? Snapshot
    {
        get { lock (_sync) return _snapshot; }
    }

    internal async Task<WindowsFirewallProfileObservationSnapshot?> OpenAsync(IWindowsFirewallProfileObservationSource source)
    {
        long generation;
        lock (_sync)
        {
            generation = ++_generation;
            _snapshot = null;
        }

        WindowsFirewallProfileObservationSnapshot snapshot;
        try { snapshot = await Task.Run(source.Collect).ConfigureAwait(false); }
        catch (Exception error) when (IsRecoverableFailure(error)) { snapshot = WindowsFirewallProfileObservationSource.Unavailable(DateTimeOffset.UtcNow); }

        lock (_sync)
        {
            if (generation != _generation) return null;
            _snapshot = snapshot;
            return snapshot;
        }
    }

    internal bool IsCurrent(WindowsFirewallProfileObservationSnapshot snapshot)
    {
        lock (_sync) return ReferenceEquals(_snapshot, snapshot);
    }

    internal void Clear()
    {
        lock (_sync)
        {
            ++_generation;
            _snapshot = null;
        }
    }

    private static bool IsRecoverableFailure(Exception error) => error is not OutOfMemoryException and not StackOverflowException and not AccessViolationException;
}
