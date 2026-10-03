using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class WindowsFirewallProfileObservationTests
{
    [TestMethod]
    public void Source_maps_individual_and_combined_active_profile_bits_without_inactive_configuration()
    {
        var now = DateTimeOffset.UtcNow;
        var domain = new WindowsFirewallProfileObservationSource(new FakeNativeReader(Native(
            WindowsFirewallProfileObservationSource.DomainProfileBit,
            WindowsFirewallLocalState.Enabled,
            WindowsFirewallLocalState.NotObserved,
            WindowsFirewallLocalState.NotObserved)), () => now).Collect();
        var combined = new WindowsFirewallProfileObservationSource(new FakeNativeReader(Native(
            WindowsFirewallProfileObservationSource.PrivateProfileBit | WindowsFirewallProfileObservationSource.PublicProfileBit,
            WindowsFirewallLocalState.NotObserved,
            WindowsFirewallLocalState.Disabled,
            WindowsFirewallLocalState.Enabled)), () => now).Collect();

        Assert.AreEqual(now, domain.ObservedAtUtc);
        Assert.AreEqual(WindowsFirewallProfileObservationState.Current, domain.State);
        Assert.AreEqual(WindowsFirewallProfileActivity.Active, domain.Profiles[0].Activity);
        Assert.AreEqual(WindowsFirewallLocalState.Enabled, domain.Profiles[0].LocalState);
        Assert.AreEqual(WindowsFirewallProfileActivity.NotActive, domain.Profiles[1].Activity);
        Assert.AreEqual(WindowsFirewallLocalState.NotObserved, domain.Profiles[1].LocalState);
        Assert.AreEqual(WindowsFirewallProfileObservationState.Current, combined.State);
        Assert.AreEqual(WindowsFirewallProfileActivity.NotActive, combined.Profiles[0].Activity);
        Assert.AreEqual(WindowsFirewallLocalState.Disabled, combined.Profiles[1].LocalState);
        Assert.AreEqual(WindowsFirewallLocalState.Enabled, combined.Profiles[2].LocalState);
    }

    [TestMethod]
    public void Native_reader_queries_enabled_state_once_for_each_active_individual_bit_only()
    {
        var policy = new FakePolicy(WindowsFirewallProfileObservationSource.DomainProfileBit |
            WindowsFirewallProfileObservationSource.PublicProfileBit)
        {
            Values =
            {
                [WindowsFirewallProfileObservationSource.DomainProfileBit] = -1,
                [WindowsFirewallProfileObservationSource.PublicProfileBit] = 0
            }
        };
        var reader = new WindowsFirewallProfileNativeReader(new FakePolicyFactory(policy), () => true);

        var result = reader.Read();

        CollectionAssert.AreEqual(new[]
        {
            WindowsFirewallProfileObservationSource.DomainProfileBit,
            WindowsFirewallProfileObservationSource.PublicProfileBit
        }, policy.EnabledCalls);
        Assert.AreEqual(WindowsFirewallLocalState.Enabled, result.ProfileStates[0]);
        Assert.AreEqual(WindowsFirewallLocalState.NotObserved, result.ProfileStates[1]);
        Assert.AreEqual(WindowsFirewallLocalState.Disabled, result.ProfileStates[2]);
        Assert.AreEqual(1, policy.DisposeCalls);
    }

    [TestMethod]
    public void Source_maps_zero_mask_unknown_bits_and_unknown_boolean_values_fail_closed()
    {
        var zero = new WindowsFirewallProfileObservationSource(new FakeNativeReader(Native(0,
            WindowsFirewallLocalState.NotObserved, WindowsFirewallLocalState.NotObserved, WindowsFirewallLocalState.NotObserved))).Collect();
        var unknownBits = new WindowsFirewallProfileObservationSource(new FakeNativeReader(Native(
            WindowsFirewallProfileObservationSource.DomainProfileBit | 0x40,
            WindowsFirewallLocalState.Unknown, WindowsFirewallLocalState.NotObserved, WindowsFirewallLocalState.NotObserved))).Collect();

        Assert.AreEqual(WindowsFirewallProfileObservationState.Empty, zero.State);
        Assert.IsTrue(zero.Profiles.All(value => value.Activity == WindowsFirewallProfileActivity.NotActive));
        Assert.AreEqual(WindowsFirewallProfileObservationState.Partial, unknownBits.State);
        Assert.AreEqual(WindowsFirewallLocalState.Unknown, unknownBits.Profiles[0].LocalState);
    }

    [TestMethod]
    public void Per_profile_and_category_failures_are_scoped_without_diagnostics_and_release_policy_once()
    {
        var partialPolicy = new FakePolicy(WindowsFirewallProfileObservationSource.DomainProfileBit |
            WindowsFirewallProfileObservationSource.PrivateProfileBit)
        {
            Values = { [WindowsFirewallProfileObservationSource.DomainProfileBit] = -1 },
            FailingProfile = WindowsFirewallProfileObservationSource.PrivateProfileBit
        };
        var partial = new WindowsFirewallProfileObservationSource(new WindowsFirewallProfileNativeReader(
            new FakePolicyFactory(partialPolicy), () => true)).Collect();
        var unavailable = new WindowsFirewallProfileObservationSource(new WindowsFirewallProfileNativeReader(
            new ThrowingPolicyFactory(), () => true)).Collect();
        var presentation = WindowsFirewallProfileObservationPresentation.Create(unavailable, DateTimeOffset.UtcNow);

        Assert.AreEqual(WindowsFirewallProfileObservationState.Partial, partial.State);
        Assert.AreEqual(WindowsFirewallLocalState.Unavailable, partial.Profiles[1].LocalState);
        Assert.AreEqual(1, partialPolicy.DisposeCalls);
        Assert.AreEqual(WindowsFirewallProfileObservationState.Unavailable, unavailable.State);
        Assert.IsFalse(presentation.StateText.Contains("diagnostic", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(presentation.StateText.Contains("exception", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Unsupported_environment_does_not_create_a_policy_object()
    {
        var factory = new FakePolicyFactory(new FakePolicy(0));
        var result = new WindowsFirewallProfileNativeReader(factory, () => false).Read();

        Assert.IsFalse(result.Available);
        Assert.AreEqual(0, factory.CreateCalls);
    }

    [TestMethod]
    public void Native_reader_maps_an_unexpected_variant_boolean_to_unknown_and_partial()
    {
        var policy = new FakePolicy(WindowsFirewallProfileObservationSource.DomainProfileBit)
        {
            Values = { [WindowsFirewallProfileObservationSource.DomainProfileBit] = 7 }
        };

        var result = new WindowsFirewallProfileNativeReader(new FakePolicyFactory(policy), () => true).Read();

        Assert.IsTrue(result.Partial);
        Assert.AreEqual(WindowsFirewallLocalState.Unknown, result.ProfileStates[0]);
        Assert.AreEqual(1, policy.DisposeCalls);
    }

    [TestMethod]
    public void Session_is_asynchronous_and_late_current_unavailable_and_partial_results_are_discarded()
    {
        var snapshots = new[]
        {
            Snapshot(WindowsFirewallProfileObservationState.Current),
            Snapshot(WindowsFirewallProfileObservationState.Unavailable),
            Snapshot(WindowsFirewallProfileObservationState.Partial)
        };

        foreach (var snapshot in snapshots)
        {
            var source = new BlockingSource();
            var session = new NetworkFirewallProfileObservationSession();
            var stopwatch = Stopwatch.StartNew();
            var loading = session.OpenAsync(source);
            Assert.IsTrue(stopwatch.Elapsed < TimeSpan.FromSeconds(1));
            source.Entered.Task.Wait(TimeSpan.FromSeconds(2));
            Assert.IsFalse(loading.IsCompleted);

            session.Clear();
            source.Complete(snapshot);

            Assert.IsNull(loading.GetAwaiter().GetResult());
            Assert.IsNull(session.Snapshot);
        }
    }

    [TestMethod]
    public void Presentation_is_stale_after_two_minutes_and_uses_only_truthful_profile_language()
    {
        var snapshot = Snapshot(WindowsFirewallProfileObservationState.Current) with { ObservedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-3) };

        var presentation = WindowsFirewallProfileObservationPresentation.Create(snapshot, DateTimeOffset.UtcNow);

        Assert.AreEqual(WindowsFirewallProfileObservationDisplayState.Stale, presentation.State);
        Assert.AreEqual("Windows-reported firewall profile observations are shown for this interactive session. They do not assess network safety, Vantrel active protection, firewall effectiveness, intrusion detection, malware, or configuration completeness.", presentation.NoticeText);
        Assert.AreEqual("Domain profile: active; Windows-reported firewall enabled locally.", presentation.ProfileText[0]);
        Assert.IsFalse(Regex.IsMatch(string.Join(' ', presentation.NoticeText, presentation.StateText, string.Join(' ', presentation.ProfileText)),
            "\\b(Protected|Safe|Secure|Trusted|Clean)\\b", RegexOptions.IgnoreCase));
    }

    private static WindowsFirewallProfileNativeSnapshot Native(int mask, params WindowsFirewallLocalState[] states) =>
        new(true, mask, false, [.. states]);

    private static WindowsFirewallProfileObservationSnapshot Snapshot(WindowsFirewallProfileObservationState state) => new(DateTimeOffset.UtcNow, state,
        [
            new(WindowsFirewallProfile.Domain, WindowsFirewallProfileActivity.Active, WindowsFirewallLocalState.Enabled),
            new(WindowsFirewallProfile.Private, WindowsFirewallProfileActivity.NotActive, WindowsFirewallLocalState.NotObserved),
            new(WindowsFirewallProfile.Public, WindowsFirewallProfileActivity.NotActive, WindowsFirewallLocalState.NotObserved)
        ]);

    private sealed class FakeNativeReader(WindowsFirewallProfileNativeSnapshot result) : IWindowsFirewallProfileNativeReader
    {
        public WindowsFirewallProfileNativeSnapshot Read() => result;
    }

    private sealed class FakePolicyFactory(FakePolicy policy) : IWindowsFirewallPolicyFactory
    {
        internal int CreateCalls { get; private set; }
        public IWindowsFirewallPolicy Create() { CreateCalls++; return policy; }
    }

    private sealed class ThrowingPolicyFactory : IWindowsFirewallPolicyFactory
    {
        public IWindowsFirewallPolicy Create() => throw new COMException("private failure", unchecked((int)0x80004005));
    }

    private sealed class FakePolicy(int mask) : IWindowsFirewallPolicy
    {
        internal Dictionary<int, short> Values { get; } = [];
        internal List<int> EnabledCalls { get; } = [];
        internal int? FailingProfile { get; init; }
        internal int DisposeCalls { get; private set; }
        public bool TryGetCurrentProfileTypes(out int profileMask) { profileMask = mask; return true; }
        public bool TryGetFirewallEnabled(int profileBit, out short enabled)
        {
            EnabledCalls.Add(profileBit);
            if (FailingProfile == profileBit) { enabled = 0; return false; }
            return Values.TryGetValue(profileBit, out enabled);
        }
        public void Dispose() => DisposeCalls++;
    }

    private sealed class BlockingSource : IWindowsFirewallProfileObservationSource
    {
        private readonly TaskCompletionSource<WindowsFirewallProfileObservationSnapshot> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public WindowsFirewallProfileObservationSnapshot Collect()
        {
            Entered.TrySetResult(true);
            return _completion.Task.GetAwaiter().GetResult();
        }
        internal void Complete(WindowsFirewallProfileObservationSnapshot snapshot) => _completion.TrySetResult(snapshot);
    }
}
