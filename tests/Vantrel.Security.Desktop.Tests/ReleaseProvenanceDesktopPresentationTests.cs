using Vantrel.Security.Core;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class ReleaseProvenanceDesktopPresentationTests
{
    [TestMethod]
    public void Presentation_has_bounded_current_unavailable_disconnected_and_recovered_states()
    {
        var now = DateTimeOffset.UtcNow;
        var current = Valid(now.AddMinutes(-1));
        Assert.AreEqual(ReleaseProvenanceDisplayState.Current, ReleaseProvenanceDesktopPresentation.Create(current, true, now).DisplayState);
        Assert.AreEqual(ReleaseProvenanceDisplayState.Unavailable, ReleaseProvenanceDesktopPresentation.Create(null, true, now).DisplayState);
        Assert.AreEqual(ReleaseProvenanceDisplayState.Disconnected, ReleaseProvenanceDesktopPresentation.Create(current, false, now).DisplayState);
        Assert.AreEqual(ReleaseProvenanceDisplayState.Recovered, ReleaseProvenanceDesktopPresentation.Create(current, true, now, true).DisplayState);
    }

    [DataTestMethod]
    [DataRow(ReleaseMetadataSignatureState.SignatureInvalid, ReleaseManifestBindingState.ManifestUnavailable, ReleasePolicyDecision.PolicyUnavailable)]
    [DataRow(ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.ManifestMismatch, ReleasePolicyDecision.PolicyUnavailable)]
    [DataRow(ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.Bound, ReleasePolicyDecision.RollbackBlocked)]
    [DataRow(ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.Bound, ReleasePolicyDecision.SequenceConflict)]
    [DataRow(ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.Bound, ReleasePolicyDecision.PolicyUnavailable)]
    public void Bounded_failure_states_are_rendered_without_paths_hashes_or_free_form_service_text(
        ReleaseMetadataSignatureState signature, ReleaseManifestBindingState binding, ReleasePolicyDecision policy)
    {
        var view = ReleaseProvenanceDesktopPresentation.Create(Valid(DateTimeOffset.UtcNow) with
        {
            MetadataSignatureState = signature, ManifestBindingState = binding, PolicyDecision = policy,
            Product = null, Architecture = null, Channel = null, ReleaseSequence = null, DisplayVersion = null, ManifestSha256 = null
        }, true, DateTimeOffset.UtcNow);
        StringAssert.Contains(view.ValueText, signature.ToString());
        StringAssert.Contains(view.ValueText, binding.ToString());
        StringAssert.Contains(view.ValueText, policy.ToString());
        Assert.IsFalse(view.ValueText.Contains("C:\\", StringComparison.Ordinal));
        Assert.IsFalse(view.ValueText.Contains("SHA", StringComparison.OrdinalIgnoreCase));
    }

    private static ReleaseProvenanceSnapshot Valid(DateTimeOffset sampledAt) => new(sampledAt,
        ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.Bound, ReleaseMetadataCodec.Product,
        ReleaseMetadataCodec.Architecture, ReleaseMetadataCodec.Channel, 1, "0.1.0", ReleasePolicyDecision.BootstrapAccepted,
        new string('A', 64));
}