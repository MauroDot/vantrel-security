using System.Collections.Immutable;
using Vantrel.Security.Core;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class TrustedManifestIntegrityHistoryPresentationTests
{
    [TestMethod]
    public void Presentation_distinguishes_loading_empty_current_disconnected_unavailable_recovered_and_reset()
    {
        var empty = Snapshot([]);
        Assert.AreEqual(TrustedManifestIntegrityHistoryDisplayState.Empty, TrustedManifestIntegrityHistoryPresentation.State(empty, true));
        Assert.AreEqual(TrustedManifestIntegrityHistoryDisplayState.Unavailable, TrustedManifestIntegrityHistoryPresentation.State(null, true));
        Assert.AreEqual(TrustedManifestIntegrityHistoryDisplayState.Disconnected, TrustedManifestIntegrityHistoryPresentation.State(empty, false));
        Assert.AreEqual(TrustedManifestIntegrityHistoryDisplayState.Recovered, TrustedManifestIntegrityHistoryPresentation.State(Snapshot([Entry()]), true, true));
        Assert.AreEqual(TrustedManifestIntegrityHistoryDisplayState.Reset, TrustedManifestIntegrityHistoryPresentation.State(empty, true, false, true));
        Assert.AreEqual(TrustedManifestIntegrityHistoryDisplayState.Current, TrustedManifestIntegrityHistoryPresentation.State(Snapshot([Entry()]), true));
    }

    [TestMethod]
    public void Record_has_only_the_three_bounded_historical_fields()
    {
        Assert.IsTrue(typeof(TrustedManifestIntegrityHistoryRecord).GetProperties().Select(property => property.Name).OrderBy(name => name)
            .SequenceEqual(new[] { "Evaluation", "SampledAtUtc", "SignatureState" }));
    }

    private static TrustedManifestIntegrityHistorySnapshot Snapshot(ImmutableArray<TrustedManifestIntegrityHistoryRecord> entries)
    {
        var now = DateTimeOffset.UtcNow; return new(now.AddMinutes(-1), now, entries);
    }
    private static TrustedManifestIntegrityHistoryRecord Entry() => new(DateTimeOffset.UtcNow,
        TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.AllMatch);
}
