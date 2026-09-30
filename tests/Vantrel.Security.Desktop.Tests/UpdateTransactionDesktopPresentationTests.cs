using Vantrel.Security.Core;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class UpdateTransactionDesktopPresentationTests
{
    [DataTestMethod]
    [DataRow(UpdateTransactionPhase.Idle)]
    [DataRow(UpdateTransactionPhase.Prepared)]
    [DataRow(UpdateTransactionPhase.Verified)]
    [DataRow(UpdateTransactionPhase.ServiceStopped)]
    [DataRow(UpdateTransactionPhase.Replaced)]
    [DataRow(UpdateTransactionPhase.Restarted)]
    [DataRow(UpdateTransactionPhase.PostVerified)]
    [DataRow(UpdateTransactionPhase.PolicyCommitted)]
    [DataRow(UpdateTransactionPhase.Completed)]
    [DataRow(UpdateTransactionPhase.RollbackRequired)]
    [DataRow(UpdateTransactionPhase.RolledBack)]
    [DataRow(UpdateTransactionPhase.Failed)]
    public void Every_durable_phase_has_bounded_read_only_presentation(UpdateTransactionPhase phase)
    {
        var value = UpdateTransactionDesktopPresentation.Create(new UpdateTransactionSnapshot(DateTimeOffset.UtcNow, phase, phase == UpdateTransactionPhase.Verified,
            1, phase == UpdateTransactionPhase.Idle ? null : 2, UpdateTransactionResult.None), true, DateTimeOffset.UtcNow);
        Assert.AreEqual(UpdateTransactionDisplayState.Current, value.State);
        Assert.IsFalse(value.ValueText.Contains("\\", StringComparison.Ordinal));
        Assert.IsFalse(value.ValueText.Contains("hash", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(value.ValueText.Contains("Apply", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(value.ValueText.Contains("Rollback", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Stale_disconnected_and_unavailable_are_action_free()
    {
        var stale = UpdateTransactionDesktopPresentation.Create(new UpdateTransactionSnapshot(DateTimeOffset.UtcNow.AddMinutes(-31), UpdateTransactionPhase.Verified, true, 1, 2, UpdateTransactionResult.None), true, DateTimeOffset.UtcNow);
        var disconnected = UpdateTransactionDesktopPresentation.Create(null, false, DateTimeOffset.UtcNow);
        var unavailable = UpdateTransactionDesktopPresentation.Create(null, true, DateTimeOffset.UtcNow);
        Assert.AreEqual(UpdateTransactionDisplayState.Stale, stale.State);
        Assert.AreEqual(UpdateTransactionDisplayState.Disconnected, disconnected.State);
        Assert.AreEqual(UpdateTransactionDisplayState.Unavailable, unavailable.State);
    }
    [TestMethod]
    public void Presentation_is_read_only_and_formats_completed_recovery_without_paths_or_controls()
    {
        var snapshot = new UpdateTransactionSnapshot(DateTimeOffset.UtcNow, UpdateTransactionPhase.Completed, false, 1, 2, UpdateTransactionResult.Completed);
        var value = UpdateTransactionDesktopPresentation.Create(snapshot, true, DateTimeOffset.UtcNow, true);
        Assert.AreEqual(UpdateTransactionDisplayState.Recovered, value.State);
        StringAssert.Contains(value.ValueText, "completed");
        Assert.IsFalse(value.ValueText.Contains("\\", StringComparison.Ordinal));
        Assert.IsFalse(value.ValueText.Contains("Apply", StringComparison.Ordinal));
    }
}