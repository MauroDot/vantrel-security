using Vantrel.Security.Core;

namespace Vantrel.Security.Desktop;

/// <summary>Read-only Status.v1 presentation for the fixed offline update transaction.</summary>
internal static class UpdateTransactionDesktopPresentation
{
    internal static (UpdateTransactionDisplayState State, string StateText, string SampleText, string ValueText) Create(
        UpdateTransactionSnapshot? value, bool connected, DateTimeOffset now, bool wasDisconnected = false)
    {
        var state = UpdateTransactionPresentation.State(value, connected, now, wasDisconnected);
        if (!connected || value is null) return (state,
            state == UpdateTransactionDisplayState.Disconnected ? "Disconnected - service unavailable" : "Unavailable - update transaction state could not be read",
            "Sample: unavailable", "Update transaction: unavailable.");
        var stateText = state switch
        {
            UpdateTransactionDisplayState.Stale => "Stale - update transaction status is over 30 minutes old",
            UpdateTransactionDisplayState.Recovered => "Recovered - current update transaction status",
            _ => "Current update transaction status"
        };
        var valueText = value.Phase switch
        {
            UpdateTransactionPhase.Idle => "No update transaction is active.",
            UpdateTransactionPhase.Prepared => "Update transaction prepared.",
            UpdateTransactionPhase.Verified => "Candidate verified and awaiting the guarded offline transaction.",
            UpdateTransactionPhase.ServiceStopped or UpdateTransactionPhase.Replaced => "Service update is in progress.",
            UpdateTransactionPhase.Restarted => "Restarting service and verifying the installed release.",
            UpdateTransactionPhase.PostVerified => "Installed release verified; finalizing release policy.",
            UpdateTransactionPhase.PolicyCommitted => "Release policy committed; finalizing update transaction.",
            UpdateTransactionPhase.Completed => "Update completed.",
            UpdateTransactionPhase.RollbackRequired => "Update requires guarded predecessor restoration.",
            UpdateTransactionPhase.RolledBack => "Update rolled back to the verified predecessor.",
            _ => "Update failed; Administrator recovery is required."
        };
        return (state, stateText, $"Sample: {value.SampledAtUtc.ToLocalTime():G}", valueText);
    }
}