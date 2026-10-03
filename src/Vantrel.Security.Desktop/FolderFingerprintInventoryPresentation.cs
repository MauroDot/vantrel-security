namespace Vantrel.Security.Desktop;

internal sealed record FolderFingerprintInventoryPresentation(string NoticeText, string StateText, IReadOnlyList<string> EntryText)
{
    internal const string Notice =
        "Folder fingerprint inventory records SHA-256 fingerprints for selected local files. It does not scan, detect, classify, authenticate publishers, determine safety, or remediate files.";

    internal static FolderFingerprintInventoryPresentation Initial() =>
        new(Notice, "Choose one local folder to inventory its direct regular-file children.", []);
    internal static FolderFingerprintInventoryPresentation InProgress() =>
        new(Notice, "Creating a bounded local folder fingerprint inventory...", []);
    internal static FolderFingerprintInventoryPresentation Cancelled() =>
        new(Notice, "Folder fingerprint inventory was cancelled.", []);
    internal static FolderFingerprintInventoryPresentation Create(FolderFingerprintInventoryResult result) => new(
        Notice,
        result.Outcome switch
        {
            FolderFingerprintInventoryOutcome.Completed => "Inventory completed; listed files were observed.",
            FolderFingerprintInventoryOutcome.Incomplete => "Inventory incomplete; only listed files were observed.",
            FolderFingerprintInventoryOutcome.Declined => "Folder fingerprint inventory was declined for this selection.",
            FolderFingerprintInventoryOutcome.AlreadyInProgress => "Another file inspection is already in progress.",
            _ => "Folder fingerprint inventory is unavailable for this selection."
        },
        result.Outcome is FolderFingerprintInventoryOutcome.Completed or FolderFingerprintInventoryOutcome.Incomplete
            ? result.Entries.Select(FormatEntry).ToArray()
            : []);

    private static string FormatEntry(FolderFingerprintInventoryEntry entry) => entry.Outcome switch
    {
        FolderFingerprintEntryOutcome.Fingerprinted => $"{entry.RelativeName} — {entry.ByteLength:N0} bytes — SHA-256: {entry.Sha256}",
        FolderFingerprintEntryOutcome.Changed => $"{entry.RelativeName} — changed during inventory",
        FolderFingerprintEntryOutcome.Declined => $"{entry.RelativeName} — declined",
        _ => $"{entry.RelativeName} — unavailable"
    };
}
