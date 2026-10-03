namespace Vantrel.Security.Desktop;

internal sealed record FileFingerprintInspectionPresentation(
    string NoticeText,
    string StateText,
    string? FileName,
    long? ByteLength,
    string? Sha256)
{
    internal const string Notice =
        "File inspection creates a SHA-256 fingerprint. It does not scan, classify, or determine whether a file is safe.";

    internal bool HasCompletedFingerprint => FileName is not null && ByteLength is not null && Sha256 is not null;

    internal static FileFingerprintInspectionPresentation Initial() =>
        new(Notice, "Choose one local regular file to create a fingerprint.", null, null, null);

    internal static FileFingerprintInspectionPresentation InProgress() =>
        new(Notice, "Creating fingerprint…", null, null, null);

    internal static FileFingerprintInspectionPresentation Cancelled() =>
        new(Notice, "File inspection was cancelled.", null, null, null);

    internal static FileFingerprintInspectionPresentation Create(FileFingerprintInspectionResult result) => result.Outcome switch
    {
        FileFingerprintInspectionOutcome.Completed when result.FileName is not null && result.ByteLength is not null && result.Sha256 is not null =>
            new(Notice, "Fingerprint completed.", result.FileName, result.ByteLength, result.Sha256),
        FileFingerprintInspectionOutcome.Declined =>
            new(Notice, "File inspection was declined for this selection.", null, null, null),
        FileFingerprintInspectionOutcome.Changed =>
            new(Notice, "File inspection did not complete because the file changed.", null, null, null),
        FileFingerprintInspectionOutcome.AlreadyInProgress =>
            new(Notice, "A file inspection is already in progress.", null, null, null),
        _ => new(Notice, "File inspection is unavailable for this selection.", null, null, null)
    };
}
