namespace Vantrel.Security.Desktop;

internal sealed record FileFingerprintComparisonPresentation(string NoticeText, string StateText)
{
    internal const string Notice =
        "This comparison checks a newly created fingerprint against a value you supplied. It does not authenticate the publisher or source, and does not determine whether a file is safe.";

    internal static FileFingerprintComparisonPresentation Initial() =>
        new(Notice, "Enter an expected SHA-256 value, then choose one local file to compare.");
    internal static FileFingerprintComparisonPresentation InProgress() =>
        new(Notice, "Creating a new fingerprint for comparison...");
    internal static FileFingerprintComparisonPresentation Cancelled() =>
        new(Notice, "Fingerprint comparison was cancelled.");
    internal static FileFingerprintComparisonPresentation Create(FileFingerprintComparisonResult result) => result.Outcome switch
    {
        FileFingerprintComparisonOutcome.Match => new(Notice, "Fingerprint matches the value you supplied."),
        FileFingerprintComparisonOutcome.Mismatch => new(Notice, "Fingerprint does not match the value you supplied."),
        FileFingerprintComparisonOutcome.InvalidExpectedValue => new(Notice, "Enter exactly 64 ASCII hexadecimal characters."),
        FileFingerprintComparisonOutcome.Declined => new(Notice, "Fingerprint comparison was declined for this selection."),
        FileFingerprintComparisonOutcome.Changed => new(Notice, "Fingerprint comparison did not complete because the file changed."),
        FileFingerprintComparisonOutcome.AlreadyInProgress => new(Notice, "Another file inspection is already in progress."),
        _ => new(Notice, "Fingerprint comparison is unavailable for this selection.")
    };
}
