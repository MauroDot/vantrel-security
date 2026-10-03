namespace Vantrel.Security.Desktop;

internal sealed record WindowsSignatureInspectionPresentation(
    string NoticeText,
    string StateText,
    string? FileName,
    long? ByteLength,
    string? EmbeddedStateText,
    string? DeclaredEmbeddedSignerSubject,
    string? CatalogStateText)
{
    internal const string Notice =
        "Windows signature inspection reports embedded Authenticode and locally enumerated catalog observations. It does not scan, classify, or determine file safety.";

    internal bool HasResult => FileName is not null && ByteLength is not null && EmbeddedStateText is not null && CatalogStateText is not null;

    internal static WindowsSignatureInspectionPresentation Initial() =>
        new(Notice, "Choose one local file to inspect embedded and local catalog signature observations.", null, null, null, null, null);
    internal static WindowsSignatureInspectionPresentation InProgress() =>
        new(Notice, "Inspecting Windows signature observations...", null, null, null, null, null);
    internal static WindowsSignatureInspectionPresentation Cancelled() =>
        new(Notice, "Windows signature inspection was cancelled.", null, null, null, null, null);

    internal static WindowsSignatureInspectionPresentation Create(WindowsSignatureInspectionResult result)
    {
        if (result.Outcome != WindowsSignatureInspectionOutcome.Completed || result.FileName is null || result.ByteLength is null ||
            result.EmbeddedOutcome is null || result.CatalogOutcome is null)
        {
            return result.Outcome switch
            {
                WindowsSignatureInspectionOutcome.Declined => new(Notice, "Windows signature inspection was declined for this selection.", null, null, null, null, null),
                WindowsSignatureInspectionOutcome.Changed => new(Notice, "Windows signature inspection did not complete because the file changed.", null, null, null, null, null),
                WindowsSignatureInspectionOutcome.AlreadyInProgress => new(Notice, "Another file inspection is already in progress.", null, null, null, null, null),
                _ => new(Notice, "Windows signature inspection is unavailable on this device.", null, null, null, null, null)
            };
        }

        var combinedAbsence = result.EmbeddedOutcome == AuthenticodePublisherInspectionOutcome.NoUsableEmbeddedSignature &&
            result.CatalogOutcome == LocalCatalogSignatureOutcome.NoMatchingCatalogObserved;
        return new(
            Notice,
            combinedAbsence
                ? "No usable embedded signature or matching local catalog signature was observed. This does not establish that the file is unsigned."
                : "Windows signature observations completed.",
            result.FileName,
            result.ByteLength,
            EmbeddedText(result.EmbeddedOutcome.Value),
            result.DeclaredEmbeddedSignerSubject,
            CatalogText(result.CatalogOutcome.Value));
    }

    private static string EmbeddedText(AuthenticodePublisherInspectionOutcome outcome) => outcome switch
    {
        AuthenticodePublisherInspectionOutcome.Verified => "Embedded Authenticode: Windows returned success using cached revocation data.",
        AuthenticodePublisherInspectionOutcome.VerificationFailed => "Embedded Authenticode: Windows returned a non-success result.",
        AuthenticodePublisherInspectionOutcome.NoUsableEmbeddedSignature => "Embedded Authenticode: no usable embedded signature was observed.",
        AuthenticodePublisherInspectionOutcome.UnsupportedFileForm => "Embedded Authenticode: this file form is unsupported.",
        AuthenticodePublisherInspectionOutcome.Unavailable => "Embedded Authenticode: Windows inspection is unavailable on this device.",
        _ => "Embedded Authenticode: no observation was available."
    };

    private static string CatalogText(LocalCatalogSignatureOutcome outcome) => outcome switch
    {
        LocalCatalogSignatureOutcome.MatchingCatalogVerified => "Local catalog: one matching locally enumerated catalog was verified by Windows using cached revocation data.",
        LocalCatalogSignatureOutcome.MatchingCatalogVerificationFailed => "Local catalog: matching local catalog verification returned a non-success result.",
        LocalCatalogSignatureOutcome.NoMatchingCatalogObserved => "Local catalog: no matching local catalog signature was observed. This does not establish that the file is unsigned.",
        LocalCatalogSignatureOutcome.Incomplete => "Local catalog: inspection was incomplete; no absence conclusion is available.",
        _ => "Local catalog: Windows catalog inspection is unavailable on this device."
    };
}
