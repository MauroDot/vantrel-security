namespace Vantrel.Security.Desktop;

internal sealed record AuthenticodePublisherInspectionPresentation(
    string NoticeText,
    string StateText,
    string? FileName,
    long? ByteLength,
    string? DeclaredSignerSubject)
{
    internal const string Notice =
        "Embedded Authenticode publisher inspection reads signer information. It does not scan, classify, or determine whether a file is safe.";

    internal bool HasResult => FileName is not null && ByteLength is not null;

    internal static AuthenticodePublisherInspectionPresentation Initial() =>
        new(Notice, "Choose one local file to inspect its embedded Authenticode publisher information.", null, null, null);
    internal static AuthenticodePublisherInspectionPresentation InProgress() =>
        new(Notice, "Inspecting embedded Authenticode publisher information...", null, null, null);
    internal static AuthenticodePublisherInspectionPresentation Cancelled() =>
        new(Notice, "Embedded Authenticode publisher inspection was cancelled.", null, null, null);

    internal static AuthenticodePublisherInspectionPresentation Create(AuthenticodePublisherInspectionResult result) => result.Outcome switch
    {
        AuthenticodePublisherInspectionOutcome.Verified => new(Notice,
            "Windows Authenticode verification returned success using cached revocation data.", result.FileName, result.ByteLength, result.DeclaredSignerSubject),
        AuthenticodePublisherInspectionOutcome.VerificationFailed => new(Notice,
            "Windows Authenticode verification returned a non-success result.", result.FileName, result.ByteLength, result.DeclaredSignerSubject),
        AuthenticodePublisherInspectionOutcome.NoUsableEmbeddedSignature => new(Notice,
            "No usable embedded Authenticode signature was observed. Catalog signatures are not inspected in this build.", null, null, null),
        AuthenticodePublisherInspectionOutcome.Declined => new(Notice,
            "Embedded Authenticode publisher inspection was declined for this selection.", null, null, null),
        AuthenticodePublisherInspectionOutcome.UnsupportedFileForm => new(Notice,
            "Windows Authenticode does not support embedded-signature inspection for this file form.", null, null, null),
        AuthenticodePublisherInspectionOutcome.Changed => new(Notice,
            "Inspection did not complete because the file changed.", null, null, null),
        AuthenticodePublisherInspectionOutcome.AlreadyInProgress => new(Notice,
            "Another file inspection is already in progress.", null, null, null),
        _ => new(Notice, "Windows Authenticode inspection is unavailable on this device.", null, null, null)
    };
}
