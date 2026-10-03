namespace Vantrel.Security.Desktop;

internal sealed record WindowsSecurityHandoffPresentation(string NoticeText, string StateText)
{
    internal const string Notice =
        "Windows Security manages antivirus scans and any resulting actions. Vantrel does not request, monitor, interpret, or report those scans.";

    internal static WindowsSecurityHandoffPresentation Initial() =>
        new(Notice, "Windows Security has not been opened from this view.");

    internal static WindowsSecurityHandoffPresentation Create(bool opened) =>
        new(Notice, opened ? "Windows Security open request was sent to Windows." : "Windows Security could not be opened.");
}
