using Vantrel.Security.Core;

namespace Vantrel.Security.Desktop;

internal sealed record DashboardProtectionPresentation(string StateText, string NoticeText)
{
    internal const string UnavailableState = "Unavailable";
    internal const string UnavailableNotice = "Vantrel active protection is unavailable in this build.";

    internal static DashboardProtectionPresentation Create(ProtectionState? _) =>
        new(UnavailableState, UnavailableNotice);
}
