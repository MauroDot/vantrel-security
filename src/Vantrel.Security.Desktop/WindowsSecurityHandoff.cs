using System.Diagnostics;

namespace Vantrel.Security.Desktop;

internal interface IWindowsSecurityHandoffLauncher
{
    bool TryLaunch(Uri target);
}

internal sealed class WindowsSecurityHandoffLauncher : IWindowsSecurityHandoffLauncher
{
    public bool TryLaunch(Uri target)
    {
        ArgumentNullException.ThrowIfNull(target);
        try
        {
            return Process.Start(new ProcessStartInfo(target.OriginalString) { UseShellExecute = true }) is not null;
        }
        catch (Exception error) when (IsRecoverableFailure(error))
        {
            return false;
        }
    }

    private static bool IsRecoverableFailure(Exception error) => error is not OutOfMemoryException and not StackOverflowException and not AccessViolationException;
}

internal sealed class WindowsSecurityHandoff
{
    internal const string SettingsUri = "ms-settings:windowsdefender";
    private static readonly Uri Target = new(SettingsUri, UriKind.Absolute);
    private readonly IWindowsSecurityHandoffLauncher _launcher;

    internal WindowsSecurityHandoff(IWindowsSecurityHandoffLauncher? launcher = null) =>
        _launcher = launcher ?? new WindowsSecurityHandoffLauncher();

    internal WindowsSecurityHandoffPresentation Open()
    {
        try
        {
            return WindowsSecurityHandoffPresentation.Create(_launcher.TryLaunch(Target));
        }
        catch (Exception error) when (IsRecoverableFailure(error))
        {
            return WindowsSecurityHandoffPresentation.Create(false);
        }
    }

    private static bool IsRecoverableFailure(Exception error) => error is not OutOfMemoryException and not StackOverflowException and not AccessViolationException;
}
