using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Core;

namespace Vantrel.Security.Infrastructure;

/// <summary>Creates the single local status endpoint with an explicit, non-inherited DACL.</summary>
public static class StatusPipeServer
{
    // ReadWrite is deliberately not used: FILE_APPEND_DATA aliases FILE_CREATE_PIPE_INSTANCE.
    public const PipeAccessRights ClientRights = PipeAccessRights.ReadData |
        PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes |
        PipeAccessRights.ReadPermissions | PipeAccessRights.Synchronize;

    public static NamedPipeServerStream Create(string pipeName = StatusProtocol.PipeName)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Status IPC requires Windows.");

        var owner = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("The service account has no Windows SID.");
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(owner);
        security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), ClientRights, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
            StatusProtocol.MaximumMessageBytes, StatusProtocol.MaximumMessageBytes, security);
    }
}
