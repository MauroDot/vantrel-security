using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;

namespace Vantrel.Security.Infrastructure;

/// <summary>Creates the separate authorized-command endpoint; Status.v1 is never used for commands.</summary>
public static class CommandPipeServer
{
    internal const uint PipeRejectRemoteClients = 0x00000008;
    private const uint PipeAccessDuplex = 0x00000003, FileFlagOverlapped = 0x40000000, FileFlagFirstPipeInstance = 0x00080000;
    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipe(string name, uint openMode, uint pipeMode, uint instances, uint outBuffer, uint inBuffer, uint timeout, ref SecurityAttributes security);
    public static NamedPipeServerStream Create(string pipeName = CommandProtocol.PipeName)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Command IPC requires Windows.");
        var owner = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("The service account has no Windows SID.");
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(owner);
        security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), StatusPipeServer.ClientRights, AccessControlType.Allow));
        var descriptor = security.GetSecurityDescriptorBinaryForm();
        var memory = Marshal.AllocHGlobal(descriptor.Length);
        try
        {
            Marshal.Copy(descriptor, 0, memory, descriptor.Length);
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = memory, Inherit = false };
            var handle = CreateNamedPipe("\\\\.\\pipe\\" + pipeName, PipeAccessDuplex | FileFlagOverlapped | FileFlagFirstPipeInstance,
                PipeRejectRemoteClients, 1, CommandProtocol.MaximumMessageBytes, CommandProtocol.MaximumMessageBytes, 0, ref attributes);
            if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
            return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
        }
        finally { Marshal.FreeHGlobal(memory); }
    }
}
