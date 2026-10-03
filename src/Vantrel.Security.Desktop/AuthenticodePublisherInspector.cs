using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Desktop;

internal enum AuthenticodePublisherInspectionOutcome
{
    Verified,
    Declined,
    VerificationFailed,
    NoUsableEmbeddedSignature,
    UnsupportedFileForm,
    Unavailable,
    Changed,
    AlreadyInProgress
}

internal sealed record AuthenticodePublisherInspectionResult(
    AuthenticodePublisherInspectionOutcome Outcome,
    string? FileName,
    long? ByteLength,
    string? DeclaredSignerSubject)
{
    internal static AuthenticodePublisherInspectionResult WithoutFile(AuthenticodePublisherInspectionOutcome outcome) =>
        new(outcome, null, null, null);
}

internal sealed record AuthenticodeNativeResult(int Status, string? DeclaredSignerSubject);

internal interface IAuthenticodeTrustAdapter
{
    AuthenticodeNativeResult VerifyEmbeddedSignature(string finalDosPath, SafeFileHandle fileHandle);
}

internal sealed class AuthenticodePublisherInspector
{
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustEProviderUnknown = unchecked((int)0x800B0001);
    private const int TrustEActionUnknown = unchecked((int)0x800B0002);
    private readonly IAuthenticodeTrustAdapter _trust;
    private readonly LocalFileInspectionCoordinator _coordinator;
    private readonly Func<CancellationToken, Task>? _afterPathValidationAsync;

    internal AuthenticodePublisherInspector(
        IAuthenticodeTrustAdapter? trust = null,
        LocalFileInspectionCoordinator? coordinator = null,
        Func<CancellationToken, Task>? afterPathValidationAsync = null)
    {
        _trust = trust ?? new WindowsAuthenticodeTrustAdapter();
        _coordinator = coordinator ?? new LocalFileInspectionCoordinator();
        _afterPathValidationAsync = afterPathValidationAsync;
    }

    internal async Task<AuthenticodePublisherInspectionResult> InspectAsync(string selectedPath, CancellationToken cancellationToken)
    {
        if (!_coordinator.TryAcquire(out var operation))
            return AuthenticodePublisherInspectionResult.WithoutFile(AuthenticodePublisherInspectionOutcome.AlreadyInProgress);

        using (operation)
        {
            var opened = await LocalRegularFileLease.OpenAsync(selectedPath, cancellationToken, _afterPathValidationAsync)
                .ConfigureAwait(false);
            if (opened.Outcome != LocalRegularFileLeaseOutcome.Opened)
            {
                return AuthenticodePublisherInspectionResult.WithoutFile(opened.Outcome == LocalRegularFileLeaseOutcome.Declined
                    ? AuthenticodePublisherInspectionOutcome.Declined
                    : AuthenticodePublisherInspectionOutcome.Unavailable);
            }

            using var file = opened.Lease!;
            cancellationToken.ThrowIfCancellationRequested();
            AuthenticodeNativeResult native;
            try
            {
                native = _trust.VerifyEmbeddedSignature(file.FinalDosPath, file.Handle);
            }
            catch (DllNotFoundException) { return AuthenticodePublisherInspectionResult.WithoutFile(AuthenticodePublisherInspectionOutcome.Unavailable); }
            catch (EntryPointNotFoundException) { return AuthenticodePublisherInspectionResult.WithoutFile(AuthenticodePublisherInspectionOutcome.Unavailable); }
            catch (BadImageFormatException) { return AuthenticodePublisherInspectionResult.WithoutFile(AuthenticodePublisherInspectionOutcome.Unavailable); }

            // Native verification cannot be cancelled. Suppress its result after it returns if cancellation won.
            cancellationToken.ThrowIfCancellationRequested();
            if (!file.IsUnchanged())
                return AuthenticodePublisherInspectionResult.WithoutFile(AuthenticodePublisherInspectionOutcome.Changed);

            return new AuthenticodePublisherInspectionResult(MapStatus(native.Status), file.FileName, file.ByteLength,
                native.DeclaredSignerSubject);
        }
    }

    internal static AuthenticodePublisherInspectionOutcome MapStatus(int status) => status switch
    {
        0 => AuthenticodePublisherInspectionOutcome.Verified,
        TrustENoSignature => AuthenticodePublisherInspectionOutcome.NoUsableEmbeddedSignature,
        TrustESubjectFormUnknown => AuthenticodePublisherInspectionOutcome.UnsupportedFileForm,
        TrustEProviderUnknown or TrustEActionUnknown => AuthenticodePublisherInspectionOutcome.Unavailable,
        _ => AuthenticodePublisherInspectionOutcome.VerificationFailed
    };
}

internal interface IWinTrustNativeApi
{
    WinTrustNativeCall Verify(string finalDosPath, SafeFileHandle fileHandle);
    string? GetDeclaredSignerSubject(WinTrustNativeCall call);
    void Close(WinTrustNativeCall call);
}

internal sealed record WinTrustNativeCall(int Status, object? State);

internal sealed class WindowsAuthenticodeTrustAdapter : IAuthenticodeTrustAdapter
{
    private readonly IWinTrustNativeApi _native;

    internal WindowsAuthenticodeTrustAdapter(IWinTrustNativeApi? native = null) => _native = native ?? new WinTrustNativeApi();

    public AuthenticodeNativeResult VerifyEmbeddedSignature(string finalDosPath, SafeFileHandle fileHandle)
    {
        var call = _native.Verify(finalDosPath, fileHandle);
        try
        {
            return new AuthenticodeNativeResult(call.Status,
                call.State is null ? null : _native.GetDeclaredSignerSubject(call));
        }
        finally
        {
            _native.Close(call);
        }
    }
}

internal sealed class WinTrustNativeApi : IWinTrustNativeApi
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckChain = 0x00000040;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    private const uint WtdDisableMd2Md4 = 0x00002000;
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public WinTrustNativeCall Verify(string finalDosPath, SafeFileHandle fileHandle)
    {
        var path = Marshal.StringToCoTaskMemUni(finalDosPath);
        var fileInfo = new WinTrustFileInfo
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            pcwszFilePath = path,
            hFile = fileHandle.DangerousGetHandle()
        };
        var fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
        var data = new WinTrustData
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
            dwUIChoice = WtdUiNone,
            fdwRevocationChecks = WtdRevokeWholeChain,
            dwUnionChoice = WtdChoiceFile,
            pFile = fileInfoPointer,
            dwStateAction = WtdStateActionVerify,
            dwProvFlags = WtdRevocationCheckChain | WtdCacheOnlyUrlRetrieval | WtdDisableMd2Md4
        };
        try
        {
            var action = GenericVerifyV2;
            var status = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return new WinTrustNativeCall(status, new NativeState(path, fileInfoPointer, data));
        }
        catch
        {
            Marshal.FreeHGlobal(fileInfoPointer);
            Marshal.FreeCoTaskMem(path);
            throw;
        }
    }

    public string? GetDeclaredSignerSubject(WinTrustNativeCall call)
    {
        if (call.State is not NativeState state || state.Data.hWVTStateData == IntPtr.Zero) return null;
        var provider = WTHelperProvDataFromStateData(state.Data.hWVTStateData);
        if (provider == IntPtr.Zero) return null;
        var signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
        if (signer == IntPtr.Zero) return null;
        var certificate = WTHelperGetProvCertFromChain(signer, 0);
        if (certificate == IntPtr.Zero) return null;
        var providerCertificate = Marshal.PtrToStructure<CryptProviderCert>(certificate);
        if (providerCertificate.pCert == IntPtr.Zero) return null;
        var length = CertGetNameString(providerCertificate.pCert, 4, 0, IntPtr.Zero, null, 0);
        if (length <= 1) return null;
        var subject = new StringBuilder((int)length);
        return CertGetNameString(providerCertificate.pCert, 4, 0, IntPtr.Zero, subject, length) == 0 ? null : subject.ToString();
    }

    public void Close(WinTrustNativeCall call)
    {
        if (call.State is not NativeState state) return;
        try
        {
            if (state.Data.hWVTStateData != IntPtr.Zero)
            {
                var data = state.Data;
                data.dwStateAction = WtdStateActionClose;
                var action = GenericVerifyV2;
                _ = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(state.FileInfoPointer);
            Marshal.FreeCoTaskMem(state.PathPointer);
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid actionId, ref WinTrustData data);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr providerData, uint signerIndex, [MarshalAs(UnmanagedType.Bool)] bool counterSigner, uint counterSignerIndex);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint certificateIndex);
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint CertGetNameString(IntPtr certificateContext, uint type, uint flags, IntPtr typeParameter, StringBuilder? name, uint nameChars);

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        internal uint cbStruct;
        internal IntPtr pcwszFilePath;
        internal IntPtr hFile;
        internal IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        internal uint cbStruct;
        internal IntPtr pPolicyCallbackData;
        internal IntPtr pSIPClientData;
        internal uint dwUIChoice;
        internal uint fdwRevocationChecks;
        internal uint dwUnionChoice;
        internal IntPtr pFile;
        internal uint dwStateAction;
        internal IntPtr hWVTStateData;
        internal IntPtr pwszURLReference;
        internal uint dwProvFlags;
        internal uint dwUIContext;
        internal IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderCert
    {
        internal uint cbStruct;
        internal IntPtr pCert;
    }

    private sealed record NativeState(IntPtr PathPointer, IntPtr FileInfoPointer, WinTrustData Data);
}
