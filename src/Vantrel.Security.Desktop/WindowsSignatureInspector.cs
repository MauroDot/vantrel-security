using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Desktop;

internal enum WindowsSignatureInspectionOutcome
{
    Completed,
    Declined,
    Unavailable,
    Changed,
    AlreadyInProgress
}

internal enum LocalCatalogSignatureOutcome
{
    MatchingCatalogVerified,
    MatchingCatalogVerificationFailed,
    NoMatchingCatalogObserved,
    Unavailable,
    Incomplete
}

internal sealed record LocalCatalogSignatureResult(LocalCatalogSignatureOutcome Outcome);

internal sealed record WindowsSignatureInspectionResult(
    WindowsSignatureInspectionOutcome Outcome,
    string? FileName,
    long? ByteLength,
    AuthenticodePublisherInspectionOutcome? EmbeddedOutcome,
    string? DeclaredEmbeddedSignerSubject,
    LocalCatalogSignatureOutcome? CatalogOutcome)
{
    internal static WindowsSignatureInspectionResult WithoutFile(WindowsSignatureInspectionOutcome outcome) =>
        new(outcome, null, null, null, null, null);
}

/// <summary>
/// Observes embedded Authenticode and locally installed catalog membership for one validated file.
/// It intentionally does not make a composite trust or safety determination.
/// </summary>
internal sealed class WindowsSignatureInspector
{
    private readonly IAuthenticodeTrustAdapter _embeddedTrust;
    private readonly ILocalCatalogSignatureAdapter _catalogTrust;
    private readonly LocalFileInspectionCoordinator _coordinator;
    private readonly Func<CancellationToken, Task>? _afterPathValidationAsync;

    internal WindowsSignatureInspector(
        IAuthenticodeTrustAdapter? embeddedTrust = null,
        ILocalCatalogSignatureAdapter? catalogTrust = null,
        LocalFileInspectionCoordinator? coordinator = null,
        Func<CancellationToken, Task>? afterPathValidationAsync = null)
    {
        _embeddedTrust = embeddedTrust ?? new WindowsAuthenticodeTrustAdapter();
        _catalogTrust = catalogTrust ?? new WindowsLocalCatalogSignatureAdapter();
        _coordinator = coordinator ?? new LocalFileInspectionCoordinator();
        _afterPathValidationAsync = afterPathValidationAsync;
    }

    internal async Task<WindowsSignatureInspectionResult> InspectAsync(string selectedPath, CancellationToken cancellationToken)
    {
        if (!_coordinator.TryAcquire(out var operation))
            return WindowsSignatureInspectionResult.WithoutFile(WindowsSignatureInspectionOutcome.AlreadyInProgress);

        using (operation)
        {
            var opened = await LocalRegularFileLease.OpenAsync(selectedPath, cancellationToken, _afterPathValidationAsync)
                .ConfigureAwait(false);
            if (opened.Outcome != LocalRegularFileLeaseOutcome.Opened)
            {
                return WindowsSignatureInspectionResult.WithoutFile(opened.Outcome == LocalRegularFileLeaseOutcome.Declined
                    ? WindowsSignatureInspectionOutcome.Declined
                    : WindowsSignatureInspectionOutcome.Unavailable);
            }

            using var file = opened.Lease!;
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var embedded = _embeddedTrust.VerifyEmbeddedSignature(file.FinalDosPath, file.Handle);
                // WinTrust is synchronous and cannot be cancelled. Do not begin catalog work after cancellation or change.
                cancellationToken.ThrowIfCancellationRequested();
                if (!file.IsUnchanged())
                    return WindowsSignatureInspectionResult.WithoutFile(WindowsSignatureInspectionOutcome.Changed);

                var catalog = _catalogTrust.Inspect(file.FinalDosPath, file.Handle);
                // Catalog hashing, enumeration, and WinTrust verification are synchronous native work.
                cancellationToken.ThrowIfCancellationRequested();
                if (!file.IsUnchanged())
                    return WindowsSignatureInspectionResult.WithoutFile(WindowsSignatureInspectionOutcome.Changed);

                return new WindowsSignatureInspectionResult(
                    WindowsSignatureInspectionOutcome.Completed,
                    file.FileName,
                    file.ByteLength,
                    AuthenticodePublisherInspector.MapStatus(embedded.Status),
                    embedded.DeclaredSignerSubject,
                    catalog.Outcome);
            }
            catch (DllNotFoundException) { return WindowsSignatureInspectionResult.WithoutFile(WindowsSignatureInspectionOutcome.Unavailable); }
            catch (EntryPointNotFoundException) { return WindowsSignatureInspectionResult.WithoutFile(WindowsSignatureInspectionOutcome.Unavailable); }
            catch (BadImageFormatException) { return WindowsSignatureInspectionResult.WithoutFile(WindowsSignatureInspectionOutcome.Unavailable); }
        }
    }
}

internal interface ILocalCatalogSignatureAdapter
{
    LocalCatalogSignatureResult Inspect(string finalDosPath, SafeFileHandle fileHandle);
}

internal enum LocalCatalogEnumerationKind { Catalog, Completed, Failed }

internal readonly record struct LocalCatalogEnumeration(LocalCatalogEnumerationKind Kind, IntPtr CatalogContext);
internal sealed record LocalCatalogMetadata(string CatalogPath);
internal sealed record CatalogTrustNativeCall(int Status, object? State);

internal interface ILocalCatalogNativeApi
{
    IntPtr AcquireCatalogAdmin();
    bool TryGetHashLength(IntPtr catalogAdmin, SafeFileHandle fileHandle, out uint hashLength);
    bool TryCalculateHash(IntPtr catalogAdmin, SafeFileHandle fileHandle, byte[] hash);
    LocalCatalogEnumeration Enumerate(IntPtr catalogAdmin, byte[] hash, IntPtr previousCatalogContext);
    bool TryGetCatalogMetadata(IntPtr catalogContext, out LocalCatalogMetadata metadata);
    CatalogTrustNativeCall VerifyCatalog(string catalogPath, string memberTag, string finalDosPath, SafeFileHandle fileHandle, byte[] hash, IntPtr catalogAdmin);
    void Close(CatalogTrustNativeCall call);
    void ReleaseCatalog(IntPtr catalogAdmin, IntPtr catalogContext);
    void ReleaseCatalogAdmin(IntPtr catalogAdmin);
}

internal sealed class WindowsLocalCatalogSignatureAdapter : ILocalCatalogSignatureAdapter
{
    internal const uint MaximumCatalogHashLength = 64 * 1024;
    internal const int MaximumCatalogCandidates = 16;
    private readonly ILocalCatalogNativeApi _native;

    internal WindowsLocalCatalogSignatureAdapter(ILocalCatalogNativeApi? native = null) =>
        _native = native ?? new LocalCatalogNativeApi();

    public LocalCatalogSignatureResult Inspect(string finalDosPath, SafeFileHandle fileHandle)
    {
        IntPtr catalogAdmin = IntPtr.Zero;
        IntPtr previousCatalog = IntPtr.Zero;
        try
        {
            catalogAdmin = _native.AcquireCatalogAdmin();
            if (catalogAdmin == IntPtr.Zero || !_native.TryGetHashLength(catalogAdmin, fileHandle, out var hashLength) ||
                hashLength == 0 || hashLength > MaximumCatalogHashLength)
            {
                return new LocalCatalogSignatureResult(LocalCatalogSignatureOutcome.Unavailable);
            }

            var hash = new byte[hashLength];
            if (!_native.TryCalculateHash(catalogAdmin, fileHandle, hash))
                return new LocalCatalogSignatureResult(LocalCatalogSignatureOutcome.Unavailable);

            var memberTag = Convert.ToHexString(hash);
            var observedMatchingCatalog = false;
            for (var candidate = 0; candidate < MaximumCatalogCandidates; candidate++)
            {
                var next = _native.Enumerate(catalogAdmin, hash, previousCatalog);
                if (previousCatalog != IntPtr.Zero)
                {
                    _native.ReleaseCatalog(catalogAdmin, previousCatalog);
                    previousCatalog = IntPtr.Zero;
                }

                if (next.Kind == LocalCatalogEnumerationKind.Failed)
                    return new LocalCatalogSignatureResult(LocalCatalogSignatureOutcome.Incomplete);
                if (next.Kind == LocalCatalogEnumerationKind.Completed)
                    return new LocalCatalogSignatureResult(observedMatchingCatalog
                        ? LocalCatalogSignatureOutcome.MatchingCatalogVerificationFailed
                        : LocalCatalogSignatureOutcome.NoMatchingCatalogObserved);
                previousCatalog = next.CatalogContext;
                if (previousCatalog == IntPtr.Zero || !_native.TryGetCatalogMetadata(previousCatalog, out var metadata) ||
                    string.IsNullOrWhiteSpace(metadata.CatalogPath))
                {
                    return new LocalCatalogSignatureResult(LocalCatalogSignatureOutcome.Incomplete);
                }

                observedMatchingCatalog = true;
                CatalogTrustNativeCall call = _native.VerifyCatalog(
                    metadata.CatalogPath, memberTag, finalDosPath, fileHandle, hash, catalogAdmin);
                try
                {
                    if (call.Status == 0)
                        return new LocalCatalogSignatureResult(LocalCatalogSignatureOutcome.MatchingCatalogVerified);
                }
                finally
                {
                    _native.Close(call);
                }
            }

            return new LocalCatalogSignatureResult(LocalCatalogSignatureOutcome.Incomplete);
        }
        catch (Win32Exception) { return new LocalCatalogSignatureResult(LocalCatalogSignatureOutcome.Unavailable); }
        catch (ExternalException) { return new LocalCatalogSignatureResult(LocalCatalogSignatureOutcome.Unavailable); }
        catch (SecurityException) { return new LocalCatalogSignatureResult(LocalCatalogSignatureOutcome.Unavailable); }
        catch (CatalogVerificationSetupException) { return new LocalCatalogSignatureResult(LocalCatalogSignatureOutcome.Unavailable); }
        finally
        {
            if (previousCatalog != IntPtr.Zero)
                _native.ReleaseCatalog(catalogAdmin, previousCatalog);
            if (catalogAdmin != IntPtr.Zero)
                _native.ReleaseCatalogAdmin(catalogAdmin);
        }
    }
}

internal sealed class LocalCatalogNativeApi : ILocalCatalogNativeApi
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckChain = 0x00000040;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    private const uint WtdDisableMd2Md4 = 0x00002000;
    private const int MaxPath = 260;
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    private readonly ILocalCatalogTrustMemory _memory;

    internal LocalCatalogNativeApi(ILocalCatalogTrustMemory? memory = null) => _memory = memory ?? new CatalogTrustMemory();

    public IntPtr AcquireCatalogAdmin()
    {
        return CryptCATAdminAcquireContext2(out var catalogAdmin, IntPtr.Zero, null, IntPtr.Zero, 0) ? catalogAdmin : IntPtr.Zero;
    }

    public bool TryGetHashLength(IntPtr catalogAdmin, SafeFileHandle fileHandle, out uint hashLength)
    {
        hashLength = 0;
        return CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, fileHandle, ref hashLength, null, 0);
    }

    public bool TryCalculateHash(IntPtr catalogAdmin, SafeFileHandle fileHandle, byte[] hash)
    {
        var hashLength = checked((uint)hash.Length);
        return CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, fileHandle, ref hashLength, hash, 0) && hashLength == hash.Length;
    }

    public LocalCatalogEnumeration Enumerate(IntPtr catalogAdmin, byte[] hash, IntPtr previousCatalogContext)
    {
        Marshal.SetLastPInvokeError(0);
        var catalog = CryptCATAdminEnumCatalogFromHash(catalogAdmin, hash, checked((uint)hash.Length), 0, previousCatalogContext);
        if (catalog != IntPtr.Zero) return new(LocalCatalogEnumerationKind.Catalog, catalog);
        return Marshal.GetLastPInvokeError() == 0
            ? new(LocalCatalogEnumerationKind.Completed, IntPtr.Zero)
            : new(LocalCatalogEnumerationKind.Failed, IntPtr.Zero);
    }

    public bool TryGetCatalogMetadata(IntPtr catalogContext, out LocalCatalogMetadata metadata)
    {
        var info = new CatalogInfo { cbStruct = (uint)Marshal.SizeOf<CatalogInfo>() };
        if (CryptCATCatalogInfoFromContext(catalogContext, ref info, 0) && !string.IsNullOrWhiteSpace(info.wszCatalogFile))
        {
            metadata = new LocalCatalogMetadata(info.wszCatalogFile);
            return true;
        }
        metadata = null!;
        return false;
    }

    public CatalogTrustNativeCall VerifyCatalog(string catalogPath, string memberTag, string finalDosPath, SafeFileHandle fileHandle, byte[] hash, IntPtr catalogAdmin)
    {
        var catalogPathPointer = IntPtr.Zero;
        var memberTagPointer = IntPtr.Zero;
        var memberPathPointer = IntPtr.Zero;
        var hashPointer = IntPtr.Zero;
        var catalogInfoPointer = IntPtr.Zero;
        var ownershipTransferred = false;
        try
        {
            catalogPathPointer = _memory.AllocCoTaskMemString(catalogPath);
            memberTagPointer = _memory.AllocCoTaskMemString(memberTag);
            memberPathPointer = _memory.AllocCoTaskMemString(finalDosPath);
            hashPointer = _memory.AllocHGlobal(hash.Length);
            _memory.Copy(hash, hashPointer);
            var catalogInfo = new WinTrustCatalogInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                pcwszCatalogFilePath = catalogPathPointer,
                pcwszMemberTag = memberTagPointer,
                pcwszMemberFilePath = memberPathPointer,
                hMemberFile = fileHandle.DangerousGetHandle(),
                pbCalculatedFileHash = hashPointer,
                cbCalculatedFileHash = checked((uint)hash.Length),
                hCatAdmin = catalogAdmin
            };
            catalogInfoPointer = _memory.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
            _memory.WriteCatalogInfo(catalogInfoPointer, catalogInfo);
            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeWholeChain,
                dwUnionChoice = WtdChoiceCatalog,
                pCatalog = catalogInfoPointer,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdRevocationCheckChain | WtdCacheOnlyUrlRetrieval | WtdDisableMd2Md4
            };
            var action = GenericVerifyV2;
            var status = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            var call = new CatalogTrustNativeCall(status,
                new CatalogNativeState(catalogPathPointer, memberTagPointer, memberPathPointer, hashPointer, catalogInfoPointer, data));
            ownershipTransferred = true;
            return call;
        }
        catch
        {
            throw new CatalogVerificationSetupException();
        }
        finally
        {
            if (!ownershipTransferred)
                ReleaseSetupAllocations(catalogPathPointer, memberTagPointer, memberPathPointer, hashPointer, catalogInfoPointer);
        }
    }

    private void ReleaseSetupAllocations(IntPtr catalogPathPointer, IntPtr memberTagPointer, IntPtr memberPathPointer,
        IntPtr hashPointer, IntPtr catalogInfoPointer)
    {
        try { if (catalogInfoPointer != IntPtr.Zero) _memory.FreeHGlobal(catalogInfoPointer); }
        finally
        {
            try { if (hashPointer != IntPtr.Zero) _memory.FreeHGlobal(hashPointer); }
            finally
            {
                try { if (memberPathPointer != IntPtr.Zero) _memory.FreeCoTaskMem(memberPathPointer); }
                finally
                {
                    try { if (memberTagPointer != IntPtr.Zero) _memory.FreeCoTaskMem(memberTagPointer); }
                    finally { if (catalogPathPointer != IntPtr.Zero) _memory.FreeCoTaskMem(catalogPathPointer); }
                }
            }
        }
    }

    public void Close(CatalogTrustNativeCall call)
    {
        if (call.State is not CatalogNativeState state) return;
        try
        {
            if (state.Data.hWVTStateData != IntPtr.Zero)
            {
                var close = state.Data;
                close.dwStateAction = WtdStateActionClose;
                var action = GenericVerifyV2;
                _ = WinVerifyTrust(IntPtr.Zero, ref action, ref close);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(state.CatalogInfoPointer);
            Marshal.FreeHGlobal(state.HashPointer);
            Marshal.FreeCoTaskMem(state.MemberPathPointer);
            Marshal.FreeCoTaskMem(state.MemberTagPointer);
            Marshal.FreeCoTaskMem(state.CatalogPathPointer);
        }
    }

    public void ReleaseCatalog(IntPtr catalogAdmin, IntPtr catalogContext)
    {
        if (catalogAdmin != IntPtr.Zero && catalogContext != IntPtr.Zero)
            _ = CryptCATAdminReleaseCatalogContext(catalogAdmin, catalogContext, 0);
    }

    public void ReleaseCatalogAdmin(IntPtr catalogAdmin)
    {
        if (catalogAdmin != IntPtr.Zero)
            _ = CryptCATAdminReleaseContext(catalogAdmin, 0);
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr catalogAdmin, IntPtr subsystem, string? hashAlgorithm, IntPtr strongHashPolicy, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catalogAdmin, SafeFileHandle fileHandle, ref uint hashLength, byte[]? hash, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catalogAdmin, byte[] hash, uint hashLength, uint flags, IntPtr previousCatalogContext);
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalogContext, ref CatalogInfo info, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catalogAdmin, IntPtr catalogContext, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catalogAdmin, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid actionId, ref WinTrustData data);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        internal uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MaxPath)]
        internal string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustCatalogInfo
    {
        internal uint cbStruct;
        internal uint dwCatalogVersion;
        internal IntPtr pcwszCatalogFilePath;
        internal IntPtr pcwszMemberTag;
        internal IntPtr pcwszMemberFilePath;
        internal IntPtr hMemberFile;
        internal IntPtr pbCalculatedFileHash;
        internal uint cbCalculatedFileHash;
        internal IntPtr hCatAdmin;
        internal uint dwFlags;
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
        internal IntPtr pCatalog;
        internal uint dwStateAction;
        internal IntPtr hWVTStateData;
        internal IntPtr pwszURLReference;
        internal uint dwProvFlags;
        internal uint dwUIContext;
        internal IntPtr pSignatureSettings;
    }

    private sealed record CatalogNativeState(
        IntPtr CatalogPathPointer,
        IntPtr MemberTagPointer,
        IntPtr MemberPathPointer,
        IntPtr HashPointer,
        IntPtr CatalogInfoPointer,
        WinTrustData Data);
}

internal sealed class CatalogVerificationSetupException : Exception;

internal interface ILocalCatalogTrustMemory
{
    IntPtr AllocCoTaskMemString(string value);
    IntPtr AllocHGlobal(int byteCount);
    void Copy(byte[] source, IntPtr destination);
    void WriteCatalogInfo(IntPtr destination, LocalCatalogNativeApi.WinTrustCatalogInfo catalogInfo);
    void FreeCoTaskMem(IntPtr pointer);
    void FreeHGlobal(IntPtr pointer);
}

internal sealed class CatalogTrustMemory : ILocalCatalogTrustMemory
{
    public IntPtr AllocCoTaskMemString(string value) => Marshal.StringToCoTaskMemUni(value);
    public IntPtr AllocHGlobal(int byteCount) => Marshal.AllocHGlobal(byteCount);
    public void Copy(byte[] source, IntPtr destination) => Marshal.Copy(source, 0, destination, source.Length);
    public void WriteCatalogInfo(IntPtr destination, LocalCatalogNativeApi.WinTrustCatalogInfo catalogInfo) =>
        Marshal.StructureToPtr(catalogInfo, destination, false);
    public void FreeCoTaskMem(IntPtr pointer) => Marshal.FreeCoTaskMem(pointer);
    public void FreeHGlobal(IntPtr pointer) => Marshal.FreeHGlobal(pointer);
}
