using System.Runtime.InteropServices;

namespace Vantrel.Security.ReleaseLayoutTool;

public sealed record MsiAuthenticodeInspectionResult(bool Success, NativeAuthenticodeTrustCategory Trust,
    PrimarySignatureCountPolicyCategory PrimarySignatureCount, NativeDigestAlgorithmCategory Digest,
    TimestampPolicyCategory Timestamp, AuthenticodeEkuPolicyCategory EkuCategory)
{
    public const string PolicyId = "vantrel-azure-artifact-signing-durable-eku-v1";
}

/// <summary>Read-only MSI inspection; neither a release approval nor a distribution record.</summary>
public interface IMsiAuthenticodeInspector
{
    MsiAuthenticodeInspectionResult Inspect(string filePath);
    MsiAuthenticodeInspectionResult Inspect(MsiFileBinding retainedBinding);
}

public interface IMsiDatabaseValidator { bool IsReadOnlyDatabase(string path); }
public interface IMsiDatabaseNativeApi
{
    uint OpenReadOnly(string path, out uint database);
    uint Close(uint database);
}

public sealed class WindowsMsiDatabaseValidator(IMsiDatabaseNativeApi? native = null) : IMsiDatabaseValidator
{
    private readonly IMsiDatabaseNativeApi _native = native ?? new WindowsMsiDatabaseNativeApi();
    public bool IsReadOnlyDatabase(string path)
    {
        uint handle = 0; var opened = false; var closed = false;
        try { opened = _native.OpenReadOnly(path, out handle) == 0 && handle != 0; }
        catch { opened = false; }
        finally
        {
            if (handle != 0)
            {
                try { closed = _native.Close(handle) == 0; }
                catch { closed = false; }
            }
        }
        return opened && closed;
    }
    private sealed class WindowsMsiDatabaseNativeApi : IMsiDatabaseNativeApi
    {
        public uint OpenReadOnly(string path, out uint database) => MsiOpenDatabase(path, IntPtr.Zero, out database);
        public uint Close(uint database) => MsiCloseHandle(database);
        [DllImport("msi.dll", EntryPoint = "MsiOpenDatabaseW", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint MsiOpenDatabase(string databasePath, IntPtr persist, out uint database);
        [DllImport("msi.dll", ExactSpelling = true)] private static extern uint MsiCloseHandle(uint handle);
    }
}

public sealed class SingleMsiAuthenticodeInspector : IMsiAuthenticodeInspector
{
    private readonly IAuthenticodeNativeVerifier _native;
    private readonly IMsiDatabaseValidator _database;
    private readonly IReleaseSigningPolicy? _policy;

    public SingleMsiAuthenticodeInspector(IAuthenticodeNativeVerifier? native = null, IMsiDatabaseValidator? database = null)
    {
        _native = native ?? new WindowsAuthenticodeNativeVerifier(new WindowsWinTrustNativeApi(), new WindowsMsiProviderEvidenceReader());
        _database = database ?? new WindowsMsiDatabaseValidator();
        var profiles = new SourceOwnedReleaseSigningProfileSource();
        if (profiles.TryGet("vantrel-production", out var profile) &&
            profile.PolicyId == MsiAuthenticodeInspectionResult.PolicyId) _policy = profile.PublisherPolicy;
    }

    public MsiAuthenticodeInspectionResult Inspect(string filePath)
    {
        try
        {
            using var binding = MsiFileBinding.Open(ValidatePath(filePath));
            return Inspect(binding);
        }
        catch { throw new IOException("MSI inspection input is unavailable."); }
    }

    public MsiAuthenticodeInspectionResult Inspect(MsiFileBinding retainedBinding)
    {
        if (retainedBinding is null) throw new IOException("MSI inspection input is unavailable.");
        var path = ValidatePath(retainedBinding.Path);
        try
        {
            retainedBinding.RequireUnchanged();
            if (!_database.IsReadOnlyDatabase(path)) throw new IOException();
            retainedBinding.RequireUnchanged();
        }
        catch { throw new IOException("MSI inspection input is unavailable."); }
        // The caller retains this handle through native WinTrust and the final byte comparison.
        NativeAuthenticodeEvidence evidence;
        try { evidence = _native.Verify(path, retainedBinding.Handle); retainedBinding.RequireUnchanged(); }
        catch { evidence = new(NativeAuthenticodeTrustCategory.Unavailable, PrimarySignatureCountPolicyCategory.Indeterminate,
            NativeDigestAlgorithmCategory.Indeterminate, TimestampPolicyCategory.Indeterminate, null); }
        var eku = evidence.Trust != NativeAuthenticodeTrustCategory.Success ||
            evidence.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne ||
            evidence.DigestAlgorithm != NativeDigestAlgorithmCategory.Sha256 || evidence.Timestamp != TimestampPolicyCategory.ValidRfc3161
            ? AuthenticodeEkuPolicyCategory.NotEvaluated
            : evidence.Signer is null ? AuthenticodeEkuPolicyCategory.MissingOrMalformed
            : _policy?.Matches(evidence.Signer) == true ? AuthenticodeEkuPolicyCategory.Match : AuthenticodeEkuPolicyCategory.Rejected;
        return new(eku == AuthenticodeEkuPolicyCategory.Match, evidence.Trust, evidence.PrimarySignatureCount,
            evidence.DigestAlgorithm, evidence.Timestamp, eku);
    }

    private static string ValidatePath(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
                !string.Equals(Path.GetExtension(path), ".msi", StringComparison.OrdinalIgnoreCase)) throw new IOException();
            var full = Path.GetFullPath(path);
            if (!string.Equals(full, path, StringComparison.OrdinalIgnoreCase) || !File.Exists(full) || Directory.Exists(full) ||
                (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new IOException();
            for (var parent = Directory.GetParent(full); parent is not null; parent = parent.Parent)
                if (!parent.Exists || (parent.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException();
            return full;
        }
        catch { throw new IOException("MSI inspection input is unavailable."); }
    }
}

public static class MsiAuthenticodeInspectionOutput
{
    public static string Create(MsiAuthenticodeInspectionResult value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!Enum.IsDefined(value.Trust) || !Enum.IsDefined(value.PrimarySignatureCount) || !Enum.IsDefined(value.Digest) ||
            !Enum.IsDefined(value.Timestamp) || !Enum.IsDefined(value.EkuCategory)) throw new ArgumentException("MSI inspection result is unavailable.");
        return $"result={(value.Success ? "success" : "failure")}\npolicy-id={MsiAuthenticodeInspectionResult.PolicyId}\n" +
            $"wintrust={value.Trust}\nprimary-signature-count={value.PrimarySignatureCount}\ndigest={value.Digest}\n" +
            $"timestamp={value.Timestamp}\neku-category={value.EkuCategory}\n";
    }
}

public sealed record MsiProviderStateEvidence(uint ProviderSize, uint SignatureStateSize, IntPtr Message,
    IntPtr Primary, uint Signers, uint SecondaryCount, bool ExtraProviderSigner, SignerCertificateEvidence? Signer);
public interface IMsiProviderState : IDisposable { MsiProviderStateEvidence Value { get; } }
public interface IMsiProviderStateAccess { IMsiProviderState Read(IntPtr stateHandle); }
public interface IMsiBorrowedMessage : IDisposable
{
    PrimarySignatureCountPolicyCategory PrimarySignatureCount { get; }
    byte[] Content();
    byte[] EncryptedDigest();
    IReadOnlyList<AuthenticodeTimestampAttribute> UnauthenticatedAttributes();
}
public interface IMsiBorrowedMessageFactory { IMsiBorrowedMessage Borrow(IntPtr message); }

/// <summary>Reads only borrowed data in the retained WinTrust state; it never reopens the pathname.</summary>
public sealed class WindowsMsiProviderEvidenceReader : IWinTrustProviderEvidenceReader
{
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private readonly IMsiProviderStateAccess _state;
    private readonly IMsiBorrowedMessageFactory _messages;
    private readonly IAuthenticodeTimestampEvidenceVerifier _timestamp;
    public WindowsMsiProviderEvidenceReader(IAuthenticodeTimestampEvidenceVerifier? timestampVerifier = null,
        IMsiProviderStateAccess? state = null, IMsiBorrowedMessageFactory? messages = null)
    {
        _state = state ?? new NativeMsiProviderStateAccess();
        _messages = messages ?? new NativeMsiBorrowedMessageFactory();
        _timestamp = timestampVerifier ?? new WindowsNativeTimestampEvidenceVerifier();
    }

    public static int RequiredProviderDataSize => Marshal.SizeOf<ProviderData>();
    public static int RequiredSignatureStateSize => Marshal.SizeOf<ProviderSignatureState>();

    public NativeAuthenticodeEvidence Read(IWinTrustNativeCall call)
    {
        if (call.StateHandle == IntPtr.Zero) throw new AuthenticodeProviderUnavailableException();
        using var state = _state.Read(call.StateHandle);
        var provider = state.Value;
        if (provider.ProviderSize < RequiredProviderDataSize || provider.Signers > 64 || provider.SecondaryCount > 64)
            throw new AuthenticodeProviderUnavailableException();
        if (provider.Signers == 0)
            return new(NativeAuthenticodeTrustCategory.Success, PrimarySignatureCountPolicyCategory.None,
                NativeDigestAlgorithmCategory.Indeterminate, TimestampPolicyCategory.Indeterminate, null);
        if (provider.SignatureStateSize < RequiredSignatureStateSize || provider.Message == IntPtr.Zero ||
            provider.Primary == IntPtr.Zero || provider.Signer is null)
            throw new AuthenticodeProviderUnavailableException();
        using var message = _messages.Borrow(provider.Message);
        var attributes = message.UnauthenticatedAttributes();
        var count = message.PrimarySignatureCount;
        if (provider.Signers == 0 || count == PrimarySignatureCountPolicyCategory.None)
            count = PrimarySignatureCountPolicyCategory.None;
        else if (provider.Signers != 1 || provider.ExtraProviderSigner || provider.SecondaryCount != 0 ||
            provider.Primary != provider.Message ||
            attributes.Any(attribute => attribute.Oid == WindowsWinTrustProviderEvidenceReader.NestedSignatureOid))
            count = PrimarySignatureCountPolicyCategory.ExtraOrDuplicate;
        if (count != PrimarySignatureCountPolicyCategory.ExactlyOne)
            return new(NativeAuthenticodeTrustCategory.Success, count, NativeDigestAlgorithmCategory.Indeterminate,
                TimestampPolicyCategory.Indeterminate, provider.Signer);
        var content = message.Content();
        var digest = DerReader.TryReadAuthenticodeFileDigestOid(content, out var oid)
            ? oid == Sha256Oid ? NativeDigestAlgorithmCategory.Sha256 : NativeDigestAlgorithmCategory.Unsupported
            : NativeDigestAlgorithmCategory.Indeterminate;
        return new(NativeAuthenticodeTrustCategory.Success, count,
            digest, AuthenticodeTimestampEvidence.Classify(attributes, message.EncryptedDigest(), _timestamp), provider.Signer);
    }

    private sealed class NativeMsiProviderStateAccess : IMsiProviderStateAccess
    {
        public IMsiProviderState Read(IntPtr state)
        {
            IntPtr library = IntPtr.Zero;
            try
            {
                if (!NativeLibrary.TryLoad("wintrust.dll", out library) ||
                    !NativeLibrary.TryGetExport(library, "WTHelperProvDataFromStateData", out var export))
                    throw new AuthenticodeProviderUnavailableException();
                var helper = Marshal.GetDelegateForFunctionPointer<ProviderDataFromState>(export);
                var pointer = helper(state);
                if (pointer == IntPtr.Zero || unchecked((uint)Marshal.ReadInt32(pointer)) < RequiredProviderDataSize)
                    throw new AuthenticodeProviderUnavailableException();
                var provider = Marshal.PtrToStructure<ProviderData>(pointer);
                uint signatureSize = 0; IntPtr primary = IntPtr.Zero; uint secondary = 0;
                if (provider.SignatureState != IntPtr.Zero)
                {
                    signatureSize = unchecked((uint)Marshal.ReadInt32(provider.SignatureState));
                    if (signatureSize < RequiredSignatureStateSize) throw new AuthenticodeProviderUnavailableException();
                    var signature = Marshal.PtrToStructure<ProviderSignatureState>(provider.SignatureState);
                    primary = signature.Primary; secondary = signature.SecondaryCount;
                }
                SignerCertificateEvidence? signer = null; var extra = false;
                if (provider.Signers != 0)
                    signer = WindowsWinTrustProviderEvidenceReader.GetProviderSigner(state, out extra);
                var value = new MsiProviderStateEvidence(provider.Size, signatureSize, provider.Message, primary,
                    provider.Signers, secondary, extra, signer);
                var result = new NativeMsiProviderState(library, value);
                library = IntPtr.Zero;
                return result;
            }
            catch { throw new AuthenticodeProviderUnavailableException(); }
            finally { if (library != IntPtr.Zero) NativeLibrary.Free(library); }
        }
    }

    private sealed class NativeMsiProviderState(IntPtr library, MsiProviderStateEvidence value) : IMsiProviderState
    {
        private IntPtr _library = library;
        public MsiProviderStateEvidence Value { get; } = value;
        public void Dispose() { if (_library != IntPtr.Zero) { NativeLibrary.Free(_library); _library = IntPtr.Zero; } }
    }
    private sealed class NativeMsiBorrowedMessageFactory : IMsiBorrowedMessageFactory
    {
        public IMsiBorrowedMessage Borrow(IntPtr message) => new NativeMsiBorrowedMessage(NativeSignedMessage.Borrow(message));
    }
    private sealed class NativeMsiBorrowedMessage(NativeSignedMessage message) : IMsiBorrowedMessage
    {
        public PrimarySignatureCountPolicyCategory PrimarySignatureCount => message.PrimarySignatureCount;
        public byte[] Content() => message.ReadBytes(NativeSignedMessage.CmsgContentParam, 0);
        public byte[] EncryptedDigest() => message.ReadBytes(NativeSignedMessage.CmsgEncryptedDigest, 0);
        public IReadOnlyList<AuthenticodeTimestampAttribute> UnauthenticatedAttributes() =>
            message.ReadUnauthenticatedAttributes(0).Select(a => new AuthenticodeTimestampAttribute(a.Oid, a.Values)).ToArray();
        public void Dispose() => message.Dispose(); // Borrow never calls CryptMsgClose.
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate IntPtr ProviderDataFromState(IntPtr state);
    // Prefix and trailing fields mirror the documented CRYPT_PROVIDER_DATA layout through pSigState.
    [StructLayout(LayoutKind.Sequential)] private struct ProviderData
    {
        internal uint Size; internal IntPtr TrustData; internal int OpenedFile; internal IntPtr Window; internal IntPtr Action;
        internal IntPtr Provider; internal uint Error; internal uint RegistrySecurity; internal uint RegistryPolicy;
        internal IntPtr Functions; internal uint TrustStepCount; internal IntPtr TrustStepErrors; internal uint StoreCount;
        internal IntPtr Stores; internal uint Encoding; internal IntPtr Message; internal uint Signers; internal IntPtr SignerArray;
        internal uint PrivateDataCount; internal IntPtr PrivateData; internal uint SubjectChoice; internal IntPtr SipData;
        internal IntPtr UsageOid; internal int RecallWithState; internal uint SystemTimeLow; internal uint SystemTimeHigh;
        internal IntPtr CtlSignerUsageOid;
        internal uint ProviderFlags; internal uint FinalError; internal IntPtr RequestUsage; internal uint PublisherSettings;
        internal uint UiStateFlags; internal IntPtr SignatureState;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ProviderSignatureState
    {
        internal uint Size; internal IntPtr Secondary; internal IntPtr Primary; internal int FirstAttempt;
        internal int NoMoreSignatures; internal uint SecondaryCount;
    }
}
