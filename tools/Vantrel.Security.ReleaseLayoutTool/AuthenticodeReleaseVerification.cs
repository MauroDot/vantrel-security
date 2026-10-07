using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.ReleaseLayoutTool;

public sealed record ReleaseSigningArtifact(string RelativePath);

public static class ReleaseSigningContract
{
    public static IReadOnlyList<ReleaseSigningArtifact> VantrelOwnedPeArtifacts { get; } =
        Array.AsReadOnly(new ReleaseSigningArtifact[]
        {
            new("service/Vantrel.Security.Service.exe"), new("service/Vantrel.Security.Service.dll"),
            new("service/Vantrel.Security.Infrastructure.dll"), new("service/Vantrel.Security.Core.dll"),
            new("desktop/Vantrel.Security.Desktop.exe"), new("desktop/Vantrel.Security.Desktop.dll"),
            new("desktop/Vantrel.Security.Infrastructure.dll"), new("desktop/Vantrel.Security.Core.dll"),
            new("offline-update-tool/Vantrel.Security.OfflineUpdateTool.exe"), new("offline-update-tool/Vantrel.Security.OfflineUpdateTool.dll"),
            new("offline-update-tool/Vantrel.Security.Service.dll"), new("offline-update-tool/Vantrel.Security.Infrastructure.dll"),
            new("offline-update-tool/Vantrel.Security.Core.dll")
        });
}

// This data stays inside the verifier and is never emitted in a release record.
public sealed class SignerCertificateEvidence
{
    public SignerCertificateEvidence(string certificateSha256, IEnumerable<string> enhancedKeyUsageOids)
    {
        if (!IsSha256(certificateSha256)) throw new ArgumentException("Certificate identity is unavailable.", nameof(certificateSha256));
        if (enhancedKeyUsageOids is null) throw new ArgumentNullException(nameof(enhancedKeyUsageOids));
        var values = enhancedKeyUsageOids.ToArray();
        if (values.Length == 0 || values.Any(value => !IsCanonicalOid(value))) throw new ArgumentException("Certificate usage evidence is unavailable.", nameof(enhancedKeyUsageOids));
        CertificateSha256 = certificateSha256;
        EnhancedKeyUsageOids = Array.AsReadOnly(values);
    }

    // The leaf hash is audit/test evidence only. It is not a release trust anchor.
    public string CertificateSha256 { get; }
    public IReadOnlyList<string> EnhancedKeyUsageOids { get; }

    internal static bool IsSha256(string? value) => value is { Length: 64 } && value.All(item => item is >= '0' and <= '9' or >= 'A' and <= 'F');

    internal static bool IsCanonicalOid(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 128) return false;
        var values = value.Split('.');
        if (values.Length < 2 || values.Any(item => item.Length == 0 || (item.Length > 1 && item[0] == '0') || item.Any(character => character is < '0' or > '9'))) return false;
        if (values[0] is not ("0" or "1" or "2")) return false;
        if (values[0] is "0" or "1" && (!ulong.TryParse(values[1], out var second) || second > 39)) return false;
        return true;
    }
}

public interface IReleaseSigningPolicy { bool Matches(SignerCertificateEvidence signer); }

public sealed class AzureArtifactSigningEkuPolicy : IReleaseSigningPolicy
{
    public const string CodeSigningEku = "1.3.6.1.5.5.7.3.3";
    public const string AzureArtifactSigningPublicTrustEku = "1.3.6.1.4.1.311.97.1.0";
    public const string VantrelCertificateProfileEku = "1.3.6.1.4.1.311.97.790899309.69055806.5460467.69741027";
    private const string AzureArtifactSigningEkuPrefix = "1.3.6.1.4.1.311.97.";
    private readonly string _profileEku;

    public AzureArtifactSigningEkuPolicy(string profileEku)
    {
        if (!string.Equals(profileEku, VantrelCertificateProfileEku, StringComparison.Ordinal)) throw new ArgumentException("Certificate profile is unavailable.", nameof(profileEku));
        _profileEku = profileEku;
    }

    public bool Matches(SignerCertificateEvidence signer)
    {
        if (signer is null || !SignerCertificateEvidence.IsSha256(signer.CertificateSha256)) return false;
        var usages = signer.EnhancedKeyUsageOids;
        if (usages is null || usages.Count == 0 || usages.Any(usage => !SignerCertificateEvidence.IsCanonicalOid(usage))) return false;
        if (!usages.Contains(CodeSigningEku, StringComparer.Ordinal) ||
            !usages.Contains(AzureArtifactSigningPublicTrustEku, StringComparer.Ordinal) ||
            !usages.Contains(_profileEku, StringComparer.Ordinal)) return false;
        return !usages.Any(usage => usage.StartsWith(AzureArtifactSigningEkuPrefix, StringComparison.Ordinal) &&
            !string.Equals(usage, AzureArtifactSigningPublicTrustEku, StringComparison.Ordinal) &&
            !string.Equals(usage, _profileEku, StringComparison.Ordinal));
    }
}

public sealed record ReleaseSigningProfile(string Alias, string PolicyId, IReleaseSigningPolicy? PublisherPolicy)
{
    public bool IsConfigured => PublisherPolicy is not null;
}

public interface IReleaseSigningProfileSource { bool TryGet(string alias, out ReleaseSigningProfile profile); }

public sealed class SourceOwnedReleaseSigningProfileSource : IReleaseSigningProfileSource
{
    private static readonly IReadOnlyList<ReleaseSigningProfile> Profiles = Array.AsReadOnly(new ReleaseSigningProfile[]
    {
        // No Azure Artifact Signing profile is provisioned in source. This policy cannot approve a release.
        new("vantrel-production", "vantrel-azure-artifact-signing-unprovisioned", null)
    });
    public bool TryGet(string alias, out ReleaseSigningProfile profile)
    {
        profile = Profiles.SingleOrDefault(item => string.Equals(item.Alias, alias, StringComparison.Ordinal))!;
        return profile is not null;
    }
}

public enum AuthenticodeVerificationCategory
{
    Valid, UnknownProfile, UnconfiguredProfile, Unsigned, AlteredOrTrustFailure, WrongPublisherPolicy,
    MissingTimestamp, InvalidTimestamp, UnsupportedTimestampAlgorithm, UnsupportedDigestAlgorithm,
    ExtraOrDuplicatePrimarySignature, RevocationOrNetworkUncertain, NativeUnavailable, Indeterminate
}

public enum PrimarySignatureCountPolicyCategory { ExactlyOne, None, ExtraOrDuplicate, Indeterminate }
public enum TimestampPolicyCategory { ValidRfc3161, Missing, LegacyOnly, Invalid, UnsupportedAlgorithm, Indeterminate }
public enum NativeAuthenticodeTrustCategory { Success, Unsigned, AlteredOrNonzero, RevocationOrNetworkUncertain, Unavailable }
public enum NativeDigestAlgorithmCategory { Sha256, Unsupported, Indeterminate }

public sealed record NativeAuthenticodeEvidence(NativeAuthenticodeTrustCategory Trust,
    PrimarySignatureCountPolicyCategory PrimarySignatureCount, NativeDigestAlgorithmCategory DigestAlgorithm,
    TimestampPolicyCategory Timestamp, SignerCertificateEvidence? Signer);

public sealed record AuthenticodeReleaseEvidence(string RelativePath, AuthenticodeVerificationCategory Category,
    string SignerPolicyId, PrimarySignatureCountPolicyCategory PrimarySignatureCount, TimestampPolicyCategory Timestamp);

public interface IAuthenticodeNativeVerifier { NativeAuthenticodeEvidence Verify(string absolutePath, SafeFileHandle fileHandle); }

public sealed class ReleaseAuthenticodeVerifier
{
    private readonly IReleaseSigningProfileSource _profiles;
    private readonly IAuthenticodeNativeVerifier _native;
    public ReleaseAuthenticodeVerifier(IReleaseSigningProfileSource? profiles = null, IAuthenticodeNativeVerifier? native = null)
    {
        _profiles = profiles ?? new SourceOwnedReleaseSigningProfileSource();
        _native = native ?? new WindowsAuthenticodeNativeVerifier();
    }

    public AuthenticodeReleaseEvidence Verify(string relativePath, string absolutePath, string profileAlias)
    {
        using var stream = new FileStream(absolutePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        return Verify(relativePath, absolutePath, profileAlias, stream.SafeFileHandle);
    }

    internal AuthenticodeReleaseEvidence Verify(string relativePath, string absolutePath, string profileAlias, SafeFileHandle fileHandle)
    {
        if (!_profiles.TryGet(profileAlias, out var profile)) return new(relativePath, AuthenticodeVerificationCategory.UnknownProfile, "unrecognized", PrimarySignatureCountPolicyCategory.Indeterminate, TimestampPolicyCategory.Indeterminate);
        if (!profile.IsConfigured) return new(relativePath, AuthenticodeVerificationCategory.UnconfiguredProfile, profile.PolicyId, PrimarySignatureCountPolicyCategory.Indeterminate, TimestampPolicyCategory.Indeterminate);
        NativeAuthenticodeEvidence native;
        try { native = _native.Verify(absolutePath, fileHandle); }
        catch (DllNotFoundException) { return Unavailable(relativePath, profile); }
        catch (EntryPointNotFoundException) { return Unavailable(relativePath, profile); }
        catch (BadImageFormatException) { return Unavailable(relativePath, profile); }
        catch { return Indeterminate(relativePath, profile); }
        var category = native.Trust switch
        {
            NativeAuthenticodeTrustCategory.Unsigned => AuthenticodeVerificationCategory.Unsigned,
            NativeAuthenticodeTrustCategory.AlteredOrNonzero => AuthenticodeVerificationCategory.AlteredOrTrustFailure,
            NativeAuthenticodeTrustCategory.RevocationOrNetworkUncertain => AuthenticodeVerificationCategory.RevocationOrNetworkUncertain,
            NativeAuthenticodeTrustCategory.Unavailable => AuthenticodeVerificationCategory.NativeUnavailable,
            NativeAuthenticodeTrustCategory.Success => EvaluateSuccessfulTrust(native, profile),
            _ => AuthenticodeVerificationCategory.Indeterminate
        };
        return new(relativePath, category, profile.PolicyId, native.PrimarySignatureCount, native.Timestamp);
    }

    private static AuthenticodeVerificationCategory EvaluateSuccessfulTrust(NativeAuthenticodeEvidence native, ReleaseSigningProfile profile)
    {
        if (native.PrimarySignatureCount == PrimarySignatureCountPolicyCategory.ExtraOrDuplicate) return AuthenticodeVerificationCategory.ExtraOrDuplicatePrimarySignature;
        if (native.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne) return AuthenticodeVerificationCategory.Indeterminate;
        if (native.DigestAlgorithm != NativeDigestAlgorithmCategory.Sha256) return AuthenticodeVerificationCategory.UnsupportedDigestAlgorithm;
        if (native.Timestamp is TimestampPolicyCategory.Missing or TimestampPolicyCategory.LegacyOnly) return AuthenticodeVerificationCategory.MissingTimestamp;
        if (native.Timestamp == TimestampPolicyCategory.Invalid) return AuthenticodeVerificationCategory.InvalidTimestamp;
        if (native.Timestamp == TimestampPolicyCategory.UnsupportedAlgorithm) return AuthenticodeVerificationCategory.UnsupportedTimestampAlgorithm;
        if (native.Timestamp != TimestampPolicyCategory.ValidRfc3161 || native.Signer is null) return AuthenticodeVerificationCategory.Indeterminate;
        return profile.PublisherPolicy!.Matches(native.Signer) ? AuthenticodeVerificationCategory.Valid : AuthenticodeVerificationCategory.WrongPublisherPolicy;
    }

    private static AuthenticodeReleaseEvidence Unavailable(string path, ReleaseSigningProfile profile) => new(path, AuthenticodeVerificationCategory.NativeUnavailable, profile.PolicyId, PrimarySignatureCountPolicyCategory.Indeterminate, TimestampPolicyCategory.Indeterminate);
    private static AuthenticodeReleaseEvidence Indeterminate(string path, ReleaseSigningProfile profile) => new(path, AuthenticodeVerificationCategory.Indeterminate, profile.PolicyId, PrimarySignatureCountPolicyCategory.Indeterminate, TimestampPolicyCategory.Indeterminate);
}

public interface IWinTrustNativeApi { IWinTrustNativeCall BeginFileVerification(string absolutePath, SafeFileHandle fileHandle); }
public interface IWinTrustNativeCall : IDisposable { int NativeResult { get; } IntPtr StateHandle { get; } string FilePath { get; } }
public interface IWinTrustProviderEvidenceReader { NativeAuthenticodeEvidence Read(IWinTrustNativeCall call); }

public sealed class WindowsAuthenticodeNativeVerifier : IAuthenticodeNativeVerifier
{
    private readonly IWinTrustNativeApi _winTrust;
    private readonly IWinTrustProviderEvidenceReader _evidence;
    public WindowsAuthenticodeNativeVerifier(IWinTrustNativeApi? winTrust = null, IWinTrustProviderEvidenceReader? evidence = null)
    {
        _winTrust = winTrust ?? new WindowsWinTrustNativeApi(); _evidence = evidence ?? new WindowsWinTrustProviderEvidenceReader();
    }
    public NativeAuthenticodeEvidence Verify(string absolutePath, SafeFileHandle fileHandle)
    {
        try
        {
            using var call = _winTrust.BeginFileVerification(absolutePath, fileHandle);
            var trust = MapTrust(call.NativeResult);
            return trust == NativeAuthenticodeTrustCategory.Success ? _evidence.Read(call) : Empty(trust);
        }
        catch (AuthenticodeProviderUnavailableException) { return Empty(NativeAuthenticodeTrustCategory.Unavailable); }
        catch (DllNotFoundException) { return Empty(NativeAuthenticodeTrustCategory.Unavailable); }
        catch (EntryPointNotFoundException) { return Empty(NativeAuthenticodeTrustCategory.Unavailable); }
        catch (BadImageFormatException) { return Empty(NativeAuthenticodeTrustCategory.Unavailable); }
        catch { return Empty(NativeAuthenticodeTrustCategory.Success); }
    }
    private static NativeAuthenticodeTrustCategory MapTrust(int result) => result == 0 ? NativeAuthenticodeTrustCategory.Success : result switch
    {
        unchecked((int)0x800B0100) => NativeAuthenticodeTrustCategory.Unsigned,
        unchecked((int)0x800B010E) or unchecked((int)0x80092013) => NativeAuthenticodeTrustCategory.RevocationOrNetworkUncertain,
        _ => NativeAuthenticodeTrustCategory.AlteredOrNonzero
    };
    private static NativeAuthenticodeEvidence Empty(NativeAuthenticodeTrustCategory trust) => new(trust, PrimarySignatureCountPolicyCategory.Indeterminate, NativeDigestAlgorithmCategory.Indeterminate, TimestampPolicyCategory.Indeterminate, null);
}

public sealed class AuthenticodeProviderUnavailableException : Exception { public AuthenticodeProviderUnavailableException() { } }
// The provider-state helpers are resolved dynamically as required by their WinTrust contract.
// The provider certificate is reduced immediately to internal leaf-hash and EKU evidence.
public sealed class WindowsWinTrustProviderEvidenceReader : IWinTrustProviderEvidenceReader
{
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private const string Sha384Oid = "2.16.840.1.101.3.4.2.2";
    private const string Sha512Oid = "2.16.840.1.101.3.4.2.3";
    private const string Rfc3161TimestampOid = "1.2.840.113549.1.9.16.2.14";
    private const string LegacyCountersignatureOid = "1.2.840.113549.1.9.6";
    private const string NestedSignatureOid = "1.3.6.1.4.1.311.2.4.1";

    public NativeAuthenticodeEvidence Read(IWinTrustNativeCall call)
    {
        if (call.StateHandle == IntPtr.Zero || string.IsNullOrWhiteSpace(call.FilePath)) throw new AuthenticodeProviderUnavailableException();
        var signer = GetProviderSigner(call.StateHandle, out var extraProviderSigner);
        using var message = NativeSignedMessage.Open(call.FilePath);
        var primaryCount = message.PrimarySignatureCount;
        var attributes = message.ReadUnauthenticatedAttributes(0);
        if (extraProviderSigner || attributes.Any(attribute => attribute.Oid == NestedSignatureOid)) primaryCount = PrimarySignatureCountPolicyCategory.ExtraOrDuplicate;
        if (primaryCount != PrimarySignatureCountPolicyCategory.ExactlyOne)
            return new(NativeAuthenticodeTrustCategory.Success, primaryCount, NativeDigestAlgorithmCategory.Indeterminate, TimestampPolicyCategory.Indeterminate, signer);
        return new(NativeAuthenticodeTrustCategory.Success, primaryCount, ReadPrimaryFileDigest(message), ReadRfc3161Timestamp(message, attributes), signer);
    }

    private static SignerCertificateEvidence GetProviderSigner(IntPtr state, out bool extraSigner)
    {
        extraSigner = false;
        IntPtr library = IntPtr.Zero;
        try
        {
            if (!NativeLibrary.TryLoad("wintrust.dll", out library) ||
                !NativeLibrary.TryGetExport(library, "WTHelperProvDataFromStateData", out var dataExport) ||
                !NativeLibrary.TryGetExport(library, "WTHelperGetProvSignerFromChain", out var signerExport) ||
                !NativeLibrary.TryGetExport(library, "WTHelperGetProvCertFromChain", out var certExport))
                throw new AuthenticodeProviderUnavailableException();
            var dataFromState = Marshal.GetDelegateForFunctionPointer<ProviderDataFromStateDelegate>(dataExport);
            var signerFromChain = Marshal.GetDelegateForFunctionPointer<ProviderSignerFromChainDelegate>(signerExport);
            var certFromChain = Marshal.GetDelegateForFunctionPointer<ProviderCertFromChainDelegate>(certExport);
            var provider = dataFromState(state);
            if (provider == IntPtr.Zero) throw new AuthenticodeProviderUnavailableException();
            var signer = signerFromChain(provider, 0, false, 0);
            if (signer == IntPtr.Zero) throw new AuthenticodeProviderUnavailableException();
            extraSigner = signerFromChain(provider, 1, false, 0) != IntPtr.Zero;
            var certificate = certFromChain(signer, 0);
            if (certificate == IntPtr.Zero) throw new AuthenticodeProviderUnavailableException();
            var providerCertificate = Marshal.PtrToStructure<CryptProviderCert>(certificate);
            if (providerCertificate.CertificateContext == IntPtr.Zero) throw new AuthenticodeProviderUnavailableException();
            return GetCertificateEvidence(providerCertificate.CertificateContext);
        }
        catch (AuthenticodeProviderUnavailableException) { throw; }
        catch (DllNotFoundException) { throw new AuthenticodeProviderUnavailableException(); }
        catch (EntryPointNotFoundException) { throw new AuthenticodeProviderUnavailableException(); }
        catch (BadImageFormatException) { throw new AuthenticodeProviderUnavailableException(); }
        catch { throw new AuthenticodeProviderUnavailableException(); }
        finally { if (library != IntPtr.Zero) NativeLibrary.Free(library); }
    }

    private static NativeDigestAlgorithmCategory ReadPrimaryFileDigest(NativeSignedMessage message)
    {
        var content = message.ReadBytes(NativeSignedMessage.CmsgContentParam, 0);
        return DerReader.TryReadAuthenticodeFileDigestOid(content, out var oid)
            ? oid == Sha256Oid ? NativeDigestAlgorithmCategory.Sha256 : NativeDigestAlgorithmCategory.Unsupported
            : NativeDigestAlgorithmCategory.Indeterminate;
    }

    private static TimestampPolicyCategory ReadRfc3161Timestamp(NativeSignedMessage message, IReadOnlyList<NativeAttribute> attributes)
    {
        var tokens = attributes.Where(attribute => attribute.Oid == Rfc3161TimestampOid).SelectMany(attribute => attribute.Values).ToArray();
        if (tokens.Length == 0) return attributes.Any(attribute => attribute.Oid == LegacyCountersignatureOid) ? TimestampPolicyCategory.LegacyOnly : TimestampPolicyCategory.Missing;
        if (tokens.Length != 1) return TimestampPolicyCategory.Invalid;
        var signedData = message.ReadBytes(NativeSignedMessage.CmsgEncryptedDigest, 0);
        if (!NativeTimestampVerifier.Verify(tokens[0], signedData, out var algorithm)) return TimestampPolicyCategory.Invalid;
        return algorithm is Sha256Oid or Sha384Oid or Sha512Oid ? TimestampPolicyCategory.ValidRfc3161 : TimestampPolicyCategory.UnsupportedAlgorithm;
    }

    private static string GetCertificateSha256(IntPtr certificateContext)
    {
        uint size = 32; var value = new byte[size];
        if (!CertGetCertificateContextProperty(certificateContext, 107, value, ref size) || size != value.Length) throw new AuthenticodeProviderUnavailableException();
        return Convert.ToHexString(value);
    }

    private static SignerCertificateEvidence GetCertificateEvidence(IntPtr certificateContext)
    {
        var certificateHash = GetCertificateSha256(certificateContext);
        using var certificate = new X509Certificate2(certificateContext);
        var extensions = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        if (extensions.Length != 1) throw new AuthenticodeProviderUnavailableException();
        var usages = extensions[0].EnhancedKeyUsages.Cast<Oid>().Select(usage => usage.Value).ToArray();
        try { return new SignerCertificateEvidence(certificateHash, usages!); }
        catch (ArgumentException) { throw new AuthenticodeProviderUnavailableException(); }
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate IntPtr ProviderDataFromStateDelegate(IntPtr state);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate IntPtr ProviderSignerFromChainDelegate(IntPtr data, uint signerIndex, [MarshalAs(UnmanagedType.Bool)] bool counterSigner, uint counterSignerIndex);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate IntPtr ProviderCertFromChainDelegate(IntPtr signer, uint certificateIndex);
    [StructLayout(LayoutKind.Sequential)] private struct CryptProviderCert { internal uint Size; internal IntPtr CertificateContext; }
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateContextProperty(IntPtr certificateContext, uint propertyId, byte[] data, ref uint dataSize);
}

internal sealed record NativeAttribute(string Oid, IReadOnlyList<byte[]> Values);

internal sealed class NativeSignedMessage : IDisposable
{
    internal const uint CmsgContentParam = 2;
    internal const uint CmsgSignerCountParam = 5;
    internal const uint CmsgSignerUnauthAttrParam = 10;
    internal const uint CmsgEncryptedDigest = 27;
    private const uint QueryObjectFile = 1;
    private const uint QueryContentPkcs7SignedEmbedded = 1u << 10;
    private const uint QueryFormatBinary = 1u << 1;
    private const int MaxNativeValueBytes = 4 * 1024 * 1024;
    private IntPtr _store;
    private IntPtr _message;
    private NativeSignedMessage(IntPtr store, IntPtr message) { _store = store; _message = message; }

    internal static NativeSignedMessage Open(string path)
    {
        if (!CryptQueryObject(QueryObjectFile, path, QueryContentPkcs7SignedEmbedded, QueryFormatBinary, 0, out _, out _, out _, out var store, out var message, IntPtr.Zero) || message == IntPtr.Zero)
        {
            if (store != IntPtr.Zero) CertCloseStore(store, 0);
            throw new AuthenticodeProviderUnavailableException();
        }
        return new NativeSignedMessage(store, message);
    }

    internal PrimarySignatureCountPolicyCategory PrimarySignatureCount
    {
        get
        {
            var bytes = ReadBytes(CmsgSignerCountParam, 0);
            if (bytes.Length != sizeof(uint)) return PrimarySignatureCountPolicyCategory.Indeterminate;
            return BitConverter.ToUInt32(bytes, 0) switch { 0 => PrimarySignatureCountPolicyCategory.None, 1 => PrimarySignatureCountPolicyCategory.ExactlyOne, _ => PrimarySignatureCountPolicyCategory.ExtraOrDuplicate };
        }
    }

    internal byte[] ReadBytes(uint parameter, uint index)
    {
        uint size = 0;
        if (!CryptMsgGetParam(_message, parameter, index, IntPtr.Zero, ref size) || size == 0 || size > MaxNativeValueBytes) throw new AuthenticodeProviderUnavailableException();
        var memory = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            var actual = size;
            if (!CryptMsgGetParam(_message, parameter, index, memory, ref actual) || actual == 0 || actual > size) throw new AuthenticodeProviderUnavailableException();
            var value = new byte[actual]; Marshal.Copy(memory, value, 0, checked((int)actual)); return value;
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    internal IReadOnlyList<NativeAttribute> ReadUnauthenticatedAttributes(uint index)
    {
        uint size = 0;
        if (!CryptMsgGetParam(_message, CmsgSignerUnauthAttrParam, index, IntPtr.Zero, ref size) || size == 0 || size > MaxNativeValueBytes) return Array.Empty<NativeAttribute>();
        var memory = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            var actual = size;
            if (!CryptMsgGetParam(_message, CmsgSignerUnauthAttrParam, index, memory, ref actual) || actual == 0 || actual > size) throw new AuthenticodeProviderUnavailableException();
            return ParseAttributes(memory, actual);
        }
        finally { Marshal.FreeHGlobal(memory); }
    }
    private static IReadOnlyList<NativeAttribute> ParseAttributes(IntPtr memory, uint size)
    {
        var first = Marshal.PtrToStructure<CryptAttributes>(memory);
        if (first.Count > 64 || !Contains(memory, size, first.Attributes, checked((ulong)first.Count * (ulong)Marshal.SizeOf<CryptAttribute>()))) throw new AuthenticodeProviderUnavailableException();
        var attributes = new List<NativeAttribute>(checked((int)first.Count));
        for (var index = 0u; index < first.Count; index++)
        {
            var pointer = IntPtr.Add(first.Attributes, checked((int)(index * (uint)Marshal.SizeOf<CryptAttribute>())));
            var attribute = Marshal.PtrToStructure<CryptAttribute>(pointer);
            if (attribute.ValueCount == 0 || attribute.ValueCount > 16 || !Contains(memory, size, attribute.ObjectIdentifier, 2) || !Contains(memory, size, attribute.Values, checked((ulong)attribute.ValueCount * (ulong)Marshal.SizeOf<CryptDataBlob>()))) throw new AuthenticodeProviderUnavailableException();
            var oid = Marshal.PtrToStringAnsi(attribute.ObjectIdentifier);
            if (string.IsNullOrWhiteSpace(oid) || oid.Length > 128) throw new AuthenticodeProviderUnavailableException();
            var values = new List<byte[]>(checked((int)attribute.ValueCount));
            for (var valueIndex = 0u; valueIndex < attribute.ValueCount; valueIndex++)
            {
                var blobPointer = IntPtr.Add(attribute.Values, checked((int)(valueIndex * (uint)Marshal.SizeOf<CryptDataBlob>())));
                var blob = Marshal.PtrToStructure<CryptDataBlob>(blobPointer);
                if (blob.Size == 0 || blob.Size > MaxNativeValueBytes || !Contains(memory, size, blob.Data, blob.Size)) throw new AuthenticodeProviderUnavailableException();
                var bytes = new byte[blob.Size]; Marshal.Copy(blob.Data, bytes, 0, checked((int)blob.Size)); values.Add(bytes);
            }
            attributes.Add(new NativeAttribute(oid, values));
        }
        return attributes;
    }

    private static bool Contains(IntPtr baseAddress, uint size, IntPtr value, ulong required)
    {
        if (value == IntPtr.Zero || required == 0) return false;
        var start = unchecked((ulong)baseAddress.ToInt64()); var end = start + size; var target = unchecked((ulong)value.ToInt64());
        return end >= start && target >= start && target <= end && required <= end - target;
    }

    public void Dispose()
    {
        if (_message != IntPtr.Zero) { CryptMsgClose(_message); _message = IntPtr.Zero; }
        if (_store != IntPtr.Zero) { CertCloseStore(_store, 0); _store = IntPtr.Zero; }
    }

    [StructLayout(LayoutKind.Sequential)] private struct CryptAttributes { internal uint Count; internal IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct CryptAttribute { internal IntPtr ObjectIdentifier; internal uint ValueCount; internal IntPtr Values; }
    [StructLayout(LayoutKind.Sequential)] private struct CryptDataBlob { internal uint Size; internal IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptQueryObject(uint objectType, string @object, uint contentFlags, uint formatFlags, uint flags, out uint encoding, out uint contentType, out uint formatType, out IntPtr store, out IntPtr message, IntPtr context);
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptMsgGetParam(IntPtr message, uint parameter, uint index, IntPtr data, ref uint dataSize);
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptMsgClose(IntPtr message);
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CertCloseStore(IntPtr store, uint flags);
}

internal static class NativeTimestampVerifier
{
    internal static bool Verify(byte[] token, byte[] signedData, out string algorithmOid)
    {
        algorithmOid = string.Empty;
        IntPtr tokenMemory = IntPtr.Zero, signedDataMemory = IntPtr.Zero, timestampContext = IntPtr.Zero;
        try
        {
            if (token.Length == 0 || token.Length > 4 * 1024 * 1024 || signedData.Length == 0 || signedData.Length > 4 * 1024 * 1024) return false;
            tokenMemory = Marshal.AllocHGlobal(token.Length); Marshal.Copy(token, 0, tokenMemory, token.Length);
            signedDataMemory = Marshal.AllocHGlobal(signedData.Length); Marshal.Copy(signedData, 0, signedDataMemory, signedData.Length);
            if (!CryptVerifyTimeStampSignature(tokenMemory, checked((uint)token.Length), signedDataMemory, checked((uint)signedData.Length), IntPtr.Zero, out timestampContext, IntPtr.Zero, IntPtr.Zero) || timestampContext == IntPtr.Zero) return false;
            var context = Marshal.PtrToStructure<CryptTimestampContext>(timestampContext);
            if (context.TimestampInfo == IntPtr.Zero) return false;
            var info = Marshal.PtrToStructure<CryptTimestampInfo>(context.TimestampInfo);
            algorithmOid = Marshal.PtrToStringAnsi(info.HashAlgorithm.ObjectIdentifier) ?? string.Empty;
            return algorithmOid.Length > 0 && algorithmOid.Length <= 128;
        }
        catch (DllNotFoundException) { throw new AuthenticodeProviderUnavailableException(); }
        catch (EntryPointNotFoundException) { throw new AuthenticodeProviderUnavailableException(); }
        catch (BadImageFormatException) { throw new AuthenticodeProviderUnavailableException(); }
        catch { return false; }
        finally
        {
            if (timestampContext != IntPtr.Zero) CryptMemFree(timestampContext);
            if (signedDataMemory != IntPtr.Zero) Marshal.FreeHGlobal(signedDataMemory);
            if (tokenMemory != IntPtr.Zero) Marshal.FreeHGlobal(tokenMemory);
        }
    }

    [StructLayout(LayoutKind.Sequential)] private struct CryptTimestampContext { internal uint EncodedSize; internal IntPtr Encoded; internal IntPtr TimestampInfo; }
    [StructLayout(LayoutKind.Sequential)] private struct CryptDataBlob { internal uint Size; internal IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)] private struct CryptAlgorithmIdentifier { internal IntPtr ObjectIdentifier; internal CryptDataBlob Parameters; }
    [StructLayout(LayoutKind.Sequential)] private struct CryptTimestampInfo { internal uint Version; internal IntPtr PolicyId; internal CryptAlgorithmIdentifier HashAlgorithm; }
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptVerifyTimeStampSignature(IntPtr timestampContent, uint timestampContentLength, IntPtr data, uint dataLength, IntPtr additionalStore, out IntPtr timestampContext, IntPtr timestampSigner, IntPtr store);
    [DllImport("crypt32.dll")] private static extern void CryptMemFree(IntPtr memory);
}

internal static class DerReader
{
    internal static bool TryReadAuthenticodeFileDigestOid(ReadOnlySpan<byte> bytes, out string oid)
    {
        oid = string.Empty;
        try
        {
            var outer = new Reader(bytes); var sequence = new Reader(outer.Read(0x30)); if (!outer.AtEnd) return false;
            sequence.SkipAny();
            var digestInfo = new Reader(sequence.Read(0x30)); var algorithm = new Reader(digestInfo.Read(0x30)); oid = algorithm.ReadOid();
            if (!algorithm.AtEnd) algorithm.SkipAny();
            return digestInfo.TryRead(0x04, out _) && digestInfo.AtEnd && sequence.AtEnd && oid.Length <= 128;
        }
        catch { oid = string.Empty; return false; }
    }

    private ref struct Reader
    {
        private ReadOnlySpan<byte> _value;
        internal Reader(ReadOnlySpan<byte> value) => _value = value;
        internal bool AtEnd => _value.IsEmpty;
        internal ReadOnlySpan<byte> Read(byte tag)
        {
            if (_value.Length < 2 || _value[0] != tag) throw new InvalidDataException();
            var length = ReadLength(_value[1..], out var lengthBytes); var start = 1 + lengthBytes;
            if (start > _value.Length || length > _value.Length - start) throw new InvalidDataException();
            var result = _value.Slice(start, length); _value = _value[(start + length)..]; return result;
        }
        internal bool TryRead(byte tag, out ReadOnlySpan<byte> value) { value = default; if (_value.IsEmpty || _value[0] != tag) return false; value = Read(tag); return true; }
        internal void SkipAny()
        {
            if (_value.Length < 2) throw new InvalidDataException();
            var length = ReadLength(_value[1..], out var lengthBytes); var start = 1 + lengthBytes;
            if (start > _value.Length || length > _value.Length - start) throw new InvalidDataException(); _value = _value[(start + length)..];
        }
        internal string ReadOid()
        {
            var value = Read(0x06); if (value.IsEmpty) throw new InvalidDataException();
            var first = value[0]; var values = new List<uint> { (uint)(first / 40), (uint)(first % 40) }; var item = 0u;
            foreach (var current in value[1..]) { if (item > (uint.MaxValue >> 7)) throw new InvalidDataException(); item = (item << 7) | (uint)(current & 0x7f); if ((current & 0x80) == 0) { values.Add(item); item = 0; } }
            if (item != 0) throw new InvalidDataException(); return string.Join('.', values);
        }
        private static int ReadLength(ReadOnlySpan<byte> bytes, out int lengthBytes)
        {
            if (bytes.IsEmpty) throw new InvalidDataException();
            if ((bytes[0] & 0x80) == 0) { lengthBytes = 1; return bytes[0]; }
            var count = bytes[0] & 0x7f; if (count is 0 or > 4 || bytes.Length < count + 1 || bytes[1] == 0) throw new InvalidDataException();
            uint length = 0; for (var index = 0; index < count; index++) length = (length << 8) | bytes[index + 1]; if (length > int.MaxValue) throw new InvalidDataException(); lengthBytes = count + 1; return (int)length;
        }
    }
}
public sealed class WindowsWinTrustNativeApi : IWinTrustNativeApi
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public IWinTrustNativeCall BeginFileVerification(string absolutePath, SafeFileHandle fileHandle)
    {
        IntPtr path = IntPtr.Zero, fileInfo = IntPtr.Zero;
        try
        {
            path = Marshal.StringToCoTaskMemUni(absolutePath);
            if (fileHandle is null || fileHandle.IsInvalid || fileHandle.IsClosed) throw new IOException("Release artifact handle is unavailable.");
            var file = new WinTrustFileInfo { cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(), pcwszFilePath = path, hFile = fileHandle.DangerousGetHandle() };
            fileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>()); Marshal.StructureToPtr(file, fileInfo, false);
            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = 2, // WTD_UI_NONE
                fdwRevocationChecks = 1, // WTD_REVOKE_WHOLECHAIN: normal online whole-chain policy
                dwUnionChoice = 1, // WTD_CHOICE_FILE
                pFile = fileInfo,
                dwStateAction = 1, // WTD_STATEACTION_VERIFY
                dwProvFlags = 0x2000 // WTD_DISABLE_MD2_MD4; no cache-only or lifetime-signing flags
            };
            var action = GenericVerifyV2; var result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return new WinTrustNativeCall(absolutePath, action, data, result, path, fileInfo);
        }
        catch
        {
            if (fileInfo != IntPtr.Zero) Marshal.FreeHGlobal(fileInfo);
            if (path != IntPtr.Zero) Marshal.FreeCoTaskMem(path);
            throw;
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid actionId, ref WinTrustData data);
    [StructLayout(LayoutKind.Sequential)] private struct WinTrustFileInfo { internal uint cbStruct; internal IntPtr pcwszFilePath; internal IntPtr hFile; internal IntPtr pgKnownSubject; }
    [StructLayout(LayoutKind.Sequential)] private struct WinTrustData
    {
        internal uint cbStruct; internal IntPtr pPolicyCallbackData; internal IntPtr pSIPClientData; internal uint dwUIChoice;
        internal uint fdwRevocationChecks; internal uint dwUnionChoice; internal IntPtr pFile; internal uint dwStateAction;
        internal IntPtr hWVTStateData; internal IntPtr pwszURLReference; internal uint dwProvFlags; internal uint dwUIContext; internal IntPtr pSignatureSettings;
    }

    private sealed class WinTrustNativeCall(string filePath, Guid action, WinTrustData data, int result, IntPtr path, IntPtr fileInfo) : IWinTrustNativeCall
    {
        private Guid _action = action; private WinTrustData _data = data; private IntPtr _path = path; private IntPtr _fileInfo = fileInfo; private bool _disposed;
        public int NativeResult { get; } = result;
        public IntPtr StateHandle => _data.hWVTStateData;
        public string FilePath { get; } = filePath;
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                if (_data.hWVTStateData != IntPtr.Zero)
                {
                    _data.dwStateAction = 2; // WTD_STATEACTION_CLOSE
                    _ = WinVerifyTrust(IntPtr.Zero, ref _action, ref _data);
                }
            }
            finally
            {
                if (_fileInfo != IntPtr.Zero) { Marshal.FreeHGlobal(_fileInfo); _fileInfo = IntPtr.Zero; }
                if (_path != IntPtr.Zero) { Marshal.FreeCoTaskMem(_path); _path = IntPtr.Zero; }
            }
        }
    }
}
