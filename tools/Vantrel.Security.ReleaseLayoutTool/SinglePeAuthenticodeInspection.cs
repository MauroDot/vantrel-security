using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>
/// Sanitized result for an explicit, local Authenticode inspection. It is not release approval evidence.
/// </summary>
public sealed record SinglePeAuthenticodeInspectionResult(bool Success, string PolicyId,
    PrimarySignatureCountPolicyCategory PrimarySignatureCount, TimestampPolicyCategory Timestamp,
    AuthenticodeEkuPolicyCategory EkuCategory);

public enum AuthenticodeEkuPolicyCategory { Match, Rejected, MissingOrMalformed, NotEvaluated }

/// <summary>
/// Reads one regular PE through a retained handle and evaluates only the fixed Vantrel Artifact Signing EKU policy.
/// This inspector deliberately has no release-profile, layout, record, or signing authority.
/// </summary>
public sealed class SinglePeAuthenticodeInspector
{
    public const string PolicyId = "vantrel-azure-artifact-signing-eku";
    private readonly IAuthenticodeNativeVerifier _native;
    private readonly AzureArtifactSigningEkuPolicy _policy;

    public SinglePeAuthenticodeInspector(IAuthenticodeNativeVerifier? native = null)
    {
        _native = native ?? new WindowsAuthenticodeNativeVerifier();
        _policy = new AzureArtifactSigningEkuPolicy(AzureArtifactSigningEkuPolicy.VantrelCertificateProfileEku);
    }

    public SinglePeAuthenticodeInspectionResult Inspect(string filePath)
    {
        var path = ValidatePath(filePath);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        if (!IsPortableExecutable(stream.SafeFileHandle, stream)) throw new IOException("Inspection input is unavailable.");

        NativeAuthenticodeEvidence native;
        try { native = _native.Verify(path, stream.SafeFileHandle); }
        catch (DllNotFoundException) { return Failure(PrimarySignatureCountPolicyCategory.Indeterminate, TimestampPolicyCategory.Indeterminate, AuthenticodeEkuPolicyCategory.NotEvaluated); }
        catch (EntryPointNotFoundException) { return Failure(PrimarySignatureCountPolicyCategory.Indeterminate, TimestampPolicyCategory.Indeterminate, AuthenticodeEkuPolicyCategory.NotEvaluated); }
        catch (BadImageFormatException) { return Failure(PrimarySignatureCountPolicyCategory.Indeterminate, TimestampPolicyCategory.Indeterminate, AuthenticodeEkuPolicyCategory.NotEvaluated); }
        catch { return Failure(PrimarySignatureCountPolicyCategory.Indeterminate, TimestampPolicyCategory.Indeterminate, AuthenticodeEkuPolicyCategory.NotEvaluated); }

        if (native.Trust != NativeAuthenticodeTrustCategory.Success)
            return Failure(native.PrimarySignatureCount, native.Timestamp, AuthenticodeEkuPolicyCategory.NotEvaluated);
        if (native.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne ||
            native.DigestAlgorithm != NativeDigestAlgorithmCategory.Sha256 ||
            native.Timestamp != TimestampPolicyCategory.ValidRfc3161)
            return Failure(native.PrimarySignatureCount, native.Timestamp, AuthenticodeEkuPolicyCategory.NotEvaluated);
        if (native.Signer is null)
            return Failure(native.PrimarySignatureCount, native.Timestamp, AuthenticodeEkuPolicyCategory.MissingOrMalformed);

        var eku = _policy.Matches(native.Signer) ? AuthenticodeEkuPolicyCategory.Match : AuthenticodeEkuPolicyCategory.Rejected;
        return new(eku == AuthenticodeEkuPolicyCategory.Match, PolicyId, native.PrimarySignatureCount, native.Timestamp, eku);
    }

    private static SinglePeAuthenticodeInspectionResult Failure(PrimarySignatureCountPolicyCategory signatures,
        TimestampPolicyCategory timestamp, AuthenticodeEkuPolicyCategory eku) => new(false, PolicyId, signatures, timestamp, eku);

    private static string ValidatePath(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) throw new IOException("Inspection input is unavailable.");
        string path;
        try { path = Path.GetFullPath(filePath); }
        catch { throw new IOException("Inspection input is unavailable."); }
        if (!File.Exists(path) || Directory.Exists(path)) throw new IOException("Inspection input is unavailable.");
        try
        {
            for (var directory = new FileInfo(path).Directory; directory is not null; directory = directory.Parent)
                if (!directory.Exists || (File.GetAttributes(directory.FullName) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Inspection input is unavailable.");
            var attributes = File.GetAttributes(path);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new IOException("Inspection input is unavailable.");
        }
        catch (IOException) { throw; }
        catch { throw new IOException("Inspection input is unavailable."); }
        return path;
    }

    private static bool IsPortableExecutable(SafeFileHandle handle, FileStream stream)
    {
        if (handle.IsInvalid || handle.IsClosed || stream.Length < 64) return false;
        Span<byte> header = stackalloc byte[64];
        stream.Position = 0;
        if (stream.Read(header) != header.Length || header[0] != (byte)'M' || header[1] != (byte)'Z') return false;
        var offset = BitConverter.ToInt32(header[60..64]);
        if (offset < 64 || offset > stream.Length - 4) return false;
        Span<byte> signature = stackalloc byte[4];
        stream.Position = offset;
        return stream.Read(signature) == signature.Length && signature.SequenceEqual("PE\0\0"u8);
    }
}

public static class SinglePeAuthenticodeInspectionOutput
{
    public static string Create(SinglePeAuthenticodeInspectionResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (!string.Equals(result.PolicyId, SinglePeAuthenticodeInspector.PolicyId, StringComparison.Ordinal) ||
            !Enum.IsDefined(result.PrimarySignatureCount) || !Enum.IsDefined(result.Timestamp) || !Enum.IsDefined(result.EkuCategory))
            throw new ArgumentException("Inspection result is unavailable.", nameof(result));
        return $"result={(result.Success ? "success" : "failure")}\n" +
               $"policy-id={result.PolicyId}\n" +
               $"primary-signature-count={result.PrimarySignatureCount}\n" +
               $"timestamp={result.Timestamp}\n" +
               $"eku-category={result.EkuCategory}\n";
    }
}
