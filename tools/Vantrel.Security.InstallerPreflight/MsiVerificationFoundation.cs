using System.Text;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.InstallerPreflight;

/// <summary>Canonical public evidence only; no command in this task creates a distribution record.</summary>
public sealed record MsiDistributionRecord(string RelativeMsiFileName, string FinalMsiSha256,
    string ReleaseRecordSha256, string InstallerPlanSha256, string PolicyId,
    NativeAuthenticodeTrustCategory WinTrust, PrimarySignatureCountPolicyCategory PrimarySignatureCount,
    NativeDigestAlgorithmCategory Digest, TimestampPolicyCategory Timestamp, AuthenticodeEkuPolicyCategory Eku);

public static class MsiDistributionRecordCodec
{
    public const string Schema = "vantrel-msi-distribution-record-v1";
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly string[] Keys = ["schema", "msi-file", "final-msi-sha256", "release-record-sha256",
        "installer-plan-sha256", "policy-id", "wintrust", "primary-signature-count", "digest", "timestamp", "eku-category"];

    public static byte[] CreateCanonical(MsiDistributionRecord value)
    {
        Validate(value);
        var fields = new[] { Schema, value.RelativeMsiFileName, value.FinalMsiSha256, value.ReleaseRecordSha256,
            value.InstallerPlanSha256, value.PolicyId, value.WinTrust.ToString(), value.PrimarySignatureCount.ToString(),
            value.Digest.ToString(), value.Timestamp.ToString(), value.Eku.ToString() };
        var text = new StringBuilder();
        for (var index = 0; index < Keys.Length; index++) text.Append(Keys[index]).Append('=').Append(fields[index]).Append('\n');
        return Utf8.GetBytes(text.ToString());
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out MsiDistributionRecord? record)
    {
        record = null;
        if (bytes.Length is 0 or > 4096 || bytes[0] == 0xEF || bytes.IndexOf((byte)'\r') >= 0 ||
            bytes.ToArray().Any(item => item > 0x7F)) return false;
        var text = Utf8.GetString(bytes);
        if (!text.EndsWith('\n')) return false;
        var lines = text.Split('\n');
        if (lines.Length != Keys.Length + 1 || lines[^1] != "") return false;
        var values = new string[Keys.Length];
        for (var index = 0; index < Keys.Length; index++)
        {
            var prefix = Keys[index] + "=";
            if (!lines[index].StartsWith(prefix, StringComparison.Ordinal)) return false;
            values[index] = lines[index][prefix.Length..];
        }
        if (values[0] != Schema || !Enum.TryParse(values[6], false, out NativeAuthenticodeTrustCategory trust) ||
            !Enum.TryParse(values[7], false, out PrimarySignatureCountPolicyCategory signatures) ||
            !Enum.TryParse(values[8], false, out NativeDigestAlgorithmCategory digest) ||
            !Enum.TryParse(values[9], false, out TimestampPolicyCategory timestamp) ||
            !Enum.TryParse(values[10], false, out AuthenticodeEkuPolicyCategory eku)) return false;
        try
        {
            record = new(values[1], values[2], values[3], values[4], values[5], trust, signatures, digest, timestamp, eku);
            return bytes.SequenceEqual(CreateCanonical(record));
        }
        catch (ArgumentException) { record = null; return false; }
    }

    private static void Validate(MsiDistributionRecord value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!IsSafeName(value.RelativeMsiFileName) || !IsHash(value.FinalMsiSha256) || !IsHash(value.ReleaseRecordSha256) ||
            !IsHash(value.InstallerPlanSha256) || value.PolicyId != MsiAuthenticodeInspectionResult.PolicyId ||
            value.WinTrust != NativeAuthenticodeTrustCategory.Success ||
            value.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne ||
            value.Digest != NativeDigestAlgorithmCategory.Sha256 || value.Timestamp != TimestampPolicyCategory.ValidRfc3161 ||
            value.Eku != AuthenticodeEkuPolicyCategory.Match)
            throw new ArgumentException("MSI distribution evidence is unavailable.", nameof(value));
    }

    private static bool IsSafeName(string? name) => name is { Length: > 4 and <= 128 } &&
        name.EndsWith(".msi", StringComparison.Ordinal) && name[0] is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' &&
        name.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_') &&
        !name.Contains("..", StringComparison.Ordinal);
    private static bool IsHash(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
}

/// <summary>Injected request only. There is no real signer or production command in this task.</summary>
public interface IMsiSigningRequest { bool Sign(string singleMsiPath); }

public sealed record MsiCopyInspectionResult(string FinalMsiSha256, MsiAuthenticodeInspectionResult Inspection);

public sealed class InjectedMsiSigningOrchestrator(IMsiSigningRequest signing, IMsiAuthenticodeInspector inspector,
    IMsiDatabaseValidator? database = null)
{
    private const string Failure = "MSI signing validation failed.";
    private readonly IMsiDatabaseValidator _database = database ?? new WindowsMsiDatabaseValidator();

    public MsiCopyInspectionResult CopySignAndInspect(string releaseLayoutRoot, string installerPlanPath,
        string unsignedMsiPath, string expectedUnsignedSha256, string signedMsiPath)
    {
        try { return CopySignAndInspectCore(releaseLayoutRoot, installerPlanPath, unsignedMsiPath, expectedUnsignedSha256, signedMsiPath); }
        catch { throw new IOException(Failure); }
    }

    private MsiCopyInspectionResult CopySignAndInspectCore(string releaseLayoutRoot, string installerPlanPath,
        string unsignedMsiPath, string expectedUnsignedSha256, string signedMsiPath)
    {
        if (!IsHash(expectedUnsignedSha256)) throw new IOException(Failure);
        var layout = SafeDirectory(releaseLayoutRoot);
        ValidatePlan(layout, installerPlanPath);
        var source = SafeExistingFile(unsignedMsiPath);
        var destination = SafeNewFile(signedMsiPath);
        if (string.Equals(source, destination, StringComparison.OrdinalIgnoreCase) || IsWithin(layout, source) || IsWithin(layout, destination))
            throw new IOException(Failure);
        using var sourceBinding = MsiFileBinding.Open(source);
        sourceBinding.RequireUnchanged();
        if (!_database.IsReadOnlyDatabase(source)) throw new IOException(Failure);
        var before = sourceBinding.Sha256();
        if (before != expectedUnsignedSha256) throw new IOException(Failure);
        var sourceStorage = MsiCompoundStorage.ReadFromHandle(sourceBinding.Handle);
        if (sourceStorage.WholeFileSha256 != before) throw new IOException(Failure);
        var stagingPath = Path.GetDirectoryName(destination)!;
        using var staging = MsiProtectedStaging.CreateNew(stagingPath);
        FileIdentity createdIdentity;
        using (var created = staging.CreateNewMsi(destination))
        {
            Copy(sourceBinding.Handle, created);
            createdIdentity = staging.VerifyFile(destination, created);
            if (Hash(created) != before || sourceBinding.Sha256() != before) throw new IOException(Failure);
        }
        using (var baseline = MsiFileBinding.Open(destination))
        {
            if (staging.VerifyFile(destination, baseline.Handle) != createdIdentity || baseline.Sha256() != before)
                throw new IOException(Failure);
            var copiedStorage = MsiCompoundStorage.ReadFromHandle(baseline.Handle);
            if (copiedStorage.WholeFileSha256 != before ||
                !sourceStorage.Entries.OrderBy(item => item.Key, StringComparer.Ordinal)
                    .SequenceEqual(copiedStorage.Entries.OrderBy(item => item.Key, StringComparer.Ordinal)))
                throw new IOException(Failure);
        }
        // Only the read-only leaf binding is released for the injected signing interval.
        // The parent binding is retained for identity checks; it is not a rename barrier.
        bool signed;
        try { signed = signing.Sign(destination); }
        catch { throw new IOException(Failure); }
        sourceBinding.RequireUnchanged();
        if (!signed || sourceBinding.Sha256() != before) throw new IOException(Failure);
        using var destinationBinding = MsiFileBinding.Open(destination);
        if (staging.VerifyFile(destination, destinationBinding.Handle) != createdIdentity) throw new IOException(Failure);
        var signedStorage = MsiCompoundStorage.ReadFromHandle(destinationBinding.Handle);
        MsiCompoundStorageComparer.RequireOnlySignatureChanges(sourceStorage, signedStorage);
        var verifiedBytes = destinationBinding.Sha256();
        if (verifiedBytes != signedStorage.WholeFileSha256) throw new IOException(Failure);
        MsiAuthenticodeInspectionResult result;
        try { result = inspector.Inspect(destinationBinding); }
        catch { throw new IOException(Failure); }
        if (!result.Success || result.Trust != NativeAuthenticodeTrustCategory.Success ||
            result.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne ||
            result.Digest != NativeDigestAlgorithmCategory.Sha256 || result.Timestamp != TimestampPolicyCategory.ValidRfc3161 ||
            result.EkuCategory != AuthenticodeEkuPolicyCategory.Match || destinationBinding.Sha256() != verifiedBytes || sourceBinding.Sha256() != before)
            throw new IOException(Failure);
        ValidatePlan(layout, installerPlanPath);
        destinationBinding.RequireUnchanged();
        if (staging.VerifyFile(destination, destinationBinding.Handle) != createdIdentity ||
            MsiCompoundStorage.ReadFromHandle(destinationBinding.Handle).WholeFileSha256 != verifiedBytes)
            throw new IOException(Failure);
        return new(verifiedBytes, result);
    }

    private static void ValidatePlan(string layout, string planPath)
    {
        var path = SafeExistingPlan(planPath);
        if (IsWithin(layout, path) ||
            !InstallerInputPlanCodec.TryParse(File.ReadAllBytes(path), out var plan) || plan is null) throw new IOException(Failure);
        var current = new InstallerInputValidator().CreatePlan(layout, plan.MsiProductVersion);
        if (!string.Equals(InstallerInputValidator.CreateCanonicalPlan(current), InstallerInputValidator.CreateCanonicalPlan(plan), StringComparison.Ordinal))
            throw new IOException(Failure);
    }

    private static string SafeExistingPlan(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException(Failure);
        for (var parent = Directory.GetParent(path); parent is not null; parent = parent.Parent)
            if (!parent.Exists || (parent.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException(Failure);
        return path;
    }

    private static string SafeExistingFile(string path)
    {
        var full = SafePath(path);
        if (!File.Exists(full) || Directory.Exists(full) || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new IOException(Failure);
        return full;
    }
    private static string SafeDirectory(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
                !string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)), Path.TrimEndingDirectorySeparator(path), StringComparison.OrdinalIgnoreCase))
                throw new IOException();
            var full = Path.TrimEndingDirectorySeparator(path);
            for (var directory = new DirectoryInfo(full); directory is not null; directory = directory.Parent)
                if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException();
            return full;
        }
        catch { throw new IOException(Failure); }
    }
    private static bool IsWithin(string root, string path) => path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    private static string SafeNewFile(string path)
    {
        var full = SafePath(path);
        if (File.Exists(full) || Directory.Exists(full) ||
            Directory.Exists(Path.GetDirectoryName(full)!) || File.Exists(Path.GetDirectoryName(full)!)) throw new IOException(Failure);
        return full;
    }
    private static string SafePath(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || Path.GetExtension(path) != ".msi" ||
                !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase)) throw new IOException();
            var immediate = Path.GetDirectoryName(path)!;
            for (var parent = new DirectoryInfo(immediate); parent is not null; parent = parent.Parent)
            {
                if (!parent.Exists) { if (parent.FullName == immediate) continue; throw new IOException(); }
                if ((parent.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException();
            }
            return path;
        }
        catch { throw new IOException(Failure); }
    }
    private static bool IsHash(string? hash) => hash is { Length: 64 } && hash.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static void Copy(SafeFileHandle source, SafeFileHandle destination)
    {
        var length = RandomAccess.GetLength(source);
        if (length is < 512 or > 512L * 1024 * 1024) throw new IOException(Failure);
        var buffer = new byte[65536];
        long offset = 0;
        while (offset < length)
        {
            var count = RandomAccess.Read(source, buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - offset)), offset);
            if (count <= 0) throw new IOException(Failure);
            RandomAccess.Write(destination, buffer.AsSpan(0, count), offset);
            offset += count;
        }
        RandomAccess.FlushToDisk(destination);
        if (RandomAccess.GetLength(source) != length || RandomAccess.GetLength(destination) != length)
            throw new IOException(Failure);
    }

    private static string Hash(SafeFileHandle handle)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var length = RandomAccess.GetLength(handle);
        var buffer = new byte[65536];
        long offset = 0;
        while (offset < length)
        {
            var count = RandomAccess.Read(handle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - offset)), offset);
            if (count <= 0) throw new IOException(Failure);
            digest.AppendData(buffer.AsSpan(0, count));
            offset += count;
        }
        if (RandomAccess.GetLength(handle) != length) throw new IOException(Failure);
        return Convert.ToHexString(digest.GetHashAndReset());
    }
}
