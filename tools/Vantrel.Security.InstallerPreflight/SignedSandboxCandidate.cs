using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.InstallerPreflight;

public sealed record SignedSandboxCandidateInput(SandboxValidationInput Installation,
    string ReleaseRecordSha256, string DistributionRecordSha256, string PolicyId);

/// <summary>A distinct, canonical input contract for a completed signed MSI candidate.</summary>
public static class SignedSandboxCandidateInputCodec
{
    public const string Schema = "vantrel-signed-sandbox-input-v1";
    public const string FileName = "vantrel-signed-sandbox-input-v1.txt";
    private const string LegacySchemaLine = "schema=vantrel-sandbox-input-v1\n";
    private const string ExtraAnchor = "artifact-count=";
    private static readonly UTF8Encoding Ascii = new(false, true);

    public static byte[] CreateCanonical(SignedSandboxCandidateInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!IsHash(input.ReleaseRecordSha256) || !IsHash(input.DistributionRecordSha256) ||
            input.PolicyId != MsiAuthenticodeInspectionResult.PolicyId)
            throw new ArgumentException("Signed Sandbox input is invalid.", nameof(input));
        var legacy = SandboxValidationInputCodec.CreateCanonical(input.Installation);
        var index = legacy.IndexOf(ExtraAnchor, StringComparison.Ordinal);
        if (!legacy.StartsWith(LegacySchemaLine, StringComparison.Ordinal) || index < 0)
            throw new ArgumentException("Signed Sandbox input is invalid.", nameof(input));
        var canonical = "schema=" + Schema + "\n" + legacy[LegacySchemaLine.Length..index] +
            "release-record-sha256=" + input.ReleaseRecordSha256 + "\n" +
            "distribution-record-sha256=" + input.DistributionRecordSha256 + "\n" +
            "policy-id=" + input.PolicyId + "\n" + legacy[index..];
        return Ascii.GetBytes(canonical);
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out SignedSandboxCandidateInput? input)
    {
        input = null;
        if (bytes.Length is 0 or > 1024 * 1024 || bytes.IndexOf((byte)'\r') >= 0 ||
            bytes.ToArray().Any(value => value > 127)) return false;
        var text = Ascii.GetString(bytes);
        var lines = text.Split('\n');
        if (lines.Length < 14 || lines[0] != "schema=" + Schema || lines[^1] != "" ||
            !lines[8].StartsWith("release-record-sha256=", StringComparison.Ordinal) ||
            !lines[9].StartsWith("distribution-record-sha256=", StringComparison.Ordinal) ||
            !lines[10].StartsWith("policy-id=", StringComparison.Ordinal)) return false;
        var releaseHash = lines[8]["release-record-sha256=".Length..];
        var distributionHash = lines[9]["distribution-record-sha256=".Length..];
        var policy = lines[10]["policy-id=".Length..];
        if (!IsHash(releaseHash) || !IsHash(distributionHash) || policy != MsiAuthenticodeInspectionResult.PolicyId)
            return false;
        var legacy = LegacySchemaLine + string.Join('\n', lines.Skip(1).Take(7).Concat(lines.Skip(11)));
        if (!SandboxValidationInputCodec.TryParse(Ascii.GetBytes(legacy), out var installation) || installation is null) return false;
        try
        {
            input = new(installation, releaseHash, distributionHash, policy);
            return bytes.SequenceEqual(CreateCanonical(input));
        }
        catch (ArgumentException) { input = null; return false; }
    }

    private static bool IsHash(string? value) => value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
}

/// <summary>Host-only copying and input binding; this never builds, signs, installs, or launches.</summary>
public static class SignedSandboxCandidatePreparation
{
    private const string Failure = "Signed Sandbox preparation failed.";
    public static void Prepare(string layoutRoot, string planPath, string signedMsiPath,
        string distributionRecordPath, string expectedMsiHash, string expectedPlanHash,
        string expectedReleaseRecordHash, string expectedDistributionRecordHash, string outputRoot)
    {
        try { PrepareCore(layoutRoot, planPath, signedMsiPath, distributionRecordPath,
            expectedMsiHash, expectedPlanHash, expectedReleaseRecordHash, expectedDistributionRecordHash, outputRoot); }
        catch { throw new IOException(Failure); }
    }

    public static void ValidatePreparedInput(string inputRoot, string approvedDistributionRecordHash)
    {
        try
        {
            if (!IsHash(approvedDistributionRecordHash)) throw new IOException();
            var root = SafeDirectory(inputRoot);
            var expected = new HashSet<string>(StringComparer.Ordinal)
            {
                "VantrelSecurity.msi", InstallerInputValidator.PlanFileName,
                BetaReleaseLayoutValidator.RecordFileName, MsiDistributionRecordCodec.FileName,
                SignedSandboxCandidateInputCodec.FileName, "Validate-VantrelSignedCandidateSandbox.ps1"
            };
            var observed = Directory.EnumerateFileSystemEntries(root).ToArray();
            if (observed.Length != expected.Count || observed.Any(path =>
                !expected.Remove(Path.GetFileName(path)) || !File.Exists(SafeFile(path)))) throw new IOException();
            var manifestBytes = File.ReadAllBytes(SafeFile(Path.Combine(root, SignedSandboxCandidateInputCodec.FileName)));
            var planBytes = File.ReadAllBytes(SafeFile(Path.Combine(root, InstallerInputValidator.PlanFileName)));
            var recordBytes = File.ReadAllBytes(SafeFile(Path.Combine(root, BetaReleaseLayoutValidator.RecordFileName)));
            var distributionBytes = File.ReadAllBytes(SafeFile(Path.Combine(root, MsiDistributionRecordCodec.FileName)));
            if (!SignedSandboxCandidateInputCodec.TryParse(manifestBytes, out var manifest) || manifest is null ||
                !InstallerInputPlanCodec.TryParse(planBytes, out var plan) || plan is null ||
                !BetaReleaseRecordCodec.TryParse(recordBytes, out var record) || record is null ||
                !MsiDistributionRecordCodec.TryParse(distributionBytes, out var distribution) || distribution is null ||
                Hash(planBytes) != manifest.Installation.InstallerPlanSha256 ||
                Hash(recordBytes) != manifest.ReleaseRecordSha256 ||
                Hash(distributionBytes) != approvedDistributionRecordHash ||
                manifest.DistributionRecordSha256 != approvedDistributionRecordHash ||
                plan.Descriptor != record.Descriptor ||
                plan.Descriptor.SourceCommit != manifest.Installation.SourceCommit ||
                plan.Descriptor.ReleaseVersion != manifest.Installation.ReleaseVersion ||
                plan.Descriptor.ReleaseSequence != manifest.Installation.ReleaseSequence ||
                plan.Descriptor.PublishedAtUtc != manifest.Installation.PublishedAtUtc ||
                plan.MsiProductVersion != manifest.Installation.MsiProductVersion ||
                plan.Artifacts.Count != manifest.Installation.Artifacts.Count ||
                !plan.Artifacts.SequenceEqual(manifest.Installation.Artifacts) ||
                distribution.RelativeMsiFileName != "VantrelSecurity.msi" ||
                distribution.ReleaseRecordSha256 != manifest.ReleaseRecordSha256 ||
                distribution.InstallerPlanSha256 != manifest.Installation.InstallerPlanSha256 ||
                distribution.FinalMsiSha256 != manifest.Installation.MsiSha256 ||
                distribution.PolicyId != manifest.PolicyId)
                throw new IOException();
            using var msi = MsiFileBinding.Open(Path.Combine(root, "VantrelSecurity.msi"));
            if (msi.Sha256() != manifest.Installation.MsiSha256) throw new IOException();
        }
        catch { throw new IOException(Failure); }
    }

    private static void PrepareCore(string layoutRoot, string planPath, string signedMsiPath,
        string distributionRecordPath, string expectedMsiHash, string expectedPlanHash,
        string expectedReleaseRecordHash, string expectedDistributionRecordHash, string outputRoot)
    {
        if (!IsHash(expectedMsiHash) || !IsHash(expectedPlanHash) || !IsHash(expectedReleaseRecordHash) ||
            !IsHash(expectedDistributionRecordHash)) throw new IOException();
        var layout = SafeDirectory(layoutRoot);
        var plan = SafeFile(planPath);
        var distribution = SafeFile(distributionRecordPath);
        var release = SafeFile(Path.Combine(layout, BetaReleaseLayoutValidator.RecordFileName));
        var msi = SafeFile(signedMsiPath);
        var output = SafeNewDirectory(outputRoot);
        foreach (var path in new[] { plan, distribution, msi, output })
            if (Within(layout, path)) throw new IOException();
        foreach (var path in new[] { plan, distribution, msi })
            if (Within(output, path) || Within(path, output)) throw new IOException();

        using var boundPlan = new BoundInput(plan);
        using var boundRelease = new BoundInput(release);
        using var boundDistribution = new BoundInput(distribution);
        var planBytes = boundPlan.ReadBytes();
        var recordBytes = boundRelease.ReadBytes();
        var distributionBytes = boundDistribution.ReadBytes();
        if (Hash(planBytes) != expectedPlanHash || Hash(recordBytes) != expectedReleaseRecordHash ||
            Hash(distributionBytes) != expectedDistributionRecordHash ||
            !InstallerInputPlanCodec.TryParse(planBytes, out var parsedPlan) || parsedPlan is null ||
            !BetaReleaseRecordCodec.TryParse(recordBytes, out var parsedRecord) || parsedRecord is null ||
            !MsiDistributionRecordCodec.TryParse(distributionBytes, out var parsedDistribution) || parsedDistribution is null ||
            parsedDistribution.RelativeMsiFileName != "VantrelSecurity.msi" ||
            parsedDistribution.FinalMsiSha256 != expectedMsiHash ||
            parsedDistribution.ReleaseRecordSha256 != expectedReleaseRecordHash ||
            parsedDistribution.InstallerPlanSha256 != expectedPlanHash ||
            parsedPlan.Descriptor != parsedRecord.Descriptor)
            throw new IOException();
        var current = new InstallerInputValidator().CreatePlan(layout, parsedPlan.MsiProductVersion);
        if (!string.Equals(InstallerInputValidator.CreateCanonicalPlan(current),
            InstallerInputValidator.CreateCanonicalPlan(parsedPlan), StringComparison.Ordinal)) throw new IOException();

        using var source = MsiFileBinding.Open(msi);
        if (source.Sha256() != expectedMsiHash) throw new IOException();
        if (File.Exists(output) || Directory.Exists(output)) throw new IOException();
        Directory.CreateDirectory(output);
        var input = Path.Combine(output, "input");
        Directory.CreateDirectory(input);
        var copiedMsi = Path.Combine(input, "VantrelSecurity.msi");
        using (var destination = new FileStream(copiedMsi, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            var length = RandomAccess.GetLength(source.Handle);
            var buffer = new byte[65536];
            for (long position = 0; position < length;)
            {
                var read = RandomAccess.Read(source.Handle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - position)), position);
                if (read <= 0) throw new IOException();
                destination.Write(buffer, 0, read);
                position += read;
            }
            destination.Flush(true);
        }
        using (var copy = MsiFileBinding.Open(copiedMsi))
        {
            if (copy.Sha256() != expectedMsiHash || source.Sha256() != expectedMsiHash) throw new IOException();
            File.WriteAllBytes(Path.Combine(input, InstallerInputValidator.PlanFileName), planBytes);
            File.WriteAllBytes(Path.Combine(input, BetaReleaseLayoutValidator.RecordFileName), recordBytes);
            File.WriteAllBytes(Path.Combine(input, MsiDistributionRecordCodec.FileName), distributionBytes);
            if (Hash(boundPlan.ReadBytes()) != expectedPlanHash ||
                Hash(boundRelease.ReadBytes()) != expectedReleaseRecordHash ||
                Hash(boundDistribution.ReadBytes()) != expectedDistributionRecordHash)
                throw new IOException();
            var legacy = new SandboxValidationInput(parsedPlan.Descriptor.SourceCommit,
                parsedPlan.Descriptor.ReleaseVersion, parsedPlan.Descriptor.ReleaseSequence,
                parsedPlan.Descriptor.PublishedAtUtc, parsedPlan.MsiProductVersion, expectedMsiHash,
                expectedPlanHash, parsedPlan.Artifacts);
            var signedInput = new SignedSandboxCandidateInput(legacy, expectedReleaseRecordHash,
                expectedDistributionRecordHash, parsedDistribution.PolicyId);
            File.WriteAllBytes(Path.Combine(input, SignedSandboxCandidateInputCodec.FileName),
                SignedSandboxCandidateInputCodec.CreateCanonical(signedInput));
            copy.RequireUnchanged();
        }
        source.RequireUnchanged();
    }

    private static string SafeDirectory(string path)
    {
        if (!IsFixedAbsolute(path) ||
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)) != Path.TrimEndingDirectorySeparator(path)) throw new IOException();
        MsiProtectedStaging.CheckAncestors(path);
        return path;
    }
    private static string SafeFile(string path)
    {
        if (!IsFixedAbsolute(path) || Path.GetFullPath(path) != path ||
            !File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException();
        MsiProtectedStaging.CheckAncestors(Path.GetDirectoryName(path)!);
        return path;
    }
    private static string SafeNewDirectory(string path)
    {
        if (!IsFixedAbsolute(path) ||
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)) != Path.TrimEndingDirectorySeparator(path) ||
            File.Exists(path) || Directory.Exists(path)) throw new IOException();
        MsiProtectedStaging.CheckAncestors(Path.GetDirectoryName(path)!);
        return path;
    }
    private static bool Within(string parent, string path) => path.StartsWith(
        Path.TrimEndingDirectorySeparator(parent) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    private static bool IsFixedAbsolute(string? path) => path is { Length: >= 3 } && path[1] == ':' && path[2] == '\\' &&
        Path.IsPathFullyQualified(path) && new DriveInfo(path[..3]).DriveType == DriveType.Fixed;
    private static bool IsHash(string? value) => value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    private sealed class BoundInput : IDisposable
    {
        private readonly string _path;
        private readonly FileStream _stream;
        private readonly FileIdentity _identity;
        internal BoundInput(string path)
        {
            _path = path;
            _stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                _identity = MsiProtectedStaging.Inspect(_stream.SafeFileHandle, expectDirectory: false);
                RequireUnchanged();
            }
            catch { _stream.Dispose(); throw; }
        }
        internal byte[] ReadBytes()
        {
            RequireUnchanged();
            if (_stream.Length > 1024 * 1024 * 16) throw new IOException();
            _stream.Position = 0;
            using var memory = new MemoryStream();
            _stream.CopyTo(memory);
            if (_stream.Position != _stream.Length) throw new IOException();
            RequireUnchanged();
            return memory.ToArray();
        }
        private void RequireUnchanged()
        {
            MsiProtectedStaging.CheckAncestors(Path.GetDirectoryName(_path)!);
            if (!File.Exists(_path) || (File.GetAttributes(_path) & FileAttributes.ReparsePoint) != 0 ||
                MsiProtectedStaging.Inspect(_stream.SafeFileHandle, expectDirectory: false) != _identity ||
                !string.Equals(_identity.FinalPath, "\\\\?\\" + _path, StringComparison.OrdinalIgnoreCase))
                throw new IOException();
        }
        public void Dispose() => _stream.Dispose();
    }
}
