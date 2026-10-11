using System.Runtime.Versioning;
using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.ManifestTool;

namespace Vantrel.Security.ReleaseLayoutTool;

internal interface IServiceReleaseV2PrivateKeyProvider
{
    ECDsa OpenKey(string absolutePath);
}

internal enum ServiceReleaseV2PublicationCheckpoint
{
    BeforeTemporaryReadback,
    BeforeTemporaryVerification,
    BeforeFinalConsistency,
    BeforeFinalMove,
    ImmediatelyBeforeRename
}

/// <summary>
/// Reads only an external, protected PKCS#8 file. The command line carries a path, never
/// private bytes; the returned key is checked against its purpose-specific public root by
/// the ManifestTool signing helper before it can create either sidecar.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ProtectedExternalV2PrivateKeyProvider(string sourceRoot, string outputRoot) :
    IServiceReleaseV2PrivateKeyProvider
{
    private const string Invalid = "V2 offline signing key is unavailable or invalid.";

    public ECDsa OpenKey(string absolutePath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(absolutePath) || !Path.IsPathFullyQualified(absolutePath) ||
                Path.GetFullPath(absolutePath) != absolutePath ||
                !Path.GetExtension(absolutePath).Equals(".pk8", StringComparison.OrdinalIgnoreCase) ||
                IsSameOrBelow(absolutePath, sourceRoot) ||
                IsSameOrBelow(absolutePath, Path.GetDirectoryName(outputRoot) ?? outputRoot))
                throw new IOException(Invalid);
            var parent = Path.GetDirectoryName(absolutePath) ?? throw new IOException(Invalid);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(parent);
            var privateBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(absolutePath, 16 * 1024);
            try
            {
                var key = ECDsa.Create();
                try
                {
                    key.ImportPkcs8PrivateKey(privateBytes, out var consumed);
                    if (consumed != privateBytes.Length || key.KeySize != 256 ||
                        key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                        throw new CryptographicException();
                    return key;
                }
                catch { key.Dispose(); throw; }
            }
            finally { CryptographicOperations.ZeroMemory(privateBytes); }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or
            NotSupportedException or CryptographicException or PlatformNotSupportedException)
        { throw new IOException(Invalid); }
    }

    private static bool IsSameOrBelow(string candidate, string root) =>
        candidate.Equals(root, StringComparison.OrdinalIgnoreCase) ||
        candidate.StartsWith(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// The explicit v2 sidecar producer. It proves the final post-Authenticode Service layout
/// before consulting an external key, and Record independently repeats every release check.
/// Existing v1 ManifestTool commands and offline-update consumers never call this path.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ServiceReleaseV2SidecarProducer
{
    private const string Invalid = "V2 Service sidecar operation failed.";
    private static readonly string[] DiagnosticNames =
    [
        "Vantrel.Security.Core.pdb", "Vantrel.Security.Infrastructure.pdb",
        "Vantrel.Security.Service.pdb"
    ];

    private readonly IServiceReleaseV2SourceBinding _sourceBinding;
    private readonly IServiceReleaseV2AuthenticodeGate _authenticode;
    private readonly IServiceReleaseV2PrivateKeyProvider _keys;
    private readonly byte[] _manifestRoot;
    private readonly byte[] _metadataRoot;
    private readonly Action<ServiceReleaseV2PublicationCheckpoint, string, string>? _publicationCheckpoint;

    internal ServiceReleaseV2SidecarProducer(IServiceReleaseV2SourceBinding sourceBinding,
        IServiceReleaseV2AuthenticodeGate authenticode,
        IServiceReleaseV2PrivateKeyProvider keys,
        byte[] manifestPublicSpki, byte[] metadataPublicSpki,
        Action<ServiceReleaseV2PublicationCheckpoint, string, string>? publicationCheckpoint = null)
    {
        _sourceBinding = sourceBinding ?? throw new ArgumentNullException(nameof(sourceBinding));
        _authenticode = authenticode ?? throw new ArgumentNullException(nameof(authenticode));
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
        _manifestRoot = manifestPublicSpki?.ToArray() ?? throw new ArgumentNullException(nameof(manifestPublicSpki));
        _metadataRoot = metadataPublicSpki?.ToArray() ?? throw new ArgumentNullException(nameof(metadataPublicSpki));
        _publicationCheckpoint = publicationCheckpoint;
        if (_manifestRoot.AsSpan().SequenceEqual(_metadataRoot)) throw new ArgumentException(Invalid);
    }

    internal byte[] SignManifest(string outputRoot, ServiceReleaseV2BuildProvenance provenance,
        string privateKeyPath)
    {
        ApprovedLayout? approved = null;
        try
        {
            approved = ValidateFinalService(outputRoot, provenance, manifestExpected: false);
            byte[] bytes;
            using (var key = _keys.OpenKey(privateKeyPath))
                bytes = TrustedManifestV2SidecarSigning.CreateSignedManifest(
                    approved.Descriptor.ReleaseVersion, approved.Descriptor.ReleaseSequence,
                    approved.ServiceFiles, key, _manifestRoot);
            if (!VerifyManifest(bytes, approved)) throw new IOException(Invalid);
            approved.Binding.Recheck();
            PublishProtectedSidecar(Path.Combine(outputRoot, ServiceReleaseV2RecordGate.ManifestFileName),
                bytes, TrustedManifestV2Codec.MaximumBytes,
                readback => VerifyManifest(readback, approved), approved.Binding.Recheck);
            return bytes;
        }
        catch (TrackedSourceProvenanceException) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or
            InvalidDataException or CryptographicException or NotSupportedException or InvalidOperationException)
        { throw new IOException(Invalid); }
        finally
        {
            // Disposal is non-semantic cleanup after the rename commit point. It must not
            // turn a published, verified sidecar into a reported command failure.
            try { approved?.Dispose(); } catch { }
        }
    }

    internal byte[] SignMetadata(string outputRoot, ServiceReleaseV2BuildProvenance provenance,
        string privateKeyPath)
    {
        ApprovedLayout? approved = null;
        try
        {
            approved = ValidateFinalService(outputRoot, provenance, manifestExpected: true);
            var manifestBytes = approved.ManifestBytes ?? throw new IOException(Invalid);
            if (!VerifyManifest(manifestBytes, approved)) throw new IOException(Invalid);
            byte[] bytes;
            using (var key = _keys.OpenKey(privateKeyPath))
                bytes = TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                    manifestBytes, approved.Descriptor.ReleaseVersion, approved.Descriptor.ReleaseSequence,
                    approved.Descriptor.PublishedAtUtc, key, _manifestRoot, _metadataRoot);
            if (!VerifyMetadata(manifestBytes, bytes, approved.Descriptor)) throw new IOException(Invalid);
            approved.Binding.Recheck();
            PublishProtectedSidecar(Path.Combine(outputRoot, ServiceReleaseV2RecordGate.MetadataFileName),
                bytes, ReleaseMetadataCodec.MaximumBytes,
                readback => VerifyMetadata(manifestBytes, readback, approved.Descriptor),
                () =>
                {
                    if (!approved.Binding.ReadBounded(ServiceReleaseV2RecordGate.ManifestFileName,
                            TrustedManifestV2Codec.MaximumBytes).AsSpan().SequenceEqual(manifestBytes))
                        throw new IOException(Invalid);
                    approved.Binding.Recheck();
                });
            return bytes;
        }
        catch (TrackedSourceProvenanceException) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or
            InvalidDataException or CryptographicException or NotSupportedException or InvalidOperationException)
        { throw new IOException(Invalid); }
        finally
        {
            try { approved?.Dispose(); } catch { }
        }
    }

    private ApprovedLayout ValidateFinalService(string outputRoot,
        ServiceReleaseV2BuildProvenance provenance, bool manifestExpected)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(outputRoot) ||
            Path.GetFullPath(outputRoot) != outputRoot ||
            provenance.SdkVersion != BetaReleaseRecordV2Codec.SdkVersion ||
            provenance.TargetFramework != BetaReleaseRecordV2Codec.TargetFramework ||
            provenance.RuntimeIdentifier != TrustedManifestV2Codec.Architecture ||
            provenance.Deployment != TrustedManifestV2Codec.Deployment ||
            !IsUpperHash(provenance.SourceLockSha256)) throw new IOException(Invalid);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(outputRoot);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(
            Path.GetDirectoryName(outputRoot) ?? throw new IOException(Invalid));
        RequireExactRoot(outputRoot, manifestExpected);

        var descriptorBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(
            Path.Combine(outputRoot, BetaReleaseDescriptorCodec.FileName), 4096);
        var notesBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(
            Path.Combine(outputRoot, BetaReleaseLayoutValidator.ReleaseNotesFileName), 1024 * 1024);
        if (!BetaReleaseDescriptorCodec.TryParse(descriptorBytes, out var descriptor) || descriptor is null ||
            descriptor.SourceCommit != provenance.SourceCommit ||
            descriptor.SdkVersion != provenance.SdkVersion || descriptor.Configuration != "Release" ||
            descriptor.Runtime != provenance.RuntimeIdentifier ||
            descriptor.ReleaseNotesSha256 != Hash(notesBytes)) throw new IOException(Invalid);

        var serviceRoot = Path.Combine(outputRoot, ServiceReleaseV2ProductionProjector.ServiceDirectoryName);
        var diagnosticsRoot = Path.Combine(outputRoot,
            ServiceReleaseV2ProductionProjector.DiagnosticDirectoryName);
        var service = ServicePublishFileSnapshot.Capture(serviceRoot).Files.ToArray();
        if (service.Any(file => file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)))
            throw new IOException(Invalid);
        _ = ServicePublishDependencyValidator.Validate(serviceRoot, service);
        _ = TrustedManifestV2Codec.CreateCanonicalPayload(descriptor.ReleaseVersion,
            descriptor.ReleaseSequence, service);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedTree(serviceRoot, service);
        var diagnostics = DiagnosticNames.Select(name => new TrustedManifestV2File(name,
            ServiceReleaseV2FileSystemSecurity.HashProtectedFile(Path.Combine(diagnosticsRoot, name),
                1024L * 1024 * 1024))).ToArray();
        _ = ServiceReleaseV2ProductionProjector.ValidateDiagnosticSymbols(diagnosticsRoot, diagnostics);

        byte[]? manifestBytes = null;
        if (manifestExpected)
        {
            manifestBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(
                Path.Combine(outputRoot, ServiceReleaseV2RecordGate.ManifestFileName),
                TrustedManifestV2Codec.MaximumBytes);
            if (!TrustedManifestV2Codec.TryParse(manifestBytes, out var manifest, out _) ||
                manifest is null || manifest.Release != descriptor.ReleaseVersion ||
                manifest.ReleaseSequence != descriptor.ReleaseSequence ||
                !manifest.Files.SequenceEqual(service) ||
                !TrustedManifestV2Codec.Verify(manifest, _manifestRoot)) throw new IOException(Invalid);
        }

        var expected = new List<ServiceReleaseV2BoundFile>
        {
            new(BetaReleaseDescriptorCodec.FileName, Hash(descriptorBytes)),
            new(BetaReleaseLayoutValidator.ReleaseNotesFileName, Hash(notesBytes))
        };
        expected.AddRange(service.Select(file => new ServiceReleaseV2BoundFile("service/" + file.Path,
            file.Sha256)));
        expected.AddRange(diagnostics.Select(file => new ServiceReleaseV2BoundFile(
            "diagnostic-symbols/" + file.Path, file.Sha256)));
        if (manifestBytes is not null)
            expected.Add(new(ServiceReleaseV2RecordGate.ManifestFileName, Hash(manifestBytes)));
        expected.Sort((left, right) => StringComparer.Ordinal.Compare(left.RelativePath, right.RelativePath));
        ServiceReleaseV2FinalBinding? binding = null;
        try
        {
            binding = ServiceReleaseV2FinalBinding.Open(outputRoot, expected);
            if (!binding.ReadBounded(BetaReleaseDescriptorCodec.FileName, 4096)
                    .AsSpan().SequenceEqual(descriptorBytes) ||
                !binding.ReadBounded(BetaReleaseLayoutValidator.ReleaseNotesFileName, 1024 * 1024)
                    .AsSpan().SequenceEqual(notesBytes) ||
                (manifestBytes is not null &&
                 !binding.ReadBounded(ServiceReleaseV2RecordGate.ManifestFileName,
                     TrustedManifestV2Codec.MaximumBytes).AsSpan().SequenceEqual(manifestBytes)))
                throw new IOException(Invalid);
            _sourceBinding.Verify(outputRoot, descriptor, provenance, service, diagnostics, binding);
            foreach (var artifact in ServiceReleaseV2PeContract.VantrelOwnedPeArtifacts)
            {
                var relative = artifact.RelativePath;
                var before = binding.Hash(relative);
                var evidence = _authenticode.Verify(relative,
                    Path.Combine(outputRoot, relative.Replace('/', '\\')), binding.GetHandle(relative));
                if (evidence.RelativePath != relative ||
                    evidence.Category != AuthenticodeVerificationCategory.Valid ||
                    evidence.SignerPolicyId != BetaReleaseRecordV2Codec.SigningPolicyId ||
                    evidence.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne ||
                    evidence.Timestamp != TimestampPolicyCategory.ValidRfc3161 ||
                    binding.Hash(relative) != before) throw new IOException(Invalid);
            }
            binding.Recheck();
            return new ApprovedLayout(descriptor, service, expected, manifestBytes, binding);
        }
        catch { binding?.Dispose(); throw; }
    }

    private bool VerifyManifest(ReadOnlySpan<byte> bytes, ApprovedLayout approved) =>
        TrustedManifestV2Codec.TryParse(bytes, out var parsed, out _) && parsed is not null &&
        parsed.Release == approved.Descriptor.ReleaseVersion &&
        parsed.ReleaseSequence == approved.Descriptor.ReleaseSequence &&
        parsed.Files.SequenceEqual(approved.ServiceFiles) &&
        TrustedManifestV2Codec.Verify(parsed, _manifestRoot);

    private bool VerifyMetadata(ReadOnlySpan<byte> manifestBytes, ReadOnlySpan<byte> metadataBytes,
        BetaReleaseDescriptor descriptor) =>
        TrustedManifestV2Codec.VerifyBoundMetadata(manifestBytes, metadataBytes,
            _manifestRoot, _metadataRoot) &&
        ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out _) && metadata is not null &&
        metadata.DisplayVersion == descriptor.ReleaseVersion &&
        metadata.ReleaseSequence == descriptor.ReleaseSequence &&
        metadata.PublishedAtUtc == descriptor.PublishedAtUtc &&
        metadata.ManifestSha256 == Hash(manifestBytes);

    private void PublishProtectedSidecar(string path, byte[] bytes, int maximumBytes,
        Func<byte[], bool> verifyReadback, Action verifyFinalConsistency)
    {
        if (Path.Exists(path)) throw new IOException(Invalid);
        // The protected parent is on the same volume as the release layout. Keeping the
        // temporary outside that exact layout lets its retained inventory be rechecked
        // immediately before the no-overwrite publication rename.
        var parent = Path.GetDirectoryName(Path.GetDirectoryName(path)!)!;
        var temporary = Path.Combine(parent, "." + Path.GetFileName(path) + "." +
            Guid.NewGuid().ToString("N") + ".tmp");
        var published = false;
        var created = false;
        try
        {
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None))
            {
                created = true;
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }
            ServiceReleaseV2FileSystemSecurity.ProtectFile(temporary);
            _publicationCheckpoint?.Invoke(ServiceReleaseV2PublicationCheckpoint.BeforeTemporaryReadback,
                temporary, path);
            var readback = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(
                temporary, maximumBytes);
            if (!readback.AsSpan().SequenceEqual(bytes)) throw new IOException(Invalid);
            _publicationCheckpoint?.Invoke(ServiceReleaseV2PublicationCheckpoint.BeforeTemporaryVerification,
                temporary, path);
            if (!verifyReadback(readback)) throw new IOException(Invalid);
            _publicationCheckpoint?.Invoke(ServiceReleaseV2PublicationCheckpoint.BeforeFinalConsistency,
                temporary, path);
            verifyFinalConsistency();
            _publicationCheckpoint?.Invoke(ServiceReleaseV2PublicationCheckpoint.BeforeFinalMove,
                temporary, path);
            verifyFinalConsistency();
            if (!ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(temporary, maximumBytes)
                    .AsSpan().SequenceEqual(readback) || Path.Exists(path))
                throw new IOException(Invalid);
            _publicationCheckpoint?.Invoke(ServiceReleaseV2PublicationCheckpoint.ImmediatelyBeforeRename,
                temporary, path);
            // This is the publication commit point. No semantic check follows it.
            File.Move(temporary, path);
            published = true;
        }
        finally
        {
            if (created && !published)
            {
                // A failed cleanup leaves only a randomly named .tmp outside the exact
                // layout. Neither producer nor Record accepts it as a final sidecar.
                try { File.Delete(temporary); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    private static void RequireExactRoot(string root, bool manifestExpected)
    {
        if (Path.Exists(Path.Combine(root, BetaReleaseRecordV2Codec.FileName)))
            throw new IOException(Invalid);
        string[] expected = manifestExpected ?
        [BetaReleaseDescriptorCodec.FileName,
            ServiceReleaseV2ProductionProjector.DiagnosticDirectoryName,
            BetaReleaseLayoutValidator.ReleaseNotesFileName,
            ServiceReleaseV2ProductionProjector.ServiceDirectoryName,
            ServiceReleaseV2RecordGate.ManifestFileName] :
        [BetaReleaseDescriptorCodec.FileName,
            ServiceReleaseV2ProductionProjector.DiagnosticDirectoryName,
            BetaReleaseLayoutValidator.ReleaseNotesFileName,
            ServiceReleaseV2ProductionProjector.ServiceDirectoryName];
        var actual = Directory.EnumerateFileSystemEntries(root)
            .Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
        if (!actual.SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            throw new IOException(Invalid);
    }

    private static bool IsUpperHash(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    private sealed class ApprovedLayout(BetaReleaseDescriptor descriptor,
        IReadOnlyList<TrustedManifestV2File> serviceFiles,
        IReadOnlyList<ServiceReleaseV2BoundFile> expectedFiles,
        byte[]? manifestBytes, ServiceReleaseV2FinalBinding binding) : IDisposable
    {
        internal BetaReleaseDescriptor Descriptor { get; } = descriptor;
        internal IReadOnlyList<TrustedManifestV2File> ServiceFiles { get; } = serviceFiles;
        internal IReadOnlyList<ServiceReleaseV2BoundFile> ExpectedFiles { get; } = expectedFiles;
        internal byte[]? ManifestBytes { get; } = manifestBytes;
        internal ServiceReleaseV2FinalBinding Binding { get; } = binding;
        public void Dispose() => Binding.Dispose();
    }
}
