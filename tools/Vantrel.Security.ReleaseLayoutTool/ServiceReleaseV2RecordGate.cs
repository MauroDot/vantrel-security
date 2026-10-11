using System.Security.Cryptography;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

internal interface IServiceReleaseV2SignatureGate
{
    bool Verify(ReadOnlySpan<byte> manifestBytes, ReadOnlySpan<byte> metadataBytes);
}

internal sealed class ProductionServiceReleaseV2SignatureGate : IServiceReleaseV2SignatureGate
{
    public bool Verify(ReadOnlySpan<byte> manifestBytes, ReadOnlySpan<byte> metadataBytes) =>
        TrustedManifestV2Codec.VerifyProductionBoundMetadata(manifestBytes, metadataBytes);
}

internal interface IServiceReleaseV2AuthenticodeGate
{
    AuthenticodeReleaseEvidence Verify(string relativePath, string absolutePath, SafeFileHandle retainedHandle);
}

internal sealed class ProductionServiceReleaseV2AuthenticodeGate : IServiceReleaseV2AuthenticodeGate
{
    private readonly ReleaseAuthenticodeVerifier _verifier = new();

    public AuthenticodeReleaseEvidence Verify(string relativePath, string absolutePath,
        SafeFileHandle retainedHandle) => _verifier.Verify(relativePath, absolutePath,
            BetaReleaseRecordV2Codec.SigningProfileAlias, retainedHandle);
}

/// <summary>
/// Explicit v2-only approval. The manifest and metadata must already have been signed over
/// the final Service bytes. No signer is called here, and v1 Record is never consulted.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ServiceReleaseV2RecordGate
{
    internal const string ManifestFileName = "Vantrel.Security.TrustedManifest";
    internal const string MetadataFileName = "Vantrel.Security.ReleaseMetadata";
    private const string Invalid = "V2 Service release approval failed.";
    private static readonly string[] DiagnosticNames =
    [
        "Vantrel.Security.Core.pdb", "Vantrel.Security.Infrastructure.pdb",
        "Vantrel.Security.Service.pdb"
    ];

    private readonly IServiceReleaseV2SignatureGate _signatures;
    private readonly IServiceReleaseV2AuthenticodeGate _authenticode;
    private readonly IServiceReleaseV2SourceBinding _sourceBinding;

    internal ServiceReleaseV2RecordGate(IServiceReleaseV2SourceBinding sourceBinding,
        IServiceReleaseV2SignatureGate? signatures = null,
        IServiceReleaseV2AuthenticodeGate? authenticode = null)
    {
        _sourceBinding = sourceBinding ?? throw new ArgumentNullException(nameof(sourceBinding));
        _signatures = signatures ?? new ProductionServiceReleaseV2SignatureGate();
        _authenticode = authenticode ?? new ProductionServiceReleaseV2AuthenticodeGate();
    }

    internal BetaReleaseRecordV2 ValidateAndWriteRecord(string outputRoot,
        ServiceReleaseV2BuildProvenance provenance)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(provenance);
            if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(outputRoot) ||
                Path.GetFullPath(outputRoot) != outputRoot ||
                provenance.SdkVersion != BetaReleaseRecordV2Codec.SdkVersion ||
                provenance.TargetFramework != BetaReleaseRecordV2Codec.TargetFramework ||
                provenance.RuntimeIdentifier != TrustedManifestV2Codec.Architecture ||
                provenance.Deployment != TrustedManifestV2Codec.Deployment ||
                !IsHash(provenance.SourceLockSha256)) throw new IOException(Invalid);

            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(outputRoot);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(
                Path.GetDirectoryName(outputRoot) ?? throw new IOException(Invalid));
            var recordPath = Path.Combine(outputRoot, BetaReleaseRecordV2Codec.FileName);
            if (Path.Exists(recordPath)) throw new IOException(Invalid);

            var descriptorPath = Path.Combine(outputRoot, BetaReleaseDescriptorCodec.FileName);
            var notesPath = Path.Combine(outputRoot, BetaReleaseLayoutValidator.ReleaseNotesFileName);
            var manifestPath = Path.Combine(outputRoot, ManifestFileName);
            var metadataPath = Path.Combine(outputRoot, MetadataFileName);
            foreach (var path in new[] { descriptorPath, notesPath, manifestPath, metadataPath })
                ServiceReleaseV2FileSystemSecurity.RequireProtectedFile(path);
            var descriptorBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(descriptorPath, 4096);
            var notesBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(notesPath, 1024 * 1024);
            var manifestBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(manifestPath,
                TrustedManifestV2Codec.MaximumBytes);
            var metadataBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(metadataPath,
                ReleaseMetadataCodec.MaximumBytes);
            if (!BetaReleaseDescriptorCodec.TryParse(descriptorBytes, out var descriptor) || descriptor is null ||
                descriptor.SourceCommit != provenance.SourceCommit ||
                descriptor.SdkVersion != provenance.SdkVersion ||
                descriptor.Configuration != "Release" ||
                descriptor.Runtime != provenance.RuntimeIdentifier ||
                descriptor.ReleaseNotesSha256 != Hash(notesBytes) ||
                !TrustedManifestV2Codec.TryParse(manifestBytes, out var manifest, out _) || manifest is null ||
                manifest.Release != descriptor.ReleaseVersion ||
                manifest.ReleaseSequence != descriptor.ReleaseSequence ||
                !_signatures.Verify(manifestBytes, metadataBytes) ||
                !ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out _) || metadata is null ||
                metadata.PublishedAtUtc != descriptor.PublishedAtUtc ||
                metadata.ReleaseSequence != descriptor.ReleaseSequence ||
                metadata.DisplayVersion != descriptor.ReleaseVersion ||
                metadata.ManifestSha256 != Hash(manifestBytes)) throw new IOException(Invalid);

            var serviceRoot = Path.Combine(outputRoot, ServiceReleaseV2ProductionProjector.ServiceDirectoryName);
            var diagnosticsRoot = Path.Combine(outputRoot,
                ServiceReleaseV2ProductionProjector.DiagnosticDirectoryName);
            if (manifest.Files.Any(file => file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)))
                throw new IOException(Invalid);
            _ = ServicePublishDependencyValidator.Validate(serviceRoot, manifest.Files);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedTree(serviceRoot, manifest.Files);
            var diagnostics = DiagnosticNames.Select(name =>
                new TrustedManifestV2File(name, HashSafeFile(Path.Combine(diagnosticsRoot, name)))).ToArray();
            _ = ServiceReleaseV2ProductionProjector.ValidateDiagnosticSymbols(diagnosticsRoot, diagnostics);

            var expected = new List<ServiceReleaseV2BoundFile>
            {
                new(BetaReleaseDescriptorCodec.FileName, Hash(descriptorBytes)),
                new(BetaReleaseLayoutValidator.ReleaseNotesFileName, Hash(notesBytes)),
                new(ManifestFileName, Hash(manifestBytes)),
                new(MetadataFileName, Hash(metadataBytes))
            };
            expected.AddRange(manifest.Files.Select(file =>
                new ServiceReleaseV2BoundFile("service/" + file.Path, file.Sha256)));
            expected.AddRange(diagnostics.Select(file =>
                new ServiceReleaseV2BoundFile("diagnostic-symbols/" + file.Path, file.Sha256)));
            expected.Sort((a, b) => StringComparer.Ordinal.Compare(a.RelativePath, b.RelativePath));

            using var binding = ServiceReleaseV2FinalBinding.Open(outputRoot, expected);
            if (!binding.ReadBounded(ManifestFileName, TrustedManifestV2Codec.MaximumBytes)
                    .AsSpan().SequenceEqual(manifestBytes) ||
                !binding.ReadBounded(MetadataFileName, ReleaseMetadataCodec.MaximumBytes)
                    .AsSpan().SequenceEqual(metadataBytes) ||
                !binding.ReadBounded(BetaReleaseDescriptorCodec.FileName, 4096)
                    .AsSpan().SequenceEqual(descriptorBytes) ||
                !binding.ReadBounded(BetaReleaseLayoutValidator.ReleaseNotesFileName, 1024 * 1024)
                    .AsSpan().SequenceEqual(notesBytes)) throw new IOException(Invalid);

            // Record independently reproduces the unsigned SDK publish. A successful
            // sign-v2 command cannot be inferred merely from a self-consistent layout.
            _sourceBinding.Verify(outputRoot, descriptor, provenance, manifest.Files,
                diagnostics, binding);

            var signed = new List<AuthenticodeReleaseEvidence>(4);
            foreach (var artifact in ServiceReleaseV2PeContract.VantrelOwnedPeArtifacts)
            {
                var relative = artifact.RelativePath;
                var path = Path.Combine(outputRoot, relative.Replace('/', '\\'));
                var before = binding.Hash(relative);
                var evidence = _authenticode.Verify(relative, path, binding.GetHandle(relative));
                if (evidence.RelativePath != relative ||
                    evidence.Category != AuthenticodeVerificationCategory.Valid ||
                    evidence.SignerPolicyId != BetaReleaseRecordV2Codec.SigningPolicyId ||
                    evidence.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne ||
                    evidence.Timestamp != TimestampPolicyCategory.ValidRfc3161 ||
                    binding.Hash(relative) != before)
                    throw new IOException(Invalid);
                signed.Add(evidence);
            }

            binding.Recheck();
            // Reverify the signed metadata against the same retained bytes used to form the
            // record; a signature over a different manifest cannot approve this inventory.
            if (!_signatures.Verify(binding.ReadBounded(ManifestFileName,
                    TrustedManifestV2Codec.MaximumBytes),
                    binding.ReadBounded(MetadataFileName, ReleaseMetadataCodec.MaximumBytes)))
                throw new IOException(Invalid);
            var record = new BetaReleaseRecordV2(descriptor, provenance.SourceLockSha256,
                binding.Hash(ManifestFileName),
                Hash(TrustedManifestV2Codec.CreateCanonicalPayload(descriptor.ReleaseVersion,
                    descriptor.ReleaseSequence, manifest.Files)),
                binding.Hash(MetadataFileName), manifest.Files, signed, diagnostics);
            var canonical = BetaReleaseRecordV2Codec.CreateCanonical(record);
            if (!BetaReleaseRecordV2Codec.TryParse(canonical, out _)) throw new IOException(Invalid);

            var parent = Path.GetDirectoryName(outputRoot)!;
            var temporary = Path.Combine(parent, "." + BetaReleaseRecordV2Codec.FileName + "." +
                Guid.NewGuid().ToString("N") + ".tmp");
            using (var stream = new FileStream(temporary, FileMode.CreateNew,
                FileAccess.Write, FileShare.None))
            {
                stream.Write(canonical);
                stream.Flush(flushToDisk: true);
            }
            ServiceReleaseV2FileSystemSecurity.ProtectFile(temporary);
            if (!ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(temporary,
                    canonical.Length).AsSpan().SequenceEqual(canonical))
                throw new IOException(Invalid);
            binding.Recheck();
            if (Path.Exists(recordPath)) throw new IOException(Invalid);
            // The protected, byte-verified temporary is on the same volume. Make the
            // no-overwrite rename the last fallible operation: a later check throwing
            // after publication would leave a valid-looking record on a failed call.
            File.Move(temporary, recordPath);
            return record;
        }
        catch (TrackedSourceProvenanceException) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or InvalidDataException or CryptographicException or
            NotSupportedException or PlatformNotSupportedException)
        {
            throw new IOException(Invalid);
        }
    }

    private static string HashSafeFile(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        return ServiceReleaseV2FileSystemSecurity.HashProtectedFile(path, 1024L * 1024 * 1024);
    }

    private static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    private static bool IsHash(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
}
