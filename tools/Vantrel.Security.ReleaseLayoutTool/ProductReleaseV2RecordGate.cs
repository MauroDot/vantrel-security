using System.Runtime.Versioning;
using System.Security.Cryptography;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

internal sealed record ProductReleaseV2SourceEvidence(string DesktopLockSha256,
    string ToolLockSha256, IReadOnlyList<TrustedManifestV2File> DiagnosticSymbols,
    IReadOnlyList<TrustedManifestV2File> ExcludedBuildArtifacts);

internal interface IProductReleaseV2SourceGate
{
    ProductReleaseV2SourceEvidence Verify(string outputRoot, BetaReleaseRecordV2 serviceRecord,
        IReadOnlyList<TrustedManifestV2File> desktopFiles,
        IReadOnlyList<TrustedManifestV2File> toolFiles,
        IReadOnlyList<TrustedManifestV2File> diagnostics,
        ServiceReleaseV2FinalBinding binding);
}

[SupportedOSPlatform("windows")]
internal sealed class ProductionProductReleaseV2SourceGate(string sourceRoot,
    ServiceReleaseV2BuildProvenance provenance, IReleaseV2CommandRunner runner)
    : IProductReleaseV2SourceGate
{
    private const string Invalid = "V2 product source binding failed.";

    public ProductReleaseV2SourceEvidence Verify(string outputRoot, BetaReleaseRecordV2 record,
        IReadOnlyList<TrustedManifestV2File> desktopFiles,
        IReadOnlyList<TrustedManifestV2File> toolFiles,
        IReadOnlyList<TrustedManifestV2File> diagnostics,
        ServiceReleaseV2FinalBinding binding)
    {
        try
        {
            var source = ProductReleaseV2BuildInputs.Publish(sourceRoot,
                Path.GetDirectoryName(outputRoot)!, record.Descriptor, provenance, runner);
            CheckGroup(source.Desktop, source.DesktopValidation, desktopFiles, "desktop", binding);
            CheckGroup(source.Tool, source.ToolValidation, toolFiles, "offline-update-tool", binding);
            var expectedDiagnostics = source.DesktopValidation.DiagnosticSymbols.Select(file =>
                    new TrustedManifestV2File("diagnostic-symbols/desktop/" + file.Path, file.Sha256))
                .Concat(source.ToolValidation.DiagnosticSymbols.Select(file =>
                    new TrustedManifestV2File("diagnostic-symbols/offline-update-tool/" + file.Path,
                        file.Sha256)))
                .Concat(record.DiagnosticSymbols.Select(file =>
                    new TrustedManifestV2File("diagnostic-symbols/" + file.Path, file.Sha256)))
                .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
            if (!expectedDiagnostics.SequenceEqual(diagnostics)) throw new IOException(Invalid);
            var residue = source.DesktopValidation.ExcludedBuildArtifacts.Select(file =>
                    new TrustedManifestV2File("publish/desktop/" + file.RelativePath, file.Sha256))
                .Concat(source.ToolValidation.ExcludedBuildArtifacts.Select(file =>
                    new TrustedManifestV2File("publish/offline-update-tool/" + file.RelativePath,
                        file.Sha256)))
                .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
            binding.Recheck();
            ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(sourceRoot,
                record.Descriptor.SourceCommit, provenance.SourceLockSha256, runner);
            return new(source.DesktopLockSha256, source.ToolLockSha256,
                expectedDiagnostics, residue);
        }
        catch (TrackedSourceProvenanceException) { throw; }
        catch (Exception exception) when (exception is IOException or InvalidDataException or
            ArgumentException or UnauthorizedAccessException or CryptographicException)
        { throw new IOException(Invalid); }
    }

    private static void CheckGroup(string sourceRoot, ProductPublishValidation source,
        IReadOnlyList<TrustedManifestV2File> finalFiles, string group,
        ServiceReleaseV2FinalBinding binding)
    {
        if (source.Files.Count != finalFiles.Count ||
            !source.Files.Select(file => file.Path).SequenceEqual(finalFiles.Select(file => file.Path)))
            throw new IOException(Invalid);
        var signed = ReleaseSigningContract.VantrelOwnedPeArtifacts.Skip(4)
            .Select(item => item.RelativePath).ToHashSet(StringComparer.Ordinal);
        foreach (var (original, final) in source.Files.Zip(finalFiles))
        {
            var path = group + "/" + original.Path;
            if (signed.Contains(path))
            {
                var sourcePath = Path.Combine(sourceRoot,
                    original.Path.Replace('/', Path.DirectorySeparatorChar));
                using var stream = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
                    FileShare.Read);
                if (stream.Length < 1 || stream.Length > 1024L * 1024 * 1024)
                    throw new IOException(Invalid);
                var bytes = new byte[checked((int)stream.Length)];
                stream.ReadExactly(bytes);
                if (Convert.ToHexString(SHA256.HashData(bytes)) != original.Sha256)
                    throw new IOException(Invalid);
                ServiceReleaseV2PeByteEquivalence.RequireAuthenticodeOnlyChange(bytes,
                    binding.ReadBounded(path, 1024 * 1024 * 1024));
            }
            else if (original.Sha256 != final.Sha256) throw new IOException(Invalid);
        }
        if (!source.DiagnosticSymbols.All(file =>
                binding.Hash("diagnostic-symbols/" + group + "/" + file.Path) == file.Sha256))
            throw new IOException(Invalid);
    }
}

/// <summary>Separately approves a complete product after the Service-only record exists.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ProductReleaseV2RecordGate(
    IServiceReleaseV2SourceBinding serviceSource,
    IProductReleaseV2SourceGate productSource,
    IServiceReleaseV2SignatureGate? signatures = null,
    IServiceReleaseV2AuthenticodeGate? authenticode = null)
{
    private const string Invalid = "V2 product release approval failed.";
    private readonly IServiceReleaseV2SignatureGate _signatures =
        signatures ?? new ProductionServiceReleaseV2SignatureGate();
    private readonly IServiceReleaseV2AuthenticodeGate _authenticode =
        authenticode ?? new ProductionServiceReleaseV2AuthenticodeGate();

    internal ProductReleaseRecordV2 ValidateAndWriteRecord(string root,
        ServiceReleaseV2BuildProvenance provenance)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(root) ||
                Path.GetFullPath(root) != root ||
                provenance.SdkVersion != BetaReleaseRecordV2Codec.SdkVersion ||
                provenance.TargetFramework != BetaReleaseRecordV2Codec.TargetFramework ||
                provenance.RuntimeIdentifier != TrustedManifestV2Codec.Architecture ||
                provenance.Deployment != TrustedManifestV2Codec.Deployment)
                throw new IOException(Invalid);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(root);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(
                Path.GetDirectoryName(root) ?? throw new IOException(Invalid));
            var finalPath = Path.Combine(root, ProductReleaseRecordV2Codec.FileName);
            if (Path.Exists(finalPath)) throw new IOException(Invalid);
            var serviceRecordBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(
                Path.Combine(root, BetaReleaseRecordV2Codec.FileName), 512 * 1024);
            if (!BetaReleaseRecordV2Codec.TryParse(serviceRecordBytes, out var serviceRecord) ||
                serviceRecord is null || serviceRecord.Descriptor.SourceCommit != provenance.SourceCommit ||
                serviceRecord.SourceLockSha256 != provenance.SourceLockSha256)
                throw new IOException(Invalid);
            var serviceExpected = ProductReleaseV2Projector.ServiceFiles(root, serviceRecord,
                serviceRecordBytes);
            var desktop = ProductPublishDependencyValidator.ValidateProjected(
                Path.Combine(root, "desktop"), ProductPublishKind.Desktop,
                ServicePublishFileSnapshot.Capture(Path.Combine(root, "desktop"),
                    "Vantrel.Security.Desktop.deps.json",
                    "Vantrel.Security.Desktop.runtimeconfig.json").Files);
            var tool = ProductPublishDependencyValidator.ValidateProjected(
                Path.Combine(root, "offline-update-tool"), ProductPublishKind.OfflineUpdateTool,
                ServicePublishFileSnapshot.Capture(Path.Combine(root, "offline-update-tool"),
                    "Vantrel.Security.OfflineUpdateTool.deps.json",
                    "Vantrel.Security.OfflineUpdateTool.runtimeconfig.json").Files);
            var diagnostics = CaptureDiagnostics(root, serviceRecord);
            var expected = serviceExpected
                .Concat(desktop.Files.Select(file => new ServiceReleaseV2BoundFile(
                    "desktop/" + file.Path, file.Sha256)))
                .Concat(tool.Files.Select(file => new ServiceReleaseV2BoundFile(
                    "offline-update-tool/" + file.Path, file.Sha256)))
                .Concat(diagnostics.Where(file =>
                    !serviceRecord.DiagnosticSymbols.Any(service =>
                        file.Path == "diagnostic-symbols/" + service.Path))
                    .Select(file => new ServiceReleaseV2BoundFile(file.Path, file.Sha256)))
                .OrderBy(file => file.RelativePath, StringComparer.Ordinal).ToArray();
            using var binding = ServiceReleaseV2FinalBinding.Open(root, expected);
            var descriptorBytes = binding.ReadBounded(BetaReleaseDescriptorCodec.FileName, 4096);
            var notesBytes = binding.ReadBounded(BetaReleaseLayoutValidator.ReleaseNotesFileName, 1024 * 1024);
            var manifestBytes = binding.ReadBounded(ServiceReleaseV2RecordGate.ManifestFileName,
                TrustedManifestV2Codec.MaximumBytes);
            var metadataBytes = binding.ReadBounded(ServiceReleaseV2RecordGate.MetadataFileName,
                ReleaseMetadataCodec.MaximumBytes);
            if (!BetaReleaseDescriptorCodec.TryParse(descriptorBytes, out var descriptor) ||
                descriptor != serviceRecord.Descriptor ||
                descriptor.ReleaseNotesSha256 != Convert.ToHexString(SHA256.HashData(notesBytes)) ||
                !_signatures.Verify(manifestBytes, metadataBytes) ||
                !TrustedManifestV2Codec.TryParse(manifestBytes, out var manifest, out _) ||
                manifest is null || manifest.Release != descriptor.ReleaseVersion ||
                manifest.ReleaseSequence != descriptor.ReleaseSequence ||
                !manifest.Files.SequenceEqual(serviceRecord.ServiceFiles) ||
                binding.Hash(ServiceReleaseV2RecordGate.ManifestFileName) !=
                    serviceRecord.SignedManifestSha256 ||
                binding.Hash(ServiceReleaseV2RecordGate.MetadataFileName) !=
                    serviceRecord.SignedMetadataSha256 ||
                Convert.ToHexString(SHA256.HashData(TrustedManifestV2Codec.CreateCanonicalPayload(
                    descriptor.ReleaseVersion, descriptor.ReleaseSequence, manifest.Files))) !=
                    serviceRecord.ManifestPayloadSha256 ||
                !ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out _) ||
                metadata is null || metadata.PublishedAtUtc != descriptor.PublishedAtUtc ||
                metadata.ReleaseSequence != descriptor.ReleaseSequence ||
                metadata.DisplayVersion != descriptor.ReleaseVersion ||
                metadata.ManifestSha256 != serviceRecord.SignedManifestSha256)
                throw new IOException(Invalid);
            _ = ServicePublishDependencyValidator.Validate(Path.Combine(root, "service"),
                serviceRecord.ServiceFiles);
            serviceSource.Verify(root, descriptor, provenance, serviceRecord.ServiceFiles,
                serviceRecord.DiagnosticSymbols, binding);
            VerifyOwned(ServiceReleaseV2PeContract.VantrelOwnedPeArtifacts, binding, root);
            var source = productSource.Verify(root, serviceRecord, desktop.Files, tool.Files,
                diagnostics, binding);
            var evidence = VerifyOwned(ReleaseSigningContract.VantrelOwnedPeArtifacts.Skip(4),
                binding, root);
            binding.Recheck();
            if (!_signatures.Verify(binding.ReadBounded(ServiceReleaseV2RecordGate.ManifestFileName,
                    TrustedManifestV2Codec.MaximumBytes),
                    binding.ReadBounded(ServiceReleaseV2RecordGate.MetadataFileName,
                        ReleaseMetadataCodec.MaximumBytes))) throw new IOException(Invalid);
            var record = new ProductReleaseRecordV2(descriptor,
                Convert.ToHexString(SHA256.HashData(serviceRecordBytes)),
                serviceRecord.SignedManifestSha256, serviceRecord.SignedMetadataSha256,
                source.DesktopLockSha256, source.ToolLockSha256,
                serviceRecord.ServiceFiles, desktop.Files, tool.Files,
                diagnostics, source.ExcludedBuildArtifacts, evidence);
            var canonical = ProductReleaseRecordV2Codec.CreateCanonical(record);
            if (!ProductReleaseRecordV2Codec.TryParse(canonical, out _)) throw new IOException(Invalid);
            var temporary = Path.Combine(Path.GetDirectoryName(root)!, "." +
                ProductReleaseRecordV2Codec.FileName + "." + Guid.NewGuid().ToString("N") + ".tmp");
            using (var output = new FileStream(temporary, FileMode.CreateNew,
                       FileAccess.Write, FileShare.None))
            {
                output.Write(canonical);
                output.Flush(flushToDisk: true);
            }
            ServiceReleaseV2FileSystemSecurity.ProtectFile(temporary);
            if (!ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(temporary,
                    canonical.Length).AsSpan().SequenceEqual(canonical)) throw new IOException(Invalid);
            binding.Recheck();
            if (Path.Exists(finalPath)) throw new IOException(Invalid);
            File.Move(temporary, finalPath);
            return record;
        }
        catch (TrackedSourceProvenanceException) { throw; }
        catch (Exception exception) when (exception is IOException or InvalidDataException or
            ArgumentException or UnauthorizedAccessException or CryptographicException or
            NotSupportedException)
        { throw new IOException(Invalid); }
    }

    private IReadOnlyList<AuthenticodeReleaseEvidence> VerifyOwned(
        IEnumerable<ReleaseSigningArtifact> artifacts, ServiceReleaseV2FinalBinding binding,
        string root)
    {
        var result = new List<AuthenticodeReleaseEvidence>();
        foreach (var artifact in artifacts)
        {
            var relative = artifact.RelativePath;
            var before = binding.Hash(relative);
            var evidence = _authenticode.Verify(relative,
                Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)),
                binding.GetHandle(relative));
            if (evidence.RelativePath != relative ||
                evidence.Category != AuthenticodeVerificationCategory.Valid ||
                evidence.SignerPolicyId != BetaReleaseRecordV2Codec.SigningPolicyId ||
                evidence.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne ||
                evidence.Timestamp != TimestampPolicyCategory.ValidRfc3161 ||
                binding.Hash(relative) != before) throw new IOException(Invalid);
            result.Add(evidence);
        }
        return result;
    }

    private static IReadOnlyList<TrustedManifestV2File> CaptureDiagnostics(string root,
        BetaReleaseRecordV2 record)
    {
        var directory = Path.Combine(root, "diagnostic-symbols");
        ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(directory);
        var expected = record.DiagnosticSymbols.Select(file =>
                new TrustedManifestV2File("diagnostic-symbols/" + file.Path, file.Sha256))
            .ToList();
        foreach (var (group, names) in new[]
        {
            ("desktop", new[] { "Vantrel.Security.Core.pdb", "Vantrel.Security.Desktop.pdb",
                "Vantrel.Security.Infrastructure.pdb" }),
            ("offline-update-tool", new[] { "Vantrel.Security.Core.pdb",
                "Vantrel.Security.Infrastructure.pdb", "Vantrel.Security.OfflineUpdateTool.pdb",
                "Vantrel.Security.Service.pdb" })
        })
        {
            var child = Path.Combine(directory, group);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(child);
            foreach (var name in names)
                expected.Add(new("diagnostic-symbols/" + group + "/" + name,
                    ServiceReleaseV2FileSystemSecurity.HashProtectedFile(Path.Combine(child, name),
                        1024L * 1024 * 1024)));
        }
        return expected.OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
    }
}
