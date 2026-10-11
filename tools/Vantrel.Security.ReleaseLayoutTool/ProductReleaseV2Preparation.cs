using System.Runtime.Versioning;
using System.Security.Cryptography;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

internal sealed record ProductPublishInputs(
    string Service, string Desktop, string Tool,
    ProductPublishValidation DesktopValidation, ProductPublishValidation ToolValidation,
    string ServiceLockSha256, string DesktopLockSha256, string ToolLockSha256,
    IReadOnlyDictionary<string, string> ServiceHostResidue);

/// <summary>Reproduces all three products from one clean, pinned, locked checkout.</summary>
[SupportedOSPlatform("windows")]
internal static class ProductReleaseV2BuildInputs
{
    private const string Invalid = "V2 product build inputs are invalid.";

    internal static ProductPublishInputs Publish(string sourceRoot, string outputParent,
        BetaReleaseDescriptor descriptor, ServiceReleaseV2BuildProvenance provenance,
        IReleaseV2CommandRunner runner)
    {
        ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(sourceRoot,
            descriptor.SourceCommit, provenance.SourceLockSha256, runner);
        var scratch = Path.Combine(outputParent, ".product-publish-" + Guid.NewGuid().ToString("N"));
        ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(scratch);
        var service = Path.Combine(scratch, "service");
        var desktop = Path.Combine(scratch, "desktop");
        var tool = Path.Combine(scratch, "tool");
        RunPublish(sourceRoot, "src/Vantrel.Security.Service/Vantrel.Security.Service.csproj",
            service, descriptor, runner);
        RunPublish(sourceRoot, "src/Vantrel.Security.Desktop/Vantrel.Security.Desktop.csproj",
            desktop, descriptor, runner);
        RunPublish(sourceRoot, "tools/Vantrel.Security.OfflineUpdateTool/Vantrel.Security.OfflineUpdateTool.csproj",
            tool, descriptor, runner);
        var serviceValidated = ServicePublishDependencyValidator.ValidateSdkPublish(service,
            provenance.SourceLockSha256);
        var serviceHost = new[] { "Vantrel.Security.Service.exe", "Vantrel.Security.Service.deps.json",
            "Vantrel.Security.Service.runtimeconfig.json" }.ToDictionary(name => name,
            name => serviceValidated.DeployableFiles.Single(file => file.Path == name).Sha256,
            StringComparer.Ordinal);
        var desktopLock = SourceLock(sourceRoot, "src/Vantrel.Security.Desktop/packages.lock.json");
        var toolLock = SourceLock(sourceRoot, "tools/Vantrel.Security.OfflineUpdateTool/packages.lock.json");
        var desktopValidated = ProductPublishDependencyValidator.ValidateSdkPublish(desktop,
            ProductPublishKind.Desktop, desktopLock);
        var toolValidated = ProductPublishDependencyValidator.ValidateSdkPublish(tool,
            ProductPublishKind.OfflineUpdateTool, provenance.SourceLockSha256, serviceHost);
        ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(sourceRoot,
            descriptor.SourceCommit, provenance.SourceLockSha256, runner);
        if (desktopLock != SourceLock(sourceRoot, "src/Vantrel.Security.Desktop/packages.lock.json") ||
            toolLock != SourceLock(sourceRoot, "tools/Vantrel.Security.OfflineUpdateTool/packages.lock.json"))
            throw new IOException(Invalid);
        return new(service, desktop, tool, desktopValidated, toolValidated,
            provenance.SourceLockSha256, desktopLock, toolLock, serviceHost);
    }

    private static void RunPublish(string sourceRoot, string projectRelative, string destination,
        BetaReleaseDescriptor descriptor, IReleaseV2CommandRunner runner)
    {
        var project = Path.Combine(sourceRoot, projectRelative.Replace('/', Path.DirectorySeparatorChar));
        var result = runner.Run("dotnet", ["publish", project, "--configuration", "Release",
            "--runtime", "win-x64", "--self-contained", "false", "--no-restore",
            "--output", destination, "-p:VantrelReleaseVersion=" + descriptor.ReleaseVersion,
            "-p:VantrelSourceCommit=" + descriptor.SourceCommit], sourceRoot, false);
        if (result.ExitCode != 0 || result.StandardOutput.Length != 0) throw new IOException(Invalid);
    }

    private static string SourceLock(string root, string relative)
    {
        var path = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new IOException(Invalid);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}

/// <summary>Copies only validated runtime files into a new product layout; signing is separate.</summary>
[SupportedOSPlatform("windows")]
internal static class ProductReleaseV2Projector
{
    private const string Invalid = "V2 product projection failed.";

    internal static void Project(string serviceReleaseRoot, string destinationRoot,
        ProductPublishInputs source, IServiceReleaseV2SignatureGate? signatures = null)
    {
        if (Path.Exists(destinationRoot) ||
            !Path.IsPathFullyQualified(destinationRoot) ||
            Path.GetFullPath(destinationRoot) != destinationRoot)
            throw new IOException(Invalid);
        var parent = Path.GetDirectoryName(destinationRoot) ?? throw new IOException(Invalid);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(parent);
        var recordBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(
            Path.Combine(serviceReleaseRoot, BetaReleaseRecordV2Codec.FileName), 512 * 1024);
        if (!BetaReleaseRecordV2Codec.TryParse(recordBytes, out var record) || record is null)
            throw new IOException(Invalid);
        var serviceExpected = ServiceFiles(serviceReleaseRoot, record, recordBytes);
        using var retainedService = ServiceReleaseV2FinalBinding.Open(serviceReleaseRoot, serviceExpected);
        var manifestBytes = retainedService.ReadBounded(ServiceReleaseV2RecordGate.ManifestFileName,
            TrustedManifestV2Codec.MaximumBytes);
        var metadataBytes = retainedService.ReadBounded(ServiceReleaseV2RecordGate.MetadataFileName,
            ReleaseMetadataCodec.MaximumBytes);
        if (!(signatures ?? new ProductionServiceReleaseV2SignatureGate()).Verify(
                manifestBytes, metadataBytes) ||
            !TrustedManifestV2Codec.TryParse(manifestBytes, out var manifest, out _) ||
            manifest is null || manifest.Release != record.Descriptor.ReleaseVersion ||
            manifest.ReleaseSequence != record.Descriptor.ReleaseSequence ||
            !manifest.Files.SequenceEqual(record.ServiceFiles) ||
            !ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out _) ||
            metadata is null || metadata.DisplayVersion != record.Descriptor.ReleaseVersion ||
            metadata.ReleaseSequence != record.Descriptor.ReleaseSequence ||
            metadata.PublishedAtUtc != record.Descriptor.PublishedAtUtc ||
            !ServicePublishDependencyValidator.Validate(Path.Combine(serviceReleaseRoot, "service"),
                record.ServiceFiles).SequenceEqual(record.ServiceFiles)) throw new IOException(Invalid);

        ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(destinationRoot);
        foreach (var directory in new[] { "service", "desktop", "offline-update-tool",
            "diagnostic-symbols" })
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(
                Path.Combine(destinationRoot, directory));
        var copied = new List<ServiceReleaseV2BoundFile>();
        foreach (var file in serviceExpected)
        {
            Copy(retainedService.GetHandle(file.RelativePath), destinationRoot, file);
            copied.Add(file);
        }
        CopyGroup(source.Desktop, source.DesktopValidation.Files, destinationRoot,
            "desktop", copied);
        CopyGroup(source.Tool, source.ToolValidation.Files, destinationRoot,
            "offline-update-tool", copied);
        CopySymbols(source.Desktop, source.DesktopValidation.DiagnosticSymbols, destinationRoot,
            "desktop", copied);
        CopySymbols(source.Tool, source.ToolValidation.DiagnosticSymbols, destinationRoot,
            "offline-update-tool", copied);
        retainedService.Recheck();
        _ = ProductPublishDependencyValidator.ValidateSdkPublish(source.Desktop,
            ProductPublishKind.Desktop, source.DesktopLockSha256);
        // The tool's excluded Service-host files were validated against the independently
        // reproduced Service publish by ProductReleaseV2BuildInputs.Publish.
        _ = ProductPublishDependencyValidator.ValidateSdkPublish(source.Tool,
            ProductPublishKind.OfflineUpdateTool, source.ServiceLockSha256,
            source.ServiceHostResidue);
        using var final = ServiceReleaseV2FinalBinding.Open(destinationRoot,
            copied.OrderBy(file => file.RelativePath, StringComparer.Ordinal).ToArray());
        final.Recheck();
        ProductPublishDependencyValidator.ValidateProjected(Path.Combine(destinationRoot, "desktop"),
            ProductPublishKind.Desktop, source.DesktopValidation.Files);
        ProductPublishDependencyValidator.ValidateProjected(Path.Combine(destinationRoot, "offline-update-tool"),
            ProductPublishKind.OfflineUpdateTool, source.ToolValidation.Files);
    }

    internal static ServiceReleaseV2BoundFile[] ServiceFiles(string serviceReleaseRoot,
        BetaReleaseRecordV2 record,
        byte[] recordBytes)
    {
        var files = new List<ServiceReleaseV2BoundFile>
        {
            new(BetaReleaseDescriptorCodec.FileName,
                ServiceReleaseV2FileSystemSecurity.HashProtectedFile(
                    Path.Combine(serviceReleaseRoot, BetaReleaseDescriptorCodec.FileName), 4096)),
            new(BetaReleaseLayoutValidator.ReleaseNotesFileName,
                record.Descriptor.ReleaseNotesSha256),
            new(ServiceReleaseV2RecordGate.ManifestFileName, record.SignedManifestSha256),
            new(ServiceReleaseV2RecordGate.MetadataFileName, record.SignedMetadataSha256),
            new(BetaReleaseRecordV2Codec.FileName,
                Convert.ToHexString(SHA256.HashData(recordBytes)))
        };
        files.AddRange(record.ServiceFiles.Select(file =>
            new ServiceReleaseV2BoundFile("service/" + file.Path, file.Sha256)));
        files.AddRange(record.DiagnosticSymbols.Select(file =>
            new ServiceReleaseV2BoundFile("diagnostic-symbols/" + file.Path, file.Sha256)));
        return files.OrderBy(file => file.RelativePath, StringComparer.Ordinal).ToArray();
    }

    private static void CopyGroup(string sourceRoot, IReadOnlyList<TrustedManifestV2File> files,
        string destinationRoot, string destinationGroup, List<ServiceReleaseV2BoundFile> copied)
    {
        foreach (var file in files)
        {
            var target = destinationGroup + "/" + file.Path;
            var destination = MakeDestination(destinationRoot, target);
            ServicePublishFileSnapshot.CopyValidatedFile(sourceRoot, file, destination);
            ServiceReleaseV2FileSystemSecurity.ProtectFile(destination);
            copied.Add(new(target, file.Sha256));
        }
    }

    private static void CopySymbols(string sourceRoot, IReadOnlyList<TrustedManifestV2File> symbols,
        string destinationRoot, string group, List<ServiceReleaseV2BoundFile> copied)
    {
        foreach (var file in symbols)
        {
            var target = "diagnostic-symbols/" + group + "/" + file.Path;
            var destination = MakeDestination(destinationRoot, target);
            ServicePublishFileSnapshot.CopyValidatedFile(sourceRoot, file, destination);
            ServiceReleaseV2FileSystemSecurity.ProtectFile(destination);
            copied.Add(new(target, file.Sha256));
        }
    }

    private static void Copy(Microsoft.Win32.SafeHandles.SafeFileHandle source,
        string root, ServiceReleaseV2BoundFile file)
    {
        var destination = MakeDestination(root, file.RelativePath);
        using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write,
                   FileShare.None, 65536, FileOptions.WriteThrough))
        {
            var buffer = new byte[65536];
            var length = RandomAccess.GetLength(source);
            long offset = 0;
            while (offset < length)
            {
                var read = RandomAccess.Read(source, buffer, offset);
                if (read <= 0) throw new IOException(Invalid);
                output.Write(buffer, 0, read);
                offset += read;
            }
            output.Flush(flushToDisk: true);
        }
        ServiceReleaseV2FileSystemSecurity.ProtectFile(destination);
        if (ServiceReleaseV2FileSystemSecurity.HashProtectedFile(destination,
                1024L * 1024 * 1024) != file.Sha256)
            throw new IOException(Invalid);
    }

    private static string MakeDestination(string root, string relative)
    {
        var parts = relative.Split('/');
        var parent = root;
        for (var i = 0; i < parts.Length - 1; i++)
        {
            parent = Path.Combine(parent, parts[i]);
            if (!Directory.Exists(parent))
                ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(parent);
            else ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(parent);
        }
        var destination = Path.Combine(parent, parts[^1]);
        if (Path.Exists(destination)) throw new IOException(Invalid);
        return destination;
    }
}
