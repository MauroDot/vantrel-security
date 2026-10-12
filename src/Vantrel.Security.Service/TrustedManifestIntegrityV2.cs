using System.ComponentModel;
using System.Collections.Immutable;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public sealed partial class TrustedManifestIntegritySource
{
    private const int MaximumV2FileBytes = 512 * 1024 * 1024;
    private const long MaximumV2TreeBytes = 2L * 1024 * 1024 * 1024;
    private const string ManifestName = "Vantrel.Security.TrustedManifest";
    private const string MetadataName = "Vantrel.Security.ReleaseMetadata";
    internal Func<SafeFileHandle, bool, bool> StreamInspector { get; init; } =
        static (handle, directory) => ComponentInspectionNative.HasOnlyDefaultDataStream(handle, directory);

    private void RequireOnlyDefaultStream(SafeFileHandle handle, bool directory = false)
    {
        if (StreamInspector is null || !StreamInspector(handle, directory))
            throw new IOException("Installed object has an unapproved data stream.");
    }

    private static TrustedManifestCollectionResult V2Result(DateTimeOffset sampled, TrustedManifestSignatureState signature,
        TrustedManifestInstallationEvaluation evaluation, ComponentInspectionReason? reason = null) =>
        new(new(sampled, StatusProtocol.TrustedManifestIntegrityPolicyRevisionV2, signature, evaluation, reason,
            evaluation == TrustedManifestInstallationEvaluation.ComponentMismatch ? TrustedManifestComponent.RuntimeInventory : null), null);

    private async Task<TrustedManifestCollectionResult> CollectV2Async(DateTimeOffset sampled, string root,
        byte[] manifestBytes, TrustedManifestV2 manifest, ProtectedV2File protectedManifest, CancellationToken token)
    {
        var signatureVerified = false;
        try
        {
            if (!VerifyV2Signature(manifest, _manifestPublicKey()))
                return V2Result(sampled, TrustedManifestSignatureState.SignatureInvalid, TrustedManifestInstallationEvaluation.ManifestInvalid);
            signatureVerified = true;
            using var protectedMetadata = await OpenProtectedV2Async(Path.Combine(root, MetadataName), root,
                ReleaseMetadataCodec.MaximumBytes, token);
            var metadataBytes = protectedMetadata.Bytes;
            if (!ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out _) || metadata is null ||
                !TrustedManifestV2Codec.VerifyBoundMetadata(manifestBytes, metadataBytes, _manifestPublicKey(), _metadataPublicKey()))
                return V2Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ManifestInvalid);
            var manifestHash = Convert.ToHexString(SHA256.HashData(manifestBytes));
            var identity = new ReleaseIdentity(ReleaseGeneration.V2, manifest.ReleaseSequence, manifestHash);
            if (!identity.IsValid)
                return V2Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ManifestInvalid);

            var expectedFiles = manifest.Files.ToDictionary(static file => file.Path, StringComparer.Ordinal);
            var expectedDirectories = new HashSet<string>(StringComparer.Ordinal);
            foreach (var file in manifest.Files)
            {
                if (IsNonDeployable(file.Path))
                    return V2Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ManifestInvalid);
                for (var slash = file.Path.IndexOf('/'); slash >= 0; slash = file.Path.IndexOf('/', slash + 1))
                    expectedDirectories.Add(file.Path[..slash]);
            }
            // Retain directory identities across both enumerations and all file reads.
            var heldDirectories = new List<(SafeFileHandle Handle, ComponentInspectionNative.Metadata Before, string FinalPath)>();
            try
            {
                foreach (var directory in new[] { "" }.Concat(expectedDirectories.OrderBy(static value => value, StringComparer.Ordinal)))
                {
                    var path = directory.Length == 0 ? root : Path.Combine(root, directory.Replace('/', Path.DirectorySeparatorChar));
                    var handle = ComponentInspectionNative.OpenProtected(path, directory: true);
                    try
                    {
                        var before = _operations.Metadata(handle);
                        var final = _operations.FinalPath(handle);
                        if (!before.IsDirectory || before.IsReparsePoint ||
                            !string.Equals(Path.GetFullPath(path), Path.GetFullPath(final), StringComparison.OrdinalIgnoreCase))
                            throw new IOException("Installed directory binding failed.");
                        RequireOnlyDefaultStream(handle, directory: true);
                        heldDirectories.Add((handle, before, final));
                    }
                    catch { handle.Dispose(); throw; }
                }
            var first = EnumerateV2Tree(root, expectedFiles.Keys, expectedDirectories);
            if (first is null)
                return V2Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ComponentMismatch);

            // Keep every file handle alive through the second physical inventory and identity recheck.
            var held = new List<(string Path, SafeFileHandle Handle, FileStream Stream, ComponentInspectionNative.Metadata Before, string FinalPath)>();
            try
            {
                long total = 0;
                foreach (var file in manifest.Files)
                {
                    token.ThrowIfCancellationRequested();
                    var path = Path.Combine(root, file.Path.Replace('/', Path.DirectorySeparatorChar));
                    var handle = ComponentInspectionNative.OpenProtected(path);
                    FileStream? stream = null;
                    try
                    {
                        var before = _operations.Metadata(handle);
                        var final = _operations.FinalPath(handle);
                        Validate(before, root, final, MaximumV2FileBytes);
                        RequireOnlyDefaultStream(handle);
                        total = checked(total + before.Length);
                        if (total > MaximumV2TreeBytes) throw new IOException("Installed v2 inventory exceeds bound.");
                        stream = _operations.CreateStream(handle);
                        held.Add((path, handle, stream, before, final));
                        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                        var buffer = new byte[65536]; int read; long bytesRead = 0;
                        while ((read = await stream.ReadAsync(buffer, token)) != 0)
                        {
                            bytesRead = checked(bytesRead + read);
                            if (bytesRead > before.Length || bytesRead > MaximumV2FileBytes)
                                throw new IOException("Installed file changed during bounded read.");
                            hash.AppendData(buffer, 0, read);
                        }
                        if (bytesRead != before.Length)
                            throw new IOException("Installed file length changed during read.");
                        if (_operations.Metadata(handle) != before || _operations.FinalPath(handle) != final)
                            return V2Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ObservationUnavailable,
                                ComponentInspectionReason.ChangedDuringRead);
                        RequireOnlyDefaultStream(handle);
                        if (!string.Equals(Convert.ToHexString(hash.GetHashAndReset()), file.Sha256, StringComparison.Ordinal))
                            return V2Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ComponentMismatch);
                    }
                    catch { if (stream is null) handle.Dispose(); throw; }
                }
                var second = EnumerateV2Tree(root, expectedFiles.Keys, expectedDirectories);
                if (second is null || !first.SequenceEqual(second, StringComparer.Ordinal))
                    return V2Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ComponentMismatch);
                foreach (var entry in held)
                {
                    if (_operations.Metadata(entry.Handle) != entry.Before || _operations.FinalPath(entry.Handle) != entry.FinalPath)
                        return V2Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ObservationUnavailable,
                            ComponentInspectionReason.ChangedDuringRead);
                    RequireOnlyDefaultStream(entry.Handle);
                    using var current = ComponentInspectionNative.OpenProtected(entry.Path);
                    if (_operations.Metadata(current) != entry.Before || _operations.FinalPath(current) != entry.FinalPath)
                        return V2Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ObservationUnavailable,
                            ComponentInspectionReason.ChangedDuringRead);
                }
                if (!protectedManifest.Unchanged(_operations) || !protectedMetadata.Unchanged(_operations) ||
                    heldDirectories.Any(entry => _operations.Metadata(entry.Handle) != entry.Before ||
                        _operations.FinalPath(entry.Handle) != entry.FinalPath))
                    return V2Result(sampled, TrustedManifestSignatureState.Valid,
                        TrustedManifestInstallationEvaluation.ObservationUnavailable, ComponentInspectionReason.ChangedDuringRead);
                RequireOnlyDefaultStream(protectedManifest.Handle);
                RequireOnlyDefaultStream(protectedMetadata.Handle);
                foreach (var directory in heldDirectories) RequireOnlyDefaultStream(directory.Handle, directory: true);
                return new TrustedManifestCollectionResult(
                    new(sampled, StatusProtocol.TrustedManifestIntegrityPolicyRevisionV2, TrustedManifestSignatureState.Valid,
                        TrustedManifestInstallationEvaluation.AllMatch, null, null), manifestHash, identity, metadata,
                    Convert.ToHexString(SHA256.HashData(metadataBytes)), manifest.Files.ToImmutableArray());
            }
            finally
            {
                foreach (var entry in held) { entry.Stream.Dispose(); entry.Handle.Dispose(); }
            }
            }
            finally { foreach (var entry in heldDirectories) entry.Handle.Dispose(); }
        }
        catch (OperationCanceledException) { throw; }
        catch (UnauthorizedAccessException) { return V2Result(sampled, signatureVerified ? TrustedManifestSignatureState.Valid : TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ObservationUnavailable, ComponentInspectionReason.AccessDenied); }
        catch (Win32Exception) { return V2Result(sampled, signatureVerified ? TrustedManifestSignatureState.Valid : TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ObservationUnavailable, ComponentInspectionReason.IoFailure); }
        catch (IOException) { return V2Result(sampled, signatureVerified ? TrustedManifestSignatureState.Valid : TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ObservationUnavailable, ComponentInspectionReason.IoFailure); }
    }

    private async Task<ProtectedV2File> OpenProtectedV2Async(string path, string root, int maximum, CancellationToken token)
    {
        var handle = ComponentInspectionNative.OpenProtected(path);
        FileStream? stream = null;
        try
        {
            var before = _operations.Metadata(handle);
            var final = _operations.FinalPath(handle);
            Validate(before, root, final, maximum);
            if (!string.Equals(Path.GetFullPath(path), Path.GetFullPath(final), StringComparison.OrdinalIgnoreCase))
                throw new IOException("Installed sidecar path binding failed.");
            RequireOnlyDefaultStream(handle);
            stream = _operations.CreateStream(handle);
            using var memory = new MemoryStream();
            var buffer = new byte[65536]; int read;
            while ((read = await stream.ReadAsync(buffer, token)) != 0)
            {
                if (memory.Length + read > maximum) throw new IOException("Installed sidecar exceeds bound.");
                memory.Write(buffer, 0, read);
            }
            if (memory.Length != before.Length || _operations.Metadata(handle) != before || _operations.FinalPath(handle) != final)
                throw new IOException("Installed sidecar changed during read.");
            RequireOnlyDefaultStream(handle);
            return new ProtectedV2File(handle, stream, before, final, memory.ToArray());
        }
        catch { stream?.Dispose(); handle.Dispose(); throw; }
    }

    private sealed class ProtectedV2File(SafeFileHandle handle, FileStream stream,
        ComponentInspectionNative.Metadata before, string finalPath, byte[] bytes) : IDisposable
    {
        internal byte[] Bytes { get; } = bytes;
        internal SafeFileHandle Handle => handle;
        internal bool Unchanged(IComponentInspectionHandleOperations operations) =>
            operations.Metadata(handle) == before && operations.FinalPath(handle) == finalPath;
        public void Dispose() { stream.Dispose(); handle.Dispose(); }
    }

    private static bool IsNonDeployable(string path)
    {
        var leaf = path[(path.LastIndexOf('/') + 1)..];
        return leaf.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase) ||
            leaf.Equals("packages.lock.json", StringComparison.OrdinalIgnoreCase) ||
            leaf.StartsWith("beta-release-record-", StringComparison.OrdinalIgnoreCase) ||
            leaf.StartsWith("beta-release-descriptor-", StringComparison.OrdinalIgnoreCase) ||
            leaf.StartsWith("product-release-record-", StringComparison.OrdinalIgnoreCase) ||
            leaf.Equals("release-notes.md", StringComparison.OrdinalIgnoreCase);
    }

    private static string[]? EnumerateV2Tree(string root, IEnumerable<string> files, HashSet<string> directories)
    {
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) return null;
        var expectedFiles = new HashSet<string>(files, StringComparer.Ordinal);
        expectedFiles.Add(ManifestName);
        expectedFiles.Add(MetadataName);
        var expected = new HashSet<string>(expectedFiles, StringComparer.Ordinal);
        expected.UnionWith(directories);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var observed = new List<string>();
        var pending = new Stack<(string Physical, string Relative)>();
        pending.Push((root, ""));
        while (pending.Count != 0)
        {
            var (physical, prefix) = pending.Pop();
            foreach (var entry in Directory.EnumerateFileSystemEntries(physical))
            {
                var name = Path.GetFileName(entry);
                var relative = prefix.Length == 0 ? name : prefix + "/" + name;
                if (observed.Count >= TrustedManifestV2Codec.MaximumFiles * TrustedManifestV2Codec.MaximumDepth + 2 ||
                    !seen.Add(relative) || !expected.Contains(relative)) return null;
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0) return null;
                if ((attributes & FileAttributes.Device) != 0) return null;
                var isDirectory = (attributes & FileAttributes.Directory) != 0;
                if (isDirectory != directories.Contains(relative)) return null;
                observed.Add(relative);
                if (isDirectory) pending.Push((entry, relative));
            }
        }
        if (observed.Count != expected.Count) return null;
        observed.Sort(StringComparer.Ordinal);
        return observed.ToArray();
    }
}
