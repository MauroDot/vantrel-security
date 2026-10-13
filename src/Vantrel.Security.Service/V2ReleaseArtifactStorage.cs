using System.Collections.Immutable;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

internal enum V2ArtifactRole { PrivateCandidate, PredecessorBackup }

/// <summary>An internal fault seam. It is not exposed by either production constructor or an update entry point.</summary>
internal sealed record V2ArtifactCopyCheckpoint(string Stage, int FileIndex, string? RelativePath);

/// <summary>
/// Evidence for one completed physical copy, not transferable authorization for an update. A
/// future transaction must independently authenticate the artifact again before using it.
/// </summary>
internal sealed record V2ArtifactCopyEvidence(ReleaseIdentity Identity,
    ImmutableArray<TrustedManifestV2File> RuntimeInventory, V2ArtifactRole Role, string ArtifactId);

/// <summary>
/// Isolated V2 artifact copy/retirement. It has no production transaction caller and never
/// writes a journal, policy, installed Service tree, or V1 storage. Production roots are fixed;
/// the root/key/ACL/fault injection constructor exists only for disposable tests.
/// </summary>
internal sealed class V2ReleaseArtifactStorage
{
    private const string ManifestName = "Vantrel.Security.TrustedManifest";
    private const string MetadataName = "Vantrel.Security.ReleaseMetadata";
    private const long MaximumFileBytes = 512L * 1024 * 1024;
    private const long MaximumTreeBytes = 2L * 1024 * 1024 * 1024;
    private const int BufferBytes = 65536;
    private readonly GenerationAwareOfflineReleaseVerifier _verifier;
    private readonly string _artifactRoot;
    private readonly string _transactionsRoot;
    private readonly string _backupsRoot;
    private readonly string _stagedRoot;
    private readonly string _installedRoot;
    private readonly bool _enforceAcls;
    private readonly Action<V2ArtifactCopyCheckpoint>? _fault;

    internal V2ReleaseArtifactStorage() : this(new GenerationAwareOfflineReleaseVerifier(),
        Path.Combine(FixedUpdatePaths.UpdatesRoot, "V2Artifacts"),
        Path.Combine(FixedUpdatePaths.UpdatesRoot, "StagedV2", "candidate"),
        FixedUpdatePaths.InstalledServiceRoot, enforceAcls: true, fault: null, production: true) { }

    internal V2ReleaseArtifactStorage(GenerationAwareOfflineReleaseVerifier verifier, string artifactRoot,
        string stagedRoot, string installedRoot, bool enforceAcls,
        Action<V2ArtifactCopyCheckpoint>? fault = null)
        : this(verifier, artifactRoot, stagedRoot, installedRoot, enforceAcls, fault, production: false) { }

    private V2ReleaseArtifactStorage(GenerationAwareOfflineReleaseVerifier verifier, string artifactRoot,
        string stagedRoot, string installedRoot, bool enforceAcls,
        Action<V2ArtifactCopyCheckpoint>? fault, bool production)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("V2 artifact storage requires Windows.");
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _artifactRoot = CanonicalRoot(artifactRoot);
        _stagedRoot = CanonicalRoot(stagedRoot);
        _installedRoot = CanonicalRoot(installedRoot);
        if (production)
        {
            if (!enforceAcls || !Same(_artifactRoot, Path.Combine(FixedUpdatePaths.UpdatesRoot, "V2Artifacts")) ||
                !Same(_stagedRoot, Path.Combine(FixedUpdatePaths.UpdatesRoot, "StagedV2", "candidate")) ||
                !Same(_installedRoot, FixedUpdatePaths.InstalledServiceRoot))
                throw new IOException("Fixed V2 artifact storage roots rejected.");
        }
        else if (Overlaps(_artifactRoot, FixedUpdatePaths.VantrelRoot) ||
                 Overlaps(_artifactRoot, FixedUpdatePaths.InstalledServiceRoot) ||
                 Overlaps(_stagedRoot, FixedUpdatePaths.VantrelRoot) ||
                 Overlaps(_stagedRoot, FixedUpdatePaths.InstalledServiceRoot) ||
                 Overlaps(_installedRoot, FixedUpdatePaths.VantrelRoot) ||
                 Overlaps(_installedRoot, FixedUpdatePaths.InstalledServiceRoot))
            throw new IOException("Disposable V2 artifact roots overlap production storage.");
        if (Overlaps(_artifactRoot, _stagedRoot) || Overlaps(_artifactRoot, _installedRoot) ||
            Overlaps(_stagedRoot, _installedRoot))
            throw new IOException("V2 artifact source and destination roots overlap.");
        _transactionsRoot = Path.Combine(_artifactRoot, "Transactions");
        _backupsRoot = Path.Combine(_artifactRoot, "Backups");
        _enforceAcls = enforceAcls;
        _fault = fault;
    }

    internal string GetPrivateCandidatePath(string transactionId) =>
        Path.Combine(_transactionsRoot, RequireId(transactionId), "candidate");

    internal string GetPredecessorBackupPath(string backupId) =>
        Path.Combine(_backupsRoot, RequireId(backupId));

    internal Task<V2ArtifactCopyEvidence> CopyPrivateCandidateAsync(string transactionId,
        ReleaseIdentity expected, CancellationToken token) =>
        CopyAsync(_stagedRoot, GetPrivateCandidatePath(transactionId), transactionId,
            expected, V2ArtifactRole.PrivateCandidate, token);

    internal Task<V2ArtifactCopyEvidence> CopyPredecessorBackupAsync(string backupId,
        ReleaseIdentity expected, CancellationToken token) =>
        CopyAsync(_installedRoot, GetPredecessorBackupPath(backupId), backupId,
            expected, V2ArtifactRole.PredecessorBackup, token);

    internal Task RetirePrivateCandidateAsync(string transactionId, ReleaseIdentity expected,
        CancellationToken token) => RetireAsync(GetPrivateCandidatePath(transactionId), expected,
            V2ArtifactRole.PrivateCandidate, token);

    internal Task RetirePredecessorBackupAsync(string backupId, ReleaseIdentity expected,
        CancellationToken token) => RetireAsync(GetPredecessorBackupPath(backupId), expected,
            V2ArtifactRole.PredecessorBackup, token);

    private async Task<V2ArtifactCopyEvidence> CopyAsync(string source, string destination, string id,
        ReleaseIdentity expected, V2ArtifactRole role, CancellationToken token)
    {
        RequireExpectedIdentity(expected);
        token.ThrowIfCancellationRequested();
        // Only this fresh, complete V2 authentication supplies the copy inventory.
        var authenticated = await AuthenticateAsync(source, expected, token);
        var inventory = authenticated.RuntimeInventory;
        RequireCanonicalInventory(inventory, expected);
        var directories = ImpliedDirectories(inventory);
        using var sourceBindings = new HeldBindings();
        BindSourceDirectories(source, directories, sourceBindings);
        using var infrastructure = BindInfrastructure(role);
        var branchRoot = role == V2ArtifactRole.PrivateCandidate ? _transactionsRoot : _backupsRoot;
        // There is no production journal coordinator yet to authorize a sibling artifact.
        // A new copy therefore requires an otherwise empty role root.
        if (Directory.EnumerateFileSystemEntries(branchRoot).Any())
            throw new IOException("V2 artifact role root contains an unexpected sibling.");
        var destinationParent = role == V2ArtifactRole.PrivateCandidate
            ? Path.Combine(_transactionsRoot, id) : _backupsRoot;
        var transactionParent = role == V2ArtifactRole.PrivateCandidate;
        RequireAbsent(transactionParent ? destinationParent : destination);
        Checkpoint("BeforeRoot", -1, null);
        if (transactionParent)
        {
            infrastructure.Add(destinationParent, CreateAndBindDirectory(destinationParent));
        }
        // A failure after this point leaves the exact occupied residue. There is deliberately no
        // automatic recursive or pathname-based partial cleanup; a retry cannot merge into it.
        using var destinationBindings = new HeldBindings();
        destinationBindings.Add(destination, CreateAndBindDirectory(destination));
        Checkpoint("AfterRoot", -1, null);
        foreach (var relative in directories)
        {
            token.ThrowIfCancellationRequested();
            Checkpoint("BeforeDirectory", -1, relative);
            var path = ResolveContained(destination, relative);
            destinationBindings.Add(path, CreateAndBindDirectory(path));
        }
        long total = 0;
        for (var index = 0; index < inventory.Length; index++)
        {
            token.ThrowIfCancellationRequested();
            var file = inventory[index];
            Checkpoint("BeforeFile", index, file.Path);
            total = checked(total + await CopyOneAsync(source, destination, file.Path, file.Sha256,
                MaximumFileBytes, destinationBindings, token));
            if (total > MaximumTreeBytes) throw new IOException("V2 artifact runtime inventory exceeds its bound.");
            Checkpoint("AfterFile", index, file.Path);
        }
        Checkpoint("BeforeSidecars", -1, null);
        await CopyOneAsync(source, destination, ManifestName, null,
            TrustedManifestV2Codec.MaximumBytes, destinationBindings, token);
        await CopyOneAsync(source, destination, MetadataName, null,
            ReleaseMetadataCodec.MaximumBytes, destinationBindings, token);
        Checkpoint("AfterSidecars", -1, null);
        Checkpoint("BeforeFinalVerification", -1, null);
        var copied = await AuthenticateAsync(destination, expected, token);
        if (!inventory.SequenceEqual(copied.RuntimeInventory))
            throw new IOException("V2 artifact authenticated inventories differ.");
        var sourceAtCompletion = await AuthenticateAsync(source, expected, token);
        if (!inventory.SequenceEqual(sourceAtCompletion.RuntimeInventory))
            throw new IOException("V2 artifact source changed during copy.");
        RequireExactRoleBranch(branchRoot, id);
        if (transactionParent) RequireExactTransactionContainer(destinationParent);
        destinationBindings.Recheck(_enforceAcls);
        sourceBindings.Recheck(enforceAcl: false);
        infrastructure.Recheck(_enforceAcls);
        return new(expected, copied.RuntimeInventory, role, id);
    }

    private async Task RetireAsync(string destination, ReleaseIdentity expected,
        V2ArtifactRole role, CancellationToken token)
    {
        RequireExpectedIdentity(expected);
        token.ThrowIfCancellationRequested();
        using var infrastructure = BindInfrastructure(role);
        // Missing is a failure, not silent idempotent success.
        if (!Directory.Exists(destination)) throw new IOException("V2 artifact retirement target is absent.");
        RequireExactRoleBranch(role == V2ArtifactRole.PrivateCandidate ? _transactionsRoot : _backupsRoot,
            Path.GetFileName(role == V2ArtifactRole.PrivateCandidate ? Path.GetDirectoryName(destination)! : destination));
        var transactionParent = role == V2ArtifactRole.PrivateCandidate
            ? Path.GetDirectoryName(destination)! : null;
        ComponentInspectionNative.Metadata parentBefore = default;
        string? parentFinal = null;
        SafeFileHandle? heldParent = null;
        if (transactionParent is not null)
        {
            heldParent = V2ArtifactFileSystemSecurity.OpenValidatedDirectory(transactionParent, _enforceAcls);
            try
            {
                parentBefore = ComponentInspectionNative.GetMetadata(heldParent);
                parentFinal = ComponentInspectionNative.FinalPath(heldParent);
                if (!Directory.EnumerateFileSystemEntries(transactionParent)
                    .Select(Path.GetFileName).SequenceEqual(["candidate"], StringComparer.Ordinal))
                    throw new IOException("V2 artifact transaction container has unexpected entries.");
            }
            catch { heldParent.Dispose(); throw; }
        }
        try
        {
        var authenticated = await AuthenticateAsync(destination, expected, token);
        Checkpoint("AfterRetirementAuthentication", -1, null);
        RequireCanonicalInventory(authenticated.RuntimeInventory, expected);
        var directories = ImpliedDirectories(authenticated.RuntimeInventory);
        var expectedFiles = authenticated.RuntimeInventory.Select(static f => f.Path)
            .Concat([ManifestName, MetadataName]).ToArray();
        var expectedTree = expectedFiles.Concat(directories).ToHashSet(StringComparer.Ordinal);
        RequireExactTree(destination, expectedTree, directories);

        // Snapshot every exact object under retained, write-denying handles. A delete handle is
        // reopened only after all read handles close; its identity and bytes are rechecked.
        var observed = new List<ObservedObject>();
        using (var held = new HeldBindings())
        {
            held.Add(destination, V2ArtifactFileSystemSecurity.OpenValidatedDirectory(destination, _enforceAcls));
            foreach (var directory in directories)
            {
                var path = ResolveContained(destination, directory);
                held.Add(path, V2ArtifactFileSystemSecurity.OpenValidatedDirectory(path, _enforceAcls));
            }
            foreach (var relative in expectedFiles)
            {
                token.ThrowIfCancellationRequested();
                var path = ResolveContained(destination, relative);
                var handle = V2ArtifactFileSystemSecurity.OpenValidatedFile(path, _enforceAcls);
                held.Add(path, handle);
                var maximum = relative == ManifestName ? TrustedManifestV2Codec.MaximumBytes :
                    relative == MetadataName ? ReleaseMetadataCodec.MaximumBytes : MaximumFileBytes;
                var hash = await HashBoundAsync(handle, maximum, token);
                var runtime = authenticated.RuntimeInventory.FirstOrDefault(f => f.Path == relative);
                if (runtime is not null && !string.Equals(hash, runtime.Sha256, StringComparison.Ordinal))
                    throw new IOException("V2 artifact runtime bytes changed before retirement.");
                observed.Add(new(path, ComponentInspectionNative.GetMetadata(handle),
                    ComponentInspectionNative.FinalPath(handle), hash, maximum, IsDirectory: false));
            }
            foreach (var relative in directories.Reverse())
            {
                var path = ResolveContained(destination, relative);
                using var handle = V2ArtifactFileSystemSecurity.OpenValidatedDirectory(path, _enforceAcls);
                observed.Add(new(path, ComponentInspectionNative.GetMetadata(handle),
                    ComponentInspectionNative.FinalPath(handle), null, 0, IsDirectory: true));
            }
            using var rootHandle = V2ArtifactFileSystemSecurity.OpenValidatedDirectory(destination, _enforceAcls);
            observed.Add(new(destination, ComponentInspectionNative.GetMetadata(rootHandle),
                ComponentInspectionNative.FinalPath(rootHandle), null, 0, IsDirectory: true));
            RequireExactTree(destination, expectedTree, directories);
            // The first authentication selected the expected inventory. Reauthenticate once
            // more while every observed runtime file and both sidecars are write/delete-denying
            // held objects. This binds the captured sidecar hashes to signed V2 evidence before
            // any handle is released for deletion.
            var retainedAuthentication = await AuthenticateAsync(destination, expected, token);
            if (!authenticated.RuntimeInventory.SequenceEqual(retainedAuthentication.RuntimeInventory))
                throw new IOException("V2 artifact retirement inventory changed.");
            held.Recheck(_enforceAcls);
        }
        heldParent?.Dispose();
        // Acquire and reauthenticate every DELETE-capable handle before deleting the first
        // object. These handles deny writes and replacement to all original files and sidecars
        // through the bottom-up retirement. Unknown newly inserted entries keep a directory
        // nonempty and therefore block its handle-bound deletion.
        var pending = new List<(ObservedObject Entry, SafeFileHandle Handle)>();
        SafeFileHandle? parentDelete = null;
        try
        {
            foreach (var entry in observed)
            {
                token.ThrowIfCancellationRequested();
                var handle = ComponentInspectionNative.OpenProtectedForDeletion(entry.Path, entry.IsDirectory);
                try
                {
                    await RequireRetirementBindingAsync(handle, entry, token);
                    pending.Add((entry, handle));
                }
                catch { handle.Dispose(); throw; }
            }
            if (transactionParent is not null)
            {
                parentDelete = ComponentInspectionNative.OpenProtectedForDeletion(transactionParent, directory: true);
                var parentNow = ComponentInspectionNative.GetMetadata(parentDelete);
                if (!parentNow.IsDirectory || parentNow.IsReparsePoint ||
                    parentNow.VolumeSerial != parentBefore.VolumeSerial || parentNow.Identity != parentBefore.Identity ||
                    !Same(ComponentInspectionNative.FinalPath(parentDelete), parentFinal!) ||
                    !Directory.EnumerateFileSystemEntries(transactionParent)
                        .Select(Path.GetFileName).SequenceEqual(["candidate"], StringComparer.Ordinal))
                    throw new IOException("V2 artifact transaction container changed.");
                if (_enforceAcls) V2ArtifactFileSystemSecurity.RequireDirectoryAcl(parentDelete);
            }
            RequireExactTree(destination, expectedTree, directories);
            for (var index = 0; index < pending.Count; index++)
            {
                var (entry, handle) = pending[index];
                token.ThrowIfCancellationRequested();
                var current = await RequireRetirementBindingAsync(handle, entry, token);
                ComponentInspectionNative.MarkValidatedObjectForDeletion(handle, current,
                    entry.FinalPath, entry.IsDirectory);
                handle.Dispose();
                Checkpoint("AfterRetirementDelete", index, entry.Path);
            }
            if (parentDelete is not null)
            {
                var parentNow = ComponentInspectionNative.GetMetadata(parentDelete);
                if (!parentNow.IsDirectory || parentNow.IsReparsePoint ||
                    parentNow.VolumeSerial != parentBefore.VolumeSerial || parentNow.Identity != parentBefore.Identity ||
                    !Same(ComponentInspectionNative.FinalPath(parentDelete), parentFinal!) ||
                    Directory.EnumerateFileSystemEntries(transactionParent!).Any())
                    throw new IOException("V2 artifact transaction container is not empty.");
                if (_enforceAcls) V2ArtifactFileSystemSecurity.RequireDirectoryAcl(parentDelete);
                ComponentInspectionNative.MarkValidatedObjectForDeletion(parentDelete, parentNow,
                    parentFinal!, directory: true);
                parentDelete.Dispose();
            }
        }
        finally
        {
            foreach (var (_, handle) in pending) handle.Dispose();
            parentDelete?.Dispose();
        }
        RequireAbsent(role == V2ArtifactRole.PrivateCandidate ? transactionParent! : destination);
        if (Directory.EnumerateFileSystemEntries(role == V2ArtifactRole.PrivateCandidate
            ? _transactionsRoot : _backupsRoot).Any())
            throw new IOException("V2 artifact role root contains retirement residue.");
        infrastructure.Recheck(_enforceAcls);
        }
        finally { heldParent?.Dispose(); }
    }

    private async Task<ComponentInspectionNative.Metadata> RequireRetirementBindingAsync(
        SafeFileHandle handle, ObservedObject entry, CancellationToken token)
    {
        var current = ComponentInspectionNative.GetMetadata(handle);
        var changed = entry.IsDirectory
            ? !current.IsDirectory || current.IsReparsePoint ||
              current.VolumeSerial != entry.Metadata.VolumeSerial || current.Identity != entry.Metadata.Identity
            : current != entry.Metadata;
        if (changed || !Same(ComponentInspectionNative.FinalPath(handle), entry.FinalPath) ||
            !ComponentInspectionNative.HasOnlyDefaultDataStream(handle, entry.IsDirectory) ||
            (!entry.IsDirectory && ComponentInspectionNative.GetHardLinkCount(handle) != 1))
            throw new IOException("V2 artifact retirement object changed.");
        if (_enforceAcls)
        {
            if (entry.IsDirectory) V2ArtifactFileSystemSecurity.RequireDirectoryAcl(handle);
            else V2ArtifactFileSystemSecurity.RequireFileAcl(handle);
        }
        if (entry.Hash is not null && !string.Equals(await HashBoundAsync(handle, entry.MaximumBytes, token),
            entry.Hash, StringComparison.Ordinal))
            throw new IOException("V2 artifact retirement bytes changed.");
        return current;
    }

    private async Task<long> CopyOneAsync(string sourceRoot, string destinationRoot, string relative,
        string? expectedHash, long maximumBytes, HeldBindings destinationBindings, CancellationToken token)
    {
        var from = ResolveContained(sourceRoot, relative);
        var to = ResolveContained(destinationRoot, relative);
        OfflineReleaseVerifier.RejectReparseAncestors(from);
        using var source = ComponentInspectionNative.OpenProtected(from);
        var sourceBefore = RequireBoundFile(source, from, sourceRoot, maximumBytes);
        var sourceHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        string actualHash;
        ComponentInspectionNative.Metadata destinationBefore;
        using (sourceHash)
        {
            await using (var destination = V2ArtifactFileSystemSecurity.CreateNewFile(to, _enforceAcls))
            {
                var buffer = new byte[BufferBytes];
                long offset = 0;
                int read;
                while ((read = await RandomAccess.ReadAsync(source, buffer, offset, token)) != 0)
                {
                    offset = checked(offset + read);
                    if (offset > sourceBefore.Length || offset > maximumBytes)
                        throw new IOException("V2 artifact source changed during bounded copy.");
                    sourceHash.AppendData(buffer.AsSpan(0, read));
                    await destination.WriteAsync(buffer.AsMemory(0, read), token);
                }
                if (offset != sourceBefore.Length)
                    throw new IOException("V2 artifact source length changed during copy.");
                await destination.FlushAsync(token);
                destination.Flush(flushToDisk: true);
                actualHash = Convert.ToHexString(sourceHash.GetHashAndReset());
                if (expectedHash is not null && !string.Equals(actualHash, expectedHash, StringComparison.Ordinal))
                    throw new IOException("V2 artifact source hash differs from signed inventory.");
                if (ComponentInspectionNative.GetMetadata(source) != sourceBefore ||
                    !Same(ComponentInspectionNative.FinalPath(source), from) ||
                    !ComponentInspectionNative.HasOnlyDefaultDataStream(source))
                    throw new IOException("V2 artifact source identity changed.");
                var created = destination.SafeFileHandle;
                destinationBefore = RequireBoundFile(created, to, destinationRoot, maximumBytes);
                if (ComponentInspectionNative.GetHardLinkCount(created) != 1 ||
                    destinationBefore.Length != offset ||
                    !string.Equals(await HashBoundAsync(created, maximumBytes, token), actualHash,
                        StringComparison.Ordinal))
                    throw new IOException("V2 artifact destination bytes or hard links changed.");
                // The exact descriptor was attached at create-new time. Reopen only after the
                // write handle closes, and require the same file ID and bytes before acceptance.
            }
            var retained = V2ArtifactFileSystemSecurity.OpenValidatedFile(to, _enforceAcls);
            try
            {
                if (ComponentInspectionNative.GetMetadata(retained) != destinationBefore ||
                    !string.Equals(await HashBoundAsync(retained, maximumBytes, token),
                        actualHash, StringComparison.Ordinal))
                    throw new IOException("V2 artifact destination changed after ACL application.");
                destinationBindings.Add(to, retained);
            }
            catch { retained.Dispose(); throw; }
            return sourceBefore.Length;
        }
    }

    private async Task<GenerationAwareOfflineReleaseEvidence> AuthenticateAsync(string root,
        ReleaseIdentity expected, CancellationToken token)
    {
        var result = await _verifier.VerifyChainAsync(root, token);
        if (result.Result != GenerationAwareOfflineVerificationResult.Authenticated ||
            result.Release is not { Identity.Generation: ReleaseGeneration.V2 } evidence ||
            evidence.Identity != expected || evidence.RuntimeInventory.IsDefaultOrEmpty)
            throw new IOException("V2 artifact full authentication failed.");
        return evidence;
    }

    private static void RequireExpectedIdentity(ReleaseIdentity expected)
    {
        if (expected is not { IsValid: true, Generation: ReleaseGeneration.V2 })
            throw new ArgumentException("Expected V2 artifact identity is invalid.", nameof(expected));
    }

    private static void RequireCanonicalInventory(ImmutableArray<TrustedManifestV2File> inventory,
        ReleaseIdentity expected)
    {
        if (inventory.IsDefaultOrEmpty)
            throw new IOException("Authenticated V2 inventory is absent.");
        // Reuse the canonical codec's exact path, collision, ordering, hash, and bound rules.
        _ = TrustedManifestV2Codec.CreateCanonicalPayload("0.0.0", expected.ReleaseSequence, inventory.ToArray());
    }

    private static string[] ImpliedDirectories(ImmutableArray<TrustedManifestV2File> inventory)
    {
        var directories = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in inventory)
            for (var slash = file.Path.IndexOf('/'); slash >= 0; slash = file.Path.IndexOf('/', slash + 1))
                directories.Add(file.Path[..slash]);
        return directories.OrderBy(static value => value.Count(static c => c == '/'))
            .ThenBy(static value => value, StringComparer.Ordinal).ToArray();
    }

    private HeldBindings BindInfrastructure(V2ArtifactRole role)
    {
        var bindings = new HeldBindings();
        try
        {
            var branch = role == V2ArtifactRole.PrivateCandidate ? _transactionsRoot : _backupsRoot;
            foreach (var path in new[] { _artifactRoot, branch })
            {
                OfflineReleaseVerifier.RejectReparseAncestors(path);
                bindings.Add(path, V2ArtifactFileSystemSecurity.OpenValidatedDirectory(path, _enforceAcls));
            }
            return bindings;
        }
        catch { bindings.Dispose(); throw; }
    }

    private static void BindSourceDirectories(string source, string[] directories, HeldBindings bindings)
    {
        foreach (var relative in new[] { "" }.Concat(directories))
        {
            var path = relative.Length == 0 ? source : ResolveContained(source, relative);
            OfflineReleaseVerifier.RejectReparseAncestors(path);
            var handle = ComponentInspectionNative.OpenProtected(path, directory: true);
            try
            {
                var before = ComponentInspectionNative.GetMetadata(handle);
                if (!before.IsDirectory || before.IsReparsePoint ||
                    !Same(ComponentInspectionNative.FinalPath(handle), path) ||
                    !ComponentInspectionNative.HasOnlyDefaultDataStream(handle, directory: true))
                    throw new IOException("V2 artifact source directory binding failed.");
                bindings.Add(path, handle);
            }
            catch { handle.Dispose(); throw; }
        }
    }

    private static ComponentInspectionNative.Metadata RequireBoundFile(SafeFileHandle handle,
        string path, string root, long maximum)
    {
        var metadata = ComponentInspectionNative.GetMetadata(handle);
        if (metadata.IsDirectory || metadata.IsReparsePoint || metadata.Length is < 0 or > MaximumFileBytes ||
            metadata.Length > maximum || !ComponentInspectionSource.Contained(root, path) ||
            !Same(ComponentInspectionNative.FinalPath(handle), path) ||
            !ComponentInspectionNative.HasOnlyDefaultDataStream(handle))
            throw new IOException("V2 artifact retained file binding failed.");
        return metadata;
    }

    private static async Task<string> HashBoundAsync(SafeFileHandle handle, long maximum,
        CancellationToken token)
    {
        var before = ComponentInspectionNative.GetMetadata(handle);
        if (before.IsDirectory || before.IsReparsePoint || before.Length is < 0 || before.Length > maximum)
            throw new IOException("V2 artifact bounded hash target rejected.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[BufferBytes];
        long offset = 0;
        int read;
        while ((read = await RandomAccess.ReadAsync(handle, buffer, offset, token)) != 0)
        {
            offset = checked(offset + read);
            if (offset > before.Length || offset > maximum)
                throw new IOException("V2 artifact changed during bounded hash.");
            hash.AppendData(buffer.AsSpan(0, read));
        }
        if (offset != before.Length || ComponentInspectionNative.GetMetadata(handle) != before ||
            !ComponentInspectionNative.HasOnlyDefaultDataStream(handle))
            throw new IOException("V2 artifact changed during bounded hash.");
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void RequireExactTree(string root, HashSet<string> expected,
        IReadOnlyCollection<string> directories)
    {
        var directorySet = directories.ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<(string Path, string Relative)>();
        pending.Push((root, ""));
        while (pending.Count != 0)
        {
            var current = pending.Pop();
            foreach (var path in Directory.EnumerateFileSystemEntries(current.Path))
            {
                var relative = current.Relative.Length == 0 ? Path.GetFileName(path) :
                    current.Relative + "/" + Path.GetFileName(path);
                if (seen.Count >= TrustedManifestV2Codec.MaximumFiles * TrustedManifestV2Codec.MaximumDepth + 2 ||
                    !seen.Add(relative) || !expected.Contains(relative))
                    throw new IOException("V2 artifact physical tree contains an unknown entry.");
                var attributes = File.GetAttributes(path);
                if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
                    ((attributes & FileAttributes.Directory) != 0) != directorySet.Contains(relative))
                    throw new IOException("V2 artifact physical tree contains an unsafe entry.");
                if (directorySet.Contains(relative)) pending.Push((path, relative));
            }
        }
        if (seen.Count != expected.Count)
            throw new IOException("V2 artifact physical tree is incomplete.");
    }

    private static void RequireExactRoleBranch(string branch, string id)
    {
        var entries = Directory.EnumerateFileSystemEntries(branch).ToArray();
        if (entries.Length != 1 || !string.Equals(Path.GetFileName(entries[0]), id, StringComparison.Ordinal) ||
            (File.GetAttributes(entries[0]) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) !=
            FileAttributes.Directory)
            throw new IOException("V2 artifact role root contains unexpected entries.");
    }

    private static void RequireExactTransactionContainer(string transactionParent)
    {
        var entries = Directory.EnumerateFileSystemEntries(transactionParent).ToArray();
        if (entries.Length != 1 ||
            !string.Equals(Path.GetFileName(entries[0]), "candidate", StringComparison.Ordinal) ||
            (File.GetAttributes(entries[0]) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) !=
            FileAttributes.Directory)
            throw new IOException("V2 artifact transaction container contains unexpected entries.");
    }

    private static string ResolveContained(string root, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative) || relative.Contains('\\') || relative.Contains(':') ||
            Path.IsPathRooted(relative) || relative.Split('/').Any(static part => part is "" or "." or ".."))
            throw new IOException("V2 artifact relative path rejected.");
        var path = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!ComponentInspectionSource.Contained(root, path))
            throw new IOException("V2 artifact path escaped its root.");
        return path;
    }

    private static string CanonicalRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            path.StartsWith("\\\\", StringComparison.Ordinal) ||
            path.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            path.StartsWith("\\\\.\\", StringComparison.Ordinal))
            throw new ArgumentException("V2 artifact root must be an ordinary absolute path.", nameof(path));
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!string.Equals(Path.TrimEndingDirectorySeparator(path), full, StringComparison.OrdinalIgnoreCase) ||
            full.AsSpan(Path.GetPathRoot(full)!.Length).Contains(':') ||
            Same(full, Path.GetPathRoot(full)!))
            throw new ArgumentException("V2 artifact root cannot be a volume root.", nameof(path));
        return full;
    }

    private static bool Same(string left, string right) =>
        string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);

    private static bool Overlaps(string left, string right)
    {
        left = Path.TrimEndingDirectorySeparator(Path.GetFullPath(left));
        right = Path.TrimEndingDirectorySeparator(Path.GetFullPath(right));
        return Same(left, right) || left.StartsWith(right + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            right.StartsWith(left + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string RequireId(string id)
    {
        if (!V2UpdateTransactionJournalCodec.IsId(id))
            throw new ArgumentException("V2 artifact identifier is invalid.", nameof(id));
        return id;
    }

    private static void RequireAbsent(string path)
    {
        try { _ = File.GetAttributes(path); }
        catch (FileNotFoundException) { return; }
        catch (DirectoryNotFoundException) { return; }
        throw new IOException("V2 artifact destination already exists.");
    }

    private SafeFileHandle CreateAndBindDirectory(string path)
    {
        return V2ArtifactFileSystemSecurity.CreateNewDirectory(path, _enforceAcls);
    }

    private void Checkpoint(string stage, int index, string? relative) =>
        _fault?.Invoke(new(stage, index, relative));

    private sealed record ObservedObject(string Path, ComponentInspectionNative.Metadata Metadata,
        string FinalPath, string? Hash, long MaximumBytes, bool IsDirectory);

    private sealed class HeldBindings : IDisposable
    {
        private readonly List<(string Path, SafeFileHandle Handle, ComponentInspectionNative.Metadata Metadata,
            string FinalPath)> _items = [];

        internal void Add(string path, SafeFileHandle handle)
        {
            try
            {
                var metadata = ComponentInspectionNative.GetMetadata(handle);
                _items.Add((path, handle, metadata, ComponentInspectionNative.FinalPath(handle)));
            }
            catch { handle.Dispose(); throw; }
        }

        internal void Recheck(bool enforceAcl)
        {
            foreach (var item in _items)
            {
                var now = ComponentInspectionNative.GetMetadata(item.Handle);
                // Creating canonical children legitimately changes a directory's timestamps and
                // reported size. Its volume/file ID, type and reparse status must remain fixed.
                var identityChanged = item.Metadata.IsDirectory
                    ? !now.IsDirectory || now.IsReparsePoint ||
                      now.VolumeSerial != item.Metadata.VolumeSerial || now.Identity != item.Metadata.Identity
                    : now != item.Metadata;
                if (identityChanged ||
                    !Same(ComponentInspectionNative.FinalPath(item.Handle), item.FinalPath) ||
                    !Same(item.FinalPath, item.Path) ||
                    !ComponentInspectionNative.HasOnlyDefaultDataStream(item.Handle, item.Metadata.IsDirectory) ||
                    (!item.Metadata.IsDirectory && ComponentInspectionNative.GetHardLinkCount(item.Handle) != 1))
                    throw new IOException("V2 artifact retained binding changed.");
                if (enforceAcl)
                {
                    if (item.Metadata.IsDirectory) V2ArtifactFileSystemSecurity.RequireDirectoryAcl(item.Handle);
                    else V2ArtifactFileSystemSecurity.RequireFileAcl(item.Handle);
                }
            }
        }

        public void Dispose()
        {
            for (var index = _items.Count - 1; index >= 0; index--)
                _items[index].Handle.Dispose();
        }
    }
}
