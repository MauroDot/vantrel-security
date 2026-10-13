using System.Collections.Immutable;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

internal sealed record V2ServiceTreeCheckpoint(string Stage, int FileIndex, string? RelativePath);

/// <summary>A rename was attempted; only fresh physical observation can determine its outcome.</summary>
internal sealed class V2ServiceTreeMoveOutcomeAmbiguousException : IOException
{
    internal V2ServiceTreeMoveOutcomeAmbiguousException(string stage) :
        base("V2 Service tree move outcome is ambiguous at " + stage +
            "; fresh physical classification is required.") { }
}

/// <summary>Observation at one instant, never durable transaction authorization.</summary>
internal sealed record V2PreparedServiceTreeEvidence(ReleaseIdentity Identity,
    ImmutableArray<TrustedManifestV2File> RuntimeInventory, string TransactionId);

/// <summary>
/// Dormant, single-operation V2 Program Files primitives. No production caller, journal, SCM,
/// policy, or recovery action is connected. A future caller must prove SCM STOPPED and persist
/// durable intent before any rename. Two renames are never one atomic transaction.
/// </summary>
internal sealed class V2ServiceTreeStorage
{
    private const string Manifest = "Vantrel.Security.TrustedManifest";
    private const string Metadata = "Vantrel.Security.ReleaseMetadata";
    private const long MaximumFileBytes = 512L * 1024 * 1024;
    private const long MaximumTreeBytes = 2L * 1024 * 1024 * 1024;
    private const int BufferBytes = 65536;
    private readonly GenerationAwareOfflineReleaseVerifier _verifier;
    private readonly string _productParent;
    private readonly string _artifactRoot;
    private readonly bool _enforceAcls;
    private readonly Action<V2ServiceTreeCheckpoint>? _fault;

    internal V2ServiceTreeStorage() : this(new GenerationAwareOfflineReleaseVerifier(),
        Path.GetDirectoryName(FixedUpdatePaths.InstalledServiceRoot)!,
        Path.Combine(FixedUpdatePaths.UpdatesRoot, "V2Artifacts"), true, null, true) { }

    // Only disposable tests can inject roots, keys, ACL bypass or deterministic faults.
    internal V2ServiceTreeStorage(GenerationAwareOfflineReleaseVerifier verifier,
        string disposableProductParent, string disposableArtifactRoot, bool enforceAcls = false,
        Action<V2ServiceTreeCheckpoint>? fault = null)
        : this(verifier, disposableProductParent, disposableArtifactRoot, enforceAcls, fault, false) { }

    private V2ServiceTreeStorage(GenerationAwareOfflineReleaseVerifier verifier, string productParent,
        string artifactRoot, bool enforceAcls, Action<V2ServiceTreeCheckpoint>? fault, bool production)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("V2 Service tree storage requires Windows.");
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _productParent = CanonicalRoot(productParent);
        _artifactRoot = CanonicalRoot(artifactRoot);
        if (production)
        {
            if (!enforceAcls || !Same(_productParent, Path.GetDirectoryName(FixedUpdatePaths.InstalledServiceRoot)!) ||
                !Same(_artifactRoot, Path.Combine(FixedUpdatePaths.UpdatesRoot, "V2Artifacts")))
                throw new IOException("Fixed V2 Service tree roots rejected.");
        }
        else if (Overlaps(_productParent, _artifactRoot) ||
            Overlaps(_productParent, FixedUpdatePaths.InstalledServiceRoot) ||
            Overlaps(_productParent, FixedUpdatePaths.VantrelRoot) ||
            Overlaps(_artifactRoot, FixedUpdatePaths.InstalledServiceRoot) ||
            Overlaps(_artifactRoot, FixedUpdatePaths.VantrelRoot))
            throw new IOException("Disposable V2 Service tree roots overlap protected storage.");
        _enforceAcls = enforceAcls;
        _fault = fault;
    }

    internal string CanonicalServiceRoot => Path.Combine(_productParent, "Service");
    internal string GetPrivateCandidatePath(string transactionId) =>
        Path.Combine(_artifactRoot, "Transactions", RequireId(transactionId), "candidate");
    internal string GetPreparedTargetPath(string transactionId) =>
        Path.Combine(_productParent, ".service-next-" + RequireId(transactionId));
    internal string GetDetachedPredecessorPath(string transactionId) =>
        Path.Combine(_productParent, ".service-prev-" + RequireId(transactionId));
    internal string GetAbandonedTargetPath(string transactionId) =>
        Path.Combine(_productParent, ".service-abandoned-" + RequireId(transactionId));

    internal async Task<V2PreparedServiceTreeEvidence> PrepareTargetAsync(string transactionId,
        ReleaseIdentity target, CancellationToken token)
    {
        RequireIdentity(target);
        var id = RequireId(transactionId);
        token.ThrowIfCancellationRequested();
        var sourceRoot = GetPrivateCandidatePath(id);
        var destinationRoot = GetPreparedTargetPath(id);
        using var parent = V2ServiceDirectoryMoveNative.OpenBoundParent(_productParent);
        RequireManagedNamespace(id, service: null, next: false, prev: false, abandoned: false,
            checkService: false);
        var sourceEvidence = await AuthenticateAsync(sourceRoot, target, token);
        using var source = await BindTreeAsync(sourceRoot, sourceEvidence.RuntimeInventory,
            serviceTree: false, token);
        // Source and all destination roles are distinct both lexically and by their bound roots.
        if (source.RootMetadata.VolumeSerial == ComponentInspectionNative.GetMetadata(parent).VolumeSerial &&
            source.RootMetadata.Identity == ComponentInspectionNative.GetMetadata(parent).Identity)
            throw new IOException("V2 Service tree source aliases destination parent.");
        Checkpoint("BeforeRoot");
        using var prepared = new HeldTree(destinationRoot);
        prepared.Add(destinationRoot, V2ServiceTreeFileSystemSecurity.CreateNewDirectory(destinationRoot, _enforceAcls));
        Checkpoint("AfterRoot");
        var inventory = sourceEvidence.RuntimeInventory;
        var directories = ImpliedDirectories(inventory);
        foreach (var relative in directories)
        {
            token.ThrowIfCancellationRequested();
            Checkpoint("BeforeDirectory", -1, relative);
            var path = ResolveContained(destinationRoot, relative);
            prepared.Add(path, V2ServiceTreeFileSystemSecurity.CreateNewDirectory(path, _enforceAcls));
        }
        long total = 0;
        for (var index = 0; index < inventory.Length; index++)
        {
            token.ThrowIfCancellationRequested();
            var file = inventory[index];
            Checkpoint("BeforeFile", index, file.Path);
            total = checked(total + await CopyOneAsync(source, prepared, sourceRoot,
                destinationRoot, file.Path, file.Sha256, MaximumFileBytes, token));
            if (total > MaximumTreeBytes) throw new IOException("V2 Service tree runtime inventory exceeds its bound.");
            Checkpoint("AfterFile", index, file.Path);
        }
        Checkpoint("BeforeSidecars");
        await CopyOneAsync(source, prepared, sourceRoot, destinationRoot, Manifest, null,
            TrustedManifestV2Codec.MaximumBytes, token);
        await CopyOneAsync(source, prepared, sourceRoot, destinationRoot, Metadata, null,
            ReleaseMetadataCodec.MaximumBytes, token);
        Checkpoint("AfterSidecars");
        Checkpoint("BeforeFinalVerification");
        var copied = await AuthenticateAsync(destinationRoot, target, token);
        if (!inventory.SequenceEqual(copied.RuntimeInventory))
            throw new IOException("V2 Service tree prepared inventory differs from authenticated source.");
        var sourceAgain = await AuthenticateAsync(sourceRoot, target, token);
        if (!inventory.SequenceEqual(sourceAgain.RuntimeInventory))
            throw new IOException("V2 Service tree private candidate changed during copy.");
        RequireExactTree(destinationRoot, inventory);
        prepared.Recheck(_enforceAcls, serviceTree: true);
        source.Recheck(_enforceAcls, serviceTree: false);
        RequireManagedNamespace(id, service: null, next: true, prev: false, abandoned: false,
            checkService: false);
        V2ServiceDirectoryMoveNative.RequireBoundParent(parent, _productParent);
        return new(target, copied.RuntimeInventory, id);
    }

    internal Task DetachPredecessorAsync(string id, ReleaseIdentity predecessor,
        ReleaseIdentity target, CancellationToken token) => MoveOneAsync(id, predecessor, target,
            0, token);
    internal Task ActivatePreparedTargetAsync(string id, ReleaseIdentity predecessor,
        ReleaseIdentity target, CancellationToken token) => MoveOneAsync(id, predecessor, target,
            1, token);
    internal Task DetachActivatedTargetForRollbackAsync(string id, ReleaseIdentity predecessor,
        ReleaseIdentity target, CancellationToken token) => MoveOneAsync(id, predecessor, target,
            2, token);
    internal Task RestorePredecessorAsync(string id, ReleaseIdentity predecessor,
        ReleaseIdentity target, CancellationToken token) => MoveOneAsync(id, predecessor, target,
            3, token);

    private async Task MoveOneAsync(string transactionId, ReleaseIdentity predecessor,
        ReleaseIdentity target, int step, CancellationToken token)
    {
        RequireIdentity(predecessor);
        RequireIdentity(target);
        if (predecessor == target) throw new IOException("V2 Service tree predecessor and target identities coincide.");
        var id = RequireId(transactionId);
        token.ThrowIfCancellationRequested();
        var paths = new[] { CanonicalServiceRoot, GetPreparedTargetPath(id),
            GetDetachedPredecessorPath(id), GetAbandonedTargetPath(id) };
        ReleaseIdentity?[] before = step switch
        {
            0 => [predecessor, target, null, null],
            1 => [null, target, predecessor, null],
            2 => [target, null, predecessor, null],
            3 => [null, null, predecessor, target],
            _ => throw new ArgumentOutOfRangeException(nameof(step))
        };
        ReleaseIdentity?[] after = step switch
        {
            0 => [null, target, predecessor, null],
            1 => [target, null, predecessor, null],
            2 => [null, null, predecessor, target],
            3 => [predecessor, null, null, target],
            _ => throw new ArgumentOutOfRangeException(nameof(step))
        };
        var sourceIndex = step switch { 0 => 0, 1 => 1, 2 => 0, 3 => 2, _ => -1 };
        var destinationIndex = step switch { 0 => 2, 1 => 0, 2 => 3, 3 => 0, _ => -1 };
        using var parent = V2ServiceDirectoryMoveNative.OpenBoundParent(_productParent);
        var sourceMetadata = await ObserveStateAsync(id, paths, before, token);
        Checkpoint("BeforeMoveAttempt");
        token.ThrowIfCancellationRequested();
        // The source's read handle cannot coexist with a DELETE-capable rename handle. Compare
        // the freshly authenticated file ID and final path across that handle transition.
        var observed = sourceMetadata[sourceIndex];
        if (observed is null)
            throw new IOException("V2 Service tree rename source identity changed.");
        using var source = V2ServiceDirectoryMoveNative.OpenBoundSourceForRename(paths[sourceIndex],
            parent, observed.Value, _enforceAcls);
        RequireManagedNamespace(id, before[0] is not null, before[1] is not null,
            before[2] is not null, before[3] is not null, checkService: true);
        token.ThrowIfCancellationRequested();
        var attempted = false;
        var stage = "native-rename";
        try
        {
            V2ServiceDirectoryMoveNative.RenameBoundSameParent(parent, _productParent, source,
                paths[sourceIndex], Path.GetFileName(paths[destinationIndex]), observed.Value,
                () =>
                {
                    attempted = true;
                    Checkpoint("AfterMoveAttemptBeforeNative");
                }, _enforceAcls);
            stage = "post-rename-checkpoint";
            Checkpoint("AfterMove");
            Checkpoint("BeforePostVerification");
            source.Dispose();
            // A successful OS return is not enough: all physical roles must be reauthenticated.
            Checkpoint("DuringPostVerification");
            stage = "post-rename-observation";
            _ = await ObserveStateAsync(id, paths, after, token);
            V2ServiceDirectoryMoveNative.RequireBoundParent(parent, _productParent);
        }
        catch when (attempted)
        {
            // Never compensate or infer success/failure from path existence after an attempt.
            throw new V2ServiceTreeMoveOutcomeAmbiguousException(stage);
        }
    }

    private async Task<ComponentInspectionNative.Metadata?[]> ObserveStateAsync(string id,
        string[] paths, ReleaseIdentity?[] expected, CancellationToken token)
    {
        RequireManagedNamespace(id, expected[0] is not null, expected[1] is not null,
            expected[2] is not null, expected[3] is not null, checkService: true);
        var observed = new ComponentInspectionNative.Metadata?[paths.Length];
        for (var index = 0; index < paths.Length; index++)
        {
            token.ThrowIfCancellationRequested();
            if (expected[index] is null) continue;
            var evidence = await AuthenticateAsync(paths[index], expected[index]!, token);
            using var bound = await BindTreeAsync(paths[index], evidence.RuntimeInventory,
                serviceTree: true, token);
            RequireExactTree(paths[index], evidence.RuntimeInventory);
            // Authentication while all tree handles are held binds the signed sidecars and
            // runtime inventory to the currently opened physical objects.
            var again = await AuthenticateAsync(paths[index], expected[index]!, token);
            if (!evidence.RuntimeInventory.SequenceEqual(again.RuntimeInventory))
                throw new IOException("V2 Service tree inventory changed during observation.");
            bound.Recheck(_enforceAcls, serviceTree: true);
            observed[index] = bound.RootMetadata;
        }
        RequireManagedNamespace(id, expected[0] is not null, expected[1] is not null,
            expected[2] is not null, expected[3] is not null, checkService: true);
        return observed;
    }

    private async Task<GenerationAwareOfflineReleaseEvidence> AuthenticateAsync(string root,
        ReleaseIdentity expected, CancellationToken token)
    {
        var result = await _verifier.VerifyChainAsync(root, token);
        if (result.Result != GenerationAwareOfflineVerificationResult.Authenticated ||
            result.Release is not { Identity.Generation: ReleaseGeneration.V2 } release ||
            release.Identity != expected || release.RuntimeInventory.IsDefaultOrEmpty)
            throw new IOException("V2 Service tree full authentication failed.");
        _ = TrustedManifestV2Codec.CreateCanonicalPayload("0.0.0", expected.ReleaseSequence,
            release.RuntimeInventory.ToArray());
        return release;
    }

    private async Task<HeldTree> BindTreeAsync(string root,
        ImmutableArray<TrustedManifestV2File> inventory, bool serviceTree, CancellationToken token)
    {
        RequireExactTree(root, inventory);
        var held = new HeldTree(root);
        try
        {
            var openDir = serviceTree
                ? (Func<string, SafeFileHandle>)(path => V2ServiceTreeFileSystemSecurity.OpenValidatedDirectory(path, _enforceAcls))
                : path => V2ArtifactFileSystemSecurity.OpenValidatedDirectory(path, _enforceAcls);
            var openFile = serviceTree
                ? (Func<string, SafeFileHandle>)(path => V2ServiceTreeFileSystemSecurity.OpenValidatedFile(path, _enforceAcls))
                : path => V2ArtifactFileSystemSecurity.OpenValidatedFile(path, _enforceAcls);
            held.Add(root, openDir(root));
            foreach (var relative in ImpliedDirectories(inventory))
            {
                token.ThrowIfCancellationRequested();
                var path = ResolveContained(root, relative);
                held.Add(path, openDir(path));
            }
            foreach (var file in inventory)
            {
                token.ThrowIfCancellationRequested();
                var path = ResolveContained(root, file.Path);
                var handle = openFile(path);
                held.Add(path, handle);
                if (!string.Equals(await HashBoundAsync(handle, MaximumFileBytes, token),
                    file.Sha256, StringComparison.Ordinal))
                    throw new IOException("V2 Service tree runtime bytes changed.");
            }
            foreach (var sidecar in new[] { Manifest, Metadata })
            {
                token.ThrowIfCancellationRequested();
                var path = ResolveContained(root, sidecar);
                var handle = openFile(path);
                held.Add(path, handle);
                _ = await HashBoundAsync(handle, sidecar == Manifest ?
                    TrustedManifestV2Codec.MaximumBytes : ReleaseMetadataCodec.MaximumBytes, token);
            }
            held.Recheck(_enforceAcls, serviceTree);
            return held;
        }
        catch { held.Dispose(); throw; }
    }

    private async Task<long> CopyOneAsync(HeldTree source, HeldTree prepared, string fromRoot,
        string toRoot, string relative, string? expectedHash, long maximum, CancellationToken token)
    {
        var from = ResolveContained(fromRoot, relative);
        var to = ResolveContained(toRoot, relative);
        var sourceHandle = source.Get(from);
        var sourceBefore = RequireBoundFile(sourceHandle, from, fromRoot, maximum);
        ComponentInspectionNative.Metadata destinationBefore;
        string copiedHash;
        using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            await using (var destination = V2ServiceTreeFileSystemSecurity.CreateNewFile(to, _enforceAcls))
            {
                var buffer = new byte[BufferBytes];
                long offset = 0;
                int read;
                while ((read = await RandomAccess.ReadAsync(sourceHandle, buffer, offset, token)) != 0)
                {
                    offset = checked(offset + read);
                    if (offset > sourceBefore.Length || offset > maximum)
                        throw new IOException("V2 Service tree bounded source copy changed.");
                    hash.AppendData(buffer.AsSpan(0, read));
                    await destination.WriteAsync(buffer.AsMemory(0, read), token);
                }
                if (offset != sourceBefore.Length) throw new IOException("V2 Service tree source length changed.");
                await destination.FlushAsync(token);
                destination.Flush(flushToDisk: true);
                copiedHash = Convert.ToHexString(hash.GetHashAndReset());
                if (expectedHash is not null && !string.Equals(copiedHash, expectedHash, StringComparison.Ordinal))
                    throw new IOException("V2 Service tree copied source disagrees with signed inventory.");
                if (ComponentInspectionNative.GetMetadata(sourceHandle) != sourceBefore ||
                    ComponentInspectionNative.GetHardLinkCount(sourceHandle) != 1 ||
                    !Same(ComponentInspectionNative.FinalPath(sourceHandle), from) ||
                    !ComponentInspectionNative.HasOnlyDefaultDataStream(sourceHandle))
                    throw new IOException("V2 Service tree source binding changed during copy.");
                destinationBefore = RequireBoundFile(destination.SafeFileHandle, to, toRoot, maximum);
                if (destinationBefore.Length != offset ||
                    ComponentInspectionNative.GetHardLinkCount(destination.SafeFileHandle) != 1 ||
                    !string.Equals(await HashBoundAsync(destination.SafeFileHandle, maximum, token),
                        copiedHash, StringComparison.Ordinal))
                    throw new IOException("V2 Service tree destination bytes changed during copy.");
            }
            var retained = V2ServiceTreeFileSystemSecurity.OpenValidatedFile(to, _enforceAcls);
            try
            {
                if (ComponentInspectionNative.GetMetadata(retained) != destinationBefore ||
                    !string.Equals(await HashBoundAsync(retained, maximum, token), copiedHash,
                        StringComparison.Ordinal))
                    throw new IOException("V2 Service tree destination changed after creation.");
                prepared.Add(to, retained);
            }
            catch { retained.Dispose(); throw; }
        }
        return sourceBefore.Length;
    }

    private static ComponentInspectionNative.Metadata RequireBoundFile(SafeFileHandle handle,
        string path, string root, long maximum)
    {
        var metadata = ComponentInspectionNative.GetMetadata(handle);
        if (metadata.IsDirectory || metadata.IsReparsePoint || metadata.Length is < 0 ||
            metadata.Length > maximum || !ComponentInspectionSource.Contained(root, path) ||
            !Same(ComponentInspectionNative.FinalPath(handle), path) ||
            !ComponentInspectionNative.HasOnlyDefaultDataStream(handle) ||
            ComponentInspectionNative.GetHardLinkCount(handle) != 1)
            throw new IOException("V2 Service tree retained file binding failed.");
        return metadata;
    }

    private static async Task<string> HashBoundAsync(SafeFileHandle handle, long maximum,
        CancellationToken token)
    {
        var before = ComponentInspectionNative.GetMetadata(handle);
        if (before.IsDirectory || before.IsReparsePoint || before.Length is < 0 || before.Length > maximum)
            throw new IOException("V2 Service tree bounded hash target rejected.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[BufferBytes];
        long offset = 0;
        int read;
        while ((read = await RandomAccess.ReadAsync(handle, buffer, offset, token)) != 0)
        {
            offset = checked(offset + read);
            if (offset > before.Length || offset > maximum)
                throw new IOException("V2 Service tree file changed during bounded hash.");
            hash.AppendData(buffer.AsSpan(0, read));
        }
        if (offset != before.Length || ComponentInspectionNative.GetMetadata(handle) != before ||
            !ComponentInspectionNative.HasOnlyDefaultDataStream(handle) ||
            ComponentInspectionNative.GetHardLinkCount(handle) != 1)
            throw new IOException("V2 Service tree file changed during bounded hash.");
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private void RequireManagedNamespace(string id, bool? service, bool next, bool prev,
        bool abandoned, bool checkService)
    {
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            // Unrelated product children are intentionally outside the managed namespace.
        };
        if (next) expected.Add(Path.GetFileName(GetPreparedTargetPath(id)));
        if (prev) expected.Add(Path.GetFileName(GetDetachedPredecessorPath(id)));
        if (abandoned) expected.Add(Path.GetFileName(GetAbandonedTargetPath(id)));
        if (checkService && service == true) expected.Add("Service");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var child in Directory.EnumerateFileSystemEntries(_productParent))
        {
            var leaf = Path.GetFileName(child);
            var managed = leaf.Equals("Service", StringComparison.OrdinalIgnoreCase) ||
                leaf.StartsWith(".service-next-", StringComparison.OrdinalIgnoreCase) ||
                leaf.StartsWith(".service-prev-", StringComparison.OrdinalIgnoreCase) ||
                leaf.StartsWith(".service-abandoned-", StringComparison.OrdinalIgnoreCase);
            if (!managed) continue;
            if (!seen.Add(leaf)) throw new IOException("V2 Service tree case-collision sibling rejected.");
            if (leaf.Equals("Service", StringComparison.OrdinalIgnoreCase) && !checkService)
            {
                if (leaf != "Service") throw new IOException("V2 Service tree canonical name differs.");
                var canonicalAttributes = File.GetAttributes(child);
                if ((canonicalAttributes & (FileAttributes.Directory | FileAttributes.ReparsePoint |
                    FileAttributes.Device)) != FileAttributes.Directory)
                    throw new IOException("V2 Service tree canonical sibling is unsafe.");
                continue;
            }
            if (!expected.Remove(leaf))
                throw new IOException("V2 Service tree managed sibling conflict or foreign residue.");
            var attributes = File.GetAttributes(child);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) !=
                FileAttributes.Directory)
                throw new IOException("V2 Service tree sibling is not an ordinary directory.");
        }
        if (expected.Count != 0) throw new IOException("V2 Service tree required sibling is absent.");
    }

    private static void RequireExactTree(string root, ImmutableArray<TrustedManifestV2File> inventory)
    {
        var expectedFiles = inventory.Select(static f => f.Path).Concat([Manifest, Metadata]).ToArray();
        var directories = ImpliedDirectories(inventory);
        var expected = expectedFiles.Concat(directories).ToHashSet(StringComparer.Ordinal);
        var directorySet = directories.ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<(string Path, string Relative)>();
        pending.Push((root, ""));
        while (pending.Count != 0)
        {
            var current = pending.Pop();
            foreach (var child in Directory.EnumerateFileSystemEntries(current.Path))
            {
                var relative = current.Relative.Length == 0 ? Path.GetFileName(child) :
                    current.Relative + "/" + Path.GetFileName(child);
                if (seen.Count >= TrustedManifestV2Codec.MaximumFiles * TrustedManifestV2Codec.MaximumDepth + 2 ||
                    !seen.Add(relative) || !expected.Contains(relative))
                    throw new IOException("V2 Service tree contains an unapproved entry.");
                var attributes = File.GetAttributes(child);
                if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
                    ((attributes & FileAttributes.Directory) != 0) != directorySet.Contains(relative))
                    throw new IOException("V2 Service tree contains an unsafe entry.");
                if (directorySet.Contains(relative)) pending.Push((child, relative));
            }
        }
        if (seen.Count != expected.Count) throw new IOException("V2 Service tree is incomplete.");
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

    private static string ResolveContained(string root, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative) || relative.Contains('\\') || relative.Contains(':') ||
            Path.IsPathRooted(relative) || relative.Split('/').Any(static part => part is "" or "." or ".."))
            throw new IOException("V2 Service tree relative path rejected.");
        var path = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!ComponentInspectionSource.Contained(root, path))
            throw new IOException("V2 Service tree relative path escaped its root.");
        return path;
    }

    private static string CanonicalRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            path.StartsWith("\\\\", StringComparison.Ordinal) ||
            path.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            path.StartsWith("\\\\.\\", StringComparison.Ordinal))
            throw new ArgumentException("V2 Service tree root must be an ordinary absolute path.", nameof(path));
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!string.Equals(Path.TrimEndingDirectorySeparator(path), full, StringComparison.OrdinalIgnoreCase) ||
            full.AsSpan(Path.GetPathRoot(full)!.Length).Contains(':') ||
            Same(full, Path.GetPathRoot(full)!))
            throw new ArgumentException("V2 Service tree root cannot be a volume root.", nameof(path));
        return full;
    }

    private static bool Same(string left, string right) =>
        string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);

    private static bool Overlaps(string left, string right)
    {
        left = Path.TrimEndingDirectorySeparator(Path.GetFullPath(left));
        right = Path.TrimEndingDirectorySeparator(Path.GetFullPath(right));
        return Same(left, right) || left.StartsWith(right + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase) || right.StartsWith(left + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameDirectoryIdentity(ComponentInspectionNative.Metadata left,
        ComponentInspectionNative.Metadata right) => left.IsDirectory && right.IsDirectory &&
        !left.IsReparsePoint && !right.IsReparsePoint && left.VolumeSerial == right.VolumeSerial &&
        left.Identity == right.Identity;

    private static void RequireIdentity(ReleaseIdentity identity)
    {
        if (identity is not { IsValid: true, Generation: ReleaseGeneration.V2 })
            throw new ArgumentException("Expected V2 Service tree identity is invalid.", nameof(identity));
    }

    private static string RequireId(string id)
    {
        if (!V2UpdateTransactionJournalCodec.IsId(id))
            throw new ArgumentException("V2 Service tree transaction identifier is invalid.", nameof(id));
        return id;
    }

    private void Checkpoint(string stage, int index = -1, string? relative = null) =>
        _fault?.Invoke(new(stage, index, relative));

    private sealed class HeldTree(string root) : IDisposable
    {
        private readonly List<(string Path, SafeFileHandle Handle, ComponentInspectionNative.Metadata Before)> _held = [];
        internal ComponentInspectionNative.Metadata RootMetadata => _held.Single(item => Same(item.Path, root)).Before;
        internal void Add(string path, SafeFileHandle handle)
        {
            try { _held.Add((path, handle, ComponentInspectionNative.GetMetadata(handle))); }
            catch { handle.Dispose(); throw; }
        }
        internal SafeFileHandle Get(string path) => _held.Single(item => Same(item.Path, path)).Handle;
        internal void Recheck(bool enforceAcl, bool serviceTree)
        {
            foreach (var item in _held)
            {
                var now = ComponentInspectionNative.GetMetadata(item.Handle);
                var changed = item.Before.IsDirectory
                    ? !SameDirectoryIdentity(item.Before, now)
                    : now != item.Before;
                if (changed || !Same(ComponentInspectionNative.FinalPath(item.Handle), item.Path) ||
                    !ComponentInspectionNative.HasOnlyDefaultDataStream(item.Handle, item.Before.IsDirectory) ||
                    (!item.Before.IsDirectory && ComponentInspectionNative.GetHardLinkCount(item.Handle) != 1))
                    throw new IOException("V2 Service tree retained object binding changed.");
                if (!enforceAcl) continue;
                if (serviceTree)
                {
                    if (item.Before.IsDirectory) V2ServiceTreeFileSystemSecurity.RequireDirectoryAcl(item.Handle);
                    else V2ServiceTreeFileSystemSecurity.RequireFileAcl(item.Handle);
                }
                else
                {
                    if (item.Before.IsDirectory) V2ArtifactFileSystemSecurity.RequireDirectoryAcl(item.Handle);
                    else V2ArtifactFileSystemSecurity.RequireFileAcl(item.Handle);
                }
            }
        }
        public void Dispose()
        {
            for (var i = _held.Count - 1; i >= 0; i--) _held[i].Handle.Dispose();
        }
    }
}
