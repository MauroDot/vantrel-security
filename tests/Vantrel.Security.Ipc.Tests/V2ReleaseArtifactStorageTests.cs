using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class V2ReleaseArtifactStorageTests
{
    private const string TransactionId = "11111111111111111111111111111111";
    private const string BackupId = "22222222222222222222222222222222";
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);

    [TestMethod]
    public void Protected_artifact_descriptors_allow_only_administrators_and_system()
    {
        var directory = V2ArtifactFileSystemSecurity.CreateDirectoryDescriptor();
        var file = V2ArtifactFileSystemSecurity.CreateFileDescriptor();
        Assert.IsTrue(V2ArtifactFileSystemSecurity.ValidateDirectoryDescriptor(directory).IsMatch);
        Assert.IsTrue(V2ArtifactFileSystemSecurity.ValidateFileDescriptor(file).IsMatch);

        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        directory.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.Read,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        file.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.Read,
            AccessControlType.Allow));
        Assert.IsFalse(V2ArtifactFileSystemSecurity.ValidateDirectoryDescriptor(directory).IsMatch);
        Assert.IsFalse(V2ArtifactFileSystemSecurity.ValidateFileDescriptor(file).IsMatch);
    }

    [TestMethod]
    public async Task Protected_v2_artifact_acl_round_trip_requires_administrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("Windows is required for the protected artifact ACL test.");
            return;
        }
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Assert.Inconclusive("An elevated Administrator token is required for the protected artifact ACL test.");
            return;
        }

        using var scope = new Scope(enforceAcls: true);
        var candidate = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "target apphost"),
            ("deps/nested/Microsoft.Extensions.Hosting.dll", "target dependency"));
        var predecessor = scope.WriteSignedRelease(scope.InstalledRoot, 7,
            ("Vantrel.Security.Service.exe", "predecessor apphost"),
            ("deps/Old.Dependency.dll", "predecessor dependency"));

        await scope.Storage.CopyPrivateCandidateAsync(TransactionId, candidate, CancellationToken.None);
        await scope.Storage.CopyPredecessorBackupAsync(BackupId, predecessor, CancellationToken.None);

        var candidateRoot = scope.PrivateDestination(TransactionId);
        var backupRoot = scope.BackupDestination(BackupId);
        foreach (var path in new[]
        {
            scope.ArtifactRoot,
            Path.Combine(scope.ArtifactRoot, "Transactions"),
            Path.Combine(scope.ArtifactRoot, "Backups"),
            Path.GetDirectoryName(candidateRoot)!,
            candidateRoot,
            backupRoot
        }.Concat(Directory.GetDirectories(candidateRoot, "*", SearchOption.AllDirectories))
            .Concat(Directory.GetDirectories(backupRoot, "*", SearchOption.AllDirectories)))
            AssertProtectedDirectoryOnDisk(path);

        foreach (var path in Directory.GetFiles(candidateRoot, "*", SearchOption.AllDirectories)
            .Concat(Directory.GetFiles(backupRoot, "*", SearchOption.AllDirectories)))
            AssertProtectedFileOnDisk(path);

        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(candidateRoot, CancellationToken.None)).Result);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(backupRoot, CancellationToken.None)).Result);
        Assert.AreEqual(V2ArtifactObservationState.Authenticated,
            (await scope.Storage.ObservePrivateCandidateAsync(TransactionId, candidate,
                CancellationToken.None)).State);
        Assert.AreEqual(V2ArtifactObservationState.Authenticated,
            (await scope.Storage.ObservePredecessorBackupAsync(BackupId, predecessor,
                CancellationToken.None)).State);

        await scope.Storage.RetirePrivateCandidateAsync(TransactionId, candidate, CancellationToken.None);
        await scope.Storage.RetirePredecessorBackupAsync(BackupId, predecessor, CancellationToken.None);
        Assert.IsFalse(Directory.Exists(candidateRoot));
        Assert.IsFalse(Directory.Exists(Path.GetDirectoryName(candidateRoot)!));
        Assert.IsFalse(Directory.Exists(backupRoot));
        Assert.AreEqual(0, Directory.GetFileSystemEntries(Path.Combine(scope.ArtifactRoot, "Transactions")).Length);
        Assert.AreEqual(0, Directory.GetFileSystemEntries(Path.Combine(scope.ArtifactRoot, "Backups")).Length);
    }

    [TestMethod]
    public void Unavailable_hard_link_count_is_rejected()
    {
        using var invalid = new SafeFileHandle(nint.Zero, ownsHandle: false);
        Assert.ThrowsException<IOException>(() => ComponentInspectionNative.GetHardLinkCount(invalid));
    }

    [TestMethod]
    public async Task Observation_distinguishes_proven_absence_from_exact_authenticated_artifacts()
    {
        using var scope = new Scope();
        var target = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "target apphost"),
            ("deps/Added.dll", "target dependency"));
        var predecessor = scope.WriteSignedRelease(scope.InstalledRoot, 7,
            ("Vantrel.Security.Service.exe", "predecessor apphost"));

        var absentPrivate = await scope.Storage.ObservePrivateCandidateAsync(TransactionId, target,
            CancellationToken.None);
        var absentBackup = await scope.Storage.ObservePredecessorBackupAsync(BackupId, predecessor,
            CancellationToken.None);
        Assert.AreEqual(V2ArtifactObservationState.Absent, absentPrivate.State);
        Assert.IsNull(absentPrivate.Evidence);
        Assert.AreEqual(V2ArtifactObservationState.Absent, absentBackup.State);
        Assert.IsNull(absentBackup.Evidence);

        await scope.Storage.CopyPrivateCandidateAsync(TransactionId, target, CancellationToken.None);
        await scope.Storage.CopyPredecessorBackupAsync(BackupId, predecessor, CancellationToken.None);
        var privateObserved = await scope.Storage.ObservePrivateCandidateAsync(TransactionId, target,
            CancellationToken.None);
        var backupObserved = await scope.Storage.ObservePredecessorBackupAsync(BackupId, predecessor,
            CancellationToken.None);
        Assert.AreEqual(V2ArtifactObservationState.Authenticated, privateObserved.State);
        Assert.AreEqual(target, privateObserved.Evidence!.Identity);
        Assert.AreEqual(V2ArtifactRole.PrivateCandidate, privateObserved.Evidence.Role);
        Assert.AreEqual(TransactionId, privateObserved.Evidence.ArtifactId);
        Assert.AreEqual(V2ArtifactObservationState.Authenticated, backupObserved.State);
        Assert.AreEqual(predecessor, backupObserved.Evidence!.Identity);
        Assert.AreEqual(V2ArtifactRole.PredecessorBackup, backupObserved.Evidence.Role);
        Assert.AreEqual(BackupId, backupObserved.Evidence.ArtifactId);
        Assert.AreEqual(V2ArtifactObservationState.InvalidOrUnavailable,
            (await scope.Storage.ObservePrivateCandidateAsync(TransactionId, predecessor,
                CancellationToken.None)).State);
    }

    [TestMethod]
    public async Task Observation_rejects_partial_and_foreign_role_residue_without_creating_or_repairing()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var partial = scope.PrivateDestination(TransactionId);
        Directory.CreateDirectory(partial);
        File.WriteAllText(Path.Combine(partial, "partial.bin"), "untrusted");
        Assert.AreEqual(V2ArtifactObservationState.InvalidOrUnavailable,
            (await scope.Storage.ObservePrivateCandidateAsync(TransactionId, expected,
                CancellationToken.None)).State);
        Assert.IsTrue(File.Exists(Path.Combine(partial, "partial.bin")),
            "Read-only observation must not clean uncertain residue.");

        Directory.CreateDirectory(Path.Combine(scope.ArtifactRoot, "Backups", TransactionId));
        Assert.AreEqual(V2ArtifactObservationState.InvalidOrUnavailable,
            (await scope.Storage.ObservePredecessorBackupAsync(BackupId, expected,
                CancellationToken.None)).State);
        Assert.IsFalse(Directory.Exists(scope.BackupDestination(BackupId)));
    }

    [TestMethod]
    public async Task Observation_never_treats_missing_role_infrastructure_as_artifact_absence()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var branch = Path.Combine(scope.ArtifactRoot, "Backups");
        Directory.Delete(branch);

        var observed = await scope.Storage.ObservePredecessorBackupAsync(BackupId, expected,
            CancellationToken.None);
        Assert.AreEqual(V2ArtifactObservationState.InvalidOrUnavailable, observed.State);
        Assert.IsNull(observed.Evidence);
        Assert.IsFalse(Directory.Exists(branch), "Read-only observation must not repair infrastructure.");
    }

    [TestMethod]
    public async Task Observation_rejects_mutated_or_missing_runtime_bytes_and_role_siblings()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/Added.dll", "dependency"));
        await scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected, CancellationToken.None);
        var destination = scope.PrivateDestination(TransactionId);
        var dependency = Path.Combine(destination, "deps", "Added.dll");
        File.AppendAllText(dependency, "mutated");
        Assert.AreEqual(V2ArtifactObservationState.InvalidOrUnavailable,
            (await scope.Storage.ObservePrivateCandidateAsync(TransactionId, expected,
                CancellationToken.None)).State);

        File.Delete(dependency);
        Assert.AreEqual(V2ArtifactObservationState.InvalidOrUnavailable,
            (await scope.Storage.ObservePrivateCandidateAsync(TransactionId, expected,
                CancellationToken.None)).State);

        File.WriteAllText(dependency, "dependency");
        Assert.AreEqual(V2ArtifactObservationState.Authenticated,
            (await scope.Storage.ObservePrivateCandidateAsync(TransactionId, expected,
                CancellationToken.None)).State);
        Directory.CreateDirectory(Path.Combine(scope.ArtifactRoot, "Transactions", BackupId));
        Assert.AreEqual(V2ArtifactObservationState.InvalidOrUnavailable,
            (await scope.Storage.ObservePrivateCandidateAsync(TransactionId, expected,
                CancellationToken.None)).State);
    }

    [TestMethod]
    public async Task Private_copy_freshly_authenticates_a_signed_variable_inventory()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/Microsoft.Extensions.Hosting.dll", "managed dependency"),
            ("deps/new/Added.Dependency.dll", "added dependency"),
            ("runtimes/win-x64/native/helper.dll", "native dependency"));

        var copy = await scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None);

        Assert.AreEqual(expected, copy.Identity);
        var source = await scope.Verifier.VerifyChainAsync(scope.StagedRoot, CancellationToken.None);
        var destination = await scope.Verifier.VerifyChainAsync(scope.PrivateDestination(TransactionId),
            CancellationToken.None);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated, source.Result);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated, destination.Result);
        Assert.AreEqual(expected, destination.Release!.Identity);
        AssertInventoryEqual(source.Release!.RuntimeInventory, destination.Release.RuntimeInventory);
        AssertInventoryEqual(source.Release.RuntimeInventory, copy.RuntimeInventory);
        Assert.AreEqual(4, destination.Release.RuntimeInventory.Length);
        AssertExactArtifactTree(scope.PrivateDestination(TransactionId), destination.Release.RuntimeInventory);
        foreach (var sidecar in new[] { "Vantrel.Security.TrustedManifest", "Vantrel.Security.ReleaseMetadata" })
            CollectionAssert.AreEqual(File.ReadAllBytes(Path.Combine(scope.StagedRoot, sidecar)),
                File.ReadAllBytes(Path.Combine(scope.PrivateDestination(TransactionId), sidecar)), sidecar);
    }

    [TestMethod]
    public async Task Candidate_and_backup_use_distinct_freshly_authenticated_inventories()
    {
        using var scope = new Scope();
        var target = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "target apphost"),
            ("deps/Added.dll", "target dependency"));
        var predecessor = scope.WriteSignedRelease(scope.InstalledRoot, 7,
            ("Vantrel.Security.Service.exe", "predecessor apphost"),
            ("deps/Removed.dll", "predecessor dependency"),
            ("runtimes/win-x64/native/old.dll", "predecessor native"));

        var candidate = await scope.Storage.CopyPrivateCandidateAsync(TransactionId, target,
            CancellationToken.None);
        var backup = await scope.Storage.CopyPredecessorBackupAsync(BackupId, predecessor,
            CancellationToken.None);

        Assert.AreEqual(target, candidate.Identity);
        Assert.AreEqual(predecessor, backup.Identity);
        Assert.AreEqual(2, candidate.RuntimeInventory.Length);
        Assert.AreEqual(3, backup.RuntimeInventory.Length);
        Assert.IsFalse(candidate.RuntimeInventory.SequenceEqual(backup.RuntimeInventory));
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.PrivateDestination(TransactionId),
                CancellationToken.None)).Result);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.BackupDestination(BackupId),
                CancellationToken.None)).Result);
    }

    [TestMethod]
    public async Task Changed_source_or_wrong_expected_identity_cannot_be_copied()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/Microsoft.Extensions.Hosting.dll", "dependency"));
        var wrong = expected with { ManifestSha256 = new string('A', 64) };

        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId, wrong,
            CancellationToken.None));
        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));

        File.AppendAllText(Path.Combine(scope.StagedRoot, "deps", "Microsoft.Extensions.Hosting.dll"),
            "mutated");
        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));
        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));
    }

    [TestMethod]
    public async Task Existing_destination_cannot_be_merged_or_overwritten()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var destination = scope.PrivateDestination(TransactionId);
        Directory.CreateDirectory(destination);
        var sentinel = Path.Combine(destination, "unrelated.txt");
        File.WriteAllText(sentinel, "preserve");

        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));

        Assert.AreEqual("preserve", File.ReadAllText(sentinel));
        CollectionAssert.AreEqual(new[] { sentinel }, Directory.GetFiles(destination));
    }

    [TestMethod]
    public async Task Unrelated_sibling_in_role_root_blocks_new_copy()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var sibling = Path.Combine(scope.ArtifactRoot, "Transactions", BackupId);
        Directory.CreateDirectory(sibling);
        File.WriteAllText(Path.Combine(sibling, "unknown.txt"), "preserve");

        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));

        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));
        Assert.AreEqual("preserve", File.ReadAllText(Path.Combine(sibling, "unknown.txt")));
    }

    [TestMethod]
    public async Task Unexpected_transaction_sibling_added_during_copy_blocks_completion()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var parent = Path.GetDirectoryName(scope.PrivateDestination(TransactionId))!;
        var extra = Path.Combine(parent, "unexpected.txt");
        var inserted = false;
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage != "BeforeFinalVerification") return;
            File.WriteAllText(extra, "preserve");
            inserted = true;
        });

        await AssertFailsAsync(() => storage.CopyPrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));

        Assert.IsTrue(inserted);
        Assert.AreEqual("preserve", File.ReadAllText(extra));
        Assert.IsTrue(Directory.Exists(scope.PrivateDestination(TransactionId)));
    }

    [TestMethod]
    public async Task Full_retirement_requires_fresh_authentication_and_exact_identity()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/sub/One.dll", "one"),
            ("deps/sub/Two.dll", "two"));
        await scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected, CancellationToken.None);
        var destination = scope.PrivateDestination(TransactionId);

        await AssertFailsAsync(() => scope.Storage.RetirePrivateCandidateAsync(TransactionId,
            expected with { ManifestSha256 = new string('B', 64) }, CancellationToken.None));
        Assert.IsTrue(Directory.Exists(destination));

        var dependency = Path.Combine(destination, "deps", "sub", "Two.dll");
        File.AppendAllText(dependency, "tampered");
        await AssertFailsAsync(() => scope.Storage.RetirePrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));
        Assert.IsTrue(File.Exists(dependency));
    }

    [TestMethod]
    public async Task Valid_complete_nested_artifact_retires_bottom_up()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.InstalledRoot, 7,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/sub/One.dll", "one"),
            ("runtimes/win-x64/native/helper.dll", "native"));
        await scope.Storage.CopyPredecessorBackupAsync(BackupId, expected, CancellationToken.None);

        await scope.Storage.RetirePredecessorBackupAsync(BackupId, expected, CancellationToken.None);

        Assert.IsFalse(Directory.Exists(scope.BackupDestination(BackupId)));
    }

    [TestMethod]
    public async Task Valid_private_candidate_retires_its_exact_transaction_container()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/sub/One.dll", "one"));
        await scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected, CancellationToken.None);

        await scope.Storage.RetirePrivateCandidateAsync(TransactionId, expected, CancellationToken.None);

        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));
        Assert.IsFalse(Directory.Exists(Path.GetDirectoryName(scope.PrivateDestination(TransactionId))!));
    }

    [TestMethod]
    public async Task Interrupted_retirement_leaves_blocking_residue_without_retry_success()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/One.dll", "one"));
        await scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected, CancellationToken.None);
        var destination = scope.PrivateDestination(TransactionId);
        var reached = false;
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage != "AfterRetirementDelete" || checkpoint.FileIndex != 0) return;
            reached = true;
            throw new IOException("Synthetic retirement interruption.");
        });

        await AssertFailsAsync(() => storage.RetirePrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));

        Assert.IsTrue(reached);
        Assert.IsTrue(Directory.Exists(destination));
        Assert.IsTrue(File.Exists(Path.Combine(destination, "Vantrel.Security.TrustedManifest")));
        await AssertFailsAsync(() => scope.Storage.RetirePrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));
    }

    [DataTestMethod]
    [DataRow("BeforeRoot", -1, false)]
    [DataRow("AfterRoot", -1, true)]
    [DataRow("BeforeDirectory", -1, true)]
    [DataRow("BeforeFile", 0, true)]
    [DataRow("AfterFile", 0, true)]
    [DataRow("BeforeFile", 1, true)]
    [DataRow("AfterFile", 1, true)]
    [DataRow("BeforeFile", 2, true)]
    [DataRow("AfterFile", 2, true)]
    [DataRow("BeforeSidecars", -1, true)]
    [DataRow("AfterSidecars", -1, true)]
    [DataRow("BeforeFinalVerification", -1, true)]
    public async Task Copy_fault_never_returns_evidence_or_merges_with_residue(
        string stage, int fileIndex, bool rootExpected)
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/One.dll", "one"),
            ("deps/nested/Two.dll", "two"));
        var reached = false;
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage == stage &&
                (fileIndex < 0 || checkpoint.FileIndex == fileIndex))
            {
                reached = true;
                throw new IOException("Synthetic copy interruption.");
            }
        });

        await AssertFailsAsync(() => storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));

        var destination = scope.PrivateDestination(TransactionId);
        Assert.IsTrue(reached, "The requested fault checkpoint was not reached.");
        Assert.AreEqual(rootExpected, Directory.Exists(destination));
        if (rootExpected)
            await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId,
                expected, CancellationToken.None));
    }

    [DataTestMethod]
    [DataRow("file")]
    [DataRow("directory")]
    public async Task Unknown_residue_is_preserved_and_prevents_retry(string kind)
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/One.dll", "one"));
        var destination = scope.PrivateDestination(TransactionId);
        var unexpected = Path.Combine(destination, "unrecognized");
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage != "AfterRoot") return;
            if (kind == "file") File.WriteAllText(unexpected, "preserve");
            else Directory.CreateDirectory(unexpected);
            throw new IOException("Synthetic interruption with unknown residue.");
        });

        await AssertFailsAsync(() => storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));

        Assert.IsTrue(kind == "file" ? File.Exists(unexpected) : Directory.Exists(unexpected));
        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));
        Assert.IsTrue(kind == "file" ? File.Exists(unexpected) : Directory.Exists(unexpected));
    }

    [TestMethod]
    public async Task Source_mutation_after_authentication_fails_at_copied_byte_hash()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/Microsoft.Extensions.Hosting.dll", "hosting"));
        var mutated = false;
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage != "AfterFile" || checkpoint.FileIndex != 0 || mutated) return;
            mutated = true;
            File.AppendAllText(Path.Combine(scope.StagedRoot, "deps", "Microsoft.Extensions.Hosting.dll"),
                "changed after authentication");
        });

        await AssertFailsAsync(() => storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));

        Assert.IsTrue(mutated);
        Assert.IsTrue(Directory.Exists(scope.PrivateDestination(TransactionId)));
        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));
    }

    [DataTestMethod]
    [DataRow("Vantrel.Security.TrustedManifest")]
    [DataRow("Vantrel.Security.ReleaseMetadata")]
    public async Task Sidecar_mutation_after_source_authentication_cannot_complete_copy(string sidecar)
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var reached = false;
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage != "BeforeSidecars") return;
            reached = true;
            File.AppendAllText(Path.Combine(scope.StagedRoot, sidecar), "mutated");
        });

        await AssertFailsAsync(() => storage.CopyPrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));

        Assert.IsTrue(reached);
        Assert.IsTrue(Directory.Exists(scope.PrivateDestination(TransactionId)));
    }

    [DataTestMethod]
    [DataRow("missing-runtime")]
    [DataRow("extra-file")]
    [DataRow("extra-directory")]
    [DataRow("changed-manifest")]
    [DataRow("changed-metadata")]
    public async Task Incomplete_or_unlisted_source_tree_never_creates_artifact(string mutation)
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/One.dll", "one"));
        switch (mutation)
        {
            case "missing-runtime": File.Delete(Path.Combine(scope.StagedRoot, "deps", "One.dll")); break;
            case "extra-file": File.WriteAllText(Path.Combine(scope.StagedRoot, "extra.dll"), "extra"); break;
            case "extra-directory": Directory.CreateDirectory(Path.Combine(scope.StagedRoot, "empty")); break;
            case "changed-manifest": File.AppendAllText(Path.Combine(scope.StagedRoot,
                "Vantrel.Security.TrustedManifest"), "changed"); break;
            case "changed-metadata": File.AppendAllText(Path.Combine(scope.StagedRoot,
                "Vantrel.Security.ReleaseMetadata"), "changed"); break;
        }

        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));

        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));
    }

    [DataTestMethod]
    [DataRow("leaf")]
    [DataRow("ancestor")]
    public async Task Destination_reparse_path_is_rejected_without_following_target_when_privileged(string kind)
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var destination = scope.PrivateDestination(TransactionId);
        var linkedPath = kind == "leaf" ? destination : Path.GetDirectoryName(destination)!;
        var outside = Path.Combine(scope.Root, "outside-destination");
        Directory.CreateDirectory(outside);
        Directory.CreateDirectory(Path.GetDirectoryName(linkedPath)!);
        try { Directory.CreateSymbolicLink(linkedPath, outside); }
        catch (Exception error) when (IsPrivilegeNotHeld(error))
        { Assert.Inconclusive("Directory symlink privilege is unavailable."); return; }
        if (kind == "ancestor") Directory.CreateDirectory(Path.Combine(outside, "candidate"));

        var inspectedPath = kind == "leaf" ? linkedPath : destination;
        await AssertFailsAsync(() => Task.Run(() =>
        {
            using var handle = V2ArtifactFileSystemSecurity.OpenValidatedDirectory(inspectedPath,
                enforceAcl: false);
        }));

        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));

        var outsideEntries = Directory.GetFileSystemEntries(outside);
        Assert.AreEqual(kind == "ancestor" ? 1 : 0, outsideEntries.Length);
        if (kind == "ancestor")
            Assert.AreEqual(Path.Combine(outside, "candidate"), outsideEntries[0]);
    }

    [DataTestMethod]
    [DataRow("runtime")]
    [DataRow("manifest")]
    [DataRow("metadata")]
    [DataRow("extra-file")]
    [DataRow("extra-directory")]
    public async Task Full_retirement_refuses_tampering_and_unexpected_objects(string mutation)
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/One.dll", "one"));
        await scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected, CancellationToken.None);
        var destination = scope.PrivateDestination(TransactionId);
        switch (mutation)
        {
            case "runtime": File.AppendAllText(Path.Combine(destination, "deps", "One.dll"), "changed"); break;
            case "manifest": File.AppendAllText(Path.Combine(destination, "Vantrel.Security.TrustedManifest"), "changed"); break;
            case "metadata": File.AppendAllText(Path.Combine(destination, "Vantrel.Security.ReleaseMetadata"), "changed"); break;
            case "extra-file": File.WriteAllText(Path.Combine(destination, "extra.dll"), "extra"); break;
            case "extra-directory": Directory.CreateDirectory(Path.Combine(destination, "empty")); break;
        }

        await AssertFailsAsync(() => scope.Storage.RetirePrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));

        Assert.IsTrue(Directory.Exists(destination));
        Assert.IsTrue(File.Exists(Path.Combine(destination, "Vantrel.Security.TrustedManifest")));
    }

    [TestMethod]
    public async Task Retirement_sidecar_mutation_after_first_authentication_cannot_delete_any_file()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/One.dll", "one"));
        await scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected, CancellationToken.None);
        var destination = scope.PrivateDestination(TransactionId);
        var originalPaths = Directory.GetFiles(destination, "*", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.Ordinal).ToArray();
        var called = false;
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage != "AfterRetirementAuthentication") return;
            called = true;
            File.AppendAllText(Path.Combine(destination, "Vantrel.Security.ReleaseMetadata"), "mutated");
        });

        await AssertFailsAsync(() => storage.RetirePrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));

        Assert.IsTrue(called);
        CollectionAssert.AreEqual(originalPaths, Directory.GetFiles(destination, "*", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.Ordinal).ToArray());
        Assert.IsTrue(Directory.Exists(destination));
    }

    [TestMethod]
    public async Task Locked_unlisted_source_file_is_not_skipped_from_fresh_authentication()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var extra = Path.Combine(scope.StagedRoot, "inaccessible-extra.dll");
        File.WriteAllText(extra, "unlisted");
        using var unavailable = new FileStream(extra, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));

        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));
    }

    [TestMethod]
    public async Task Extra_source_file_added_after_initial_authentication_blocks_completion()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var inserted = false;
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage != "BeforeFinalVerification") return;
            File.WriteAllText(Path.Combine(scope.StagedRoot, "unlisted.dll"), "extra");
            inserted = true;
        });

        await AssertFailsAsync(() => storage.CopyPrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));

        Assert.IsTrue(inserted);
        Assert.IsTrue(Directory.Exists(scope.PrivateDestination(TransactionId)));
    }

    [TestMethod]
    public async Task Missing_artifact_does_not_count_as_successful_retirement()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));

        await AssertFailsAsync(() => scope.Storage.RetirePrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));
    }

    [TestMethod]
    public async Task Cancellation_before_copy_creates_no_artifact()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await AssertCancelledAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId,
            expected, cancellation.Token));

        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));
    }

    [TestMethod]
    public async Task Cancellation_after_root_creation_leaves_nonmergeable_residue()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/One.dll", "one"));
        using var cancellation = new CancellationTokenSource();
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage == "AfterRoot") cancellation.Cancel();
        });

        await AssertCancelledAsync(() => storage.CopyPrivateCandidateAsync(TransactionId,
            expected, cancellation.Token));

        Assert.IsTrue(Directory.Exists(scope.PrivateDestination(TransactionId)));
        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));
    }

    [TestMethod]
    public async Task Case_colliding_partial_residue_fails_create_new_and_remains_occupied()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var collision = Path.Combine(scope.PrivateDestination(TransactionId),
            "vantrel.security.service.exe");
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage == "AfterRoot") File.WriteAllText(collision, "colliding residue");
        });

        await AssertFailsAsync(() => storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));

        Assert.AreEqual("colliding residue", File.ReadAllText(collision));
        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));
        Assert.AreEqual("colliding residue", File.ReadAllText(collision));
    }

    [TestMethod]
    public async Task Symlink_partial_residue_is_preserved_without_following_it_when_privileged()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        var outside = Path.Combine(scope.Root, "outside-residue.txt");
        File.WriteAllText(outside, "preserve outside");
        var probe = Path.Combine(scope.Root, "symlink-probe.txt");
        try { File.CreateSymbolicLink(probe, outside); }
        catch (Exception error) when (IsPrivilegeNotHeld(error))
        { Assert.Inconclusive("File symlink privilege is unavailable."); return; }
        File.Delete(probe);
        var residue = Path.Combine(scope.PrivateDestination(TransactionId), "unexpected-link");
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage != "AfterRoot") return;
            File.CreateSymbolicLink(residue, outside);
            throw new IOException("Synthetic interruption with symlink residue.");
        });

        await AssertFailsAsync(() => storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));

        Assert.IsTrue((File.GetAttributes(residue) & FileAttributes.ReparsePoint) != 0);
        Assert.AreEqual("preserve outside", File.ReadAllText(outside));
        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId,
            expected, CancellationToken.None));
        Assert.AreEqual("preserve outside", File.ReadAllText(outside));
    }

    [TestMethod]
    public async Task Invalid_ids_and_signed_v1_source_do_not_create_a_v2_artifact()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync("../escape", expected,
            CancellationToken.None));
        await AssertFailsAsync(() => scope.Storage.CopyPredecessorBackupAsync("ABC", expected,
            CancellationToken.None));
        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));

        scope.WriteSignedV1(scope.StagedRoot);
        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));
        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));
    }

    [DataTestMethod]
    [DataRow("runtime")]
    [DataRow("manifest")]
    [DataRow("metadata")]
    [DataRow("directory")]
    public async Task Source_reparse_object_cannot_be_copied_when_privilege_is_available(string target)
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/One.dll", "one"));
        var outside = Path.Combine(scope.Root, "outside-" + target);
        if (target == "directory")
        {
            var sourceDirectory = Path.Combine(scope.StagedRoot, "deps");
            Directory.Move(sourceDirectory, outside);
            try { Directory.CreateSymbolicLink(sourceDirectory, outside); }
            catch (Exception error) when (IsPrivilegeNotHeld(error))
            { Assert.Inconclusive("Directory symlink privilege is unavailable."); return; }
        }
        else
        {
            var sourceFile = target switch
            {
                "runtime" => Path.Combine(scope.StagedRoot, "deps", "One.dll"),
                "manifest" => Path.Combine(scope.StagedRoot, "Vantrel.Security.TrustedManifest"),
                _ => Path.Combine(scope.StagedRoot, "Vantrel.Security.ReleaseMetadata")
            };
            File.Move(sourceFile, outside);
            try { File.CreateSymbolicLink(sourceFile, outside); }
            catch (Exception error) when (IsPrivilegeNotHeld(error))
            { Assert.Inconclusive("File symlink privilege is unavailable."); return; }
        }

        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));
        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));
    }

    [DataTestMethod]
    [DataRow("runtime")]
    [DataRow("manifest")]
    [DataRow("metadata")]
    [DataRow("directory")]
    public async Task Source_named_stream_cannot_be_copied_when_volume_supports_it(string target)
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/One.dll", "one"));
        var source = target switch
        {
            "runtime" => Path.Combine(scope.StagedRoot, "deps", "One.dll"),
            "manifest" => Path.Combine(scope.StagedRoot, "Vantrel.Security.TrustedManifest"),
            "metadata" => Path.Combine(scope.StagedRoot, "Vantrel.Security.ReleaseMetadata"),
            _ => Path.Combine(scope.StagedRoot, "deps")
        };
        try { File.WriteAllText(source + ":unrecorded", "hidden"); }
        catch (Exception error) when (error is IOException or NotSupportedException or UnauthorizedAccessException)
        { Assert.Inconclusive("Named streams are unavailable on this volume."); return; }

        await AssertFailsAsync(() => scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));
        Assert.IsFalse(Directory.Exists(scope.PrivateDestination(TransactionId)));
    }

    [TestMethod]
    public async Task Hard_link_count_above_one_blocks_authenticated_retirement()
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"));
        await scope.Storage.CopyPrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None);
        var destination = scope.PrivateDestination(TransactionId);
        var original = Path.Combine(destination, "Vantrel.Security.Service.exe");
        var alternate = Path.Combine(scope.Root, "alternate-hard-link.exe");
        if (!CreateHardLink(alternate, original, nint.Zero))
        { Assert.Inconclusive("Hard-link creation is unavailable on this volume."); return; }
        using (var handle = ComponentInspectionNative.Open(original))
            Assert.AreEqual(2U, ComponentInspectionNative.GetHardLinkCount(handle));

        await AssertFailsAsync(() => scope.Storage.RetirePrivateCandidateAsync(TransactionId, expected,
            CancellationToken.None));

        Assert.IsTrue(File.Exists(alternate));
        Assert.IsTrue(File.Exists(original));
        Assert.IsTrue(Directory.Exists(destination));
    }

    [DataTestMethod]
    [DataRow("Vantrel.Security.Service.exe")]
    [DataRow("Vantrel.Security.TrustedManifest")]
    [DataRow("Vantrel.Security.ReleaseMetadata")]
    public async Task Late_hard_link_blocks_final_copy_acceptance(string attackedFile)
    {
        using var scope = new Scope();
        var expected = scope.WriteSignedRelease(scope.StagedRoot, 8,
            ("Vantrel.Security.Service.exe", "apphost"),
            ("deps/One.dll", "dependency"));
        var destination = scope.PrivateDestination(TransactionId);
        var original = Path.Combine(destination, attackedFile);
        var alternate = Path.Combine(scope.Root, "late-link-" + attackedFile);
        var inserted = false;
        var storage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage != "BeforeFinalVerification") return;
            Assert.IsTrue(File.Exists(original), "The copied file must exist before the late-link attack.");
            using (var handle = ComponentInspectionNative.Open(original))
                Assert.AreEqual(1U, ComponentInspectionNative.GetHardLinkCount(handle),
                    "The first destination link-count check must have completed before the attack.");
            Assert.IsTrue(CreateHardLink(alternate, original, nint.Zero),
                "The late hard link must be created for this acceptance test to be meaningful.");
            using (var handle = ComponentInspectionNative.Open(original))
                Assert.AreEqual(2U, ComponentInspectionNative.GetHardLinkCount(handle));
            inserted = true;
        });

        await Assert.ThrowsExceptionAsync<IOException>(() =>
            storage.CopyPrivateCandidateAsync(TransactionId, expected, CancellationToken.None));

        Assert.IsTrue(inserted, "The final-acceptance attack checkpoint was not reached.");
        Assert.IsTrue(File.Exists(original));
        Assert.IsTrue(File.Exists(alternate));
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(destination, CancellationToken.None)).Result,
            "The signed copy remains cryptographically valid; its late hard link must be rejected by the final binding.");
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string fileName, string existingFileName, nint securityAttributes);

    private static bool IsPrivilegeNotHeld(Exception error) => error.HResult == PrivilegeNotHeldHResult;

    private static void AssertProtectedDirectoryOnDisk(string path)
    {
        var descriptor = new DirectoryInfo(path).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        Assert.IsTrue(V2ArtifactFileSystemSecurity.ValidateDirectoryDescriptor(descriptor).IsMatch, path);
        AssertExactProtectedAcl(descriptor,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
    }

    private static void AssertProtectedFileOnDisk(string path)
    {
        var descriptor = new FileInfo(path).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        Assert.IsTrue(V2ArtifactFileSystemSecurity.ValidateFileDescriptor(descriptor).IsMatch, path);
        AssertExactProtectedAcl(descriptor, InheritanceFlags.None);
    }

    private static void AssertExactProtectedAcl(FileSystemSecurity descriptor,
        InheritanceFlags inheritance)
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        Assert.IsTrue(descriptor.AreAccessRulesProtected);
        Assert.AreEqual(administrators, descriptor.GetOwner(typeof(SecurityIdentifier)));
        var rules = descriptor.GetAccessRules(includeExplicit: true, includeInherited: true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.AreEqual(2, rules.Length);
        foreach (var sid in new[] { administrators, system })
            Assert.AreEqual(1, rules.Count(rule =>
                rule.IdentityReference.Equals(sid) && !rule.IsInherited &&
                rule.AccessControlType == AccessControlType.Allow &&
                rule.FileSystemRights == FileSystemRights.FullControl &&
                rule.InheritanceFlags == inheritance &&
                rule.PropagationFlags == PropagationFlags.None));
        foreach (var broadSid in new[]
        {
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null)
        })
            Assert.IsFalse(rules.Any(rule => rule.IdentityReference.Equals(broadSid)));
    }

    private static void AssertInventoryEqual(ImmutableArray<TrustedManifestV2File> expected,
        ImmutableArray<TrustedManifestV2File> actual) =>
        CollectionAssert.AreEqual(expected.ToArray(), actual.ToArray());

    private static void AssertExactArtifactTree(string root, ImmutableArray<TrustedManifestV2File> inventory)
    {
        var expected = inventory.Select(file => file.Path)
            .Concat(["Vantrel.Security.TrustedManifest", "Vantrel.Security.ReleaseMetadata"])
            .OrderBy(path => path, StringComparer.Ordinal).ToArray();
        var actual = Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/'))
            .OrderBy(path => path, StringComparer.Ordinal).ToArray();
        CollectionAssert.AreEqual(expected, actual);
        var expectedDirectories = new HashSet<string>(StringComparer.Ordinal);
        foreach (var path in expected)
            for (var slash = path.IndexOf('/'); slash >= 0; slash = path.IndexOf('/', slash + 1))
                expectedDirectories.Add(path[..slash]);
        var actualDirectories = Directory.GetDirectories(root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/')).ToArray();
        CollectionAssert.AreEquivalent(expectedDirectories.ToArray(), actualDirectories);
    }

    private static async Task AssertFailsAsync(Func<Task> operation)
    {
        try { await operation(); }
        catch (Exception error) when (error is IOException or InvalidDataException or
            UnauthorizedAccessException or InvalidOperationException or ArgumentException or
            System.ComponentModel.Win32Exception)
        { return; }
        Assert.Fail("The operation unexpectedly accepted an invalid V2 artifact.");
    }

    private static async Task AssertCancelledAsync(Func<Task> operation)
    {
        try { await operation(); }
        catch (OperationCanceledException) { return; }
        Assert.Fail("The operation unexpectedly ignored cancellation.");
    }

    private sealed class Scope : IDisposable
    {
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly bool _enforceAcls;
        internal Scope(bool enforceAcls = false)
        {
            _enforceAcls = enforceAcls;
            Directory.CreateDirectory(Path.Combine(Root, "Updates"));
            if (enforceAcls)
            {
                using var artifact = V2ArtifactFileSystemSecurity.CreateNewDirectory(ArtifactRoot);
                using var transactions = V2ArtifactFileSystemSecurity.CreateNewDirectory(
                    Path.Combine(ArtifactRoot, "Transactions"));
                using var backups = V2ArtifactFileSystemSecurity.CreateNewDirectory(
                    Path.Combine(ArtifactRoot, "Backups"));
            }
            else
            {
                Directory.CreateDirectory(Path.Combine(ArtifactRoot, "Transactions"));
                Directory.CreateDirectory(Path.Combine(ArtifactRoot, "Backups"));
            }
        }
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-v2-artifact-" +
            Guid.NewGuid().ToString("N"));
        internal string ArtifactRoot => Path.Combine(Root, "Updates", "V2Artifacts");
        internal string StagedRoot => Path.Combine(Root, "staged");
        internal string InstalledRoot => Path.Combine(Root, "installed");
        internal GenerationAwareOfflineReleaseVerifier Verifier => new(
            _metadataKey.ExportSubjectPublicKeyInfo(), _manifestKey.ExportSubjectPublicKeyInfo());
        internal V2ReleaseArtifactStorage Storage => new(Verifier, ArtifactRoot, StagedRoot,
            InstalledRoot, enforceAcls: _enforceAcls);
        internal V2ReleaseArtifactStorage StorageWithFault(Action<V2ArtifactCopyCheckpoint> fault) =>
            new(Verifier, ArtifactRoot, StagedRoot, InstalledRoot, enforceAcls: _enforceAcls, fault);
        internal string PrivateDestination(string transactionId) => Storage.GetPrivateCandidatePath(transactionId);
        internal string BackupDestination(string backupId) => Storage.GetPredecessorBackupPath(backupId);

        internal ReleaseIdentity WriteSignedRelease(string root, ulong sequence,
            params (string Path, string Content)[] runtimeFiles)
        {
            Directory.CreateDirectory(root);
            var inventory = new List<TrustedManifestV2File>();
            foreach (var (relative, content) in runtimeFiles.OrderBy(file => file.Path,
                StringComparer.Ordinal))
            {
                var path = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                var bytes = Encoding.UTF8.GetBytes(content);
                File.WriteAllBytes(path, bytes);
                inventory.Add(new(relative, Convert.ToHexString(SHA256.HashData(bytes))));
            }
            var manifest = TrustedManifestV2Codec.CreateFile("0.1.0-beta.2", sequence, inventory,
                _manifestKey);
            File.WriteAllBytes(Path.Combine(root, "Vantrel.Security.TrustedManifest"), manifest);
            var manifestHash = Convert.ToHexString(SHA256.HashData(manifest));
            File.WriteAllBytes(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"),
                ReleaseMetadataCodec.CreateFile(sequence, manifestHash, "0.1.0-beta.2",
                    new DateTimeOffset(2026, 10, 12, 12, 0, 0, TimeSpan.Zero), _metadataKey));
            return new(ReleaseGeneration.V2, sequence, manifestHash);
        }

        internal void WriteSignedV1(string root)
        {
            foreach (var entry in Directory.GetFileSystemEntries(root))
            {
                if (Directory.Exists(entry)) Directory.Delete(entry, recursive: true);
                else File.Delete(entry);
            }
            var components = new Dictionary<TrustedManifestComponent, string>();
            foreach (var (component, name) in FixedServiceReleaseFiles.Components)
            {
                var bytes = Encoding.UTF8.GetBytes("v1:" + name);
                File.WriteAllBytes(Path.Combine(root, name), bytes);
                components.Add(component, Convert.ToHexString(SHA256.HashData(bytes)));
            }
            var manifest = TrustedManifestCodec.CreateFile("0.1.0-beta.2", components,
                _manifestKey);
            File.WriteAllBytes(Path.Combine(root, "Vantrel.Security.TrustedManifest"), manifest);
            File.WriteAllBytes(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"),
                ReleaseMetadataCodec.CreateFile(7, Convert.ToHexString(SHA256.HashData(manifest)),
                    "0.1.0-beta.2", new DateTimeOffset(2026, 10, 12, 12, 0, 0, TimeSpan.Zero),
                    _metadataKey));
        }

        public void Dispose()
        {
            _manifestKey.Dispose();
            _metadataKey.Dispose();
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
