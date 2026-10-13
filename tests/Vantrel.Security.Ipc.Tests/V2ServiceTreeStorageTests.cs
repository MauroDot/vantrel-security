using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class V2ServiceTreeStorageTests
{
    private const string TransactionId = "11111111111111111111111111111111";
    private const string ForeignId = "22222222222222222222222222222222";
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);

    [DataTestMethod]
    [DataRow("Service")]
    [DataRow(".service-next-11111111111111111111111111111111")]
    [DataRow(".service-abandoned-11111111111111111111111111111111")]
    public void Native_rename_buffer_uses_full_x64_structure_plus_utf16_name(string targetLeaf)
    {
        var parent = new IntPtr(unchecked((long)0x1122334455667788));
        var nameBytes = Encoding.Unicode.GetBytes(targetLeaf);
        var buffer = V2ServiceDirectoryMoveNative.BuildRenameInformationBuffer(targetLeaf, parent);

        Assert.AreEqual(24 + nameBytes.Length, buffer.Length);
        Assert.AreEqual(0, BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(0, 4)),
            "The native no-replace field must remain false.");
        Assert.AreEqual(parent.ToInt64(), BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(8, 8)));
        Assert.AreEqual(nameBytes.Length, BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(16, 4)));
        CollectionAssert.AreEqual(nameBytes, buffer.AsSpan(20, nameBytes.Length).ToArray());
        Assert.IsTrue(buffer.AsSpan(20 + nameBytes.Length, 4).ToArray().All(value => value == 0),
            "The full x64 allocation retains four zero-filled bytes after the name.");
    }

    [TestMethod]
    public void Native_rename_buffer_rejects_invalid_and_oversized_leaf_before_allocation()
    {
        Assert.ThrowsException<IOException>(() =>
            V2ServiceDirectoryMoveNative.BuildRenameInformationBuffer("Desktop", new IntPtr(1)));
        Assert.ThrowsException<IOException>(() =>
            V2ServiceDirectoryMoveNative.BuildRenameInformationBuffer(
                ".service-next-" + new string('1', 4096), new IntPtr(1)));
    }

    [TestMethod]
    public async Task Prepared_target_copies_exact_freshly_authenticated_private_inventory()
    {
        using var scope = new Scope();
        await scope.BuildInitialAsync();

        await scope.AssertStateAsync(0);
        var source = await scope.Verifier.VerifyChainAsync(scope.PrivateCandidate, CancellationToken.None);
        var prepared = await scope.Verifier.VerifyChainAsync(scope.Prepared, CancellationToken.None);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated, source.Result);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated, prepared.Result);
        CollectionAssert.AreEqual(source.Release!.RuntimeInventory.ToArray(),
            prepared.Release!.RuntimeInventory.ToArray());
        AssertExactTree(scope.Prepared, prepared.Release.RuntimeInventory);
        Assert.IsTrue(Directory.Exists(Path.Combine(scope.ProductParent, "Desktop")),
            "An unrelated product child must be allowed and left in place.");
    }

    [TestMethod]
    public async Task Preparation_rejects_wrong_expected_identity_without_creating_a_sibling()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var wrong = new ReleaseIdentity(ReleaseGeneration.V2, 9, new string('A', 64));

        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, wrong, CancellationToken.None));

        AssertAbsent(scope.Prepared);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.PrivateCandidate, CancellationToken.None)).Result);
    }

    [TestMethod]
    public async Task Preparation_rejects_a_tampered_private_candidate()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        File.AppendAllText(Path.Combine(scope.PrivateCandidate, "deps", "Added.dll"), "tampered");

        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));

        AssertAbsent(scope.Prepared);
        Assert.AreNotEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.PrivateCandidate, CancellationToken.None)).Result);
    }

    [DataTestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task Preparation_never_merges_with_an_occupied_sibling(bool occupiedByFile)
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        if (occupiedByFile) File.WriteAllText(scope.Prepared, "occupied");
        else Directory.CreateDirectory(scope.Prepared);

        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));

        Assert.AreEqual(occupiedByFile, File.Exists(scope.Prepared));
        Assert.AreEqual(!occupiedByFile, Directory.Exists(scope.Prepared));
    }

    [TestMethod]
    public async Task Preparation_rejects_foreign_managed_sibling_but_allows_unrelated_product_child()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var foreign = Path.Combine(scope.ProductParent, ".service-prev-" + ForeignId);
        Directory.CreateDirectory(foreign);

        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));

        AssertAbsent(scope.Prepared);
        Assert.IsTrue(Directory.Exists(foreign));
        Assert.IsTrue(Directory.Exists(Path.Combine(scope.ProductParent, "Desktop")));
    }

    [DataTestMethod]
    [DataRow(".service-next-")]
    [DataRow(".service-prev-")]
    [DataRow(".service-abandoned-")]
    public async Task Every_managed_foreign_role_blocks_preparation(string prefix)
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var foreign = Path.Combine(scope.ProductParent, prefix + ForeignId);
        Directory.CreateDirectory(foreign);
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        AssertAbsent(scope.Prepared);
        Assert.IsTrue(Directory.Exists(foreign));
    }

    [DataTestMethod]
    [DataRow("Vantrel.Security.Service.exe")]
    [DataRow("Vantrel.Security.TrustedManifest")]
    [DataRow("Vantrel.Security.ReleaseMetadata")]
    public async Task A_hard_link_in_any_private_source_role_blocks_preparation(string relative)
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var source = Path.Combine(scope.PrivateCandidate, relative);
        var link = Path.Combine(scope.Root, "source-link-" + relative);
        if (!CreateHardLink(link, source, nint.Zero))
        {
            Assert.Inconclusive("Hard-link creation is unavailable on this volume.");
            return;
        }
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        AssertAbsent(scope.Prepared);
    }

    [TestMethod]
    public async Task An_unrecorded_private_runtime_file_blocks_preparation()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        File.WriteAllText(Path.Combine(scope.PrivateCandidate, "unexpected.dll"), "extra");
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        AssertAbsent(scope.Prepared);
    }

    [TestMethod]
    public async Task An_unrecorded_private_directory_blocks_preparation()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        Directory.CreateDirectory(Path.Combine(scope.PrivateCandidate, "unrecorded-directory"));
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        AssertAbsent(scope.Prepared);
    }

    [TestMethod]
    public async Task A_missing_signed_runtime_file_blocks_preparation()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        File.Delete(Path.Combine(scope.PrivateCandidate, "deps", "Added.dll"));
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        AssertAbsent(scope.Prepared);
    }

    [TestMethod]
    public void Disposable_source_and_destination_roots_cannot_overlap()
    {
        using var scope = new Scope();
        Assert.ThrowsException<IOException>(() => new V2ServiceTreeStorage(scope.Verifier,
            scope.ProductParent, Path.Combine(scope.ProductParent, "Artifact"), enforceAcls: false));
        Assert.ThrowsException<IOException>(() => new V2ServiceTreeStorage(scope.Verifier,
            scope.ArtifactRoot, scope.ArtifactRoot, enforceAcls: false));
    }

    [TestMethod]
    public async Task Cancellation_before_preparation_writes_no_sibling()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, canceled.Token));
        AssertAbsent(scope.Prepared);
    }

    [TestMethod]
    public async Task Preparation_fault_after_root_leaves_residue_and_never_returns_evidence()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var reached = false;
        var storage = scope.WithFault(checkpoint =>
        {
            if (checkpoint.Stage != "AfterRoot") return;
            reached = true;
            throw new IOException("Injected prepared-copy failure.");
        });

        await Assert.ThrowsExceptionAsync<IOException>(() =>
            storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));

        Assert.IsTrue(reached);
        Assert.IsTrue(Directory.Exists(scope.Prepared));
        Assert.AreNotEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.Prepared, CancellationToken.None)).Result);
    }

    [DataTestMethod]
    [DataRow("BeforeRoot", false)]
    [DataRow("AfterRoot", true)]
    [DataRow("BeforeDirectory", true)]
    [DataRow("BeforeFile", true)]
    [DataRow("BeforeSidecars", true)]
    [DataRow("AfterSidecars", true)]
    [DataRow("BeforeFinalVerification", true)]
    public async Task Prepared_copy_fault_boundaries_never_return_success_evidence(
        string stage, bool expectResidue)
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var reached = false;
        var storage = scope.WithFault(checkpoint =>
        {
            if (checkpoint.Stage != stage) return;
            reached = true;
            throw new IOException("Injected prepared-copy checkpoint failure.");
        });
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        Assert.IsTrue(reached);
        Assert.AreEqual(expectResidue, Directory.Exists(scope.Prepared));
    }

    [TestMethod]
    public async Task Source_write_after_authentication_cannot_produce_a_mixed_prepared_tree()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var reached = false;
        var writeDenied = false;
        var storage = scope.WithFault(checkpoint =>
        {
            if (checkpoint.Stage != "BeforeRoot") return;
            reached = true;
            try
            {
                File.AppendAllText(Path.Combine(scope.PrivateCandidate, "deps", "Added.dll"),
                    "post-authentication mutation");
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { writeDenied = true; }
        });
        var failure = await CaptureFailureOrSuccessAsync(() => storage.PrepareTargetAsync(
            TransactionId, scope.Target, CancellationToken.None));
        Assert.IsTrue(reached);
        if (writeDenied)
        {
            Assert.IsNull(failure);
            Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
                (await scope.Verifier.VerifyChainAsync(scope.Prepared, CancellationToken.None)).Result);
        }
        else
        {
            Assert.IsNotNull(failure);
            Assert.IsFalse(failure is V2ServiceTreeMoveOutcomeAmbiguousException);
        }
    }

    [DataTestMethod]
    [DataRow("Vantrel.Security.Service.exe")]
    [DataRow("Vantrel.Security.TrustedManifest")]
    [DataRow("Vantrel.Security.ReleaseMetadata")]
    public async Task Late_hard_link_blocks_prepared_target_final_acceptance(string attackedFile)
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var original = Path.Combine(scope.Prepared, attackedFile);
        var alternate = Path.Combine(scope.Root, "late-link-" + attackedFile);
        var reached = false;
        var storage = scope.WithFault(checkpoint =>
        {
            if (checkpoint.Stage != "BeforeFinalVerification") return;
            using (var handle = ComponentInspectionNative.Open(original))
                Assert.AreEqual(1U, ComponentInspectionNative.GetHardLinkCount(handle));
            if (!CreateHardLink(alternate, original, nint.Zero))
            { Assert.Inconclusive("Hard-link creation is unavailable on this volume."); return; }
            using (var handle = ComponentInspectionNative.Open(original))
                Assert.AreEqual(2U, ComponentInspectionNative.GetHardLinkCount(handle));
            reached = true;
        });

        await Assert.ThrowsExceptionAsync<IOException>(() =>
            storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));

        Assert.IsTrue(reached);
        Assert.IsTrue(File.Exists(original));
        Assert.IsTrue(File.Exists(alternate));
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.Prepared, CancellationToken.None)).Result,
            "The signed bytes remain valid; retained file security must reject the added link.");
    }

    [TestMethod]
    public async Task Forward_and_rollback_moves_each_leave_an_authenticated_classifiable_state()
    {
        using var scope = new Scope();
        await scope.BuildInitialAsync();
        await scope.AssertStateAsync(0);

        await scope.InvokeMoveAsync(0);
        await scope.AssertStateAsync(1);
        await scope.InvokeMoveAsync(1);
        await scope.AssertStateAsync(2);
        await scope.InvokeMoveAsync(2);
        await scope.AssertStateAsync(3);
        await scope.InvokeMoveAsync(3);
        await scope.AssertStateAsync(4);
    }

    [DataTestMethod]
    [DataRow(0, 0, 2)]
    [DataRow(1, 1, 0)]
    [DataRow(2, 0, 3)]
    [DataRow(3, 2, 0)]
    public async Task Each_native_move_preserves_source_volume_and_full_file_id_at_destination(
        int move, int sourceRole, int destinationRole)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var roots = new[] { scope.Canonical, scope.Prepared, scope.Detached, scope.Abandoned };
        var source = roots[sourceRole];
        var destination = roots[destinationRole];
        using var sourceHandle = ComponentInspectionNative.OpenProtected(source, directory: true);
        var before = ComponentInspectionNative.GetMetadata(sourceHandle);
        Assert.AreEqual(source, ComponentInspectionNative.FinalPath(sourceHandle),
            StringComparer.OrdinalIgnoreCase);
        AssertAbsent(destination);
        sourceHandle.Dispose(); // The native rename needs DELETE access to this physical directory.

        await scope.InvokeMoveAsync(move);

        AssertAbsent(source);
        using var destinationHandle = ComponentInspectionNative.OpenProtected(destination, directory: true);
        var after = ComponentInspectionNative.GetMetadata(destinationHandle);
        Assert.AreEqual(before.VolumeSerial, after.VolumeSerial);
        Assert.AreEqual(before.Identity, after.Identity, "The complete 64-bit file ID must follow the move.");
        Assert.AreEqual(destination, ComponentInspectionNative.FinalPath(destinationHandle),
            StringComparer.OrdinalIgnoreCase);
        await scope.AssertStateAsync(move + 1);
    }

    [DataTestMethod]
    [DataRow(0, ".service-next-")]
    [DataRow(0, ".service-prev-")]
    [DataRow(0, ".service-abandoned-")]
    [DataRow(1, ".service-next-")]
    [DataRow(1, ".service-prev-")]
    [DataRow(1, ".service-abandoned-")]
    [DataRow(2, ".service-next-")]
    [DataRow(2, ".service-prev-")]
    [DataRow(2, ".service-abandoned-")]
    [DataRow(3, ".service-next-")]
    [DataRow(3, ".service-prev-")]
    [DataRow(3, ".service-abandoned-")]
    public async Task Every_move_rejects_a_foreign_managed_sibling_without_changing_namespace(
        int move, string prefix)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var foreign = Path.Combine(scope.ProductParent, prefix + ForeignId);
        Directory.CreateDirectory(foreign);

        await Assert.ThrowsExceptionAsync<IOException>(() => scope.InvokeMoveAsync(move));

        await scope.AssertStateAsync(move);
        Assert.IsTrue(Directory.Exists(foreign));
    }

    [DataTestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    public async Task Every_move_rejects_tampered_required_tree_before_namespace_change(int move)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var tamperedRoot = move switch
        {
            0 => scope.Canonical,
            1 => scope.Prepared,
            2 => scope.Canonical,
            3 => scope.Detached,
            _ => throw new ArgumentOutOfRangeException(nameof(move))
        };
        var before = scope.ExistenceVector();
        File.AppendAllText(Path.Combine(tamperedRoot, "Vantrel.Security.Service.exe"), "tampered");

        await Assert.ThrowsExceptionAsync<IOException>(() => scope.InvokeMoveAsync(move));

        CollectionAssert.AreEqual(before, scope.ExistenceVector());
        Assert.AreNotEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(tamperedRoot, CancellationToken.None)).Result);
    }

    [DataTestMethod]
    [DataRow(0, 2)]
    [DataRow(1, 0)]
    [DataRow(2, 3)]
    [DataRow(3, 0)]
    public async Task Every_move_refuses_an_occupied_destination_without_overwriting(int move,
        int destinationRole)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var destination = new[] { scope.Canonical, scope.Prepared, scope.Detached, scope.Abandoned }
            [destinationRole];
        Directory.CreateDirectory(destination);
        var marker = Path.Combine(destination, "occupied.txt");
        File.WriteAllText(marker, "preserve");
        var prior = scope.ExistenceVector();
        var error = await CaptureFailureAsync(() => scope.InvokeMoveAsync(move));
        Assert.IsFalse(error is V2ServiceTreeMoveOutcomeAmbiguousException);
        CollectionAssert.AreEqual(prior, scope.ExistenceVector());
        Assert.AreEqual("preserve", File.ReadAllText(marker));
    }

    [DataTestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    public async Task Fault_before_each_move_attempt_preserves_the_namespace(int move)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var reached = false;
        var storage = scope.WithFault(checkpoint =>
        {
            if (checkpoint.Stage != "BeforeMoveAttempt") return;
            reached = true;
            throw new IOException("Injected pre-move failure.");
        });

        var failure = await CaptureFailureAsync(() => scope.InvokeMoveAsync(move, storage));

        Assert.IsTrue(reached);
        Assert.IsFalse(failure is V2ServiceTreeMoveOutcomeAmbiguousException,
            "A pre-attempt fault must not be marked as an attempted move.");
        await scope.AssertStateAsync(move);
    }

    [DataTestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    public async Task Cancellation_at_pre_move_checkpoint_preserves_the_namespace(int move)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        using var cancellation = new CancellationTokenSource();
        var storage = scope.WithFault(checkpoint =>
        {
            if (checkpoint.Stage == "BeforeMoveAttempt") cancellation.Cancel();
        });
        var action = move switch
        {
            0 => (Func<Task>)(() => storage.DetachPredecessorAsync(TransactionId, scope.Predecessor,
                scope.Target, cancellation.Token)),
            1 => () => storage.ActivatePreparedTargetAsync(TransactionId, scope.Predecessor,
                scope.Target, cancellation.Token),
            2 => () => storage.DetachActivatedTargetForRollbackAsync(TransactionId,
                scope.Predecessor, scope.Target, cancellation.Token),
            3 => () => storage.RestorePredecessorAsync(TransactionId, scope.Predecessor,
                scope.Target, cancellation.Token),
            _ => throw new ArgumentOutOfRangeException(nameof(move))
        };
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(action);
        await scope.AssertStateAsync(move);
    }

    [DataTestMethod]
    [DataRow(0, "AfterMove")]
    [DataRow(1, "AfterMove")]
    [DataRow(2, "AfterMove")]
    [DataRow(3, "AfterMove")]
    [DataRow(0, "DuringPostVerification")]
    [DataRow(1, "DuringPostVerification")]
    [DataRow(2, "DuringPostVerification")]
    [DataRow(3, "DuringPostVerification")]
    public async Task Fault_after_each_move_attempt_is_typed_ambiguous_and_never_compensates(
        int move, string faultStage)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var reached = false;
        var storage = scope.WithFault(checkpoint =>
        {
            if (checkpoint.Stage != faultStage) return;
            reached = true;
            throw new IOException("Injected post-attempt failure.");
        });

        await Assert.ThrowsExceptionAsync<V2ServiceTreeMoveOutcomeAmbiguousException>(() =>
            scope.InvokeMoveAsync(move, storage));

        Assert.IsTrue(reached);
        await scope.AssertStateAsync(move + 1);
    }

    [DataTestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    public async Task Attempted_rename_can_remain_at_source_and_is_still_ambiguous(int move)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var reached = false;
        var storage = scope.WithFault(checkpoint =>
        {
            if (checkpoint.Stage != "AfterMoveAttemptBeforeNative") return;
            reached = true;
            throw new IOException("Injected attempted-native failure.");
        });
        await Assert.ThrowsExceptionAsync<V2ServiceTreeMoveOutcomeAmbiguousException>(() =>
            scope.InvokeMoveAsync(move, storage));
        Assert.IsTrue(reached);
        await scope.AssertStateAsync(move);
    }

    [DataTestMethod]
    [DataRow(0, 0, 2)]
    [DataRow(1, 1, 0)]
    [DataRow(2, 0, 3)]
    [DataRow(3, 2, 0)]
    public async Task Late_destination_after_precheck_is_never_overwritten_by_native_rename(
        int move, int sourceRole, int destinationRole)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var roots = new[] { scope.Canonical, scope.Prepared, scope.Detached, scope.Abandoned };
        var source = roots[sourceRole];
        var destination = roots[destinationRole];
        ComponentInspectionNative.Metadata occupiedBefore = default;
        var reached = false;
        var storage = scope.WithFault(checkpoint =>
        {
            if (checkpoint.Stage != "AfterMoveAttemptBeforeNative") return;
            AssertAbsent(destination);
            Directory.CreateDirectory(destination);
            File.WriteAllText(Path.Combine(destination, "occupied.txt"), "preserve");
            using var occupied = ComponentInspectionNative.OpenProtected(destination, directory: true);
            occupiedBefore = ComponentInspectionNative.GetMetadata(occupied);
            reached = true;
        });

        using var sourceHandle = ComponentInspectionNative.OpenProtected(source, directory: true);
        var sourceBefore = ComponentInspectionNative.GetMetadata(sourceHandle);
        sourceHandle.Dispose();
        await Assert.ThrowsExceptionAsync<V2ServiceTreeMoveOutcomeAmbiguousException>(() =>
            scope.InvokeMoveAsync(move, storage));

        Assert.IsTrue(reached, "The destination must be introduced after native prechecks.");
        using var sourceAfterHandle = ComponentInspectionNative.OpenProtected(source, directory: true);
        var sourceAfter = ComponentInspectionNative.GetMetadata(sourceAfterHandle);
        Assert.AreEqual(sourceBefore.VolumeSerial, sourceAfter.VolumeSerial);
        Assert.AreEqual(sourceBefore.Identity, sourceAfter.Identity);
        Assert.AreEqual(source, ComponentInspectionNative.FinalPath(sourceAfterHandle),
            StringComparer.OrdinalIgnoreCase);
        using var occupiedAfter = ComponentInspectionNative.OpenProtected(destination, directory: true);
        var occupiedNow = ComponentInspectionNative.GetMetadata(occupiedAfter);
        Assert.AreEqual(occupiedBefore.VolumeSerial, occupiedNow.VolumeSerial);
        Assert.AreEqual(occupiedBefore.Identity, occupiedNow.Identity);
        Assert.AreEqual("preserve", File.ReadAllText(Path.Combine(destination, "occupied.txt")));
    }

    [DataTestMethod]
    [DataRow(0, 1)]
    [DataRow(0, 0)]
    [DataRow(1, 2)]
    [DataRow(1, 1)]
    [DataRow(2, 0)]
    [DataRow(2, 2)]
    [DataRow(3, 3)]
    [DataRow(3, 2)]
    public async Task A_wrong_authenticated_role_blocks_a_move_before_attempt(int move, int role)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        scope.ReplaceRoleWithWrongIdentity(role);
        var prior = scope.ExistenceVector();
        var error = await CaptureFailureAsync(() => scope.InvokeMoveAsync(move));
        Assert.IsFalse(error is V2ServiceTreeMoveOutcomeAmbiguousException);
        CollectionAssert.AreEqual(prior, scope.ExistenceVector());
    }

    [DataTestMethod]
    [DataRow(0, 0)]
    [DataRow(0, 1)]
    [DataRow(1, 1)]
    [DataRow(1, 2)]
    [DataRow(2, 0)]
    [DataRow(2, 2)]
    [DataRow(3, 2)]
    [DataRow(3, 3)]
    public async Task Missing_required_role_blocks_move_before_attempt(int move, int role)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var root = new[] { scope.Canonical, scope.Prepared, scope.Detached, scope.Abandoned }[role];
        Assert.IsTrue(Path.GetFullPath(root).StartsWith(Path.GetFullPath(scope.ProductParent) +
            Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
        Directory.Delete(root, recursive: true);
        var prior = scope.ExistenceVector();
        var error = await CaptureFailureAsync(() => scope.InvokeMoveAsync(move));
        Assert.IsFalse(error is V2ServiceTreeMoveOutcomeAmbiguousException);
        CollectionAssert.AreEqual(prior, scope.ExistenceVector());
    }

    [DataTestMethod]
    [DataRow(0, 0)]
    [DataRow(1, 1)]
    [DataRow(2, 0)]
    [DataRow(3, 2)]
    public async Task Unapproved_nested_file_in_required_role_blocks_move(int move, int role)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var root = new[] { scope.Canonical, scope.Prepared, scope.Detached, scope.Abandoned }[role];
        File.WriteAllText(Path.Combine(root, "unapproved.txt"), "extra");
        var prior = scope.ExistenceVector();
        var error = await CaptureFailureAsync(() => scope.InvokeMoveAsync(move));
        Assert.IsFalse(error is V2ServiceTreeMoveOutcomeAmbiguousException);
        CollectionAssert.AreEqual(prior, scope.ExistenceVector());
    }

    [DataTestMethod]
    [DataRow(0, 0)]
    [DataRow(1, 1)]
    [DataRow(2, 0)]
    [DataRow(3, 2)]
    public async Task Reparse_source_sibling_blocks_move_without_following_it(int move, int role)
    {
        using var scope = new Scope();
        await scope.BuildThroughAsync(move);
        var root = new[] { scope.Canonical, scope.Prepared, scope.Detached, scope.Abandoned }[role];
        var moved = Path.Combine(scope.Root, "outside-move-" + move);
        Assert.IsTrue(Path.GetFullPath(root).StartsWith(Path.GetFullPath(scope.ProductParent) +
            Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
        Assert.IsTrue(Path.GetFullPath(moved).StartsWith(Path.GetFullPath(scope.Root) +
            Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
        Directory.Move(root, moved);
        try { Directory.CreateSymbolicLink(root, moved); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeldHResult)
        { Assert.Inconclusive("Directory symlink privilege is unavailable."); return; }
        var failure = await CaptureFailureAsync(() => scope.InvokeMoveAsync(move));
        Assert.IsFalse(failure is V2ServiceTreeMoveOutcomeAmbiguousException);
        Assert.IsTrue(Directory.Exists(moved));
    }

    [DataTestMethod]
    [DataRow("Vantrel.Security.Service.exe")]
    [DataRow("Vantrel.Security.TrustedManifest")]
    [DataRow("Vantrel.Security.ReleaseMetadata")]
    public async Task Private_candidate_named_stream_blocks_preparation(string relative)
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var stream = Path.Combine(scope.PrivateCandidate, relative) + ":alternate";
        File.WriteAllText(stream, "alternate");
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        AssertAbsent(scope.Prepared);
    }

    [TestMethod]
    public async Task Private_candidate_directory_named_stream_blocks_preparation()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var stream = Path.Combine(scope.PrivateCandidate, "deps") + ":alternate";
        File.WriteAllText(stream, "alternate");
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        AssertAbsent(scope.Prepared);
    }

    [TestMethod]
    [TestCategory("AdministratorOnly")]
    public async Task Protected_service_tree_acl_survives_preparation_and_each_physical_move()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Assert.Inconclusive("An elevated Administrator token is required for the full Service-tree ACL gate.");
            return;
        }
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        scope.Predecessor = scope.CreatePredecessor();
        ApplyPrivateDescriptor(scope.PrivateCandidate);
        ApplyServiceDescriptor(scope.Canonical);
        var storage = new V2ServiceTreeStorage(scope.Verifier, scope.ProductParent,
            scope.ArtifactRoot, enforceAcls: true);
        await storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None);
        CheckServiceDescriptor(scope.Prepared);
        for (var move = 0; move < 4; move++)
        {
            await scope.InvokeMoveAsync(move, storage);
            foreach (var path in new[] { scope.Canonical, scope.Prepared, scope.Detached, scope.Abandoned })
                if (Directory.Exists(path)) CheckServiceDescriptor(path);
        }
    }

    [TestMethod]
    [TestCategory("AdministratorOnly")]
    public async Task Changed_prepared_runtime_acl_blocks_physical_detach_before_attempt()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Assert.Inconclusive("An elevated Administrator token is required for ACL-mismatch rejection.");
            return;
        }
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        scope.Predecessor = scope.CreatePredecessor();
        ApplyPrivateDescriptor(scope.PrivateCandidate);
        ApplyServiceDescriptor(scope.Canonical);
        var storage = new V2ServiceTreeStorage(scope.Verifier, scope.ProductParent,
            scope.ArtifactRoot, enforceAcls: true);
        await storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None);
        var runtime = Path.Combine(scope.Prepared, "Vantrel.Security.Service.exe");
        var altered = V2ServiceTreeFileSystemSecurity.CreateFileDescriptor();
        altered.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Modify, AccessControlType.Allow));
        new FileInfo(runtime).SetAccessControl(altered);
        var failure = await CaptureFailureAsync(() => storage.DetachPredecessorAsync(TransactionId,
            scope.Predecessor, scope.Target, CancellationToken.None));
        Assert.IsFalse(failure is V2ServiceTreeMoveOutcomeAmbiguousException);
        Assert.IsTrue(Directory.Exists(scope.Canonical));
        Assert.IsFalse(Directory.Exists(scope.Detached));
    }

    [DataTestMethod]
    [DataRow("deps/Added.dll")]
    [DataRow("Vantrel.Security.TrustedManifest")]
    [DataRow("Vantrel.Security.ReleaseMetadata")]
    public async Task Preparation_rejects_reparse_candidate_file(string relative)
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var original = Path.Combine(scope.PrivateCandidate,
            relative.Replace('/', Path.DirectorySeparatorChar));
        var outside = Path.Combine(scope.Root, "outside.dll");
        File.WriteAllText(outside, "outside");
        File.Delete(original);
        try { File.CreateSymbolicLink(original, outside); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeldHResult)
        { Assert.Inconclusive("File symlink privilege is unavailable."); return; }

        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        AssertAbsent(scope.Prepared);
    }

    [TestMethod]
    public async Task Preparation_rejects_reparse_product_parent()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        Assert.IsTrue(Path.GetFullPath(scope.ProductParent).StartsWith(
            Path.GetFullPath(scope.Root) + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase));
        Directory.Delete(scope.ProductParent, recursive: true);
        var elsewhere = Path.Combine(scope.Root, "alternate-product-parent");
        Directory.CreateDirectory(elsewhere);
        try { Directory.CreateSymbolicLink(scope.ProductParent, elsewhere); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeldHResult)
        { Assert.Inconclusive("Directory symlink privilege is unavailable."); return; }
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        Assert.IsFalse(Directory.Exists(Path.Combine(elsewhere, ".service-next-" + TransactionId)));
    }

    [TestMethod]
    public async Task Preparation_rejects_reparse_destination_leaf_without_following_target()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var elsewhere = Path.Combine(scope.Root, "outside-prepared-target");
        Directory.CreateDirectory(elsewhere);
        try { Directory.CreateSymbolicLink(scope.Prepared, elsewhere); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeldHResult)
        { Assert.Inconclusive("Directory symlink privilege is unavailable."); return; }
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        CollectionAssert.AreEqual(Array.Empty<string>(), Directory.GetFileSystemEntries(elsewhere));
    }

    [TestMethod]
    public async Task Preparation_rejects_reparse_nested_private_directory()
    {
        using var scope = new Scope();
        await scope.BuildPrivateCandidateAsync();
        var nested = Path.Combine(scope.PrivateCandidate, "deps", "nested");
        var elsewhere = Path.Combine(scope.Root, "other-nested");
        Directory.Move(nested, elsewhere);
        try { Directory.CreateSymbolicLink(nested, elsewhere); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeldHResult)
        { Assert.Inconclusive("Directory symlink privilege is unavailable."); return; }
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Storage.PrepareTargetAsync(TransactionId, scope.Target, CancellationToken.None));
        AssertAbsent(scope.Prepared);
    }

    private static async Task<Exception> CaptureFailureAsync(Func<Task> action)
    {
        try { await action(); }
        catch (Exception error) { return error; }
        Assert.Fail("The operation unexpectedly succeeded.");
        throw new InvalidOperationException("Unreachable.");
    }

    private static async Task<Exception?> CaptureFailureOrSuccessAsync(Func<Task> action)
    {
        try { await action(); return null; }
        catch (Exception error) { return error; }
    }

    private static void AssertAbsent(string path) =>
        Assert.IsFalse(File.Exists(path) || Directory.Exists(path), "Expected an absent path: " + path);

    private static void AssertExactTree(string root, ImmutableArray<TrustedManifestV2File> inventory)
    {
        var expectedFiles = inventory.Select(file => file.Path)
            .Concat(["Vantrel.Security.TrustedManifest", "Vantrel.Security.ReleaseMetadata"])
            .OrderBy(path => path, StringComparer.Ordinal).ToArray();
        var actualFiles = Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/'))
            .OrderBy(path => path, StringComparer.Ordinal).ToArray();
        CollectionAssert.AreEqual(expectedFiles, actualFiles);
        var expectedDirectories = new HashSet<string>(StringComparer.Ordinal);
        foreach (var path in expectedFiles)
            for (var slash = path.IndexOf('/'); slash >= 0; slash = path.IndexOf('/', slash + 1))
                expectedDirectories.Add(path[..slash]);
        var actualDirectories = Directory.GetDirectories(root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/')).ToArray();
        CollectionAssert.AreEquivalent(expectedDirectories.ToArray(), actualDirectories);
    }

    private static void ApplyPrivateDescriptor(string root)
    {
        foreach (var file in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
            new FileInfo(file).SetAccessControl(V2ArtifactFileSystemSecurity.CreateFileDescriptor());
        foreach (var directory in Directory.GetDirectories(root, "*", SearchOption.AllDirectories)
            .Prepend(root))
            new DirectoryInfo(directory).SetAccessControl(
                V2ArtifactFileSystemSecurity.CreateDirectoryDescriptor());
    }

    private static void ApplyServiceDescriptor(string root)
    {
        foreach (var file in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
            new FileInfo(file).SetAccessControl(V2ServiceTreeFileSystemSecurity.CreateFileDescriptor());
        foreach (var directory in Directory.GetDirectories(root, "*", SearchOption.AllDirectories)
            .Prepend(root))
            new DirectoryInfo(directory).SetAccessControl(
                V2ServiceTreeFileSystemSecurity.CreateDirectoryDescriptor());
    }

    private static void CheckServiceDescriptor(string root)
    {
        foreach (var directory in Directory.GetDirectories(root, "*", SearchOption.AllDirectories)
            .Prepend(root))
            V2ServiceTreeFileSystemSecurity.RequireDirectoryAcl(directory);
        foreach (var file in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
            V2ServiceTreeFileSystemSecurity.RequireFileAcl(file);
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string fileName, string existingFileName,
        nint securityAttributes);

    private sealed class Scope : IDisposable
    {
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        internal Scope()
        {
            Directory.CreateDirectory(ProductParent);
            Directory.CreateDirectory(Path.Combine(ProductParent, "Desktop"));
            Directory.CreateDirectory(Path.Combine(ArtifactRoot, "Transactions"));
            Directory.CreateDirectory(Path.Combine(ArtifactRoot, "Backups"));
        }

        internal string Root { get; } = Path.Combine(Path.GetTempPath(),
            "vantrel-v2-service-tree-" + Guid.NewGuid().ToString("N"));
        internal string ProductParent => Path.Combine(Root, "ProgramFiles", "Vantrel Security");
        internal string ArtifactRoot => Path.Combine(Root, "ProgramData", "Vantrel Security",
            "Updates", "V2Artifacts");
        internal string StagedRoot => Path.Combine(Root, "StagedTarget");
        internal GenerationAwareOfflineReleaseVerifier Verifier => new(
            _metadataKey.ExportSubjectPublicKeyInfo(), _manifestKey.ExportSubjectPublicKeyInfo());
        internal V2ServiceTreeStorage Storage => new(Verifier, ProductParent, ArtifactRoot,
            enforceAcls: false);
        internal V2ServiceTreeStorage WithFault(Action<V2ServiceTreeCheckpoint> fault) =>
            new(Verifier, ProductParent, ArtifactRoot, enforceAcls: false, fault);
        internal string Canonical => Storage.CanonicalServiceRoot;
        internal string PrivateCandidate => Storage.GetPrivateCandidatePath(TransactionId);
        internal string Prepared => Storage.GetPreparedTargetPath(TransactionId);
        internal string Detached => Storage.GetDetachedPredecessorPath(TransactionId);
        internal string Abandoned => Storage.GetAbandonedTargetPath(TransactionId);
        internal ReleaseIdentity Target { get; private set; } = null!;
        internal ReleaseIdentity Predecessor { get; set; } = null!;

        internal ReleaseIdentity CreatePredecessor() => WriteSignedRelease(Canonical, 7,
            ("Vantrel.Security.Service.exe", "predecessor apphost"),
            ("deps/Removed.dll", "predecessor dependency"));

        internal void ReplaceRoleWithWrongIdentity(int role)
        {
            var path = new[] { Canonical, Prepared, Detached, Abandoned }[role];
            Directory.Delete(path, recursive: true);
            _ = WriteSignedRelease(path, 42,
                ("Vantrel.Security.Service.exe", "wrong authenticated role"));
        }

        internal async Task BuildPrivateCandidateAsync()
        {
            Target = WriteSignedRelease(StagedRoot, 8,
                ("Vantrel.Security.Service.exe", "target apphost"),
                ("deps/Added.dll", "target dependency"),
                ("deps/nested/Second.dll", "nested dependency"));
            var artifact = new V2ReleaseArtifactStorage(Verifier, ArtifactRoot, StagedRoot,
                Canonical, enforceAcls: false);
            await artifact.CopyPrivateCandidateAsync(TransactionId, Target, CancellationToken.None);
            Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
                (await Verifier.VerifyChainAsync(PrivateCandidate, CancellationToken.None)).Result);
        }

        internal async Task BuildInitialAsync()
        {
            await BuildPrivateCandidateAsync();
            Predecessor = CreatePredecessor();
            await Storage.PrepareTargetAsync(TransactionId, Target, CancellationToken.None);
        }

        internal async Task BuildThroughAsync(int move)
        {
            await BuildInitialAsync();
            for (var prior = 0; prior < move; prior++) await InvokeMoveAsync(prior);
            await AssertStateAsync(move);
        }

        internal Task InvokeMoveAsync(int move, V2ServiceTreeStorage? storage = null)
        {
            storage ??= Storage;
            return move switch
            {
                0 => storage.DetachPredecessorAsync(TransactionId, Predecessor, Target,
                    CancellationToken.None),
                1 => storage.ActivatePreparedTargetAsync(TransactionId, Predecessor, Target,
                    CancellationToken.None),
                2 => storage.DetachActivatedTargetForRollbackAsync(TransactionId, Predecessor,
                    Target, CancellationToken.None),
                3 => storage.RestorePredecessorAsync(TransactionId, Predecessor, Target,
                    CancellationToken.None),
                _ => throw new ArgumentOutOfRangeException(nameof(move))
            };
        }

        internal bool[] ExistenceVector() =>
            [Directory.Exists(Canonical), Directory.Exists(Prepared), Directory.Exists(Detached),
                Directory.Exists(Abandoned)];

        internal async Task AssertStateAsync(int state)
        {
            var expected = state switch
            {
                0 => new ReleaseIdentity?[] { Predecessor, Target, null, null },
                1 => new ReleaseIdentity?[] { null, Target, Predecessor, null },
                2 => new ReleaseIdentity?[] { Target, null, Predecessor, null },
                3 => new ReleaseIdentity?[] { null, null, Predecessor, Target },
                4 => new ReleaseIdentity?[] { Predecessor, null, null, Target },
                _ => throw new ArgumentOutOfRangeException(nameof(state))
            };
            var roots = new[] { Canonical, Prepared, Detached, Abandoned };
            for (var index = 0; index < roots.Length; index++)
            {
                if (expected[index] is null) AssertAbsent(roots[index]);
                else
                {
                    var result = await Verifier.VerifyChainAsync(roots[index], CancellationToken.None);
                    Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
                        result.Result, roots[index]);
                    Assert.AreEqual(expected[index], result.Release!.Identity, roots[index]);
                }
            }
        }

        private ReleaseIdentity WriteSignedRelease(string root, ulong sequence,
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

        public void Dispose()
        {
            _manifestKey.Dispose();
            _metadataKey.Dispose();
            var temporary = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
            var resolved = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Root));
            if (!resolved.StartsWith(temporary + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(resolved).StartsWith("vantrel-v2-service-tree-", StringComparison.Ordinal))
                throw new IOException("Disposable V2 Service-tree root escaped its temporary parent.");
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
