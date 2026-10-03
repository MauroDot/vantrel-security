using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class WindowsSignatureInspectorTests
{
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);

    [TestMethod]
    public async Task Fresh_handle_bound_inspection_reports_separate_embedded_and_matching_catalog_observations()
    {
        using var root = new DisposableRoot();
        var path = root.File("sample.bin", "content"u8.ToArray());
        var embedded = new FakeEmbeddedTrust(0, "CN=Declared Subject");
        var catalog = new FakeCatalogAdapter(LocalCatalogSignatureOutcome.MatchingCatalogVerified);

        var result = await new WindowsSignatureInspector(embedded, catalog).InspectAsync(path, CancellationToken.None);

        Assert.AreEqual(WindowsSignatureInspectionOutcome.Completed, result.Outcome);
        Assert.AreEqual("sample.bin", result.FileName);
        Assert.AreEqual(7L, result.ByteLength);
        Assert.AreEqual(AuthenticodePublisherInspectionOutcome.Verified, result.EmbeddedOutcome);
        Assert.AreEqual("CN=Declared Subject", result.DeclaredEmbeddedSignerSubject);
        Assert.AreEqual(LocalCatalogSignatureOutcome.MatchingCatalogVerified, result.CatalogOutcome);
        Assert.AreEqual(1, embedded.Calls);
        Assert.AreEqual(1, catalog.Calls);
        Assert.IsTrue(catalog.ReceivedOpenHandle);
        Assert.IsTrue(catalog.FinalPath!.StartsWith("\\\\?\\", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task No_embedded_signature_and_clean_no_catalog_match_use_the_limited_combined_absence_message()
    {
        using var root = new DisposableRoot();
        var path = root.File("sample.bin", "content"u8.ToArray());

        var result = await new WindowsSignatureInspector(
            new FakeEmbeddedTrust(unchecked((int)0x800B0100), null),
            new FakeCatalogAdapter(LocalCatalogSignatureOutcome.NoMatchingCatalogObserved)).InspectAsync(path, CancellationToken.None);
        var presentation = WindowsSignatureInspectionPresentation.Create(result);

        Assert.IsTrue(presentation.StateText.Contains("No usable embedded signature or matching local catalog signature was observed.", StringComparison.Ordinal));
        Assert.IsTrue(presentation.StateText.Contains("does not establish", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task Matching_catalog_nonzero_and_catalog_failures_remain_separate_scoped_observations()
    {
        using var root = new DisposableRoot();
        var path = root.File("sample.bin", "content"u8.ToArray());
        foreach (var outcome in new[]
                 {
                     LocalCatalogSignatureOutcome.MatchingCatalogVerificationFailed,
                     LocalCatalogSignatureOutcome.Unavailable,
                     LocalCatalogSignatureOutcome.Incomplete
                 })
        {
            var result = await new WindowsSignatureInspector(new FakeEmbeddedTrust(0, null), new FakeCatalogAdapter(outcome))
                .InspectAsync(path, CancellationToken.None);
            var presentation = WindowsSignatureInspectionPresentation.Create(result);
            Assert.AreEqual(WindowsSignatureInspectionOutcome.Completed, result.Outcome);
            Assert.AreEqual(outcome, result.CatalogOutcome);
            Assert.IsFalse(presentation.CatalogStateText!.Contains("safe", StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(presentation.CatalogStateText.Contains("trusted", StringComparison.OrdinalIgnoreCase));
        }
    }

    [TestMethod]
    public void Catalog_adapter_uses_bounded_two_pass_hash_and_releases_every_native_context_after_later_candidate_success()
    {
        var native = new FakeCatalogNative
        {
            HashLength = 32,
            Enumeration = new Queue<LocalCatalogEnumeration>([
                new(LocalCatalogEnumerationKind.Catalog, new IntPtr(11)),
                new(LocalCatalogEnumerationKind.Catalog, new IntPtr(12)),
                new(LocalCatalogEnumerationKind.Completed, IntPtr.Zero)]),
            VerificationStatuses = new Queue<int>([unchecked((int)0x800B0109), 0])
        };
        var adapter = new WindowsLocalCatalogSignatureAdapter(native);
        using var handle = new SafeFileHandle(new IntPtr(1), ownsHandle: false);

        var result = adapter.Inspect("\\\\?\\C:\\sample.bin", handle);

        Assert.AreEqual(LocalCatalogSignatureOutcome.MatchingCatalogVerified, result.Outcome);
        Assert.AreEqual(1, native.AcquireCalls);
        Assert.AreEqual(1, native.HashLengthCalls);
        Assert.AreEqual(1, native.HashCalls);
        Assert.AreEqual(2, native.VerifyCalls);
        Assert.AreEqual(2, native.CloseCalls);
        CollectionAssert.AreEquivalent(new[] { new IntPtr(11), new IntPtr(12) }, native.ReleasedCatalogs);
        Assert.AreEqual(1, native.ReleaseAdminCalls);
    }

    [TestMethod]
    public void Catalog_adapter_reports_nonzero_matching_catalogs_and_closes_their_native_state_before_clean_completion()
    {
        var native = new FakeCatalogNative
        {
            Enumeration = new Queue<LocalCatalogEnumeration>([
                new(LocalCatalogEnumerationKind.Catalog, new IntPtr(21)),
                new(LocalCatalogEnumerationKind.Completed, IntPtr.Zero)]),
            VerificationStatuses = new Queue<int>([unchecked((int)0x800B0109)])
        };
        using var handle = new SafeFileHandle(new IntPtr(1), ownsHandle: false);

        var result = new WindowsLocalCatalogSignatureAdapter(native).Inspect("\\\\?\\C:\\sample.bin", handle);

        Assert.AreEqual(LocalCatalogSignatureOutcome.MatchingCatalogVerificationFailed, result.Outcome);
        Assert.AreEqual(1, native.CloseCalls);
        CollectionAssert.AreEquivalent(new[] { new IntPtr(21) }, native.ReleasedCatalogs);
        Assert.AreEqual(1, native.ReleaseAdminCalls);
    }

    [TestMethod]
    public void Catalog_adapter_maps_acquisition_hash_enumeration_and_metadata_failures_without_verifying()
    {
        using var handle = new SafeFileHandle(new IntPtr(1), ownsHandle: false);
        foreach (var native in new[]
                 {
                     new FakeCatalogNative { Admin = IntPtr.Zero },
                     new FakeCatalogNative { HashLengthSucceeds = false },
                     new FakeCatalogNative { HashSucceeds = false },
                     new FakeCatalogNative { Enumeration = new Queue<LocalCatalogEnumeration>([new(LocalCatalogEnumerationKind.Failed, IntPtr.Zero)]) },
                     new FakeCatalogNative { Enumeration = new Queue<LocalCatalogEnumeration>([new(LocalCatalogEnumerationKind.Catalog, new IntPtr(3))]), MetadataSucceeds = false }
                 })
        {
            var result = new WindowsLocalCatalogSignatureAdapter(native).Inspect("\\\\?\\C:\\sample.bin", handle);
            Assert.IsTrue(result.Outcome is LocalCatalogSignatureOutcome.Unavailable or LocalCatalogSignatureOutcome.Incomplete);
            Assert.AreEqual(0, native.VerifyCalls);
            Assert.AreEqual(native.Admin == IntPtr.Zero ? 0 : 1, native.ReleaseAdminCalls);
        }
    }

    [TestMethod]
    public void Catalog_adapter_rejects_oversized_hash_buffer_before_calculation()
    {
        var native = new FakeCatalogNative { HashLength = WindowsLocalCatalogSignatureAdapter.MaximumCatalogHashLength + 1 };
        using var handle = new SafeFileHandle(new IntPtr(1), ownsHandle: false);

        var result = new WindowsLocalCatalogSignatureAdapter(native).Inspect("\\\\?\\C:\\sample.bin", handle);

        Assert.AreEqual(LocalCatalogSignatureOutcome.Unavailable, result.Outcome);
        Assert.AreEqual(0, native.HashCalls);
        Assert.AreEqual(0, native.VerifyCalls);
        Assert.AreEqual(1, native.ReleaseAdminCalls);
    }

    [TestMethod]
    public void Catalog_verification_setup_failure_frees_allocations_and_releases_current_and_admin_contexts()
    {
        var memory = new ThrowingCatalogTrustMemory();
        var setup = new LocalCatalogNativeApi(memory);
        var native = new FakeCatalogNative
        {
            Enumeration = new Queue<LocalCatalogEnumeration>([new(LocalCatalogEnumerationKind.Catalog, new IntPtr(31))]),
            VerifyOverride = setup.VerifyCatalog
        };
        using var handle = new SafeFileHandle(new IntPtr(1), ownsHandle: false);

        var result = new WindowsLocalCatalogSignatureAdapter(native).Inspect("\\\\?\\C:\\sample.bin", handle);

        Assert.AreEqual(LocalCatalogSignatureOutcome.Unavailable, result.Outcome);
        Assert.AreEqual(1, native.VerifyCalls);
        CollectionAssert.AreEquivalent(new[] { new IntPtr(31) }, native.ReleasedCatalogs);
        Assert.AreEqual(1, native.ReleaseAdminCalls);
        CollectionAssert.AreEquivalent(memory.AllocatedCoTaskMemory, memory.FreedCoTaskMemory);
        CollectionAssert.AreEquivalent(memory.AllocatedHGlobalMemory, memory.FreedHGlobalMemory);
        Assert.AreEqual(memory.AllocatedCoTaskMemory.Count, memory.FreedCoTaskMemory.Count);
        Assert.AreEqual(memory.AllocatedHGlobalMemory.Count, memory.FreedHGlobalMemory.Count);
    }

    [TestMethod]
    public async Task Native_unavailable_exceptions_publish_no_partial_observation_or_native_details()
    {
        using var root = new DisposableRoot();
        var path = root.File("native.bin", "content"u8.ToArray());
        foreach (var error in new Exception[]
                 { new DllNotFoundException("test"), new EntryPointNotFoundException("test"), new BadImageFormatException("test") })
        {
            var result = await new WindowsSignatureInspector(new FakeEmbeddedTrust(0, "CN=Not published"), new ThrowingCatalogAdapter(error))
                .InspectAsync(path, CancellationToken.None);
            var presentation = WindowsSignatureInspectionPresentation.Create(result);
            Assert.AreEqual(WindowsSignatureInspectionOutcome.Unavailable, result.Outcome);
            Assert.IsNull(result.FileName);
            Assert.IsNull(result.DeclaredEmbeddedSignerSubject);
            Assert.IsFalse(presentation.StateText.Contains(error.Message, StringComparison.Ordinal));
        }
    }

    [TestMethod]
    public async Task Cancellation_after_catalog_native_entry_suppresses_all_publication_until_native_work_returns()
    {
        using var root = new DisposableRoot();
        var path = root.File("wait.bin", "content"u8.ToArray());
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        using var cancellation = new CancellationTokenSource();
        var catalog = new FakeCatalogAdapter(LocalCatalogSignatureOutcome.MatchingCatalogVerified, () => { entered.Set(); release.Wait(); });
        var inspector = new WindowsSignatureInspector(new FakeEmbeddedTrust(0, null), catalog);

        var inspection = Task.Run(() => inspector.InspectAsync(path, cancellation.Token));
        Assert.IsTrue(entered.Wait(TimeSpan.FromSeconds(5)));
        cancellation.Cancel();
        release.Set();

        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => inspection);
        Assert.AreEqual(1, catalog.Calls);
    }

    [TestMethod]
    public async Task Mutation_after_catalog_work_and_concurrent_file_action_publish_no_result_and_share_the_coordinator()
    {
        using var root = new DisposableRoot();
        var path = root.File("changing.bin", new byte[128 * 1024]);
        var coordinator = new LocalFileInspectionCoordinator();
        var catalog = new FakeCatalogAdapter(LocalCatalogSignatureOutcome.MatchingCatalogVerified, () => File.AppendAllText(path, "changed"));
        var inspection = new WindowsSignatureInspector(new FakeEmbeddedTrust(0, null), catalog, coordinator);

        var changed = await inspection.InspectAsync(path, CancellationToken.None);
        Assert.AreEqual(WindowsSignatureInspectionOutcome.Changed, changed.Outcome);
        Assert.IsNull(changed.FileName);

        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var occupied = new LocalFileFingerprintInspector(_ => { entered.TrySetResult(); return release.Task; }, coordinator: coordinator);
        var first = occupied.InspectAsync(path, CancellationToken.None);
        await entered.Task;
        var second = await inspection.InspectAsync(path, CancellationToken.None);
        release.TrySetResult();
        Assert.AreEqual(WindowsSignatureInspectionOutcome.AlreadyInProgress, second.Outcome);
        _ = await first;
    }

    [TestMethod]
    public async Task Final_path_redirect_is_rejected_before_any_signature_adapter_when_supported()
    {
        using var root = new DisposableRoot();
        var ordinary = Path.Combine(root.Path, "ordinary");
        var target = Path.Combine(root.Path, "target");
        Directory.CreateDirectory(ordinary);
        Directory.CreateDirectory(target);
        var selected = root.File(Path.Combine("ordinary", "sample.bin"), "original"u8.ToArray());
        root.File(Path.Combine("target", "sample.bin"), "redirected"u8.ToArray());
        var embedded = new FakeEmbeddedTrust(0, null);
        var catalog = new FakeCatalogAdapter(LocalCatalogSignatureOutcome.MatchingCatalogVerified);
        var redirected = false;
        var privilegeUnavailable = false;
        var inspector = new WindowsSignatureInspector(embedded, catalog, afterPathValidationAsync: _ =>
        {
            File.Delete(selected);
            Directory.Delete(ordinary);
            try { Directory.CreateSymbolicLink(ordinary, target); redirected = true; }
            catch (Exception error) when (error.HResult == PrivilegeNotHeldHResult) { privilegeUnavailable = true; }
            return Task.CompletedTask;
        });

        var result = await inspector.InspectAsync(selected, CancellationToken.None);
        if (!redirected)
        {
            Assert.IsTrue(privilegeUnavailable, "Only missing symbolic-link privilege may skip this test.");
            Assert.Inconclusive("The test host does not permit symbolic-link creation.");
            return;
        }

        Assert.AreEqual(WindowsSignatureInspectionOutcome.Declined, result.Outcome);
        Assert.AreEqual(0, embedded.Calls);
        Assert.AreEqual(0, catalog.Calls);
        Assert.IsNull(result.FileName);
    }

    private sealed class FakeEmbeddedTrust(int status, string? subject) : IAuthenticodeTrustAdapter
    {
        internal int Calls { get; private set; }
        public AuthenticodeNativeResult VerifyEmbeddedSignature(string finalDosPath, SafeFileHandle fileHandle)
        {
            Calls++;
            return new AuthenticodeNativeResult(status, subject);
        }
    }

    private sealed class FakeCatalogAdapter(LocalCatalogSignatureOutcome outcome, Action? beforeReturn = null) : ILocalCatalogSignatureAdapter
    {
        internal int Calls { get; private set; }
        internal string? FinalPath { get; private set; }
        internal bool ReceivedOpenHandle { get; private set; }
        public LocalCatalogSignatureResult Inspect(string finalDosPath, SafeFileHandle fileHandle)
        {
            Calls++;
            FinalPath = finalDosPath;
            ReceivedOpenHandle = !fileHandle.IsInvalid && !fileHandle.IsClosed;
            beforeReturn?.Invoke();
            return new LocalCatalogSignatureResult(outcome);
        }
    }

    private sealed class ThrowingCatalogAdapter(Exception error) : ILocalCatalogSignatureAdapter
    {
        public LocalCatalogSignatureResult Inspect(string finalDosPath, SafeFileHandle fileHandle) => throw error;
    }

    private sealed class FakeCatalogNative : ILocalCatalogNativeApi
    {
        internal IntPtr Admin { get; init; } = new(1);
        internal uint HashLength { get; init; } = 32;
        internal bool HashLengthSucceeds { get; init; } = true;
        internal bool HashSucceeds { get; init; } = true;
        internal bool MetadataSucceeds { get; init; } = true;
        internal Queue<LocalCatalogEnumeration> Enumeration { get; init; } = new([new(LocalCatalogEnumerationKind.Completed, IntPtr.Zero)]);
        internal Queue<int> VerificationStatuses { get; init; } = new([0]);
        internal Func<string, string, string, SafeFileHandle, byte[], IntPtr, CatalogTrustNativeCall>? VerifyOverride { get; init; }
        internal int AcquireCalls { get; private set; }
        internal int HashLengthCalls { get; private set; }
        internal int HashCalls { get; private set; }
        internal int VerifyCalls { get; private set; }
        internal int CloseCalls { get; private set; }
        internal int ReleaseAdminCalls { get; private set; }
        internal List<IntPtr> ReleasedCatalogs { get; } = [];

        public IntPtr AcquireCatalogAdmin() { AcquireCalls++; return Admin; }
        public bool TryGetHashLength(IntPtr catalogAdmin, SafeFileHandle fileHandle, out uint hashLength)
        { HashLengthCalls++; hashLength = HashLength; return HashLengthSucceeds; }
        public bool TryCalculateHash(IntPtr catalogAdmin, SafeFileHandle fileHandle, byte[] hash)
        { HashCalls++; Array.Fill(hash, (byte)0xA5); return HashSucceeds; }
        public LocalCatalogEnumeration Enumerate(IntPtr catalogAdmin, byte[] hash, IntPtr previousCatalogContext) =>
            Enumeration.Count == 0 ? new(LocalCatalogEnumerationKind.Completed, IntPtr.Zero) : Enumeration.Dequeue();
        public bool TryGetCatalogMetadata(IntPtr catalogContext, out LocalCatalogMetadata metadata)
        { metadata = new LocalCatalogMetadata("C:\\catalog.cat"); return MetadataSucceeds; }
        public CatalogTrustNativeCall VerifyCatalog(string catalogPath, string memberTag, string finalDosPath, SafeFileHandle fileHandle, byte[] hash, IntPtr catalogAdmin)
        {
            VerifyCalls++;
            return VerifyOverride?.Invoke(catalogPath, memberTag, finalDosPath, fileHandle, hash, catalogAdmin)
                ?? new CatalogTrustNativeCall(VerificationStatuses.Count == 0 ? unchecked((int)0x800B0109) : VerificationStatuses.Dequeue(), new object());
        }
        public void Close(CatalogTrustNativeCall call) => CloseCalls++;
        public void ReleaseCatalog(IntPtr catalogAdmin, IntPtr catalogContext) => ReleasedCatalogs.Add(catalogContext);
        public void ReleaseCatalogAdmin(IntPtr catalogAdmin) => ReleaseAdminCalls++;
    }

    private sealed class ThrowingCatalogTrustMemory : ILocalCatalogTrustMemory
    {
        private int _nextPointer;
        internal List<IntPtr> AllocatedCoTaskMemory { get; } = [];
        internal List<IntPtr> AllocatedHGlobalMemory { get; } = [];
        internal List<IntPtr> FreedCoTaskMemory { get; } = [];
        internal List<IntPtr> FreedHGlobalMemory { get; } = [];

        public IntPtr AllocCoTaskMemString(string value)
        {
            var pointer = new IntPtr(++_nextPointer);
            AllocatedCoTaskMemory.Add(pointer);
            return pointer;
        }

        public IntPtr AllocHGlobal(int byteCount)
        {
            var pointer = new IntPtr(++_nextPointer);
            AllocatedHGlobalMemory.Add(pointer);
            return pointer;
        }

        public void Copy(byte[] source, IntPtr destination) => throw new InvalidOperationException("injected marshalling failure");
        public void WriteCatalogInfo(IntPtr destination, LocalCatalogNativeApi.WinTrustCatalogInfo catalogInfo) =>
            throw new InvalidOperationException("not reached");
        public void FreeCoTaskMem(IntPtr pointer) => FreedCoTaskMemory.Add(pointer);
        public void FreeHGlobal(IntPtr pointer) => FreedHGlobalMemory.Add(pointer);
    }

    private sealed class DisposableRoot : IDisposable
    {
        internal DisposableRoot()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "Vantrel.Security.Desktop.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }
        internal string Path { get; }
        internal string File(string name, byte[] contents)
        {
            var path = System.IO.Path.Combine(Path, name);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            System.IO.File.WriteAllBytes(path, contents);
            return path;
        }
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, true); }
    }
}
