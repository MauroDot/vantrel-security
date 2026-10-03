using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class AuthenticodePublisherInspectorTests
{
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);

    [TestMethod]
    public async Task Verified_embedded_signature_returns_only_transient_file_details_and_declared_subject()
    {
        using var root = new DisposableRoot();
        var path = root.File("signed.bin", "content"u8.ToArray());
        var trust = new FakeTrust(0, "CN=Example Publisher");

        var result = await new AuthenticodePublisherInspector(trust).InspectAsync(path, CancellationToken.None);

        Assert.AreEqual(AuthenticodePublisherInspectionOutcome.Verified, result.Outcome);
        Assert.AreEqual("signed.bin", result.FileName);
        Assert.AreEqual(7L, result.ByteLength);
        Assert.AreEqual("CN=Example Publisher", result.DeclaredSignerSubject);
        Assert.IsNotNull(trust.FinalPath);
        Assert.IsTrue(trust.FinalPath!.StartsWith("\\\\?\\", StringComparison.Ordinal));
        Assert.IsTrue(trust.ReceivedHandle);
    }

    [TestMethod]
    public async Task Nonzero_no_signature_unsupported_and_unavailable_native_outcomes_are_scoped()
    {
        using var root = new DisposableRoot();
        var path = root.File("sample.bin", "content"u8.ToArray());

        Assert.AreEqual(AuthenticodePublisherInspectionOutcome.VerificationFailed,
            (await new AuthenticodePublisherInspector(new FakeTrust(unchecked((int)0x800B0109), "CN=Declared"))
                .InspectAsync(path, CancellationToken.None)).Outcome);
        Assert.AreEqual(AuthenticodePublisherInspectionOutcome.NoUsableEmbeddedSignature,
            (await new AuthenticodePublisherInspector(new FakeTrust(unchecked((int)0x800B0100), null))
                .InspectAsync(path, CancellationToken.None)).Outcome);
        Assert.AreEqual(AuthenticodePublisherInspectionOutcome.UnsupportedFileForm,
            (await new AuthenticodePublisherInspector(new FakeTrust(unchecked((int)0x800B0003), null))
                .InspectAsync(path, CancellationToken.None)).Outcome);
        Assert.AreEqual(AuthenticodePublisherInspectionOutcome.Unavailable,
            (await new AuthenticodePublisherInspector(new FakeTrust(unchecked((int)0x800B0001), null))
                .InspectAsync(path, CancellationToken.None)).Outcome);
    }

    [TestMethod]
    public async Task Invalid_selection_is_declined_before_native_entry()
    {
        using var root = new DisposableRoot();
        var trust = new FakeTrust(0, null);

        var result = await new AuthenticodePublisherInspector(trust).InspectAsync(root.Path, CancellationToken.None);

        Assert.AreEqual(AuthenticodePublisherInspectionOutcome.Declined, result.Outcome);
        Assert.AreEqual(0, trust.Calls);
    }

    [TestMethod]
    public async Task Native_infrastructure_failures_are_mapped_to_the_same_unavailable_result()
    {
        using var root = new DisposableRoot();
        var path = root.File("native.bin", "content"u8.ToArray());

        foreach (var exception in new Exception[]
                 { new DllNotFoundException("test"), new EntryPointNotFoundException("test"), new BadImageFormatException("test") })
        {
            var result = await new AuthenticodePublisherInspector(new ThrowingTrust(exception))
                .InspectAsync(path, CancellationToken.None);

            Assert.AreEqual(AuthenticodePublisherInspectionOutcome.Unavailable, result.Outcome);
            Assert.IsNull(result.FileName);
            Assert.IsNull(result.DeclaredSignerSubject);
            var presentation = AuthenticodePublisherInspectionPresentation.Create(result);
            Assert.AreEqual("Windows Authenticode inspection is unavailable on this device.", presentation.StateText);
            Assert.IsFalse(presentation.StateText.Contains(exception.Message, StringComparison.Ordinal));
        }
    }

    [TestMethod]
    public async Task Validation_to_open_redirect_is_rejected_before_publisher_inspection_when_supported()
    {
        using var root = new DisposableRoot();
        var ordinaryDirectory = Path.Combine(root.Path, "ordinary");
        var targetDirectory = Path.Combine(root.Path, "target");
        Directory.CreateDirectory(ordinaryDirectory);
        Directory.CreateDirectory(targetDirectory);
        var selectedPath = root.File(Path.Combine("ordinary", "sample.bin"), "original"u8.ToArray());
        root.File(Path.Combine("target", "sample.bin"), "redirected"u8.ToArray());
        var redirected = false;
        var privilegeUnavailable = false;
        var trust = new FakeTrust(0, "CN=Should not be read");
        var inspector = new AuthenticodePublisherInspector(trust, afterPathValidationAsync: _ =>
        {
            File.Delete(selectedPath);
            Directory.Delete(ordinaryDirectory);
            try
            {
                Directory.CreateSymbolicLink(ordinaryDirectory, targetDirectory);
                redirected = true;
            }
            catch (Exception error) when (IsPrivilegeNotHeld(error))
            {
                privilegeUnavailable = true;
            }
            return Task.CompletedTask;
        });

        var result = await inspector.InspectAsync(selectedPath, CancellationToken.None);

        if (!redirected)
        {
            Assert.IsTrue(privilegeUnavailable, "Only missing symbolic-link privilege may skip this test.");
            Assert.Inconclusive("The test host does not permit symbolic-link creation.");
            return;
        }

        Assert.AreEqual(AuthenticodePublisherInspectionOutcome.Declined, result.Outcome);
        Assert.AreEqual(0, trust.Calls);
        Assert.IsNull(result.FileName);
        Assert.IsNull(result.DeclaredSignerSubject);
    }

    [TestMethod]
    public async Task Cancellation_after_native_entry_suppresses_result_until_native_call_returns()
    {
        using var root = new DisposableRoot();
        var path = root.File("wait.bin", "content"u8.ToArray());
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        using var cancellation = new CancellationTokenSource();
        var trust = new FakeTrust(0, null, () => { entered.Set(); release.Wait(); });
        var inspector = new AuthenticodePublisherInspector(trust);

        var inspection = Task.Run(() => inspector.InspectAsync(path, cancellation.Token));
        Assert.IsTrue(entered.Wait(TimeSpan.FromSeconds(5)));
        cancellation.Cancel();
        release.Set();

        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => inspection);
        Assert.AreEqual(1, trust.Calls);
    }

    [TestMethod]
    public async Task File_mutation_after_native_verification_suppresses_result()
    {
        using var root = new DisposableRoot();
        var path = root.File("changing.bin", "content"u8.ToArray());
        var trust = new FakeTrust(0, "CN=Example", () => File.AppendAllText(path, "changed"));

        var result = await new AuthenticodePublisherInspector(trust).InspectAsync(path, CancellationToken.None);

        Assert.AreEqual(AuthenticodePublisherInspectionOutcome.Changed, result.Outcome);
        Assert.IsNull(result.FileName);
    }

    [TestMethod]
    public async Task Fingerprint_and_publisher_actions_share_one_in_flight_lease()
    {
        using var root = new DisposableRoot();
        var path = root.File("shared.bin", new byte[128 * 1024]);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var coordinator = new LocalFileInspectionCoordinator();
        var fingerprint = new LocalFileFingerprintInspector(_ => { entered.TrySetResult(); return release.Task; }, coordinator: coordinator);
        var publisher = new AuthenticodePublisherInspector(new FakeTrust(0, null), coordinator);

        var first = fingerprint.InspectAsync(path, CancellationToken.None);
        await entered.Task;
        var second = await publisher.InspectAsync(path, CancellationToken.None);
        release.TrySetResult();

        Assert.AreEqual(AuthenticodePublisherInspectionOutcome.AlreadyInProgress, second.Outcome);
        Assert.AreEqual(FileFingerprintInspectionOutcome.Completed, (await first).Outcome);
    }

    [TestMethod]
    public void Trust_adapter_closes_state_in_finally_when_signer_extraction_fails()
    {
        var native = new FakeNative { ThrowOnSubject = true };
        var adapter = new WindowsAuthenticodeTrustAdapter(native);
        using var handle = new SafeFileHandle(new IntPtr(1), ownsHandle: false);

        Assert.ThrowsException<InvalidOperationException>(() => adapter.VerifyEmbeddedSignature("\\\\?\\C:\\sample.bin", handle));
        Assert.AreEqual(1, native.CloseCalls);
    }

    [TestMethod]
    public void Trust_adapter_closes_state_after_a_successful_verification()
    {
        var native = new FakeNative();
        var adapter = new WindowsAuthenticodeTrustAdapter(native);
        using var handle = new SafeFileHandle(new IntPtr(1), ownsHandle: false);

        var result = adapter.VerifyEmbeddedSignature("\\\\?\\C:\\sample.bin", handle);

        Assert.AreEqual(0, result.Status);
        Assert.AreEqual(1, native.CloseCalls);
    }

    private sealed class FakeTrust(int status, string? subject, Action? beforeReturn = null) : IAuthenticodeTrustAdapter
    {
        internal int Calls { get; private set; }
        internal string? FinalPath { get; private set; }
        internal bool ReceivedHandle { get; private set; }

        public AuthenticodeNativeResult VerifyEmbeddedSignature(string finalDosPath, SafeFileHandle fileHandle)
        {
            Calls++;
            FinalPath = finalDosPath;
            ReceivedHandle = !fileHandle.IsInvalid && !fileHandle.IsClosed;
            beforeReturn?.Invoke();
            return new AuthenticodeNativeResult(status, subject);
        }
    }

    private sealed class ThrowingTrust(Exception error) : IAuthenticodeTrustAdapter
    {
        public AuthenticodeNativeResult VerifyEmbeddedSignature(string finalDosPath, SafeFileHandle fileHandle) => throw error;
    }

    private sealed class FakeNative : IWinTrustNativeApi
    {
        internal bool ThrowOnSubject { get; init; }
        internal int CloseCalls { get; private set; }
        public WinTrustNativeCall Verify(string finalDosPath, SafeFileHandle fileHandle) => new(0, new object());
        public string? GetDeclaredSignerSubject(WinTrustNativeCall call)
        {
            if (ThrowOnSubject) throw new InvalidOperationException("test");
            return "CN=Example";
        }
        public void Close(WinTrustNativeCall call) => CloseCalls++;
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

    private static bool IsPrivilegeNotHeld(Exception error) => error.HResult == PrivilegeNotHeldHResult;
}
