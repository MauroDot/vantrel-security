using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Kestermere.Security.LocalServiceAclHarness;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
[DoNotParallelize]
public sealed class V2ProductParentEffectiveRightsTests
{
    private const string ManualPhase = "product-parent-evidence";
    private const string ParentPrefix = "Vantrel.ParentAclTest.";
    private const string ResultPrefix = "Vantrel.ParentAclResult.";
    private const string ServicePrefix = "Vantrel079ParentAcl_";
    private const int MaximumHarnessFileBytes = 64 * 1024 * 1024;
    private const string RuntimeConfigName = "Kestermere.Security.LocalServiceAclHarness.runtimeconfig.json";
    private const string DepsName = "Kestermere.Security.LocalServiceAclHarness.deps.json";
    private const FileSystemRights ReadAndExecute = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;
    private const uint FileDeleteChild = 0x00000040;
    private const uint DeleteAccess = 0x00010000;
    private const uint WriteDac = 0x00040000;
    private const uint WriteOwner = 0x00080000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private static readonly TimeSpan ServiceTimeout = TimeSpan.FromSeconds(30);
    private static readonly string[] HarnessPayload =
    [
        "Kestermere.Security.LocalServiceAclHarness.exe",
        "Kestermere.Security.LocalServiceAclHarness.dll",
        "Kestermere.Security.LocalServiceAclHarness.deps.json",
        "Kestermere.Security.LocalServiceAclHarness.runtimeconfig.json",
        "System.Diagnostics.EventLog.dll",
        "System.Diagnostics.EventLog.Messages.dll",
        "System.ServiceProcess.ServiceController.dll"
    ];
    private static readonly (string Name, bool Allowed)[] ExpectedHarnessProbes =
    [
        ("parent-list", true),
        ("service-read", true),
        ("service-execute", true),
        ("parent-add-file-right", false),
        ("parent-add-directory-right", false),
        ("parent-delete-child-right", false),
        ("parent-write-dac-right", false),
        ("parent-write-owner-right", false),
        ("create-file", false),
        ("create-directory", false),
        ("service-delete-right", false),
        ("next-delete-right", false),
        ("prev-delete-right", false),
        ("abandoned-delete-right", false),
        ("change-parent-acl", false),
        ("take-parent-ownership", false)
    ];

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public uint Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    private readonly record struct TrackedObject(bool IsDirectory, uint VolumeSerial, ulong Identity);

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryWithSecurity(string path, ref SecurityAttributes attributes);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateRestrictedToken(SafeAccessTokenHandle existing, uint flags,
        uint disableSidCount, [In] SidAndAttributes[] sidsToDisable, uint deletePrivilegeCount,
        IntPtr privilegesToDelete, uint restrictedSidCount, IntPtr sidsToRestrict,
        out SafeAccessTokenHandle restrictedToken);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, FileShare share,
        IntPtr securityAttributes, uint creation, uint flags, IntPtr template);

    [TestMethod]
    [TestCategory("AdministratorOnly")]
    [TestCategory("ManualAclHarness")]
    public void Administrator_only_real_Program_Files_parent_effective_rights()
    {
        // Keep this as the first executable statement. Discovery and routine test runs
        // cannot create a Program Files fixture or contact SCM without the manual phase.
        ManualAclHarnessGate.RequirePhase(ManualPhase);
        RequireAdministrator();

        var id = Guid.NewGuid().ToString("N");
        var parent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            ParentPrefix + id);
        var resultRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            ResultPrefix + id);
        var resultFile = Path.Combine(resultRoot, "result.json");
        var name = ServicePrefix + id;
        var nonce = Guid.NewGuid().ToString("N").ToUpperInvariant();
        using var source = HarnessOutput();
        var executable = Path.Combine(parent, "Service", HarnessPayload[0]);
        var tracked = new Dictionary<string, TrackedObject>(StringComparer.OrdinalIgnoreCase);
        TemporaryService? service = null;
        Exception? failure = null;
        var safeToCleanup = true;

        try
        {
            using (var created = V2ProductParentFileSystemSecurity.CreateNewDisposableDirectory(parent))
                tracked.Add(parent, Capture(created, isDirectory: true));
            using (var handle = V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(parent))
                V2ProductParentFileSystemSecurity.RequireDirectoryAcl(handle);
            CreateProductChildren(parent, source, tracked);
            CreateResultFile(resultRoot, resultFile, tracked);

            var commandLine = Quote(executable) + " --product-parent-probe" +
                " --service-name " + Quote(name) +
                " --parent-root " + Quote(parent) +
                " --result-file " + Quote(resultFile) +
                " --nonce " + Quote(nonce);
            service = TemporaryService.Create(name, commandLine, executable);
            service.Start();
            var result = service.WaitForResult(resultFile, nonce, ServiceTimeout);
            Assert.AreEqual("product-parent-v1", result.Schema);
            Assert.AreEqual(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null).Value,
                result.IdentitySid);
            Assert.IsTrue(result.Completed);
            RequireExactHarnessProbes(result.Assertions);

            service.StopAndDelete(ServiceTimeout);
            service.WaitForHarnessExitAndExecutableUnlock(executable, ServiceTimeout);
            service.Dispose();
            service = null;

            VerifyFilteredNonAdministratorRights(parent);
            VerifyAdministratorServicingRights(parent);
            using var final = V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(parent);
            V2ProductParentFileSystemSecurity.RequireDirectoryAcl(final);
        }
        catch (Exception error) { failure = error; }
        finally
        {
            if (service is not null)
            {
                try
                {
                    service.StopAndDelete(ServiceTimeout);
                    service.WaitForHarnessExitAndExecutableUnlock(executable, ServiceTimeout);
                }
                catch (Exception error)
                {
                    safeToCleanup = false;
                    failure = failure is null ? error : new AggregateException(failure, error);
                }
                finally { service.Dispose(); }
            }
            if (safeToCleanup)
            {
                try
                {
                    CleanupTrackedFixture(parent, resultRoot, tracked);
                }
                catch (Exception error)
                {
                    failure = failure is null ? error : new AggregateException(failure, error);
                }
            }
        }
        if (failure is not null) throw failure;
    }

    [TestMethod]
    [TestCategory("AdministratorOnly")]
    public void Administrator_only_on_disk_parent_validation_rejects_relaxed_acl()
    {
        // This test is intentionally excluded from ordinary runs even when the token is elevated.
        ManualAclHarnessGate.RequirePhase(ManualPhase);
        RequireAdministrator();
        var root = Path.Combine(Path.GetTempPath(), ParentPrefix + Guid.NewGuid().ToString("N"));
        TrackedObject? createdRoot = null;
        try
        {
            using (var created = V2ProductParentFileSystemSecurity.CreateNewDisposableDirectory(root))
                createdRoot = Capture(created, isDirectory: true);
            using (var valid = V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(root)) { }
            var info = new DirectoryInfo(root);
            var descriptor = info.GetAccessControl();
            descriptor.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.DeleteSubdirectoriesAndFiles, AccessControlType.Allow));
            info.SetAccessControl(descriptor);
            Assert.ThrowsException<IOException>(() =>
                V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(root));
        }
        finally { CleanupCreatedDisposableRoot(root, createdRoot); }
    }

    [TestMethod]
    public void Preexisting_disposable_parent_is_never_deleted_after_create_new_fails()
    {
        var root = NewTempDisposableRoot();
        TrackedObject? preexisting = null;
        try
        {
            preexisting = CreateTempDisposableRoot(root);
            Assert.ThrowsException<IOException>(() => CreateTempDisposableRoot(root));
            CleanupCreatedDisposableRoot(root, created: null);
            using var retained = V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(root,
                enforceAcl: false);
            RequireSameIdentity(retained, preexisting.Value);
        }
        finally { CleanupCreatedDisposableRoot(root, preexisting); }
    }

    [TestMethod]
    public void Substituted_disposable_parent_is_never_deleted_by_original_identity()
    {
        var root = NewTempDisposableRoot();
        var movedRoot = NewTempDisposableRoot();
        TrackedObject? original = null;
        TrackedObject? replacement = null;
        var moved = false;
        try
        {
            original = CreateTempDisposableRoot(root);
            Directory.Move(root, movedRoot);
            moved = true;
            replacement = CreateTempDisposableRoot(root);
            Assert.ThrowsException<IOException>(() => CleanupCreatedDisposableRoot(root, original));
            using var retained = V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(root,
                enforceAcl: false);
            RequireSameIdentity(retained, replacement.Value);
        }
        finally
        {
            CleanupCreatedDisposableRoot(root, moved ? replacement : original);
            if (moved) CleanupCreatedDisposableRoot(movedRoot, original);
        }
    }

    [TestMethod]
    public void Exact_created_disposable_parent_is_cleaned_without_recursive_deletion()
    {
        var root = NewTempDisposableRoot();
        TrackedObject? created = null;
        try
        {
            created = CreateTempDisposableRoot(root);
            CleanupCreatedDisposableRoot(root, created);
            created = null;
            Assert.IsFalse(Directory.Exists(root));
        }
        finally { CleanupCreatedDisposableRoot(root, created); }
    }

    [TestMethod]
    public void Disposable_parent_identity_mismatch_leaves_residue_untouched()
    {
        var root = NewTempDisposableRoot();
        TrackedObject? created = null;
        try
        {
            created = CreateTempDisposableRoot(root);
            var wrongIdentity = created.Value with { Identity = created.Value.Identity ^ 1UL };
            Assert.ThrowsException<IOException>(() => CleanupCreatedDisposableRoot(root, wrongIdentity));
            using var retained = V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(root,
                enforceAcl: false);
            RequireSameIdentity(retained, created.Value);
        }
        finally { CleanupCreatedDisposableRoot(root, created); }
    }

    [TestMethod]
    public void Harness_probe_consumer_requires_exact_native_rights_and_exact_probe_set()
    {
        var accessDenied = new Win32Exception(5);
        var valid = ExpectedHarnessProbes.Select(item =>
            item.Allowed
                ? new HarnessAssertionResult(item.Name, "passed", null, null, null)
                : item.Name.EndsWith("-right", StringComparison.Ordinal)
                    ? new HarnessAssertionResult(item.Name, "passed", accessDenied.GetType().FullName,
                        accessDenied.HResult, accessDenied.NativeErrorCode, "native-open")
                    : new HarnessAssertionResult(item.Name, "passed",
                        typeof(UnauthorizedAccessException).FullName, unchecked((int)0x80070005), 5)).ToArray();
        RequireExactHarnessProbes(valid);
        Assert.AreEqual(16, valid.Length);
        Assert.ThrowsException<AssertFailedException>(() =>
            RequireExactHarnessProbes([.. valid[..^1], valid[0]]));
        Assert.ThrowsException<AssertFailedException>(() =>
            RequireExactHarnessProbes(valid[..^1]));
        Assert.ThrowsException<AssertFailedException>(() =>
            RequireExactHarnessProbes([.. valid[..^1], valid[^1] with { Name = "unexpected" }]));
        Assert.ThrowsException<AssertFailedException>(() =>
            RequireExactHarnessProbes([.. valid[..^1], valid[^1] with { Outcome = "failed" }]));
        Assert.ThrowsException<AssertFailedException>(() =>
            RequireExactHarnessProbes([.. valid[..^1], valid[^1] with { NativeError = null }]));
        Assert.ThrowsException<AssertFailedException>(() =>
            RequireExactHarnessProbes([valid[0] with { NativeError = 5 }, .. valid[1..]]));

        // Same-parent directory rename needs the source removal and destination-add
        // authority represented by these nonmutating native rights requests.
        foreach (var child in new[]
                 {
                     "service-delete-right", "next-delete-right", "prev-delete-right",
                     "abandoned-delete-right"
                 })
        {
            foreach (var required in new[]
                     {
                         child, "parent-delete-child-right", "parent-add-directory-right"
                     })
            {
                var incomplete = valid.Where(item => item.Name != required).ToArray();
                Assert.ThrowsException<AssertFailedException>(() => RequireExactHarnessProbes(incomplete));
            }
        }

        foreach (var name in new[]
                 {
                     "parent-add-directory-right", "parent-delete-child-right",
                     "service-delete-right", "next-delete-right", "prev-delete-right",
                     "abandoned-delete-right"
                 })
        {
            Reject(name, current => current with { Outcome = "unexpected-success" });
            Reject(name, current => current with { NativeError = null });
            Reject(name, current => current with { NativeError = 2, HResult = new Win32Exception(2).HResult });
            Reject(name, current => current with { NativeError = 32, HResult = new Win32Exception(32).HResult });
            Reject(name, current => current with { NativeError = 145, HResult = new Win32Exception(145).HResult });
            Reject(name, current => current with { Stage = null });
            Reject(name, current => current with
            {
                ExceptionType = typeof(IOException).FullName,
                HResult = unchecked((int)0x80131620), NativeError = 5
            });
            Reject(name, current => current with
            {
                ExceptionType = typeof(UnauthorizedAccessException).FullName,
                HResult = unchecked((int)0x80070005), NativeError = 5
            });
        }

        void Reject(string name, Func<HarnessAssertionResult, HarnessAssertionResult> change)
        {
            var changed = (HarnessAssertionResult[])valid.Clone();
            var index = Array.FindIndex(changed, item => item.Name == name);
            Assert.IsTrue(index >= 0);
            changed[index] = change(changed[index]);
            Assert.ThrowsException<AssertFailedException>(() => RequireExactHarnessProbes(changed));
        }
    }

    [TestMethod]
    public void Product_parent_delete_rights_are_nonmutating_native_open_requests()
    {
        var root = Path.Combine(Path.GetTempPath(), ParentPrefix + Guid.NewGuid().ToString("N"));
        Assert.IsFalse(Directory.Exists(root));
        var plan = ProductParentNativeAccessEvidence.DeleteRights(root);
        var requests = new[] { plan.Parent, plan.Service, plan.Next, plan.Previous, plan.Abandoned };
        CollectionAssert.AreEqual(new[]
        {
            "parent-delete-child-right", "service-delete-right", "next-delete-right",
            "prev-delete-right", "abandoned-delete-right"
        }, requests.Select(static item => item.Name).ToArray());
        Assert.AreEqual(root, plan.Parent.Path);
        Assert.AreEqual(0x00000004u, ProductParentNativeAccessEvidence.FileAddSubdirectory);
        Assert.AreEqual(ProductParentNativeAccessEvidence.FileDeleteChild, plan.Parent.DesiredAccess);
        foreach (var (kind, request) in new[]
                 {
                     ("Service", plan.Service), (".service-next-11111111111111111111111111111111", plan.Next),
                     (".service-prev-11111111111111111111111111111111", plan.Previous),
                     (".service-abandoned-11111111111111111111111111111111", plan.Abandoned)
                 })
        {
            Assert.AreEqual(Path.Combine(root, kind), request.Path);
            Assert.AreEqual(ProductParentNativeAccessEvidence.Delete, request.DesiredAccess);
        }

        var opens = new List<(string Path, uint Access)>();
        foreach (var request in requests)
        {
            var result = ProductParentNativeAccessEvidence.Probe(request, (path, access) =>
            {
                opens.Add((path, access));
                throw new Win32Exception(5);
            });
            Assert.AreEqual("passed", result.Outcome);
            Assert.AreEqual(5, result.NativeError);
            Assert.AreEqual("native-open", result.Stage);
        }
        CollectionAssert.AreEqual(requests.Select(static item => (item.Path, item.DesiredAccess)).ToArray(),
            opens.ToArray());
        Assert.IsFalse(Directory.Exists(root));

        var sample = plan.Next;
        Assert.AreEqual("unexpected-success", ProductParentNativeAccessEvidence.Probe(sample,
            static (_, _) => { }).Outcome);
        foreach (var code in new[] { 2, 32, 145 })
        {
            var result = ProductParentNativeAccessEvidence.Probe(sample,
                (_, _) => throw new Win32Exception(code));
            Assert.AreEqual("failed", result.Outcome);
            Assert.AreEqual(code, result.NativeError);
        }
        var generic = ProductParentNativeAccessEvidence.Probe(sample,
            static (_, _) => throw new IOException("Unclassified failure."));
        Assert.AreEqual("failed", generic.Outcome);
        Assert.AreEqual(unchecked((int)0x80131620), generic.HResult);
        Assert.IsNull(generic.NativeError);
        var managedDenial = ProductParentNativeAccessEvidence.Probe(sample,
            static (_, _) => throw new UnauthorizedAccessException("Managed denial has no native error."));
        Assert.AreEqual("failed", managedDenial.Outcome);
        Assert.IsNull(managedDenial.NativeError);
    }

    [TestMethod]
    public void Product_parent_harness_source_contains_no_managed_rename_operation()
    {
        // This narrow guard covers the product-parent producer only. The older,
        // separate ACL harness has its own transaction rename probes.
        var source = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "tests",
            "Vantrel.Security.LocalServiceAclHarness", "ProductParentHarnessMode.cs"));
        foreach (var operation in new[]
                 {
                     "Directory.Move(", "File.Move(", "MoveFileEx(", "SetFileInformationByHandle("
                 })
            Assert.IsFalse(source.Contains(operation, StringComparison.Ordinal),
                "Product-parent evidence must not attempt a managed-sibling rename.");
        Assert.IsFalse(source.Contains("-moved", StringComparison.Ordinal),
            "Product-parent evidence must not construct a rename destination.");
    }

    [TestMethod]
    public void Filtered_user_native_denial_helper_rejects_unclassified_failures()
    {
        AssertNativeDenied(() => throw new Win32Exception(5));
        Assert.ThrowsException<AssertFailedException>(() => AssertNativeDenied(static () => { }));
        Assert.ThrowsException<Win32Exception>(() => AssertNativeDenied(() => throw new Win32Exception(32)));
        Assert.ThrowsException<Win32Exception>(() => AssertNativeDenied(() => throw new Win32Exception(145)));
        Assert.ThrowsException<IOException>(() => AssertNativeDenied(() => throw new IOException("Unclassified failure.")));
        Assert.ThrowsException<UnauthorizedAccessException>(() => AssertNativeDenied(() =>
            throw new UnauthorizedAccessException("Managed denial has no native error.")));
    }

    [TestMethod]
    public void Harness_publish_output_is_configuration_bound_and_complete_without_service_creation()
    {
        var repository = FindRepositoryRoot();
        var debug = HarnessPublishPath(repository, "Debug");
        var release = HarnessPublishPath(repository, "Release");
        Assert.AreNotEqual(debug, release);
        StringAssert.Contains(debug, Path.Combine("bin", "Debug", "net10.0-windows", "win-x64", "publish"));
        StringAssert.Contains(release, Path.Combine("bin", "Release", "net10.0-windows", "win-x64", "publish"));
        Assert.ThrowsException<IOException>(() => HarnessPublishPath(repository, "Other"));

        using var source = HarnessOutput();
        foreach (var name in HarnessPayload)
            Assert.IsTrue(source.ReadAllBytes(name).Length > 0, "Harness publish entry is empty: " + name);
    }

    [TestMethod]
    public void Harness_publish_root_is_derived_from_the_test_assembly_not_the_working_directory()
    {
        var assemblyPath = typeof(V2ProductParentEffectiveRightsTests).Assembly.Location;
        var repository = FindRepositoryRootFromAssembly(assemblyPath);
        Assert.IsTrue(string.Equals(repository, FindRepositoryRoot(), StringComparison.OrdinalIgnoreCase));
        var testProject = Path.Combine(repository, "tests", "Vantrel.Security.Ipc.Tests");
        foreach (var configuration in new[] { "Debug", "Release" })
        {
            var fixedAssemblyPath = Path.Combine(testProject, "bin", configuration,
                "net10.0-windows", Path.GetFileName(assemblyPath));
            Assert.IsTrue(string.Equals(repository, FindRepositoryRootFromAssembly(fixedAssemblyPath),
                StringComparison.OrdinalIgnoreCase));
        }
        Assert.ThrowsException<IOException>(() => FindRepositoryRootFromAssembly(
            Path.Combine(Path.GetTempPath(), "unrelated", Path.GetFileName(assemblyPath))));
    }

    [TestMethod]
    public void Harness_payload_rejects_missing_EventLog_message_file_before_fixture_creation()
    {
        var root = NewTempDisposableRoot();
        var tracked = new Dictionary<string, TrackedObject>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using (var directory = V2ProductParentFileSystemSecurity.CreateNewDisposableDirectory(root,
                       enforceAcl: false))
                tracked.Add(root, Capture(directory, isDirectory: true));
            foreach (var name in HarnessPayload.Where(name => name != "System.Diagnostics.EventLog.Messages.dll"))
            {
                var path = Path.Combine(root, name);
                using var stream = V2ServiceTreeFileSystemSecurity.CreateNewFile(path, enforceAcl: false);
                stream.WriteByte(1);
                stream.Flush(flushToDisk: true);
                tracked.Add(path, Capture(stream.SafeFileHandle, isDirectory: false));
            }
            Assert.ThrowsException<IOException>(() => OpenProtectedPayload(root));
            var messagePath = Path.Combine(root, "System.Diagnostics.EventLog.Messages.dll");
            using (var stream = V2ServiceTreeFileSystemSecurity.CreateNewFile(messagePath, enforceAcl: false))
            {
                stream.WriteByte(1);
                stream.Flush(flushToDisk: true);
                tracked.Add(messagePath, Capture(stream.SafeFileHandle, isDirectory: false));
            }
            using var complete = OpenProtectedPayload(root);
            foreach (var name in HarnessPayload)
                Assert.AreEqual(1, complete.ReadAllBytes(name).Length);
        }
        finally { CleanupTrackedFixture(root, root, tracked); }
    }

    [TestMethod]
    public void Harness_runtimeconfig_reader_rejects_oversize_before_allocation_and_accepts_exact_bound()
    {
        AssertBoundedHarnessJsonRead(RuntimeConfigName,
            LocalServiceHarnessPublishContract.MaximumRuntimeConfigBytes);
    }

    [TestMethod]
    public void Harness_deps_reader_rejects_oversize_before_allocation_and_accepts_exact_bound()
    {
        AssertBoundedHarnessJsonRead(DepsName,
            LocalServiceHarnessPublishContract.MaximumDepsBytes);
    }

    [TestMethod]
    public void Harness_payload_rejects_future_dated_eighth_direct_file()
    {
        var root = NewTempDisposableRoot();
        var tracked = new Dictionary<string, TrackedObject>(StringComparer.OrdinalIgnoreCase);
        try
        {
            CreateSyntheticHarnessPayload(root, tracked);
            using (var seven = OpenProtectedPayload(root))
                foreach (var name in HarnessPayload)
                    Assert.AreEqual(1, seven.ReadAllBytes(name).Length);

            var extra = Path.Combine(root, "unexpected-stale-runtime.dll");
            using (var stream = V2ServiceTreeFileSystemSecurity.CreateNewFile(extra, enforceAcl: false))
            {
                stream.WriteByte(1);
                stream.Flush(flushToDisk: true);
                tracked.Add(extra, Capture(stream.SafeFileHandle, isDirectory: false));
            }
            File.SetLastWriteTimeUtc(extra, DateTime.UtcNow.AddYears(1));
            Assert.AreEqual(HarnessPayload.Length + 1, Directory.GetFileSystemEntries(root).Length);
            Assert.IsFalse((File.GetAttributes(extra) & FileAttributes.ReparsePoint) != 0);
            Assert.ThrowsException<IOException>(() => OpenProtectedPayload(root));

            DeleteTrackedObject(extra, tracked[extra], root);
            tracked.Remove(extra);
            using var restored = OpenProtectedPayload(root);
            Assert.AreEqual(1, restored.ReadAllBytes(HarnessPayload[0]).Length);
        }
        finally { CleanupTrackedFixture(root, root, tracked); }
    }

    private static void AssertBoundedHarnessJsonRead(string name, int maximumBytes)
    {
        foreach (var length in new[] { maximumBytes + 1, maximumBytes })
        {
            var root = NewTempDisposableRoot();
            var tracked = new Dictionary<string, TrackedObject>(StringComparer.OrdinalIgnoreCase);
            try
            {
                CreateSyntheticHarnessPayload(root, tracked, name, length);
                using var payload = OpenProtectedPayload(root);
                if (length > maximumBytes)
                    Assert.ThrowsException<IOException>(() => payload.ReadAllBytes(name, maximumBytes));
                else
                    Assert.AreEqual(maximumBytes, payload.ReadAllBytes(name, maximumBytes).Length);
            }
            finally { CleanupTrackedFixture(root, root, tracked); }
        }
    }

    private static void CreateSyntheticHarnessPayload(string root,
        IDictionary<string, TrackedObject> tracked, string? sizedFile = null, int sizedLength = 1)
    {
        using (var directory = V2ProductParentFileSystemSecurity.CreateNewDisposableDirectory(root,
                   enforceAcl: false))
            tracked.Add(root, Capture(directory, isDirectory: true));
        foreach (var name in HarnessPayload)
        {
            var path = Path.Combine(root, name);
            using var stream = V2ServiceTreeFileSystemSecurity.CreateNewFile(path, enforceAcl: false);
            if (name == sizedFile) stream.SetLength(sizedLength);
            else stream.WriteByte(1);
            stream.Flush(flushToDisk: true);
            tracked.Add(path, Capture(stream.SafeFileHandle, isDirectory: false));
        }
    }

    private static string NewTempDisposableRoot() =>
        Path.Combine(Path.GetTempPath(), ParentPrefix + Guid.NewGuid().ToString("N"));

    private static TrackedObject CreateTempDisposableRoot(string root)
    {
        using var created = V2ProductParentFileSystemSecurity.CreateNewDisposableDirectory(root,
            enforceAcl: false);
        return Capture(created, isDirectory: true);
    }

    private static void CleanupCreatedDisposableRoot(string root, TrackedObject? created)
    {
        if (created is not { } expected) return;
        // No pathname-only or recursive fallback. The native delete rechecks the exact
        // retained object, its final path, type, reparse state, and physical identity.
        DeleteTrackedObject(root, expected, root);
    }

    private static void RequireExactHarnessProbes(IReadOnlyList<HarnessAssertionResult> assertions)
    {
        var names = assertions.Select(static assertion => assertion.Name).ToArray();
        var expectedNames = ExpectedHarnessProbes.Select(static probe => probe.Name).ToArray();
        Assert.AreEqual(expectedNames.Length, assertions.Count);
        Assert.AreEqual(expectedNames.Length, names.Distinct(StringComparer.Ordinal).Count(),
            "LocalService probe names must be unique.");
        CollectionAssert.AreEquivalent(expectedNames, names,
            "LocalService probe names differ from the exact expected set.");
        foreach (var (name, allowed) in ExpectedHarnessProbes)
        {
            var assertion = assertions.Single(item => string.Equals(item.Name, name, StringComparison.Ordinal));
            Assert.AreEqual("passed", assertion.Outcome,
                $"LocalService probe {name}: {assertion.ExceptionType}, HRESULT={assertion.HResult:X8}, native={assertion.NativeError}");
            if (allowed)
            {
                Assert.IsNull(assertion.ExceptionType, $"Allowed probe {name} reported an exception.");
                Assert.IsNull(assertion.HResult, $"Allowed probe {name} reported a failure HRESULT.");
                Assert.IsNull(assertion.NativeError, $"Allowed probe {name} reported a native error.");
            }
            else
            {
                Assert.IsFalse(string.IsNullOrWhiteSpace(assertion.ExceptionType),
                    $"Denied probe {name} lacks exception evidence.");
                Assert.IsNotNull(assertion.HResult, $"Denied probe {name} lacks a failure HRESULT.");
                Assert.AreEqual(5, assertion.NativeError, $"Denied probe {name} was not denied access.");
                if (name.EndsWith("-right", StringComparison.Ordinal))
                {
                    // Every right probe uses CreateFileW. A managed exception cannot supply
                    // machine-checkable native denial even if a result claims native error 5.
                    Assert.AreEqual(typeof(Win32Exception).FullName, assertion.ExceptionType);
                    Assert.AreEqual(new Win32Exception(5).HResult, assertion.HResult);
                    Assert.AreEqual("native-open", assertion.Stage);
                }
                else
                {
                    var nativeDenied = assertion.ExceptionType == typeof(Win32Exception).FullName &&
                        assertion.HResult == new Win32Exception(5).HResult;
                    var managedDenied = assertion.ExceptionType is "System.UnauthorizedAccessException" or "System.IO.IOException" &&
                        assertion.HResult == unchecked((int)0x80070005);
                    Assert.IsTrue(nativeDenied || managedDenied,
                        $"Denied probe {name} lacks exact access-denied evidence.");
                }
            }
        }
    }

    private static void CreateProductChildren(string parent, ValidatedHarnessPayload source,
        IDictionary<string, TrackedObject> tracked)
    {
        var service = Path.Combine(parent, "Service");
        using (var created = V2ServiceTreeFileSystemSecurity.CreateNewDirectory(service))
            tracked.Add(service, Capture(created, isDirectory: true));
        foreach (var fileName in HarnessPayload)
        {
            var bytes = source.ReadAllBytes(fileName);
            var path = Path.Combine(service, fileName);
            using var stream = V2ServiceTreeFileSystemSecurity.CreateNewFile(path);
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
            tracked.Add(path, Capture(stream.SafeFileHandle, isDirectory: false));
        }
        var readProbe = Path.Combine(service, "read-probe.bin");
        using (var stream = V2ServiceTreeFileSystemSecurity.CreateNewFile(readProbe))
        {
            stream.WriteByte(0x42);
            stream.Flush(flushToDisk: true);
            tracked.Add(readProbe, Capture(stream.SafeFileHandle, isDirectory: false));
        }
        foreach (var kind in new[] { "next", "prev", "abandoned" })
        {
            var siblingPath = Path.Combine(parent, ".service-" + kind + "-11111111111111111111111111111111");
            using var sibling = V2ServiceTreeFileSystemSecurity.CreateNewDirectory(siblingPath);
            tracked.Add(siblingPath, Capture(sibling, isDirectory: true));
        }
        foreach (var name in new[] { "Desktop", "OfflineUpdateTool" })
        {
            var child = Path.Combine(parent, name);
            using (var created = V2ServiceTreeFileSystemSecurity.CreateNewDirectory(child,
                       enforceAcl: false))
                tracked.Add(child, Capture(created, isDirectory: true));
            var file = Path.Combine(child, "read-probe.bin");
            using var stream = new FileStream(file, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            stream.WriteByte(0x42);
            stream.Flush(flushToDisk: true);
            tracked.Add(file, Capture(stream.SafeFileHandle, isDirectory: false));
        }
    }

    private static void CreateResultFile(string directory, string file,
        IDictionary<string, TrackedObject> tracked)
    {
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var local = new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null);
        var directoryAcl = new DirectorySecurity();
        directoryAcl.SetOwner(admins);
        directoryAcl.SetAccessRuleProtection(true, false);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        directoryAcl.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        directoryAcl.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        directoryAcl.AddAccessRule(new FileSystemAccessRule(local, ReadAndExecute,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        var directoryBytes = directoryAcl.GetSecurityDescriptorBinaryForm();
        var pinned = GCHandle.Alloc(directoryBytes, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = checked((uint)Marshal.SizeOf<SecurityAttributes>()),
                SecurityDescriptor = pinned.AddrOfPinnedObject(),
                InheritHandle = false
            };
            if (!CreateDirectoryWithSecurity(directory, ref attributes))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "Disposable result directory create-new failed.");
        }
        finally { pinned.Free(); }
        using (var created = V2ServiceTreeFileSystemSecurity.OpenValidatedDirectory(directory,
                   enforceAcl: false))
            tracked.Add(directory, Capture(created, isDirectory: true));

        var fileAcl = new FileSecurity();
        fileAcl.SetOwner(admins);
        fileAcl.SetAccessRuleProtection(true, false);
        fileAcl.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
        fileAcl.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        fileAcl.AddAccessRule(new FileSystemAccessRule(local,
            FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Synchronize,
            AccessControlType.Allow));
        using var stream = new FileInfo(file).Create(FileMode.CreateNew, FileSystemRights.FullControl,
            FileShare.None, 4096, FileOptions.WriteThrough, fileAcl);
        tracked.Add(file, Capture(stream.SafeFileHandle, isDirectory: false));
    }

    private static TrackedObject Capture(SafeFileHandle handle, bool isDirectory)
    {
        var metadata = ComponentInspectionNative.GetMetadata(handle);
        if (metadata.IsReparsePoint || metadata.IsDirectory != isDirectory)
            throw new IOException("Fixture object type changed during creation.");
        return new(isDirectory, metadata.VolumeSerial, metadata.Identity);
    }

    private static void CleanupTrackedFixture(string parent, string resultRoot,
        IReadOnlyDictionary<string, TrackedObject> tracked)
    {
        // Verify the entire expected inventory before any deletion. A missing, substituted,
        // reparse, or unexpected entry is evidence; leave the fixture for manual review.
        foreach (var item in tracked)
            RequireTrackedObject(item.Key, item.Value, parent);
        foreach (var item in tracked.Where(item => item.Value.IsDirectory))
        {
            var actual = Directory.EnumerateFileSystemEntries(item.Key)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
            var expected = tracked.Keys.Where(path =>
                    string.Equals(Path.GetDirectoryName(path), item.Key, StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
            if (!actual.SequenceEqual(expected, StringComparer.OrdinalIgnoreCase))
                throw new IOException("Disposable fixture inventory differs; unexpected residue preserved: " + item.Key);
        }

        foreach (var item in tracked.OrderByDescending(item => item.Key.Length))
            DeleteTrackedObject(item.Key, item.Value, parent);
        if (tracked.ContainsKey(parent) && Directory.Exists(parent) ||
            tracked.ContainsKey(resultRoot) && Directory.Exists(resultRoot))
            throw new IOException("Disposable fixture deletion did not retire its roots.");
    }

    private static void RequireTrackedObject(string path, TrackedObject expected, string parent)
    {
        using var handle = string.Equals(path, parent, StringComparison.OrdinalIgnoreCase)
            ? V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(path, enforceAcl: false)
            : expected.IsDirectory
                ? V2ServiceTreeFileSystemSecurity.OpenValidatedDirectory(path, enforceAcl: false)
                : V2ServiceTreeFileSystemSecurity.OpenValidatedFile(path, enforceAcl: false);
        RequireSameIdentity(handle, expected);
    }

    private static void DeleteTrackedObject(string path, TrackedObject expected, string parent)
    {
        using var handle = ComponentInspectionNative.OpenProtectedForDeletion(path, expected.IsDirectory);
        if (string.Equals(path, parent, StringComparison.OrdinalIgnoreCase))
            V2ProductParentFileSystemSecurity.RequireValidatedDisposableHandle(handle, path, enforceAcl: false);
        else if (expected.IsDirectory)
            V2ServiceTreeFileSystemSecurity.RequireValidatedDirectoryHandle(handle, path, enforceAcl: false);
        else
            V2ServiceTreeFileSystemSecurity.RequireValidatedFileHandle(handle, path, enforceAcl: false);
        RequireSameIdentity(handle, expected);
        var current = ComponentInspectionNative.GetMetadata(handle);
        ComponentInspectionNative.MarkValidatedObjectForDeletion(handle, current, path, expected.IsDirectory);
    }

    private static void RequireSameIdentity(SafeFileHandle handle, TrackedObject expected)
    {
        var current = ComponentInspectionNative.GetMetadata(handle);
        if (current.IsReparsePoint || current.IsDirectory != expected.IsDirectory ||
            current.VolumeSerial != expected.VolumeSerial || current.Identity != expected.Identity)
            throw new IOException("Disposable fixture object identity changed; residue preserved.");
    }

    private static void VerifyFilteredNonAdministratorRights(string parent)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        var sidMemory = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, sidMemory, bytes.Length);
            var disabled = new[] { new SidAndAttributes { Sid = sidMemory } };
            if (!CreateRestrictedToken(identity.AccessToken, flags: 1, disableSidCount: 1,
                    disabled, deletePrivilegeCount: 0, IntPtr.Zero, restrictedSidCount: 0,
                    IntPtr.Zero, out var restricted))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRestrictedToken failed.");
            using (restricted)
                WindowsIdentity.RunImpersonated(restricted, () =>
                {
                    using var current = WindowsIdentity.GetCurrent();
                    Assert.IsFalse(new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator));
                    Assert.IsTrue(Directory.EnumerateFileSystemEntries(parent).Any());
                    Assert.AreEqual(0x42, File.ReadAllBytes(Path.Combine(parent, "Desktop", "read-probe.bin"))[0]);
                    Assert.AreEqual(0x42, File.ReadAllBytes(Path.Combine(parent, "OfflineUpdateTool", "read-probe.bin"))[0]);
                    AssertDenied(() => Directory.CreateDirectory(Path.Combine(parent, "user-denied-directory")));
                    AssertDenied(() => File.WriteAllBytes(Path.Combine(parent, "user-denied-file.bin"), [0x42]));
                    AssertNativeDenied(() => OpenAccess(parent, FileDeleteChild));
                    AssertNativeDenied(() => OpenAccess(parent,
                        ProductParentNativeAccessEvidence.FileAddSubdirectory));
                    AssertDenied(() => OpenAccess(parent, WriteDac));
                    AssertDenied(() => OpenAccess(parent, WriteOwner));
                    AssertNativeDenied(() => OpenAccess(Path.Combine(parent,
                        ".service-next-11111111111111111111111111111111"), DeleteAccess));
                    AssertDenied(() => ChangeParentAcl(parent));
                    AssertDenied(() => TakeParentOwnership(parent, current.User!));
                });
        }
        finally { Marshal.FreeHGlobal(sidMemory); }
    }

    private static void VerifyAdministratorServicingRights(string parent)
    {
        OpenAccess(parent, FileDeleteChild);
        OpenAccess(parent, WriteDac);
        OpenAccess(parent, WriteOwner);
        var probe = Path.Combine(parent, "administrator-create-probe");
        Directory.CreateDirectory(probe);
        Directory.Delete(probe);
    }

    private static void ChangeParentAcl(string parent)
    {
        var info = new DirectoryInfo(parent);
        var descriptor = info.GetAccessControl();
        descriptor.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.WriteData, AccessControlType.Allow));
        info.SetAccessControl(descriptor);
    }

    private static void TakeParentOwnership(string parent, SecurityIdentifier owner)
    {
        var info = new DirectoryInfo(parent);
        var descriptor = info.GetAccessControl();
        descriptor.SetOwner(owner);
        info.SetAccessControl(descriptor);
    }

    private static void AssertDenied(Action operation)
    {
        try { operation(); }
        catch (Win32Exception error) when (error.NativeErrorCode == 5) { return; }
        catch (Exception error) when (error is UnauthorizedAccessException or IOException &&
                                      error.HResult == unchecked((int)0x80070005)) { return; }
        Assert.Fail("A filtered non-administrator token unexpectedly received product-parent mutation rights.");
    }

    private static void AssertNativeDenied(Action operation)
    {
        try { operation(); }
        catch (Win32Exception error) when (error.NativeErrorCode == 5) { return; }
        Assert.Fail("A native right request was not denied with ERROR_ACCESS_DENIED.");
    }

    private static void OpenAccess(string path, uint access)
    {
        using var handle = CreateFileW(path, access, FileShare.ReadWrite | FileShare.Delete,
            IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint | FileFlagBackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    private static ValidatedHarnessPayload HarnessOutput()
    {
        var assemblyPath = typeof(V2ProductParentEffectiveRightsTests).Assembly.Location;
        var assemblyDirectory = new DirectoryInfo(Path.GetDirectoryName(assemblyPath)!);
        var output = HarnessPublishPath(FindRepositoryRootFromAssembly(assemblyPath),
            assemblyDirectory.Parent?.Name);
        var payload = OpenProtectedPayload(output);
        try
        {
            // Parse exactly the bytes held by the protected source handles. This must
            // finish before the Administrator test creates a fixture or contacts SCM.
            LocalServiceHarnessPublishContract.Validate(
                payload.ReadAllBytes(RuntimeConfigName,
                    LocalServiceHarnessPublishContract.MaximumRuntimeConfigBytes),
                payload.ReadAllBytes(DepsName,
                    LocalServiceHarnessPublishContract.MaximumDepsBytes));
            return payload;
        }
        catch
        {
            payload.Dispose();
            throw;
        }
    }

    private static string FindRepositoryRoot() =>
        FindRepositoryRootFromAssembly(typeof(V2ProductParentEffectiveRightsTests).Assembly.Location);

    private static string FindRepositoryRootFromAssembly(string assemblyPath)
    {
        if (!Path.IsPathFullyQualified(assemblyPath))
            throw new IOException("Test assembly path is unavailable for local-service harness.");
        var assemblyDirectory = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(assemblyPath))!);
        for (var current = assemblyDirectory; current is not null; current = current.Parent)
        {
            if (current.Name != "Vantrel.Security.Ipc.Tests" || current.Parent?.Name != "tests" ||
                current.Parent.Parent is not { } repository)
                continue;
            if (!File.Exists(Path.Combine(repository.FullName, "Vantrel.Security.sln")) ||
                !File.Exists(Path.Combine(current.FullName, "Vantrel.Security.Ipc.Tests.csproj")) ||
                !File.Exists(Path.Combine(repository.FullName, "tests", "Vantrel.Security.LocalServiceAclHarness",
                    "Vantrel.Security.LocalServiceAclHarness.csproj")))
                break;
            var relative = Path.GetRelativePath(current.FullName, assemblyDirectory.FullName);
            if (relative is not ("bin\\Debug\\net10.0-windows" or "bin\\Release\\net10.0-windows"))
                break;
            return repository.FullName;
        }
        throw new IOException("Repository root unavailable for local-service harness.");
    }

    private static string HarnessPublishPath(string repository, string? configuration)
    {
        if (configuration is not ("Debug" or "Release"))
            throw new IOException("Harness configuration unavailable.");
        return Path.Combine(repository, "tests", "Vantrel.Security.LocalServiceAclHarness",
            "bin", configuration, "net10.0-windows", "win-x64", "publish");
    }

    private static ValidatedHarnessPayload OpenProtectedPayload(string output)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(output));
        RequireNoReparseHarnessAncestors(root);
        var rootHandle = ComponentInspectionNative.OpenProtected(root, directory: true);
        var files = new Dictionary<string, HarnessFileBinding>(StringComparer.Ordinal);
        try
        {
            var rootMetadata = RequireHarnessBinding(rootHandle, root, directory: true);
            var actual = Directory.EnumerateFileSystemEntries(root)
                .Select(Path.GetFileName).ToArray();
            var allowed = HarnessPayload;
            if (actual.Length != actual.Distinct(StringComparer.OrdinalIgnoreCase).Count() ||
                actual.Except(allowed, StringComparer.Ordinal).Any() ||
                HarnessPayload.Except(actual, StringComparer.Ordinal).Any())
                throw new IOException("Local-service harness publish file set is incomplete or unexpected.");

            foreach (var name in actual)
            {
                var path = Path.Combine(root, name!);
                var handle = ComponentInspectionNative.OpenProtected(path);
                try
                {
                    var metadata = RequireHarnessBinding(handle, path, directory: false);
                    if (metadata.Length is <= 0 or > MaximumHarnessFileBytes)
                        throw new IOException("Local-service harness publish file length is invalid.");
                    files.Add(name!, new(path, handle, metadata));
                }
                catch
                {
                    handle.Dispose();
                    throw;
                }
            }
            RequireHarnessBinding(rootHandle, root, directory: true, expectedMetadata: rootMetadata);
            return new(root, rootHandle, rootMetadata, files);
        }
        catch
        {
            foreach (var file in files.Values) file.Handle.Dispose();
            rootHandle.Dispose();
            throw;
        }
    }

    private static void RequireNoReparseHarnessAncestors(string path)
    {
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            using var handle = ComponentInspectionNative.OpenProtected(current, directory: true);
            RequireHarnessBinding(handle, current, directory: true);
        }
    }

    private static ComponentInspectionNative.Metadata RequireHarnessBinding(SafeFileHandle handle,
        string expectedPath, bool directory, ComponentInspectionNative.Metadata? expectedMetadata = null)
    {
        var metadata = ComponentInspectionNative.GetMetadata(handle);
        if (metadata.IsReparsePoint || metadata.IsDirectory != directory ||
            expectedMetadata is { } bound && metadata != bound ||
            !string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(ComponentInspectionNative.FinalPath(handle))),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(expectedPath)), StringComparison.OrdinalIgnoreCase) ||
            !directory && (ComponentInspectionNative.GetHardLinkCount(handle) != 1 ||
                           !ComponentInspectionNative.HasOnlyDefaultDataStream(handle)))
            throw new IOException("Local-service harness publish path is redirected or changed.");
        return metadata;
    }

    private sealed record HarnessFileBinding(string Path, SafeFileHandle Handle,
        ComponentInspectionNative.Metadata Metadata);

    private sealed class ValidatedHarnessPayload : IDisposable
    {
        private readonly string _root;
        private readonly SafeFileHandle _rootHandle;
        private readonly ComponentInspectionNative.Metadata _rootMetadata;
        private readonly IReadOnlyDictionary<string, HarnessFileBinding> _files;

        internal ValidatedHarnessPayload(string root, SafeFileHandle rootHandle,
            ComponentInspectionNative.Metadata rootMetadata, IReadOnlyDictionary<string, HarnessFileBinding> files)
        {
            _root = root;
            _rootHandle = rootHandle;
            _rootMetadata = rootMetadata;
            _files = files;
        }

        internal byte[] ReadAllBytes(string name, int maximumBytes = MaximumHarnessFileBytes)
        {
            if (maximumBytes is <= 0 or > MaximumHarnessFileBytes ||
                !_files.TryGetValue(name, out var file) || _rootHandle.IsClosed || file.Handle.IsClosed)
                throw new IOException("Local-service harness publish entry is unavailable.");
            RequireHarnessBinding(_rootHandle, _root, directory: true, expectedMetadata: _rootMetadata);
            var length = RequireHarnessBinding(file.Handle, file.Path, directory: false,
                expectedMetadata: file.Metadata).Length;
            if (length <= 0 || length > maximumBytes || length > int.MaxValue)
                throw new IOException("Local-service harness publish entry length exceeds its read bound.");
            var bytes = new byte[checked((int)length)];
            var offset = 0;
            while (offset < bytes.Length)
            {
                var read = RandomAccess.Read(file.Handle, bytes.AsSpan(offset), offset);
                if (read <= 0) throw new IOException("Local-service harness publish entry is truncated.");
                offset += read;
            }
            RequireHarnessBinding(file.Handle, file.Path, directory: false, expectedMetadata: file.Metadata);
            RequireHarnessBinding(_rootHandle, _root, directory: true, expectedMetadata: _rootMetadata);
            return bytes;
        }

        public void Dispose()
        {
            foreach (var file in _files.Values) file.Handle.Dispose();
            _rootHandle.Dispose();
        }
    }

    private static void RequireAdministrator()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows is required.");
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("An enabled Administrator token is required.");
    }

    private static string Quote(string value)
    {
        if (value.Contains('"')) throw new IOException("Harness command argument rejected.");
        return '"' + value + '"';
    }
}
