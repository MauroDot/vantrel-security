using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass, DoNotParallelize]
public sealed class CrossGenerationUpdateLockTests
{
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);
    private const string ManualPhase = "product-parent-evidence";
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier LocalService = new(WellKnownSidType.LocalServiceSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfo { public int DeleteFile; }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string newPath, string existingPath, nint securityAttributes);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle OpenForDeletion(string path, uint access, FileShare share,
        nint securityAttributes, uint creation, uint flags, nint template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int informationClass,
        ref FileDispositionInfo information, uint informationLength);

    [TestMethod]
    public void Fixed_lock_descriptor_is_exactly_Administrators_and_SYSTEM()
    {
        var descriptor = CrossGenerationLockFileSystemSecurity.CreateLockDescriptor();
        Assert.IsTrue(CrossGenerationLockFileSystemSecurity.ValidateLockDescriptor(descriptor).IsMatch);
        Assert.AreEqual(Administrators, descriptor.GetOwner(typeof(SecurityIdentifier)));
        Assert.IsTrue(descriptor.AreAccessRulesProtected);
        var rules = Rules(descriptor);
        Assert.AreEqual(2, rules.Length);
        foreach (var sid in new[] { Administrators, System })
        {
            var rule = rules.Single(rule => rule.IdentityReference.Equals(sid));
            Assert.AreEqual(FileSystemRights.FullControl, rule.FileSystemRights);
            Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
            Assert.AreEqual(InheritanceFlags.None, rule.InheritanceFlags);
            Assert.AreEqual(PropagationFlags.None, rule.PropagationFlags);
            Assert.IsFalse(rule.IsInherited);
        }
        Assert.IsFalse(rules.Any(rule => rule.IdentityReference.Equals(LocalService) ||
                                         rule.IdentityReference.Equals(Users)));
    }

    [TestMethod]
    public void Descriptor_rejects_wrong_owner_unprotected_DACL_and_extra_or_changed_ACE()
    {
        var owner = CrossGenerationLockFileSystemSecurity.CreateLockDescriptor();
        owner.SetOwner(Users);
        Assert.IsFalse(CrossGenerationLockFileSystemSecurity.ValidateLockDescriptor(owner).IsMatch);
        var inherited = CrossGenerationLockFileSystemSecurity.CreateLockDescriptor();
        inherited.SetAccessRuleProtection(false, true);
        Assert.IsFalse(CrossGenerationLockFileSystemSecurity.ValidateLockDescriptor(inherited).IsMatch);
        var extra = CrossGenerationLockFileSystemSecurity.CreateLockDescriptor();
        extra.AddAccessRule(new FileSystemAccessRule(LocalService, FileSystemRights.Write, AccessControlType.Allow));
        Assert.IsFalse(CrossGenerationLockFileSystemSecurity.ValidateLockDescriptor(extra).IsMatch);
        var changed = CrossGenerationLockFileSystemSecurity.CreateLockDescriptor();
        changed.RemoveAccessRuleAll(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
        changed.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.Read, AccessControlType.Allow));
        Assert.IsFalse(CrossGenerationLockFileSystemSecurity.ValidateLockDescriptor(changed).IsMatch);
    }

    [TestMethod]
    public async Task Lease_binds_retained_lock_to_one_Updates_root_and_fails_after_disposal()
    {
        using var fixture = new Scope();
        using var lease = await fixture.Lock().AcquireAsync(CancellationToken.None);
        lease.RequireHeldFor(fixture.UpdatesRoot);
        Assert.ThrowsException<IOException>(() => lease.RequireHeldFor(Path.Combine(fixture.Root, "other-updates")));
        lease.Dispose();
        Assert.ThrowsException<IOException>(() => lease.RequireHeldFor(fixture.UpdatesRoot));
    }

    [TestMethod]
    public async Task Contention_is_bounded_and_release_allows_a_second_acquisition()
    {
        using var fixture = new Scope();
        using var first = await fixture.Lock().AcquireAsync(CancellationToken.None);
        await Assert.ThrowsExceptionAsync<TimeoutException>(() =>
            fixture.Lock(TimeSpan.FromMilliseconds(125)).AcquireAsync(CancellationToken.None));
        first.Dispose();
        using var second = await fixture.Lock().AcquireAsync(CancellationToken.None);
        second.RequireHeldFor(fixture.UpdatesRoot);
    }

    [TestMethod]
    public async Task Contended_wait_is_cancellable_without_releasing_first_lease()
    {
        using var fixture = new Scope();
        using var first = await fixture.Lock().AcquireAsync(CancellationToken.None);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(125));
        await Assert.ThrowsExceptionAsync<TaskCanceledException>(() => fixture.Lock().AcquireAsync(cancellation.Token));
        first.RequireHeldFor(fixture.UpdatesRoot);
    }

    [TestMethod, TestCategory("AdministratorOnly"), TestCategory("ManualAclHarness")]
    public async Task Protected_cross_generation_lock_round_trip_requires_administrator()
    {
        // The manual phase is checked before creating protected infrastructure.
        ManualAclHarnessGate.RequirePhase(ManualPhase);
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Administrator token required.");

        using var fixture = new Scope(protectedAcl: true);
        using (var handle = ComponentInspectionNative.OpenProtected(fixture.LockPath))
        {
            var metadata = ComponentInspectionNative.GetMetadata(handle);
            Assert.IsFalse(metadata.IsDirectory || metadata.IsReparsePoint);
            Assert.IsTrue(CrossGenerationUpdateLock.PathsEqual(
                ComponentInspectionNative.FinalPath(handle), fixture.LockPath));
            Assert.AreEqual(1U, ComponentInspectionNative.GetHardLinkCount(handle));
            Assert.IsTrue(ComponentInspectionNative.HasOnlyDefaultDataStream(handle));
            CrossGenerationLockFileSystemSecurity.RequireLockFile(handle, fixture.LockPath, enforceAcl: true);
        }
        foreach (var (path, role) in new[]
        {
            (fixture.Root, UpdateDirectoryRole.ProductRoot),
            (fixture.UpdatesRoot, UpdateDirectoryRole.UpdatesRoot)
        })
            Assert.IsTrue(UpdateFilesystemSecurity.ValidateDirectoryOnDisk(role, new DirectoryInfo(path)).IsMatch);
        var descriptor = new FileInfo(fixture.LockPath).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        Assert.IsTrue(CrossGenerationLockFileSystemSecurity.ValidateLockDescriptor(descriptor).IsMatch);
        Assert.AreEqual(Administrators, descriptor.GetOwner(typeof(SecurityIdentifier)));
        Assert.IsTrue(descriptor.AreAccessRulesProtected);
        var rules = Rules(descriptor);
        Assert.AreEqual(2, rules.Length);
        Assert.IsTrue(rules.All(rule => rule.AccessControlType == AccessControlType.Allow &&
                                        rule.FileSystemRights == FileSystemRights.FullControl &&
                                        (rule.IdentityReference.Equals(Administrators) ||
                                         rule.IdentityReference.Equals(System))));
        Assert.IsFalse(rules.Any(rule => rule.IdentityReference.Equals(LocalService) ||
                                         rule.IdentityReference.Equals(Users)));

        using (var first = await fixture.Lock(enforceAcl: true).AcquireAsync(CancellationToken.None))
            first.RequireHeldFor(fixture.UpdatesRoot);
        using var second = await fixture.Lock(enforceAcl: true).AcquireAsync(CancellationToken.None);
        second.RequireHeldFor(fixture.UpdatesRoot);
    }

    [TestMethod]
    public async Task Additional_hard_link_blocks_common_lock_acquisition()
    {
        using var fixture = new Scope();
        var alternate = Path.Combine(fixture.Root, "second-link.lock");
        if (!CreateHardLink(alternate, fixture.LockPath, nint.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            if (error is 1 or 50 or 1314)
                Assert.Inconclusive($"Hard-link creation unavailable: Windows error {error}.");
            Assert.Fail($"Hard-link creation failed: Windows error {error}.");
        }
        fixture.TrackCreated(alternate, directory: false);
        using (var handle = ComponentInspectionNative.OpenProtected(fixture.LockPath))
            Assert.AreEqual(2U, ComponentInspectionNative.GetHardLinkCount(handle));
        await Assert.ThrowsExceptionAsync<IOException>(() => fixture.Lock().AcquireAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task Named_stream_blocks_common_lock_acquisition()
    {
        using var fixture = new Scope();
        File.WriteAllText(fixture.LockPath + ":unexpected", "stream");
        using (var handle = ComponentInspectionNative.OpenProtected(fixture.LockPath))
            Assert.IsFalse(ComponentInspectionNative.HasOnlyDefaultDataStream(handle));
        await Assert.ThrowsExceptionAsync<IOException>(() => fixture.Lock().AcquireAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task Simulated_V1_and_V2_admissions_share_one_publication_boundary()
    {
        using var fixture = new Scope();
        using var first = await fixture.Lock().AcquireAsync(CancellationToken.None);
        first.RequireHeldFor(fixture.UpdatesRoot);
        // Future V1/V2 admission will inspect both journals and publish one generation's
        // absent-to-present journal while the owner and this shared lease are both held.
        var v1JournalPresent = false;
        var v2JournalPresent = false;
        Assert.IsFalse(v1JournalPresent || v2JournalPresent);
        v1JournalPresent = true;
        var v2Attempting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var v2Entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var second = Task.Run(async () =>
        {
            var pending = fixture.Lock().AcquireAsync(CancellationToken.None);
            v2Attempting.TrySetResult();
            using var lease = await pending;
            lease.RequireHeldFor(fixture.UpdatesRoot);
            v2Entered.TrySetResult();
            Assert.IsTrue(v1JournalPresent);
            Assert.IsFalse(v2JournalPresent);
        });
        await v2Attempting.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.ThrowsExceptionAsync<TimeoutException>(() => v2Entered.Task.WaitAsync(TimeSpan.FromMilliseconds(125)));
        first.Dispose();
        await second.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [DataTestMethod]
    [DataRow("missing")]
    [DataRow("directory")]
    [DataRow("reparse")]
    public async Task Missing_wrong_type_or_reparse_lock_fails_closed(string scenario)
    {
        using var fixture = new Scope();
        fixture.DeleteTracked(fixture.LockPath);
        if (scenario == "directory") fixture.CreateDirectory(fixture.LockPath);
        if (scenario == "reparse")
        {
            var target = Path.Combine(fixture.Root, "target");
            fixture.CreateFile(target, "target");
            try { File.CreateSymbolicLink(fixture.LockPath, target); }
            catch (Exception error) when (error.HResult == PrivilegeNotHeldHResult)
            { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
            fixture.TrackCreated(fixture.LockPath, directory: false);
        }
        if (scenario == "missing")
            await Assert.ThrowsExceptionAsync<FileNotFoundException>(() => fixture.Lock().AcquireAsync(CancellationToken.None));
        else
            await Assert.ThrowsExceptionAsync<IOException>(() => fixture.Lock().AcquireAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task Reparse_Updates_root_fails_closed()
    {
        using var fixture = new Scope();
        var moved = Path.Combine(fixture.Root, "real-updates");
        fixture.MoveUpdates(moved);
        try { Directory.CreateSymbolicLink(fixture.UpdatesRoot, moved); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeldHResult)
        { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
        fixture.TrackCreated(fixture.UpdatesRoot, directory: true);
        await Assert.ThrowsExceptionAsync<IOException>(() => fixture.Lock().AcquireAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task ACL_enforcement_rejects_a_normal_user_fixture_and_lock_descriptor_mismatch()
    {
        using var fixture = new Scope();
        using var handle = ComponentInspectionNative.OpenProtected(fixture.LockPath);
        Assert.ThrowsException<IOException>(() =>
            CrossGenerationLockFileSystemSecurity.RequireLockFile(handle, fixture.LockPath, enforceAcl: true));
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            new CrossGenerationUpdateLock(fixture.UpdatesRoot, enforceAcl: true).AcquireAsync(CancellationToken.None));
    }

    [TestMethod]
    public void Disposable_constructor_cannot_target_production_updates_namespace()
    {
        foreach (var protectedRoot in new[]
        {
            FixedUpdatePaths.VantrelRoot,
            FixedUpdatePaths.UpdatesRoot,
            FixedUpdatePaths.InstalledServiceRoot,
            Path.GetDirectoryName(FixedUpdatePaths.InstalledServiceRoot)!,
            Path.GetDirectoryName(FixedUpdatePaths.VantrelRoot)!,
            Path.Combine(Path.GetDirectoryName(FixedUpdatePaths.InstalledServiceRoot)!, "Desktop"),
            @"\\?\" + FixedUpdatePaths.UpdatesRoot,
            @"\\.\" + FixedUpdatePaths.UpdatesRoot,
            Path.Combine(Path.GetPathRoot(FixedUpdatePaths.InstalledServiceRoot)!, "PROGRA~1",
                "Vantrel Security", "Service"),
            Path.Combine(Path.GetTempPath(), "other-" + Guid.NewGuid().ToString("N"), "Updates"),
            Path.Combine(Path.GetTempPath(), "VANTRE~1", "Updates")
        })
            Assert.ThrowsException<ArgumentException>(() => new CrossGenerationUpdateLock(protectedRoot, false));
        Assert.ThrowsException<ArgumentException>(() => new CrossGenerationUpdateLock(FixedUpdatePaths.UpdatesRoot, true));
    }

    [TestMethod]
    public async Task Direct_lease_seam_rejects_production_overlap_and_invalid_wait()
    {
        foreach (var protectedRoot in new[]
        {
            FixedUpdatePaths.VantrelRoot,
            FixedUpdatePaths.UpdatesRoot,
            FixedUpdatePaths.InstalledServiceRoot,
            Path.GetDirectoryName(FixedUpdatePaths.InstalledServiceRoot)!,
            @"\\?\" + FixedUpdatePaths.UpdatesRoot,
            @"\\.\" + FixedUpdatePaths.UpdatesRoot,
            Path.Combine(Path.GetPathRoot(FixedUpdatePaths.InstalledServiceRoot)!, "PROGRA~1",
                "Vantrel Security", "Service"),
            Path.Combine(Path.GetTempPath(), "other-" + Guid.NewGuid().ToString("N"), "Updates"),
            Path.Combine(Path.GetTempPath(), "VANTRE~1", "Updates")
        })
            await Assert.ThrowsExceptionAsync<IOException>(() => CrossGenerationUpdateLease.AcquireAsync(
                protectedRoot, enforceAcl: false, TimeSpan.FromMilliseconds(1), CancellationToken.None));
        using var fixture = new Scope();
        await Assert.ThrowsExceptionAsync<IOException>(() => CrossGenerationUpdateLease.AcquireAsync(
            fixture.UpdatesRoot, enforceAcl: false, TimeSpan.FromSeconds(31), CancellationToken.None));
    }

    private static FileSystemAccessRule[] Rules(FileSecurity descriptor) =>
        descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();

    private sealed class Scope : IDisposable
    {
        private readonly Dictionary<string, TrackedObject> _tracked = new(StringComparer.OrdinalIgnoreCase);
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-cross-generation-" + Guid.NewGuid().ToString("N"));
        internal string UpdatesRoot => Path.Combine(Root, "Updates");
        internal string LockPath => Path.Combine(UpdatesRoot, CrossGenerationUpdateLock.LockFileName);

        internal Scope(bool protectedAcl = false)
        {
            try
            {
                CreateDirectory(Root);
                if (protectedAcl)
                    new DirectoryInfo(Root).SetAccessControl(
                        UpdateFilesystemSecurity.CreateDirectoryDescriptor(UpdateDirectoryRole.ProductRoot));
                CreateDirectory(UpdatesRoot);
                if (protectedAcl)
                    new DirectoryInfo(UpdatesRoot).SetAccessControl(
                        UpdateFilesystemSecurity.CreateDirectoryDescriptor(UpdateDirectoryRole.UpdatesRoot));
                if (protectedAcl)
                {
                    using var created = new FileInfo(LockPath).Create(FileMode.CreateNew,
                        FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.WriteThrough,
                        CrossGenerationLockFileSystemSecurity.CreateLockDescriptor());
                    Track(LockPath, created.SafeFileHandle, directory: false);
                }
                else
                {
                    using var created = new FileStream(LockPath, FileMode.CreateNew, FileAccess.ReadWrite,
                        FileShare.None);
                    Track(LockPath, created.SafeFileHandle, directory: false);
                }
            }
            catch { Dispose(); throw; }
        }

        internal CrossGenerationUpdateLock Lock(TimeSpan? maximumWait = null, bool enforceAcl = false) =>
            new(UpdatesRoot, enforceAcl, maximumWait);

        internal void CreateDirectory(string path)
        {
            using var created = V2ServiceTreeFileSystemSecurity.CreateNewDirectory(path, enforceAcl: false);
            Track(path, created, directory: true);
        }

        internal void CreateFile(string path, string contents)
        {
            using var created = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            created.Write(Encoding.UTF8.GetBytes(contents));
            created.Flush(flushToDisk: true);
            Track(path, created.SafeFileHandle, directory: false);
        }

        internal void TrackCreated(string path, bool directory)
        {
            using var handle = ComponentInspectionNative.OpenProtected(path, directory);
            Track(path, handle, directory);
        }

        private void Track(string path, SafeFileHandle handle, bool directory)
        {
            var metadata = ComponentInspectionNative.GetMetadata(handle);
            if (metadata.IsDirectory != directory || !CrossGenerationUpdateLock.PathsEqual(
                    ComponentInspectionNative.FinalPath(handle), path))
                throw new IOException("Cross-generation fixture identity could not be captured.");
            _tracked.Add(path, new TrackedObject(directory, metadata.IsReparsePoint,
                metadata.VolumeSerial, metadata.Identity));
        }

        internal void MoveUpdates(string destination)
        {
            Directory.Move(UpdatesRoot, destination);
            foreach (var item in _tracked.Where(item => CrossGenerationUpdateLock.PathsEqual(item.Key, UpdatesRoot) ||
                         item.Key.StartsWith(UpdatesRoot + Path.DirectorySeparatorChar,
                             StringComparison.OrdinalIgnoreCase)).ToArray())
            {
                _tracked.Remove(item.Key);
                _tracked.Add(destination + item.Key[UpdatesRoot.Length..], item.Value);
            }
        }

        internal void DeleteTracked(string path)
        {
            var expected = _tracked[path];
            DeleteObject(path, expected);
            _tracked.Remove(path);
        }

        public void Dispose()
        {
            if (_tracked.Count == 0) return;
            // Do not clean a partially substituted fixture. Check every exact identity and
            // direct-child inventory before deleting anything; never recursively delete.
            foreach (var item in _tracked) RequireTracked(item.Key, item.Value);
            foreach (var item in _tracked.Where(item => item.Value.Directory && !item.Value.Reparse))
            {
                var actual = Directory.EnumerateFileSystemEntries(item.Key)
                    .OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
                var expected = _tracked.Keys.Where(path => CrossGenerationUpdateLock.PathsEqual(
                        Path.GetDirectoryName(path)!, item.Key))
                    .OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
                if (!actual.SequenceEqual(expected, StringComparer.OrdinalIgnoreCase))
                    throw new IOException("Cross-generation fixture inventory changed; residue preserved.");
            }
            foreach (var item in _tracked.OrderByDescending(item => item.Key.Length).ToArray())
                DeleteTracked(item.Key);
        }

        private static void RequireTracked(string path, TrackedObject expected)
        {
            using var handle = ComponentInspectionNative.OpenProtected(path, expected.Directory);
            var metadata = ComponentInspectionNative.GetMetadata(handle);
            if (metadata.IsDirectory != expected.Directory || metadata.IsReparsePoint != expected.Reparse ||
                metadata.VolumeSerial != expected.VolumeSerial || metadata.Identity != expected.Identity ||
                !CrossGenerationUpdateLock.PathsEqual(ComponentInspectionNative.FinalPath(handle), path))
                throw new IOException("Cross-generation fixture identity changed; residue preserved.");
        }

        private static void DeleteObject(string path, TrackedObject expected)
        {
            using var handle = OpenForDeletion(path, GenericRead | DeleteAccess, FileShare.Read,
                nint.Zero, OpenExisting, FileFlagOpenReparsePoint | FileFlagBackupSemantics, nint.Zero);
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            var metadata = ComponentInspectionNative.GetMetadata(handle);
            if (metadata.IsDirectory != expected.Directory || metadata.IsReparsePoint != expected.Reparse ||
                metadata.VolumeSerial != expected.VolumeSerial || metadata.Identity != expected.Identity ||
                !CrossGenerationUpdateLock.PathsEqual(ComponentInspectionNative.FinalPath(handle), path))
                throw new IOException("Cross-generation fixture cleanup identity changed; residue preserved.");
            var disposition = new FileDispositionInfo { DeleteFile = 1 };
            if (!SetFileInformationByHandle(handle, 4, ref disposition,
                    checked((uint)Marshal.SizeOf<FileDispositionInfo>())))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        private readonly record struct TrackedObject(bool Directory, bool Reparse, uint VolumeSerial, ulong Identity);
    }
}
