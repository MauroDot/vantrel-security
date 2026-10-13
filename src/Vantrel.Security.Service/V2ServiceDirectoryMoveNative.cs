using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>
/// One same-parent V2 Service directory rename, relative to a retained parent handle.
/// The caller must have freshly authenticated the source tree and must classify the
/// physical state again after any attempted rename. This class never retries or rolls back.
/// </summary>
internal static class V2ServiceDirectoryMoveNative
{
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const int FileRenameInformationClass = 10;
    private const int FileNameOffset = 20; // x64 FILE_RENAME_INFORMATION.FileName offset.
    private const int FileRenameInformationX64Size = 24;
    private const int MaximumManagedLeafCharacters = 51; // .service-abandoned- plus a 32-character V2 ID.

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, FileShare share,
        IntPtr securityAttributes, uint creation, uint flags, IntPtr template);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtSetInformationFile(SafeFileHandle fileHandle,
        out IoStatusBlock ioStatusBlock, IntPtr fileInformation, uint length,
        int fileInformationClass);

    /// <summary>Return a retained, validated product-parent handle. Its installed ACL is
    /// not assumed to be the Service-tree ACL.</summary>
    internal static SafeFileHandle OpenBoundParent(string parentPath)
    {
        var parent = RequireLocalCanonicalPath(parentPath);
        // Windows opens the rename target relative to this directory with write access.
        // Permit that access, then recheck this retained parent's identity and final path.
        // The sharing mode alone is not a claim that parent substitution is impossible.
        var handle = CreateFileW(parent, GenericRead, FileShare.ReadWrite, IntPtr.Zero,
            OpenExisting, FileFlagOpenReparsePoint | FileFlagBackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new IOException("V2 Service directory parent could not be opened.");
        }
        try
        {
            V2ServiceTreeFileSystemSecurity.RequireValidatedDirectoryHandle(handle, parent,
                enforceAcl: false);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>Open exactly the earlier authenticated source directory for a later
    /// handle-relative rename. Verification handles must be closed before this open because
    /// they deny DELETE sharing.</summary>
    internal static SafeFileHandle OpenBoundSourceForRename(string sourcePath,
        SafeFileHandle parent, ComponentInspectionNative.Metadata previouslyAuthenticated,
        bool enforceAcl = true)
    {
        var source = RequireLocalCanonicalPath(sourcePath);
        var parentPath = RequireParentOf(source);
        RequireManagedLeaf(Path.GetFileName(source));
        RequireParent(parent, parentPath);
        if (previouslyAuthenticated.IsReparsePoint || !previouslyAuthenticated.IsDirectory ||
            previouslyAuthenticated.VolumeSerial != ComponentInspectionNative.GetMetadata(parent).VolumeSerial)
            throw new IOException("Authenticated V2 Service directory binding rejected.");

        // A synchronous handle avoids STATUS_PENDING during the one native rename attempt.
        var handle = CreateFileW(source, GenericRead | DeleteAccess, FileShare.Read,
            IntPtr.Zero, OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new IOException("Authenticated V2 Service directory could not be opened for rename.");
        }
        try
        {
            RequireSource(handle, source, previouslyAuthenticated, enforceAcl);
            RequireParent(parent, parentPath);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>Make exactly one no-replace native rename of the retained source object.
    /// A nonzero native result, including pending completion, fails closed. The caller must
    /// treat every failure at or after this call as a possibly changed namespace.</summary>
    internal static void RenameBoundSameParent(SafeFileHandle parent, string parentPath,
        SafeFileHandle source, string sourcePath, string targetLeaf,
        ComponentInspectionNative.Metadata previouslyAuthenticated, Action markMoveAttempted,
        bool enforceAcl = true)
    {
        ArgumentNullException.ThrowIfNull(markMoveAttempted);
        var expectedParent = RequireLocalCanonicalPath(parentPath);
        var expectedSource = RequireLocalCanonicalPath(sourcePath);
        if (!string.Equals(RequireParentOf(expectedSource), expectedParent,
                StringComparison.OrdinalIgnoreCase))
            throw new IOException("V2 Service directory move is not same-parent.");
        RequireManagedLeaf(Path.GetFileName(expectedSource));
        RequireManagedLeaf(targetLeaf);
        RequireAllowedTransition(Path.GetFileName(expectedSource), targetLeaf);
        if (string.Equals(Path.GetFileName(expectedSource), targetLeaf,
                StringComparison.OrdinalIgnoreCase))
            throw new IOException("V2 Service directory move has no distinct target.");

        RequireParent(parent, expectedParent);
        RequireSource(source, expectedSource, previouslyAuthenticated, enforceAcl);
        if (ComponentInspectionNative.GetMetadata(parent).VolumeSerial !=
            previouslyAuthenticated.VolumeSerial)
            throw new IOException("V2 Service directory move crossed a volume.");

        // Detect case aliases and dangling reparse leaves. The native no-replace flag is the
        // final authority on destination occupancy at the instant of the rename.
        if (Directory.EnumerateFileSystemEntries(expectedParent, "*", SearchOption.TopDirectoryOnly)
            .Any(path => string.Equals(Path.GetFileName(path), targetLeaf,
                StringComparison.OrdinalIgnoreCase)))
            throw new IOException("V2 Service directory move target is occupied.");
        RequireParent(parent, expectedParent);
        RequireSource(source, expectedSource, previouslyAuthenticated, enforceAcl);

        var parentAddedRef = false;
        var buffer = IntPtr.Zero;
        try
        {
            parent.DangerousAddRef(ref parentAddedRef);
            var information = BuildRenameInformationBuffer(targetLeaf, parent.DangerousGetHandle());
            buffer = Marshal.AllocHGlobal(information.Length);
            Marshal.Copy(information, 0, buffer, information.Length);
            // ReplaceIfExists=FALSE at byte zero. RootDirectory is the *retained* parent,
            // not a pathname; FileName is exactly one checked leaf, with no separators.
            markMoveAttempted();
            var status = NtSetInformationFile(source, out _, buffer, checked((uint)information.Length),
                FileRenameInformationClass);
            if (status != 0)
                throw new IOException("Bound V2 Service directory rename failed.");
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (parentAddedRef) parent.DangerousRelease();
        }

        RequireParent(parent, expectedParent);
        var expectedTarget = Path.Combine(expectedParent, targetLeaf);
        V2ServiceTreeFileSystemSecurity.RequireValidatedDirectoryHandle(source, expectedTarget,
            enforceAcl);
        var after = ComponentInspectionNative.GetMetadata(source);
        if (after.IsReparsePoint || !after.IsDirectory ||
            after.Identity != previouslyAuthenticated.Identity ||
            after.VolumeSerial != previouslyAuthenticated.VolumeSerial ||
            !string.Equals(Path.GetFileName(ComponentInspectionNative.FinalPath(source)),
                targetLeaf, StringComparison.Ordinal))
            throw new IOException("Bound V2 Service directory rename identity changed.");
    }

    private static void RequireParent(SafeFileHandle parent, string expectedPath)
    {
        if (parent is null || parent.IsInvalid || parent.IsClosed)
            throw new IOException("V2 Service directory parent binding is unavailable.");
        V2ServiceTreeFileSystemSecurity.RequireValidatedDirectoryHandle(parent, expectedPath,
            enforceAcl: false);
        var metadata = ComponentInspectionNative.GetMetadata(parent);
        if (metadata.IsReparsePoint || !metadata.IsDirectory)
            throw new IOException("V2 Service directory parent binding changed.");
    }

    internal static void RequireBoundParent(SafeFileHandle parent, string expectedPath) =>
        RequireParent(parent, RequireLocalCanonicalPath(expectedPath));

    private static void RequireSource(SafeFileHandle source, string expectedPath,
        ComponentInspectionNative.Metadata expected, bool enforceAcl)
    {
        if (source is null || source.IsInvalid || source.IsClosed ||
            expected.IsReparsePoint || !expected.IsDirectory)
            throw new IOException("V2 Service directory source binding is unavailable.");
        V2ServiceTreeFileSystemSecurity.RequireValidatedDirectoryHandle(source, expectedPath,
            enforceAcl);
        if (ComponentInspectionNative.GetMetadata(source) != expected)
            throw new IOException("Authenticated V2 Service directory identity changed.");
    }

    private static string RequireParentOf(string path) =>
        Path.GetDirectoryName(path) ?? throw new IOException("V2 Service directory parent is absent.");

    private static string RequireLocalCanonicalPath(string path)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) || path.Length < 3 || path[1] != ':' ||
            path[2] != '\\' || path.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            path.StartsWith("\\\\.\\", StringComparison.Ordinal))
            throw new IOException("V2 Service directory path rejected.");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!string.Equals(path, full, StringComparison.OrdinalIgnoreCase) ||
            full.AsSpan(3).Contains(':'))
            throw new IOException("V2 Service directory path is noncanonical.");
        return full;
    }

    private static void RequireManagedLeaf(string leaf)
    {
        if (leaf == "Service") return;
        foreach (var prefix in new[] { ".service-next-", ".service-prev-", ".service-abandoned-" })
        {
            if (leaf.StartsWith(prefix, StringComparison.Ordinal) &&
                V2UpdateTransactionJournalCodec.IsId(leaf[prefix.Length..]))
                return;
        }
        throw new IOException("V2 Service directory leaf rejected.");
    }

    // This exact buffer is copied to NtSetInformationFile. The documented x64 allocation is
    // sizeof(FILE_RENAME_INFORMATION) plus the UTF-16 filename byte length, while FileName
    // begins at offset 20. The trailing allocation bytes remain zero; FileNameLength excludes them.
    internal static byte[] BuildRenameInformationBuffer(string targetLeaf, IntPtr parentHandle)
    {
        if (IntPtr.Size != 8)
            throw new PlatformNotSupportedException("Bound V2 Service directory rename requires x64 Windows.");
        if (string.IsNullOrEmpty(targetLeaf) || targetLeaf.Length > MaximumManagedLeafCharacters)
            throw new IOException("V2 Service directory leaf length rejected.");
        RequireManagedLeaf(targetLeaf);
        var nameBytes = Encoding.Unicode.GetBytes(targetLeaf);
        if (nameBytes.Length > checked(MaximumManagedLeafCharacters * sizeof(char)))
            throw new IOException("V2 Service directory leaf byte length rejected.");
        var information = new byte[checked(FileRenameInformationX64Size + nameBytes.Length)];
        // The zero-filled first field is ReplaceIfExists=FALSE for FileRenameInformation (10).
        BinaryPrimitives.WriteInt64LittleEndian(information.AsSpan(8), parentHandle.ToInt64());
        BinaryPrimitives.WriteInt32LittleEndian(information.AsSpan(16), nameBytes.Length);
        nameBytes.CopyTo(information, FileNameOffset);
        return information;
    }

    private static void RequireAllowedTransition(string sourceLeaf, string targetLeaf)
    {
        if (sourceLeaf == "Service" &&
            (targetLeaf.StartsWith(".service-prev-", StringComparison.Ordinal) ||
             targetLeaf.StartsWith(".service-abandoned-", StringComparison.Ordinal)))
            return;
        if (targetLeaf == "Service" &&
            (sourceLeaf.StartsWith(".service-next-", StringComparison.Ordinal) ||
             sourceLeaf.StartsWith(".service-prev-", StringComparison.Ordinal)))
            return;
        throw new IOException("V2 Service directory transition rejected.");
    }
}
