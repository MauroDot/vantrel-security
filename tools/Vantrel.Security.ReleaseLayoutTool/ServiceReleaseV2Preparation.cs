using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>Unsigned v2 preparation evidence. Only the later final release gate may approve it.</summary>
public sealed record ServiceReleaseV2PreparationResult(
    BetaReleaseDescriptor Descriptor,
    ServiceReleaseV2ProductionProjection Projection,
    string PublishScratchRoot);

/// <summary>
/// Explicit v2-only Prepare composition. The SDK publish scratch is outside the checkout and
/// final layout. Failure leaves any created scratch/output in place for inspection, and never
/// creates a trusted manifest, release metadata, or record.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ServiceReleaseV2Preparation
{
    private const string Invalid = "V2 release preparation did not complete.";
    private const int MaxReleaseNotesBytes = 1024 * 1024;
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint ReadControl = 0x00020000;
    private const uint WriteDac = 0x00040000;
    private const uint WriteOwner = 0x00080000;
    private const uint ShareRead = 1;
    private const uint CreateNew = 1;
    private const uint OpenReparsePoint = 0x00200000;

    public static ServiceReleaseV2PreparationResult Prepare(string sourceRoot,
        string expectedFullCommit, string outputRoot, string releaseNotesPath,
        string releaseVersion, ulong releaseSequence, DateTimeOffset publishedAtUtc) =>
        Prepare(sourceRoot, expectedFullCommit, outputRoot, releaseNotesPath,
            releaseVersion, releaseSequence, publishedAtUtc, new SystemReleaseV2CommandRunner());

    internal static ServiceReleaseV2PreparationResult Prepare(string sourceRoot,
        string expectedFullCommit, string outputRoot, string releaseNotesPath,
        string releaseVersion, ulong releaseSequence, DateTimeOffset publishedAtUtc,
        IReleaseV2CommandRunner runner)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(runner);
            var source = RequireDirectory(sourceRoot);
            var destination = RequireNewDestination(outputRoot);
            var notesPath = RequireRegularExternalInput(releaseNotesPath, source, destination);
            var parent = Path.GetDirectoryName(destination)!;
            if (Overlaps(source, parent) || Overlaps(destination, notesPath))
                throw new IOException(Invalid);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(parent);
            // Validate canonical identity before running even the locked restore.
            var provisional = new BetaReleaseDescriptor(expectedFullCommit, releaseVersion,
                releaseSequence, publishedAtUtc, "Release", "win-x64",
                ServiceReleaseV2BuildProvenancePreflight.RequiredSdkVersion, new string('0', 64));
            _ = BetaReleaseDescriptorCodec.CreateCanonical(provisional);

            // Keep the input open with sharing that denies writes and replacement throughout
            // restore, publish, projection and final descriptor publication.
            using var notes = new FileStream(notesPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            RequireBoundNotes(notes, notesPath);
            if (notes.Length is <= 0 or > MaxReleaseNotesBytes) throw new IOException(Invalid);
            var notesBytes = new byte[checked((int)notes.Length)];
            notes.ReadExactly(notesBytes);
            var notesHash = Convert.ToHexString(SHA256.HashData(notesBytes));
            var descriptor = provisional with { ReleaseNotesSha256 = notesHash };
            var descriptorBytes = BetaReleaseDescriptorCodec.CreateCanonical(descriptor);

            var provenance = ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(
                source, expectedFullCommit, runner);
            if (provenance.SourceLockSha256.Length != 64 ||
                provenance.SourceCommit != descriptor.SourceCommit ||
                provenance.SdkVersion != descriptor.SdkVersion ||
                provenance.TargetFramework != ServiceReleaseV2BuildProvenancePreflight.TargetFramework ||
                provenance.RuntimeIdentifier != descriptor.Runtime ||
                provenance.Deployment != ServiceReleaseV2BuildProvenancePreflight.Deployment)
                throw new IOException(Invalid);
            RequireBoundNotes(notes, notesPath);
            if (Path.Exists(destination)) throw new IOException(Invalid);

            var scratch = Path.Combine(parent, "." + Path.GetFileName(destination) +
                ".sdk-publish-" + Guid.NewGuid().ToString("N"));
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(scratch);
            var project = Path.Combine(source, "src", "Vantrel.Security.Service",
                "Vantrel.Security.Service.csproj");
            var published = runner.Run("dotnet", ["publish", project, "--configuration", "Release",
                "--runtime", "win-x64", "--self-contained", "false", "--no-restore",
                "--output", scratch, "-p:VantrelReleaseVersion=" + releaseVersion,
                "-p:VantrelSourceCommit=" + expectedFullCommit], source, false);
            if (published.ExitCode != 0 || published.StandardOutput.Length != 0)
                throw new IOException(Invalid);
            ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(source,
                expectedFullCommit, provenance.SourceLockSha256, runner);
            RequireBoundNotes(notes, notesPath);
            _ = ServicePublishDependencyValidator.ValidateSdkPublish(
                scratch, provenance.SourceLockSha256);
            var projection = new ServiceReleaseV2ProductionProjector().Project(scratch,
                destination, provenance.SourceLockSha256, releaseVersion, releaseSequence);
            ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(source,
                expectedFullCommit, provenance.SourceLockSha256, runner);
            RequireBoundNotes(notes, notesPath);

            WriteProtectedBytes(Path.Combine(destination, BetaReleaseDescriptorCodec.FileName),
                descriptorBytes);
            WriteProtectedBytes(Path.Combine(destination,
                BetaReleaseLayoutValidator.ReleaseNotesFileName), notesBytes);
            RequireExactOutput(destination, descriptorBytes, notesBytes, projection);
            ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(source,
                expectedFullCommit, provenance.SourceLockSha256, runner);
            RequireBoundNotes(notes, notesPath);
            return new ServiceReleaseV2PreparationResult(descriptor, projection, scratch);
        }
        catch (TrackedSourceProvenanceException) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or InvalidDataException or CryptographicException or
            NotSupportedException or OverflowException)
        { throw new IOException(Invalid); }
    }

    private static void RequireExactOutput(string root, byte[] descriptorBytes, byte[] notesBytes,
        ServiceReleaseV2ProductionProjection projection)
    {
        ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(root);
        var entries = Directory.EnumerateFileSystemEntries(root)
            .Select(Path.GetFileName).OrderBy(name => name, StringComparer.Ordinal).ToArray();
        string[] expected = [BetaReleaseDescriptorCodec.FileName,
            ServiceReleaseV2ProductionProjector.DiagnosticDirectoryName,
            BetaReleaseLayoutValidator.ReleaseNotesFileName,
            ServiceReleaseV2ProductionProjector.ServiceDirectoryName];
        if (!entries.SequenceEqual(expected, StringComparer.Ordinal)) throw new IOException(Invalid);
        RequireProtectedExactBytes(Path.Combine(root, BetaReleaseDescriptorCodec.FileName), descriptorBytes);
        RequireProtectedExactBytes(Path.Combine(root,
            BetaReleaseLayoutValidator.ReleaseNotesFileName), notesBytes);
        var serviceRoot = Path.Combine(root, ServiceReleaseV2ProductionProjector.ServiceDirectoryName);
        _ = ServicePublishDependencyValidator.Validate(serviceRoot, projection.ServiceFiles);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedTree(serviceRoot, projection.ServiceFiles);
        _ = ServiceReleaseV2ProductionProjector.ValidateDiagnosticSymbols(
            Path.Combine(root, ServiceReleaseV2ProductionProjector.DiagnosticDirectoryName),
            projection.DiagnosticSymbols);
    }

    private static void WriteProtectedBytes(string path, byte[] bytes)
    {
        if (Path.Exists(path) || bytes.Length == 0 || bytes.Length > MaxReleaseNotesBytes)
            throw new IOException(Invalid);
        using var handle = CreateFile(path, GenericRead | GenericWrite | ReadControl | WriteDac |
            WriteOwner, ShareRead, IntPtr.Zero, CreateNew, OpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid) throw new IOException(Invalid);
        ServiceReleaseV2FileSystemSecurity.ProtectFile(handle);
        using var stream = new FileStream(handle, FileAccess.ReadWrite);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
        stream.Position = 0;
        if (stream.Length != bytes.Length || !SHA256.HashData(stream).AsSpan().SequenceEqual(
                SHA256.HashData(bytes))) throw new IOException(Invalid);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedHandle(stream.SafeFileHandle,
            directory: false);
    }

    private static void RequireProtectedExactBytes(string path, byte[] expected)
    {
        ServiceReleaseV2FileSystemSecurity.RequireProtectedFile(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length != expected.Length || !SHA256.HashData(stream).AsSpan().SequenceEqual(
                SHA256.HashData(expected))) throw new IOException(Invalid);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedHandle(stream.SafeFileHandle,
            directory: false);
    }

    private static string RequireDirectory(string path)
    {
        RequireCanonicalPath(path);
        for (var item = new DirectoryInfo(path); item is not null; item = item.Parent)
            if (!item.Exists || (item.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException(Invalid);
        return path;
    }

    private static string RequireNewDestination(string path)
    {
        RequireCanonicalPath(path);
        if (Path.Exists(path)) throw new IOException(Invalid);
        var parent = Path.GetDirectoryName(path);
        if (parent is null) throw new IOException(Invalid);
        RequireDirectory(parent);
        return path;
    }

    private static string RequireRegularExternalInput(string path, string source,
        string destination)
    {
        RequireCanonicalPath(path);
        if (Overlaps(source, path) || Overlaps(destination, path)) throw new IOException(Invalid);
        RequireDirectory(Path.GetDirectoryName(path)!);
        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new IOException(Invalid);
        return path;
    }

    private static void RequireCanonicalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            Path.GetFullPath(path) != path || path.Length < 4 || path[1] != ':' ||
            path[2] != '\\' || new DriveInfo(path[..3]).DriveType != DriveType.Fixed ||
            path.IndexOf(':', 2) >= 0) throw new IOException(Invalid);
    }

    private static bool Overlaps(string first, string second)
    {
        var a = Path.TrimEndingDirectorySeparator(first);
        var b = Path.TrimEndingDirectorySeparator(second);
        return a.Equals(b, StringComparison.OrdinalIgnoreCase) ||
            a.StartsWith(b + '\\', StringComparison.OrdinalIgnoreCase) ||
            b.StartsWith(a + '\\', StringComparison.OrdinalIgnoreCase);
    }

    private static void RequireBoundNotes(FileStream stream, string expectedPath)
    {
        if (stream.SafeFileHandle.IsInvalid || stream.SafeFileHandle.IsClosed ||
            !GetFileInformationByHandle(stream.SafeFileHandle, out var info) ||
            (info.Attributes & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
            info.LinkCount != 1 || GetFileType(stream.SafeFileHandle) != 1)
            throw new IOException(Invalid);
        var count = GetFinalPathNameByHandle(stream.SafeFileHandle, null, 0, 0);
        if (count == 0 || count > 32768) throw new IOException(Invalid);
        var name = new StringBuilder((int)count + 1);
        var written = GetFinalPathNameByHandle(stream.SafeFileHandle, name, (uint)name.Capacity, 0);
        if (written == 0 || written >= name.Capacity ||
            !string.Equals(name.ToString(), "\\\\?\\" + expectedPath,
                StringComparison.OrdinalIgnoreCase)) throw new IOException(Invalid);
        ServiceReleaseV2FileSystemSecurity.RequireNoNamedStreams(stream.SafeFileHandle);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfoNative
    {
        internal uint Attributes;
        private uint _creationLow, _creationHigh, _accessLow, _accessHigh, _writeLow, _writeHigh;
        private uint _volume, _sizeHigh, _sizeLow;
        internal uint LinkCount;
        private uint _indexHigh, _indexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfoNative info);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle handle);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,
        StringBuilder? path, uint length, uint flags);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
}
