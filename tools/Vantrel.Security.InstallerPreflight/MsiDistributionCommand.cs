using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.InstallerPreflight;

internal sealed record MsiDistributionOptions(string OutputRoot, string InstallerPlan, string UnsignedMsi,
    string UnsignedMsiSha256, string SignedMsi, string DistributionRecord, string SignTool, string Dlib,
    string Metadata);

internal interface IMsiDistributionRecordPublisher
{
    void Publish(string path, ReadOnlySpan<byte> canonicalBytes);
}

internal interface IMsiSignToolProcessRunner
{
    int Run(string executable, IReadOnlyList<string> arguments);
}

internal static class MsiDistributionCommand
{
    private const string Failure = "MSI distribution signing failed.";
    private static readonly string[] Flags =
    [
        "--output-root", "--installer-plan", "--unsigned-msi", "--unsigned-msi-sha256",
        "--signed-msi", "--distribution-record", "--signtool", "--dlib", "--metadata"
    ];

    internal static MsiDistributionOptions Parse(string[] args)
    {
        try
        {
            if (args.Length != 1 + Flags.Length * 2 || args[0] != "sign-msi-distribution") throw new IOException();
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var index = 1; index < args.Length; index += 2)
                if (!Flags.Contains(args[index], StringComparer.Ordinal) || string.IsNullOrWhiteSpace(args[index + 1]) ||
                    !values.TryAdd(args[index], args[index + 1])) throw new IOException();
            if (values.Count != Flags.Length || !IsHash(values["--unsigned-msi-sha256"])) throw new IOException();
            foreach (var flag in Flags.Where(flag => flag != "--unsigned-msi-sha256"))
                if (!Path.IsPathFullyQualified(values[flag]) ||
                    !string.Equals(Path.GetFullPath(values[flag]), values[flag], StringComparison.OrdinalIgnoreCase))
                    throw new IOException();
            return new(values[Flags[0]], values[Flags[1]], values[Flags[2]], values[Flags[3]], values[Flags[4]],
                values[Flags[5]], values[Flags[6]], values[Flags[7]], values[Flags[8]]);
        }
        catch { throw new IOException(Failure); }
    }

    internal static void ExecuteProduction(string[] args)
    {
        var options = Parse(args);
        var signer = new MsiSignToolSigningRequest(options, new SignToolProcessRunner());
        _ = Execute(options, signer, new SingleMsiAuthenticodeInspector(), new WindowsMsiDatabaseValidator(),
            new AtomicMsiDistributionRecordPublisher());
    }

    internal static MsiDistributionRecord Execute(MsiDistributionOptions options, IMsiSigningRequest signer,
        IMsiAuthenticodeInspector inspector, IMsiDatabaseValidator database, IMsiDistributionRecordPublisher publisher)
    {
        try { return ExecuteCore(options, signer, inspector, database, publisher); }
        catch { throw new IOException(Failure); }
    }

    private static MsiDistributionRecord ExecuteCore(MsiDistributionOptions options, IMsiSigningRequest signer,
        IMsiAuthenticodeInspector inspector, IMsiDatabaseValidator database, IMsiDistributionRecordPublisher publisher)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(inspector);
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(publisher);
        var root = SafeDirectory(options.OutputRoot);
        var planPath = SafeExistingFile(options.InstallerPlan);
        var unsignedPath = SafeExistingFile(options.UnsignedMsi);
        var signedPath = SafeNewStagedFile(options.SignedMsi);
        var recordPath = SafeNewFile(options.DistributionRecord);
        if (!IsHash(options.UnsignedMsiSha256) || !MsiDistributionRecordCodec.IsSafeName(Path.GetFileName(signedPath)) ||
            !string.Equals(Path.GetFileName(recordPath), MsiDistributionRecordCodec.FileName, StringComparison.Ordinal) ||
            !string.Equals(Path.GetExtension(unsignedPath), ".msi", StringComparison.Ordinal) ||
            !string.Equals(Path.GetExtension(signedPath), ".msi", StringComparison.Ordinal) ||
            IsWithin(root, planPath) || IsWithin(root, unsignedPath) || IsWithin(root, signedPath) ||
            IsWithin(root, recordPath) || IsWithin(Path.GetDirectoryName(signedPath)!, recordPath) ||
            string.Equals(Path.GetDirectoryName(signedPath), Path.GetDirectoryName(recordPath), StringComparison.OrdinalIgnoreCase))
            throw new IOException(Failure);

        var releaseRecordPath = SafeExistingFile(Path.Combine(root, BetaReleaseLayoutValidator.RecordFileName));
        using var releaseRecord = RetainedCanonicalInput.Open(releaseRecordPath);
        using var installerPlan = RetainedCanonicalInput.Open(planPath);
        var releaseRecordBytes = releaseRecord.ReadBytes(1024 * 1024);
        var installerPlanBytes = installerPlan.ReadBytes(1024 * 1024);
        var releaseRecordHash = Convert.ToHexString(SHA256.HashData(releaseRecordBytes));
        var installerPlanHash = Convert.ToHexString(SHA256.HashData(installerPlanBytes));
        if (!BetaReleaseRecordCodec.TryParse(releaseRecordBytes, out var parsedRecord) || parsedRecord is null ||
            !InstallerInputPlanCodec.TryParse(installerPlanBytes, out var plan) || plan is null)
            throw new IOException(Failure);
        void ValidateBoundInputs()
        {
            releaseRecord.RequireUnchanged();
            installerPlan.RequireUnchanged();
            if (Hash(releaseRecord.Handle) != releaseRecordHash || Hash(installerPlan.Handle) != installerPlanHash)
                throw new IOException(Failure);
            var validatedPlan = new InstallerInputValidator().CreatePlan(root, plan.MsiProductVersion, parsedRecord);
            if (!string.Equals(InstallerInputValidator.CreateCanonicalPlan(plan),
                InstallerInputValidator.CreateCanonicalPlan(validatedPlan), StringComparison.Ordinal))
                throw new IOException(Failure);
            releaseRecord.RequireUnchanged();
            installerPlan.RequireUnchanged();
            if (Hash(releaseRecord.Handle) != releaseRecordHash || Hash(installerPlan.Handle) != installerPlanHash)
                throw new IOException(Failure);
        }
        ValidateBoundInputs();

        MsiDistributionRecord? published = null;
        _ = new InjectedMsiSigningOrchestrator(signer, inspector, database).CopySignAndInspectBound(
            root, planPath, unsignedPath, options.UnsignedMsiSha256, signedPath, approved =>
            {
                ValidateBoundInputs();
                var evidence = approved.Inspection;
                var value = new MsiDistributionRecord(Path.GetFileName(signedPath), approved.FinalMsiSha256,
                    releaseRecordHash, installerPlanHash, MsiAuthenticodeInspectionResult.PolicyId,
                    evidence.Trust, evidence.PrimarySignatureCount, evidence.Digest, evidence.Timestamp, evidence.EkuCategory);
                publisher.Publish(recordPath, MsiDistributionRecordCodec.CreateCanonical(value));
                published = value;
            }, ValidateBoundInputs);
        return published ?? throw new IOException(Failure);
    }

    internal static string SafeExistingFile(string path)
    {
        var full = SafeAbsolutePath(path);
        if (!File.Exists(full) || Directory.Exists(full) || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new IOException(Failure);
        return full;
    }

    private static string SafeNewFile(string path)
    {
        var full = SafeAbsolutePath(path);
        if (File.Exists(full) || Directory.Exists(full)) throw new IOException(Failure);
        return full;
    }

    private static string SafeNewStagedFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase)) throw new IOException(Failure);
        var stage = Path.GetDirectoryName(path)!;
        _ = SafeDirectory(Path.GetDirectoryName(stage)!);
        if (File.Exists(stage) || Directory.Exists(stage) || File.Exists(path) || Directory.Exists(path))
            throw new IOException(Failure);
        return path;
    }

    private static string SafeAbsolutePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase)) throw new IOException(Failure);
        _ = SafeDirectory(Path.GetDirectoryName(path)!);
        return path;
    }

    private static string SafeDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)),
                Path.TrimEndingDirectorySeparator(path), StringComparison.OrdinalIgnoreCase)) throw new IOException(Failure);
        for (var directory = new DirectoryInfo(path); directory is not null; directory = directory.Parent)
            if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException(Failure);
        return Path.TrimEndingDirectorySeparator(path);
    }

    private static string Hash(SafeFileHandle handle)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var length = RandomAccess.GetLength(handle);
        var buffer = new byte[65536];
        long offset = 0;
        while (offset < length)
        {
            var count = RandomAccess.Read(handle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - offset)), offset);
            if (count <= 0) throw new IOException(Failure);
            digest.AppendData(buffer.AsSpan(0, count));
            offset += count;
        }
        if (RandomAccess.GetLength(handle) != length) throw new IOException(Failure);
        return Convert.ToHexString(digest.GetHashAndReset());
    }

    private static bool IsWithin(string root, string path) =>
        path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    private static bool IsHash(string? hash) => hash is { Length: 64 } &&
        hash.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private sealed class SignToolProcessRunner : IMsiSignToolProcessRunner
    {
        public int Run(string executable, IReadOnlyList<string> arguments)
        {
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (var argument in arguments) start.ArgumentList.Add(argument);
            using var process = Process.Start(start) ?? throw new IOException(Failure);
            var output = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
            var error = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
            process.WaitForExit();
            Task.WhenAll(output, error).GetAwaiter().GetResult();
            return process.ExitCode;
        }
    }
}

// The parent handle supplies identity checks, not a rename barrier. All canonical bytes
// are read from the retained leaf handle, so a swap-and-restore cannot validate other bytes.
internal sealed class RetainedCanonicalInput : IDisposable
{
    private const uint Read = 0x80000000, ReadAttributes = 0x80;
    private const uint ShareRead = 1, ShareReadWrite = 3, OpenExisting = 3;
    private const uint BackupSemantics = 0x02000000, OpenReparse = 0x00200000;
    private readonly string _path;
    private readonly SafeFileHandle _parent;
    private readonly FileIdentity _parentIdentity, _fileIdentity;
    private readonly FileStream _file;
    internal SafeFileHandle Handle => _file.SafeFileHandle;

    private RetainedCanonicalInput(string path, SafeFileHandle parent, FileStream file)
    {
        _path = path;
        _parent = parent;
        _file = file;
        _parentIdentity = MsiProtectedStaging.Inspect(parent, expectDirectory: true);
        _fileIdentity = MsiProtectedStaging.Inspect(file.SafeFileHandle, expectDirectory: false);
        RequireUnchanged();
    }

    internal static RetainedCanonicalInput Open(string path)
    {
        _ = MsiDistributionCommand.SafeExistingFile(path);
        var parent = CreateFile(Path.GetDirectoryName(path)!, ReadAttributes, ShareReadWrite,
            IntPtr.Zero, OpenExisting, BackupSemantics | OpenReparse, IntPtr.Zero);
        if (parent.IsInvalid) { parent.Dispose(); throw new IOException("MSI distribution signing failed."); }
        try
        {
            var handle = CreateFile(path, Read, ShareRead, IntPtr.Zero, OpenExisting, OpenReparse, IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); throw new IOException("MSI distribution signing failed."); }
            FileStream file;
            try { file = new FileStream(handle, FileAccess.Read); }
            catch { handle.Dispose(); throw; }
            try { return new RetainedCanonicalInput(path, parent, file); }
            catch { file.Dispose(); throw; }
        }
        catch { parent.Dispose(); throw; }
    }

    internal byte[] ReadBytes(int maximumLength)
    {
        RequireUnchanged();
        var length = RandomAccess.GetLength(Handle);
        if (length is <= 0 || length > maximumLength) throw new IOException("MSI distribution signing failed.");
        var bytes = new byte[(int)length];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var count = RandomAccess.Read(Handle, bytes.AsSpan(offset), offset);
            if (count <= 0) throw new IOException("MSI distribution signing failed.");
            offset += count;
        }
        if (RandomAccess.GetLength(Handle) != length) throw new IOException("MSI distribution signing failed.");
        RequireUnchanged();
        return bytes;
    }

    internal void RequireUnchanged()
    {
        _ = MsiDistributionCommand.SafeExistingFile(_path);
        if (Handle.IsClosed || _parent.IsClosed ||
            MsiProtectedStaging.Inspect(_parent, expectDirectory: true) != _parentIdentity ||
            MsiProtectedStaging.Inspect(Handle, expectDirectory: false) != _fileIdentity ||
            !string.Equals(_parentIdentity.FinalPath, ExpectedFinal(Path.GetDirectoryName(_path)!), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(_fileIdentity.FinalPath, ExpectedFinal(_path), StringComparison.OrdinalIgnoreCase))
            throw new IOException("MSI distribution signing failed.");
        using var current = CreateFile(_path, ReadAttributes, ShareRead, IntPtr.Zero,
            OpenExisting, OpenReparse, IntPtr.Zero);
        if (current.IsInvalid || MsiProtectedStaging.Inspect(current, expectDirectory: false) != _fileIdentity)
            throw new IOException("MSI distribution signing failed.");
    }

    private static string ExpectedFinal(string path) => "\\\\?\\" + path.TrimEnd(Path.DirectorySeparatorChar);
    public void Dispose() { _file.Dispose(); _parent.Dispose(); }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
}

internal sealed class MsiSignToolSigningRequest : IMsiSigningRequest
{
    private const string Failure = "MSI distribution signing failed.";
    private readonly string _target, _tool, _dlib, _metadata;
    private readonly IMsiSignToolProcessRunner _runner;
    private int _attempted;

    internal MsiSignToolSigningRequest(MsiDistributionOptions options, IMsiSignToolProcessRunner runner)
    {
        _target = options.SignedMsi;
        _tool = MsiDistributionCommand.SafeExistingFile(options.SignTool);
        _dlib = MsiDistributionCommand.SafeExistingFile(options.Dlib);
        _metadata = MsiDistributionCommand.SafeExistingFile(options.Metadata);
        if (!AzureArtifactSigningMetadataCodec.ReadValidatedLocalFile(_metadata).InteractiveBrowserOnly)
            throw new IOException(Failure);
        _runner = runner;
    }

    public bool Sign(string singleMsiPath)
    {
        if (!string.Equals(singleMsiPath, _target, StringComparison.Ordinal) ||
            Interlocked.Exchange(ref _attempted, 1) != 0) return false;
        var args = new[] { "sign", "/fd", "SHA256", "/tr", "http://timestamp.acs.microsoft.com/",
            "/td", "SHA256", "/dlib", _dlib, "/dmdf", _metadata, singleMsiPath };
        try { return _runner.Run(_tool, Array.AsReadOnly(args)) == 0; }
        catch { return false; }
    }

}

internal sealed class AtomicMsiDistributionRecordPublisher : IMsiDistributionRecordPublisher
{
    public void Publish(string path, ReadOnlySpan<byte> canonicalBytes)
    {
        if (File.Exists(path) || Directory.Exists(path)) throw new IOException("MSI distribution signing failed.");
        var temporary = Path.Combine(Path.GetDirectoryName(path)!, "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(canonicalBytes);
                stream.Flush(true);
            }
            File.Move(temporary, path, false);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
