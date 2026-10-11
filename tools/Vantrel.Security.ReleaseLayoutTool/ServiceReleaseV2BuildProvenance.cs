using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>
/// Evidence from a clean, pinned, locked v2 build-input preflight. This is not a signed
/// release or a substitute for validating the eventual published files and manifest.
/// </summary>
public sealed record ServiceReleaseV2BuildProvenance(
    string SourceCommit, string SdkVersion, string SourceLockSha256,
    string TargetFramework, string RuntimeIdentifier, string Deployment);

internal sealed record ReleaseV2CommandResult(int ExitCode, string StandardOutput);

internal interface IReleaseV2CommandRunner
{
    ReleaseV2CommandResult Run(string executable, IReadOnlyList<string> arguments,
        string workingDirectory, bool captureStandardOutput);
    ReleaseV2CommandResult RunWithInput(string executable, IReadOnlyList<string> arguments,
        string workingDirectory, Stream standardInput);
}

internal sealed class TrackedSourceProvenanceException(string relativePath) : IOException(
    "V2 release build inputs are unavailable or invalid. Tracked path: " +
    JsonSerializer.Serialize(relativePath))
{
    internal string RelativePath { get; } = relativePath;
}

/// <summary>
/// V2-only preflight. It runs before any restore, build, or publish in the caller. The
/// release composer must subsequently publish with the returned build identity and must
/// revalidate its final bytes; this object cannot authorize a release by itself.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ServiceReleaseV2BuildProvenancePreflight
{
    public const string RequiredSdkVersion = "10.0.401";
    public const string TargetFramework = "net10.0-windows";
    public const string RuntimeIdentifier = "win-x64";
    public const string Deployment = "framework-dependent";

    private const string Invalid = "V2 release build inputs are unavailable or invalid.";
    private const string LockRelative = "src/Vantrel.Security.Service/packages.lock.json";
    private const string ProjectRelative = "src/Vantrel.Security.Service/Vantrel.Security.Service.csproj";
    private const string GlobalRelative = "global.json";
    private const string SolutionRelative = "Vantrel.Security.sln";
    private const uint GenericRead = 0x80000000;
    private const uint ShareRead = 1;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;

    public static ServiceReleaseV2BuildProvenance VerifyAndRestore(string sourceRoot,
        string expectedFullCommit) => VerifyAndRestore(sourceRoot, expectedFullCommit,
            new SystemReleaseV2CommandRunner());

    /// <summary>Post-publish source check; ignored SDK intermediates are expected by then.</summary>
    internal static void RequireSourceStillBound(string sourceRoot, string expectedFullCommit,
        string approvedSourceLockSha256, IReleaseV2CommandRunner runner)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(runner);
            var root = RequireDirectory(sourceRoot);
            if (!IsFullCommit(expectedFullCommit) || !IsUpperSha256(approvedSourceLockSha256))
                throw new IOException(Invalid);
            using var sourceLock = OpenInput(root, LockRelative);
            if (Hash(sourceLock) != approvedSourceLockSha256 ||
                !SamePath(RequireSuccess(runner, "git", Git(root, "rev-parse", "--show-toplevel"), root, true), root) ||
                RequireSuccess(runner, "git", Git(root, "rev-parse", "--verify", "HEAD^{commit}"), root, true) !=
                    expectedFullCommit ||
                RequireSuccess(runner, "git", Git(root, "cat-file", "-t", expectedFullCommit), root, true) !=
                    "commit" ||
                RequireSuccess(runner, "git", Git(root, "ls-files", "--error-unmatch", "--", LockRelative),
                    root, true).Replace('\\', '/') != LockRelative ||
                RequireSuccess(runner, "git", Git(root, "status", "--porcelain=v1",
                    "--untracked-files=all"), root, true, allowEmpty: true).Length != 0 ||
                Hash(sourceLock) != approvedSourceLockSha256)
                throw new IOException(Invalid);
            RequireTrackedWorktreeMatchesHead(root, expectedFullCommit, runner);
            RequireBoundInput(sourceLock, Path.Combine(root, LockRelative.Replace('/', '\\')));
            RequireDirectory(root);
        }
        catch (TrackedSourceProvenanceException) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or
            InvalidOperationException)
        { throw new IOException(Invalid); }
    }

    internal static ServiceReleaseV2BuildProvenance VerifyAndRestore(string sourceRoot,
        string expectedFullCommit, IReleaseV2CommandRunner runner)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(runner);
            var root = RequireDirectory(sourceRoot);
            if (!IsFullCommit(expectedFullCommit)) throw new IOException(Invalid);

            // Do not expose git status or native process output: it can contain local paths.
            var top = RequireSuccess(runner, "git", Git(root, "rev-parse", "--show-toplevel"), root, true);
            if (!SamePath(top, root)) throw new IOException(Invalid);
            var head = RequireSuccess(runner, "git", Git(root, "rev-parse", "--verify", "HEAD^{commit}"), root, true);
            if (!IsFullCommit(head) || !string.Equals(head, expectedFullCommit, StringComparison.Ordinal))
                throw new IOException(Invalid);
            if (RequireSuccess(runner, "git", Git(root, "cat-file", "-t", expectedFullCommit), root, true) != "commit")
                throw new IOException(Invalid);
            foreach (var path in new[] { GlobalRelative, ProjectRelative, LockRelative, SolutionRelative })
            {
                var tracked = RequireSuccess(runner, "git", Git(root, "ls-files", "--error-unmatch", "--", path),
                    root, true);
                if (tracked.Replace('\\', '/') != path) throw new IOException(Invalid);
            }

            // Retain read-only, write/delete-denying handles through locked restore. A
            // changed lock graph cannot be silently substituted while restore is running.
            using var global = OpenInput(root, GlobalRelative);
            using var project = OpenInput(root, ProjectRelative);
            using var sourceLock = OpenInput(root, LockRelative);
            using var solution = OpenInput(root, SolutionRelative);
            RequireGlobalSdk(global);
            RequireServiceProject(project);
            var sourceLockHash = Hash(sourceLock);
            // Status runs after the critical input handles are acquired. Those handles
            // deny replacement and writes from this point through restore.
            var status = RequireSuccess(runner, "git", Git(root, "status", "--porcelain=v1",
                "--untracked-files=all", "--ignored=matching"), root, true, allowEmpty: true);
            if (status.Length != 0) throw new IOException(Invalid);
            RequireTrackedWorktreeMatchesHead(root, expectedFullCommit, runner);
            var actualSdk = RequireSuccess(runner, "dotnet", ["--version"], root, true);
            if (actualSdk != RequiredSdkVersion) throw new IOException(Invalid);

            var restore = runner.Run("dotnet", ["restore", Path.Combine(root, SolutionRelative),
                "--runtime", RuntimeIdentifier, "--locked-mode"], root, false);
            if (restore.ExitCode != 0 || restore.StandardOutput.Length != 0 ||
                Hash(sourceLock) != sourceLockHash)
                throw new IOException(Invalid);
            RequireBoundInput(global, Path.Combine(root, GlobalRelative));
            RequireBoundInput(project, Path.Combine(root, ProjectRelative.Replace('/', '\\')));
            RequireBoundInput(sourceLock, Path.Combine(root, LockRelative.Replace('/', '\\')));
            RequireBoundInput(solution, Path.Combine(root, SolutionRelative));
            RequireTrackedWorktreeMatchesHead(root, expectedFullCommit, runner);
            RequireDirectory(root);

            return new ServiceReleaseV2BuildProvenance(expectedFullCommit, RequiredSdkVersion,
                sourceLockHash, TargetFramework, RuntimeIdentifier, Deployment);
        }
        catch (TrackedSourceProvenanceException) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException
            or JsonException or System.Xml.XmlException or InvalidOperationException)
        {
            throw new IOException(Invalid);
        }
    }

    private static string RequireDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            Path.GetFullPath(path) != path || path.Length < 3 || path[1] != ':' || path[2] != '\\' ||
            new DriveInfo(path[..3]).DriveType != DriveType.Fixed)
            throw new IOException(Invalid);
        for (var current = new DirectoryInfo(path); current is not null; current = current.Parent)
            if (!current.Exists || (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException(Invalid);
        return path;
    }

    private static FileStream OpenInput(string root, string relative)
    {
        var path = root;
        var segments = relative.Split('/');
        for (var i = 0; i < segments.Length - 1; ++i)
            path = RequireDirectory(Path.Combine(path, segments[i]));
        path = Path.Combine(path, segments[^1]);
        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new IOException(Invalid);
        var handle = CreateFile(path, GenericRead, ShareRead, IntPtr.Zero, OpenExisting,
            OpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new IOException(Invalid); }
        var stream = new FileStream(handle, FileAccess.Read);
        try
        {
            RequireBoundInput(stream, path);
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    private static void RequireBoundInput(FileStream stream, string expectedPath)
    {
        var handle = stream.SafeFileHandle;
        if (handle.IsInvalid || handle.IsClosed || GetFileType(handle) != 1 ||
            !GetFileInformationByHandle(handle, out var info) ||
            (info.Attributes & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
            info.LinkCount != 1)
            throw new IOException(Invalid);
        var length = GetFinalPathNameByHandle(handle, null, 0, 0);
        if (length == 0 || length > 32768) throw new IOException(Invalid);
        var finalPath = new StringBuilder((int)length + 1);
        var written = GetFinalPathNameByHandle(handle, finalPath, (uint)finalPath.Capacity, 0);
        if (written == 0 || written >= finalPath.Capacity ||
            !string.Equals(finalPath.ToString(), "\\\\?\\" + expectedPath,
                StringComparison.OrdinalIgnoreCase))
            throw new IOException(Invalid);
        ServiceReleaseV2FileSystemSecurity.RequireNoNamedStreams(handle);
    }

    private static void RequireGlobalSdk(Stream stream)
    {
        using var document = JsonDocument.Parse(stream, new JsonDocumentOptions
        {
            AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 4
        });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 ||
            !root.TryGetProperty("sdk", out var sdk) || sdk.ValueKind != JsonValueKind.Object ||
            sdk.EnumerateObject().Count() != 2 ||
            sdk.EnumerateObject().Any(p => p.Name is not ("version" or "rollForward")) ||
            !sdk.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.String ||
            version.GetString() != RequiredSdkVersion ||
            !sdk.TryGetProperty("rollForward", out var rollForward) ||
            rollForward.ValueKind != JsonValueKind.String || rollForward.GetString() != "disable")
            throw new IOException(Invalid);
    }

    private static void RequireServiceProject(Stream stream)
    {
        using var reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            CloseInput = false
        });
        var project = XDocument.Load(reader, LoadOptions.None);
        var properties = project.Root?.Elements("PropertyGroup").ToArray() ?? [];
        if (project.Root?.Name != "Project" ||
            properties.SelectMany(group => group.Elements("TargetFramework")).Select(e => e.Value).SingleOrDefault() !=
            TargetFramework ||
            properties.SelectMany(group => group.Elements()).Any(e => e.Name.LocalName is
                "TargetFrameworks" or "RuntimeIdentifier" or "RuntimeIdentifiers" or "SelfContained" or
                "PublishSelfContained"))
            throw new IOException(Invalid);
    }

    private static string Hash(Stream stream)
    {
        stream.Position = 0;
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        stream.Position = 0;
        return hash;
    }

    private static string RequireSuccess(IReleaseV2CommandRunner runner, string executable,
        IReadOnlyList<string> arguments, string root, bool capture, bool allowEmpty = false)
    {
        var result = runner.Run(executable, arguments, root, capture);
        if (result.ExitCode != 0) throw new IOException(Invalid);
        if (!capture) return string.Empty;
        var value = result.StandardOutput.TrimEnd('\r', '\n');
        if ((!allowEmpty && value.Length == 0) || value.Contains('\n') || value.Contains('\r') || value.Length > 1024)
            throw new IOException(Invalid);
        return value;
    }

    private static string[] Git(string root, params string[] arguments) => ["-C", root, .. arguments];

    /// <summary>
    /// Git status is an additional residue check, not evidence that tracked bytes equal HEAD:
    /// index flags can make status omit a changed working-tree file. Compare the complete
    /// index with the committed tree, then hash bytes from each retained working-tree handle
    /// with Git's own path-aware clean conversion (including legitimate CRLF conversion).
    /// </summary>
    internal static void RequireTrackedWorktreeMatchesHead(string root, string expectedFullCommit,
        IReleaseV2CommandRunner runner)
    {
        if (!IsFullCommit(expectedFullCommit)) throw new IOException(Invalid);
        var treeResult = runner.Run("git", Git(root, "--no-replace-objects", "ls-tree",
            "-r", "--full-tree", "-z", expectedFullCommit), root, true);
        var indexResult = runner.Run("git", Git(root, "ls-files", "--stage", "-v", "-z"), root, true);
        var tree = new Dictionary<string, GitTrackedEntry>(StringComparer.Ordinal);
        var treeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in RequireGitRecords(treeResult))
        {
            var tab = record.IndexOf('\t');
            if (tab < 0) throw new IOException(Invalid);
            var fields = record[..tab].Split(' ');
            var relative = RequireTrackedPath(record[(tab + 1)..]);
            if (fields.Length != 3 || fields[1] != "blob" ||
                !IsRegularGitMode(fields[0]) || !IsFullCommit(fields[2]) ||
                !treeNames.Add(relative) ||
                !tree.TryAdd(relative, new GitTrackedEntry(fields[0], fields[2])))
                throw new TrackedSourceProvenanceException(relative);
        }
        if (tree.Count < 4) throw new IOException(Invalid);

        var index = new Dictionary<string, GitTrackedEntry>(StringComparer.Ordinal);
        var indexNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in RequireGitRecords(indexResult))
        {
            var tab = record.IndexOf('\t');
            if (tab < 0) throw new IOException(Invalid);
            var fields = record[..tab].Split(' ');
            var relative = RequireTrackedPath(record[(tab + 1)..]);
            // -v exposes assume-unchanged as lowercase and skip-worktree as S.
            // Stages other than zero, intent-to-add and every nonordinary index state
            // are also rejected before any source file can authorize a build.
            if (fields.Length != 4 || fields[0] != "H" ||
                !IsRegularGitMode(fields[1]) || !IsFullCommit(fields[2]) ||
                fields[3] != "0" ||
                !indexNames.Add(relative) ||
                !index.TryAdd(relative, new GitTrackedEntry(fields[1], fields[2])))
                throw new TrackedSourceProvenanceException(relative);
        }
        foreach (var (relative, committed) in tree)
            if (!index.TryGetValue(relative, out var cached) ||
                cached.Mode != committed.Mode || cached.ObjectId != committed.ObjectId)
                throw new TrackedSourceProvenanceException(relative);
        foreach (var relative in index.Keys)
            if (!tree.ContainsKey(relative)) throw new TrackedSourceProvenanceException(relative);

        // A user-selected clean filter can map arbitrary build bytes to an approved blob.
        // Only Git's built-in text/eol normalization is acceptable for this source proof.
        using var names = new MemoryStream();
        foreach (var relative in tree.Keys.Order(StringComparer.Ordinal))
        {
            names.Write(Encoding.UTF8.GetBytes(relative));
            names.WriteByte(0);
        }
        names.Position = 0;
        var attributes = runner.RunWithInput("git", Git(root, "check-attr", "-z", "--stdin", "--all"),
            root, names);
        var attributeRecords = RequireGitRecords(attributes, allowEmpty: true);
        if (attributeRecords.Length % 3 != 0) throw new IOException(Invalid);
        for (var i = 0; i < attributeRecords.Length; i += 3)
        {
            var relative = RequireTrackedPath(attributeRecords[i]);
            if (!tree.ContainsKey(relative) || attributeRecords[i + 1] is
                    "filter" or "ident" or "working-tree-encoding")
                throw new TrackedSourceProvenanceException(relative);
        }

        foreach (var (relative, committed) in tree.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            try
            {
                using var tracked = OpenInput(root, relative);
                var rawBefore = Hash(tracked);
                var actual = runner.RunWithInput("git", Git(root, "hash-object",
                    "--path=" + relative, "--stdin"), root, tracked);
                if (actual.ExitCode != 0 ||
                    !IsFullCommit(actual.StandardOutput.TrimEnd('\r', '\n')) ||
                    actual.StandardOutput.TrimEnd('\r', '\n') != committed.ObjectId ||
                    Hash(tracked) != rawBefore)
                    throw new TrackedSourceProvenanceException(relative);
                RequireBoundInput(tracked, Path.Combine(root, relative.Replace('/', '\\')));
            }
            catch (TrackedSourceProvenanceException) { throw; }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or
                ArgumentException or InvalidOperationException or NotSupportedException)
            { throw new TrackedSourceProvenanceException(relative); }
        }
    }

    private static string[] RequireGitRecords(ReleaseV2CommandResult result, bool allowEmpty = false)
    {
        var output = result.StandardOutput;
        if (result.ExitCode != 0 || output.Length > 2 * 1024 * 1024)
            throw new IOException(Invalid);
        if (allowEmpty && output.Length == 0) return [];
        if (output.Length == 0 || output[^1] != '\0') throw new IOException(Invalid);
        var records = output.Split('\0');
        if (records.Length > 30_001 || records[^1].Length != 0) throw new IOException(Invalid);
        return records[..^1];
    }

    private static string RequireTrackedPath(string relative)
    {
        if (relative.Length is < 1 or > 1024 || relative.Contains(':') ||
            relative.Contains('\\') || relative.StartsWith('/') ||
            relative.Any(char.IsControl) ||
            relative.Split('/').Any(segment => segment.Length == 0 ||
                segment is "." or ".." || segment.EndsWith('.') || segment.EndsWith(' ')))
            throw new IOException(Invalid);
        return relative;
    }

    private static bool IsRegularGitMode(string mode) => mode is "100644" or "100755";
    private readonly record struct GitTrackedEntry(string Mode, string ObjectId);
    private static bool IsFullCommit(string? value) => value is { Length: 40 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool IsUpperSha256(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool SamePath(string fromGit, string root)
    {
        if (!Path.IsPathFullyQualified(fromGit)) return false;
        return string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(fromGit)),
            Path.TrimEndingDirectorySeparator(root), StringComparison.OrdinalIgnoreCase);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfoNative
    {
        internal uint Attributes;
        private uint _creationLow, _creationHigh, _accessLow, _accessHigh, _writeLow, _writeHigh;
        internal uint Volume;
        private uint _sizeHigh, _sizeLow;
        internal uint LinkCount;
        internal uint IndexHigh, IndexLow;
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

/// <summary>Only the explicit v2 command should instantiate this process runner.</summary>
internal sealed class SystemReleaseV2CommandRunner : IReleaseV2CommandRunner
{
    private const int ProcessTimeoutMilliseconds = 600_000;
    private const int DrainTimeoutMilliseconds = 15_000;

    public ReleaseV2CommandResult Run(string executable, IReadOnlyList<string> arguments,
        string workingDirectory, bool captureStandardOutput)
        => RunCore(executable, arguments, workingDirectory, captureStandardOutput, null);

    public ReleaseV2CommandResult RunWithInput(string executable, IReadOnlyList<string> arguments,
        string workingDirectory, Stream standardInput)
        => RunCore(executable, arguments, workingDirectory, true,
            standardInput ?? throw new ArgumentNullException(nameof(standardInput)));

    private static ReleaseV2CommandResult RunCore(string executable, IReadOnlyList<string> arguments,
        string workingDirectory, bool captureStandardOutput, Stream? standardInput)
    {
        var start = new ProcessStartInfo(executable)
        {
            WorkingDirectory = workingDirectory, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            RedirectStandardInput = standardInput is not null,
            StandardOutputEncoding = new UTF8Encoding(false, true)
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        try
        {
            using var process = Process.Start(start) ?? throw new IOException();
            var maximumOutput = arguments.Contains("-z", StringComparer.Ordinal) &&
                arguments.Any(value => value is "ls-files" or "ls-tree" or "check-attr")
                    ? 2 * 1024 * 1024 : 1024;
            var stdout = Drain(process.StandardOutput, captureStandardOutput, maximumOutput);
            var stderr = Drain(process.StandardError, false, 1024);
            var input = standardInput is null ? null : PumpInput(standardInput, process.StandardInput);
            RequireProcessExit(process.WaitForExit,
                () => process.Kill(entireProcessTree: true), ProcessTimeoutMilliseconds);
            if (input is not null)
            {
                if (!input.Wait(DrainTimeoutMilliseconds))
                {
                    StopTimedOutDrains(process);
                    throw new IOException();
                }
                input.GetAwaiter().GetResult();
            }
            return new ReleaseV2CommandResult(process.ExitCode,
                CompleteDrains(stdout, stderr, DrainTimeoutMilliseconds,
                    () => StopTimedOutDrains(process)));
        }
        catch (Exception error) when (error is IOException or System.ComponentModel.Win32Exception or
            InvalidOperationException or AggregateException)
        { throw new IOException("V2 release build command failed."); }
    }

    private static async Task PumpInput(Stream source, StreamWriter destination)
    {
        source.Position = 0;
        await source.CopyToAsync(destination.BaseStream);
        await destination.BaseStream.FlushAsync();
        destination.Close();
    }

    internal static void RequireProcessExit(Func<int, bool> waitForExit, Action terminateTree,
        int timeoutMilliseconds)
    {
        if (timeoutMilliseconds < 1 || !waitForExit(timeoutMilliseconds))
        {
            terminateTree();
            throw new IOException("V2 release build command failed.");
        }
    }

    private static void StopTimedOutDrains(Process process)
    {
        // A child that inherited a pipe can keep a read pending after the direct
        // process exits. Kill its tree where the OS still permits it, then close
        // our pipe readers so the failed command retains no open output handles.
        try { process.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { } // The direct process already exited.
        catch (System.ComponentModel.Win32Exception) { }
        try { process.StandardOutput.Dispose(); }
        catch (IOException) { }
        try { process.StandardError.Dispose(); }
        catch (IOException) { }
    }

    internal static string CompleteDrains(Task<string> stdout, Task<string> stderr,
        int timeoutMilliseconds, Action onTimeout)
    {
        try
        {
            if (timeoutMilliseconds < 1 || !Task.WaitAll([stdout, stderr], timeoutMilliseconds))
            {
                onTimeout();
                throw new IOException();
            }
            return stdout.Result;
        }
        catch (Exception error) when (error is IOException or AggregateException)
        { throw new IOException("V2 release build command failed."); }
    }

    private static async Task<string> Drain(StreamReader reader, bool capture, int maximum)
    {
        var text = capture ? new StringBuilder(Math.Min(maximum, 4096)) : null;
        var buffer = new char[1024];
        int count;
        while ((count = await reader.ReadAsync(buffer)) != 0)
            if (text is not null && text.Length <= maximum)
                text.Append(buffer, 0, Math.Min(count, maximum + 1 - text.Length));
        return text?.ToString() ?? string.Empty;
    }
}
