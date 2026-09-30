using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Service;

namespace Kestermere.Security.LocalServiceAclHarness;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (!HarnessOptions.TryParse(args, out var options)) return 2;
        ServiceBase.Run(new LocalServiceHarnessService(options!));
        return 0;
    }
}

internal sealed class LocalServiceHarnessService : ServiceBase
{
    private readonly HarnessOptions _options;
    private readonly CancellationTokenSource _stop = new();

    internal LocalServiceHarnessService(HarnessOptions options)
    {
        _options = options;
        ServiceName = options.ServiceName;
        AutoLog = false;
        CanStop = true;
    }

    protected override void OnStart(string[] args) => _ = Task.Run(RunAsync);

    protected override void OnStop() => _stop.Cancel();

    private async Task RunAsync()
    {
        try
        {
            var result = await HarnessOperations.ExecuteAsync(_options, _stop.Token).ConfigureAwait(false);
            HarnessOperations.WriteResult(_options, result);
        }
        catch (Exception exception)
        {
            try { HarnessOperations.WriteFatalResult(_options, exception); } catch { }
        }
        finally
        {
            try { Stop(); } catch { }
        }
    }
}

internal sealed record HarnessOptions(string ServiceName, string FixtureRoot, string ResultFile, string Nonce)
{
    internal static bool TryParse(string[] args, out HarnessOptions? options)
    {
        options = null;
        if (args.Length != 8) return false;
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (args[index] is not ("--service-name" or "--fixture-root" or "--result-file" or "--nonce") ||
                !values.TryAdd(args[index], args[index + 1])) return false;
        }

        var serviceName = values["--service-name"];
        var nonce = values["--nonce"];
        if (!serviceName.StartsWith(HarnessProtocol.ServicePrefix, StringComparison.Ordinal) ||
            serviceName.Length is < 47 or > 55 || !serviceName[HarnessProtocol.ServicePrefix.Length..].All(Uri.IsHexDigit) ||
            nonce.Length != 32 || !nonce.All(Uri.IsHexDigit)) return false;

        try
        {
            var fixture = HarnessPaths.ValidateFixtureRoot(values["--fixture-root"]);
            var result = Path.GetFullPath(values["--result-file"]);
            if (!HarnessPaths.Equal(result, Path.Combine(fixture, HarnessProtocol.HarnessDirectoryName, HarnessProtocol.ResultFileName)))
                return false;
            options = new(serviceName, fixture, result, nonce.ToUpperInvariant());
            return true;
        }
        catch { return false; }
    }
}

internal sealed record HarnessPaths(
    string ProductRoot,
    string UpdatesRoot,
    string TransactionsRoot,
    string TransactionRoot,
    string CandidateRoot,
    string BackupsRoot,
    string BackupRoot,
    string PolicyRoot,
    string JournalFile,
    string PolicyFile,
    string CandidateProbe,
    string DeleteProbe,
    string RenameProbe,
    string RenameDestination,
    string CandidateRenameDestination,
    string AncestorProbe)
{
    internal static HarnessPaths FromRoot(string root)
    {
        root = ValidateFixtureRoot(root);
        var updates = Path.Combine(root, "Updates");
        var transactions = Path.Combine(updates, "Transactions");
        var transaction = Path.Combine(transactions, HarnessProtocol.TransactionId);
        var candidate = Path.Combine(transaction, "candidate");
        var backups = Path.Combine(updates, "Backups");
        var policy = Path.Combine(root, "ReleasePolicy");
        return new(root, updates, transactions, transaction, candidate, backups,
            Path.Combine(backups, HarnessProtocol.BackupId), policy,
            Path.Combine(transactions, "current-update-v1"), Path.Combine(policy, "accepted-release-v1.json"),
            Path.Combine(candidate, HarnessProtocol.CandidateProbeName),
            Path.Combine(transactions, HarnessProtocol.TransactionDeleteProbeName),
            Path.Combine(transactions, HarnessProtocol.TransactionRenameProbeName),
            Path.Combine(transactions, HarnessProtocol.TransactionRenameDestinationName),
            Path.Combine(transaction, HarnessProtocol.CandidateRenameDestinationName),
            Path.Combine(updates, HarnessProtocol.AncestorProbeName));
    }

    // LocalService deliberately has no access to the transaction, candidate, or backup
    // subtrees. Validate only identities it can legitimately inspect; the protected
    // operation itself supplies the access-denied evidence for the other paths.
    internal void RevalidateAccessibleForLocalService()
    {
        _ = ValidateFixtureRoot(ProductRoot);
        var directories = new (string Path, UpdateDirectoryRole Role)[]
        {
            (ProductRoot, UpdateDirectoryRole.ProductRoot), (UpdatesRoot, UpdateDirectoryRole.UpdatesRoot),
            (TransactionsRoot, UpdateDirectoryRole.TransactionsRoot), (PolicyRoot, UpdateDirectoryRole.ReleasePolicyRoot)
        };
        foreach (var item in directories)
        {
            RequireContainedExisting(item.Path, directory: true);
            var validation = UpdateFilesystemSecurity.ValidateDirectoryOnDisk(item.Role, new DirectoryInfo(item.Path));
            if (!validation.IsMatch) throw new IOException("Fixture directory descriptor mismatch: " + item.Role);
        }
        foreach (var file in new[] { JournalFile, PolicyFile }) RequireContainedExisting(file, directory: false);
        if (!HarnessMutableFileSecurity.ValidateDaclOnDisk(new FileInfo(JournalFile)).IsMatch ||
            !HarnessMutableFileSecurity.ValidateDaclOnDisk(new FileInfo(PolicyFile)).IsMatch)
            throw new IOException("Mutable fixture descriptor mismatch.");
    }

    private void RequireContainedExisting(string path, bool directory)
    {
        path = Path.GetFullPath(path);
        if (!IsSameOrChild(path, ProductRoot) || (directory ? !Directory.Exists(path) : !File.Exists(path)))
            throw new IOException("Required fixture identity is unavailable.");
        RejectReparsePath(path);
    }

    internal static string ValidateFixtureRoot(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || !Path.IsPathFullyQualified(raw))
            throw new InvalidOperationException("Fixture root rejected.");
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(raw));
        var programFiles = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
        if (!Equal(Path.GetDirectoryName(root), programFiles) ||
            !Path.GetFileName(root).StartsWith(HarnessProtocol.FixturePrefix, StringComparison.Ordinal) ||
            Equal(root, Path.Combine(programFiles, "Vantrel Security")) ||
            !Directory.Exists(root)) throw new InvalidOperationException("Fixture root rejected.");
        RejectReparsePath(root);
        return root;
    }

    internal static void RejectReparsePath(string path)
    {
        for (var current = new FileInfo(path).Directory; current is not null; current = current.Parent)
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse path rejected.");
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse path rejected.");
    }

    internal static bool Equal(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static bool IsSameOrChild(string child, string parent) => Equal(child, parent) ||
        child.StartsWith(Path.TrimEndingDirectorySeparator(parent) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
}

internal static class HarnessOperations
{
    private static readonly SecurityIdentifier LocalService = new(WellKnownSidType.LocalServiceSid, null);

    internal static Task<HarnessResult> ExecuteAsync(HarnessOptions options, CancellationToken token)
    {
        var assertions = new List<HarnessAssertionResult>();
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var sid = identity.User?.Value ?? string.Empty;
        if (identity.User is null || !LocalService.Equals(identity.User))
        {
            assertions.Add(Failure("identity.localservice", new UnauthorizedAccessException("LocalService token required.")));
            return Task.FromResult(new HarnessResult("kestermere-localservice-acl-result-v1", options.Nonce, sid, false, assertions));
        }

        var paths = HarnessPaths.FromRoot(options.FixtureRoot);
        RunPositive(assertions, "journal.replace-readback", paths, paths.JournalFile,
            ".transaction-localservice-" + options.Nonce + ".tmp", "journal-localservice-" + options.Nonce, token);
        RunPositive(assertions, "policy.replace-readback", paths, paths.PolicyFile,
            ".accepted-release-v1.localservice-" + options.Nonce + ".tmp", "policy-localservice-" + options.Nonce, token);
        RunDenied(assertions, "candidate.file-modification", paths, () =>
        {
            using var stream = new FileStream(paths.CandidateProbe, FileMode.Open, FileAccess.Write, FileShare.None);
            stream.WriteByte(0x41);
        });
        RunDirectoryDeletionDenied(assertions, paths);
        RunDenied(assertions, "transaction.directory-rename", paths, () => Directory.Move(paths.RenameProbe, paths.RenameDestination));
        RunDenied(assertions, "candidate.directory-substitution", paths,
            () => Directory.Move(paths.CandidateRoot, paths.CandidateRenameDestination));
        RunDenied(assertions, "protected-ancestor.modification", paths, () =>
        {
            using var stream = new FileStream(paths.AncestorProbe, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        });
        RunDenied(assertions, "protected-ancestor.acl-change", paths, () =>
        {
            var descriptor = new DirectorySecurity();
            descriptor.SetAccessRuleProtection(true, preserveInheritance: false);
            descriptor.AddAccessRule(new FileSystemAccessRule(LocalService, FileSystemRights.FullControl, AccessControlType.Allow));
            new DirectoryInfo(paths.UpdatesRoot).SetAccessControl(descriptor);
        });
        var completed = assertions.Count == 8 && assertions.All(item => item.Outcome == "passed");
        return Task.FromResult(new HarnessResult("kestermere-localservice-acl-result-v1", options.Nonce, sid, completed, assertions));
    }

    private static void RunPositive(List<HarnessAssertionResult> results, string name, HarnessPaths paths,
        string destination, string temporaryName, string content, CancellationToken token)
    {
        var stage = "revalidate-paths";
        var evidence = new List<HarnessFileSecurityEvidence>();
        var openEvidence = new List<HarnessNativeOpenEvidence>();
        try
        {
            paths.RevalidateAccessibleForLocalService();
            var temporary = Path.Combine(Path.GetDirectoryName(destination)!, temporaryName);
            stage = "temporary-existence";
            if (File.Exists(temporary) || Directory.Exists(temporary)) throw new IOException("Temporary identity already exists.");
            stage = "cancellation";
            token.ThrowIfCancellationRequested();
            var bytes = Encoding.UTF8.GetBytes(content);
            stage = "CreateNew";
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                evidence.Add(HarnessMutableFileSecurity.Capture("temporary-before-dacl", temporary));
                // Match the production persistence sequence: ownership and the exact
                // descriptor must succeed while the CreateNew handle is still open.
                stage = "SetAccessControl";
                new FileInfo(temporary).SetAccessControl(HarnessMutableFileSecurity.CreateDaclOnlyDescriptor());
                evidence.Add(HarnessMutableFileSecurity.Capture("temporary-after-dacl", temporary));
                stage = "temporary-descriptor-validation";
                var temporaryValidation = HarnessMutableFileSecurity.ValidateDaclOnDisk(new FileInfo(temporary));
                if (!temporaryValidation.IsMatch) throw new IOException("Temporary descriptor mismatch.");
                stage = "write";
                stream.Write(bytes);
                stage = "durable-flush";
                stream.Flush(flushToDisk: true);
            }
            stage = "temporary-reparse";
            HarnessPaths.RejectReparsePath(temporary);
            stage = "File.Replace";
            evidence.Add(HarnessMutableFileSecurity.Capture("destination-before-replace", destination));
            openEvidence.Add(HarnessNativeFileProbe.Open("replacement-primary", "temporary", temporary,
                HarnessNativeFileProbe.ReplacementPrimaryAccess, HarnessNativeFileProbe.ShareReadWriteDelete));
            openEvidence.Add(HarnessNativeFileProbe.Open("replacement-fallback", "temporary", temporary,
                HarnessNativeFileProbe.ReplacementFallbackAccess, HarnessNativeFileProbe.ShareReadWriteDelete));
            openEvidence.Add(HarnessNativeFileProbe.Open("replaced-destination", "destination", destination,
                HarnessNativeFileProbe.ReplacedDestinationAccess, HarnessNativeFileProbe.ShareReadWriteDelete));
            File.Replace(temporary, destination, null, ignoreMetadataErrors: false);
            evidence.Add(HarnessMutableFileSecurity.Capture("destination-after-replace", destination));
            stage = "destination-reparse";
            HarnessPaths.RejectReparsePath(destination);
            stage = "dacl-reapplication";
            new FileInfo(destination).SetAccessControl(HarnessMutableFileSecurity.CreateDaclOnlyDescriptor());
            evidence.Add(HarnessMutableFileSecurity.Capture("destination-after-dacl-reapplication", destination));
            stage = "destination-descriptor-validation";
            var destinationValidation = HarnessMutableFileSecurity.ValidateDaclOnDisk(new FileInfo(destination));
            if (!destinationValidation.IsMatch) throw new IOException("Destination descriptor mismatch.");
            stage = "readback";
            if (!File.ReadAllBytes(destination).AsSpan().SequenceEqual(bytes)) throw new IOException("Replacement readback mismatch.");
            evidence.Add(HarnessMutableFileSecurity.Capture("destination-after-readback", destination));
            results.Add(Passed(name, stage, evidence, openEvidence));
        }
        catch (Exception exception) { results.Add(Failure(name, exception, stage, evidence, openEvidence)); }
    }

    private static void RunDenied(List<HarnessAssertionResult> results, string name, HarnessPaths paths, Action operation)
    {
        results.Add(HarnessDenialEvaluation.Evaluate(name, paths.RevalidateAccessibleForLocalService, operation));
    }

    private static void RunDirectoryDeletionDenied(List<HarnessAssertionResult> results, HarnessPaths paths)
    {
        try { paths.RevalidateAccessibleForLocalService(); }
        catch (Exception exception)
        {
            results.Add(Failure("transaction.directory-deletion", exception, "revalidate-paths"));
            return;
        }

        Marshal.SetLastPInvokeError(0);
        var removed = HarnessNativeMethods.RemoveDirectory(paths.DeleteProbe);
        var error = Marshal.GetLastPInvokeError();
        if (removed)
        {
            results.Add(new("transaction.directory-deletion", "unexpected-success", null, null, null,
                "RemoveDirectoryW"));
            return;
        }

        var hresult = HarnessNativeMethods.HResultFromWin32(error);
        results.Add(new("transaction.directory-deletion", error == 5 ? "passed" : "failed",
            typeof(Win32Exception).FullName, hresult, error, "RemoveDirectoryW"));
    }

    internal static void WriteFatalResult(HarnessOptions options, Exception exception)
    {
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        WriteResult(options, new("kestermere-localservice-acl-result-v1", options.Nonce,
            identity.User?.Value ?? string.Empty, false, [Failure("harness.fatal", exception)]));
    }

    internal static void WriteResult(HarnessOptions options, HarnessResult result)
    {
        var expected = Path.Combine(options.FixtureRoot, HarnessProtocol.HarnessDirectoryName, HarnessProtocol.ResultFileName);
        if (!HarnessPaths.Equal(Path.GetFullPath(options.ResultFile), expected)) throw new InvalidOperationException("Result identity rejected.");
        HarnessPaths.RejectReparsePath(options.ResultFile);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(result, HarnessProtocol.Json.HarnessResult);
        if (bytes.Length > HarnessProtocol.MaximumResultBytes) throw new IOException("Harness result exceeds its fixed bound.");
        using var stream = new FileStream(options.ResultFile, FileMode.Open, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        stream.SetLength(0);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    private static HarnessAssertionResult Passed(string name, string? stage = null,
        IReadOnlyList<HarnessFileSecurityEvidence>? evidence = null,
        IReadOnlyList<HarnessNativeOpenEvidence>? openEvidence = null) =>
        new(name, "passed", null, null, null, stage, evidence, openEvidence);
    private static HarnessAssertionResult Failure(string name, Exception exception, string? stage = null,
        IReadOnlyList<HarnessFileSecurityEvidence>? evidence = null,
        IReadOnlyList<HarnessNativeOpenEvidence>? openEvidence = null) => new(name, "failed",
        exception.GetType().FullName, exception.HResult, HarnessExceptionEvidence.NativeError(exception),
        stage, evidence, openEvidence);
}

internal static class HarnessNativeFileProbe
{
    internal const uint GenericRead = 0x80000000;
    internal const uint GenericWrite = 0x40000000;
    internal const uint Delete = 0x00010000;
    internal const uint WriteDac = 0x00040000;
    internal const uint Synchronize = 0x00100000;
    internal const uint ReplacementPrimaryAccess = GenericRead | GenericWrite | Delete | WriteDac | Synchronize;
    internal const uint ReplacementFallbackAccess = GenericRead | Delete | WriteDac | Synchronize;
    internal const uint ReplacedDestinationAccess = GenericRead | Delete | Synchronize;
    internal const uint ShareReadWriteDelete = 0x00000001 | 0x00000002 | 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    internal static HarnessNativeOpenEvidence Open(string stage, string identity, string path,
        uint requestedAccess, uint shareMode)
    {
        var attributes = HarnessNativeMethods.GetFileAttributes(path);
        using SafeFileHandle handle = HarnessNativeMethods.CreateFile(path, requestedAccess, shareMode,
            IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
        var error = Marshal.GetLastPInvokeError();
        if (!handle.IsInvalid)
            return new(stage, identity, requestedAccess, shareMode, true, null, attributes);
        return new(stage, identity, requestedAccess, shareMode, false, error, attributes);
    }
}

internal static class HarnessNativeMethods
{
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true,
        CharSet = CharSet.Unicode)]
    internal static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess,
        uint shareMode, IntPtr securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", EntryPoint = "GetFileAttributesW", SetLastError = true,
        CharSet = CharSet.Unicode)]
    internal static extern uint GetFileAttributes(string fileName);

    [DllImport("kernel32.dll", EntryPoint = "RemoveDirectoryW", SetLastError = true,
        CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool RemoveDirectory(string pathName);

    internal static int HResultFromWin32(int error) => error <= 0
        ? error
        : unchecked((int)(0x80070000u | ((uint)error & 0x0000ffffu)));
}

internal static class HarnessMutableFileSecurity
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier LocalService = new(WellKnownSidType.LocalServiceSid, null);
    private const FileSystemRights LocalServiceMutableFile = FileSystemRights.Read | FileSystemRights.Write |
        FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.Synchronize;

    internal static FileSecurity CreateDaclOnlyDescriptor()
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(LocalService, LocalServiceMutableFile, AccessControlType.Allow));
        return security;
    }

    internal static UpdateDescriptorValidation ValidateDaclOnDisk(FileInfo file)
    {
        var security = file.GetAccessControl(AccessControlSections.Access);
        if (!security.AreAccessRulesProtected) return UpdateDescriptorValidation.Reject("DACL inheritance is not protected.");
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        if (rules.Any(rule => rule.IsInherited) || rules.Length != 3) return UpdateDescriptorValidation.Reject("Mutable DACL differs.");
        return HasRule(Administrators, FileSystemRights.FullControl) && HasRule(System, FileSystemRights.FullControl) &&
            HasRule(LocalService, LocalServiceMutableFile) ? UpdateDescriptorValidation.Match : UpdateDescriptorValidation.Reject("Mutable DACL differs.");
        bool HasRule(SecurityIdentifier sid, FileSystemRights rights) => rules.Count(rule => rule.IdentityReference.Equals(sid) &&
            rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights == rights &&
            rule.InheritanceFlags == InheritanceFlags.None && rule.PropagationFlags == PropagationFlags.None) == 1;
    }

    internal static HarnessFileSecurityEvidence Capture(string state, string path)
    {
        var security = new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var dacl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        if (owner is null || owner.Value.Length > HarnessProtocol.MaximumSidLength ||
            dacl.Length > HarnessProtocol.MaximumDaclSddlLength)
            throw new IOException("Mutable security evidence exceeds its bound.");
        return new(state, owner.Value, dacl);
    }
}
