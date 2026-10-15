using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Kestermere.Security.LocalServiceAclHarness;

// Separate, opt-in service mode for Task 079E1A. The historical Task 016 mode is unchanged.
internal static class ProductParentHarnessProgram
{
    internal static int Run(string[] args)
    {
        if (!ProductParentHarnessOptions.TryParse(args, out var options)) return 2;
        ServiceBase.Run(new ProductParentHarnessService(options!));
        return 0;
    }
}

internal sealed record ProductParentHarnessOptions(
    string ServiceName, string ParentRoot, string ResultFile, string Nonce)
{
    private const string ServicePrefix = "Vantrel079ParentAcl_";
    private const string ParentPrefix = "Vantrel.ParentAclTest.";
    private const string ResultPrefix = "Vantrel.ParentAclResult.";

    internal static bool TryParse(string[] args, out ProductParentHarnessOptions? options)
    {
        options = null;
        if (args.Length != 8) return false;
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (args[index] is not ("--service-name" or "--parent-root" or "--result-file" or "--nonce") ||
                !values.TryAdd(args[index], args[index + 1])) return false;
        }
        if (!values.TryGetValue("--service-name", out var name) ||
            !values.TryGetValue("--parent-root", out var root) ||
            !values.TryGetValue("--result-file", out var result) ||
            !values.TryGetValue("--nonce", out var nonce) ||
            !HasGuidSuffix(name, ServicePrefix) || nonce.Length != 32 || !nonce.All(Uri.IsHexDigit))
            return false;
        try
        {
            var programFiles = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
            var commonData = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)));
            root = RequireCanonical(root);
            result = RequireCanonical(result);
            if (!string.Equals(Path.GetDirectoryName(root), programFiles, StringComparison.OrdinalIgnoreCase) ||
                !HasGuidSuffix(Path.GetFileName(root), ParentPrefix) ||
                !string.Equals(Path.GetFileName(result), "result.json", StringComparison.Ordinal) ||
                !string.Equals(Path.GetDirectoryName(Path.GetDirectoryName(result)), commonData,
                    StringComparison.OrdinalIgnoreCase) ||
                !HasGuidSuffix(Path.GetFileName(Path.GetDirectoryName(result)!), ResultPrefix) ||
                !string.Equals(Path.GetFileName(root)[ParentPrefix.Length..],
                    Path.GetFileName(Path.GetDirectoryName(result)!)[ResultPrefix.Length..],
                    StringComparison.OrdinalIgnoreCase))
                return false;
            RequireNoReparse(root);
            RequireNoReparse(Path.GetDirectoryName(result)!);
            if ((File.GetAttributes(root) & FileAttributes.Directory) == 0 ||
                (File.GetAttributes(result) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                return false;
            options = new(name, root, result, nonce.ToUpperInvariant());
            return true;
        }
        catch { return false; }
    }

    private static bool HasGuidSuffix(string value, string prefix) =>
        value.StartsWith(prefix, StringComparison.Ordinal) && value.Length == prefix.Length + 32 &&
        value[prefix.Length..].All(Uri.IsHexDigit);

    private static string RequireCanonical(string value)
    {
        if (!Path.IsPathFullyQualified(value) || value.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            value.StartsWith("\\\\.\\", StringComparison.Ordinal))
            throw new IOException("Harness path rejected.");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(value));
        if (!string.Equals(value, full, StringComparison.OrdinalIgnoreCase) ||
            full.AsSpan(Path.GetPathRoot(full)!.Length).Contains(':'))
            throw new IOException("Harness path is noncanonical.");
        return full;
    }

    private static void RequireNoReparse(string path)
    {
        for (var current = new DirectoryInfo(path); current is not null; current = current.Parent)
        {
            if ((File.GetAttributes(current.FullName) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Harness reparse point rejected.");
        }
    }
}

internal sealed class ProductParentHarnessService : ServiceBase
{
    private readonly ProductParentHarnessOptions _options;

    internal ProductParentHarnessService(ProductParentHarnessOptions options)
    {
        _options = options;
        ServiceName = options.ServiceName;
        AutoLog = false;
        CanStop = true;
    }

    protected override void OnStart(string[] args) => _ = Task.Run(() =>
    {
        HarnessResult result;
        try { result = ProductParentHarnessOperations.Run(_options); }
        catch (Exception error)
        {
            result = new HarnessResult("product-parent-v1", _options.Nonce,
                WindowsIdentity.GetCurrent().User?.Value ?? "unknown", false,
                [new HarnessAssertionResult("fatal", "failed", error.GetType().FullName,
                    error.HResult, error is Win32Exception win32 ? win32.NativeErrorCode : null)]);
        }
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(result, HarnessProtocol.Json.HarnessResult);
            using var stream = new FileStream(_options.ResultFile, FileMode.Open, FileAccess.Write, FileShare.None);
            stream.SetLength(0);
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        catch { }
        finally { try { Stop(); } catch { } }
    });
}

internal static class ProductParentHarnessOperations
{
    private const uint FileAddFile = 0x00000002;
    private const uint WriteDac = 0x00040000;
    private const uint WriteOwner = 0x00080000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, FileShare share,
        IntPtr securityAttributes, uint creation, uint flags, IntPtr template);

    internal static HarnessResult Run(ProductParentHarnessOptions options)
    {
        var root = options.ParentRoot;
        var service = Path.Combine(root, "Service");
        var assertions = new List<HarnessAssertionResult>();
        var deleteRights = ProductParentNativeAccessEvidence.DeleteRights(root);
        Success("parent-list", () =>
        {
            var names = Directory.EnumerateFileSystemEntries(root).Select(Path.GetFileName).ToArray();
            if (!names.Contains("Service", StringComparer.Ordinal)) throw new IOException("Service leaf unavailable.");
        });
        Success("service-read", () =>
        {
            var bytes = File.ReadAllBytes(Path.Combine(service, "read-probe.bin"));
            if (bytes.Length != 1 || bytes[0] != 0x42) throw new IOException("Service read probe differs.");
        });
        Success("service-execute", () =>
        {
            var processPath = Path.GetFullPath(Environment.ProcessPath ?? throw new IOException("Executable unavailable."));
            if (!string.Equals(Path.GetDirectoryName(processPath), service, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Service process did not launch from protected Service child.");
        });

        NativeRight(new("parent-add-file-right", root, FileAddFile));
        NativeRight(new("parent-add-directory-right", root,
            ProductParentNativeAccessEvidence.FileAddSubdirectory));
        NativeRight(deleteRights.Parent);
        NativeRight(new("parent-write-dac-right", root, WriteDac));
        NativeRight(new("parent-write-owner-right", root, WriteOwner));
        Denied("create-file", () => File.WriteAllBytes(Path.Combine(root, "denied-file.bin"), [0x42]));
        Denied("create-directory", () => Directory.CreateDirectory(Path.Combine(root, "denied-directory")));
        NativeRight(deleteRights.Service);
        NativeRight(deleteRights.Next);
        NativeRight(deleteRights.Previous);
        NativeRight(deleteRights.Abandoned);
        Denied("change-parent-acl", () =>
        {
            var directory = new DirectoryInfo(root);
            var descriptor = directory.GetAccessControl();
            descriptor.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null),
                FileSystemRights.WriteData, AccessControlType.Allow));
            directory.SetAccessControl(descriptor);
        });
        Denied("take-parent-ownership", () =>
        {
            var directory = new DirectoryInfo(root);
            var descriptor = directory.GetAccessControl();
            descriptor.SetOwner(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null));
            directory.SetAccessControl(descriptor);
        });

        return new HarnessResult("product-parent-v1", options.Nonce,
            WindowsIdentity.GetCurrent().User?.Value ?? "unknown", true, assertions);

        void NativeRight(ProductParentNativeAccessRequest request) =>
            assertions.Add(ProductParentNativeAccessEvidence.Probe(request, OpenAccess));

        void Success(string name, Action operation)
        {
            try
            {
                operation();
                assertions.Add(new(name, "passed", null, null, null));
            }
            catch (Exception error)
            {
                assertions.Add(Failure(name, error));
            }
        }

        void Denied(string name, Action operation)
        {
            try
            {
                operation();
                assertions.Add(new(name, "unexpected-success", null, null, null));
            }
            catch (Exception error) when (IsAccessDenied(error))
            {
                assertions.Add(new(name, "passed", error.GetType().FullName, error.HResult,
                    error is Win32Exception win32 ? win32.NativeErrorCode : 5));
            }
            catch (Exception error)
            {
                assertions.Add(Failure(name, error));
            }
        }
    }

    private static HarnessAssertionResult Failure(string name, Exception error) =>
        new(name, "failed", error.GetType().FullName, error.HResult,
            error is Win32Exception win32 ? win32.NativeErrorCode : null);

    private static bool IsAccessDenied(Exception error) =>
        (error is Win32Exception win32 && win32.NativeErrorCode == 5) ||
        (error is UnauthorizedAccessException or IOException &&
            error.HResult == unchecked((int)0x80070005));

    private static void OpenAccess(string path, uint access)
    {
        using var handle = CreateFileW(path, access, FileShare.ReadWrite | FileShare.Delete,
            IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint | FileFlagBackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
