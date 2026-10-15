using System.ComponentModel;

namespace Kestermere.Security.LocalServiceAclHarness;

internal readonly record struct ProductParentNativeAccessRequest(string Name, string Path, uint DesiredAccess);

internal readonly record struct ProductParentDeleteRightPlan(
    ProductParentNativeAccessRequest Parent,
    ProductParentNativeAccessRequest Service,
    ProductParentNativeAccessRequest Next,
    ProductParentNativeAccessRequest Previous,
    ProductParentNativeAccessRequest Abandoned);

internal static class ProductParentNativeAccessEvidence
{
    internal const uint FileAddSubdirectory = 0x00000004;
    internal const uint FileDeleteChild = 0x00000040;
    internal const uint Delete = 0x00010000;

    // The parent and each protected child have independent deletion-authority routes.
    // This plan contains only access requests; it never attempts a filesystem mutation.
    internal static ProductParentDeleteRightPlan DeleteRights(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        return new(
            new("parent-delete-child-right", root, FileDeleteChild),
            new("service-delete-right", Path.Combine(root, "Service"), Delete),
            Sibling("next"),
            Sibling("prev"),
            Sibling("abandoned"));

        ProductParentNativeAccessRequest Sibling(string kind) => new(
            kind + "-delete-right",
            Path.Combine(root, ".service-" + kind + "-11111111111111111111111111111111"),
            Delete);
    }

    internal static HarnessAssertionResult Probe(ProductParentNativeAccessRequest request,
        Action<string, uint> openExisting)
    {
        ArgumentNullException.ThrowIfNull(openExisting);
        try
        {
            openExisting(request.Path, request.DesiredAccess);
            return new(request.Name, "unexpected-success", null, null, null, "native-open");
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 5)
        {
            return new(request.Name, "passed", error.GetType().FullName, error.HResult,
                error.NativeErrorCode, "native-open");
        }
        catch (Exception error)
        {
            return new(request.Name, "failed", error.GetType().FullName, error.HResult,
                error is Win32Exception win32 ? win32.NativeErrorCode : null, "native-open");
        }
    }
}
