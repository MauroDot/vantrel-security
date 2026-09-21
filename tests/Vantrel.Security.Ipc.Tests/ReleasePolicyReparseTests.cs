using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

public sealed partial class ReleasePolicyStoreTests
{
    [TestMethod]
    public void Reparse_attribute_is_rejected_by_the_production_path_gate()
    {
        Assert.ThrowsException<IOException>(() => ReleasePolicyStore.RejectReparseAttributes(FileAttributes.ReparsePoint));
        ReleasePolicyStore.RejectReparseAttributes(FileAttributes.Directory | FileAttributes.NotContentIndexed);
    }
}