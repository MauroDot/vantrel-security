using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

public sealed partial class ReleasePolicyStoreTests
{
    [TestMethod]
    public void Required_acl_shape_grants_only_local_service_system_and_administrators()
    {
        var rules = ReleasePolicyStore.CreateRequiredDirectorySecurity().GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.AreEqual(3, rules.Length);
        Assert.IsTrue(rules.Any(rule => rule.IdentityReference.Value == new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null).Value && rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & FileSystemRights.Modify) == FileSystemRights.Modify));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            Assert.IsTrue(rules.Any(rule => rule.IdentityReference.Value == new SecurityIdentifier(sid, null).Value && rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl));
    }
}