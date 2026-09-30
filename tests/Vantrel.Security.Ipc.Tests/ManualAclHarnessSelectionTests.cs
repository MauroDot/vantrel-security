namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class ManualAclHarnessSelectionTests
{
    [TestMethod]
    [TestCategory("ManualAclHarness")]
    public void Manual_acl_harness_selection_probe()
    {
        ManualAclHarnessGate.RequirePhase("setup");
        Assert.IsTrue(true);
    }
}

internal static class ManualAclHarnessGate
{
    private const string PhaseVariable = "KESTERMERE_ACL_MANUAL_PHASE";

    internal static void RequirePhase(string expected)
    {
        var actual = Environment.GetEnvironmentVariable(PhaseVariable);
        if (!string.Equals(actual, expected, StringComparison.Ordinal))
            Assert.Inconclusive("Manual ACL harness phase is not enabled.");
    }
}
