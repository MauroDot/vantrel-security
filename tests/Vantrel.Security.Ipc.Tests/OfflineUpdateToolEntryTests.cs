using Vantrel.Security.OfflineUpdateTool;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class OfflineUpdateToolEntryTests
{
    [TestMethod]
    public async Task Arguments_are_rejected_before_elevation_or_fixed_operation()
    {
        var elevationCalls = 0; var operationCalls = 0; using var error = new StringWriter();
        var entry = new OfflineUpdateToolEntry(() => { elevationCalls++; return true; }, _ => { operationCalls++; return Task.FromResult(OfflineUpdateInvocationResult.Completed); });
        Assert.AreEqual(1, await entry.RunAsync(["forbidden"], error, TextWriter.Null, CancellationToken.None));
        Assert.AreEqual(0, elevationCalls); Assert.AreEqual(0, operationCalls);
    }

    [TestMethod]
    public async Task Non_elevated_invocation_rejects_before_fixed_operation()
    {
        var operationCalls = 0; using var error = new StringWriter();
        var entry = new OfflineUpdateToolEntry(() => false, _ => { operationCalls++; return Task.FromResult(OfflineUpdateInvocationResult.Completed); });
        Assert.AreEqual(1, await entry.RunAsync([], error, TextWriter.Null, CancellationToken.None));
        Assert.AreEqual(0, operationCalls); StringAssert.Contains(error.ToString(), "Administrator elevation is required.");
    }

    [TestMethod]
    public async Task Elevated_invocation_reaches_only_fixed_operation_and_preserves_bounded_exit_codes()
    {
        var calls = 0; using var output = new StringWriter();
        var entry = new OfflineUpdateToolEntry(() => true, _ => { calls++; return Task.FromResult(OfflineUpdateInvocationResult.Completed); });
        Assert.AreEqual(0, await entry.RunAsync([], TextWriter.Null, output, CancellationToken.None));
        Assert.AreEqual(1, calls); StringAssert.Contains(output.ToString(), "Completed");
    }
}
