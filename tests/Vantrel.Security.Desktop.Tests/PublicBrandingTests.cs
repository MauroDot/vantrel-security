using Vantrel.Security.Core;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class PublicBrandingTests
{
    [TestMethod]
    public void Desktop_public_branding_is_kestermere_security()
    {
        Assert.AreEqual("Kestermere Security", PublicBranding.ProductName);
        Assert.AreEqual("Security & System Integrity", PublicBranding.Tagline);
        Assert.AreEqual("Mauro Interactive", PublicBranding.Publisher);
    }

    [TestMethod]
    public void Compatibility_release_identity_remains_vantrel_security()
    {
        Assert.AreEqual("vantrel-security", ReleaseMetadataCodec.Product);
        Assert.AreEqual("VantrelSecurityService", StatusProtocol.ServiceName);
        Assert.AreEqual("Vantrel.Security.Status.v1", StatusProtocol.PipeName);
        Assert.AreEqual("Vantrel.Security.Command.v1", CommandProtocol.PipeName);
    }
}
