using System.Text.RegularExpressions;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class AuthenticodePublisherInspectionPresentationTests
{
    [TestMethod]
    public void Presentation_separates_declared_subject_from_the_windows_outcome_without_a_safety_verdict()
    {
        var presentation = AuthenticodePublisherInspectionPresentation.Create(
            new AuthenticodePublisherInspectionResult(AuthenticodePublisherInspectionOutcome.Verified,
                "sample.exe", 42, "CN=Example Publisher"));

        Assert.IsTrue(presentation.HasResult);
        Assert.AreEqual("CN=Example Publisher", presentation.DeclaredSignerSubject);
        Assert.IsTrue(presentation.StateText.Contains("Windows Authenticode", StringComparison.Ordinal));
        Assert.IsFalse(Regex.IsMatch(presentation.StateText,
            "\\b(Protected|Clean|Malware|Safe|Trust verdict)\\b", RegexOptions.IgnoreCase));
    }

    [TestMethod]
    public void No_usable_embedded_signature_does_not_claim_global_unsigned_and_discloses_catalog_noncoverage()
    {
        var presentation = AuthenticodePublisherInspectionPresentation.Create(
            AuthenticodePublisherInspectionResult.WithoutFile(AuthenticodePublisherInspectionOutcome.NoUsableEmbeddedSignature));

        Assert.IsTrue(presentation.StateText.Contains("Catalog signatures are not inspected", StringComparison.Ordinal));
        Assert.IsFalse(presentation.StateText.Contains("unsigned", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Unavailable_presentation_is_device_scoped_and_does_not_expose_native_error_details()
    {
        var presentation = AuthenticodePublisherInspectionPresentation.Create(
            AuthenticodePublisherInspectionResult.WithoutFile(AuthenticodePublisherInspectionOutcome.Unavailable));

        Assert.AreEqual("Windows Authenticode inspection is unavailable on this device.", presentation.StateText);
        Assert.IsFalse(presentation.HasResult);
        Assert.IsFalse(Regex.IsMatch(presentation.StateText, "\\b(Protected|Clean|Malware|Safe|Trust)\\b", RegexOptions.IgnoreCase));
    }
}
