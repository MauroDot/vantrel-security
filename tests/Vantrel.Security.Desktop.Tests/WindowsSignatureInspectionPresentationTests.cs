using System.Text.RegularExpressions;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class WindowsSignatureInspectionPresentationTests
{
    [TestMethod]
    public void Presentation_keeps_embedded_and_catalog_observations_separate_without_a_security_verdict()
    {
        var presentation = WindowsSignatureInspectionPresentation.Create(new WindowsSignatureInspectionResult(
            WindowsSignatureInspectionOutcome.Completed, "sample.exe", 42,
            AuthenticodePublisherInspectionOutcome.Verified, "CN=Declared", LocalCatalogSignatureOutcome.MatchingCatalogVerified));

        Assert.IsTrue(presentation.HasResult);
        Assert.AreEqual("CN=Declared", presentation.DeclaredEmbeddedSignerSubject);
        Assert.IsTrue(presentation.EmbeddedStateText!.StartsWith("Embedded Authenticode:", StringComparison.Ordinal));
        Assert.IsTrue(presentation.CatalogStateText!.StartsWith("Local catalog:", StringComparison.Ordinal));
        Assert.IsFalse(Regex.IsMatch(string.Join(' ', presentation.NoticeText, presentation.StateText, presentation.EmbeddedStateText, presentation.CatalogStateText),
            "\\b(safe|clean|trusted|protected|malware-free|publisher-authenticated)\\b", RegexOptions.IgnoreCase));
    }

    [TestMethod]
    public void Unavailable_and_incomplete_catalog_outcomes_are_scoped_and_do_not_retain_sensitive_values()
    {
        foreach (var outcome in new[] { LocalCatalogSignatureOutcome.Unavailable, LocalCatalogSignatureOutcome.Incomplete })
        {
            var presentation = WindowsSignatureInspectionPresentation.Create(new WindowsSignatureInspectionResult(
                WindowsSignatureInspectionOutcome.Completed, "sample.exe", 42,
                AuthenticodePublisherInspectionOutcome.NoUsableEmbeddedSignature, null, outcome));
            Assert.IsTrue(presentation.HasResult);
            Assert.IsTrue(presentation.CatalogStateText!.Contains("catalog", StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(presentation.CatalogStateText.Contains("C:\\", StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(presentation.CatalogStateText.Contains("SHA-256", StringComparison.OrdinalIgnoreCase));
        }
    }

    [TestMethod]
    public void Declined_changed_and_native_unavailable_results_publish_no_file_or_signer_data()
    {
        foreach (var outcome in new[]
                 {
                     WindowsSignatureInspectionOutcome.Declined,
                     WindowsSignatureInspectionOutcome.Changed,
                     WindowsSignatureInspectionOutcome.Unavailable,
                     WindowsSignatureInspectionOutcome.AlreadyInProgress
                 })
        {
            var presentation = WindowsSignatureInspectionPresentation.Create(WindowsSignatureInspectionResult.WithoutFile(outcome));
            Assert.IsFalse(presentation.HasResult);
            Assert.IsNull(presentation.FileName);
            Assert.IsNull(presentation.DeclaredEmbeddedSignerSubject);
            Assert.IsNull(presentation.CatalogStateText);
        }
    }
}
