using System.ComponentModel;
using System.Text.Json.Serialization;

namespace Kestermere.Security.LocalServiceAclHarness;

internal static class HarnessProtocol
{
    internal const string ServicePrefix = "KestermereTask016Acl_";
    internal const string FixturePrefix = "Kestermere Security ACL Provision-";
    internal const string HarnessDirectoryName = "LocalServiceHarness";
    internal const string ResultFileName = "result-v1.json";
    internal const string CandidateProbeName = "localservice-denied-probe.bin";
    internal const string TransactionDeleteProbeName = "localservice-delete-probe";
    internal const string TransactionRenameProbeName = "localservice-rename-probe";
    internal const string TransactionRenameDestinationName = "localservice-rename-destination";
    internal const string CandidateRenameDestinationName = "candidate-localservice-substitute";
    internal const string AncestorProbeName = "localservice-ancestor-probe.tmp";
    internal const string TransactionId = "11111111111111111111111111111111";
    internal const string BackupId = "22222222222222222222222222222222";
    internal const int MaximumResultBytes = 16 * 1024;
    internal const int MaximumAssertionCount = 8;
    internal const int MaximumAssertionNameLength = 64;
    internal const int MaximumOutcomeLength = 32;
    internal const int MaximumExceptionTypeLength = 192;
    internal const int MaximumStageLength = 64;
    internal const int MaximumSecurityEvidencePerAssertion = 6;
    internal const int MaximumEvidenceStateLength = 64;
    internal const int MaximumSidLength = 184;
    internal const int MaximumDaclSddlLength = 384;
    internal const int MaximumNativeOpenEvidencePerAssertion = 3;
    internal const int MaximumNativeOpenStageLength = 64;
    internal const int MaximumNativeOpenIdentityLength = 32;
    internal static readonly byte[] CandidateSentinel = "kestermere-localservice-candidate-sentinel-v1"u8.ToArray();

    internal static readonly HarnessJsonContext Json = HarnessJsonContext.Default;
}

internal sealed record HarnessResult(
    string Schema,
    string Nonce,
    string IdentitySid,
    bool Completed,
    IReadOnlyList<HarnessAssertionResult> Assertions);

internal sealed record HarnessAssertionResult(
    string Name,
    string Outcome,
    string? ExceptionType,
    int? HResult,
    int? NativeError,
    string? Stage = null,
    IReadOnlyList<HarnessFileSecurityEvidence>? SecurityEvidence = null,
    IReadOnlyList<HarnessNativeOpenEvidence>? NativeOpenEvidence = null);

internal sealed record HarnessFileSecurityEvidence(string State, string OwnerSid, string DaclSddl);

internal sealed record HarnessNativeOpenEvidence(
    string Stage,
    string Identity,
    uint RequestedAccess,
    uint ShareMode,
    bool Succeeded,
    int? NativeError,
    uint FileAttributes);

internal static class HarnessExceptionEvidence
{
    internal const int AccessDeniedHResult = unchecked((int)0x80070005);

    internal static bool IsExpectedAccessDenied(Exception exception) =>
        exception is UnauthorizedAccessException or IOException && exception.HResult == AccessDeniedHResult;

    internal static int? NativeError(Exception exception)
    {
        if (exception is Win32Exception win32) return win32.NativeErrorCode;
        var hresult = unchecked((uint)exception.HResult);
        return (hresult & 0xffff0000u) == 0x80070000u ? checked((int)(hresult & 0xffffu)) : null;
    }
}

internal static class HarnessDenialEvaluation
{
    internal static HarnessAssertionResult Evaluate(string name, Action revalidate, Action operation)
    {
        try { revalidate(); }
        catch (Exception exception)
        {
            return Failed(name, exception, "revalidate-paths");
        }

        try
        {
            operation();
            return new(name, "unexpected-success", null, null, null, "operation");
        }
        catch (Exception exception) when (HarnessExceptionEvidence.IsExpectedAccessDenied(exception))
        {
            return new(name, "passed", exception.GetType().FullName, exception.HResult,
                HarnessExceptionEvidence.NativeError(exception), "operation");
        }
        catch (Exception exception)
        {
            return Failed(name, exception, "operation");
        }
    }

    private static HarnessAssertionResult Failed(string name, Exception exception, string stage) =>
        new(name, "failed", exception.GetType().FullName, exception.HResult,
            HarnessExceptionEvidence.NativeError(exception), stage);
}

[JsonSerializable(typeof(HarnessResult))]
internal sealed partial class HarnessJsonContext : JsonSerializerContext;
