namespace Vantrel.Security.Infrastructure;

/// <summary>Safe status-connection details for the non-elevated desktop.</summary>
public sealed record StatusConnectionDiagnostic(
    string PipeName, string Reason, string Stage, string ExceptionType, string HResult, int? BytesReceived)
{
    public override string ToString() =>
        $"{Reason} at {Stage}; pipe=\\\\.\\pipe\\{PipeName}; exception={ExceptionType}; HRESULT={HResult}; bytes={BytesReceived?.ToString() ?? "none"}";
}

public interface IStatusConnectionDiagnostics
{
    StatusConnectionDiagnostic? LastDiagnostic { get; }
}
