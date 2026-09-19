namespace Vantrel.Security.Core;

public enum CommandCallerClassification { InteractiveUser, Anonymous, ServiceIdentity, NonInteractive, Remote, Unknown }
public enum CommandAuditOutcome { Accepted, Rejected, Duplicate, RateLimited, Completed, Failed, Cancelled }
public sealed record CommandAuditEntry(string? RequestId, CommandCallerClassification Caller, CommandAuditOutcome Outcome, DateTimeOffset TimestampUtc);
