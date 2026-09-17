# Security design

**Vantrel Security is pre-release software and is not a replacement for Microsoft Defender or another established endpoint protection product.** It performs no threat detection or protection today.

## Trust boundaries

- The WPF desktop runs as a normal user. It is not granted service-management or administrator rights.
- The installed worker runs as `NT AUTHORITY\LocalService`, a built-in account with minimal local privileges and anonymous network credentials. Its installed files are copied to an Administrator-controlled Program Files directory. It needs read/execute access there, not write access. See [Microsoft's LocalService account description](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account).
- The named pipe crosses from an untrusted interactive user process into the service. All requests are untrusted, even when the Windows ACL permits the connection. A service-status request provides no privileged action.

## Named pipe controls

The server supplies its own protected DACL. Its current Windows account receives full control; the Windows Interactive SID receives `ReadData`, `WriteData`, `ReadAttributes`, `ReadPermissions`, and `Synchronize`. No Everyone, anonymous, or network-logon allow rule is added. These are individual rights: Windows maps generic pipe write to `FILE_CREATE_PIPE_INSTANCE`, which would let clients create server instances, so the client is not granted generic write. See [Microsoft's named-pipe rights documentation](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

The Interactive SID covers local console and Remote Desktop logons, while network logons do not carry that SID; see [Microsoft's SID descriptions](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects). Remote SMB pipe clients and anonymous logons therefore do not pass this DACL. The client itself uses the local `.` endpoint. The service requests `FirstPipeInstance` and retains the one pipe instance until it stops. If another process already owns the name, pipe startup fails rather than joining that endpoint. The installed desktop accepts a response only while Service Control Manager reports `VantrelSecurityService` as Running. Development bypass is compiled only in Debug builds and additionally requires `DOTNET_ENVIRONMENT=Development`.

The desktop requests `TokenImpersonationLevel.Anonymous`, preventing the server from impersonating its user token through this pipe. This does not make the client anonymous to the DACL; Windows still checks the connecting process token.

## Message handling and logging

Protocol version 1 accepts only `get_status`. The service checks the request type and protocol version after a bounded 4 KiB read. It sends a typed response with service version, heartbeat, and start time. Both sides use asynchronous operations, cancellation, and timeouts. Unsupported, malformed, and oversized input receives no valid response. No CLR type names, commands, paths, or executable code are accepted over IPC.

Installed-service lifecycle and error logs go to the Windows Application Event Log. The installer registers a dedicated source; Windows bounds the log size through its existing retention settings. Development mode uses console logging. Expected IPC warnings are rate-limited. Request payloads, secrets, tokens, and personal data are not logged.

## Known limits

- Any local interactive user can request the same non-sensitive status and can briefly occupy the single pipe instance. No per-user policy or concurrency limit beyond the three-second connection deadline exists yet.
- The installed service account and desktop IPC path have not been validated on this non-Administrator development session. Administrator validation steps are in the README.
- The project still targets .NET 9, which is in maintenance support and reaches end of support in November 2026. This machine's .NET 9 runtime is 9.0.3, behind the current patch. Update the runtime before installed deployment and move the solution to .NET 10 LTS; see [Microsoft's support policy](https://dotnet.microsoft.com/en-us/platform/support/policy).
- The binaries and PowerShell scripts are unsigned. Review and sign deployment artifacts before production use. The current scripts refuse an existing installation and do not silently elevate.
- Application Event Log source creation and LocalService logging need a real installed-service test. The scripts do not change global Event Log retention settings.
- Future privileged features need explicit operations, caller authorization, audit design, and a fresh threat review. This status-only protocol must not be extended into generic command execution.

No scanning, Defender or Firewall configuration, network monitoring, drivers, kernel components, telemetry, or personal information collection is implemented.
