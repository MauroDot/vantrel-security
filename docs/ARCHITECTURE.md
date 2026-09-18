# Architecture

Vantrel Security is pre-release development software and must not be relied upon as the sole antivirus or endpoint protection solution.

```text
Non-elevated WPF desktop
       | local versioned status or health request
       v
Windows named pipe with explicit ACL
       |
       v
Windows Service (LocalService)
       | owns heartbeat, cached health sample, and status endpoint
       +--> Core models / protocol
       +--> Infrastructure pipe implementation
```

The desktop and worker are separate processes. Closing or restarting the UI does not stop the worker. Windows Service Control Manager owns the installed worker lifetime; `AddWindowsService` provides startup and stop integration, while `BackgroundService` cancellation propagates to the heartbeat and pipe loops. The internal service name is `VantrelSecurityService` and the display name is `Vantrel Security Service`. The worker has no WPF or interactive-session dependency. During development it also runs as a console host.

`Core` remains platform-neutral for status and System Health models and protocol validation. It and its tests target `net10.0`. `Infrastructure`, the service, the desktop, and IPC tests target `net10.0-windows` because they use Windows named pipes, ACLs, WPF, or Service Control Manager status. The desktop remains a normal non-elevated user process. The .NET 10 LTS baseline and deployment prerequisites are in [DEPLOYMENT.md](DEPLOYMENT.md). Protocol version 1 accepts two fixed requests. `get_status` is unchanged: its response carries protection state, service version, start time, and heartbeat; the UI derives service uptime. `get_system_health` returns the latest service-collected Windows version/build, elapsed time since system start, system-volume total/free space, Windows-reported antivirus and firewall category health, and collection time. The category fields are optional so earlier responses remain readable. Missing values are explicit nulls. The service always reports its own protection as Unavailable.

## IPC boundary

The pipe is `Vantrel.Security.Status.v1`. A client connects to the local `.` machine endpoint, sends one newline-delimited UTF-8 JSON `get_status` or `get_system_health` request, and receives the corresponding typed response. Both sides cap messages at 4 KiB; the client has a three-second overall deadline, and a connected server client has a three-second deadline. Invalid or unsupported requests get no response. No received data is executed or deserialized to arbitrary CLR types. The health worker samples once per minute outside the pipe loop and publishes an immutable cached snapshot; the pipe never performs disk or Windows Security Center reads. The WSC adapter exposes only fixed antivirus and firewall collection methods; clients cannot choose provider flags.

The service creates a single `FirstPipeInstance` with an explicit, non-inherited DACL and keeps the instance open while running. The service account has full control. The Windows Interactive SID receives only the rights required for duplex status data; it does not receive `CreateNewInstance`, generic write, ACL modification, or ownership rights. Network and anonymous logons are not allowed by this ACL. The client asks for only those rights and uses anonymous impersonation level so the server cannot impersonate the desktop user through this connection. The release desktop also checks that `VantrelSecurityService` is Running before and after the exchange. Debug development mode can instead connect to a same-user interactive worker when `DOTNET_ENVIRONMENT=Development` is set.

After a valid response, the server waits for the client to read the complete frame and close its end, within the existing three-second deadline. [Windows discards unread pipe bytes on disconnect](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe), so this prevents the response newline from being lost. Every accepted connection is then explicitly disconnected before the single server instance waits for another client. The disconnect decision uses whether the server accepted a client; it does not rely on the managed stream's `IsConnected` state after a peer closes early.

The installed service records the first accepted connection and completed response each minute in the Application Event Log. The desktop displays a sanitized reason, lifecycle stage, pipe name, exception type, HRESULT, and received byte count when status is unavailable. Framing distinguishes EOF before any response from an incomplete response frame. No request or response content is shown or logged.

The pipe name is not a secret. A local interactive user may request status or cause a short delay on the single pipe instance. Future privileged operations require separate protocol design and authorization review. Details and known limits are in [SECURITY.md](SECURITY.md).

The installed Task 004, 005, and 006 builds passed LocalService validation on 2026-09-18. The matching non-elevated Task 006 desktop displayed real System Health values and Windows-reported antivirus and firewall health as Good while Vantrel Protection Status remained Unavailable. It changed to Disconnected when the service stopped and received a newer sample in the same desktop process after restart.

## Service files and logs

The publish script creates framework-dependent `win-x64` output. The Administrator install script copies it to a dedicated Program Files directory and applies a narrow directory ACL before registering the service under LocalService. This avoids running a service binary from the developer's writable checkout. Installed service logs use the Windows Application Event Log under source `VantrelSecurityService`; Windows controls the log's maximum size and retention. Development runs log to the console. No request bodies, tokens, or personal data are logged.
