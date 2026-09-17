# Architecture

```text
Non-elevated WPF desktop
       | local versioned status request
       v
Windows named pipe with explicit ACL
       |
       v
Windows Service (LocalService)
       | owns heartbeat and status endpoint
       +--> Core models / protocol
       +--> Infrastructure pipe implementation
```

The desktop and worker are separate processes. Closing or restarting the UI does not stop the worker. Windows Service Control Manager owns the installed worker lifetime; `AddWindowsService` provides startup and stop integration, while `BackgroundService` cancellation propagates to the heartbeat and pipe loops. The internal service name is `VantrelSecurityService` and the display name is `Vantrel Security Service`. The worker has no WPF or interactive-session dependency. During development it also runs as a console host.

`Core` remains platform-neutral for status models and protocol validation. `Infrastructure` and the service target `net9.0-windows` because they use Windows named pipes, ACLs, and Service Control Manager status. The desktop also targets `net9.0-windows` and remains a normal non-elevated user process. Status is the only operation in protocol version 1. The response carries protection state, service version, start time, and heartbeat; the UI derives uptime. The service always reports protection as Unavailable.

## IPC boundary

The pipe is `Vantrel.Security.Status.v1`. A client connects to the local `.` machine endpoint, sends one newline-delimited UTF-8 JSON `get_status` request, and receives one typed response. Both sides cap messages at 4 KiB; the client has a three-second overall deadline, and a connected server client has a three-second deadline. Invalid or unsupported requests get no status response. No received data is executed or deserialized to arbitrary CLR types.

The service creates a single `FirstPipeInstance` with an explicit, non-inherited DACL and keeps the instance open while running. The service account has full control. The Windows Interactive SID receives only the rights required for duplex status data; it does not receive `CreateNewInstance`, generic write, ACL modification, or ownership rights. Network and anonymous logons are not allowed by this ACL. The client asks for only those rights and uses anonymous impersonation level so the server cannot impersonate the desktop user through this connection. The release desktop also checks that `VantrelSecurityService` is Running before and after the exchange. Debug development mode can instead connect to a same-user interactive worker when `DOTNET_ENVIRONMENT=Development` is set.

The pipe name is not a secret. A local interactive user may request status or cause a short delay on the single pipe instance. Future privileged operations require separate protocol design and authorization review. Details and known limits are in [SECURITY.md](SECURITY.md).

## Service files and logs

The publish script creates framework-dependent `win-x64` output. The Administrator install script copies it to a dedicated Program Files directory and applies a narrow directory ACL before registering the service under LocalService. This avoids running a service binary from the developer's writable checkout. Installed service logs use the Windows Application Event Log under source `VantrelSecurityService`; Windows controls the log's maximum size and retention. Development runs log to the console. No request bodies, tokens, or personal data are logged.
