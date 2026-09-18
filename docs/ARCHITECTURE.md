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

`Core` remains platform-neutral for status, System Health, narrow Activity, Scan Capability, and fixed component-observation models and protocol validation. It and its tests target `net10.0`. `Infrastructure`, the service, the desktop, and IPC tests target `net10.0-windows` because they use Windows named pipes, ACLs, WPF, or Service Control Manager status. The desktop remains a normal non-elevated user process. The .NET 10 LTS baseline and deployment prerequisites are in [DEPLOYMENT.md](DEPLOYMENT.md). Protocol version 1 accepts five fixed requests. `get_status` is unchanged: its response carries protection state, service version, start time, and heartbeat; the UI derives service uptime. `get_system_health` returns the latest service-collected Windows version/build, elapsed time since system start, system-volume total/free space, Windows-reported antivirus and firewall category health, and collection time. The category fields are optional so earlier responses remain readable. Missing values are explicit nulls. `get_activity` returns at most 12 typed antivirus/firewall health observations, the service start time, and the most recent sampling time. `get_scan_capability` returns only a fixed statement that scanning is not enabled and that no target, schedule, detection, quarantine, remediation, or real-time capability exists. `get_component_inspection` returns a cached observation of only the loaded service DLL when the process is eligible. The service always reports its own protection as Unavailable.

## IPC boundary

The pipe is `Vantrel.Security.Status.v1`. A client connects to the local `.` machine endpoint, sends one newline-delimited UTF-8 JSON `get_status`, `get_system_health`, parameter-free `get_activity`, parameter-free `get_scan_capability`, or parameter-free `get_component_inspection` request, and receives the corresponding typed response. Both sides cap messages at 4 KiB; the client has a three-second overall deadline, and a connected server client has a three-second deadline. Invalid or unsupported requests get no response. No received data is executed or deserialized to arbitrary CLR types. The health worker samples once per minute outside the pipe loop and publishes immutable cached health and Activity snapshots. The Scan Capability worker samples a fixed statement outside the pipe loop and has no filesystem dependency, target, enumeration, or file-opening operation. The component-inspection worker samples once at startup and every 15 minutes outside the pipe loop; it retains one immutable memory-only result. The WSC adapter exposes only fixed antivirus and firewall collection methods; clients cannot choose provider flags. Older desktops continue to use unchanged exchanges, while a new desktop treats an older service's unsupported request as Unavailable.

Scan Capability is its own narrow typed model. Its fixed policy revision states that file scanning is not enabled, no file scan is running, client-supplied targets are not accepted, no scheduled fixed targets exist, and detection, quarantine, remediation, and real-time protection are unavailable. It is not settings, a job model, a detection payload, or a future command transport.

Component inspection is also a narrow typed model, separate from scanning and detection. Its security chain is: SCM eligibility → internally fixed loaded `Vantrel.Security.Service.dll` → native handle opened with reparse-point handling → handle-derived final-path, regular-file, and exact-install-root validation → bounded same-handle SHA-256 read → handle metadata stability recheck → immutable memory-only observation → read-only IPC. The source rejects reparse points, nonregular objects, targets outside the exact Program Files service directory, files over 16 MiB, unstable reads, and unavailable access. It uses a 64 KiB buffer, one collection at a time, a fixed five-second collection deadline, and cancellation-aware shutdown. No path, file identity, or internal metadata crosses IPC. The observed SHA-256 has no trusted reference comparison and is not a detection, integrity verdict, or malware verdict.

Vantrel keeps four separate concept families: Windows-reported posture; Vantrel observations; future Vantrel detections with provenance and evidence; and future Vantrel actions with authorization, auditing, and retention semantics. A future manual or client-triggered scan requires a separately reviewed authorization and command-channel design. It must not add arbitrary paths to this status pipe.

Activity records two initial observations on the first completed sample, including Unavailable values, then only changes in the two fixed Windows-reported categories. The 12 newest entries live only in service memory and reset on process restart. Each entry has a typed category, initial/change kind, optional previous state, current state, and sample timestamp. “Observed at” is the sample time, not the actual time Windows changed state. This model is not an event framework for detections or actions.

The service creates a single `FirstPipeInstance` with an explicit, non-inherited DACL and keeps the instance open while running. The service account has full control. The Windows Interactive SID receives only the rights required for duplex status data; it does not receive `CreateNewInstance`, generic write, ACL modification, or ownership rights. Network and anonymous logons are not allowed by this ACL. The client asks for only those rights and uses anonymous impersonation level so the server cannot impersonate the desktop user through this connection. The release desktop also checks that `VantrelSecurityService` is Running before and after the exchange. Debug development mode can instead connect to a same-user interactive worker when `DOTNET_ENVIRONMENT=Development` is set.

After a valid response, the server waits for the client to read the complete frame and close its end, within the existing three-second deadline. [Windows discards unread pipe bytes on disconnect](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe), so this prevents the response newline from being lost. Every accepted connection is then explicitly disconnected before the single server instance waits for another client. The disconnect decision uses whether the server accepted a client; it does not rely on the managed stream's `IsConnected` state after a peer closes early.

The installed service records the first accepted connection and completed response each minute in the Application Event Log. The desktop displays a sanitized reason, lifecycle stage, pipe name, exception type, HRESULT, and received byte count when status is unavailable. Framing distinguishes EOF before any response from an incomplete response frame. No request or response content is shown or logged.

The pipe name is not a secret. A local interactive user may request status or cause a short delay on the single pipe instance. Future privileged operations require separate protocol design and authorization review. Details and known limits are in [SECURITY.md](SECURITY.md).

The installed Task 004, 005, and 006 builds passed LocalService validation on 2026-09-18. The matching non-elevated Task 006 desktop displayed real System Health values and Windows-reported antivirus and firewall health as Good while Vantrel Protection Status remained Unavailable. It changed to Disconnected when the service stopped and received a newer sample in the same desktop process after restart.

Task 007 installed LocalService validation passed on 2026-09-18. The matching non-elevated desktop showed initial Good observations for both Windows-reported categories. When the service stopped, Activity showed Disconnected and cleared the entries. After restart, the same desktop reconnected to a new service session with newer service-start and sampling-through times and only fresh initial observations; the previous in-memory history did not return.

Task 008 installed LocalService validation passed on 2026-09-18. The matching non-elevated desktop displayed the fixed Scan Capability snapshot and no scan controls. It showed Disconnected when the service stopped, then the same desktop process recovered to a newer scan-capability sample after restart. The validation did not create, select, modify, or scan files.

## Service files and logs

The publish script creates framework-dependent `win-x64` output. The Administrator install script copies it to a dedicated Program Files directory and applies a narrow directory ACL before registering the service under LocalService. This avoids running a service binary from the developer's writable checkout. Installed service logs use the Windows Application Event Log under source `VantrelSecurityService`; Windows controls the log's maximum size and retention. Development runs log to the console. No request bodies, tokens, or personal data are logged.

Task 009 installed LocalService validation passed on 2026-09-18. The component observation recovered in the same desktop process after a service restart and retained its observation-only semantics.

Task 010 adds one build-pinned comparison for only Vantrel.Security.Core.dll. A Match means the observed fixed Core DLL matches the reference compiled into this Service build; a Mismatch means it differs. This is not malware detection, a safety verdict, an independent cryptographic root of trust, or installation-wide or machine-wide integrity. It accepts no target or reference input and does no general scanning, quarantine, or remediation.

Task 010 installed LocalService validation passed: the non-elevated desktop stayed Connected with Component Integrity Match, changed to Disconnected when the service stopped, and recovered to a fresh Match sample after restart. Scan recovery labels are intentionally transient: each Scan subview renders Recovered on its first successful refresh after disconnect and Current on the following refresh. Activity uses separate session-aware recovery semantics.
