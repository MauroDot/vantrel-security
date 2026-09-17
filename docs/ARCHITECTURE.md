# Architecture

```text
WPF Desktop
    ↕ local, same-user named pipe (versioned status JSON)
Windows Worker Service
    ↓ uses
Core models and protocol  ←  Infrastructure pipe client/framing
```

The desktop and service are separate processes so the user interface can close or restart without stopping the worker. The worker owns its own lifetime and heartbeat. Future monitoring engines can be hosted there without tying their lifetime to a window. Task 001 contains no monitoring engine.

`Core` defines `SecurityServiceStatus`, `ProtectionState`, `ApplicationVersion`, the status client interface, and strict protocol validation. It has no Windows UI or pipe dependency. `Infrastructure` implements the pipe client and length-bounded framing. The service references Core and Infrastructure to host the pipe; the desktop references them to request status. Both hosts use .NET dependency injection and structured `ILogger` calls.

The pipe is `Vantrel.Security.Status.v1`. A client connects to `.` and sends a single UTF-8 JSON request terminated by a newline. The server accepts only protocol version 1 and `get_status`, then sends one typed JSON response. Framing is capped at 4 KiB, each accepted connection has a three-second deadline, and no arbitrary CLR type deserialization or command execution occurs. The pipe uses `PipeOptions.CurrentUserOnly`, so the current design is limited to the same Windows account on the local machine. A future service installation design must review the pipe ACL and authentication before allowing cross-account clients.

`ProtectionState.Protected` exists to keep the model extensible, but this service always reports `Unavailable`. The UI never invents a protected state. The service heartbeat is an indication that the worker is alive, not that a security engine is operating.
