# Vantrel Security

Vantrel Security is a planned native Windows security and system health application. This repository currently contains **Task 001: the application foundation**. It has a WPF desktop shell, an independent Windows worker service, a small domain project, and local status communication. It does **not** scan, monitor, block, or remove threats.

**Vantrel Security is currently pre-release development software and should not be relied upon as the sole antivirus or endpoint protection system.** Keep Microsoft Defender and Windows Firewall enabled.

## Current behavior

The desktop shows navigation placeholders for Dashboard, Scan, Protection, Network, System Health, Quarantine, Activity, and Settings. The dashboard displays the desktop version, the actual service connection state, and the service heartbeat when connected. Protection is shown as **Unavailable** because no protection engine exists. The service updates an internal heartbeat every five seconds and responds to a `get_status` request over a named pipe.

## Architecture

| Project | Responsibility |
| --- | --- |
| `src/Vantrel.Security.Desktop` | WPF user interface and status display |
| `src/Vantrel.Security.Service` | Independent worker host, heartbeat, status pipe server |
| `src/Vantrel.Security.Core` | Platform-neutral status models, client contract, protocol validation |
| `src/Vantrel.Security.Infrastructure` | Named pipe client and bounded message framing |
| `tests/Vantrel.Security.Core.Tests` | Protocol and status behavior tests |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for process and dependency details.

## Prerequisites

- Windows 11
- .NET 9 SDK and Windows Desktop runtime (the SDK installation supplies the runtime for development)
- PowerShell for the commands below

WinUI 3 was considered, but this machine has no WinUI template or workload and the plain VS Code/.NET setup cannot build it reliably without additional tooling. WPF is included with the installed SDK and builds here without a Windows UI workload.

## Restore, build, and test

From the repository root:

```powershell
dotnet restore Vantrel.Security.sln
dotnet build Vantrel.Security.sln --no-restore
dotnet test Vantrel.Security.sln --no-build
```

## Run during development

In one PowerShell terminal, run the service as the signed-in user:

```powershell
dotnet run --project src/Vantrel.Security.Service
```

In a second terminal under the **same Windows user**, run the desktop:

```powershell
dotnet run --project src/Vantrel.Security.Desktop
```

The dashboard should change from **Disconnected** to **Connected** within ten seconds and show a heartbeat. Stop the service with Ctrl+C; the dashboard should return to **Disconnected**. The service process is independent of the desktop and supports graceful shutdown.

`Microsoft.Extensions.Hosting.WindowsServices` enables the worker to run under Windows Service Control Manager when installed. Task 001 does not install it automatically. The status pipe currently uses Windows `CurrentUserOnly` access, so an installed service must run under the same user account as the desktop for status IPC. A service running as LocalSystem or LocalService will be inaccessible to a normal desktop session. This is an explicit foundation limitation; cross-account pipe access with a reviewed ACL belongs in a later task. Running the two processes as the same user requires no administrator privileges during development. Installing a Windows service is an administrator action.

## Limits and security

- No malware protection, scan engine, firewall management, privileged operations, HTTP endpoint, telemetry, or personal data collection is implemented.
- IPC uses the local machine pipe endpoint, a same-user access restriction, a fixed protocol version and request type, a 4 KiB message limit, and three-second connection and response timeouts. Invalid messages receive no status response.
- Status reports only the service start time, heartbeat, version, and `Unavailable` protection state. Logs contain lifecycle, connection, and error events, without request payloads or personal data. Standard .NET logging and configuration are used.
- The UI and service are development builds, not an installer. No application signing or production service ACL has been established.
