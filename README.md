# Vantrel Security

Vantrel Security is a planned Windows security and system health application. The prototype has a manageable Windows Service, local status communication, and a read-only System Health view in a non-elevated WPF desktop. It does **not** scan, monitor, block, or remove threats.

**Vantrel Security is pre-release development software and must not be relied upon as the sole antivirus or endpoint protection solution.** Keep Defender and Windows Firewall enabled.

## Projects and requirements

| Project | Responsibility |
| --- | --- |
| `src/Vantrel.Security.Desktop` | Non-elevated WPF shell, status, and System Health display |
| `src/Vantrel.Security.Service` | Independent worker, heartbeat, cached health sample, Windows Service lifetime, status pipe |
| `src/Vantrel.Security.Core` | Typed status and health models, versioned protocol validation |
| `src/Vantrel.Security.Infrastructure` | Windows pipe ACL, framing, and status client |
| `tests/Vantrel.Security.Core.Tests` | Core protocol tests |
| `tests/Vantrel.Security.Ipc.Tests` | Windows pipe and worker integration tests |

Windows 11 x64, .NET 10 LTS SDK 10.0.401, .NET and Windows Desktop runtimes 10.0.12, and Windows PowerShell 5.1 are the current development baseline. Core and its tests target `net10.0`; the WPF desktop, service, infrastructure, and IPC tests target `net10.0-windows`. The framework-dependent deployment needs current, supported .NET 10 runtime components on the target machine. Check [Microsoft's support policy](https://dotnet.microsoft.com/en-us/platform/support/policy) and [DEPLOYMENT.md](docs/DEPLOYMENT.md). `Directory.Build.props` sets version 0.1.0 for the solution, and `global.json` selects the .NET 10.0.400 SDK feature band with `latestPatch` roll-forward.

```powershell
dotnet restore Vantrel.Security.sln
dotnet build Vantrel.Security.sln --no-restore
dotnet test Vantrel.Security.sln --no-build
```

The IPC tests exercise Windows ACLs. Run them in a normal Windows session. A restricted sandbox token can receive access denied even when the same tests pass in a normal session.

## Run interactively during development

The service can run without installation. In a PowerShell terminal:

```powershell
dotnet run --project src/Vantrel.Security.Service
```

In another terminal under the same Windows account, opt in to the **Debug-only** development pipe and run the desktop:

```powershell
$env:DOTNET_ENVIRONMENT = 'Development'
dotnet run --project src/Vantrel.Security.Desktop
```

The dashboard refreshes every ten seconds. It displays Connected or Disconnected, the service version, and its heartbeat and service uptime. The System Health page displays a cached service sample of Windows version/build, elapsed time since system start, and total/free space on the Windows system volume. Each missing value is Unavailable; the page distinguishes disconnected, partial, and stale samples. The service samples approximately once per minute, and the desktop checks while the page is open. These are informational values, not an update or protection assessment. Protection always remains **Unavailable** in this build. Stop the interactive worker with Ctrl+C; the desktop should show Disconnected on its next refresh. The release desktop requires the installed service to be running and does not use the development bypass.

## Publish and manage the Windows Service

`scripts/Publish-Service.ps1` publishes a framework-dependent `win-x64` executable into a unique ignored folder under `artifacts/service/win-x64` and writes its location to `latest-path.txt`. Publishing does **not** require Administrator privileges.

```powershell
.\scripts\Publish-Service.ps1
```

Review the published executable and its displayed SHA-256 hash before installation. Open a **separate Windows PowerShell window as Administrator** for install, start, stop, restart, and uninstall. The scripts do not elevate themselves. Status can be queried from a normal window.

```powershell
.\scripts\Manage-Service.ps1 -Action Install
.\scripts\Manage-Service.ps1 -Action Start
.\scripts\Manage-Service.ps1 -Action Status
.\scripts\Manage-Service.ps1 -Action Stop
.\scripts\Manage-Service.ps1 -Action Restart
.\scripts\Manage-Service.ps1 -Action Uninstall
```

Use `-WhatIf` to inspect a management action without changing the machine. Installation refuses an existing service or installation directory, checks for the runtime required by the published service, and verifies the copied executable hash. It copies the published files into `Program Files\Vantrel Security\Service`, grants only SYSTEM and Administrators full control and LocalService read/execute, registers an Application Event Log source, and creates `VantrelSecurityService` with display name **Vantrel Security Service** under `NT AUTHORITY\LocalService`. Startup is manual so installation alone does not start a background process. Uninstall stops and removes that service, its dedicated installation directory, and its Event Log source. Historical Application log entries remain under Windows retention policy.

These scripts are unsigned. If your PowerShell execution policy requires signed scripts, sign and review them under your organization's policy before running them. Do not weaken PowerShell policy just to run this development build. This machine's policy blocked direct script execution, so service installation was not automated here. The script's runtime check confirms only the major/minor runtime required by the published service; check the patch level yourself before installation.

For an `AllSigned` machine, [docs/SERVICE-MANUAL.md](docs/SERVICE-MANUAL.md) gives equivalent commands to type into a PowerShell session without changing execution policy.

To inspect service logs after installation:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'VantrelSecurityService' } -MaxEvents 20
```

The service writes lifecycle and error events to the bounded Windows Application Event Log. Interactive development uses console logging. IPC warnings include a safe lifecycle stage, exception type, and HRESULT and are rate-limited by matching failure; request bodies are not logged. The Release WPF desktop shows a sanitized connection detail on its service-status card because a Windows GUI process has no reliable visible console output.

## Current security boundary and limits

The status pipe has an explicit non-inherited ACL: the service identity owns it; locally logged-on interactive users receive only data read/write, attribute read, permission read, and synchronization rights. They cannot create another pipe instance. Network and anonymous logons have no access rule. The service creates the first and only pipe instance and retains it until shutdown. The desktop connects to `.` with anonymous impersonation level, validates the typed versioned response, and in installed mode requires the Windows service to report Running. No HTTP listener or network port is opened. Messages are capped at 4 KiB and each connection has a three-second deadline.

The ACL permits any locally interactive user to request the same non-sensitive status and coarse health data. Local users can still delay the single pipe instance for up to three seconds per connection, so this is not a general privileged-command channel. **Task 003 installed-service validation passed on 2026-09-17:** the LocalService service remained Running; the non-elevated Release desktop showed Connected, version 0.1.0, a live heartbeat, advancing uptime, and Protection Status Unavailable. It showed Disconnected when the service stopped and reconnected automatically after restart. Fresh Application events recorded pipe startup, client connections, and consumed responses. **Task 004 installed-service validation passed on 2026-09-18:** the hash-verified, non-elevated desktop displayed a recent System Health sample, disconnected when the service stopped, and reconnected to a newer sample in the same desktop process after restart. The service stayed configured as LocalService and restarted with a new PID. There is no installer, code signing, or protection engine. See [docs/SECURITY.md](docs/SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), and [docs/SERVICE-MANUAL.md](docs/SERVICE-MANUAL.md).
