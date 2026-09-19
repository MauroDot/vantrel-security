# Vantrel Security

Vantrel Security is a planned Windows security and system health application. The prototype has a manageable Windows Service, local status communication, and read-only System Health, Activity, Scan Capability, and fixed component-inspection views in a non-elevated WPF desktop. It does **not** scan, monitor threats, block, or remove threats.

**Vantrel Security is pre-release development software and must not be relied upon as the sole antivirus or endpoint protection solution.** Keep Defender and Windows Firewall enabled.

## Projects and requirements

| Project | Responsibility |
| --- | --- |
| `src/Vantrel.Security.Desktop` | Non-elevated WPF shell, status, System Health, Activity, Scan Capability, and component-observation display |
| `src/Vantrel.Security.Service` | Independent worker, heartbeat, cached health, Activity, Scan Capability, and component-observation snapshots, Windows Service lifetime, status pipe |
| `src/Vantrel.Security.Core` | Typed status, health, capability, and observation models with versioned protocol validation |
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

The dashboard refreshes every ten seconds. It displays Connected or Disconnected, the service version, and its heartbeat and service uptime. The System Health page displays a cached service sample of Windows version/build, elapsed time since system start, total/free space on the Windows system volume, and Windows Security Center's aggregate antivirus and firewall category health. Each missing value is Unavailable; the page distinguishes disconnected, partial, and stale samples. The service samples approximately once per minute, and the desktop checks while the page is open. Activity shows only initial observations and subsequent observed changes in those two Windows-reported categories. It retains at most 12 entries in memory since service start; “observed at” is a sample time, not the time Windows changed state. Scan displays the fixed service-owned scan capability: scanning is not enabled, no file scan is running, no client target is accepted, and no scheduled targets exist. It has no Start Scan control. These Windows-reported values do not assess individual firewall profiles or rules or describe Vantrel's protection. Protection always remains **Unavailable** in this build. Stop the interactive worker with Ctrl+C; the desktop should show Disconnected on its next refresh. The release desktop requires the installed service to be running and does not use the development bypass.

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

The ACL permits any locally interactive user to request the same non-sensitive status, coarse health data, bounded Activity observations, and fixed Scan Capability snapshot. Local users can still delay the single pipe instance for up to three seconds per connection, so this is not a general privileged-command channel. **Tasks 003–008 passed installed-service validation.** Task 008 does not add a scanner or a command surface. Its non-elevated desktop showed the fixed capability snapshot, disconnected on service stop, and recovered in the same process with a newer sample after restart. Vantrel Protection Status remains Unavailable. There is no installer, code signing, or protection engine. See [docs/SECURITY.md](docs/SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), and [docs/SERVICE-MANUAL.md](docs/SERVICE-MANUAL.md).

Task 009 installed LocalService validation passed on 2026-09-18 after a corrected dependency-injection activation path. It observes only the installed service DLL and remains an observation, not a detection or trust verdict.

Task 010 adds one build-pinned comparison for only Vantrel.Security.Core.dll. A Match means the observed fixed Core DLL matches the reference compiled into this Service build; a Mismatch means it differs. This is not malware detection, a safety verdict, an independent cryptographic root of trust, or installation-wide or machine-wide integrity. It accepts no target or reference input and does no general scanning, quarantine, or remediation.

Task 010 installed LocalService validation passed: the non-elevated desktop stayed Connected with Component Integrity Match, changed to Disconnected when the service stopped, and recovered to a fresh Match sample after restart. Scan recovery labels are intentionally transient: each Scan subview renders Recovered on its first successful refresh after disconnect and Current on the following refresh. Activity uses separate session-aware recovery semantics.

Task 011 adds a separate, read-only signed-installation comparison. It authenticates a fixed `Vantrel.Security.TrustedManifest` with one embedded ECDSA P-256 public key, then compares exactly seven fixed Program Files service components. It does not scan directories, accept a target, upload telemetry, repair files, or make a malware, clean, safe, trusted, or system-wide conclusion. A valid signature means only that the manifest was signed by the corresponding external private key; `AllMatch` means those seven observed hashes match that authenticated manifest. The private key is never included in Vantrel source, runtime configuration, Program Files, IPC, or release payload.

Task 011 installed LocalService validation passed on 2026-09-19. The signed source manifest and the installed Program Files payload both verified before startup. The non-elevated desktop showed valid manifest authentication and all seven fixed components matching; it became disconnected when the service stopped and recovered in the same process after restart with a fresh current sample. These results remain a bounded signed-manifest comparison, not a malware, safety, or system-wide trust verdict.
## Task 012 bounded integrity refresh

Task 012 adds a separate local `Vantrel.Security.Command.v1` pipe for exactly one fixed interactive-user command: `refresh_trusted_manifest_integrity`. It accepts no path, target, option, hash, or manifest input. The command pipe rejects remote clients in the kernel, grants only the Interactive SID's required duplex rights, and authorizes a caller only while briefly impersonating to inspect its token; collection runs later as LocalService. The non-elevated desktop's **Refresh integrity** button sends one fresh bounded request and shows completion only after a newer signed-manifest snapshot arrives through the unchanged read-only status pipe. Command responses never contain integrity truth.