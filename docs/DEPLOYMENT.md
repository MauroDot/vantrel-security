# Deployment and signing foundation

Vantrel Security is pre-release development software and must not be relied upon as the sole antivirus or endpoint protection solution.

## .NET 10 baseline

The baseline is .NET 10 LTS on supported Windows 11 x64. On 2026-09-17 this development machine had SDK 10.0.401 and .NET, ASP.NET Core, and Windows Desktop runtimes 10.0.12. Core and its tests target `net10.0`; the desktop, service, infrastructure, and IPC tests target `net10.0-windows`. Restore, Debug and Release builds, all 18 tests in both configurations, and framework-dependent Release `win-x64` service and desktop publishes succeeded. Check [Microsoft's .NET 10 download page](https://dotnet.microsoft.com/en-us/download/dotnet/10.0) for the current patch before distribution.

For another development machine, [Microsoft's WinGet instructions](https://learn.microsoft.com/en-us/dotnet/core/install/windows) use these package IDs from an Administrator PowerShell window. Verify versions after installation:

```powershell
winget install --id Microsoft.DotNet.SDK.10 --exact
winget install --id Microsoft.DotNet.DesktopRuntime.10 --exact
dotnet --info
dotnet --list-sdks
dotnet --list-runtimes
```

`global.json` sets SDK baseline `10.0.400` with `rollForward` `latestPatch`. This selects the latest installed patch in the 10.0.400 feature band, currently 10.0.401, while rejecting a different feature band until deliberately reviewed. Upgrade the baseline when adopting a newer SDK feature band. The Microsoft.Extensions.Hosting, WindowsServices, and ServiceController packages use 10.0.12; the service relies on WindowsServices' Hosting dependency instead of a duplicate direct reference. The existing test packages were retained because they build and run cleanly on .NET 10.

`Directory.Build.props` supplies version `0.1.0` to all projects. Change this one property for a release. The service reports its assembly version to the status protocol; keep the desktop and service built from the same release source.

## Trusted release model

1. Build from a reviewed source revision on a controlled build machine with a current supported SDK. Keep build outputs and private signing material out of Git.
2. Sign the service executable and desktop executable with a trusted commercial Authenticode code-signing certificate. Sign any future installer, updater, or privileged executable before distribution. Sign PowerShell management scripts if they are distributed for use under `AllSigned` policy. There is no installer or updater in this task.
3. Verify Authenticode signatures and publisher identity on the final artifacts, record SHA-256 hashes, and distribute through a trusted channel. The certificate private key belongs in a protected signing service or hardware-backed store, never in the repository or on end-user machines.
4. Install the service under Administrator control into `Program Files\Vantrel Security\Service`, with SYSTEM and Administrators owning changes and LocalService receiving read/execute. Register the Event Log source, create the service as `NT AUTHORITY\LocalService` with manual startup, and validate its binary path and account through Service Control Manager.
5. Keep the WPF desktop non-elevated. It reads status over the local named pipe and checks SCM state. The pipe does not accept privileged commands. Windows Application Event Log holds installed-service lifecycle and error events.
6. On update, stop the service, verify the new signed payload, replace it using an Administrator-controlled process, and restart only after verifying the installation. A production updater and rollback procedure are future work.

Unsigned development builds and the direct manual service commands in [SERVICE-MANUAL.md](SERVICE-MANUAL.md) are for local validation only. Do not disable SmartScreen, weaken signature checks, or change PowerShell execution policy to run this build. Task 003 did not create a certificate, installer, or updater.

## Installed-service validation passed

On 2026-09-17, Administrator validation deployed the paired `artifacts/task003-ipc-visibility-20260917` build. The guarded replacement verified the published and installed hashes, and Service Control Manager reported a new Running process under `NT AUTHORITY\LocalService`. A fresh Application event recorded `Local status pipe started`; subsequent events recorded `Status IPC ClientConnected` and `Status IPC ResponseConsumed`. The matching non-elevated Release desktop showed Connected, service version 0.1.0, a valid heartbeat, advancing uptime, and Protection Status Unavailable. It changed to Disconnected when the service stopped and reconnected automatically after restart without restarting the desktop. This completes the Task 003 installed-service validation. [SERVICE-MANUAL.md](SERVICE-MANUAL.md) retains the guarded procedure for reproducing it on another development installation.
