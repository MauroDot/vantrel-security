# Manual Windows Service validation

Vantrel Security is pre-release development software and must not be relied upon as the sole antivirus or endpoint protection solution.

**Current status (2026-09-17): Task 003 installed-service validation passed.** The guarded deployment of `task003-ipc-visibility-20260917` produced a new LocalService service process and fresh pipe startup event. The matching non-elevated desktop showed Connected, version 0.1.0, a valid heartbeat, advancing uptime, and Protection Status Unavailable. It disconnected when the service stopped and reconnected automatically after restart. Fresh events recorded client connections and consumed responses. Confirm any other target machine has a current .NET 10 runtime and Windows Desktop Runtime.

Use this procedure when unsigned `.ps1` files cannot run under the machine's PowerShell policy. It does not change execution policy. Review the source and publish output first. **Installation, start, stop, restart, and removal require an Administrator PowerShell window.** Querying status and launching the desktop do not.

## One-time replacement from earlier Task 003 builds

This one-time procedure was used to replace either earlier Task 003 DLL pair. The current validated installation already has the new build; rerunning this block will intentionally stop at the prior-hash check. The service and matching desktop are in ignored `artifacts/task003-ipc-visibility-20260917/service` and `artifacts/task003-ipc-visibility-20260917/desktop`. Only the service and infrastructure DLLs changed in the installed service payload. The Event Log message-resource DLL was left in place even while Windows held it locked. The source registration was not removed.

From **Administrator Windows PowerShell 5.1** in the repository root, run:

```powershell
$ErrorActionPreference = 'Stop'
$repository = 'C:\Users\tmaur\VANTREL SECURITY'
Set-Location -LiteralPath $repository
$name = 'VantrelSecurityService'
$source = (Resolve-Path 'artifacts/task003-ipc-visibility-20260917/service').Path
$programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
$expected = [System.IO.Path]::GetFullPath((Join-Path $programFilesRoot 'Vantrel Security\Service'))
$target = (Resolve-Path -LiteralPath $expected).Path
if (-not $target.StartsWith($programFilesRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Installation path is outside Program Files.' }
if (-not [string]::Equals($target, $expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected installation path.' }
if ((Get-Item -LiteralPath $target -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Linked installation directory.' }
if ((Get-Item -LiteralPath (Split-Path -Parent $target) -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Linked parent directory.' }
if ((Get-Item -LiteralPath $source -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Linked publish directory.' }
if (Get-ChildItem -LiteralPath $source -Force -Recurse | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint }) { throw 'Published files contain links.' }
$expectedHashes = @{
    'Vantrel.Security.Service.exe' = 'C23423AE0B0AF023CDFD0F7955EF3066DA661175E74A28C0B03F86C2A0A4776A'
    'Vantrel.Security.Service.dll' = '30F22CD083BACD7B3A504DE268EC37DC5C31F69FBF4C08F9B66A8DBB30BBC992'
    'Vantrel.Security.Infrastructure.dll' = '70536D95E1274C0EAA43EE3C3E589CA21B283136781FC71DCF7083454DB22DB5'
    'Vantrel.Security.Core.dll' = '48BECBCC978875CB5AAA7749EBFEEB9B49CD4820C963B51C908D1904830574CB'
}
foreach ($file in $expectedHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $source $file) -Algorithm SHA256).Hash -ne $expectedHashes[$file]) { throw "Published hash mismatch: $file" }
}
$service = Get-CimInstance Win32_Service -Filter "Name='VantrelSecurityService'"
if ($null -eq $service -or $service.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Unexpected service registration or account.' }
if ($service.PathName.Trim('"') -ne (Join-Path $target 'Vantrel.Security.Service.exe')) { throw 'Unexpected service binary path.' }
$unchangedHashes = @{
    'Vantrel.Security.Service.exe' = $expectedHashes['Vantrel.Security.Service.exe']
    'Vantrel.Security.Core.dll' = $expectedHashes['Vantrel.Security.Core.dll']
    'System.Diagnostics.EventLog.Messages.dll' = '8F3DEF30D41D85E2BD87B2D2E7542D49D625F0B4D96A6DC9B03E0F49BD59B8EF'
}
foreach ($file in $unchangedHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $source $file) -Algorithm SHA256).Hash -ne $unchangedHashes[$file]) { throw "Published hash mismatch: $file" }
    if ((Get-FileHash -LiteralPath (Join-Path $target $file) -Algorithm SHA256).Hash -ne $unchangedHashes[$file]) { throw "Installed baseline mismatch: $file" }
}
$installedServiceHash = (Get-FileHash -LiteralPath (Join-Path $target 'Vantrel.Security.Service.dll') -Algorithm SHA256).Hash
$installedInfrastructureHash = (Get-FileHash -LiteralPath (Join-Path $target 'Vantrel.Security.Infrastructure.dll') -Algorithm SHA256).Hash
$isIpcFix = $installedServiceHash -eq '39866E2DAFCD5473E4F9570FFE5ED16CD4BFD6DBD39BBD8B1739A26E5B019446' -and $installedInfrastructureHash -eq 'F8436B38E1632AEFA6BD0DA1A493E8193956F70EADFD4AA556E31B1523C67234'
$isIpcDrain = $installedServiceHash -eq 'A68605C937CFA248EF7504172E26393156C1FC9656EFC95AF234E27478CF0845' -and $installedInfrastructureHash -eq '3F00B2D297E684C1C332F60D4A8829A767BCE7DD5B6FB4DF322A8BBB03D544AB'
if (-not ($isIpcFix -or $isIpcDrain)) { throw 'Installed service DLL pair is not a recognized Task 003 build.' }
foreach ($file in 'Vantrel.Security.Service.dll','Vantrel.Security.Infrastructure.dll') {
    if ((Get-Item -LiteralPath (Join-Path $target $file) -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Linked installed file: $file" }
}
$beforePid = $service.ProcessId
$restartStart = Get-Date
Stop-Service -Name $name
(Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
foreach ($file in 'Vantrel.Security.Service.dll','Vantrel.Security.Infrastructure.dll') {
    Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $target $file) -Force
    if ((Get-FileHash -LiteralPath (Join-Path $target $file) -Algorithm SHA256).Hash -ne $expectedHashes[$file]) { throw "Installed hash mismatch: $file" }
}
Start-Service -Name $name
(Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
Get-Service -Name $name
sc.exe qc $name
if ($LASTEXITCODE) { throw 'Service configuration query failed.' }
$afterPid = (Get-CimInstance Win32_Service -Filter "Name='VantrelSecurityService'").ProcessId
"Service PID before=$beforePid after=$afterPid"
$startup = $null
for ($attempt = 0; $attempt -lt 10 -and $null -eq $startup; $attempt++) {
    Start-Sleep -Seconds 1
    $startup = Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName=$name;StartTime=$restartStart} -ErrorAction SilentlyContinue |
        Where-Object { ([xml]$_.ToXml()).Event.EventData.InnerText -like '*Local status pipe started*' } |
        Select-Object -First 1
}
if ($null -eq $startup) { throw 'No fresh local status pipe startup event was recorded.' }
"Fresh pipe startup event: $($startup.TimeCreated)"
```

Then launch `artifacts/task003-ipc-visibility-20260917/desktop/Vantrel.Security.Desktop.exe` from a **non-elevated** PowerShell window. The service-status card now shows a safe connection detail if it remains Disconnected. In the Administrator window, query Application events since `$restartStart` and look for `Status IPC ClientConnected` and `Status IPC ResponseConsumed` after the desktop attempts a query. Continue at **Validate the installed service** below for stop and restart checks. If it fails, keep the service installed and collect the visible connection detail and fresh Event Log entries.

## Fresh installation when no service exists

Run from the repository root in a normal PowerShell window. Choose a new output folder if `manual` already exists:

```powershell
dotnet publish src/Vantrel.Security.Service/Vantrel.Security.Service.csproj --configuration Release --runtime win-x64 --self-contained false --output artifacts/service/win-x64/manual
Get-FileHash artifacts/service/win-x64/manual/Vantrel.Security.Service.exe -Algorithm SHA256
dotnet --list-runtimes
```

Confirm the installed .NET 10 Windows Desktop Runtime is current with [Microsoft's support policy](https://dotnet.microsoft.com/en-us/platform/support/policy). Open **Windows PowerShell as Administrator** in the repository root and type the following commands. These refuse an existing service or installation directory:

```powershell
$ErrorActionPreference = 'Stop'
$name = 'VantrelSecurityService'
$source = (Resolve-Path 'artifacts/service/win-x64/manual').Path
$target = Join-Path $env:ProgramFiles 'Vantrel Security\Service'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'Service already exists.' }
if (Test-Path -LiteralPath $target) { throw 'Installation directory already exists.' }
if (-not (Test-Path -LiteralPath (Join-Path $source 'Vantrel.Security.Service.exe') -PathType Leaf)) { throw 'Published executable is missing.' }
if ((Get-Item -LiteralPath $source -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Published directory is linked.' }
if (Get-ChildItem -LiteralPath $source -Force -Recurse | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint }) { throw 'Published files contain links.' }
New-Item -ItemType Directory -Path $target | Out-Null
icacls.exe $target /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX'
if ($LASTEXITCODE) { throw 'Setting the installation ACL failed.' }
icacls.exe $target /inheritance:r
if ($LASTEXITCODE) { throw 'Removing inherited installation rights failed.' }
Get-ChildItem -LiteralPath $source -Force | Copy-Item -Destination $target -Recurse -Force
if ((Get-FileHash (Join-Path $source 'Vantrel.Security.Service.exe') -Algorithm SHA256).Hash -ne (Get-FileHash (Join-Path $target 'Vantrel.Security.Service.exe') -Algorithm SHA256).Hash) { throw 'Copied executable hash mismatch.' }
if ([System.Diagnostics.EventLog]::SourceExists($name)) { throw 'Event Log source already exists; inspect it before continuing.' }
New-EventLog -LogName Application -Source $name -MessageResourceFile (Join-Path $target 'System.Diagnostics.EventLog.Messages.dll')
$imagePath = '"' + (Join-Path $target 'Vantrel.Security.Service.exe') + '"'
sc.exe create $name binPath= $imagePath start= demand obj= 'NT AUTHORITY\LocalService' DisplayName= 'Vantrel Security Service'
if ($LASTEXITCODE) { throw 'Service creation failed.' }
sc.exe qc $name
if ($LASTEXITCODE) { throw 'Service configuration query failed.' }
Start-Service -Name $name
(Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
Get-Service -Name $name
```

## Validate the installed service

Launch the WPF desktop from a **normal, non-elevated** PowerShell window. It should show Connected, service version 0.1.0, and a live heartbeat. Watch at least two refreshes to confirm heartbeat and uptime advance. Protection remains Unavailable:

```powershell
$desktop = (Resolve-Path 'artifacts/task003-ipc-visibility-20260917/desktop').Path
$desktopHashes = @{
    'Vantrel.Security.Desktop.exe' = '4CC534AF97DBB9638EC6FE07CF0DBF4F3ABBF6B8A0E467CF3CE20819FE383F3B'
    'Vantrel.Security.Desktop.dll' = '395AAD0C3899483BA32BAD61F3E7FC40AFBAE9377D192F0F6DB9CF72EF807DED'
    'Vantrel.Security.Infrastructure.dll' = '70536D95E1274C0EAA43EE3C3E589CA21B283136781FC71DCF7083454DB22DB5'
    'Vantrel.Security.Core.dll' = '48BECBCC978875CB5AAA7749EBFEEB9B49CD4820C963B51C908D1904830574CB'
}
foreach ($file in $desktopHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $desktop $file) -Algorithm SHA256).Hash -ne $desktopHashes[$file]) { throw "Desktop hash mismatch: $file" }
}
& (Join-Path $desktop 'Vantrel.Security.Desktop.exe')
```

In the Administrator window, stop the service. Wait until the desktop shows **Disconnected** before running the restart commands below:

```powershell
Stop-Service -Name VantrelSecurityService
(Get-Service -Name VantrelSecurityService).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
Get-Service -Name VantrelSecurityService
```

Then restart it. Confirm the desktop returns to **Connected**, shows service version 0.1.0, and resumes heartbeat/uptime updates. Inspect the Application Event Log:

```powershell
Start-Service -Name VantrelSecurityService
(Get-Service -Name VantrelSecurityService).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
Get-Service -Name VantrelSecurityService
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'VantrelSecurityService' } -MaxEvents 20 | ForEach-Object { "[$($_.TimeCreated)] $(([xml]$_.ToXml()).Event.EventData.InnerText)" }
```

## Optional removal of the development service

If you choose to remove this development installation, keep the desktop open and remove only the dedicated service installation. After removal, confirm the desktop shows Disconnected on its next refresh, then close it. These commands check the exact target and refuse linked directories before recursive removal:

```powershell
$name = 'VantrelSecurityService'
$programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
$expected = [System.IO.Path]::GetFullPath((Join-Path $programFilesRoot 'Vantrel Security\Service'))
$target = (Resolve-Path -LiteralPath $expected).Path
if (-not $target.StartsWith($programFilesRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Installation path is outside Program Files.' }
if (-not [string]::Equals($target, $expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected installation path.' }
if ((Get-Item -LiteralPath $target -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Linked installation directory.' }
if ((Get-Item -LiteralPath (Split-Path -Parent $target) -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Linked parent directory.' }
Stop-Service -Name $name -ErrorAction SilentlyContinue
(Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
sc.exe delete $name
if ($LASTEXITCODE) { throw 'Service deletion failed.' }
for ($attempt = 0; $attempt -lt 10 -and (Get-Service -Name $name -ErrorAction SilentlyContinue); $attempt++) { Start-Sleep -Seconds 1 }
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'Service is still pending deletion; close service-management handles and retry verification.' }
Remove-Item -LiteralPath $target -Recurse -Force
Remove-EventLog -Source $name
Get-Service -Name $name -ErrorAction SilentlyContinue
```

The final `Get-Service` command should produce no service. Confirm the desktop remains Disconnected after removal.

The release service is framework-dependent and unsigned. This manual procedure is for validation only; do not treat it as a production installer. Task 003 validation recorded the `sc.exe qc` account (`NT AUTHORITY\LocalService`), Running/Stopped transitions, displayed service version, heartbeat and uptime, reconnect/disconnect behavior, and Event Log entries. Removal is optional and has not been performed as part of the passing installed-service check. See [DEPLOYMENT.md](DEPLOYMENT.md) for future signing requirements.
