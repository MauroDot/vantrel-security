# Manual Windows Service validation

Vantrel Security is pre-release development software and must not be relied upon as the sole antivirus or endpoint protection solution.

**Current status (2026-09-18): Tasks 003–005 passed installed-service validation.** The guarded Task 005 upgrade verified the Task 004 baseline and kept `VantrelSecurityService` under LocalService. It restarted with PID changing from 34524 to 32576, and fresh pipe and health-sampling startup checks passed. The hash-verified desktop ran non-elevated and showed Windows-reported antivirus health Good with Vantrel Protection Status Unavailable. System Health changed to Disconnected when the service stopped; after restart, the same desktop reconnected to a fresh Good sample whose timestamp advanced from 2:38 AM to 3:03 AM. Confirm any other target machine has a current .NET 10 runtime and Windows Desktop Runtime.

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

## Task 004 update and System Health validation

The following update assumes the exact Task 003 installed DLL baseline validated above. Run it in **Administrator Windows PowerShell 5.1** from any directory. It replaces only the three changed Vantrel-owned service DLLs. It does not touch the registered Event Log source or `System.Diagnostics.EventLog.Messages.dll`.

```powershell
$ErrorActionPreference = 'Stop'
$repository = 'C:\Users\tmaur\VANTREL SECURITY'
$name = 'VantrelSecurityService'
$source = (Resolve-Path -LiteralPath (Join-Path $repository 'artifacts\task004-system-health-20260917\service')).Path
$programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
$expected = [System.IO.Path]::GetFullPath((Join-Path $programFilesRoot 'Vantrel Security\Service'))
$target = (Resolve-Path -LiteralPath $expected).Path
if (-not $target.StartsWith($programFilesRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Installation path is outside Program Files.' }
if (-not [string]::Equals($target, $expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected installation path.' }
foreach ($directory in @($source, $target, (Split-Path -Parent $target))) {
    if ((Get-Item -LiteralPath $directory -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Linked directory: $directory" }
}
$service = Get-CimInstance Win32_Service -Filter "Name='VantrelSecurityService'"
if ($null -eq $service -or $service.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Unexpected service registration or account.' }
if ($service.PathName.Trim('"') -ne (Join-Path $target 'Vantrel.Security.Service.exe')) { throw 'Unexpected service binary path.' }
$oldHashes = @{
    'Vantrel.Security.Service.exe' = 'C23423AE0B0AF023CDFD0F7955EF3066DA661175E74A28C0B03F86C2A0A4776A'
    'Vantrel.Security.Service.dll' = '30F22CD083BACD7B3A504DE268EC37DC5C31F69FBF4C08F9B66A8DBB30BBC992'
    'Vantrel.Security.Infrastructure.dll' = '70536D95E1274C0EAA43EE3C3E589CA21B283136781FC71DCF7083454DB22DB5'
    'Vantrel.Security.Core.dll' = '48BECBCC978875CB5AAA7749EBFEEB9B49CD4820C963B51C908D1904830574CB'
}
$newHashes = @{
    'Vantrel.Security.Service.dll' = 'D23D8B6FC912198EAA6FE06DFD8E1E1D8AB1A66E2E4172F690CBB10B05153223'
    'Vantrel.Security.Infrastructure.dll' = 'F34ACE9CAB08D2EFA634D2F606254EECFFCDFF55E549D9DD4C95B49DE1B81C85'
    'Vantrel.Security.Core.dll' = '5CAEB321372E4CDDD8CE77D78F061C341B99A3DD487115ECD2E6BB0AD7F82E84'
}
$unchangedMetadata = @{
    'Vantrel.Security.Service.deps.json' = '93FF404CEA5B4070091DEFFE0A944C3FAD2C6D5FDB1849F92E2873215C9064FB'
    'Vantrel.Security.Service.runtimeconfig.json' = '3E965CD7CFD553C2FF4E842D8D8019AAAE2DA0A21D92FF85A87573DD8D1B95C6'
    'System.Diagnostics.EventLog.Messages.dll' = '8F3DEF30D41D85E2BD87B2D2E7542D49D625F0B4D96A6DC9B03E0F49BD59B8EF'
}
foreach ($file in $oldHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $target $file) -Algorithm SHA256).Hash -ne $oldHashes[$file]) { throw "Installed baseline mismatch: $file" }
}
foreach ($file in $unchangedMetadata.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $source $file) -Algorithm SHA256).Hash -ne $unchangedMetadata[$file]) { throw "Published metadata mismatch: $file" }
    if ((Get-FileHash -LiteralPath (Join-Path $target $file) -Algorithm SHA256).Hash -ne $unchangedMetadata[$file]) { throw "Installed metadata mismatch: $file" }
}
foreach ($file in $newHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $source $file) -Algorithm SHA256).Hash -ne $newHashes[$file]) { throw "Published hash mismatch: $file" }
    if ((Get-Item -LiteralPath (Join-Path $source $file) -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Linked source file: $file" }
    if ((Get-Item -LiteralPath (Join-Path $target $file) -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Linked installed file: $file" }
}
$beforePid = $service.ProcessId
$restartStart = Get-Date
Stop-Service -Name $name
(Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
foreach ($file in $newHashes.Keys) {
    Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $target $file) -Force
    if ((Get-FileHash -LiteralPath (Join-Path $target $file) -Algorithm SHA256).Hash -ne $newHashes[$file]) { throw "Installed hash mismatch: $file" }
}
Start-Service -Name $name
(Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
$afterPid = (Get-CimInstance Win32_Service -Filter "Name='VantrelSecurityService'").ProcessId
if ($afterPid -eq 0 -or $afterPid -eq $beforePid) { throw 'Service did not start with a new process.' }
$events = @()
for ($attempt = 0; $attempt -lt 10; $attempt++) {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName=$name; StartTime=$restartStart } -ErrorAction SilentlyContinue)
    if (($events | Where-Object { $_.Message -like '*Local status pipe started*' }) -and
        ($events | Where-Object { $_.Message -like '*System health sampling started*' })) { break }
    Start-Sleep -Seconds 1
}
if (-not ($events | Where-Object { $_.Message -like '*Local status pipe started*' })) { throw 'No fresh status pipe startup event.' }
if (-not ($events | Where-Object { $_.Message -like '*System health sampling started*' })) { throw 'No fresh health sampling startup event.' }
Get-Service -Name $name
"Service PID before=$beforePid after=$afterPid"
```

From a separate **non-elevated** PowerShell window, verify and launch the matching published desktop:

```powershell
$desktop = (Resolve-Path -LiteralPath 'C:\Users\tmaur\VANTREL SECURITY\artifacts\task004-system-health-20260917\desktop').Path
$desktopHashes = @{
    'Vantrel.Security.Desktop.exe' = '111CB3AB4AC212883E766D1CF6E079D187DE6CDCA19D533F6395DF1D3BDF7194'
    'Vantrel.Security.Desktop.dll' = '43A6C4F9AECDC0D3E7206493BA422649BFF40B965B6F6B69F5BDC1E9B881ABF3'
    'Vantrel.Security.Infrastructure.dll' = 'F34ACE9CAB08D2EFA634D2F606254EECFFCDFF55E549D9DD4C95B49DE1B81C85'
    'Vantrel.Security.Core.dll' = '5CAEB321372E4CDDD8CE77D78F061C341B99A3DD487115ECD2E6BB0AD7F82E84'
}
foreach ($file in $desktopHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $desktop $file) -Algorithm SHA256).Hash -ne $desktopHashes[$file]) { throw "Desktop hash mismatch: $file" }
}
& (Join-Path $desktop 'Vantrel.Security.Desktop.exe')
```

On System Health, confirm a recent sample timestamp, Windows version/build, elapsed system uptime, and system-volume free/total space or explicit Unavailable values. Leave the desktop open. In the Administrator window, stop the service and wait for the desktop to show Disconnected; then start the service and confirm that the same desktop reconnects and receives a fresh sample. This validation passed on 2026-09-18 with a newer sample timestamp after reconnection:

```powershell
Stop-Service -Name VantrelSecurityService
(Get-Service -Name VantrelSecurityService).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
Get-Service -Name VantrelSecurityService
```

```powershell
Start-Service -Name VantrelSecurityService
(Get-Service -Name VantrelSecurityService).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
Get-Service -Name VantrelSecurityService
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='VantrelSecurityService' } -MaxEvents 20
```

## Task 005 antivirus-health update and validation

This guarded update assumes the exact Task 004 DLLs validated above are installed and the service is Running under LocalService. Run the following as **one uninterrupted block** in Administrator Windows PowerShell 5.1. It verifies the old installation and the new paired payload, replaces only three Vantrel-owned DLLs, and leaves the Event Log source and message-resource DLL untouched. If any guard fails, stop and inspect the installation before trying again; the block intentionally does not accept a partly updated baseline.

```powershell
$ErrorActionPreference = 'Stop'
$repository = 'C:\Users\tmaur\VANTREL SECURITY'
$name = 'VantrelSecurityService'
$source = (Resolve-Path -LiteralPath (Join-Path $repository 'artifacts\task005-antivirus-health-20260918\service')).Path
$programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
$expected = [System.IO.Path]::GetFullPath((Join-Path $programFilesRoot 'Vantrel Security\Service'))
$target = (Resolve-Path -LiteralPath $expected).Path
if (-not $target.StartsWith($programFilesRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Installation path is outside Program Files.' }
if (-not [string]::Equals($target, $expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected installation path.' }
foreach ($directory in @($source, $target, (Split-Path -Parent $target))) {
    if ((Get-Item -LiteralPath $directory -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Linked directory: $directory" }
}
$service = Get-CimInstance Win32_Service -Filter "Name='VantrelSecurityService'"
if ($null -eq $service -or $service.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Unexpected service registration or account.' }
if ($service.State -ne 'Running' -or $service.ProcessId -eq 0) { throw 'Service is not Running.' }
if ($service.PathName.Trim('"') -ne (Join-Path $target 'Vantrel.Security.Service.exe')) { throw 'Unexpected service binary path.' }
$oldHashes = @{
    'Vantrel.Security.Service.exe' = 'C23423AE0B0AF023CDFD0F7955EF3066DA661175E74A28C0B03F86C2A0A4776A'
    'Vantrel.Security.Service.dll' = 'D23D8B6FC912198EAA6FE06DFD8E1E1D8AB1A66E2E4172F690CBB10B05153223'
    'Vantrel.Security.Infrastructure.dll' = 'F34ACE9CAB08D2EFA634D2F606254EECFFCDFF55E549D9DD4C95B49DE1B81C85'
    'Vantrel.Security.Core.dll' = '5CAEB321372E4CDDD8CE77D78F061C341B99A3DD487115ECD2E6BB0AD7F82E84'
}
$newHashes = @{
    'Vantrel.Security.Service.dll' = '57492FEC1573B9CB40966D722C1087A610EDBFD8645292BDDFF1BA481C056D3F'
    'Vantrel.Security.Infrastructure.dll' = 'BE66E6838D4EBF37AC22A26CDCF5AE21BA38D4A29DC40456ACFC4EDD8674CB95'
    'Vantrel.Security.Core.dll' = '78BDB5DB78E1C1D34115C648E93B3259CC6C5156688B00182FDDBC37A5EAC348'
}
$unchangedHashes = @{
    'Vantrel.Security.Service.deps.json' = '93FF404CEA5B4070091DEFFE0A944C3FAD2C6D5FDB1849F92E2873215C9064FB'
    'Vantrel.Security.Service.runtimeconfig.json' = '3E965CD7CFD553C2FF4E842D8D8019AAAE2DA0A21D92FF85A87573DD8D1B95C6'
    'System.Diagnostics.EventLog.Messages.dll' = '8F3DEF30D41D85E2BD87B2D2E7542D49D625F0B4D96A6DC9B03E0F49BD59B8EF'
}
if ((Get-FileHash -LiteralPath (Join-Path $source 'Vantrel.Security.Service.exe') -Algorithm SHA256).Hash -ne '2E52978A89F299B88AEB0108A139E227CA03C1F1A02A185A768C1DA5EEBB8466') { throw 'Published service executable hash mismatch.' }
foreach ($file in $oldHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $target $file) -Algorithm SHA256).Hash -ne $oldHashes[$file]) { throw "Installed Task 004 baseline mismatch: $file" }
}
foreach ($file in $unchangedHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $source $file) -Algorithm SHA256).Hash -ne $unchangedHashes[$file]) { throw "Published metadata mismatch: $file" }
    if ((Get-FileHash -LiteralPath (Join-Path $target $file) -Algorithm SHA256).Hash -ne $unchangedHashes[$file]) { throw "Installed metadata mismatch: $file" }
}
foreach ($file in $newHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $source $file) -Algorithm SHA256).Hash -ne $newHashes[$file]) { throw "Published hash mismatch: $file" }
    if ((Get-Item -LiteralPath (Join-Path $source $file) -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Linked source file: $file" }
    if ((Get-Item -LiteralPath (Join-Path $target $file) -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Linked installed file: $file" }
}
$beforePid = $service.ProcessId
$restartStart = Get-Date
Stop-Service -Name $name
(Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
foreach ($file in $newHashes.Keys) {
    Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $target $file) -Force
    if ((Get-FileHash -LiteralPath (Join-Path $target $file) -Algorithm SHA256).Hash -ne $newHashes[$file]) { throw "Installed hash mismatch: $file" }
}
Start-Service -Name $name
(Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
$afterPid = (Get-CimInstance Win32_Service -Filter "Name='VantrelSecurityService'").ProcessId
if ($afterPid -eq 0 -or $afterPid -eq $beforePid) { throw 'Service did not start with a new process.' }
$events = @()
for ($attempt = 0; $attempt -lt 10; $attempt++) {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName=$name; StartTime=$restartStart } -ErrorAction SilentlyContinue)
    if (($events | Where-Object { $_.Message -like '*Local status pipe started*' }) -and
        ($events | Where-Object { $_.Message -like '*System health sampling started*' })) { break }
    Start-Sleep -Seconds 1
}
if (-not ($events | Where-Object { $_.Message -like '*Local status pipe started*' })) { throw 'No fresh status pipe startup event.' }
if (-not ($events | Where-Object { $_.Message -like '*System health sampling started*' })) { throw 'No fresh health sampling startup event.' }
Get-Service -Name $name
"Service PID before=$beforePid after=$afterPid"
```

In a separate **non-elevated** PowerShell window, verify and run the matching Task 005 desktop:

```powershell
$desktop = (Resolve-Path -LiteralPath 'C:\Users\tmaur\VANTREL SECURITY\artifacts\task005-antivirus-health-20260918\desktop').Path
$desktopHashes = @{
    'Vantrel.Security.Desktop.exe' = 'F5EE1875C748465EB51FD203F63818438A243089005F124AD12250DB44231583'
    'Vantrel.Security.Desktop.dll' = '01EF449EFF8546070CCD0B4AABCDCD03110F5A5F97EC112E2C1D83051A13245A'
    'Vantrel.Security.Infrastructure.dll' = 'BE66E6838D4EBF37AC22A26CDCF5AE21BA38D4A29DC40456ACFC4EDD8674CB95'
    'Vantrel.Security.Core.dll' = '78BDB5DB78E1C1D34115C648E93B3259CC6C5156688B00182FDDBC37A5EAC348'
}
foreach ($file in $desktopHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $desktop $file) -Algorithm SHA256).Hash -ne $desktopHashes[$file]) { throw "Desktop hash mismatch: $file" }
}
& (Join-Path $desktop 'Vantrel.Security.Desktop.exe')
```

Confirm Dashboard stays Connected with Protection Status **Unavailable**. On System Health, check the sample timestamp, the Task 004 values, and **Windows-reported antivirus health**. Record whether Windows reports Good, Poor, Snoozed, Not monitored, or Unavailable. An Unavailable result requires review of fresh safe service diagnostics; it is not evidence of Good or Poor. Leave the desktop open, then use the Administrator window to stop the service. Wait for System Health to show Disconnected before restarting it:

```powershell
Stop-Service -Name VantrelSecurityService
(Get-Service -Name VantrelSecurityService).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
Get-Service -Name VantrelSecurityService
```

```powershell
Start-Service -Name VantrelSecurityService
(Get-Service -Name VantrelSecurityService).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
Get-Service -Name VantrelSecurityService
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='VantrelSecurityService' } -MaxEvents 30 | ForEach-Object { "[$($_.TimeCreated)] $($_.Message)" }
```

The same desktop process should reconnect and show a newer sample timestamp. Do not stop or reconfigure Windows Security Center to test failure handling. This validation passed on 2026-09-18: the installed LocalService service reported Good before and after the restart, Vantrel Protection Status stayed Unavailable, and the same non-elevated desktop reconnected to a newer sample. Other Windows Security Center states and failure paths were covered by injected automated tests.

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
