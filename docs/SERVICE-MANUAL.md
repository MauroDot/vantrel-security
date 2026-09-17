# Manual Windows Service validation

Use this procedure when unsigned `.ps1` files cannot run under the machine's PowerShell policy. It does not change execution policy. Review the source and publish output first. **Installation, start, stop, restart, and removal require an Administrator PowerShell window.** Querying status and launching the desktop do not.

Run from the repository root in a normal PowerShell window. Choose a new output folder if `manual` already exists:

```powershell
dotnet publish src/Vantrel.Security.Service/Vantrel.Security.Service.csproj --configuration Release --runtime win-x64 --self-contained false --output artifacts/service/win-x64/manual
Get-FileHash artifacts/service/win-x64/manual/Vantrel.Security.Service.exe -Algorithm SHA256
dotnet --list-runtimes
```

Confirm the installed .NET 9 runtime is current with [Microsoft's support policy](https://dotnet.microsoft.com/en-us/platform/support/policy). Open **Windows PowerShell as Administrator** in the repository root and type the following commands. These refuse an existing service or installation directory:

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
New-EventLog -LogName Application -Source $name -MessageResourceFile (Join-Path $target 'System.Diagnostics.EventLog.Messages.dll')
$imagePath = '"' + (Join-Path $target 'Vantrel.Security.Service.exe') + '"'
sc.exe create $name binPath= $imagePath start= demand obj= 'NT AUTHORITY\LocalService' DisplayName= 'Vantrel Security Service'
if ($LASTEXITCODE) { throw 'Service creation failed.' }
sc.exe qc $name
Start-Service -Name $name
(Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
Get-Service -Name $name
```

Launch the WPF desktop from a **normal, non-elevated** PowerShell window. It should show Connected, service version 0.1.0, and a live heartbeat. Protection remains Unavailable:

```powershell
dotnet run --project src/Vantrel.Security.Desktop --configuration Release
```

In the Administrator window, stop and restart the service. The desktop should change to Disconnected within ten seconds after stop and reconnect within ten seconds after restart:

```powershell
Stop-Service -Name VantrelSecurityService
Get-Service -Name VantrelSecurityService
Start-Service -Name VantrelSecurityService
Get-Service -Name VantrelSecurityService
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'VantrelSecurityService' } -MaxEvents 20
```

Close the desktop and remove only the dedicated service installation. These commands check the exact target and refuse linked directories before recursive removal:

```powershell
$name = 'VantrelSecurityService'
$target = [System.IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'Vantrel Security\Service'))
$expected = [System.IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'Vantrel Security\Service'))
Stop-Service -Name $name -ErrorAction SilentlyContinue
(Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
sc.exe delete $name
if ($LASTEXITCODE) { throw 'Service deletion failed.' }
if (-not [string]::Equals($target, $expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected installation path.' }
if ((Get-Item -LiteralPath $target -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Linked installation directory.' }
if ((Get-Item -LiteralPath (Split-Path -Parent $target) -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Linked parent directory.' }
Remove-Item -LiteralPath $target -Recurse -Force
Remove-EventLog -Source $name
Get-Service -Name $name -ErrorAction SilentlyContinue
```

The release service is framework-dependent and unsigned. This manual procedure is for validation only; do not treat it as a production installer.
