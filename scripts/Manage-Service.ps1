[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'Start', 'Stop', 'Restart', 'Status', 'Uninstall')]
    [string]$Action
)

$ErrorActionPreference = 'Stop'
$serviceName = 'VantrelSecurityService'
$displayName = 'Vantrel Security Service'
$eventSource = $serviceName
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$publishRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'artifacts\service\win-x64'))
$latestPath = Join-Path $publishRoot 'latest-path.txt'
$programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
$installDirectory = [System.IO.Path]::GetFullPath((Join-Path $programFilesRoot 'Vantrel Security\Service'))
$expectedDirectory = Join-Path $programFilesRoot 'Vantrel Security\Service'
$executable = Join-Path $installDirectory 'Vantrel.Security.Service.exe'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The $Action action requires Administrator privileges. Open Windows PowerShell as Administrator and rerun it."
    }
}

function Get-VantrelService {
    return Get-Service -Name $serviceName -ErrorAction SilentlyContinue
}

function Stop-VantrelService {
    $service = Get-VantrelService
    if ($null -eq $service) { throw "Service $serviceName is not installed." }
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name $serviceName -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    }
    Write-Host "$serviceName is stopped."
}

function Start-VantrelService {
    $service = Get-VantrelService
    if ($null -eq $service) { throw "Service $serviceName is not installed." }
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        Start-Service -Name $serviceName -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    }
    Write-Host "$serviceName is running."
}

if (-not $installDirectory.StartsWith($programFilesRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals($installDirectory, $expectedDirectory, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Unexpected installation directory.'
}
if ($Action -ne 'Status' -and -not $WhatIfPreference) { Assert-Administrator }

switch ($Action) {
    'Status' {
        $service = Get-VantrelService
        if ($null -eq $service) { Write-Host "$serviceName is not installed."; break }
        $service.Refresh()
        Write-Host "$serviceName : $($service.Status)"
        & sc.exe qc $serviceName
        if ($LASTEXITCODE -ne 0) { throw "sc.exe qc failed with exit code $LASTEXITCODE." }
    }
    'Install' {
        if ($null -ne (Get-VantrelService)) { throw "$serviceName is already installed. Uninstall it before installing another build." }
        if (Test-Path -LiteralPath $installDirectory) { throw "Installation directory already exists: $installDirectory" }
        if (-not (Test-Path -LiteralPath $latestPath -PathType Leaf)) { throw 'No published service found. Run scripts\Publish-Service.ps1 first.' }
        $relativePath = [System.IO.File]::ReadAllText($latestPath).Trim()
        $publishDirectory = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $relativePath))
        if (-not $publishDirectory.StartsWith($publishRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The published path is outside the expected artifacts directory.'
        }
        $publishedExecutable = Join-Path $publishDirectory 'Vantrel.Security.Service.exe'
        if ((Get-Item -LiteralPath $publishDirectory -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'Published output directory is a link or reparse point.'
        }
        if (-not (Test-Path -LiteralPath $publishedExecutable -PathType Leaf)) { throw "Missing published executable: $publishedExecutable" }
        $runtimeConfigPath = Join-Path $publishDirectory 'Vantrel.Security.Service.runtimeconfig.json'
        if (-not (Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf)) { throw "Missing runtime configuration: $runtimeConfigPath" }
        $runtimeConfig = Get-Content -LiteralPath $runtimeConfigPath -Raw | ConvertFrom-Json
        $requiredFramework = $runtimeConfig.runtimeOptions.framework
        if ($requiredFramework.name -ne 'Microsoft.NETCore.App') { throw 'Unexpected service runtime framework.' }
        $requiredVersion = [Version]$requiredFramework.version
        $runtimePattern = '^Microsoft\.NETCore\.App\s+' + [regex]::Escape("$($requiredVersion.Major).$($requiredVersion.Minor).")
        $runtimes = & dotnet --list-runtimes
        if ($LASTEXITCODE -ne 0 -or -not ($runtimes | Where-Object { $_ -match $runtimePattern })) {
            throw "A .NET $($requiredVersion.Major).$($requiredVersion.Minor) runtime is required for this framework-dependent service. Check its patch level before installing."
        }
        $links = Get-ChildItem -LiteralPath $publishDirectory -Force -Recurse |
            Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 }
        if ($links) { throw 'Published output contains links or reparse points; refusing an elevated copy.' }
        if ($PSCmdlet.ShouldProcess($installDirectory, "Install $displayName under LocalService")) {
            New-Item -ItemType Directory -Path $installDirectory -ErrorAction Stop | Out-Null
            & icacls.exe $installDirectory /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX'
            if ($LASTEXITCODE -ne 0) { throw "icacls grant failed with exit code $LASTEXITCODE." }
            & icacls.exe $installDirectory /inheritance:r
            if ($LASTEXITCODE -ne 0) { throw "icacls inheritance change failed with exit code $LASTEXITCODE." }
            Get-ChildItem -LiteralPath $publishDirectory -Force |
                Copy-Item -Destination $installDirectory -Recurse -Force -ErrorAction Stop
            if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Copy failed: service executable is missing.' }
            $sourceHash = (Get-FileHash -LiteralPath $publishedExecutable -Algorithm SHA256).Hash
            $installedHash = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
            if ($sourceHash -ne $installedHash) { throw 'Copied executable hash does not match the published executable.' }
            if ([System.Diagnostics.EventLog]::SourceExists($eventSource)) {
                $registeredLog = [System.Diagnostics.EventLog]::LogNameFromSourceName($eventSource, '.')
                if ($registeredLog -ne 'Application') { throw "Event source $eventSource belongs to $registeredLog, not Application." }
            }
            else {
                $eventMessages = Join-Path $installDirectory 'System.Diagnostics.EventLog.Messages.dll'
                if (-not (Test-Path -LiteralPath $eventMessages -PathType Leaf)) { throw "Missing Event Log message resource: $eventMessages" }
                New-EventLog -LogName Application -Source $eventSource -MessageResourceFile $eventMessages -ErrorAction Stop
            }
            $imagePath = '"' + $executable + '"'
            & sc.exe create $serviceName binPath= $imagePath start= demand obj= 'NT AUTHORITY\LocalService' DisplayName= $displayName
            if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE." }
            Write-Host "$displayName installed as LocalService. Start it with -Action Start."
        }
    }
    'Start' {
        if ($PSCmdlet.ShouldProcess($serviceName, 'Start service')) { Start-VantrelService }
    }
    'Stop' {
        if ($PSCmdlet.ShouldProcess($serviceName, 'Stop service')) { Stop-VantrelService }
    }
    'Restart' {
        if ($PSCmdlet.ShouldProcess($serviceName, 'Restart service')) {
            Stop-VantrelService
            Start-VantrelService
        }
    }
    'Uninstall' {
        if ($null -eq (Get-VantrelService)) { throw "$serviceName is not installed." }
        if ($PSCmdlet.ShouldProcess($serviceName, 'Stop and uninstall service, then remove its dedicated installation directory')) {
            Stop-VantrelService
            & sc.exe delete $serviceName
            if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE." }
            if (Test-Path -LiteralPath $installDirectory) {
                $installItem = Get-Item -LiteralPath $installDirectory -Force
                if ($installItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    throw 'Refusing to remove a linked installation directory.'
                }
                $parentItem = Get-Item -LiteralPath (Split-Path -Parent $installDirectory) -Force
                if ($parentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    throw 'Refusing to remove through a linked parent directory.'
                }
                $resolvedInstallDirectory = (Resolve-Path -LiteralPath $installDirectory).Path
                if (-not [string]::Equals($resolvedInstallDirectory, $expectedDirectory, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Refusing to remove a directory outside the expected installation path.'
                }
                Remove-Item -LiteralPath $resolvedInstallDirectory -Recurse -Force -ErrorAction Stop
            }
            if ([System.Diagnostics.EventLog]::SourceExists($eventSource)) {
                $registeredLog = [System.Diagnostics.EventLog]::LogNameFromSourceName($eventSource, '.')
                if ($registeredLog -ne 'Application') { throw "Refusing to remove an event source owned by $registeredLog." }
                Remove-EventLog -Source $eventSource -ErrorAction Stop
            }
            Write-Host "$displayName uninstalled. Historical Application event entries remain under Windows retention policy."
        }
    }
}
