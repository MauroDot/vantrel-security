$ErrorActionPreference = 'Stop'
if ($args.Count -ne 0) { throw 'Sandbox validator accepts no arguments.' }
$input = 'C:\VantrelInput'
$manifestPath = Join-Path $input 'vantrel-sandbox-input-v1.txt'
$planPath = Join-Path $input 'vantrel-installer-input-v1.txt'
$msiPath = Join-Path $input 'VantrelSecurity.msi'

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-SafeInputRoot {
    $full = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($input))
    Assert-Condition ($full -ceq 'C:\VantrelInput') 'Sandbox input is unavailable.'
    for ($current = [IO.DirectoryInfo]$full; $null -ne $current; $current = $current.Parent) {
        Assert-Condition ($current.Exists -and (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) 'Sandbox input is unavailable.'
    }
}

function Get-Hash([string]$Path) {
    Assert-Condition (Test-Path -LiteralPath $Path -PathType Leaf) 'Sandbox input is unavailable.'
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Condition (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Sandbox input is unavailable.'
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Read-SafeInputBytes([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    Assert-Condition (([IO.Path]::GetDirectoryName($full)) -ceq $input) 'Sandbox input is unavailable.'
    Assert-Condition (Test-Path -LiteralPath $full -PathType Leaf) 'Sandbox input is unavailable.'
    $item = Get-Item -LiteralPath $full -Force
    Assert-Condition (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Sandbox input is unavailable.'
    return [IO.File]::ReadAllBytes($full)
}

function Assert-Artifact([string]$Source, [string]$Destination, [string]$Hash) {
    Assert-Condition ($Source -match '^(service|desktop|offline-update-tool)/[^\\/:|]+(?:/[^\\/:|]+)*$' -and $Source -notmatch '(^|/)(\.|\.\.|staging|source|sources|scripts|tests|tools|bin|obj)(/|$)' -and $Source -notmatch '\.(pdb|ps1|cmd|bat|cs|csx|sln|csproj|wixproj|wxs|pk8|pem|key|pfx|p12|snk)$') 'Sandbox input is invalid.'
    $parts = $Source.Split('/', 2); $folder = @{ service = 'Service'; desktop = 'Desktop'; 'offline-update-tool' = 'OfflineUpdateTool' }[$parts[0]]
    Assert-Condition ($Destination -ceq "ProgramFiles64Folder\Vantrel Security\$folder\$($parts[1].Replace('/','\'))" -and $Hash -match '^[0-9A-F]{64}$') 'Sandbox input is invalid.'
}

function Test-CanonicalReleaseVersion([string]$Value) {
    return $Value.Length -gt 0 -and $Value.Length -le 64 -and $Value -match '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$'
}
function Test-CanonicalUtc([string]$Value) {
    $parsed = [DateTimeOffset]::MinValue
    return [DateTimeOffset]::TryParseExact($Value, "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed) -and $parsed.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) -ceq $Value
}
function Test-CanonicalMsiVersion([string]$Value) {
    $parts = $Value.Split('.'); if ($parts.Count -ne 3 -or @($parts | Where-Object { $_.Length -eq 0 -or ($_.Length -gt 1 -and $_[0] -eq '0') -or $_ -notmatch '^[0-9]+$' }).Count -ne 0) { return $false }
    [uint32]$major=0; [uint32]$minor=0; [uint32]$build=0
    return [uint32]::TryParse($parts[0], [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$major) -and [uint32]::TryParse($parts[1], [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$minor) -and [uint32]::TryParse($parts[2], [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$build) -and $major -le 255 -and $minor -le 255 -and $build -le 65535 -and "$major.$minor.$build" -ceq $Value
}
function Test-CanonicalReleaseSequence([string]$Value) {
    [uint64]$sequence = 0
    return $Value -match '^[1-9][0-9]*$' -and [uint64]::TryParse($Value, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$sequence)
}

function Read-CanonicalPlan([byte[]]$Bytes) {
    Assert-Condition ($Bytes.Length -gt 0 -and $Bytes.Length -le 1048576 -and -not ($Bytes | Where-Object { $_ -eq 13 -or $_ -gt 127 })) 'Sandbox installer plan is invalid.'
    $text = [Text.Encoding]::ASCII.GetString($Bytes); Assert-Condition ($text.EndsWith("`n") -and -not $text.StartsWith([char]0xEF)) 'Sandbox installer plan is invalid.'; $lines = $text.Split("`n")
    $keys = @('schema','source-commit','release-version','release-sequence','published-at-utc','configuration','runtime','sdk-version','release-notes-sha256','msi-product-version','service-directory','desktop-directory','offline-update-tool-directory','service-name','service-display-name','service-account','service-type','service-start','service-dependencies','service-failure-actions','service-start-action','event-log-source','event-log-name','event-log-message-resource','desktop-shortcut','desktop-shortcut-elevation','desktop-shortcut-service-start','desktop-shortcut-updater-action','desktop-shortcut-target','programdata','future-operations','artifact-count')
    Assert-Condition ($lines.Count -ge 34 -and $lines[-1] -eq '') 'Sandbox installer plan is invalid.'; $values=@{}; for($i=0;$i -lt $keys.Count;$i++){ $prefix=$keys[$i]+'='; Assert-Condition($lines[$i].StartsWith($prefix,[StringComparison]::Ordinal)) 'Sandbox installer plan is invalid.'; $values[$keys[$i]]=$lines[$i].Substring($prefix.Length) }
    $count=0; Assert-Condition ($values.schema -eq 'vantrel-installer-input-v1' -and [uint32]::TryParse($values['artifact-count'],[ref]$count) -and $count -gt 0 -and $lines.Count -eq 33+$count) 'Sandbox installer plan is invalid.'
    Assert-Condition ($values['source-commit'] -match '^[0-9a-f]{40}$' -and (Test-CanonicalReleaseVersion $values['release-version']) -and (Test-CanonicalReleaseSequence $values['release-sequence']) -and (Test-CanonicalUtc $values['published-at-utc']) -and $values['sdk-version'] -match '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' -and $values['release-notes-sha256'] -match '^[0-9A-F]{64}$' -and (Test-CanonicalMsiVersion $values['msi-product-version'])) 'Sandbox installer plan is invalid.'
    $expected=@{configuration='Release';runtime='win-x64';'service-directory'='ProgramFiles64Folder\Vantrel Security\Service';'desktop-directory'='ProgramFiles64Folder\Vantrel Security\Desktop';'offline-update-tool-directory'='ProgramFiles64Folder\Vantrel Security\OfflineUpdateTool';'service-name'='VantrelSecurityService';'service-display-name'='Vantrel Security Service';'service-account'='NT AUTHORITY\LocalService';'service-type'='own-process';'service-start'='demand';'service-dependencies'='none';'service-failure-actions'='none';'service-start-action'='none';'event-log-source'='VantrelSecurityService';'event-log-name'='Application';'event-log-message-resource'='ProgramFiles64Folder\Vantrel Security\Service\System.Diagnostics.EventLog.Messages.dll';'desktop-shortcut'='all-users-non-advertised';'desktop-shortcut-elevation'='none';'desktop-shortcut-service-start'='none';'desktop-shortcut-updater-action'='none';'desktop-shortcut-target'='ProgramFiles64Folder\Vantrel Security\Desktop\Vantrel.Security.Desktop.exe';programdata='excluded';'future-operations'='unsupported'}
    foreach($key in $expected.Keys){ Assert-Condition($values[$key] -ceq $expected[$key]) 'Sandbox installer plan is invalid.' }
    $items=@(); for($i=0;$i -lt $count;$i++){ $line=$lines[32+$i]; Assert-Condition($line.StartsWith('artifact=',[StringComparison]::Ordinal)) 'Sandbox installer plan is invalid.'; $p=$line.Substring(9).Split('|'); Assert-Condition($p.Count -eq 3) 'Sandbox installer plan is invalid.'; Assert-Artifact $p[0] $p[1] $p[2]; $items += [PSCustomObject]@{Source=$p[0];Destination=$p[1];Sha256=$p[2]} }
    Assert-Condition (($items.Source|Sort-Object -Unique).Count -eq $items.Count) 'Sandbox installer plan is invalid.'
    $canonical=(($keys|ForEach-Object{"$_=$($values[$_])"})+($items|Sort-Object Source|ForEach-Object{"artifact=$($_.Source)|$($_.Destination)|$($_.Sha256)"}))-join "`n"; $canonical+="`n"; Assert-Condition($text -ceq $canonical) 'Sandbox installer plan is invalid.'; return $items
}

function Read-CanonicalSandboxInput([string]$Path) {
    $bytes = Read-SafeInputBytes $Path
    Assert-Condition ($bytes.Length -gt 0 -and $bytes.Length -le 1048576) 'Sandbox input manifest is invalid.'
    Assert-Condition (-not ($bytes | Where-Object { $_ -eq 13 -or $_ -gt 127 })) 'Sandbox input manifest is invalid.'
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    Assert-Condition ($text.EndsWith("`n") -and -not $text.StartsWith([char]0xEF)) 'Sandbox input manifest is invalid.'
    $lines = $text.Split("`n")
    $keys = @('schema', 'source-commit', 'release-version', 'release-sequence', 'published-at-utc', 'msi-product-version', 'msi-sha256', 'installer-plan-sha256', 'artifact-count')
    Assert-Condition ($lines.Count -ge 11 -and $lines[-1] -eq '') 'Sandbox input manifest is invalid.'
    $values = @{}
    for ($index = 0; $index -lt $keys.Count; $index++) {
        $prefix = $keys[$index] + '='
        Assert-Condition ($lines[$index].StartsWith($prefix, [StringComparison]::Ordinal)) 'Sandbox input manifest is invalid.'
        $values[$keys[$index]] = $lines[$index].Substring($prefix.Length)
    }
    $count = 0
    Assert-Condition ($values['schema'] -eq 'vantrel-sandbox-input-v1' -and [UInt32]::TryParse($values['artifact-count'], [ref]$count) -and $count -gt 0 -and $lines.Count -eq 10 + $count) 'Sandbox input manifest is invalid.'
    foreach ($name in @('msi-sha256', 'installer-plan-sha256')) { Assert-Condition ($values[$name] -match '^[0-9A-F]{64}$') 'Sandbox input manifest is invalid.' }
    Assert-Condition ($values['source-commit'] -match '^[0-9a-f]{40}$' -and (Test-CanonicalMsiVersion $values['msi-product-version'])) 'Sandbox input manifest is invalid.'
    Assert-Condition ((Test-CanonicalReleaseVersion $values['release-version']) -and (Test-CanonicalReleaseSequence $values['release-sequence']) -and (Test-CanonicalUtc $values['published-at-utc'])) 'Sandbox input manifest is invalid.'
    $artifacts = @()
    for ($index = 0; $index -lt $count; $index++) {
        $line = $lines[9 + $index]
        Assert-Condition ($line.StartsWith('artifact=', [StringComparison]::Ordinal)) 'Sandbox input manifest is invalid.'
        $parts = $line.Substring(9).Split('|')
    Assert-Condition ($parts.Count -eq 3) 'Sandbox input manifest is invalid.'
        Assert-Artifact $parts[0] $parts[1] $parts[2]
        $artifacts += [PSCustomObject]@{ Source = $parts[0]; Destination = $parts[1]; Sha256 = $parts[2] }
    }
    Assert-Condition (($artifacts.Source | Sort-Object -Unique).Count -eq $artifacts.Count) 'Sandbox input manifest is invalid.'
    $canonical=(($keys|ForEach-Object{"$_=$($values[$_])"})+($artifacts|Sort-Object Source|ForEach-Object{"artifact=$($_.Source)|$($_.Destination)|$($_.Sha256)"}))-join "`n"; $canonical+="`n"; Assert-Condition($text -ceq $canonical) 'Sandbox input manifest is invalid.'
    return [PSCustomObject]@{ Values = $values; Artifacts = $artifacts }
}

Assert-SafeInputRoot
$planBytes = Read-SafeInputBytes $planPath
$plan = Read-CanonicalPlan $planBytes
$manifest = Read-CanonicalSandboxInput $manifestPath
Assert-Condition ((Get-Hash $msiPath) -eq $manifest.Values['msi-sha256']) 'Sandbox MSI hash does not match.'
Assert-Condition ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($planBytes)) -eq $manifest.Values['installer-plan-sha256']) 'Sandbox installer plan hash does not match.'
Assert-Condition ($plan.Count -eq $manifest.Artifacts.Count) 'Sandbox artifact plan does not match.'
foreach ($artifact in $plan) {
    $match = @($manifest.Artifacts | Where-Object { $_.Source -ceq $artifact.Source })
    Assert-Condition ($match.Count -eq 1 -and $match[0].Destination -ceq $artifact.Destination -and $match[0].Sha256 -ceq $artifact.Sha256) 'Sandbox artifact plan does not match.'
}

& "$env:SystemRoot\System32\msiexec.exe" /i $msiPath /qn /norestart
Assert-Condition ($LASTEXITCODE -eq 0) 'Sandbox MSI installation failed.'

$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
foreach ($artifact in $plan) {
    $installed = Join-Path $programFiles $artifact.Destination.Substring('ProgramFiles64Folder\'.Length)
    Assert-Condition ((Get-Hash $installed) -eq $artifact.Sha256) 'Installed file validation failed.'
}

$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='VantrelSecurityService'"
Assert-Condition ($null -ne $service -and $service.StartName -eq 'NT AUTHORITY\LocalService' -and $service.StartMode -eq 'Manual' -and $service.State -eq 'Stopped') 'Installed service validation failed.'
$eventResource = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\VantrelSecurityService' -Name EventMessageFile).EventMessageFile
$expectedEventResource = Join-Path $programFiles 'Vantrel Security\Service\System.Diagnostics.EventLog.Messages.dll'
Assert-Condition ([Environment]::ExpandEnvironmentVariables($eventResource) -eq $expectedEventResource) 'Event Log resource validation failed.'

$allUsersShortcut = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)) 'Vantrel Security.lnk'
Assert-Condition (Test-Path -LiteralPath $allUsersShortcut -PathType Leaf) 'Start-menu shortcut validation failed.'
foreach ($desktop in @([Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop), [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonDesktopDirectory))) {
    Assert-Condition (-not (Test-Path -LiteralPath (Join-Path $desktop 'Vantrel Security.lnk') -PathType Leaf)) 'Desktop shortcut validation failed.'
}

foreach ($relative in @(
    'Vantrel Security\Updates',
    'Vantrel Security\Updates\Staged',
    'Vantrel Security\Updates\Transactions',
    'Vantrel Security\Updates\Backups',
    'Vantrel Security\Updates\.update-journal-v1.lock',
    'Vantrel Security\Updates\.offline-update-owner-v1.lock',
    'Vantrel Security\ReleasePolicy')) {
    Assert-Condition (-not (Test-Path -LiteralPath (Join-Path $env:ProgramData $relative))) 'ProgramData validation failed.'
}

Write-Host 'Windows Sandbox validation passed.'
