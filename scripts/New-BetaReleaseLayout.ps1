[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Record')]
    [string]$Phase,
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,
    [string]$SourceCommit,
    [string]$ReleaseVersion,
    [UInt64]$ReleaseSequence,
    [string]$PublishedAtUtc,
    [string]$ReleaseNotesPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$layoutTool = Join-Path $repoRoot 'tools\Vantrel.Security.ReleaseLayoutTool\Vantrel.Security.ReleaseLayoutTool.csproj'
$manifestTool = Join-Path $repoRoot 'tools\Vantrel.Security.ManifestTool\Vantrel.Security.ManifestTool.csproj'
$output = [IO.Path]::GetFullPath($OutputRoot)

function Invoke-Dotnet([string[]]$Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet command failed with exit code $LASTEXITCODE." }
}

function Remove-SafeTemporaryDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not ($item -is [IO.DirectoryInfo]) -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Release temporary directory is unsafe.' }
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
}
function Assert-EmptyOutputRoot {
    $ancestor = [IO.DirectoryInfo]$output
    while ($null -ne $ancestor) {
        if ($ancestor.Exists -and (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Release output root cannot be redirected.' }
        $ancestor = $ancestor.Parent
    }
    if (Test-Path -LiteralPath $output) {
        $item = Get-Item -LiteralPath $output -Force
        if (-not ($item -is [IO.DirectoryInfo])) { throw 'Release output root must be a directory.' }
        if ((Get-ChildItem -LiteralPath $output -Force | Measure-Object).Count -ne 0) { throw 'Release output root must be empty.' }
    }
    else { New-Item -ItemType Directory -Path $output -Force | Out-Null }
}

if ($Phase -eq 'Prepare') {
    foreach ($value in @($SourceCommit, $ReleaseVersion, $PublishedAtUtc, $ReleaseNotesPath)) {
        if ([string]::IsNullOrWhiteSpace($value)) { throw 'Prepare requires source commit, release version, publication time, and release notes.' }
    }
    Assert-EmptyOutputRoot
    $head = (& git -C $repoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cne $SourceCommit) { throw 'Source commit must equal the checked-out immutable HEAD.' }
    & git -C $repoRoot diff --quiet HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Prepare requires no tracked source changes.' }
    $notes = (Resolve-Path -LiteralPath $ReleaseNotesPath).Path
    if (-not (Test-Path -LiteralPath $notes -PathType Leaf)) { throw 'Release notes must be a regular file.' }
    $notesHash = (Get-FileHash -LiteralPath $notes -Algorithm SHA256).Hash
    $sdk = (& dotnet --version).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'dotnet SDK version could not be read.' }

    Invoke-Dotnet @('build', (Join-Path $repoRoot 'Vantrel.Security.sln'), '--configuration', 'Release', '--no-restore')
    Invoke-Dotnet @('build', $manifestTool, '--configuration', 'Release', '--no-restore')
    Invoke-Dotnet @('build', $layoutTool, '--configuration', 'Release', '--no-restore')
    $servicePublish = Join-Path $output '.service-publish'
    try {
        Invoke-Dotnet @('publish', (Join-Path $repoRoot 'src\Vantrel.Security.Service\Vantrel.Security.Service.csproj'), '--configuration', 'Release', '--runtime', 'win-x64', '--self-contained', 'false', '--no-restore', '--output', $servicePublish)
        Invoke-Dotnet @('run', '--project', $layoutTool, '--configuration', 'Release', '--no-build', '--', 'project-service-payload', '--source', $servicePublish, '--destination', (Join-Path $output 'service'))
    }
    finally { Remove-SafeTemporaryDirectory $servicePublish }
    Invoke-Dotnet @('publish', (Join-Path $repoRoot 'src\Vantrel.Security.Desktop\Vantrel.Security.Desktop.csproj'), '--configuration', 'Release', '--runtime', 'win-x64', '--self-contained', 'false', '--no-restore', '--output', (Join-Path $output 'desktop'))
    Invoke-Dotnet @('publish', (Join-Path $repoRoot 'tools\Vantrel.Security.OfflineUpdateTool\Vantrel.Security.OfflineUpdateTool.csproj'), '--configuration', 'Release', '--runtime', 'win-x64', '--self-contained', 'false', '--no-restore', '--output', (Join-Path $output 'offline-update-tool'))
    Copy-Item -LiteralPath $notes -Destination (Join-Path $output 'release-notes.md') -ErrorAction Stop
    Invoke-Dotnet @('run', '--project', $layoutTool, '--configuration', 'Release', '--no-build', '--', 'write-descriptor', '--output', (Join-Path $output 'beta-release-descriptor-v1.txt'), '--source-commit', $SourceCommit, '--release-version', $ReleaseVersion, '--release-sequence', $ReleaseSequence.ToString([Globalization.CultureInfo]::InvariantCulture), '--published-at-utc', $PublishedAtUtc, '--configuration', 'Release', '--runtime', 'win-x64', '--sdk-version', $sdk, '--release-notes-sha256', $notesHash)
    Write-Host 'Layout prepared. Complete external Authenticode signing, then create and verify the fixed service manifest and release metadata before Record.'
}
else {
    if (-not (Test-Path -LiteralPath $output -PathType Container)) { throw 'Release output root is unavailable.' }
    Invoke-Dotnet @('run', '--project', $layoutTool, '--configuration', 'Release', '--no-restore', '--', 'record', '--output-root', $output)
    Write-Host 'Validated beta release record written.'
}
