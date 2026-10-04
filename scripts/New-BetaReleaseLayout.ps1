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
$cleanCheckoutFailure = 'Beta release requires a clean immutable checkout.'

function Invoke-Dotnet([string[]]$Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet command failed with exit code $LASTEXITCODE." }
}

function Assert-CleanImmutableCheckout {
    if ([string]::IsNullOrWhiteSpace($SourceCommit) -or $SourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw $cleanCheckoutFailure }
    $head = ((& git -C $repoRoot rev-parse --verify 'HEAD^{commit}' 2>$null) -join '').Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cnotmatch '^[0-9a-f]{40}$' -or $head -cne $SourceCommit) { throw $cleanCheckoutFailure }
    & git -C $repoRoot cat-file -e "$SourceCommit^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) { throw $cleanCheckoutFailure }
    $status = (& git -C $repoRoot status --porcelain=v1 --untracked-files=all --ignored=matching 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrEmpty(($status -join "`n"))) { throw $cleanCheckoutFailure }
}

function Get-RequiredSdkVersion {
    try {
        $settings = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'global.json') | ConvertFrom-Json
        $required = [string]$settings.sdk.version
    }
    catch { throw 'Beta release requires the repository SDK.' }
    if ($required -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Beta release requires the repository SDK.' }
    return $required
}

function Assert-RequiredSdk([string]$RequiredSdk) {
    $actual = (& dotnet --version 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $actual -cne $RequiredSdk) { throw 'Beta release requires the repository SDK.' }
    return $actual
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
    Assert-CleanImmutableCheckout
    Assert-EmptyOutputRoot
    $notes = (Resolve-Path -LiteralPath $ReleaseNotesPath).Path
    if (-not (Test-Path -LiteralPath $notes -PathType Leaf)) { throw 'Release notes must be a regular file.' }
    $notesHash = (Get-FileHash -LiteralPath $notes -Algorithm SHA256).Hash
    $sdk = Assert-RequiredSdk (Get-RequiredSdkVersion)
    $releaseProperties = @("-p:VantrelReleaseVersion=$ReleaseVersion", "-p:VantrelSourceCommit=$SourceCommit")

    Invoke-Dotnet @('restore', (Join-Path $repoRoot 'Vantrel.Security.sln'), '--runtime', 'win-x64', '--locked-mode')
    Copy-Item -LiteralPath $notes -Destination (Join-Path $output 'release-notes.md') -ErrorAction Stop
    Invoke-Dotnet @('run', '--project', $layoutTool, '--configuration', 'Release', '--no-restore', '--', 'write-descriptor', '--output', (Join-Path $output 'beta-release-descriptor-v1.txt'), '--source-commit', $SourceCommit, '--release-version', $ReleaseVersion, '--release-sequence', $ReleaseSequence.ToString([Globalization.CultureInfo]::InvariantCulture), '--published-at-utc', $PublishedAtUtc, '--configuration', 'Release', '--runtime', 'win-x64', '--sdk-version', $sdk, '--release-notes-sha256', $notesHash)
    Invoke-Dotnet (@('build', (Join-Path $repoRoot 'Vantrel.Security.sln'), '--configuration', 'Release', '--no-restore') + $releaseProperties)
    Invoke-Dotnet (@('build', $manifestTool, '--configuration', 'Release', '--no-restore') + $releaseProperties)
    Invoke-Dotnet (@('build', $layoutTool, '--configuration', 'Release', '--no-restore') + $releaseProperties)
    $servicePublish = Join-Path $output '.service-publish'
    try {
        Invoke-Dotnet (@('publish', (Join-Path $repoRoot 'src\Vantrel.Security.Service\Vantrel.Security.Service.csproj'), '--configuration', 'Release', '--runtime', 'win-x64', '--self-contained', 'false', '--no-restore', '--output', $servicePublish) + $releaseProperties)
        Invoke-Dotnet @('run', '--project', $layoutTool, '--configuration', 'Release', '--no-build', '--no-restore', '--', 'project-service-payload', '--source', $servicePublish, '--destination', (Join-Path $output 'service'))
    }
    finally { Remove-SafeTemporaryDirectory $servicePublish }
    Invoke-Dotnet (@('publish', (Join-Path $repoRoot 'src\Vantrel.Security.Desktop\Vantrel.Security.Desktop.csproj'), '--configuration', 'Release', '--runtime', 'win-x64', '--self-contained', 'false', '--no-restore', '--output', (Join-Path $output 'desktop')) + $releaseProperties)
    Invoke-Dotnet (@('publish', (Join-Path $repoRoot 'tools\Vantrel.Security.OfflineUpdateTool\Vantrel.Security.OfflineUpdateTool.csproj'), '--configuration', 'Release', '--runtime', 'win-x64', '--self-contained', 'false', '--output', (Join-Path $output 'offline-update-tool')) + $releaseProperties)
    Write-Host 'Layout prepared. Complete external Authenticode signing, then create and verify the fixed service manifest and release metadata before Record.'
}
else {
    if (-not (Test-Path -LiteralPath $output -PathType Container)) { throw 'Release output root is unavailable.' }
    Invoke-Dotnet @('run', '--project', $layoutTool, '--configuration', 'Release', '--no-build', '--no-restore', '--', 'record', '--output-root', $output)
    Write-Host 'Validated beta release record written.'
}