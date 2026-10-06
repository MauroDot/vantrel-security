[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$SourceCheckout,
    [Parameter(Mandatory = $true)] [string]$SourceCommit,
    [Parameter(Mandatory = $true)] [string]$ReleaseLayoutRoot,
    [Parameter(Mandatory = $true)] [string]$InstallerPlanPath,
    [Parameter(Mandatory = $true)] [string]$SandboxInputRoot,
    [Parameter(Mandatory = $true)] [string]$ReleaseVersion,
    [Parameter(Mandatory = $true)] [string]$ReleaseSequence,
    [Parameter(Mandatory = $true)] [string]$PublishedAtUtc,
    [Parameter(Mandatory = $true)] [string]$MsiProductVersion
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$checkout = [IO.Path]::GetFullPath($SourceCheckout)
$layout = [IO.Path]::GetFullPath($ReleaseLayoutRoot)
$input = [IO.Path]::GetFullPath($SandboxInputRoot)
$plan = [IO.Path]::GetFullPath($InstallerPlanPath)
$preflightProject = Join-Path $repoRoot 'tools\Vantrel.Security.InstallerPreflight\Vantrel.Security.InstallerPreflight.csproj'
$installerProject = Join-Path $repoRoot 'installer\Vantrel.Security.Installer\Vantrel.Security.Installer.wixproj'
$sandboxValidator = Join-Path $repoRoot 'sandbox\Validate-VantrelReleaseSandbox.ps1'
$sandboxTemplate = Join-Path $repoRoot 'sandbox\Vantrel.Security.ReleaseValidation.wsb'

function Invoke-Dotnet([string[]]$Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Build-time validation failed.' }
}

function Assert-RegularDirectory([string]$Path, [string]$Message) {
    $full = [IO.Path]::GetFullPath($Path)
    for ($current = [IO.DirectoryInfo]$full; $null -ne $current; $current = $current.Parent) {
        if (-not $current.Exists -or (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw $Message }
    }
    return $full
}

function Assert-Outside([string]$Candidate, [string]$Root, [string]$Message) {
    $candidateFull = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Candidate))
    $rootFull = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Root))
    if ($candidateFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or $candidateFull.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw $Message }
}

function Assert-EmptyOutput([string]$Path) {
    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent)) { throw 'Sandbox input root is unavailable.' }
    Assert-RegularDirectory $parent 'Sandbox input root is unavailable.' | Out-Null
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not ($item -is [IO.DirectoryInfo]) -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-ChildItem -LiteralPath $Path -Force | Measure-Object).Count -ne 0) { throw 'Sandbox input root must be empty.' }
    }
    else { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Assert-CleanDetachedCheckout {
    if ($checkout -cne $repoRoot -or $SourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'Sandbox preparation requires a separate clean detached checkout.' }
    $head = ((& git -C $repoRoot rev-parse --verify 'HEAD^{commit}' 2>$null) -join '').Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cne $SourceCommit) { throw 'Sandbox preparation requires a separate clean detached checkout.' }
    & git -C $repoRoot symbolic-ref -q HEAD 2>$null
    if ($LASTEXITCODE -eq 0) { throw 'Sandbox preparation requires a separate clean detached checkout.' }
    & git -C $repoRoot cat-file -e "$SourceCommit^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Sandbox preparation requires a separate clean detached checkout.' }
    $status = (& git -C $repoRoot status --porcelain=v1 --untracked-files=all --ignored=matching 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrEmpty(($status -join "`n"))) { throw 'Sandbox preparation requires a separate clean detached checkout.' }
}

Assert-CleanDetachedCheckout
Assert-RegularDirectory $layout 'Validated release layout is unavailable.' | Out-Null
Assert-RegularDirectory (Split-Path -Parent $plan) 'Canonical installer plan is unavailable.' | Out-Null
if (-not (Test-Path -LiteralPath $plan -PathType Leaf) -or ((Get-Item -LiteralPath $plan -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Canonical installer plan is unavailable.' }
if (-not (Test-Path -LiteralPath $sandboxValidator -PathType Leaf) -or -not (Test-Path -LiteralPath $sandboxTemplate -PathType Leaf)) { throw 'Sandbox validation tooling is unavailable.' }
Assert-Outside $input $layout 'Sandbox input must be outside the release layout.'
Assert-Outside $input $repoRoot 'Sandbox input must be outside the source checkout.'
Assert-EmptyOutput $input

$build = Join-Path $input '.build'
$wixAuthoring = Join-Path $build 'Vantrel.Security.FirstInstall.wxs'
$msi = Join-Path $build 'VantrelSecurity.msi'
$mappedMsi = Join-Path $input 'VantrelSecurity.msi'
$mappedPlan = Join-Path $input 'vantrel-installer-input-v1.txt'
$mappedManifest = Join-Path $input 'vantrel-sandbox-input-v1.txt'
$mappedValidator = Join-Path $input 'Validate-VantrelReleaseSandbox.ps1'

try {
    Invoke-Dotnet @('restore', $installerProject, '--locked-mode')
    Invoke-Dotnet @('run', '--project', $preflightProject, '--configuration', 'Release', '--', 'emit-wix', '--output-root', $layout, '--installer-plan', $plan, '--wix-output', $wixAuthoring)
    Invoke-Dotnet @('build', $installerProject, '--configuration', 'Release', '--no-restore', '-t:Rebuild', "/p:InstallerInputPlan=$plan", "/p:ReleaseLayoutRoot=$layout", "/p:OutputPath=$build\")
    if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { throw 'Unsigned MSI build output is unavailable.' }
    Copy-Item -LiteralPath $msi -Destination $mappedMsi -ErrorAction Stop
    Copy-Item -LiteralPath $plan -Destination $mappedPlan -ErrorAction Stop
    Copy-Item -LiteralPath $sandboxValidator -Destination $mappedValidator -ErrorAction Stop
    Invoke-Dotnet @('run', '--project', $preflightProject, '--configuration', 'Release', '--no-restore', '--', 'write-sandbox-input', '--installer-plan', $mappedPlan, '--msi', $mappedMsi, '--output', $mappedManifest, '--source-commit', $SourceCommit, '--release-version', $ReleaseVersion, '--release-sequence', $ReleaseSequence, '--published-at-utc', $PublishedAtUtc, '--msi-product-version', $MsiProductVersion)
    $wsb = (Get-Content -Raw -LiteralPath $sandboxTemplate).Replace('__VANTREL_SANDBOX_INPUT__', [Security.SecurityElement]::Escape($input))
    $wsbPath = Join-Path (Split-Path -Parent $input) 'Vantrel.Security.ReleaseValidation.wsb'
    if (Test-Path -LiteralPath $wsbPath) { throw 'Sandbox configuration output is unavailable.' }
    [IO.File]::WriteAllText($wsbPath, $wsb, [Text.UTF8Encoding]::new($false))
}
finally {
    if (Test-Path -LiteralPath $build) {
        $item = Get-Item -LiteralPath $build -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { Remove-Item -LiteralPath $build -Recurse -Force -ErrorAction Stop }
    }
}

Write-Host 'Sandbox input is prepared. Manually launch the generated .wsb file only after separately approved signing and release-record work.'
