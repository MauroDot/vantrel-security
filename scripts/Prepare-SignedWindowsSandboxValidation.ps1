[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$ReleaseLayoutRoot,
    [Parameter(Mandatory = $true)] [string]$InstallerPlanPath,
    [Parameter(Mandatory = $true)] [string]$SignedMsiPath,
    [Parameter(Mandatory = $true)] [string]$DistributionRecordPath,
    [Parameter(Mandatory = $true)] [string]$SignedMsiSha256,
    [Parameter(Mandatory = $true)] [string]$InstallerPlanSha256,
    [Parameter(Mandatory = $true)] [string]$ReleaseRecordSha256,
    [Parameter(Mandatory = $true)] [string]$DistributionRecordSha256,
    [Parameter(Mandatory = $true)] [string]$SandboxOutputRoot
)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $repo 'tools\Vantrel.Security.InstallerPreflight\Vantrel.Security.InstallerPreflight.csproj'
$validator = Join-Path $repo 'sandbox\Validate-VantrelSignedCandidateSandbox.ps1'
$template = Join-Path $repo 'sandbox\Vantrel.Security.SignedReleaseValidation.wsb'
function Assert-RegularSource([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Signed Sandbox tooling is unavailable.' }
    $leaf = Get-Item -LiteralPath $Path -Force
    if (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Signed Sandbox tooling is unavailable.' }
    for ($parent = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($Path)); $null -ne $parent; $parent = $parent.Parent) {
        if (-not $parent.Exists -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Signed Sandbox tooling is unavailable.' }
    }
}
function Write-SignedSandboxConfiguration(
    [string]$TemplatePath,
    [string]$InputRoot,
    [string]$DistributionRecordSha256,
    [string]$OutputPath
) {
    if ($DistributionRecordSha256 -cnotmatch '^[0-9A-F]{64}$') {
        throw 'Signed Sandbox configuration input is invalid.'
    }
    [xml]$wsb = Get-Content -Raw -LiteralPath $TemplatePath
    $mapped = $wsb.Configuration.MappedFolders.MappedFolder
    if (@($mapped).Count -ne 1 -or $mapped.ReadOnly -cne 'true' -or $mapped.SandboxFolder -cne 'C:\VantrelInput' -or
        $mapped.HostFolder -cne '__VANTREL_SIGNED_SANDBOX_INPUT__' -or
        $wsb.Configuration.LogonCommand.Command -cnotmatch '__VANTREL_DISTRIBUTION_HASH__') {
        throw 'Signed Sandbox configuration is invalid.'
    }
    $mapped.HostFolder = $InputRoot
    $wsb.Configuration.LogonCommand.Command = $wsb.Configuration.LogonCommand.Command.Replace(
        '__VANTREL_DISTRIBUTION_HASH__', $DistributionRecordSha256)
    if (Test-Path -LiteralPath $OutputPath) { throw 'Signed Sandbox configuration output is unavailable.' }
    $settings = [Xml.XmlWriterSettings]::new()
    $settings.Encoding = [Text.UTF8Encoding]::new($false)
    $settings.Indent = $true
    try {
        $writer = [Xml.XmlWriter]::Create($OutputPath, $settings)
        try { $wsb.Save($writer) } finally { $writer.Dispose() }
    } catch { throw 'Signed Sandbox configuration output is unavailable.' }
}
$hashes = @($SignedMsiSha256, $InstallerPlanSha256, $ReleaseRecordSha256, $DistributionRecordSha256)
if (@($hashes | Where-Object { $_ -cnotmatch '^[0-9A-F]{64}$' }).Count -ne 0) {
    throw 'Signed Sandbox preparation inputs are invalid.'
}
Assert-RegularSource $validator
Assert-RegularSource $template
$output = [IO.Path]::GetFullPath($SandboxOutputRoot)
if ($output -cne $SandboxOutputRoot -or (Test-Path -LiteralPath $output)) { throw 'Signed Sandbox output must be new.' }
$repoPrefix = $repo.TrimEnd([char]'\') + [IO.Path]::DirectorySeparatorChar
if ($output -ceq $repo -or $output.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Signed Sandbox output must be outside the source checkout.'
}

$arguments = @(
    'run', '--project', $project, '--configuration', 'Release', '--no-build', '--no-restore', '--',
    'prepare-signed-sandbox-input', '--output-root', $ReleaseLayoutRoot, '--installer-plan', $InstallerPlanPath,
    '--signed-msi', $SignedMsiPath, '--distribution-record', $DistributionRecordPath,
    '--signed-msi-sha256', $SignedMsiSha256, '--installer-plan-sha256', $InstallerPlanSha256,
    '--release-record-sha256', $ReleaseRecordSha256, '--distribution-record-sha256', $DistributionRecordSha256,
    '--sandbox-output', $output
)
& dotnet @arguments
if ($LASTEXITCODE -ne 0) { throw 'Signed Sandbox preparation failed.' }

$inputRoot = Join-Path $output 'input'
$validatorOutput = Join-Path $inputRoot 'Validate-VantrelSignedCandidateSandbox.ps1'
[IO.File]::Copy($validator, $validatorOutput, $false)
$validateArguments = @('run', '--project', $project, '--configuration', 'Release', '--no-build', '--no-restore', '--',
    'validate-signed-sandbox-input', '--input-root', $inputRoot,
    '--distribution-record-sha256', $DistributionRecordSha256)
& dotnet @validateArguments
if ($LASTEXITCODE -ne 0) { throw 'Signed Sandbox input validation failed.' }
$wsbPath = Join-Path $output 'Vantrel.Security.SignedReleaseValidation.wsb'
Write-SignedSandboxConfiguration $template $inputRoot $DistributionRecordSha256 $wsbPath
Write-Host 'Signed Sandbox input prepared for a separately approved launch.'
