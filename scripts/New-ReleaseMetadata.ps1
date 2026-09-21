[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PayloadDirectory,
    [Parameter(Mandatory)][string]$PrivateKeyPk8Path,
    [Parameter(Mandatory)][UInt64]$ReleaseSequence,
    [Parameter(Mandatory)][string]$DisplayVersion,
    [Parameter(Mandatory)][string]$PublishedAtUtc
)

$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $PayloadDirectory).Path
$private = (Resolve-Path -LiteralPath $PrivateKeyPk8Path).Path
$tool = Join-Path $PSScriptRoot '..\tools\Vantrel.Security.ManifestTool\Vantrel.Security.ManifestTool.csproj'
dotnet run --project $tool --configuration Release -- sign-release-metadata --payload $target --private-key $private --release-sequence $ReleaseSequence --display-version $DisplayVersion --published-at-utc $PublishedAtUtc
if ($LASTEXITCODE) { throw 'Release metadata signing utility failed.' }