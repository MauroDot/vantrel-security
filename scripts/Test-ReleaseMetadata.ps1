[CmdletBinding()]
param([Parameter(Mandatory)][string]$PayloadDirectory)

$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $PayloadDirectory).Path
$tool = Join-Path $PSScriptRoot '..\tools\Vantrel.Security.ManifestTool\Vantrel.Security.ManifestTool.csproj'
dotnet run --project $tool --configuration Release -- verify-release-metadata --payload $target
if ($LASTEXITCODE) { throw 'Release metadata verification utility failed.' }