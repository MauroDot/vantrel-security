[CmdletBinding()]
param([Parameter(Mandatory)][string]$PayloadDirectory)

$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $PayloadDirectory).Path
$tool = Join-Path $PSScriptRoot '..\tools\Vantrel.Security.ManifestTool\Vantrel.Security.ManifestTool.csproj'
dotnet run --project $tool --configuration Release -- verify --payload $target
if ($LASTEXITCODE) { throw 'Trusted manifest verification utility failed.' }
