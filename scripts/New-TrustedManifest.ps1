[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PayloadDirectory,
    [Parameter(Mandatory)][string]$PrivateKeyPk8Path
)

$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $PayloadDirectory).Path
$private = (Resolve-Path -LiteralPath $PrivateKeyPk8Path).Path
$tool = Join-Path $PSScriptRoot '..\tools\Vantrel.Security.ManifestTool\Vantrel.Security.ManifestTool.csproj'
dotnet run --project $tool --configuration Release -- sign --payload $target --private-key $private
if ($LASTEXITCODE) { throw 'Trusted manifest signing utility failed.' }
