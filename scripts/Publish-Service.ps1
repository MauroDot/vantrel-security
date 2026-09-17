[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $repoRoot 'src\Vantrel.Security.Service\Vantrel.Security.Service.csproj'
$publishRoot = Join-Path $repoRoot 'artifacts\service\win-x64'
$buildId = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
$outputDirectory = Join-Path $publishRoot $buildId
$latestPath = Join-Path $publishRoot 'latest-path.txt'

Write-Host "Publishing VantrelSecurityService to $outputDirectory"
& dotnet publish $project --configuration $Configuration --runtime win-x64 --self-contained false --output $outputDirectory
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE." }

$executable = Join-Path $outputDirectory 'Vantrel.Security.Service.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Published service executable was not found at $executable."
}

New-Item -ItemType Directory -Path $publishRoot -Force | Out-Null
$relativePath = Join-Path 'artifacts\service\win-x64' $buildId
[System.IO.File]::WriteAllText($latestPath, $relativePath)
$hash = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
Write-Host "Publish succeeded. Executable SHA-256: $hash"
Write-Host "Latest publish location: $outputDirectory"
