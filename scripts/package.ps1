param([ValidateSet('win-x64','osx-arm64','osx-x64','linux-x64','linux-arm64')][string]$Runtime='win-x64')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$output=Join-Path $root "artifacts/packages/$Runtime"
& dotnet publish (Join-Path $root 'FirewallReview.Desktop/FirewallReview.Desktop.csproj') -c Release -r $Runtime --self-contained true -o $output /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
if($LASTEXITCODE -ne 0){throw 'Packaging failed'}
Write-Host "Local package: $output. No release or deployment performed."
