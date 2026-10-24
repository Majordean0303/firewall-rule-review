param([ValidateSet('Debug','Release')][string]$Configuration='Release')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'test-core.ps1') -Configuration $Configuration
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
foreach($project in @('FirewallReview.Cli','FirewallReview.Desktop')){
 $log=Join-Path $root "artifacts/$project-build.log"
 & dotnet build (Join-Path $root "$project/$project.csproj") -c $Configuration --nologo *> $log
 if($LASTEXITCODE -ne 0){Write-Host "Build FAILED: $project. Log: $log";exit 1}
 Write-Host "Build PASSED: $project"
}

& (Join-Path $PSScriptRoot 'test-ui.ps1') -Configuration $Configuration
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
