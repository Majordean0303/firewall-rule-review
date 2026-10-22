<#
.SYNOPSIS
    Runs offline core tests and prints only a short result summary.
.EXAMPLE
    ./scripts/test-core.ps1 -Filter 'FullyQualifiedName~Cancellation' -NoRestore
#>
param(
    [string]$Filter,
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$NoRestore,
    [switch]$NoBuild,
    [string]$ResultsDirectory
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'FirewallReview.UiTests/FirewallReview.UiTests.csproj'
if (-not $ResultsDirectory) { $ResultsDirectory = Join-Path $root 'artifacts/ui-tests' }
$ResultsDirectory = [System.IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
$timer = [System.Diagnostics.Stopwatch]::StartNew()
$phase = 'restore'

try {
    if (-not $NoRestore) {
        & dotnet restore $project --nologo *> (Join-Path $ResultsDirectory 'restore.log')
        if ($LASTEXITCODE -ne 0) { throw 'Restore failed.' }
    }
    $phase = 'build'
    if (-not $NoBuild) {
        & dotnet build $project -c $Configuration --no-restore --nologo *> (Join-Path $ResultsDirectory 'build.log')
        if ($LASTEXITCODE -ne 0) { throw 'Core/test build failed.' }
    }
    $phase = 'test'
    $trxPath = Join-Path $ResultsDirectory 'core.trx'
    # A stale successful result must never conceal a failed invocation or empty filter.
    if (Test-Path $trxPath) { Remove-Item $trxPath }
    $arguments = @('test', $project, '-c', $Configuration, '--no-build', '--no-restore',
        '--nologo', '--verbosity', 'quiet', '--logger', 'trx;LogFileName=core.trx',
        '--results-directory', $ResultsDirectory)
    if ($Filter) { $arguments += @('--filter', $Filter) }
    & dotnet @arguments *> (Join-Path $ResultsDirectory 'test.log')
    $testExit = $LASTEXITCODE
    if (-not (Test-Path $trxPath)) { throw 'No TRX results were produced.' }
    [xml]$trx = Get-Content $trxPath -Raw
    $counts = $trx.TestRun.ResultSummary.Counters
    $total = [int]$counts.total
    $passed = [int]$counts.passed
    $failed = [int]$counts.failed
    $skipped = $total - [int]$counts.executed
    Write-Host "UI smoke tests: $passed passed, $failed failed, $skipped skipped ($total total; $($timer.Elapsed.TotalSeconds.ToString('F1'))s)."
    foreach ($failure in @($trx.TestRun.Results.UnitTestResult | Where-Object { $_.outcome -eq 'Failed' })) {
        Write-Host "FAIL: $($failure.testName)"
    }
    if ($total -eq 0 -or [int]$counts.executed -eq 0) { throw 'Zero tests executed; check the filter and test discovery.' }
    if ($testExit -ne 0 -or $failed -gt 0 -or [int]$counts.errors -gt 0 -or [int]$counts.aborted -gt 0) { throw 'Core tests failed.' }
    Write-Host "Artifacts: $ResultsDirectory"
    exit 0
}
catch {
    Write-Host "UI validation FAILED ($phase): $($_.Exception.Message)"
    Write-Host "Artifacts: $ResultsDirectory"
    exit 1
}
