param([string]$ExePath = "")
$ErrorActionPreference = "Stop"
$uiRoot = Split-Path -Parent $PSScriptRoot
$target = Join-Path $uiRoot "target"
if (-not $ExePath) {
    $ExePath = Join-Path $target "release\rbzk-prover-desktop-live.exe"
    if (-not (Test-Path -LiteralPath $ExePath)) {
        $ExePath = Join-Path $target "release\rbzk-prover-desktop.exe"
    }
}
if (-not (Test-Path -LiteralPath $ExePath)) { throw "Build the native desktop app first." }

$settingsFile = Join-Path $target "live-telemetry.json"
if (Test-Path -LiteralPath $settingsFile) {
    $settings = Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json
    if (-not $env:RBZK_HYPERSTACK_ARK_STATE_JSON -and $settings.arkCloudState) {
        $env:RBZK_HYPERSTACK_ARK_STATE_JSON = $settings.arkCloudState
    }
    if (-not $env:RBZK_HYPERSTACK_BENCHMARK_JSON -and $settings.hyperstackBenchmark) {
        $env:RBZK_HYPERSTACK_BENCHMARK_JSON = $settings.hyperstackBenchmark
    }
}
$env:RBZK_PROVER_UI_DEV_WEB = Join-Path $uiRoot "web"
Start-Process -FilePath $ExePath -WorkingDirectory $uiRoot
