param([string]$ExePath = "")
$ErrorActionPreference = "Stop"
$uiRoot = Split-Path -Parent $PSScriptRoot
if (-not $ExePath) { $ExePath = Join-Path $uiRoot "target\release\rbzk-prover-desktop.exe" }
if (-not (Test-Path -LiteralPath $ExePath)) { throw "Build the native desktop app first." }
# Use checked-in assets with the existing native telemetry engine. No prover
# control, compiler, browser service, or additional server is launched here.
$env:RBZK_PROVER_UI_DEV_WEB = Join-Path $uiRoot "web"
Start-Process -FilePath $ExePath -WorkingDirectory $uiRoot
