param(
    [string]$ShortcutName = "ZK Rusto no Bitcoino Prover.lnk"
)

$ErrorActionPreference = "Stop"

$ProverUiRoot = Split-Path -Parent $PSScriptRoot
$CandidateBins = @(
    (Join-Path $ProverUiRoot "releases\windows-x64\rbzk-prover-desktop.exe"),
    (Join-Path $ProverUiRoot "target\release\rbzk-prover-desktop.exe"),
    (Join-Path $ProverUiRoot "dist\rbzk-prover-desktop.exe")
)

$ExePath = $CandidateBins | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $ExePath) {
    throw "rbzk-prover-desktop.exe not found under releases\windows-x64, target\release, or dist."
}

$IconPath = Join-Path $ProverUiRoot "assets\icon.ico"
if (-not (Test-Path $IconPath)) {
    $IconPath = $ExePath
}

$DesktopDir = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopDir $ShortcutName

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $ExePath
$Shortcut.WorkingDirectory = Split-Path -Parent $ExePath
$Shortcut.IconLocation = "$IconPath,0"
$Shortcut.Description = "ZK Rusto no Bitcoino - Native Rust Prover & Recursive Shard Desktop Console"
$Shortcut.WindowStyle = 1
$Shortcut.Save()

Write-Output "Created Desktop shortcut: $ShortcutPath -> $ExePath"
