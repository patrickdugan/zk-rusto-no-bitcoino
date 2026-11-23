param(
    [string]$ShortcutName = "ZK Rusto no Bitcoino Prover.lnk",
    [string]$ExePath = "",
    [switch]$LiveAssets
)

$ErrorActionPreference = "Stop"

$ProverUiRoot = Split-Path -Parent $PSScriptRoot
$CandidateBins = @(
    (Join-Path $ProverUiRoot "releases\windows-x64\rbzk-prover-desktop.exe"),
    (Join-Path $ProverUiRoot "target\release\rbzk-prover-desktop.exe"),
    (Join-Path $ProverUiRoot "dist\rbzk-prover-desktop.exe")
)

if (-not $ExePath) {
    $ExePath = $CandidateBins | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $ExePath -or -not (Test-Path -LiteralPath $ExePath)) {
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
if ($LiveAssets) {
    $Shortcut.TargetPath = Join-Path $PSHOME "powershell.exe"
    if (-not (Test-Path -LiteralPath $Shortcut.TargetPath)) {
        $Shortcut.TargetPath = Join-Path $PSHOME "pwsh.exe"
    }
    $launcher = Join-Path $PSScriptRoot "launch-live-desktop.ps1"
    $Shortcut.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$launcher`" -ExePath `"$ExePath`""
} else {
    $Shortcut.Arguments = ""
}
$Shortcut.WorkingDirectory = Split-Path -Parent $ExePath
$Shortcut.IconLocation = "$IconPath,0"
$Shortcut.Description = "ZK Rusto no Bitcoino - Native Rust Prover & Recursive Shard Desktop Console"
$Shortcut.WindowStyle = 1
$Shortcut.Save()

Write-Output "Created Desktop shortcut: $ShortcutPath -> $ExePath"
