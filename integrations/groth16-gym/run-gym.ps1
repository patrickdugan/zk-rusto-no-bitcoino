# Groth16 gym: build, prove the SPV payment circuit, then header chains of
# N = 1, 2, 4, ... headers while the next run's predicted peak stays under
# -CapGB. Writes one JSON line per run to results\<host>-<date>.jsonl.
#
#   powershell -ExecutionPolicy Bypass -File run-gym.ps1 [-CapGB 12]
#
# Needs Rust (rustup). On Windows it builds with the MSVC toolchain.
param([double]$CapGB = 12, [int]$MaxHeaders = 256)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'groth16-gym-target' }
if (-not $env:RUSTUP_TOOLCHAIN) { $env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-msvc' }
cargo build --release
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
$bin = Join-Path $env:CARGO_TARGET_DIR 'release\groth16-gym.exe'

New-Item -ItemType Directory -Force results | Out-Null
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name.Trim()
$out = "results\$($env:COMPUTERNAME.ToLower())-$(Get-Date -Format yyyyMMdd-HHmm).jsonl"
function Append([string]$text) { [IO.File]::AppendAllText((Join-Path $PSScriptRoot $out), $text + "`n", (New-Object Text.UTF8Encoding $false)) }
$machine = @{ host = $env:COMPUTERNAME; ram_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1); cpu = $cpu; cap_gb = $CapGB } | ConvertTo-Json -Compress
Append "{`"machine`":$machine}"

function Run([string[]]$a) {
    $line = & $bin @a | Select-Object -Last 1
    if ($LASTEXITCODE -ne 0) { throw "groth16-gym $a failed" }
    Append $line
    Write-Host $line
    return ($line | ConvertFrom-Json)
}

$spv = Run @('spv')
$n = 1
while ($n -le $MaxHeaders) {
    $r = Run @('headers', "$n")
    # Peak memory grows about linearly with N; stop before the next doubling passes the cap.
    if ($r.peak_rss_mb * 2 / 1024 -gt $CapGB) { break }
    $n *= 2
}
Write-Host "results: $out"
