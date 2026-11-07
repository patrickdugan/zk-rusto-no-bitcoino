# Windows 15 GB DDR4: 128 Bitcoin headers in four verified 32-header batches.
# Builds the native BN254 Groth16 gym once, proves exactly one batch, resumes
# for the remaining batches, and verifies the entire bundle.
#
# powershell -ExecutionPolicy Bypass -File integrations/groth16-gym/run-checkpoint-ddr4.ps1
# Additional options: -CapMB 13000 -ChunkSize 32 -StartHeight 959617 -EndHeight 959744
#
# A 32-header batch peaks at about 10.1 GB. A 64-header batch needs about
# 20.6 GiB committed, so it does not fit a 13 GB cap (see CHECKPOINTS.md).
param(
    [int]$CapMB = 13000,
    [ValidateRange(1,64)][int]$ChunkSize = 32,
    [int]$StartHeight = 959617,
    [int]$EndHeight = 959744,
    [string]$OutputDir = ''
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'groth16-gym-target'
}
if (-not $env:RUSTUP_TOOLCHAIN) {
    $env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-msvc'
}
if ($CapMB -lt 1024) { throw 'CapMB must be >= 1024' }
if ($StartHeight -gt $EndHeight) { throw 'start height exceeds end height' }
if (([math]::Floor($StartHeight / 2016)) -ne ([math]::Floor($EndHeight / 2016))) {
    throw 'The selected range must fit in one difficulty epoch'
}
if (-not $OutputDir) { $OutputDir = Join-Path $PSScriptRoot ".proofs\ddr4-$ChunkSize" }
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force $OutputDir | Out-Null
$log = Join-Path $OutputDir 'ddr4-benchmark.jsonl'
$bin = Join-Path $env:CARGO_TARGET_DIR 'release\checkpoint_headers.exe'
Write-Host "Compiling checkpoint_headers to $bin"
cargo build --release --bin checkpoint_headers
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
if (-not (Test-Path $bin)) { throw 'binary not found after build' }

$os = Get-CimInstance Win32_OperatingSystem
$total = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
$free = [math]::Round($os.FreePhysicalMemory / 1024)
Write-Host "Physical RAM: $total MB, available at launch: $free MB, process cap: $CapMB MB"
if ($free -lt ($CapMB + 256)) {
    Write-Warning 'Available memory is less than the configured process guard plus 256 MB. Close memory-heavy programs.'
}
function Record([object]$entry) {
    $line = ConvertTo-Json $entry -Compress -Depth 6
    [IO.File]::AppendAllText($log, $line + "`n", (New-Object Text.UTF8Encoding $false))
    Write-Host $line
}
Record @{ kind = 'host'; time = (Get-Date).ToString('o'); ram_mb = $total; available_mb = $free; cap_mb = $CapMB; chunk_size = $ChunkSize; start = $StartHeight; end = $EndHeight }

function Run-Guarded([string]$phase, [string[]]$arguments) {
    $stdout = Join-Path $OutputDir "$phase.stdout.log"
    $stderr = Join-Path $OutputDir "$phase.stderr.log"
    if (Test-Path $stdout) { Remove-Item $stdout -Force }
    if (Test-Path $stderr) { Remove-Item $stderr -Force }
    $start = Get-Date
    $process = Start-Process -FilePath $bin -ArgumentList $arguments -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    # Cache the process handle now; otherwise Windows PowerShell reports a null ExitCode after exit.
    $null = $process.Handle
    $peak = 0L
    $killed = $false
    try {
        while (-not $process.HasExited) {
            $process.Refresh()
            try {
                $rss = [long]$process.PeakWorkingSet64
                if ($rss -gt $peak) { $peak = $rss }
                if ($rss -gt [long]$CapMB * 1MB) {
                    $killed = $true
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    break
                }
            } catch [System.InvalidOperationException] {
                break
            }
            Start-Sleep -Milliseconds 250
        }
        $process.WaitForExit()
        $process.Refresh()
        try {
            $rss = [long]$process.PeakWorkingSet64
            if ($rss -gt $peak) { $peak = $rss }
        } catch [System.InvalidOperationException] {}
        $exitCode = $process.ExitCode
    } finally {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        $process.Dispose()
    }
    $seconds = ((Get-Date) - $start).TotalSeconds
    Record @{ kind = 'phase'; phase = $phase; elapsed_s = [math]::Round($seconds,2); peak_rss_mb = [math]::Round($peak/1MB,1); exit_code = $exitCode; over_cap = $killed }
    if ($killed) { throw "$phase exceeded the $CapMB MB cap; stop and reduce --chunk-size" }
    if ($exitCode -ne 0) {
        if (Test-Path $stderr) { Get-Content $stderr -Tail 30 | Write-Host }
        throw "$phase returned exit code $exitCode"
    }
    if (Test-Path $stdout) { Get-Content $stdout -Tail 5 | Write-Host }
}
# Start-Process joins ArgumentList; preserve any spaces in the repository path.
$quotedOutputDir = '"' + $OutputDir + '"'
$standard = @('--start', "$StartHeight", '--end', "$EndHeight", '--chunk-size', "$ChunkSize")
# The initial invocation intentionally seals a single batch.
Run-Guarded 'first-batch' (@('prove', $quotedOutputDir) + $standard + @('--max-new-chunks','1'))
# Resume after the first sealed proof and produce remaining batches.
Run-Guarded 'resume' (@('prove', $OutputDir) + $standard)
# Verify only: must accept the recovered proof bundle without producing more proofs.
Run-Guarded 'verify' (@('verify', $quotedOutputDir) + $standard)
Write-Host "DDR4 benchmark receipt: $log"
