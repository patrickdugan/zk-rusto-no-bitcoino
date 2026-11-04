# Prove a header chain from genesis to -To as consecutive shards, several at
# once, then export each shard to an NHC1/NHT4 bundle.
#
#   powershell -ExecutionPolicy Bypass -File shard-run.ps1 -Network mainnet `
#     -Headers C:\data\headers.bin -To 973000 -Shards 16 -Parallel 8 -Threads 1 -Out C:\proofs
#
# Shard i covers (start_i, end_i]. The first starts at genesis; each other
# shard starts from the state the native rules derive from genesis, which is
# unproven on its own. scripts/verify-segments.py accepts the set only if the
# first shard starts at the genesis anchor and every shard starts exactly at
# the previous shard's proven end state, so the whole chain is anchored.
#
# Shards are ordinary nova-chain continuations: a stopped run resumes with
# the same command (finished shards are skipped, unfinished ones resume).
# Concurrent single-thread shards gave twice the throughput of one 8-thread
# run on an 8-vCPU machine; each shard needs about 0.6-1.2 GB while folding
# and about 1.4 GB while exporting.
param(
    [ValidateSet('mainnet', 'testnet4')][string]$Network = 'mainnet',
    [Parameter(Mandatory)][string]$Headers,
    [Parameter(Mandatory)][int]$To,
    [int]$Shards = 16,
    [int]$Parallel = 8,
    [int]$Threads = 1,
    [int]$K = 5,
    [int]$Every = 400,
    [int]$ExportParallel = 2,
    [Parameter(Mandatory)][string]$Out,
    [string]$Bin = (Join-Path $PSScriptRoot '..\target\release')
)
$ErrorActionPreference = 'Stop'
$chain = Join-Path $Bin 'nova-chain.exe'
if (-not (Test-Path $chain)) { throw "build first: cargo build --release ($chain missing)" }
if ($To % $K -ne 0) { throw "-To must be a multiple of -K" }
New-Item -ItemType Directory -Force $Out | Out-Null

# Shard boundaries: multiples of K, as equal as possible.
$steps = $To / $K
$bounds = @(0)
for ($i = 1; $i -le $Shards; $i++) { $bounds += [int]([math]::Floor($steps * $i / $Shards)) * $K }
$plan = for ($i = 0; $i -lt $Shards; $i++) {
    [pscustomobject]@{ Index = $i; Start = $bounds[$i]; End = $bounds[$i + 1]; Dir = Join-Path $Out ('shard-{0:D3}' -f $i) }
}
$plan | ConvertTo-Json | Set-Content -Encoding ascii (Join-Path $Out 'plan.json')

function Done($s) {
    $m = Join-Path $s.Dir 'LATEST'
    if (-not (Test-Path $m)) { return $false }
    $g = (Get-Content $m -Raw).Trim()
    $man = Get-Content (Join-Path $s.Dir "generations\$g\manifest.json") -Raw | ConvertFrom-Json
    return ($man.end_height -eq $s.End)
}

function Launch($s) {
    $log = Join-Path $Out ('shard-{0:D3}' -f $s.Index)
    $env:RAYON_NUM_THREADS = "$Threads"
    if (Test-Path (Join-Path $s.Dir 'LATEST')) {
        $a = @('resume', '--dir', $s.Dir, '--headers', $Headers, '--to', $s.End, '--every', $Every)
    } else {
        $a = @('run', '--network', $Network, '--k', $K, '--headers', $Headers, '--start', $s.Start, '--to', $s.End, '--every', $Every, '--out', $s.Dir)
    }
    Start-Process -FilePath $chain -ArgumentList $a -NoNewWindow -PassThru `
        -RedirectStandardOutput "$log.json" -RedirectStandardError "$log.err"
}

# Fold: keep -Parallel shards running.
$queue = [System.Collections.Queue]::new(@($plan | Where-Object { -not (Done $_) }))
$running = @{}
$t0 = Get-Date
while ($queue.Count -gt 0 -or $running.Count -gt 0) {
    while ($running.Count -lt $Parallel -and $queue.Count -gt 0) {
        $s = $queue.Dequeue()
        $running[$s.Index] = @{ Shard = $s; Proc = (Launch $s) }
        Write-Host ("{0:HH:mm:ss} shard {1} ({2}..{3}) started" -f (Get-Date), $s.Index, $s.Start, $s.End)
    }
    Start-Sleep -Seconds 10
    foreach ($i in @($running.Keys)) {
        $p = $running[$i].Proc
        if ($p.HasExited) {
            $s = $running[$i].Shard
            $running.Remove($i)
            if ($p.ExitCode -ne 0 -or -not (Done $s)) {
                throw ("shard {0} failed (exit {1}); see shard-{0:D3}.err; rerun to resume" -f $i, $p.ExitCode)
            }
            Write-Host ("{0:HH:mm:ss} shard {1} folded ({2:N1} h elapsed)" -f (Get-Date), $i, ((Get-Date) - $t0).TotalHours)
        }
    }
}

# Export: compress each shard (about 1.4 GB and 1-2 minutes each).
$exports = [System.Collections.Queue]::new(@($plan | Where-Object { -not (Test-Path (Join-Path $Out ('shard-{0:D3}.bundle' -f $_.Index))) }))
$running = @{}
while ($exports.Count -gt 0 -or $running.Count -gt 0) {
    while ($running.Count -lt $ExportParallel -and $exports.Count -gt 0) {
        $s = $exports.Dequeue()
        $b = Join-Path $Out ('shard-{0:D3}.bundle' -f $s.Index)
        $a = @('export', '--dir', $s.Dir, '--bundle', "$b.tmp")
        $log = Join-Path $Out ('shard-{0:D3}-export' -f $s.Index)
        $running[$s.Index] = @{ Shard = $s; Bundle = $b; Proc = (Start-Process -FilePath $chain -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput "$log.json" -RedirectStandardError "$log.err") }
    }
    Start-Sleep -Seconds 5
    foreach ($i in @($running.Keys)) {
        $r = $running[$i]
        if ($r.Proc.HasExited) {
            $running.Remove($i)
            if ($r.Proc.ExitCode -ne 0) { throw "export of shard $i failed; see shard-$('{0:D3}' -f $i)-export.err" }
            Move-Item -Force "$($r.Bundle).tmp" $r.Bundle
            Write-Host "shard $i exported"
        }
    }
}
Write-Host "all shards proven and exported in $Out; verify with:"
Write-Host "  python scripts\verify-segments.py --network $Network --verifier $Bin\btc-header-fold.exe --nova-chain $chain $Out\shard-*.bundle"
