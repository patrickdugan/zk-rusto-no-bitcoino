# Fetch testnet4 headers from an Esplora API as "height hex" lines (the format
# of --headers-txt). Each 80-byte header is rebuilt from the API's fields and
# kept only if its double SHA-256 equals the block id and it links to its
# predecessor, so the API cannot substitute headers unnoticed. It can still
# withhold or choose a fork; authenticate the checkpoint against a node.
#
#   powershell -File scripts/fetch-testnet4-headers.ps1 -From 100690 -To 100900 -Extra 98784 -Out fixtures/testnet4/headers_100690_100900.txt
param(
    [Parameter(Mandatory = $true)][int]$From,
    [Parameter(Mandatory = $true)][int]$To,
    [int[]]$Extra = @(),
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Api = 'https://mempool.space/testnet4/api'
)
$ErrorActionPreference = 'Stop'
$sha = [Security.Cryptography.SHA256]::Create()
function Rev([byte[]]$b) { $c = [byte[]]$b.Clone(); [Array]::Reverse($c); $c }
function FromHex([string]$h) { [byte[]](0..($h.Length / 2 - 1) | ForEach-Object { [Convert]::ToByte($h.Substring(2 * $_, 2), 16) }) }
function ToHex([byte[]]$b) { -join ($b | ForEach-Object { $_.ToString('x2') }) }
function U32([long]$v) { [BitConverter]::GetBytes([uint32]$v) }

$blocks = @{}
function Fetch([int]$top) {
    for ($try = 1; $try -le 5; $try++) {
        try { return Invoke-RestMethod -Uri "$Api/blocks/$top" -TimeoutSec 30 }
        catch { Start-Sleep -Seconds (2 * $try) }
    }
    throw "fetch failed at $top"
}
$want = @($From..$To) + $Extra
$top = $To
while ($top -ge $From) {
    foreach ($b in (Fetch $top)) { $blocks[[int]$b.height] = $b }
    $top -= 10
    Start-Sleep -Milliseconds 300
}
foreach ($h in $Extra) { if (-not $blocks.ContainsKey($h)) { foreach ($b in (Fetch $h)) { $blocks[[int]$b.height] = $b } } }

$lines = New-Object System.Collections.Generic.List[string]
$hashes = @{}
foreach ($h in ($want | Sort-Object -Unique)) {
    $b = $blocks[$h]
    if (-not $b) { throw "missing block $h" }
    $hdr = [byte[]](@(U32 $b.version) + @(Rev (FromHex $b.previousblockhash)) + @(Rev (FromHex $b.merkle_root)) + @(U32 $b.timestamp) + @(U32 $b.bits) + @(U32 $b.nonce))
    if ($hdr.Length -ne 80) { throw "header $h is $($hdr.Length) bytes" }
    $id = ToHex (Rev ($sha.ComputeHash($sha.ComputeHash($hdr))))
    if ($id -ne $b.id) { throw "header $h hashes to $id, API id $($b.id)" }
    if ($hashes.ContainsKey($h - 1) -and $b.previousblockhash -ne $hashes[$h - 1]) { throw "header $h does not link to $($h - 1)" }
    $hashes[$h] = $id
    $lines.Add("$h $(ToHex $hdr)")
}
New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
[IO.File]::WriteAllLines($Out, $lines, (New-Object Text.UTF8Encoding $false))
"wrote $($lines.Count) headers to $Out"
