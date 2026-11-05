# Export headers from a local Bitcoin Core node as "height hex" lines (the
# --headers-txt format), using batched JSON-RPC with cookie authentication.
# Each header is checked against its block hash and its predecessor. Also
# prints each -Chainwork height's hash and chainwork from getblockheader.
#
#   powershell -File scripts/export-node-headers.ps1 -From 98998 -To 158948 -Extra 98784 `
#     -Chainwork 99008,100008 -Out headers.txt -Cookie D:\BitcoinTestnet\testnet4\.cookie -Port 48332
param(
    [Parameter(Mandatory = $true)][int]$From,
    [Parameter(Mandatory = $true)][int]$To,
    [string]$Extra = '',      # comma-separated heights, e.g. a period's first block
    [string]$Chainwork = '',  # comma-separated heights to report chainwork for
    [Parameter(Mandatory = $true)][string]$Out,
    [Parameter(Mandatory = $true)][string]$Cookie,
    [int]$Port = 48332,
    [int]$Batch = 1000
)
$ErrorActionPreference = 'Stop'
$extraH = @($Extra -split ',' | Where-Object { $_ } | ForEach-Object { [int]$_ })
$workH = @($Chainwork -split ',' | Where-Object { $_ } | ForEach-Object { [int]$_ })
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes((Get-Content $Cookie -Raw).Trim()))
$url = "http://127.0.0.1:$Port/"
function Call([object[]]$reqs) {
    $body = ConvertTo-Json -InputObject $reqs -Compress -Depth 5
    $res = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType 'application/json' -Headers @{ Authorization = "Basic $auth" } -TimeoutSec 300
    $map = @{}
    foreach ($r in $res) { if ($r.error) { throw "rpc error: $($r.error.message)" }; $map[[int]$r.id] = $r.result }
    $map
}
$sha = [Security.Cryptography.SHA256]::Create()
function ToHex([byte[]]$b) { -join ($b | ForEach-Object { $_.ToString('x2') }) }
function FromHex([string]$h) { $b = New-Object byte[] ($h.Length / 2); for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($h.Substring(2 * $i, 2), 16) }; $b }

$heights = @(($From..$To) + $extraH + $workH | Sort-Object -Unique)
$hashes = @{}
for ($i = 0; $i -lt $heights.Count; $i += $Batch) {
    $chunk = $heights[$i..([math]::Min($i + $Batch, $heights.Count) - 1)]
    $res = Call @($chunk | ForEach-Object { @{ jsonrpc = '1.0'; id = $_; method = 'getblockhash'; params = @($_) } })
    foreach ($h in $chunk) { $hashes[$h] = $res[$h] }
}
$lines = New-Object System.Collections.Generic.List[string]
$prevHash = $null; $prevHeight = $null
for ($i = 0; $i -lt $heights.Count; $i += $Batch) {
    $chunk = $heights[$i..([math]::Min($i + $Batch, $heights.Count) - 1)]
    $res = Call @($chunk | ForEach-Object { @{ jsonrpc = '1.0'; id = $_; method = 'getblockheader'; params = @($hashes[$_], $false) } })
    foreach ($h in $chunk) {
        $hex = $res[$h]
        $bytes = FromHex $hex
        if ($bytes.Length -ne 80) { throw "header $h is $($bytes.Length) bytes" }
        $id = $sha.ComputeHash($sha.ComputeHash($bytes)); [Array]::Reverse($id)
        if ((ToHex $id) -ne $hashes[$h]) { throw "header $h does not hash to its block hash" }
        if ($prevHeight -eq $h - 1) {
            $p = $bytes[4..35]; [Array]::Reverse($p)
            if ((ToHex $p) -ne $prevHash) { throw "header $h does not link to $($h - 1)" }
        }
        $prevHash = $hashes[$h]; $prevHeight = $h
        $lines.Add("$h $hex")
    }
}
[IO.File]::WriteAllLines($Out, $lines, (New-Object Text.UTF8Encoding $false))
"wrote $($lines.Count) headers to $Out"
if ($workH.Count) {
    $res = Call @($workH | ForEach-Object { @{ jsonrpc = '1.0'; id = $_; method = 'getblockheader'; params = @($hashes[$_], $true) } })
    foreach ($h in $workH) { "chainwork $h $($res[$h].hash) $($res[$h].chainwork)" }
}
