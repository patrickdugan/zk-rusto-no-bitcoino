# Run one groth16-gym proof inside a Windows job object with a hard limit on
# committed memory, enforced by the OS. If the proof needs more than the
# limit, its allocations fail and it stops. Afterwards this reports the job's
# peak committed memory (PeakJobMemoryUsed), which, unlike the working set,
# Windows cannot trim.
#
#   powershell -ExecutionPolicy Bypass -File run-capped.ps1 -LimitGB 14 headers 64
#
# Build first (run-gym.ps1 does). Appends one JSON line per run to
# results\<host>-capped.jsonl.
param(
    [double]$LimitGB = 14,
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$GymArgs
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'groth16-gym-target' }
$bin = Join-Path $env:CARGO_TARGET_DIR 'release\groth16-gym.exe'
if (-not (Test-Path $bin)) { throw "not built: $bin" }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CappedJob {
    [StructLayout(LayoutKind.Sequential)] struct BASIC {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] struct IO { public ulong a, b, c, d, e, f; }
    [StructLayout(LayoutKind.Sequential)] struct EXTENDED {
        public BASIC Basic; public IO Io;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct STARTUPINFO {
        public int cb; public string r, d, t; public int x, y, w, h, cx, cy, fa, flags; public short show, r2;
        public IntPtr r3, i, o, e; }
    [StructLayout(LayoutKind.Sequential)] struct PROCINFO { public IntPtr Process, Thread; public int Pid, Tid; }
    [DllImport("kernel32", SetLastError = true)] static extern IntPtr CreateJobObject(IntPtr a, string n);
    [DllImport("kernel32", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr j, int c, ref EXTENDED i, int l);
    [DllImport("kernel32", SetLastError = true)] static extern bool QueryInformationJobObject(IntPtr j, int c, out EXTENDED i, int l, IntPtr r);
    [DllImport("kernel32", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr j, IntPtr p);
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CreateProcess(string app, string cmd,
        IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCINFO pi);
    [DllImport("kernel32")] static extern uint ResumeThread(IntPtr t);
    [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32")] static extern bool GetExitCodeProcess(IntPtr p, out uint code);
    [DllImport("kernel32")] static extern bool CloseHandle(IntPtr h);
    const int ExtendedLimit = 9;
    const uint LimitProcessMemory = 0x100, LimitJobMemory = 0x200, KillOnClose = 0x2000, Suspended = 0x4, NoWindow = 0x08000000;

    // Returns { exit code, peak job commit bytes, peak process commit bytes }.
    public static ulong[] Run(string cmdLine, string cwd, ulong limitBytes) {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        var x = new EXTENDED();
        // Set both limits. When the caller already runs inside a job (some
        // terminals and sandboxes do), the job-wide limit alone was observed
        // not to be enforced; the per-process limit was.
        x.Basic.LimitFlags = LimitProcessMemory | LimitJobMemory | KillOnClose;
        x.ProcessMemoryLimit = new UIntPtr(limitBytes);
        x.JobMemoryLimit = new UIntPtr(limitBytes);
        if (!SetInformationJobObject(job, ExtendedLimit, ref x, Marshal.SizeOf(x))) throw new System.ComponentModel.Win32Exception();
        var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);
        PROCINFO pi;
        // Start suspended so the process is in the job before it allocates anything.
        if (!CreateProcess(null, cmdLine, IntPtr.Zero, IntPtr.Zero, false, Suspended | NoWindow, IntPtr.Zero, cwd, ref si, out pi))
            throw new System.ComponentModel.Win32Exception();
        if (!AssignProcessToJobObject(job, pi.Process)) throw new System.ComponentModel.Win32Exception();
        ResumeThread(pi.Thread);
        WaitForSingleObject(pi.Process, 0xFFFFFFFF);
        uint code; GetExitCodeProcess(pi.Process, out code);
        EXTENDED q;
        QueryInformationJobObject(job, ExtendedLimit, out q, Marshal.SizeOf(typeof(EXTENDED)), IntPtr.Zero);
        CloseHandle(pi.Thread); CloseHandle(pi.Process); CloseHandle(job);
        return new ulong[] { code, q.PeakJobMemoryUsed.ToUInt64(), q.PeakProcessMemoryUsed.ToUInt64() };
    }
}
'@

New-Item -ItemType Directory -Force results | Out-Null
$tag = ($GymArgs -join '-')
$stdout = Join-Path $env:TEMP "groth16-gym-capped-$tag.out"
$stderr = Join-Path $env:TEMP "groth16-gym-capped-$tag.err"
# cmd.exe redirects the gym's output; the gym runs as its child, so the job limit covers both.
$cmdLine = "cmd.exe /d /c `"`"$bin`" $($GymArgs -join ' ') > `"$stdout`" 2> `"$stderr`"`""
$limit = [uint64]($LimitGB * 1GB)
$t0 = Get-Date
$r = [CappedJob]::Run($cmdLine, $PSScriptRoot, $limit)
$secs = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)

$gym = Get-Content $stdout -ErrorAction SilentlyContinue | Where-Object { $_ -like '{*' } | Select-Object -Last 1
$err = (Get-Content $stderr -ErrorAction SilentlyContinue | Select-Object -Last 3) -join ' | '
Remove-Item $stdout, $stderr -ErrorAction SilentlyContinue
$rec = [ordered]@{
    host = $env:COMPUTERNAME; args = $GymArgs -join ' '; limit_gb = $LimitGB
    exit_code = ('0x{0:X8}' -f [uint32]$r[0]); completed = [bool]$gym
    peak_commit_mb = [math]::Round($r[1] / 1MB); peak_process_commit_mb = [math]::Round($r[2] / 1MB)
    wall_s = $secs; stderr_tail = $err
}
$line = ($rec | ConvertTo-Json -Compress)
if ($gym) { $line = $line.TrimEnd('}') + ",`"gym`":$gym}" }
[IO.File]::AppendAllText((Join-Path $PSScriptRoot "results\$($env:COMPUTERNAME.ToLower())-capped.jsonl"), $line + "`n", (New-Object Text.UTF8Encoding $false))
Write-Host $line
