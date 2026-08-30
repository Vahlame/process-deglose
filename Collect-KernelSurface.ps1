#requires -Version 5.1
<#
  Kernel-level surface capture for process-deglose. Dot-sourced from snapshot.ps1.
  Uses helpers defined there: Add-Issue, Invoke-CaptureCmd, Format-Bytes,
  Escape-MdCell, Get-PathClass, Write-MdTable.

  Everything here is READ-ONLY: it queries the kernel (NtQuerySystemInformation),
  performance counters, the SCM driver database, the filter manager, and a short
  ETW trace of the NT kernel logger. Nothing is installed, hooked, or changed.

  Needs Administrator (degrades gracefully without it):
    - loaded kernel modules      (SystemModuleInformation)
    - kernel pool tag usage      (SystemPoolTagInformation)
    - minifilter stack           (fltmc filters)
    - ETW kernel trace window    (logman + tracerpt, process/img/disk)
  Works without Administrator:
    - registered kernel drivers  (Win32_SystemDriver + file metadata)
    - kernel performance counters (Get-Counter)

  Privacy: the ETW window can contain file/process names. Only aggregated numbers
  are kept in the report; the raw .etl is deleted unless -KeepEtl was passed.
#>

if (-not ('NativeKernelInfo' -as [type])) {
  try {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class NativeKernelInfo {
  [DllImport("ntdll.dll")]
  public static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

  public const int SystemModuleInformation = 11;
  public const int SystemPoolTagInformation = 23;

  [StructLayout(LayoutKind.Sequential)]
  public struct POOL_ENTRY {
    public uint Tag;
    public uint PagedAllocs;
    public uint PagedFrees;
    public UIntPtr PagedUsed;
    public uint NonPagedAllocs;
    public uint NonPagedFrees;
    public UIntPtr NonPagedUsed;
  }

  public class ModuleInfo {
    public string Name;
    public int ImageSize;
    public int LoadOrder;
  }

  public class PoolInfo {
    public uint Tag;
    public ulong PagedUsed;
    public ulong NonPagedUsed;
  }

  public static ModuleInfo[] GetModuleInfos() {
    int returnLen = 0;
    NtQuerySystemInformation(SystemModuleInformation, IntPtr.Zero, 0, out returnLen);
    if (returnLen <= 0 || returnLen > (1 << 26)) return null;
    IntPtr buf = Marshal.AllocHGlobal(returnLen);
    try {
      int status = NtQuerySystemInformation(SystemModuleInformation, buf, returnLen, out returnLen);
      if (status != 0) return null;
      int count = Marshal.ReadInt32(buf);
      if (count <= 0 || count > 10000) return null;
      // Layout verified on Win11 24H2: ULONG count, entries at +4 with fixed
      // 296-byte stride; FullPathName (ANSI) at +44, ImageSize at +28,
      // LoadOrderIndex at +36.
      const int entrySize = 296;
      ModuleInfo[] arr = new ModuleInfo[count];
      for (int i = 0; i < count; i++) {
        IntPtr e = new IntPtr(buf.ToInt64() + 4 + (long)i * entrySize);
        ModuleInfo mi = new ModuleInfo();
        mi.ImageSize = Marshal.ReadInt32(e, 28);
        mi.LoadOrder = Marshal.ReadInt16(e, 36);
        mi.Name = Marshal.PtrToStringAnsi(new IntPtr(e.ToInt64() + 44));
        arr[i] = mi;
      }
      return arr;
    } finally { Marshal.FreeHGlobal(buf); }
  }

  public static PoolInfo[] GetPoolTagInfos() {
    int returnLen = 0;
    NtQuerySystemInformation(SystemPoolTagInformation, IntPtr.Zero, 0, out returnLen);
    if (returnLen <= 0 || returnLen > (1 << 26)) return null;
    IntPtr buf = Marshal.AllocHGlobal(returnLen);
    try {
      int status = NtQuerySystemInformation(SystemPoolTagInformation, buf, returnLen, out returnLen);
      if (status != 0) return null;
      int count = Marshal.ReadInt32(buf);
      if (count <= 0 || count > 200000) return null;
      int entrySize = Marshal.SizeOf(typeof(POOL_ENTRY));
      PoolInfo[] arr = new PoolInfo[count];
      IntPtr p = new IntPtr(buf.ToInt64() + 4);
      for (int i = 0; i < count; i++) {
        POOL_ENTRY e = (POOL_ENTRY)Marshal.PtrToStructure(p, typeof(POOL_ENTRY));
        PoolInfo pi = new PoolInfo();
        pi.Tag = e.Tag;
        pi.PagedUsed = e.PagedUsed.ToUInt64();
        pi.NonPagedUsed = e.NonPagedUsed.ToUInt64();
        arr[i] = pi;
        p = new IntPtr(p.ToInt64() + entrySize);
      }
      return arr;
    } finally { Marshal.FreeHGlobal(buf); }
  }

  public const int SystemProcessInformation = 5;
  public const int SystemPerformanceInformation = 2;
  public const int SystemProcessorPerformanceInformation = 8;

  public class PerfInfo {
    public int AvailablePages;
    public int CommittedPages;
    public int CommitLimit;
    public int PageFaultCount;
    public long PagedPoolPages;
    public long NonPagedPoolPages;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct PROC_PERF_ENTRY {
    public long IdleTime;
    public long KernelTime;
    public long UserTime;
    public long DpcTime;
    public long InterruptTime;
    public int InterruptCount;
  }

  public class PerCoreInfo {
    public long IdleTime;
    public long KernelTime;
    public long UserTime;
    public long DpcTime;
    public long InterruptTime;
    public int InterruptCount;
  }

  public class KernelProcessInfo {
    public int ProcessId;
    public int ParentProcessId;
    public string Name;
    public int ThreadCount;
    public int HandleCount;
    public int SessionId;
    public long CreateTimeTicks;
    public double CpuSeconds;
  }

  public static PerfInfo GetPerfInfo() {
    int returnLen = 0;
    NtQuerySystemInformation(SystemPerformanceInformation, IntPtr.Zero, 0, out returnLen);
    if (returnLen <= 0 || returnLen > (1 << 20)) return null;
    IntPtr buf = Marshal.AllocHGlobal(returnLen);
    try {
      int status = NtQuerySystemInformation(SystemPerformanceInformation, buf, returnLen, out returnLen);
      if (status != 0) return null;
      // Offsets verified on Win11 24H2 (leading fields of SYSTEM_PERFORMANCE_INFORMATION).
      PerfInfo p = new PerfInfo();
      p.AvailablePages = Marshal.ReadInt32(buf, 44);
      p.CommittedPages = Marshal.ReadInt32(buf, 48);
      p.CommitLimit = Marshal.ReadInt32(buf, 52);
      p.PageFaultCount = Marshal.ReadInt32(buf, 60);
      p.PagedPoolPages = Marshal.ReadInt32(buf, 112);
      p.NonPagedPoolPages = Marshal.ReadInt32(buf, 116);
      // sanity: kernel's own counters must be plausible
      if (p.CommitLimit <= 0) return null;
      if (p.AvailablePages < 0) return null;
      if (p.PagedPoolPages < 0 || p.NonPagedPoolPages < 0) return null;
      return p;
    } finally { Marshal.FreeHGlobal(buf); }
  }

  public static PerCoreInfo[] GetProcPerfInfos() {
    int returnLen = 0;
    NtQuerySystemInformation(SystemProcessorPerformanceInformation, IntPtr.Zero, 0, out returnLen);
    if (returnLen <= 0 || returnLen > (1 << 22)) return null;
    IntPtr buf = Marshal.AllocHGlobal(returnLen);
    try {
      int status = NtQuerySystemInformation(SystemProcessorPerformanceInformation, buf, returnLen, out returnLen);
      if (status != 0) return null;
      int entrySize = Marshal.SizeOf(typeof(PROC_PERF_ENTRY));
      int count = returnLen / entrySize;
      if (count <= 0 || count > 1024) return null;
      PerCoreInfo[] arr = new PerCoreInfo[count];
      IntPtr p = buf;
      for (int i = 0; i < count; i++) {
        PROC_PERF_ENTRY e = (PROC_PERF_ENTRY)Marshal.PtrToStructure(p, typeof(PROC_PERF_ENTRY));
        PerCoreInfo c = new PerCoreInfo();
        c.IdleTime = e.IdleTime;
        c.KernelTime = e.KernelTime;
        c.UserTime = e.UserTime;
        c.DpcTime = e.DpcTime;
        c.InterruptTime = e.InterruptTime;
        c.InterruptCount = e.InterruptCount;
        arr[i] = c;
        p = new IntPtr(p.ToInt64() + entrySize);
      }
      return arr;
    } finally { Marshal.FreeHGlobal(buf); }
  }

  public static KernelProcessInfo[] GetKernelProcessInfos() {
    int returnLen = 0;
    NtQuerySystemInformation(SystemProcessInformation, IntPtr.Zero, 0, out returnLen);
    if (returnLen <= 0 || returnLen > (1 << 26)) return null;
    IntPtr buf = Marshal.AllocHGlobal(returnLen);
    try {
      int status = NtQuerySystemInformation(SystemProcessInformation, buf, returnLen, out returnLen);
      if (status != 0) return null;
      List<KernelProcessInfo> list = new List<KernelProcessInfo>();
      int usSize = (IntPtr.Size == 8) ? 16 : 8; // aligned UNICODE_STRING size
      IntPtr p = buf;
      int guard = 0;
      while (guard < 100000) {
        guard++;
        int next = Marshal.ReadInt32(p, 0);
        int threadCount = Marshal.ReadInt32(p, 4);
        long createTicks = Marshal.ReadInt64(p, 32);
        long userTime = Marshal.ReadInt64(p, 40);
        long kernelTime = Marshal.ReadInt64(p, 48);
        int nameLen = Marshal.ReadInt16(p, 56);
        IntPtr nameBuf = (IntPtr.Size == 8) ? Marshal.ReadIntPtr(p, 64) : Marshal.ReadIntPtr(p, 60);
        long pid = Marshal.ReadIntPtr(p, 56 + usSize + IntPtr.Size).ToInt64();
        long ppid = Marshal.ReadIntPtr(p, 56 + usSize + 2 * IntPtr.Size).ToInt64();
        int handleCount = Marshal.ReadInt32(p, 56 + usSize + 2 * IntPtr.Size + 4);
        int sessionId = Marshal.ReadInt32(p, 56 + usSize + 2 * IntPtr.Size + 8);
        KernelProcessInfo k = new KernelProcessInfo();
        k.ProcessId = (int)pid;
        k.ParentProcessId = (int)ppid;
        k.ThreadCount = threadCount;
        k.HandleCount = handleCount;
        k.SessionId = sessionId;
        k.CreateTimeTicks = createTicks;
        k.CpuSeconds = (userTime + kernelTime) / 10000000.0;
        if (nameLen > 0 && nameBuf != IntPtr.Zero) {
          k.Name = Marshal.PtrToStringUni(nameBuf, nameLen / 2);
        }
        list.Add(k);
        if (next <= 0) break;
        p = new IntPtr(p.ToInt64() + next);
      }
      return list.ToArray();
    } finally { Marshal.FreeHGlobal(buf); }
  }
}
'@
  } catch {
    Add-Issue "NativeKernelInfo Add-Type failed: $($_.Exception.Message)"
  }
}

function Convert-KernelModuleName {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return $Name }
  $n = $Name
  $win = $env:WINDIR
  if ($win) {
    $n = $n -replace '^\\SystemRoot\\', ($win + '\')
  }
  $n = $n -replace '^\\\?\?\\', ''
  return $n
}

function Get-KernelModuleRows {
  # Loaded kernel modules (ntoskrnl + every driver currently in the kernel).
  # Administrator required (SystemModuleInformation).
  $rows = @()
  if (-not ('NativeKernelInfo' -as [type])) { return $rows }
  try {
    $mods = [NativeKernelInfo]::GetModuleInfos()
    if ($null -eq $mods) {
      Add-Issue 'Kernel modules: SystemModuleInformation query returned nothing'
      return $rows
    }
    foreach ($m in $mods) {
      $size = [int64]$m.ImageSize
      if ($size -le 0 -or $size -gt 1GB) { $size = 0 }
      $rows += New-Object psobject -Property ([ordered]@{
        Name = Convert-KernelModuleName $m.Name
        Size = $size
        LoadOrder = [int]$m.LoadOrder
      })
    }
  } catch {
    Add-Issue "Kernel modules: $($_.Exception.Message)"
  }
  return $rows
}

function Get-PoolTagRows {
  # Kernel pool usage per tag (RAMMap-style). Administrator required.
  $rows = @()
  if (-not ('NativeKernelInfo' -as [type])) { return $rows }
  try {
    $pools = [NativeKernelInfo]::GetPoolTagInfos()
    if ($null -eq $pools) {
      Add-Issue 'Pool tags: NtQuerySystemInformation(SystemPoolTagInformation) returned nothing (needs Administrator?)'
      return $rows
    }
    foreach ($p in $pools) {
      $bytes = [BitConverter]::GetBytes([uint32]$p.Tag)
      $tagStr = -join ($bytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } })
      $rows += New-Object psobject -Property ([ordered]@{
        Tag = $tagStr
        PagedUsed = [int64]$p.PagedUsed
        NonPagedUsed = [int64]$p.NonPagedUsed
        TotalBytes = ([int64]$p.PagedUsed + [int64]$p.NonPagedUsed)
      })
    }
  } catch {
    Add-Issue "Pool tags: $($_.Exception.Message)"
  }
  return $rows
}

function Get-KernelProcessRows {
  # Kernel-side process list (SystemProcessInformation): a third enumerator,
  # cross-checked against CIM / Get-Process in the report.
  $rows = @()
  if (-not ('NativeKernelInfo' -as [type])) { return $rows }
  try {
    $procs = [NativeKernelInfo]::GetKernelProcessInfos()
    if ($null -eq $procs) {
      Add-Issue 'Kernel process list: SystemProcessInformation returned nothing'
      return $rows
    }
    foreach ($kp in $procs) {
      $rows += New-Object psobject -Property ([ordered]@{
        Pid = $kp.ProcessId
        ParentPid = $kp.ParentProcessId
        Name = [string]$kp.Name
        Threads = $kp.ThreadCount
        Handles = $kp.HandleCount
        SessionId = $kp.SessionId
        CpuSeconds = [math]::Round($kp.CpuSeconds, 1)
        StartTime = $(if ($kp.CreateTimeTicks -gt 0) { ([datetime]::FromFileTimeUtc($kp.CreateTimeTicks)).ToString('o') } else { $null })
      })
    }
  } catch {
    Add-Issue "Kernel process list: $($_.Exception.Message)"
  }
  return $rows
}

function Get-KernelPerfInfo {
  # Kernel performance counters read directly from the kernel (SystemPerformanceInformation).
  $perf = $null
  if (-not ('NativeKernelInfo' -as [type])) { return $null }
  try {
    $p = [NativeKernelInfo]::GetPerfInfo()
    if ($null -eq $p) {
      Add-Issue 'Kernel perf info: SystemPerformanceInformation not readable'
      return $null
    }
    $pageSize = 4096
    return [ordered]@{
      AvailablePages = $p.AvailablePages
      CommittedPages = $p.CommittedPages
      CommitLimitPages = $p.CommitLimit
      PageFaultCount = $p.PageFaultCount
      PagedPoolBytes = ([int64]$p.PagedPoolPages * $pageSize)
      NonPagedPoolBytes = ([int64]$p.NonPagedPoolPages * $pageSize)
    }
  } catch {
    Add-Issue "Kernel perf info: $($_.Exception.Message)"
    return $null
  }
}

function Get-ProcessorPerfRows {
  # Per-logical-core CPU time shares since boot (SystemProcessorPerformanceInformation).
  $rows = @()
  if (-not ('NativeKernelInfo' -as [type])) { return $rows }
  try {
    $cores = [NativeKernelInfo]::GetProcPerfInfos()
    if ($null -eq $cores) {
      Add-Issue 'Per-core CPU times: SystemProcessorPerformanceInformation not readable'
      return $rows
    }
    for ($i = 0; $i -lt $cores.Length; $i++) {
      $c = $cores[$i]
      $total = [double]$c.KernelTime + [double]$c.UserTime
      $idle = 0.0
      $priv = 0.0
      $user = 0.0
      $dpc = 0.0
      $intr = 0.0
      if ($total -gt 0) {
        $idle = [math]::Round(100.0 * $c.IdleTime / $total, 1)
        $priv = [math]::Round(100.0 * ($c.KernelTime - $c.IdleTime) / $total, 1)
        $user = [math]::Round(100.0 * $c.UserTime / $total, 1)
        $dpc = [math]::Round(100.0 * $c.DpcTime / $total, 1)
        $intr = [math]::Round(100.0 * $c.InterruptTime / $total, 1)
      }
      $rows += New-Object psobject -Property ([ordered]@{
        Core = $i
        IdlePct = $idle
        PrivilegedPct = $priv
        UserPct = $user
        DpcPct = $dpc
        InterruptPct = $intr
        Interrupts = $c.InterruptCount
      })
    }
  } catch {
    Add-Issue "Per-core CPU: $($_.Exception.Message)"
  }
  return $rows
}

function Get-KernelCounterSamples {
  # Kernel-relevant performance counters (sampled over ~1 s). May be unavailable
  # on hardened/odd systems; every counter is best-effort.
  $paths = @(
    '\Memory\Pool Paged Bytes',
    '\Memory\Pool Nonpaged Bytes',
    '\Memory\Pool Paged Resident Bytes',
    '\Memory\Standby Cache Normal Priority Bytes',
    '\Memory\Standby Cache Reserve Bytes',
    '\Memory\Modified Page List Bytes',
    '\Memory\Free & Zero Page List Bytes',
    '\Memory\Cache Bytes',
    '\Memory\Committed Bytes',
    '\Memory\Commit Limit',
    '\System\Context Switches/sec',
    '\System\System Calls/sec',
    '\System\Processor Queue Length',
    '\System\Threads',
    '\System\Processes',
    '\Processor Information(_Total)\% Processor Time',
    '\Processor Information(_Total)\% Privileged Time',
    '\Processor Information(_Total)\% Interrupt Time',
    '\Processor Information(_Total)\% DPC Time',
    '\Processor Information(_Total)\% of Maximum Frequency',
    '\Objects\Events',
    '\Objects\Mutexes',
    '\Objects\Semaphores',
    '\Objects\Sections',
    '\Process(_Total)\IO Data Bytes/sec',
    '\PhysicalDisk(_Total)\Avg. Disk Queue Length',
    '\PhysicalDisk(*)\Disk Bytes/sec',
    '\PhysicalDisk(*)\Avg. Disk sec/Read',
    '\PhysicalDisk(*)\Avg. Disk sec/Write',
    '\Processor Information(*)\% of Maximum Frequency'
  )
  $result = [ordered]@{}
  try {
    $samples = Get-Counter -Counter $paths -SampleInterval 1 -MaxSamples 2 -ErrorAction Stop
    foreach ($s in $samples.CounterSamples) {
      $v = $s.CookedValue
      if ($null -ne $v) {
        $result[[string]$s.Path] = [math]::Round([double]$v, 1)
      }
    }
  } catch {
    Add-Issue "Kernel counters: batch Get-Counter failed, trying per-counter ($($_.Exception.Message))"
    foreach ($p in $paths) {
      try {
        $s = Get-Counter -Counter $p -MaxSamples 1 -ErrorAction Stop
        $v = $s.CounterSamples[0].CookedValue
        if ($null -ne $v) { $result[$p] = [math]::Round([double]$v, 1) }
      } catch { }
    }
  }
  if ($result.Count -eq 0) {
    Add-Issue 'Kernel counters: none readable (perf counters unavailable on this system)'
  }
  return $result
}

function Get-KernelDriverRows {
  # Registered kernel drivers from the SCM database (works without admin).
  # File metadata is best-effort and path-cached.
  $rows = @()
  $drv = @()
  try {
    $drv = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop)
  } catch {
    Add-Issue "Win32_SystemDriver: $($_.Exception.Message)"
    return $rows
  }
  $metaCache = @{}
  foreach ($d in $drv) {
    $path = [string]$d.PathName
    $company = $null
    $version = $null
    if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path)) {
      $lk = $path.ToLowerInvariant()
      if ($metaCache.ContainsKey($lk)) {
        $company = $metaCache[$lk].Company
        $version = $metaCache[$lk].Version
      } else {
        try {
          $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
          $company = $vi.CompanyName
          $version = $vi.FileVersion
        } catch { }
        $metaCache[$lk] = [ordered]@{ Company = $company; Version = $version }
      }
    }
    $rows += New-Object psobject -Property ([ordered]@{
      Name = [string]$d.Name
      State = [string]$d.State
      StartMode = [string]$d.StartMode
      PathName = $path
      Company = $company
      Version = $version
    })
  }
  return $rows
}

function Get-MinifilterRows {
  # File-system minifilter stack (order + altitude). Administrator required.
  $rows = @()
  $raw = Invoke-CaptureCmd -FileName 'fltmc.exe' -Arguments 'filters' -TimeoutMs 20000
  if ([string]::IsNullOrWhiteSpace($raw)) {
    Add-Issue 'Minifilters: fltmc filters returned nothing (needs Administrator?)'
    return @{ Rows = @(); Raw = $null }
  }
  $lines = @($raw -split "`r?`n" | Where-Object { $_ -match '^\s*\S+\s+\d+\s+\d+\s+\d+\s*$' })
  foreach ($ln in $lines) {
    $m = [regex]::Match($ln, '^\s*(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$')
    if (-not $m.Success) { continue }
    $rows += New-Object psobject -Property ([ordered]@{
      Name = $m.Groups[1].Value
      Instances = [int]$m.Groups[2].Value
      Altitude = $m.Groups[3].Value
      Frame = [int]$m.Groups[4].Value
    })
  }
  if ($rows.Count -eq 0) {
    Add-Issue 'Minifilters: fltmc filters returned no parseable rows (needs Administrator?)'
    return @{ Rows = @(); Raw = $null }
  }
  $rawTrim = (@($raw -split "`r?`n" | Select-Object -First 40) -join "`n")
  return @{ Rows = $rows; Raw = $rawTrim }
}

function Split-CsvLine {
  # Minimal CSV line splitter that honours double-quoted fields.
  param([string]$Line)
  $out = New-Object System.Collections.Generic.List[string]
  $cur = New-Object System.Text.StringBuilder
  $inQ = $false
  for ($i = 0; $i -lt $Line.Length; $i++) {
    $c = $Line[$i]
    if ($inQ) {
      if ($c -eq '"') {
        if ($i + 1 -lt $Line.Length -and $Line[$i + 1] -eq '"') {
          [void]$cur.Append('"')
          $i++
        } else {
          $inQ = $false
        }
      } else {
        [void]$cur.Append($c)
      }
    } else {
      if ($c -eq '"') { $inQ = $true }
      elseif ($c -eq ',') {
        $out.Add($cur.ToString())
        [void]$cur.Clear()
      } else {
        [void]$cur.Append($c)
      }
    }
  }
  $out.Add($cur.ToString())
  $arr = $out.ToArray()
  return ,$arr
}

function Get-CsvColIndex {
  param([object[]]$Cols, [string[]]$Names)
  for ($i = 0; $i -lt $Cols.Count; $i++) {
    foreach ($n in $Names) {
      if ([string]$Cols[$i] -eq $n) { return $i }
    }
  }
  return -1
}

function Invoke-KernelEtlDigest {
  # Short NT kernel logger trace digested locally. Administrator required.
  # Default keywords: process, image load, disk I/O. With -Deep also file,
  # network, registry, thread (larger trace; raw .etl deleted unless $KeepEtl).
  param(
    [bool]$IsAdmin,
    [int]$Seconds,
    [string]$OutDir,
    [bool]$KeepEtl,
    [bool]$Deep
  )
  if (-not $IsAdmin) {
    Add-Issue 'ETW kernel trace skipped: needs Administrator'
    return $null
  }
  if ([string]::IsNullOrWhiteSpace($OutDir)) { return $null }
  $keywords = '(process,img,disk)'
  if ($Deep) { $keywords = '(process,img,disk,file,net,registry,thread)' }
  $etl = Join-Path $OutDir 'kernel-trace.etl'
  $csv = Join-Path $OutDir 'kernel-trace-dump.csv'
  $sum = Join-Path $OutDir 'kernel-trace-summary.txt'
  $session = 'procdeglose_kernel'
  $started = $false
  try {
    $argsCreate = '-create trace {0} -p "Windows Kernel Trace" {1} -o "{2}" -ets' -f $session, $keywords, $etl
    Invoke-CaptureCmd -FileName 'logman.exe' -Arguments $argsCreate -TimeoutMs 30000 | Out-Null
    Start-Sleep -Milliseconds 800
    $etlOk = (Test-Path -LiteralPath $etl) -and ((Get-Item -LiteralPath $etl).Length -gt 0)
    if (-not $etlOk) {
      # fallback: logman start (creates + starts in one step on some builds)
      $argsStart = '-start {0} -p "Windows Kernel Trace" {1} -o "{2}" -ets' -f $session, $keywords, $etl
      Invoke-CaptureCmd -FileName 'logman.exe' -Arguments $argsStart -TimeoutMs 30000 | Out-Null
      Start-Sleep -Milliseconds 800
      $etlOk = (Test-Path -LiteralPath $etl) -and ((Get-Item -LiteralPath $etl).Length -gt 0)
    }
    if (-not $etlOk) {
      Add-Issue 'ETW kernel trace: logman could not start the kernel session (needs Administrator?)'
      return $null
    }
    $started = $true
    Write-Host ("       ETW kernel trace: capturing {0}s of process/image/disk events..." -f $Seconds)
    Start-Sleep -Seconds $Seconds
    Invoke-CaptureCmd -FileName 'logman.exe' -Arguments ('-stop {0} -ets' -f $session) -TimeoutMs 30000 | Out-Null
    $started = $false
    Invoke-CaptureCmd -FileName 'logman.exe' -Arguments ('-delete {0} -ets' -f $session) -TimeoutMs 30000 | Out-Null

    if (-not ((Test-Path -LiteralPath $etl) -and ((Get-Item -LiteralPath $etl).Length -gt 0))) {
      Add-Issue 'ETW kernel trace: ETL file empty after stop'
      return $null
    }

    $digest = [ordered]@{
      WindowSeconds = $Seconds
      Deep = $Deep
      TotalEvents = 0
      EventsLost = 0
      EventCounts = [ordered]@{}
      DiskByProcess = @()
      SummaryText = $null
      EtlKept = $false
      EtlPath = $null
    }

    # tracerpt: CSV dump (for per-process disk I/O) + text summary (counts/lost)
    $trArgs = '"{0}" -o "{1}" -of CSV -summary "{2}" -y' -f $etl, $csv, $sum
    Invoke-CaptureCmd -FileName 'tracerpt.exe' -Arguments $trArgs -TimeoutMs 120000 | Out-Null

    if (Test-Path -LiteralPath $sum) {
      try { $digest.SummaryText = ([System.IO.File]::ReadAllText($sum)) } catch { }
      $mLost = [regex]::Match([string]$digest.SummaryText, '(?im)^\s*events?\s+lost\s*[:=]?\s*(\d+)')
      if (-not $mLost.Success) {
        $mLost = [regex]::Match([string]$digest.SummaryText, '(?im)^\s*eventos?\s+perdidos\s*[:=]?\s*(\d+)')
      }
      if ($mLost.Success) { $digest.EventsLost = [int]$mLost.Groups[1].Value }
    }

    if (Test-Path -LiteralPath $csv) {
      try {
        $reader = New-Object System.IO.StreamReader($csv, $true)
        try {
          $headerLine = $reader.ReadLine()
          if ($headerLine) {
            $cols = Split-CsvLine $headerLine
            $idxName = Get-CsvColIndex $cols @('EventName')
            $idxOp = Get-CsvColIndex $cols @('Opcode')
            $idxPid = Get-CsvColIndex $cols @('ProcessId', 'Pid')
            $idxXfer = Get-CsvColIndex $cols @('TransferSize')
            $counts = @{}
            $diskAgg = @{}
            while (($line = $reader.ReadLine()) -ne $null) {
              if ($line.Length -lt 10) { continue }
              $cells = Split-CsvLine $line
              $evName = ''
              if ($idxName -ge 0 -and $idxName -lt $cells.Count) { $evName = [string]$cells[$idxName] }
              if (-not $evName) { continue }
              if ($counts.ContainsKey($evName)) { $counts[$evName]++ } else { $counts[$evName] = 1 }
              if ($idxXfer -ge 0 -and $idxPid -ge 0 -and $evName -match '(?i)^disk') {
                $xfer = [int64]0
                $pid = 0
                if ($idxXfer -lt $cells.Count) { [void][int64]::TryParse([string]$cells[$idxXfer], [ref]$xfer) }
                if ($idxPid -lt $cells.Count) { [void][int32]::TryParse([string]$cells[$idxPid], [ref]$pid) }
                $op = ''
                if ($idxOp -ge 0 -and $idxOp -lt $cells.Count) { $op = [string]$cells[$idxOp] }
                if (-not $diskAgg.ContainsKey($pid)) {
                  $diskAgg[$pid] = [ordered]@{ ReadBytes = [int64]0; WriteBytes = [int64]0; OtherBytes = [int64]0 }
                }
                if ($op -match '(?i)read') { $diskAgg[$pid].ReadBytes += $xfer }
                elseif ($op -match '(?i)write') { $diskAgg[$pid].WriteBytes += $xfer }
                else { $diskAgg[$pid].OtherBytes += $xfer }
              }
            }
            $total = [int64]0
            foreach ($k in $counts.Keys) { $total += [int64]$counts[$k] }
            $digest.TotalEvents = $total
            foreach ($k in ($counts.Keys | Sort-Object)) {
              $digest.EventCounts[$k] = $counts[$k]
            }
            $diskRows = @()
            foreach ($k in $diskAgg.Keys) {
              $d = $diskAgg[$k]
              $diskRows += New-Object psobject -Property ([ordered]@{
                Pid = $k
                ReadBytes = $d.ReadBytes
                WriteBytes = $d.WriteBytes
                OtherBytes = $d.OtherBytes
                TotalBytes = ($d.ReadBytes + $d.WriteBytes + $d.OtherBytes)
              })
            }
            $digest.DiskByProcess = @($diskRows | Sort-Object TotalBytes -Descending | Select-Object -First 10)
          }
        } finally {
          $reader.Dispose()
        }
      } catch {
        Add-Issue "ETW digest CSV parse: $($_.Exception.Message)"
      }
    }
    if ($digest.TotalEvents -eq 0 -and $digest.SummaryText) {
      $mW = [regex]::Match([string]$digest.SummaryText, '(?im)^\s*events?\s+written\s*[:=]?\s*(\d+)')
      if ($mW.Success) { $digest.TotalEvents = [int]$mW.Groups[1].Value }
    }

    if ($KeepEtl) {
      $digest.EtlKept = $true
      $digest.EtlPath = $etl
    } else {
      try { Remove-Item -LiteralPath $etl -Force -ErrorAction Stop } catch { }
    }
    try { Remove-Item -LiteralPath $csv -Force -ErrorAction Stop } catch { }
    try { Remove-Item -LiteralPath $sum -Force -ErrorAction Stop } catch { }
    return $digest
  } catch {
    Add-Issue "ETW kernel trace: $($_.Exception.Message)"
    return $null
  } finally {
    if ($started) {
      Invoke-CaptureCmd -FileName 'logman.exe' -Arguments ('-stop {0} -ets' -f $session) -TimeoutMs 30000 | Out-Null
      Invoke-CaptureCmd -FileName 'logman.exe' -Arguments ('-delete {0} -ets' -f $session) -TimeoutMs 30000 | Out-Null
    }
  }
}

function Collect-KernelSurface {
  param(
    [bool]$IsAdmin,
    [bool]$SkipKernelTrace = $false,
    [int]$KernelTraceSeconds = 15,
    [bool]$KeepEtl = $false,
    [string]$OutDir = '',
    [bool]$KernelTraceDeep = $false
  )
  if ($KernelTraceSeconds -lt 5) { $KernelTraceSeconds = 5 }
  if ($KernelTraceSeconds -gt 120) { $KernelTraceSeconds = 120 }

  $kernel = [ordered]@{}

  # Facts
  $facts = [ordered]@{}
  $nt = Join-Path $env:WINDIR 'System32\ntoskrnl.exe'
  try {
    $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($nt)
    $facts.NtoskrnlPath = $nt
    $facts.NtoskrnlVersion = $vi.FileVersion
  } catch { }
  $kernel.Facts = $facts

  # Loaded kernel modules (no admin needed on Win10/11)
  $mods = Get-KernelModuleRows
  $totalModBytes = [int64]0
  foreach ($m in $mods) { $totalModBytes += [int64]$m.Size }
  $kernel.Modules = $mods
  $kernel.TotalModuleBytes = $totalModBytes

  # Pool tags (admin usually required)
  $pools = Get-PoolTagRows
  $totalPoolBytes = [int64]0
  foreach ($p in $pools) { $totalPoolBytes += [int64]$p.TotalBytes }
  $kernel.PoolTags = $pools
  $kernel.PoolTotalBytes = $totalPoolBytes

  # Kernel performance counters (no admin needed)
  $kernel.Counters = Get-KernelCounterSamples

  # Registered kernel drivers (no admin needed)
  $kernel.Drivers = Get-KernelDriverRows

  # Minifilter stack (admin usually required)
  $flt = Get-MinifilterRows
  if ($null -eq $flt) { $flt = @{ Rows = @(); Raw = $null } }
  $kernel.Minifilters = $flt.Rows
  $kernel.MinifilterRaw = $flt.Raw

  # Kernel-side process list, perf info, per-core CPU times (kernel reads)
  $kernel.KernelProcesses = Get-KernelProcessRows
  $perf = Get-KernelPerfInfo
  if ($perf) {
    $perf.ProcessCount = $kernel.KernelProcesses.Count
    $tc = [int64]0
    foreach ($kp in $kernel.KernelProcesses) { $tc += [int64]$kp.Threads }
    $perf.ThreadCount = $tc
  }
  $kernel.PerfInfo = $perf
  $kernel.PerCore = Get-ProcessorPerfRows

  # Short ETW kernel trace (admin)
  if ($SkipKernelTrace) {
    $kernel.EtlDigest = $null
  } else {
    $kernel.EtlDigest = Invoke-KernelEtlDigest -IsAdmin $IsAdmin -Seconds $KernelTraceSeconds -OutDir $OutDir -KeepEtl $KeepEtl -Deep $KernelTraceDeep
  }

  return $kernel
}

function Write-KernelSurfaceMarkdown {
  param($Sb, $Kernel, [hashtable]$PidNameLookup)
  if ($null -eq $Kernel) { return }

  [void]$Sb.AppendLine("## Kernel surface")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine("Read-only kernel-level telemetry: loaded kernel modules, pool tags, kernel counters, registered kernel drivers, the minifilter stack, and a short ETW trace of the NT kernel logger (process/image/disk). Nothing is installed or changed.")
  [void]$Sb.AppendLine()

  if ($Kernel.Facts -and $Kernel.Facts.Count -gt 0) {
    [void]$Sb.AppendLine("### Kernel facts")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine("| Field | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    foreach ($k in $Kernel.Facts.Keys) {
      [void]$Sb.AppendLine("| $(Escape-MdCell $k) | $(Escape-MdCell $Kernel.Facts[$k]) |")
    }
    [void]$Sb.AppendLine()
  }

  if ($Kernel.PerfInfo) {
    [void]$Sb.AppendLine("### Kernel performance information (read directly from the kernel)")
    [void]$Sb.AppendLine()
    $pageSize = 4096
    $perfRows = @(
      (New-Object psobject -Property ([ordered]@{ Metric = 'Process count (kernel list)'; Value = $Kernel.PerfInfo.ProcessCount })),
      (New-Object psobject -Property ([ordered]@{ Metric = 'Thread count (kernel list)'; Value = $Kernel.PerfInfo.ThreadCount })),
      (New-Object psobject -Property ([ordered]@{ Metric = 'Available pages'; Value = $Kernel.PerfInfo.AvailablePages })),
      (New-Object psobject -Property ([ordered]@{ Metric = 'Committed pages'; Value = $Kernel.PerfInfo.CommittedPages })),
      (New-Object psobject -Property ([ordered]@{ Metric = 'Commit limit (pages)'; Value = $Kernel.PerfInfo.CommitLimitPages })),
      (New-Object psobject -Property ([ordered]@{ Metric = 'Page faults (cumulative)'; Value = $Kernel.PerfInfo.PageFaultCount })),
      (New-Object psobject -Property ([ordered]@{ Metric = 'Paged pool'; Value = (Format-Bytes $Kernel.PerfInfo.PagedPoolBytes) })),
      (New-Object psobject -Property ([ordered]@{ Metric = 'Nonpaged pool'; Value = (Format-Bytes $Kernel.PerfInfo.NonPagedPoolBytes) }))
    )
    Write-MdTable $Sb @('Metric', 'Value') $perfRows @('Metric', 'Value')
  }

  if ($Kernel.PerCore -and $Kernel.PerCore.Count -gt 0) {
    [void]$Sb.AppendLine("### Per-logical-core CPU time shares (since boot)")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('Core', 'Idle%', 'Privileged%', 'User%', 'DPC%', 'Interrupt%', 'Interrupts') $Kernel.PerCore @('Core', 'IdlePct', 'PrivilegedPct', 'UserPct', 'DpcPct', 'InterruptPct', 'Interrupts')
  }

  if ($Kernel.Modules -and $Kernel.Modules.Count -gt 0) {
    [void]$Sb.AppendLine("### Loaded kernel modules ($($Kernel.Modules.Count) total, $(Format-Bytes $Kernel.TotalModuleBytes))")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine("Top 40 by image size. This is what the kernel actually has mapped; a loaded driver shows up here even if its process is hidden from the process list.")
    [void]$Sb.AppendLine()
    $modView = @($Kernel.Modules | Sort-Object Size -Descending | Select-Object -First 40) | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Module = $_.Name
        Size = (Format-Bytes $_.Size)
        LoadOrder = $_.LoadOrder
      })
    }
    Write-MdTable $Sb @('Module', 'Size', 'LoadOrder') $modView @('Module', 'Size', 'LoadOrder')
    if ($Kernel.Modules.Count -gt 40) {
      [void]$Sb.AppendLine("_... and $($Kernel.Modules.Count - 40) more modules (all in JSON)._")
      [void]$Sb.AppendLine()
    }
  }

  if ($Kernel.PoolTags -and $Kernel.PoolTags.Count -gt 0) {
    [void]$Sb.AppendLine("### Kernel pool by tag (top 25, $(Format-Bytes $Kernel.PoolTotalBytes) total)")
    [void]$Sb.AppendLine()
    $poolView = @($Kernel.PoolTags | Sort-Object TotalBytes -Descending | Select-Object -First 25) | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Tag = $_.Tag
        Paged = (Format-Bytes $_.PagedUsed)
        NonPaged = (Format-Bytes $_.NonPagedUsed)
        Total = (Format-Bytes $_.TotalBytes)
      })
    }
    Write-MdTable $Sb @('Tag', 'Paged', 'NonPaged', 'Total') $poolView @('Tag', 'Paged', 'NonPaged', 'Total')
    if ($Kernel.PoolTags.Count -gt 25) {
      [void]$Sb.AppendLine("_... and $($Kernel.PoolTags.Count - 25) more tags (all in JSON)._")
      [void]$Sb.AppendLine()
    }
  }

  if ($Kernel.Counters -and $Kernel.Counters.Count -gt 0) {
    [void]$Sb.AppendLine("### Kernel performance counters (sampled)")
    [void]$Sb.AppendLine()
    $cntView = @()
    foreach ($k in $Kernel.Counters.Keys) {
      $cntView += New-Object psobject -Property ([ordered]@{
        Counter = $k
        Value = $Kernel.Counters[$k]
      })
    }
    Write-MdTable $Sb @('Counter', 'Value') $cntView @('Counter', 'Value')
  }

  if ($Kernel.Drivers -and $Kernel.Drivers.Count -gt 0) {
    [void]$Sb.AppendLine("### Registered kernel drivers ($($Kernel.Drivers.Count))")
    [void]$Sb.AppendLine()
    $startCounts = $Kernel.Drivers | Group-Object StartMode | ForEach-Object { "$($_.Name)=$($_.Count)" }
    [void]$Sb.AppendLine("Start types: $(($startCounts -join ', ')). Third-party rows first; cap 250 rows in Markdown (all in JSON).")
    [void]$Sb.AppendLine()
    $drvView = @($Kernel.Drivers | Sort-Object @{ Expression = { if ($_.Company -and $_.Company -match '(?i)Microsoft') { 1 } else { 0 } } }, StartMode, Name | Select-Object -First 250) | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Name = $_.Name
        State = $_.State
        Start = $_.StartMode
        Company = $_.Company
        Version = $_.Version
        Path = $_.PathName
      })
    }
    Write-MdTable $Sb @('Name', 'State', 'Start', 'Company', 'Version', 'Path') $drvView @('Name', 'State', 'Start', 'Company', 'Version', 'Path')
    if ($Kernel.Drivers.Count -gt 250) {
      [void]$Sb.AppendLine("_... and $($Kernel.Drivers.Count - 250) more drivers (all in JSON)._")
      [void]$Sb.AppendLine()
    }
  }

  if ($Kernel.Minifilters -and $Kernel.Minifilters.Count -gt 0) {
    [void]$Sb.AppendLine("### Minifilter stack (filter manager order)")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('Name', 'Instances', 'Altitude', 'Frame') $Kernel.Minifilters @('Name', 'Instances', 'Altitude', 'Frame')
  } elseif ($Kernel.MinifilterRaw) {
    [void]$Sb.AppendLine("### Minifilter stack (raw)")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine('```')
    [void]$Sb.AppendLine($Kernel.MinifilterRaw)
    [void]$Sb.AppendLine('```')
  }

  if ($Kernel.KernelProcesses -and $Kernel.KernelProcesses.Count -gt 0) {
    [void]$Sb.AppendLine("### Kernel-side process list ($($Kernel.KernelProcesses.Count) entries, SystemProcessInformation)")
    [void]$Sb.AppendLine()
    $kernelPids = @{}
    foreach ($kp in $Kernel.KernelProcesses) {
      try { $kernelPids[[int]$kp.Pid] = $true } catch { }
    }
    $kernelOnly = @($Kernel.KernelProcesses | Where-Object {
        $null -eq $PidNameLookup -or -not $PidNameLookup.ContainsKey([int]$_.Pid)
      })
    $userOnlyCount = 0
    if ($PidNameLookup) {
      foreach ($k in $PidNameLookup.Keys) {
        if (-not $kernelPids.ContainsKey([int]$k)) { $userOnlyCount++ }
      }
    }
    [void]$Sb.AppendLine("Third enumerator, cross-checked against CIM / Get-Process: **$($Kernel.KernelProcesses.Count)** kernel entries, **$($kernelOnly.Count)** kernel-only (not visible to usermode APIs), **$userOnlyCount** usermode-only. Kernel-only rows are usually processes in teardown (exited but not yet cleaned) or protected (PPL) entries; DKOM-hidden processes are not reachable from any of these lists, but their driver still appears in the modules table above.")
    [void]$Sb.AppendLine()
    $koView = @($kernelOnly | Select-Object -First 30) | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Pid = $_.Pid
        Name = $_.Name
        Threads = $_.Threads
        Handles = $_.Handles
        SessionId = $_.SessionId
      })
    }
    if ($koView.Count -gt 0) {
      Write-MdTable $Sb @('Pid', 'Name', 'Threads', 'Handles', 'SessionId') $koView @('Pid', 'Name', 'Threads', 'Handles', 'SessionId')
      if ($kernelOnly.Count -gt 30) {
        [void]$Sb.AppendLine("_... and $($kernelOnly.Count - 30) more kernel-only entries (all in JSON)._")
        [void]$Sb.AppendLine()
      }
    } else {
      [void]$Sb.AppendLine("No kernel-only entries: every kernel process is also visible to usermode APIs.")
      [void]$Sb.AppendLine()
    }
  }

  $digest = $Kernel.EtlDigest
  if ($digest) {
    [void]$Sb.AppendLine("### ETW kernel trace digest ($($digest.WindowSeconds)s window)")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine("NT kernel logger providers: process, image load, disk I/O$(if ($digest.Deep) { ', plus deep keywords file/network/registry/thread' } else { '' }). The raw trace may contain file and process names, so only aggregates are kept here; the .etl is deleted unless -KeepEtl was used.")
    [void]$Sb.AppendLine()
    if ($digest.Deep) {
      [void]$Sb.AppendLine("Deep mode was on: the trace also contains file paths, registry keys and network flows. Everything stays local and is deleted with the .etl unless -KeepEtl.")
      [void]$Sb.AppendLine()
    }
    [void]$Sb.AppendLine("| Metric | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    [void]$Sb.AppendLine("| Window | $($digest.WindowSeconds) s |")
    [void]$Sb.AppendLine("| Events parsed | $($digest.TotalEvents) |")
    [void]$Sb.AppendLine("| Events lost | $($digest.EventsLost) |")
    if ($digest.EtlKept) {
      [void]$Sb.AppendLine("| Raw ETL kept | $([System.IO.Path]::GetFileName($digest.EtlPath)) |")
    }
    [void]$Sb.AppendLine()
    if ($digest.EventCounts -and $digest.EventCounts.Count -gt 0) {
      [void]$Sb.AppendLine("Event counts by type:")
      [void]$Sb.AppendLine()
      $evView = @()
      foreach ($k in ($digest.EventCounts.Keys | Sort-Object { $digest.EventCounts[$_] } -Descending | Select-Object -First 15)) {
        $evView += New-Object psobject -Property ([ordered]@{ EventType = $k; Count = $digest.EventCounts[$k] })
      }
      Write-MdTable $Sb @('EventType', 'Count') $evView @('EventType', 'Count')
    }
    if ($digest.DiskByProcess -and $digest.DiskByProcess.Count -gt 0) {
      [void]$Sb.AppendLine("Top disk I/O by process during the window:")
      [void]$Sb.AppendLine()
      $diskView = @()
      foreach ($d in $digest.DiskByProcess) {
        $pName = '?'
        if ($PidNameLookup -and $PidNameLookup.ContainsKey([int]$d.Pid)) { $pName = $PidNameLookup[[int]$d.Pid] }
        $diskView += New-Object psobject -Property ([ordered]@{
          Process = $pName
          Pid = $d.Pid
          Read = (Format-Bytes $d.ReadBytes)
          Write = (Format-Bytes $d.WriteBytes)
          Other = (Format-Bytes $d.OtherBytes)
          Total = (Format-Bytes $d.TotalBytes)
        })
      }
      Write-MdTable $Sb @('Process', 'Pid', 'Read', 'Write', 'Other', 'Total') $diskView @('Process', 'Pid', 'Read', 'Write', 'Other', 'Total')
    }
    if ($digest.SummaryText) {
      [void]$Sb.AppendLine("tracerpt summary (trimmed):")
      [void]$Sb.AppendLine()
      [void]$Sb.AppendLine('```')
      $sumLines = @([string]$digest.SummaryText -split "`r?`n" | Select-Object -First 60)
      foreach ($ln in $sumLines) { [void]$Sb.AppendLine($ln) }
      if ((@([string]$digest.SummaryText -split "`r?`n")).Count -gt 60) {
        [void]$Sb.AppendLine("... (summary trimmed)")
      }
      [void]$Sb.AppendLine('```')
      [void]$Sb.AppendLine()
    }
  } elseif ($Kernel.Contains('EtlDigest') -and $null -eq $Kernel.EtlDigest) {
    [void]$Sb.AppendLine("_ETW kernel trace skipped (-SkipKernelTrace or needs Administrator)._")
    [void]$Sb.AppendLine()
  }

  [void]$Sb.AppendLine("Kernel-surface limits: hidden processes stay out of reach as processes, but every loaded kernel module is enumerated, so a driver cannot hide from this section. Pool tags and modules require an elevated run (Run-Snapshot.bat).")
  [void]$Sb.AppendLine()
}
