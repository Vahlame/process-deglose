#requires -Version 5.1
<#
.SYNOPSIS
  Read-only Windows 10/11 inventory for another agent to propose universal, conditional tweaks.
  Writes a Markdown report (and JSON bulk). Does not change Windows.
#>
[CmdletBinding()]
param(
  [string]$OutDir,
  [switch]$NoJson,
  [switch]$SkipSignature,
  [switch]$SkipNetwork,
  [switch]$SkipTasks,
  [switch]$SkipHeavy,
  [switch]$NoExplorer,
  [switch]$SkipKernel,
  [switch]$SkipKernelTrace,
  [int]$KernelTraceSeconds = 15,
  [switch]$KeepEtl,
  [switch]$KernelTraceDeep,
  [switch]$Help
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$script:ToolVersion = '2.3.0'
$script:StartedUtc = [datetime]::UtcNow
$script:Issues = New-Object System.Collections.Generic.List[string]

if ($Help) {
@'
process-deglose v2.3.0 - inventario read-only de Windows 10/11 (sin cambios en el sistema)

USO
  powershell -NoProfile -ExecutionPolicy Bypass -File snapshot.ps1 [opciones]

OPCIONES
  -OutDir <ruta>          Carpeta de salida (default: Desktop)
  -SkipSignature          Mas rapido (no verifica firmas digitales)
  -SkipNetwork            Salta conexiones TCP
  -SkipTasks              Salta tareas programadas
  -SkipHeavy              Salta Uninstall + AppX
  -SkipKernel             Salta toda la superficie kernel
  -SkipKernelTrace        Salta solo la traza ETW del kernel
  -KernelTraceSeconds N   Duracion de la traza ETW (5-120, default 15)
  -KernelTraceDeep        ETW con keywords file/network/registry/thread
  -KeepEtl                Conserva el .etl crudo en la carpeta de reporte
  -NoJson                 No escribe el JSON bulk
  -NoExplorer             No abre la carpeta al terminar
  -Help                   Muestra esta ayuda

Docs: https://github.com/Vahlame/process-deglose
'@ | Write-Host
  exit 0
}

function Add-Issue {
  param([string]$Message)
  [void]$script:Issues.Add($Message)
}

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-Utf8Bom {
  return New-Object System.Text.UTF8Encoding $true
}

function Format-Bytes {
  param([Nullable[int64]]$Value)
  if ($null -eq $Value -or $Value -lt 0) { return 'n/a' }
  $units = @('B', 'KB', 'MB', 'GB', 'TB')
  $v = [double]$Value
  $i = 0
  while ($v -ge 1024 -and $i -lt 4) {
    $v = $v / 1024
    $i++
  }
  return ('{0:N2} {1}' -f $v, $units[$i])
}

function Format-KbToBytes {
  param($Kb)
  if ($null -eq $Kb) { return $null }
  try { return [int64]$Kb * 1024 } catch { return $null }
}

function Convert-FileTime100ns {
  param($Ticks100ns)
  if ($null -eq $Ticks100ns) { return $null }
  try {
    $ts = [TimeSpan]::FromTicks([int64]$Ticks100ns)
    return ('{0:d}d {1:hh\:mm\:ss\.fff}' -f $ts.Days, $ts)
  } catch {
    return [string]$Ticks100ns
  }
}

function Protect-CommandLine {
  param([string]$Text)
  if ([string]::IsNullOrEmpty($Text)) { return $Text }
  $t = [regex]::Replace($Text, '(?i)(password|passwd|pwd|token|apikey|api[_-]?key|secret|authorization|bearer|connstr|connectionstring)\s*[=:]\s*\S+', '$1=***REDACTED***')
  $t = [regex]::Replace($t, '(?i)(--?(password|token|secret|apikey))\s+\S+', '$1 ***REDACTED***')
  return $t
}

function Escape-MdCell {
  param($Value)
  if ($null -eq $Value) { return '' }
  $s = [string]$Value
  $s = $s -replace "`r`n", ' ' -replace "`n", ' ' -replace "`r", ' '
  $s = $s -replace '\|', '/'
  if ($s.Length -gt 400) { $s = $s.Substring(0, 397) + '...' }
  return $s
}

function Get-CimProp {
  param($Object, [string]$Name)
  if ($null -eq $Object) { return $null }
  try {
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
  } catch {
    return $null
  }
}

function Get-RegValue {
  param([string]$RegPath, [string]$Name, $Default = $null)
  try {
    if (-not (Test-Path -LiteralPath $RegPath)) { return $Default }
    $item = Get-Item -LiteralPath $RegPath -ErrorAction Stop
    $v = $item.GetValue($Name)
    if ($null -eq $v) { return $Default }
    if ($v -is [byte[]]) {
      return (($v | ForEach-Object { $_.ToString('X2') }) -join '')
    }
    return $v
  } catch {
    return $Default
  }
}

function Invoke-CaptureCmd {
  param(
    [Parameter(Mandatory = $true)][string]$FileName,
    [string]$Arguments = '',
    [int]$TimeoutMs = 20000
  )
  try {
    if (-not (Test-Path -LiteralPath $FileName)) {
      $cmd = Get-Command $FileName -ErrorAction SilentlyContinue
      if ($cmd -and $cmd.Source) { $FileName = $cmd.Source } else { return $null }
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FileName
    $psi.Arguments = $Arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    if (-not $proc.WaitForExit($TimeoutMs)) {
      try { $proc.Kill() } catch { }
      Add-Issue ("Timeout {0} {1}" -f $FileName, $Arguments)
      return $null
    }
    $out = $proc.StandardOutput.ReadToEnd()
    $err = $proc.StandardError.ReadToEnd()
    if ($err) { return ($out + "`n" + $err) }
    return $out
  } catch {
    Add-Issue ("Invoke-CaptureCmd {0}: {1}" -f $FileName, $_.Exception.Message)
    return $null
  }
}

function Get-PathClass {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return 'unknown' }
  $n = $Path.ToLowerInvariant()
  $win = $env:WINDIR
  if ($win) {
    $w = $win.ToLowerInvariant()
    if ($n.StartsWith($w + '\system32') -or $n.StartsWith($w + '\syswow64') -or $n.StartsWith($w + '\winsxs') -or $n.StartsWith($w + '\systemapps')) {
      return 'windows-core'
    }
    if ($n.StartsWith($w)) { return 'windows' }
  }
  $pf = $env:ProgramFiles
  if ($pf -and $n.StartsWith($pf.ToLowerInvariant() + '\windowsapps')) { return 'store-uwp' }
  if ($pf -and $n.StartsWith($pf.ToLowerInvariant() + '\microsoft')) { return 'microsoft-app' }
  if ($pf -and $n.StartsWith($pf.ToLowerInvariant())) { return 'program-files' }
  $pf86 = ${env:ProgramFiles(x86)}
  if ($pf86 -and $n.StartsWith($pf86.ToLowerInvariant() + '\microsoft')) { return 'microsoft-app' }
  if ($pf86 -and $n.StartsWith($pf86.ToLowerInvariant())) { return 'program-files-x86' }
  $userProfile = $env:USERPROFILE
  if ($userProfile -and $n.StartsWith($userProfile.ToLowerInvariant() + '\appdata')) { return 'appdata' }
  return 'other'
}

function Test-LikelyMicrosoft {
  param([string]$Path, [string]$Company, [string]$PathClass)
  if ($PathClass -eq 'windows-core' -or $PathClass -eq 'windows') { return $true }
  if ($Company -and $Company -match 'Microsoft') { return $true }
  if ($Path -and $Path -match '(?i)\\WindowsApps\\Microsoft') { return $true }
  if ($PathClass -eq 'microsoft-app') { return $true }
  return $false
}

function Get-IntegrityHint {
  param([string]$PathClass, [string]$Name, [string]$ServiceNames)
  $n = ''
  if ($Name) { $n = $Name.ToLowerInvariant() }
  $svc = ''
  if ($ServiceNames) { $svc = $ServiceNames.ToLowerInvariant() }
  $blob = $n + ' ' + $svc
  if ($blob -match 'windefend|msmpeng|sense|wdnis|securityhealth|mpdefender') { return 'security-av' }
  if ($blob -match 'csrss|smss|wininit|winlogon|lsass|services|svchost|lsm|dwm|fontdrvhost') { return 'os-critical' }
  if ($PathClass -eq 'windows-core') { return 'os-core' }
  if ($PathClass -eq 'windows' -or $PathClass -eq 'microsoft-app') { return 'microsoft' }
  if ($PathClass -eq 'store-uwp') { return 'store-app' }
  if ($PathClass -eq 'appdata') { return 'user-app' }
  if ($PathClass -eq 'unknown') { return 'unknown' }
  return 'third-party'
}

if (-not ('NativeProcSnapshot' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class NativeProcSnapshot {
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool CloseHandle(IntPtr h);
  public static string ImagePath(int pid) {
    IntPtr h = OpenProcess(0x1000, false, pid);
    if (h == IntPtr.Zero) return null;
    try {
      StringBuilder sb = new StringBuilder(1024);
      int size = sb.Capacity;
      if (QueryFullProcessImageName(h, 0, sb, ref size)) return sb.ToString();
      return null;
    } finally { CloseHandle(h); }
  }
}
'@
}

function Get-NativeImage {
  param([int]$ProcessId)
  try { return [NativeProcSnapshot]::ImagePath($ProcessId) } catch { return $null }
}

function Get-FileMeta {
  param([string]$Path)
  $meta = [ordered]@{
    Company = $null
    Description = $null
    Product = $null
    FileVersion = $null
    ProductVersion = $null
    OriginalFilename = $null
  }
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $meta }
  try {
    $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $meta.Company = $vi.CompanyName
    $meta.Description = $vi.FileDescription
    $meta.Product = $vi.ProductName
    $meta.FileVersion = $vi.FileVersion
    $meta.ProductVersion = $vi.ProductVersion
    $meta.OriginalFilename = $vi.OriginalFilename
  } catch {
    Add-Issue "FileVersionInfo failed for $Path : $($_.Exception.Message)"
  }
  return $meta
}

function Get-SignatureCached {
  param([string]$Path, [hashtable]$Cache)
  if ([string]::IsNullOrWhiteSpace($Path)) {
    return [ordered]@{ Status = 'no-path'; Signer = $null; TimeStamper = $null }
  }
  $key = $Path.ToLowerInvariant()
  if ($Cache.ContainsKey($key)) { return $Cache[$key] }
  $row = [ordered]@{ Status = 'unchecked'; Signer = $null; TimeStamper = $null }
  if ($SkipSignature) {
    $row.Status = 'skipped'
    $Cache[$key] = $row
    return $row
  }
  if (-not (Test-Path -LiteralPath $Path)) {
    $row.Status = 'missing-file'
    $Cache[$key] = $row
    return $row
  }
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    $row.Status = [string]$sig.Status
    if ($sig.SignerCertificate) { $row.Signer = $sig.SignerCertificate.Subject }
    if ($sig.TimeStamperCertificate) { $row.TimeStamper = $sig.TimeStamperCertificate.Subject }
  } catch {
    $row.Status = 'error'
    Add-Issue "Signature failed for $Path : $($_.Exception.Message)"
  }
  $Cache[$key] = $row
  return $row
}

# --- output paths ---
function Get-DesktopPath {
  $p = [Environment]::GetFolderPath('Desktop')
  if ([string]::IsNullOrWhiteSpace($p) -or -not (Test-Path -LiteralPath $p)) {
    $p = Join-Path $env:USERPROFILE 'Desktop'
  }
  return $p
}

function Install-DesktopShortcut {
  $desktop = Get-DesktopPath
  $lnk = Join-Path $desktop 'Process snapshot for AI.lnk'
  $bat = Join-Path $PSScriptRoot 'Run-Snapshot.bat'
  if (-not (Test-Path -LiteralPath $bat)) { return }
  try {
    $w = New-Object -ComObject WScript.Shell
    $s = $w.CreateShortcut($lnk)
    $s.TargetPath = $bat
    $s.WorkingDirectory = $PSScriptRoot
    $s.WindowStyle = 1
    $s.Description = 'Read-only Windows inventory. Creates a Desktop folder with reports for another AI.'
    $s.IconLocation = "$env:SystemRoot\System32\imageres.dll,109"
    $s.Save()
  } catch {
    Add-Issue "Desktop shortcut: $($_.Exception.Message)"
  }
}

$stamp = $script:StartedUtc.ToLocalTime().ToString('yyyyMMdd-HHmmss')
$hostShort = $env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($OutDir)) {
  $OutDir = Join-Path (Get-DesktopPath) ("process-deglose-report-{0}-{1}" -f $hostShort, $stamp)
}
if (-not (Test-Path -LiteralPath $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}
$mdPath = Join-Path $OutDir ("snapshot-{0}-{1}.md" -f $hostShort, $stamp)
$jsonPath = Join-Path $OutDir ("snapshot-{0}-{1}.json" -f $hostShort, $stamp)
Install-DesktopShortcut

$isAdmin = Test-IsAdmin
Write-Host "Process inventory snapshot v$($script:ToolVersion)"
Write-Host "Admin: $isAdmin  Out: $mdPath"

# --- machine / RAM ---
Write-Host '[1/14] Machine and RAM...'
$os = $null
$cs = $null
$cpus = @()
$sticks = @()
$pagefiles = @()
try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { Add-Issue "Win32_OperatingSystem: $($_.Exception.Message)" }
try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch { Add-Issue "Win32_ComputerSystem: $($_.Exception.Message)" }
try { $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop) } catch { Add-Issue "Win32_Processor: $($_.Exception.Message)" }
try { $sticks = @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop) } catch { Add-Issue "Win32_PhysicalMemory: $($_.Exception.Message)" }
try { $pagefiles = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop) } catch { Add-Issue "Win32_PageFileUsage: $($_.Exception.Message)" }

$ramInstalled = [int64]0
foreach ($s in $sticks) {
  if ($s.Capacity) { $ramInstalled += [int64]$s.Capacity }
}
$ramUsable = $null
$ramFree = $null
$ramTotalVirt = $null
$ramFreeVirt = $null
if ($cs -and $cs.TotalPhysicalMemory) { $ramUsable = [int64]$cs.TotalPhysicalMemory }
if ($os) {
  $ramFree = Format-KbToBytes $os.FreePhysicalMemory
  $ramTotalVirt = Format-KbToBytes $os.TotalVirtualMemorySize
  $ramFreeVirt = Format-KbToBytes $os.FreeVirtualMemory
  if (-not $ramUsable) { $ramUsable = Format-KbToBytes $os.TotalVisibleMemorySize }
}

$memCounters = @{}
try {
  $pm = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop
  $memCounters['AvailableMBytes'] = $pm.AvailableMBytes
  $memCounters['CommittedBytes'] = $pm.CommittedBytes
  $memCounters['CommitLimit'] = $pm.CommitLimit
  $memCounters['PoolPagedBytes'] = $pm.PoolPagedBytes
  $memCounters['PoolNonpagedBytes'] = $pm.PoolNonpagedBytes
  $memCounters['CacheBytes'] = $pm.CacheBytes
  $memCounters['PercentCommittedBytesInUse'] = $pm.PercentCommittedBytesInUse
} catch {
  Add-Issue "Win32_PerfFormattedData_PerfOS_Memory: $($_.Exception.Message)"
}

# --- processes from CIM + Get-Process + native path ---
Write-Host '[2/14] Processes (CIM + Get-Process)...'
$cimProcs = @()
try { $cimProcs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop) } catch { Add-Issue "Win32_Process: $($_.Exception.Message)" }

$gpList = @()
$gpById = @{}
try {
  if ($isAdmin) {
    try {
      $gpList = @(Get-Process -IncludeUserName -ErrorAction Stop)
    } catch {
      Add-Issue "Get-Process -IncludeUserName failed, falling back: $($_.Exception.Message)"
      $gpList = @(Get-Process -ErrorAction Stop)
    }
  } else {
    $gpList = @(Get-Process -ErrorAction Stop)
  }
  foreach ($g in $gpList) { $gpById[[int]$g.Id] = $g }
} catch {
  Add-Issue "Get-Process: $($_.Exception.Message)"
}

$svcCim = @()
try { $svcCim = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop) } catch { Add-Issue "Win32_Service: $($_.Exception.Message)" }
$svcByPid = @{}
foreach ($sv in $svcCim) {
  $spid = 0
  try { $spid = [int]$sv.ProcessId } catch { continue }
  if ($spid -le 0) { continue }
  if (-not $svcByPid.ContainsKey($spid)) { $svcByPid[$spid] = New-Object System.Collections.Generic.List[string] }
  [void]$svcByPid[$spid].Add([string]$sv.Name)
}

$owners = @{}
Write-Host '       owners...'
foreach ($cp in $cimProcs) {
  $pidVal = 0
  try { $pidVal = [int]$cp.ProcessId } catch { continue }
  try {
    $ow = Invoke-CimMethod -InputObject $cp -MethodName GetOwner -ErrorAction SilentlyContinue
    if ($ow -and $ow.ReturnValue -eq 0) {
      $dom = $ow.Domain
      $user = $ow.User
      if ($dom) { $owners[$pidVal] = "$dom\$user" } else { $owners[$pidVal] = [string]$user }
    }
  } catch { }
}

$sigCache = @{}
$metaCache = @{}
$rows = @()
$cimPidSet = @{}
$gpPidSet = @{}

foreach ($g in $gpList) {
  try { $gpPidSet[[int]$g.Id] = $true } catch { }
}

foreach ($cp in $cimProcs) {
  $pidVal = 0
  try { $pidVal = [int]$cp.ProcessId } catch { continue }
  $cimPidSet[$pidVal] = $true
  $g = $null
  if ($gpById.ContainsKey($pidVal)) { $g = $gpById[$pidVal] }

  $path = [string]$cp.ExecutablePath
    if ([string]::IsNullOrWhiteSpace($path)) { $path = Get-NativeImage -ProcessId $pidVal }
    if ([string]::IsNullOrWhiteSpace($path) -and $g -and $g.Path) { $path = [string]$g.Path }

  $pathKey = ''
  if ($path) { $pathKey = $path.ToLowerInvariant() }
  $meta = $null
  if ($pathKey -and $metaCache.ContainsKey($pathKey)) {
    $meta = $metaCache[$pathKey]
  } else {
    $meta = Get-FileMeta -Path $path
    if ($pathKey) { $metaCache[$pathKey] = $meta }
  }
  $sig = Get-SignatureCached -Path $path -Cache $sigCache

  $ws = $null
  $priv = $null
  $virt = $null
  $peakWs = $null
  $handles = $null
  $threads = $null
  $cpuSec = $null
  $responding = $null
  $title = $null
  $sessionId = $null
  $startTime = $null
  $userName = $null
  $mainHwnd = 0
  $moduleCount = $null

  if ($cp.WorkingSetSize -ne $null) { $ws = [int64]$cp.WorkingSetSize }
  if ($g) {
    try { if ($g.WorkingSet64) { $ws = [int64]$g.WorkingSet64 } } catch { }
    try { $priv = [int64]$g.PrivateMemorySize64 } catch { }
    try { $virt = [int64]$g.VirtualMemorySize64 } catch { }
    try { $peakWs = [int64]$g.PeakWorkingSet64 } catch { }
    try { $handles = [int]$g.HandleCount } catch { }
    try { $threads = @($g.Threads).Count } catch { }
    try { if ($null -ne $g.CPU) { $cpuSec = [double]$g.CPU } } catch { }
    try { $responding = [bool]$g.Responding } catch { }
    try { $title = [string]$g.MainWindowTitle } catch { }
    try { $sessionId = [int]$g.SessionId } catch { }
    try { $startTime = $g.StartTime } catch { }
    try { if ($g.PSObject.Properties['UserName'] -and $g.UserName) { $userName = [string]$g.UserName } } catch { }
    try { $mainHwnd = [int64]$g.MainWindowHandle } catch { }
    # Process.Modules can hang or throw on protected processes; omit on purpose.
  }
  if ($null -eq $handles -and $cp.HandleCount -ne $null) { $handles = [int]$cp.HandleCount }
  if ($null -eq $threads -and $cp.ThreadCount -ne $null) { $threads = [int]$cp.ThreadCount }
  if ($null -eq $sessionId -and $cp.SessionId -ne $null) { $sessionId = [int]$cp.SessionId }
  if ($null -eq $startTime -and $cp.CreationDate) { $startTime = $cp.CreationDate }
  if (-not $userName -and $owners.ContainsKey($pidVal)) { $userName = $owners[$pidVal] }

  $svcNames = $null
  if ($svcByPid.ContainsKey($pidVal)) { $svcNames = ($svcByPid[$pidVal] -join ', ') }

  $pclass = Get-PathClass -Path $path
  $company = $null
  if ($meta.Company) { $company = $meta.Company }
  elseif ($g -and $g.Company) { $company = [string]$g.Company }

  $desc = $null
  if ($meta.Description) { $desc = $meta.Description }
  elseif ($g -and $g.Description) { $desc = [string]$g.Description }

  $hasWindow = $false
  if ($mainHwnd -ne 0 -and $title) { $hasWindow = $true }
  elseif ($mainHwnd -ne 0) { $hasWindow = $true }

  $row = [ordered]@{
    Pid = $pidVal
    ParentPid = $(if ($cp.ParentProcessId -ne $null) { [int]$cp.ParentProcessId } else { $null })
    Name = [string]$cp.Name
    Path = $path
    PathClass = $pclass
    CommandLine = Protect-CommandLine ([string]$cp.CommandLine)
    User = $userName
    SessionId = $sessionId
    HasWindow = $hasWindow
    WindowTitle = $title
    Responding = $responding
    WorkingSetBytes = $ws
    PrivateBytes = $priv
    VirtualBytes = $virt
    PeakWorkingSetBytes = $peakWs
    PageFileKb = $(if ($cp.PageFileUsage -ne $null) { [int64]$cp.PageFileUsage } else { $null })
    HandleCount = $handles
    ThreadCount = $threads
    ModuleCount = $moduleCount
    CpuSeconds = $cpuSec
    KernelTime = Convert-FileTime100ns $cp.KernelModeTime
    UserTime = Convert-FileTime100ns $cp.UserModeTime
    PageFaults = $cp.PageFaults
    ReadBytes = $(if ($cp.ReadTransferCount -ne $null) { [int64]$cp.ReadTransferCount } else { $null })
    WriteBytes = $(if ($cp.WriteTransferCount -ne $null) { [int64]$cp.WriteTransferCount } else { $null })
    Priority = $cp.Priority
    StartTime = $(if ($startTime) { ([datetime]$startTime).ToString('o') } else { $null })
    Company = $company
    Description = $desc
    Product = $meta.Product
    FileVersion = $meta.FileVersion
    Services = $svcNames
    SignatureStatus = $sig.Status
    Signer = $sig.Signer
    LikelyMicrosoft = Test-LikelyMicrosoft -Path $path -Company $company -PathClass $pclass
    IntegrityHint = Get-IntegrityHint -PathClass $pclass -Name ([string]$cp.Name) -ServiceNames $svcNames
    SeenByCim = $true
    SeenByGetProcess = [bool]$g
  }
  $rows += New-Object psobject -Property $row
}

# Get-Process only (not in CIM) - rare
foreach ($g in $gpList) {
  $pidVal = 0
  try { $pidVal = [int]$g.Id } catch { continue }
  if ($cimPidSet.ContainsKey($pidVal)) { continue }
  $path = $null
  try { $path = [string]$g.Path } catch { }
  if ([string]::IsNullOrWhiteSpace($path)) { $path = Get-NativeImage -ProcessId $pidVal }
  $pclass = Get-PathClass -Path $path
  $meta = Get-FileMeta -Path $path
  $sig = Get-SignatureCached -Path $path -Cache $sigCache
  $company = $meta.Company
  if (-not $company) { try { $company = [string]$g.Company } catch { } }
  $row = [ordered]@{
    Pid = $pidVal
    ParentPid = $null
    Name = [string]$g.ProcessName
    Path = $path
    PathClass = $pclass
    CommandLine = $null
    User = $(try { [string]$g.UserName } catch { $null })
    SessionId = $(try { [int]$g.SessionId } catch { $null })
    HasWindow = $(try { [int64]$g.MainWindowHandle -ne 0 } catch { $false })
    WindowTitle = $(try { [string]$g.MainWindowTitle } catch { $null })
    Responding = $(try { [bool]$g.Responding } catch { $null })
    WorkingSetBytes = $(try { [int64]$g.WorkingSet64 } catch { $null })
    PrivateBytes = $(try { [int64]$g.PrivateMemorySize64 } catch { $null })
    VirtualBytes = $(try { [int64]$g.VirtualMemorySize64 } catch { $null })
    PeakWorkingSetBytes = $(try { [int64]$g.PeakWorkingSet64 } catch { $null })
    PageFileKb = $null
    HandleCount = $(try { [int]$g.HandleCount } catch { $null })
    ThreadCount = $(try { @($g.Threads).Count } catch { $null })
    ModuleCount = $null
    CpuSeconds = $(try { [double]$g.CPU } catch { $null })
    KernelTime = $null
    UserTime = $null
    PageFaults = $null
    ReadBytes = $null
    WriteBytes = $null
    Priority = $null
    StartTime = $(try { $g.StartTime.ToString('o') } catch { $null })
    Company = $company
    Description = $meta.Description
    Product = $meta.Product
    FileVersion = $meta.FileVersion
    Services = $(if ($svcByPid.ContainsKey($pidVal)) { ($svcByPid[$pidVal] -join ', ') } else { $null })
    SignatureStatus = $sig.Status
    Signer = $sig.Signer
    LikelyMicrosoft = Test-LikelyMicrosoft -Path $path -Company $company -PathClass $pclass
    IntegrityHint = Get-IntegrityHint -PathClass $pclass -Name ([string]$g.ProcessName) -ServiceNames $null
    SeenByCim = $false
    SeenByGetProcess = $true
  }
  $rows += New-Object psobject -Property $row
}

$rows = @($rows | Sort-Object { $_.WorkingSetBytes -as [int64] } -Descending)
Write-Host ("       {0} process rows" -f $rows.Count)

$onlyCim = @($rows | Where-Object { $_.SeenByCim -and -not $_.SeenByGetProcess })
$onlyGp = @($rows | Where-Object { $_.SeenByGetProcess -and -not $_.SeenByCim })

# --- services ---
Write-Host '[3/14] Services...'
$svcPs = @()
try { $svcPs = @(Get-Service -ErrorAction Stop) } catch { Add-Issue "Get-Service: $($_.Exception.Message)" }
$svcPsByName = @{}
foreach ($s in $svcPs) { $svcPsByName[$s.Name.ToLowerInvariant()] = $s }

$serviceRows = @()
foreach ($sv in $svcCim) {
  $name = [string]$sv.Name
  $ps = $null
  $lk = $name.ToLowerInvariant()
  if ($svcPsByName.ContainsKey($lk)) { $ps = $svcPsByName[$lk] }
  $startType = [string]$sv.StartMode
  if ($ps -and $ps.StartType) { $startType = [string]$ps.StartType }
  $delayed = $null
  try { $delayed = $sv.DelayedAutoStart } catch { }
  $serviceRows += New-Object psobject -Property ([ordered]@{
    Name = $name
    DisplayName = $(if ($ps) { [string]$ps.DisplayName } else { [string]$sv.Caption })
    State = [string]$sv.State
    StartType = $startType
    DelayedAutoStart = $delayed
    Account = [string]$sv.StartName
    Pid = $(if ($sv.ProcessId) { [int]$sv.ProcessId } else { 0 })
    PathName = Protect-CommandLine ([string]$sv.PathName)
    Description = [string]$sv.Description
    ExitCode = $sv.ExitCode
  })
}
$serviceRows = @($serviceRows | Sort-Object State, Name)

# --- startup ---
Write-Host '[4/14] Startup entries...'
function Get-RunKeyValues {
  param([string]$HivePath, [string]$Source)
  $list = @()
  try {
    $item = Get-Item -LiteralPath $HivePath -ErrorAction Stop
    foreach ($vn in $item.GetValueNames()) {
      $list += New-Object psobject -Property ([ordered]@{
        Source = $Source
        Name = $vn
        Command = Protect-CommandLine ([string]$item.GetValue($vn))
      })
    }
  } catch { }
  return $list
}

$startupRows = @()
$startupRows += Get-RunKeyValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'HKLM Run'
$startupRows += Get-RunKeyValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 'HKLM RunOnce'
$startupRows += Get-RunKeyValues 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' 'HKLM Run WOW64'
$startupRows += Get-RunKeyValues 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'HKCU Run'
$startupRows += Get-RunKeyValues 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 'HKCU RunOnce'
try {
  $wmiStart = @(Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop)
  foreach ($w in $wmiStart) {
    $startupRows += New-Object psobject -Property ([ordered]@{
      Source = "WMI $($w.Location)"
      Name = [string]$w.Name
      Command = Protect-CommandLine ([string]$w.Command)
    })
  }
} catch {
  Add-Issue "Win32_StartupCommand: $($_.Exception.Message)"
}
$startupDirs = @(
  (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
  (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
)
foreach ($dir in $startupDirs) {
  if (-not (Test-Path -LiteralPath $dir)) { continue }
  try {
    Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop | ForEach-Object {
      $startupRows += New-Object psobject -Property ([ordered]@{
        Source = "Folder $dir"
        Name = $_.Name
        Command = $_.FullName
      })
    }
  } catch {
    Add-Issue "Startup folder $dir : $($_.Exception.Message)"
  }
}

# --- scheduled tasks ---
$taskRows = @()
$disabledTaskCount = 0
$taskErrorCount = 0
if (-not $SkipTasks) {
  Write-Host '[5/14] Scheduled tasks...'
  $tasks = @()
  try {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
  } catch {
    Add-Issue "Get-ScheduledTask list: $($_.Exception.Message)"
  }
  foreach ($t in $tasks) {
    try {
      $st = [string]$t.State
      if ($st -eq 'Disabled') {
        $disabledTaskCount++
        continue
      }
      $execParts = New-Object System.Collections.Generic.List[string]
      if ($null -ne $t.Actions) {
        foreach ($act in @($t.Actions)) {
          if ($null -eq $act) { continue }
          $e = $null
          $a = $null
          try { $e = [string]$act.Execute } catch { }
          try { $a = [string]$act.Arguments } catch { }
          if ($a) { [void]$execParts.Add("$e $a") }
          elseif ($e) { [void]$execParts.Add($e) }
        }
      }
      $trigParts = New-Object System.Collections.Generic.List[string]
      if ($null -ne $t.Triggers) {
        foreach ($tr in @($t.Triggers)) {
          if ($null -eq $tr) { continue }
          $tn = $null
          try {
            if ($tr.CimClass) { $tn = [string]$tr.CimClass.CimClassName }
          } catch { }
          if (-not $tn) {
            try { $tn = $tr.GetType().Name } catch { $tn = 'trigger' }
          }
          [void]$trigParts.Add($tn)
        }
      }
      $userId = $null
      try {
        if ($t.Principal) { $userId = [string]$t.Principal.UserId }
      } catch { }
      $taskRows += New-Object psobject -Property ([ordered]@{
        TaskName = [string]$t.TaskName
        Path = [string]$t.TaskPath
        State = $st
        UserId = $userId
        Actions = Protect-CommandLine ($execParts -join ' | ')
        Triggers = ($trigParts -join ', ')
      })
    } catch {
      $taskErrorCount++
      $tn = '?'
      try { $tn = [string]$t.TaskName } catch { }
      Add-Issue "Scheduled task ${tn}: $($_.Exception.Message)"
    }
  }
} else {
  Write-Host '[5/14] Scheduled tasks skipped'
}

# --- network ---
$netRows = @()
if (-not $SkipNetwork) {
  Write-Host '[6/14] TCP listen/established...'
  try {
    $conns = @(Get-NetTCPConnection -State Listen, Established -ErrorAction Stop)
    foreach ($n in $conns) {
      $netRows += New-Object psobject -Property ([ordered]@{
        Pid = [int]$n.OwningProcess
        State = [string]$n.State
        LocalAddress = [string]$n.LocalAddress
        LocalPort = [int]$n.LocalPort
        RemoteAddress = [string]$n.RemoteAddress
        RemotePort = [int]$n.RemotePort
      })
    }
  } catch {
    Add-Issue "Get-NetTCPConnection: $($_.Exception.Message)"
  }
} else {
  Write-Host '[6/14] Network skipped'
}

$surface = $null
$extraPath = Join-Path $PSScriptRoot 'Collect-SystemSurface.ps1'
if (Test-Path -LiteralPath $extraPath) {
  . $extraPath
  $surface = Collect-SystemSurface -IsAdmin $isAdmin -SkipHeavy ([bool]$SkipHeavy)
} else {
  Add-Issue 'Collect-SystemSurface.ps1 missing'
}

$kernel = $null
$kernelPath = Join-Path $PSScriptRoot 'Collect-KernelSurface.ps1'
if (-not $SkipKernel) {
  if (Test-Path -LiteralPath $kernelPath) {
    . $kernelPath
    Write-Host '[11/14] Kernel surface (modules, pool, processes, counters, ETW)...'
    $kernel = Collect-KernelSurface -IsAdmin $isAdmin -SkipKernelTrace ([bool]$SkipKernelTrace) -KernelTraceSeconds $KernelTraceSeconds -KeepEtl ([bool]$KeepEtl) -OutDir $OutDir -KernelTraceDeep ([bool]$KernelTraceDeep)
  } else {
    Add-Issue 'Collect-KernelSurface.ps1 missing'
  }
} else {
  Write-Host '[11/14] Kernel surface skipped'
}

$extended = $null
$extPath = Join-Path $PSScriptRoot 'Collect-ExtendedSurface.ps1'
if (Test-Path -LiteralPath $extPath) {
  . $extPath
  Write-Host '[12/14] Extended telemetry (network, accounts, thermal)...'
  $extended = Collect-ExtendedSurface
} else {
  Add-Issue 'Collect-ExtendedSurface.ps1 missing'
}

$communication = $null
$commPath = Join-Path $PSScriptRoot 'Collect-CommunicationSurface.ps1'
if (Test-Path -LiteralPath $commPath) {
  . $commPath
  Write-Host '[13/14] Communication surface (pipes, firewall, talkers)...'
  $communication = Collect-CommunicationSurface
} else {
  Add-Issue 'Collect-CommunicationSurface.ps1 missing'
}

Write-Host '[14/14] Aggregates + Markdown...'

function Sum-Bytes {
  param($Items, [string]$Prop)
  $t = [int64]0
  foreach ($i in $Items) {
    $v = $i.$Prop
    if ($null -ne $v) {
      try { $t += [int64]$v } catch { }
    }
  }
  return $t
}

$byName = $rows | Group-Object Name | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    Name = $_.Name
    Instances = $_.Count
    WorkingSetBytes = (Sum-Bytes $_.Group 'WorkingSetBytes')
    PrivateBytes = (Sum-Bytes $_.Group 'PrivateBytes')
    Company = @($_.Group | Where-Object { $_.Company } | Select-Object -First 1 -ExpandProperty Company -ErrorAction SilentlyContinue)
    PathClass = @($_.Group | Select-Object -First 1 -ExpandProperty PathClass)
    LikelyMicrosoft = [bool](@($_.Group | Where-Object { $_.LikelyMicrosoft }).Count -gt 0)
    IntegrityHint = @($_.Group | Select-Object -First 1 -ExpandProperty IntegrityHint)
  })
} | Sort-Object WorkingSetBytes -Descending

$byClass = $rows | Group-Object PathClass | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    PathClass = $_.Name
    Processes = $_.Count
    WorkingSetBytes = (Sum-Bytes $_.Group 'WorkingSetBytes')
    PrivateBytes = (Sum-Bytes $_.Group 'PrivateBytes')
  })
} | Sort-Object WorkingSetBytes -Descending

$byHint = $rows | Group-Object IntegrityHint | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    IntegrityHint = $_.Name
    Processes = $_.Count
    WorkingSetBytes = (Sum-Bytes $_.Group 'WorkingSetBytes')
  })
} | Sort-Object WorkingSetBytes -Descending

$noWindow = @($rows | Where-Object { -not $_.HasWindow })
$session0 = @($rows | Where-Object { $_.SessionId -eq 0 })
$autoRunning = @($serviceRows | Where-Object {
    $_.State -eq 'Running' -and ($_.StartType -eq 'Auto' -or $_.StartType -eq 'Automatic' -or $_.StartType -eq 'AutomaticDelayedStart')
  })

# --- process tree ---
$byPid = @{}
foreach ($r in $rows) { $byPid[[int]$r.Pid] = $r }
$children = @{}
foreach ($r in $rows) {
  $pp = $r.ParentPid
  if ($null -eq $pp) { continue }
  $pp = [int]$pp
  if (-not $children.ContainsKey($pp)) { $children[$pp] = New-Object System.Collections.Generic.List[int] }
  [void]$children[$pp].Add([int]$r.Pid)
}

function Get-TreeLines {
  param([int]$MaxLines = 8000)
  $lines = New-Object System.Collections.Generic.List[string]
  $visited = @{}
  $roots = @()
  foreach ($r in $rows) {
    $pp = $r.ParentPid
    $isRoot = $false
    if ($null -eq $pp) { $isRoot = $true }
    elseif (-not $byPid.ContainsKey([int]$pp)) { $isRoot = $true }
    elseif ([int]$pp -eq [int]$r.Pid) { $isRoot = $true }
    if ($isRoot) { $roots += [int]$r.Pid }
  }
  $roots = @($roots | Sort-Object { if ($byPid.ContainsKey($_)) { $byPid[$_].Name } else { '' } }, { $_ })

  function Walk {
    param([int]$ProcessId, [string]$Prefix, [bool]$IsLast)
    if ($lines.Count -ge $MaxLines) { return }
    if ($visited.ContainsKey($ProcessId)) {
      [void]$lines.Add("$Prefix(cycle back to PID $ProcessId)")
      return
    }
    $visited[$ProcessId] = $true
    $branch = if ($IsLast) { '\-- ' } else { '+-- ' }
    $name = '?'
    $extra = ''
    if ($byPid.ContainsKey($ProcessId)) {
      $n = $byPid[$ProcessId]
      $name = $n.Name
      $ws = Format-Bytes $n.WorkingSetBytes
      $svc = ''
      if ($n.Services) { $svc = " services=$($n.Services)" }
      $extra = " ws=$ws user=$($n.User) sess=$($n.SessionId)$svc"
    }
    [void]$lines.Add("$Prefix$branch$name ($ProcessId)$extra")
    if (-not $children.ContainsKey($ProcessId)) { return }
    $kids = @($children[$ProcessId] | Sort-Object { if ($byPid.ContainsKey($_)) { $byPid[$_].Name } else { '' } }, { $_ })
    $nextPrefix = $Prefix + $(if ($IsLast) { '    ' } else { '|   ' })
    for ($i = 0; $i -lt $kids.Count; $i++) {
      Walk -ProcessId $kids[$i] -Prefix $nextPrefix -IsLast ($i -eq $kids.Count - 1)
    }
  }

  foreach ($root in $roots) {
    if ($lines.Count -ge $MaxLines) { break }
    Walk -ProcessId $root -Prefix '' -IsLast $true
  }
  $orphanKids = @($children.Keys | Where-Object { -not $byPid.ContainsKey([int]$_) -and $_ -ne 0 })
  foreach ($op in $orphanKids) {
    if ($lines.Count -ge $MaxLines) { break }
    [void]$lines.Add("(parent missing PID $op)")
    $kids = @($children[$op])
    for ($i = 0; $i -lt $kids.Count; $i++) {
      Walk -ProcessId $kids[$i] -Prefix '    ' -IsLast ($i -eq $kids.Count - 1)
    }
  }
  return $lines
}

$treeLines = Get-TreeLines

function Write-MdTable {
  param($Sb, [string[]]$Headers, $Objects, [string[]]$Properties)
  [void]$Sb.Append('| ')
  [void]$Sb.Append(($Headers -join ' | '))
  [void]$Sb.AppendLine(' |')
  [void]$Sb.Append('| ')
  [void]$Sb.Append((($Headers | ForEach-Object { '---' }) -join ' | '))
  [void]$Sb.AppendLine(' |')
  foreach ($o in $Objects) {
    $cells = @()
    foreach ($p in $Properties) {
      $cells += (Escape-MdCell $o.$p)
    }
    [void]$Sb.Append('| ')
    [void]$Sb.Append(($cells -join ' | '))
    [void]$Sb.AppendLine(' |')
  }
  [void]$Sb.AppendLine()
}

$sb = New-Object System.Text.StringBuilder (8MB)
$localNow = $script:StartedUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz')
$boot = $null
if ($os -and $os.LastBootUpTime) { $boot = ([datetime]$os.LastBootUpTime).ToString('o') }
$cpuName = $null
if ($cpus.Count -gt 0) { $cpuName = [string]$cpus[0].Name }

[void]$sb.AppendLine("# Windows process inventory snapshot")
[void]$sb.AppendLine()
[void]$sb.AppendLine("Generated by **process-deglose** snapshot.ps1 v$($script:ToolVersion). Read-only collector. This file is the input for another agent that may propose a debloat, RAM plan, or **universal IF-THEN performance tweaks**. This tool does not apply any change.")
[void]$sb.AppendLine()
[void]$sb.AppendLine("## Contract for the analyzing agent")
[void]$sb.AppendLine()
[void]$sb.AppendLine("Use this inventory to propose **safe, reversible** RAM and background-noise reductions, plus performance tweaks that can be reused on other PCs. Do not treat this file as permission to change the machine.")
[void]$sb.AppendLine()
[void]$sb.AppendLine("Universal means **conditional rules**, not one .reg for every computer:")
[void]$sb.AppendLine()
[void]$sb.AppendLine("- Key every recommendation on Decision facts: ChassisHint (laptop vs desktop), DiskHint (HDD vs SSD vs NVMe), GpuHint (integrated vs discrete vs hybrid), PowerHint (AC vs DC).")
[void]$sb.AppendLine("- Example shape: IF DiskHint=hdd THEN leave SysMain enabled; IF DiskHint=nvme AND ChassisHint=desktop AND PowerHint=ac THEN ...")
[void]$sb.AppendLine("- Split output into: Safe (autostart/user/visual), Needs review (3rd-party service, HAGS, power plan), Do not touch (OS core / security).")
[void]$sb.AppendLine("- Do not force Ultimate Performance on battery laptops. Do not disable SysMain on HDDs as a blanket rule.")
[void]$sb.AppendLine()
[void]$sb.AppendLine("Hard limits:")
[void]$sb.AppendLine()
[void]$sb.AppendLine("- Do not recommend disabling, stopping, or deleting processes/services whose IntegrityHint is ``os-critical`` or ``os-core``, or PathClass ``windows-core``, unless you can cite an official Microsoft optional-feature document **and** a rollback.")
[void]$sb.AppendLine("- Do not recommend Test Mode, disabling PatchGuard, unsigned kernel drivers, or turning off memory integrity / HVCI / VBS / SmartScreen / Windows Defender / VulnerableDriverBlocklist / Spectre-Meltdown FeatureSettingsOverride as a performance trick.")
[void]$sb.AppendLine("- Do not recommend bcdedit folklore (useplatformclock, disabledynamictick, tscsyncpolicy) unless the snapshot shows a specific timer issue **and** the machine is a dedicated AC-powered desktop; always include rollback.")
[void]$sb.AppendLine("- Do not recommend disabling at least: WinDefend, Sense, WdNisSvc, WinDefend related drivers, BFE, MpsSvc, RpcSs, DcomLaunch, RpcEptMapper, SamSs, LanmanWorkstation, EventLog, EventSystem, PlugPlay, Power, ProfSvc, UserManager, Schedule, BrokerInfrastructure, Dps, Winmgmt, CryptSvc, Dhcp, Dnscache, NlaSvc, nsi, netprofm, Audiosrv, AudioEndpointBuilder, WSearch only after user confirms they do not need search.")
[void]$sb.AppendLine("- Prefer user-level autostart, OEM utilities, duplicate updaters, overlays, Store suggestions, Game Bar if unused, and third-party services the user does not use.")
[void]$sb.AppendLine("- RAM savings from Working Set sums are an **upper bound** (shared pages, standby cache). Say so.")
[void]$sb.AppendLine("- If Admin was false, say coverage is incomplete and do not invent purposes for ACCESS-DENIED fields.")
[void]$sb.AppendLine("- Command lines and BIOS serials may be sensitive; do not echo them in public advice.")
[void]$sb.AppendLine("- Do not remove AppX packages marked NonRemovable or IsFramework.")
[void]$sb.AppendLine()
[void]$sb.AppendLine("## Capture metadata")
[void]$sb.AppendLine()
[void]$sb.AppendLine("| Field | Value |")
[void]$sb.AppendLine("| --- | --- |")
[void]$sb.AppendLine("| Local time | $(Escape-MdCell $localNow) |")
[void]$sb.AppendLine("| UTC | $($script:StartedUtc.ToString('o')) |")
[void]$sb.AppendLine("| Computer | $(Escape-MdCell $env:COMPUTERNAME) |")
[void]$sb.AppendLine("| User | $(Escape-MdCell $env:USERNAME) |")
[void]$sb.AppendLine("| Elevated | $isAdmin |")
[void]$sb.AppendLine("| 64-bit process | $([Environment]::Is64BitProcess) |")
[void]$sb.AppendLine("| 64-bit OS | $([Environment]::Is64BitOperatingSystem) |")
[void]$sb.AppendLine("| PowerShell | $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition) |")
[void]$sb.AppendLine("| Tool | snapshot.ps1 v$($script:ToolVersion) |")
[void]$sb.AppendLine()
[void]$sb.AppendLine("Coverage notes: usermode cannot see kernel-hidden rootkit processes; since v2.2 the kernel surface section enumerates every loaded kernel module (SystemModuleInformation), so a hidden process's driver still shows up there. Protected Process Light (PPL) images may omit path or modules. Session-0 services need elevation for full command lines. ``Get-Process`` vs CIM mismatches are listed below. Per-process loaded-module lists are not enumerated (that API hangs on protected processes); thread and handle counts are included. Kernel modules and the kernel process list work without admin; pool tags, minifilters, and the ETW trace need Administrator. The extended telemetry section (network L2/L3, accounts/groups/shares, logon sessions, thermal, battery wear, audio, monitors) and the communication section (named pipes, firewall, hosts, proxy, top talkers, services on ports) are read-only and mostly admin-free.")
[void]$sb.AppendLine()

[void]$sb.AppendLine("## TL;DR")
[void]$sb.AppendLine()
$tldrWs = Sum-Bytes $rows 'WorkingSetBytes'
$top5 = @($rows | Select-Object -First 5)
[void]$sb.AppendLine("| Campo | Valor |")
[void]$sb.AppendLine("| --- | --- |")
if ($cs) {
  [void]$sb.AppendLine("| Equipo | $(Escape-MdCell $cs.Manufacturer) $(Escape-MdCell $cs.Model) |")
}
[void]$sb.AppendLine("| CPU | $(Escape-MdCell $cpuName) |")
[void]$sb.AppendLine("| RAM | $(Format-Bytes $ramUsable) usable de $(Format-Bytes $ramInstalled) instalada |")
[void]$sb.AppendLine("| Working sets (suma) | $(Format-Bytes $tldrWs) |")
if ($surface) {
  [void]$sb.AppendLine("| Decision facts | chassis=$(Escape-MdCell $surface.ChassisHint) disk=$(Escape-MdCell $surface.DiskHint) gpu=$(Escape-MdCell $surface.GpuHint) power=$(Escape-MdCell $surface.PowerHint) |")
}
[void]$sb.AppendLine("| Procesos | $($rows.Count) (top: $((@($top5 | ForEach-Object { "$($_.Name)x$(Format-Bytes $_.WorkingSetBytes)" }) -join ', '))) |")
[void]$sb.AppendLine("| Servicios | $($serviceRows.Count) total, $($autoRunning.Count) auto en ejecucion |")
[void]$sb.AppendLine("| Red | $($netRows.Count) filas TCP |")
if ($kernel) {
  [void]$sb.AppendLine("| Kernel | $($kernel.Modules.Count) modulos cargados ($(Format-Bytes $kernel.TotalModuleBytes)), $($kernel.Drivers.Count) drivers registrados |")
}
if ($communication) {
  [void]$sb.AppendLine("| Comunicacion | $($communication.FirewallRules.Count) reglas de firewall, $($communication.NamedPipes.Count) pipes, $($communication.TopTalkers.Count) talkers |")
}
[void]$sb.AppendLine("| Problemas de coleccion | $($script:Issues.Count) |")
[void]$sb.AppendLine()
[void]$sb.AppendLine("## Machine")
[void]$sb.AppendLine()
[void]$sb.AppendLine("| Field | Value |")
[void]$sb.AppendLine("| --- | --- |")
if ($os) {
  [void]$sb.AppendLine("| OS | $(Escape-MdCell $os.Caption) |")
  [void]$sb.AppendLine("| Version | $(Escape-MdCell $os.Version) build $(Escape-MdCell $os.BuildNumber) |")
  [void]$sb.AppendLine("| Architecture | $(Escape-MdCell $os.OSArchitecture) |")
  [void]$sb.AppendLine("| Last boot | $(Escape-MdCell $boot) |")
  [void]$sb.AppendLine("| OS reported process count | $(Escape-MdCell $os.NumberOfProcesses) |")
}
if ($cs) {
  [void]$sb.AppendLine("| Manufacturer | $(Escape-MdCell $cs.Manufacturer) |")
  [void]$sb.AppendLine("| Model | $(Escape-MdCell $cs.Model) |")
  [void]$sb.AppendLine("| Logical processors | $(Escape-MdCell $cs.NumberOfLogicalProcessors) |")
  [void]$sb.AppendLine("| Sockets | $(Escape-MdCell $cs.NumberOfProcessors) |")
  try { [void]$sb.AppendLine("| HypervisorPresent | $(Escape-MdCell $cs.HypervisorPresent) |") } catch { }
  [void]$sb.AppendLine("| Domain / user | $(Escape-MdCell $cs.Domain) / $(Escape-MdCell $cs.UserName) |")
}
[void]$sb.AppendLine("| CPU | $(Escape-MdCell $cpuName) |")
[void]$sb.AppendLine()

[void]$sb.AppendLine("## RAM and commit")
[void]$sb.AppendLine()
[void]$sb.AppendLine("Physical sticks are the hardware total. Usable RAM is what Windows reports after hardware reservation / GPU / I/O space.")
[void]$sb.AppendLine()
[void]$sb.AppendLine("| Metric | Bytes | Human |")
[void]$sb.AppendLine("| --- | ---: | --- |")
[void]$sb.AppendLine("| Installed (sum of sticks) | $ramInstalled | $(Format-Bytes $ramInstalled) |")
[void]$sb.AppendLine("| Usable (Win32_ComputerSystem) | $ramUsable | $(Format-Bytes $ramUsable) |")
[void]$sb.AppendLine("| Free physical (OS) | $ramFree | $(Format-Bytes $ramFree) |")
[void]$sb.AppendLine("| Total virtual (commit + RAM view) | $ramTotalVirt | $(Format-Bytes $ramTotalVirt) |")
[void]$sb.AppendLine("| Free virtual | $ramFreeVirt | $(Format-Bytes $ramFreeVirt) |")
$sumWs = Sum-Bytes $rows 'WorkingSetBytes'
$sumPriv = Sum-Bytes $rows 'PrivateBytes'
[void]$sb.AppendLine("| Sum of process working sets | $sumWs | $(Format-Bytes $sumWs) |")
[void]$sb.AppendLine("| Sum of process private bytes | $sumPriv | $(Format-Bytes $sumPriv) |")
[void]$sb.AppendLine()

if ($memCounters.Count -gt 0) {
  [void]$sb.AppendLine("Perf counters:")
  [void]$sb.AppendLine()
  [void]$sb.AppendLine("| Counter | Value |")
  [void]$sb.AppendLine("| --- | --- |")
  foreach ($k in ($memCounters.Keys | Sort-Object)) {
    [void]$sb.AppendLine("| $(Escape-MdCell $k) | $(Escape-MdCell $memCounters[$k]) |")
  }
  [void]$sb.AppendLine()
}

if ($sticks.Count -gt 0) {
  [void]$sb.AppendLine("### RAM sticks")
  [void]$sb.AppendLine()
  [void]$sb.AppendLine("| Bank | Manufacturer | Part | Capacity | Speed MHz | Configured MHz |")
  [void]$sb.AppendLine("| --- | --- | --- | --- | ---: | ---: |")
  foreach ($st in $sticks) {
    $cap = $null
    if ($st.Capacity) { $cap = Format-Bytes ([int64]$st.Capacity) }
    [void]$sb.AppendLine("| $(Escape-MdCell $st.DeviceLocator) | $(Escape-MdCell $st.Manufacturer) | $(Escape-MdCell $st.PartNumber) | $cap | $(Escape-MdCell (Get-CimProp $st 'Speed')) | $(Escape-MdCell (Get-CimProp $st 'ConfiguredClockSpeed')) |")
  }
  [void]$sb.AppendLine()
}

if ($pagefiles.Count -gt 0) {
  [void]$sb.AppendLine("### Page files")
  [void]$sb.AppendLine()
  [void]$sb.AppendLine("| File | Allocated MB | Current usage MB | Peak MB |")
  [void]$sb.AppendLine("| --- | ---: | ---: | ---: |")
  foreach ($pf in $pagefiles) {
    [void]$sb.AppendLine("| $(Escape-MdCell $pf.Name) | $(Escape-MdCell $pf.AllocatedBaseSize) | $(Escape-MdCell $pf.CurrentUsage) | $(Escape-MdCell $pf.PeakUsage) |")
  }
  [void]$sb.AppendLine()
}

if ($surface) {
  Write-SystemSurfaceMarkdown -Sb $sb -Surface $surface
}

if ($kernel) {
  $pidName = @{}
  foreach ($r in $rows) {
    try {
      if (-not $pidName.ContainsKey([int]$r.Pid)) { $pidName[[int]$r.Pid] = [string]$r.Name }
    } catch { }
  }
  Write-KernelSurfaceMarkdown -Sb $sb -Kernel $kernel -PidNameLookup $pidName
}

if ($extended) {
  Write-ExtendedSurfaceMarkdown -Sb $sb -Extended $extended
}

if ($communication) {
  Write-CommunicationSurfaceMarkdown -Sb $sb -Communication $communication
}

[void]$sb.AppendLine("## Digest for the analyzing agent")
[void]$sb.AppendLine()
[void]$sb.AppendLine("- Process rows: **$($rows.Count)** (CIM $($cimProcs.Count), Get-Process $($gpList.Count))")
[void]$sb.AppendLine("- CIM-only (often session-0 / protected): **$($onlyCim.Count)**")
[void]$sb.AppendLine("- Get-Process-only: **$($onlyGp.Count)**")
[void]$sb.AppendLine("- No window (background-ish): **$($noWindow.Count)**")
[void]$sb.AppendLine("- Session 0: **$($session0.Count)**")
[void]$sb.AppendLine("- Services: **$($serviceRows.Count)** (running auto-start: $($autoRunning.Count))")
[void]$sb.AppendLine("- Startup entries: **$($startupRows.Count)**")
[void]$sb.AppendLine("- Enabled scheduled tasks: **$($taskRows.Count)** (disabled skipped: $disabledTaskCount; task parse errors: $taskErrorCount)")
[void]$sb.AppendLine("- TCP listen/established rows: **$($netRows.Count)**")
if ($surface) {
  [void]$sb.AppendLine("- ChassisHint / DiskHint / GpuHint / PowerHint: **$($surface.ChassisHint)** / **$($surface.DiskHint)** / **$($surface.GpuHint)** / **$($surface.PowerHint)**")
  [void]$sb.AppendLine("- Programs (Uninstall): **$($surface.Programs.Count)**  AppX: **$($surface.AppX.Count)**  optional features probed: **$($surface.Features.Count)**")
  [void]$sb.AppendLine("- Problem devices: **$($surface.ProblemDevices.Count)**  policy rows: **$($surface.Policy.Count)**")
}
if ($kernel) {
  [void]$sb.AppendLine("- Kernel modules loaded: **$($kernel.Modules.Count)** ($(Format-Bytes $kernel.TotalModuleBytes))  pool tags: **$($kernel.PoolTags.Count)** ($(Format-Bytes $kernel.PoolTotalBytes))  registered kernel drivers: **$($kernel.Drivers.Count)**  kernel-side processes: **$($kernel.KernelProcesses.Count)**")
  if ($kernel.EtlDigest) {
    [void]$sb.AppendLine("- ETW kernel trace: **$($kernel.EtlDigest.WindowSeconds)s**, events **$($kernel.EtlDigest.TotalEvents)**, lost **$($kernel.EtlDigest.EventsLost)**$(if ($kernel.EtlDigest.Deep) { ' (deep)' } else { '' })")
  }
}
if ($extended) {
  [void]$sb.AppendLine("- Extended telemetry: routes **$($extended.Routes.Count)**, neighbors **$($extended.Neighbors.Count)**, DNS cache **$($extended.DnsCache.Count)**, adapters **$($extended.AdapterStats.Count)**, users **$($extended.Users.Count)**, groups **$($extended.Groups.Count)**, shares **$($extended.Shares.Count)**, logon sessions **$($extended.LogonSessions.Count)**, thermal **$($extended.Thermal.Count)**")
}
if ($communication) {
  [void]$sb.AppendLine("- Communication: named pipes **$($communication.NamedPipes.Count)**, firewall rules **$($communication.FirewallRules.Count)** (enabled $($communication.FirewallSummary.Enabled)), top talkers **$($communication.TopTalkers.Count)**, services on ports **$($communication.ServicesOnPorts.Count)**, hosts entries **$($communication.HostsLines)**")
}
[void]$sb.AppendLine()

[void]$sb.AppendLine("### Working set by path class")
[void]$sb.AppendLine()
$clsView = $byClass | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    PathClass = $_.PathClass
    Processes = $_.Processes
    WorkingSet = (Format-Bytes $_.WorkingSetBytes)
    Private = (Format-Bytes $_.PrivateBytes)
  })
}
Write-MdTable $sb @('PathClass', 'Processes', 'WorkingSet', 'Private') $clsView @('PathClass', 'Processes', 'WorkingSet', 'Private')

[void]$sb.AppendLine("### Working set by integrity hint")
[void]$sb.AppendLine()
$hintView = $byHint | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    IntegrityHint = $_.IntegrityHint
    Processes = $_.Processes
    WorkingSet = (Format-Bytes $_.WorkingSetBytes)
  })
}
Write-MdTable $sb @('IntegrityHint', 'Processes', 'WorkingSet') $hintView @('IntegrityHint', 'Processes', 'WorkingSet')

[void]$sb.AppendLine("### Process names aggregated (all instances summed)")
[void]$sb.AppendLine()
$nameView = $byName | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    Name = $_.Name
    N = $_.Instances
    WorkingSet = (Format-Bytes $_.WorkingSetBytes)
    Private = (Format-Bytes $_.PrivateBytes)
    Company = $_.Company
    PathClass = $_.PathClass
    MS = $_.LikelyMicrosoft
    Hint = $_.IntegrityHint
  })
}
Write-MdTable $sb @('Name', 'N', 'WorkingSet', 'Private', 'Company', 'PathClass', 'MS', 'Hint') $nameView @('Name', 'N', 'WorkingSet', 'Private', 'Company', 'PathClass', 'MS', 'Hint')

[void]$sb.AppendLine("### Top 40 processes by working set")
[void]$sb.AppendLine()
$topWs = $rows | Select-Object -First 40 | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    Pid = $_.Pid
    Name = $_.Name
    WS = (Format-Bytes $_.WorkingSetBytes)
    Private = (Format-Bytes $_.PrivateBytes)
    Hint = $_.IntegrityHint
    Company = $_.Company
    User = $_.User
    Sess = $_.SessionId
    Win = $_.HasWindow
  })
}
Write-MdTable $sb @('Pid', 'Name', 'WS', 'Private', 'Hint', 'Company', 'User', 'Sess', 'Win') $topWs @('Pid', 'Name', 'WS', 'Private', 'Hint', 'Company', 'User', 'Sess', 'Win')

[void]$sb.AppendLine("### Top 40 by private bytes")
[void]$sb.AppendLine()
$topPriv = @($rows | Sort-Object { $_.PrivateBytes -as [int64] } -Descending | Select-Object -First 40) | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    Pid = $_.Pid
    Name = $_.Name
    Private = (Format-Bytes $_.PrivateBytes)
    WS = (Format-Bytes $_.WorkingSetBytes)
    Hint = $_.IntegrityHint
    Company = $_.Company
  })
}
Write-MdTable $sb @('Pid', 'Name', 'Private', 'WS', 'Hint', 'Company') $topPriv @('Pid', 'Name', 'Private', 'WS', 'Hint', 'Company')

[void]$sb.AppendLine("### Auto-start services that are running")
[void]$sb.AppendLine()
$arView = $autoRunning | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    Name = $_.Name
    DisplayName = $_.DisplayName
    Pid = $_.Pid
    Delayed = $_.DelayedAutoStart
    Account = $_.Account
    PathName = $_.PathName
  })
}
Write-MdTable $sb @('Name', 'DisplayName', 'Pid', 'Delayed', 'Account', 'PathName') $arView @('Name', 'DisplayName', 'Pid', 'Delayed', 'Account', 'PathName')

if ($onlyCim.Count -gt 0 -or $onlyGp.Count -gt 0) {
  [void]$sb.AppendLine("### Enumerator mismatch (possible 'hidden' from one API)")
  [void]$sb.AppendLine()
  if ($onlyCim.Count -gt 0) {
    [void]$sb.AppendLine("CIM yes / Get-Process no:")
    [void]$sb.AppendLine()
    $oc = $onlyCim | ForEach-Object {
      New-Object psobject -Property ([ordered]@{ Pid = $_.Pid; Name = $_.Name; Path = $_.Path; SessionId = $_.SessionId })
    }
    Write-MdTable $sb @('Pid', 'Name', 'Path', 'SessionId') $oc @('Pid', 'Name', 'Path', 'SessionId')
  }
  if ($onlyGp.Count -gt 0) {
    [void]$sb.AppendLine("Get-Process yes / CIM no:")
    [void]$sb.AppendLine()
    $og = $onlyGp | ForEach-Object {
      New-Object psobject -Property ([ordered]@{ Pid = $_.Pid; Name = $_.Name; Path = $_.Path })
    }
    Write-MdTable $sb @('Pid', 'Name', 'Path') $og @('Pid', 'Name', 'Path')
  }
}

[void]$sb.AppendLine("## Process tree")
[void]$sb.AppendLine()
[void]$sb.AppendLine('```')
foreach ($ln in $treeLines) { [void]$sb.AppendLine($ln) }
[void]$sb.AppendLine('```')
[void]$sb.AppendLine()

[void]$sb.AppendLine("## All processes")
[void]$sb.AppendLine()
$allView = $rows | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    Pid = $_.Pid
    PPid = $_.ParentPid
    Name = $_.Name
    WS = (Format-Bytes $_.WorkingSetBytes)
    Private = (Format-Bytes $_.PrivateBytes)
    Virt = (Format-Bytes $_.VirtualBytes)
    PeakWS = (Format-Bytes $_.PeakWorkingSetBytes)
    Thr = $_.ThreadCount
    Hnd = $_.HandleCount
    Mod = $_.ModuleCount
    CPU = $(if ($null -ne $_.CpuSeconds) { '{0:N1}' -f $_.CpuSeconds } else { '' })
    Sess = $_.SessionId
    Win = $_.HasWindow
    User = $_.User
    Class = $_.PathClass
    Hint = $_.IntegrityHint
    MS = $_.LikelyMicrosoft
    Sig = $_.SignatureStatus
    Company = $_.Company
    Services = $_.Services
    Start = $_.StartTime
    Path = $_.Path
  })
}
Write-MdTable $sb @(
  'Pid', 'PPid', 'Name', 'WS', 'Private', 'Virt', 'PeakWS', 'Thr', 'Hnd', 'Mod', 'CPU', 'Sess', 'Win', 'User', 'Class', 'Hint', 'MS', 'Sig', 'Company', 'Services', 'Start', 'Path'
) $allView @(
  'Pid', 'PPid', 'Name', 'WS', 'Private', 'Virt', 'PeakWS', 'Thr', 'Hnd', 'Mod', 'CPU', 'Sess', 'Win', 'User', 'Class', 'Hint', 'MS', 'Sig', 'Company', 'Services', 'Start', 'Path'
)

[void]$sb.AppendLine("## Command lines and extra fields")
[void]$sb.AppendLine()
foreach ($r in ($rows | Sort-Object Pid)) {
  [void]$sb.AppendLine(("### PID {0} - {1}" -f $r.Pid, $r.Name))
  [void]$sb.AppendLine()
  [void]$sb.AppendLine("- Description: $(Escape-MdCell $r.Description)")
  [void]$sb.AppendLine("- Product: $(Escape-MdCell $r.Product) $($r.FileVersion)")
  [void]$sb.AppendLine("- Signer: $(Escape-MdCell $r.Signer)")
  [void]$sb.AppendLine("- Window title: $(Escape-MdCell $r.WindowTitle)")
  [void]$sb.AppendLine("- Responding: $($r.Responding)")
  [void]$sb.AppendLine("- Kernel / user time: $($r.KernelTime) / $($r.UserTime)")
  [void]$sb.AppendLine("- Page faults: $($r.PageFaults)  pagefile KB: $($r.PageFileKb)")
  [void]$sb.AppendLine("- IO read / write: $(Format-Bytes $r.ReadBytes) / $(Format-Bytes $r.WriteBytes)")
  [void]$sb.AppendLine("- SeenByCim: $($r.SeenByCim)  SeenByGetProcess: $($r.SeenByGetProcess)")
  [void]$sb.AppendLine("- Command line:")
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('```')
  if ($r.CommandLine) { [void]$sb.AppendLine([string]$r.CommandLine) } else { [void]$sb.AppendLine('(none / access denied)') }
  [void]$sb.AppendLine('```')
  [void]$sb.AppendLine()
}

[void]$sb.AppendLine("## All services")
[void]$sb.AppendLine()
$svView = $serviceRows | ForEach-Object {
  New-Object psobject -Property ([ordered]@{
    Name = $_.Name
    DisplayName = $_.DisplayName
    State = $_.State
    StartType = $_.StartType
    Delayed = $_.DelayedAutoStart
    Pid = $_.Pid
    Account = $_.Account
    Exit = $_.ExitCode
    PathName = $_.PathName
  })
}
Write-MdTable $sb @('Name', 'DisplayName', 'State', 'StartType', 'Delayed', 'Pid', 'Account', 'Exit', 'PathName') $svView @('Name', 'DisplayName', 'State', 'StartType', 'Delayed', 'Pid', 'Account', 'Exit', 'PathName')

[void]$sb.AppendLine("### Service descriptions")
[void]$sb.AppendLine()
foreach ($sv in $serviceRows) {
  if ([string]::IsNullOrWhiteSpace($sv.Description)) { continue }
  [void]$sb.AppendLine("#### $($sv.Name)")
  [void]$sb.AppendLine()
  [void]$sb.AppendLine((Escape-MdCell $sv.Description))
  [void]$sb.AppendLine()
}

[void]$sb.AppendLine("## Startup")
[void]$sb.AppendLine()
Write-MdTable $sb @('Source', 'Name', 'Command') $startupRows @('Source', 'Name', 'Command')

[void]$sb.AppendLine("## Scheduled tasks (not Disabled)")
[void]$sb.AppendLine()
if ($SkipTasks) {
  [void]$sb.AppendLine("_Skipped by -SkipTasks._")
  [void]$sb.AppendLine()
} else {
  Write-MdTable $sb @('TaskName', 'Path', 'State', 'UserId', 'Triggers', 'Actions') $taskRows @('TaskName', 'Path', 'State', 'UserId', 'Triggers', 'Actions')
}

[void]$sb.AppendLine("## TCP connections (Listen + Established)")
[void]$sb.AppendLine()
if ($SkipNetwork) {
  [void]$sb.AppendLine("_Skipped by -SkipNetwork._")
  [void]$sb.AppendLine()
} else {
  $netView = $netRows | Sort-Object Pid, State, LocalPort
  Write-MdTable $sb @('Pid', 'State', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort') $netView @('Pid', 'State', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort')
}

[void]$sb.AppendLine("## Unique executable signatures")
[void]$sb.AppendLine()
$sigRows = @()
foreach ($k in ($sigCache.Keys | Sort-Object)) {
  $v = $sigCache[$k]
  $sigRows += New-Object psobject -Property ([ordered]@{ Path = $k; Status = $v.Status; Signer = $v.Signer })
}
Write-MdTable $sb @('Path', 'Status', 'Signer') $sigRows @('Path', 'Status', 'Signer')

[void]$sb.AppendLine("## Collection issues")
[void]$sb.AppendLine()
if ($script:Issues.Count -eq 0) {
  [void]$sb.AppendLine("None recorded.")
  [void]$sb.AppendLine()
} else {
  foreach ($iss in $script:Issues) {
    [void]$sb.AppendLine("- $(Escape-MdCell $iss)")
  }
  [void]$sb.AppendLine()
}

$elapsed = ([datetime]::UtcNow - $script:StartedUtc).TotalSeconds
[void]$sb.AppendLine("## End")
[void]$sb.AppendLine()
[void]$sb.AppendLine(("Capture duration: {0:N1}s. Markdown path: ``{1}``." -f $elapsed, $mdPath))
if (-not $NoJson) {
  [void]$sb.AppendLine(("JSON bulk: ``{0}``." -f $jsonPath))
}

$utf8 = New-Utf8Bom
[System.IO.File]::WriteAllText($mdPath, $sb.ToString(), $utf8)

if (-not $NoJson) {
  Write-Host '       JSON bulk...'
  $bulk = [ordered]@{
    SchemaVersion = '1.0'
    Generator = 'process-deglose'
    Repo = 'https://github.com/Vahlame/process-deglose'
    ToolVersion = $script:ToolVersion
    CapturedUtc = $script:StartedUtc.ToString('o')
    Elevated = $isAdmin
    Computer = $env:COMPUTERNAME
    RamInstalledBytes = $ramInstalled
    RamUsableBytes = $ramUsable
    RamFreeBytes = $ramFree
    MemoryCounters = $memCounters
    Processes = $rows
    Services = $serviceRows
    Startup = $startupRows
    Tasks = $taskRows
    Network = $netRows
    Surface = $surface
    Kernel = $kernel
    Extended = $extended
    Communication = $communication
    Issues = @($script:Issues)
  }
  try {
    $json = $bulk | ConvertTo-Json -Depth 6 -Compress:$false
    [System.IO.File]::WriteAllText($jsonPath, $json, $utf8)
  } catch {
    Add-Issue "JSON write: $($_.Exception.Message)"
    Write-Warning $_.Exception.Message
  }
} else {
  Write-Host '       JSON skipped'
}

Write-Host ""
Write-Host "Wrote $mdPath"
if (-not $NoJson -and (Test-Path -LiteralPath $jsonPath)) { Write-Host "Wrote $jsonPath" }
Write-Host ("Desktop folder: {0}" -f $OutDir)
Write-Host ("Duration {0:N1}s  processes {1}  services {2}" -f $elapsed, $rows.Count, $serviceRows.Count)

Write-Host ""
Write-Host ("  TL;DR  {0} processes - {1} services - RAM {2} in working sets" -f $rows.Count, $serviceRows.Count, (Format-Bytes $tldrWs))
if ($kernel) { Write-Host ("         {0} kernel modules - {1} drivers - {2} firewall rules" -f $kernel.Modules.Count, $kernel.Drivers.Count, $communication.FirewallRules.Count) }
Write-Host "  Top consumers:"
foreach ($r in (@($rows | Select-Object -First 5))) {
  Write-Host ("    {0,-32} {1,10}  {2}" -f $r.Name, (Format-Bytes $r.WorkingSetBytes), $r.IntegrityHint)
}
Write-Host ("  Collection issues: {0}" -f $script:Issues.Count)

$sendPath = Join-Path $OutDir 'SEND_THIS_FOLDER_TO_THE_OTHER_AI.txt'
$sendText = @"
Send this whole folder to the other AI (or at least the .md file).

What to attach
- snapshot-*.md   (main file - paste or upload this)
- snapshot-*.json (optional extra bulk)

This folder is an inventory only. It does not change Windows.
The other AI should propose IF-THEN tweaks from the Decision facts in the Markdown.
"@
try {
  [System.IO.File]::WriteAllText($sendPath, $sendText, $utf8)
} catch { }

if (-not $NoExplorer) {
  try { Start-Process -FilePath explorer.exe -ArgumentList "`"$OutDir`"" } catch { }
}

exit 0
