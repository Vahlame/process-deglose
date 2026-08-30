#requires -Version 5.1
# Dot-sourced from snapshot.ps1. Uses Add-Issue, Get-CimProp, Get-RegValue, Invoke-CaptureCmd.

function Collect-SystemSurface {
  param(
    [bool]$IsAdmin,
    [bool]$SkipHeavy
  )

  $surface = [ordered]@{
    Cpu = @()
    Enclosure = @()
    Bios = $null
    Board = $null
    Product = $null
    Gpu = @()
    NvidiaSmi = $null
    Disks = @()
    PhysicalDisks = @()
    Volumes = @()
    PageFileSettings = @()
    Battery = @()
    Adapters = @()
    Offload = $null
    NicAdvanced = @()
    PowerActive = $null
    PowerList = $null
    PowerAvailable = $null
    PowerQuery = $null
    BcdCurrent = $null
    FsutilLastAccess = $null
    SecureBoot = $null
    Tpm = $null
    DeviceGuard = $null
    MMAgent = $null
    Policy = @()
    Features = @()
    Programs = @()
    AppX = @()
    AppXAllUsers = $false
    ProblemDevices = @()
    DriversByPublisher = @()
    EventsSystemError = @()
    EventsAppError = @()
    Defender = $null
    AvProducts = @()
    FirewallProfiles = @()
    BitLocker = @()
    HotFixes = @()
    StartupApproved = @()
    Env = @()
    ChassisHint = 'unknown'
    DiskHint = 'unknown'
    GpuHint = 'unknown'
    PowerHint = 'unknown'
    PcSystemType = $null
    AutomaticManagedPagefile = $null
  }

  Write-Host '[7/14] CPU, firmware, GPU, storage...'

  $cpuCim = @()
  try { $cpuCim = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop) } catch { Add-Issue "Win32_Processor extra: $($_.Exception.Message)" }
  foreach ($c in $cpuCim) {
    $surface.Cpu += New-Object psobject -Property ([ordered]@{
      Name = Get-CimProp $c 'Name'
      Manufacturer = Get-CimProp $c 'Manufacturer'
      Cores = Get-CimProp $c 'NumberOfCores'
      Logical = Get-CimProp $c 'NumberOfLogicalProcessors'
      MaxClockMHz = Get-CimProp $c 'MaxClockSpeed'
      CurrentClockMHz = Get-CimProp $c 'CurrentClockSpeed'
      L2 = Get-CimProp $c 'L2CacheSize'
      L3 = Get-CimProp $c 'L3CacheSize'
      VirtualizationFirmwareEnabled = Get-CimProp $c 'VirtualizationFirmwareEnabled'
      VMMonitorModeExtensions = Get-CimProp $c 'VMMonitorModeExtensions'
      AddressWidth = Get-CimProp $c 'AddressWidth'
      Socket = Get-CimProp $c 'SocketDesignation'
      Family = Get-CimProp $c 'Family'
    })
  }

  $enc = @()
  try { $enc = @(Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop) } catch { Add-Issue "Win32_SystemEnclosure: $($_.Exception.Message)" }
  foreach ($e in $enc) {
    $ctypes = Get-CimProp $e 'ChassisTypes'
    $surface.Enclosure += New-Object psobject -Property ([ordered]@{
      Manufacturer = Get-CimProp $e 'Manufacturer'
      ChassisTypes = $(if ($ctypes) { ($ctypes -join ',') } else { $null })
      SerialNumber = Get-CimProp $e 'SerialNumber'
      SMBIOSAssetTag = Get-CimProp $e 'SMBIOSAssetTag'
    })
  }

  try {
    $b = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $surface.Bios = New-Object psobject -Property ([ordered]@{
      Manufacturer = Get-CimProp $b 'Manufacturer'
      SMBIOSBIOSVersion = Get-CimProp $b 'SMBIOSBIOSVersion'
      ReleaseDate = Get-CimProp $b 'ReleaseDate'
      Version = Get-CimProp $b 'Version'
    })
  } catch { Add-Issue "Win32_BIOS: $($_.Exception.Message)" }

  try {
    $bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop
    $surface.Board = New-Object psobject -Property ([ordered]@{
      Manufacturer = Get-CimProp $bb 'Manufacturer'
      Product = Get-CimProp $bb 'Product'
      Version = Get-CimProp $bb 'Version'
    })
  } catch { Add-Issue "Win32_BaseBoard: $($_.Exception.Message)" }

  try {
    $pr = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
    $surface.Product = New-Object psobject -Property ([ordered]@{
      Vendor = Get-CimProp $pr 'Vendor'
      Name = Get-CimProp $pr 'Name'
      Version = Get-CimProp $pr 'Version'
    })
  } catch { }

  try {
    $csx = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $surface.PcSystemType = Get-CimProp $csx 'PCSystemType'
    $surface.AutomaticManagedPagefile = Get-CimProp $csx 'AutomaticManagedPagefile'
  } catch { }

  $gpuCim = @()
  try { $gpuCim = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop) } catch { Add-Issue "Win32_VideoController: $($_.Exception.Message)" }
  foreach ($g in $gpuCim) {
    $ram = Get-CimProp $g 'AdapterRAM'
    $ramN = $null
    if ($null -ne $ram) { try { $ramN = [int64]$ram } catch { } }
    $surface.Gpu += New-Object psobject -Property ([ordered]@{
      Name = Get-CimProp $g 'Name'
      AdapterCompatibility = Get-CimProp $g 'AdapterCompatibility'
      DriverVersion = Get-CimProp $g 'DriverVersion'
      DriverDate = Get-CimProp $g 'DriverDate'
      VideoProcessor = Get-CimProp $g 'VideoProcessor'
      AdapterRAM = $ramN
      CurrentH = Get-CimProp $g 'CurrentHorizontalResolution'
      CurrentV = Get-CimProp $g 'CurrentVerticalResolution'
      RefreshHz = Get-CimProp $g 'CurrentRefreshRate'
      BitsPerPixel = Get-CimProp $g 'CurrentBitsPerPixel'
      Availability = Get-CimProp $g 'Availability'
      PNPDeviceID = Get-CimProp $g 'PNPDeviceID'
      Status = Get-CimProp $g 'Status'
    })
  }

  $smi = Join-Path $env:SystemRoot 'System32\nvidia-smi.exe'
  if (Test-Path -LiteralPath $smi) {
    $surface.NvidiaSmi = Invoke-CaptureCmd -FileName $smi -Arguments '--query-gpu=name,driver_version,memory.total,memory.used,utilization.gpu,power.draw,pstate --format=csv' -TimeoutMs 8000
  }

  $dd = @()
  try { $dd = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop) } catch { Add-Issue "Win32_DiskDrive: $($_.Exception.Message)" }
  foreach ($d in $dd) {
    $sz = Get-CimProp $d 'Size'
    $szN = $null
    if ($null -ne $sz) { try { $szN = [int64]$sz } catch { } }
    $surface.Disks += New-Object psobject -Property ([ordered]@{
      Model = Get-CimProp $d 'Model'
      InterfaceType = Get-CimProp $d 'InterfaceType'
      MediaType = Get-CimProp $d 'MediaType'
      Size = $szN
      Serial = Get-CimProp $d 'SerialNumber'
      Status = Get-CimProp $d 'Status'
      PNPDeviceID = Get-CimProp $d 'PNPDeviceID'
    })
  }

  try {
    $pd = @(Get-PhysicalDisk -ErrorAction Stop)
    foreach ($p in $pd) {
      $surface.PhysicalDisks += New-Object psobject -Property ([ordered]@{
        FriendlyName = [string]$p.FriendlyName
        MediaType = [string]$p.MediaType
        BusType = [string]$p.BusType
        HealthStatus = [string]$p.HealthStatus
        OperationalStatus = [string]$p.OperationalStatus
        Size = $(try { [int64]$p.Size } catch { $null })
        SpindleSpeed = $(try { [string]$p.SpindleSpeed } catch { $null })
        FirmwareVersion = $(try { [string]$p.FirmwareVersion } catch { $null })
      })
    }
  } catch {
    Add-Issue "Get-PhysicalDisk: $($_.Exception.Message)"
  }

  $vols = @()
  try { $vols = @(Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop) } catch { Add-Issue "Win32_LogicalDisk: $($_.Exception.Message)" }
  foreach ($v in $vols) {
    $free = Get-CimProp $v 'FreeSpace'
    $size = Get-CimProp $v 'Size'
    $freeN = $null; $sizeN = $null
    if ($null -ne $free) { try { $freeN = [int64]$free } catch { } }
    if ($null -ne $size) { try { $sizeN = [int64]$size } catch { } }
    $surface.Volumes += New-Object psobject -Property ([ordered]@{
      DeviceID = Get-CimProp $v 'DeviceID'
      DriveType = Get-CimProp $v 'DriveType'
      FileSystem = Get-CimProp $v 'FileSystem'
      VolumeName = Get-CimProp $v 'VolumeName'
      Size = $sizeN
      FreeSpace = $freeN
      Compressed = Get-CimProp $v 'Compressed'
    })
  }

  try {
    $pfs = @(Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction Stop)
    foreach ($p in $pfs) {
      $surface.PageFileSettings += New-Object psobject -Property ([ordered]@{
        Name = Get-CimProp $p 'Name'
        InitialSize = Get-CimProp $p 'InitialSize'
        MaximumSize = Get-CimProp $p 'MaximumSize'
      })
    }
  } catch { }

  $bat = @()
  try { $bat = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop) } catch { }
  foreach ($b in $bat) {
    $surface.Battery += New-Object psobject -Property ([ordered]@{
      Name = Get-CimProp $b 'Name'
      Status = Get-CimProp $b 'Status'
      BatteryStatus = Get-CimProp $b 'BatteryStatus'
      EstimatedChargeRemaining = Get-CimProp $b 'EstimatedChargeRemaining'
      EstimatedRunTime = Get-CimProp $b 'EstimatedRunTime'
      DesignCapacity = Get-CimProp $b 'DesignCapacity'
      Chemistry = Get-CimProp $b 'Chemistry'
    })
  }

  Write-Host '[8/14] Network adapters, power, firmware security...'
  try {
    $nics = @(Get-NetAdapter -ErrorAction Stop)
    foreach ($n in $nics) {
      $surface.Adapters += New-Object psobject -Property ([ordered]@{
        Name = [string]$n.Name
        InterfaceDescription = [string]$n.InterfaceDescription
        Status = [string]$n.Status
        MacAddress = [string]$n.MacAddress
        LinkSpeed = [string]$n.LinkSpeed
        MediaType = $(try { [string]$n.MediaType } catch { $null })
        PhysicalMediaType = $(try { [string]$n.PhysicalMediaType } catch { $null })
        DriverVersion = $(try { [string]$n.DriverVersion } catch { $null })
        DriverInformation = $(try { [string]$n.DriverInformation } catch { $null })
      })
    }
  } catch {
    Add-Issue "Get-NetAdapter: $($_.Exception.Message)"
  }

  try {
    $off = Get-NetOffloadGlobalSetting -ErrorAction Stop
    $surface.Offload = New-Object psobject -Property ([ordered]@{
      ReceiveSideScaling = [string]$off.ReceiveSideScaling
      Chimney = $(try { [string]$off.Chimney } catch { $null })
      TaskOffload = $(try { [string]$off.TaskOffload } catch { $null })
      NetworkDirect = $(try { [string]$off.NetworkDirect } catch { $null })
      NetworkDirectAcrossIPSubnets = $(try { [string]$off.NetworkDirectAcrossIPSubnets } catch { $null })
      PacketDirect = $(try { [string]$off.PacketDirect } catch { $null })
    })
  } catch { }

  try {
    $adv = @(Get-NetAdapterAdvancedProperty -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match 'Power|Energy|Green|EEE|Interrupt|Receive Side|RSS|Jumbo|Offload|Wake|NSOffload'
      })
    $i = 0
    foreach ($a in $adv) {
      if ($i -ge 80) { break }
      $i++
      $surface.NicAdvanced += New-Object psobject -Property ([ordered]@{
        Name = [string]$a.Name
        DisplayName = [string]$a.DisplayName
        DisplayValue = [string]$a.DisplayValue
        RegistryKeyword = [string]$a.RegistryKeyword
        RegistryValue = [string]($a.RegistryValue -join ',')
      })
    }
  } catch { }

  $pcfg = Join-Path $env:SystemRoot 'System32\powercfg.exe'
  $surface.PowerActive = Invoke-CaptureCmd -FileName $pcfg -Arguments '/getactivescheme' -TimeoutMs 8000
  $surface.PowerList = Invoke-CaptureCmd -FileName $pcfg -Arguments '/list' -TimeoutMs 8000
  $surface.PowerAvailable = Invoke-CaptureCmd -FileName $pcfg -Arguments '/a' -TimeoutMs 8000
  $pqParts = New-Object System.Collections.Generic.List[string]
  foreach ($sub in @('SUB_PROCESSOR', 'SUB_SLEEP', 'SUB_DISK', 'SUB_VIDEO', 'SUB_PCIEXPRESS', 'SUB_GRAPHICS')) {
    $chunk = Invoke-CaptureCmd -FileName $pcfg -Arguments ("/query SCHEME_CURRENT {0}" -f $sub) -TimeoutMs 12000
    if ($chunk) { [void]$pqParts.Add(("----- {0} -----`n{1}" -f $sub, $chunk.Trim())) }
  }
  $surface.PowerQuery = ($pqParts -join "`n`n")

  $bcd = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
  $surface.BcdCurrent = Invoke-CaptureCmd -FileName $bcd -Arguments '/enum {current}' -TimeoutMs 8000

  $fsu = Join-Path $env:SystemRoot 'System32\fsutil.exe'
  $surface.FsutilLastAccess = Invoke-CaptureCmd -FileName $fsu -Arguments 'behavior query disablelastaccess' -TimeoutMs 8000

  try { $surface.SecureBoot = Confirm-SecureBootUEFI } catch { $surface.SecureBoot = $_.Exception.Message }

  try {
    $tpm = Get-Tpm -ErrorAction Stop
    $surface.Tpm = New-Object psobject -Property ([ordered]@{
      TpmPresent = [string]$tpm.TpmPresent
      TpmReady = [string]$tpm.TpmReady
      TpmEnabled = $(try { [string]$tpm.TpmEnabled } catch { $null })
      TpmActivated = $(try { [string]$tpm.TpmActivated } catch { $null })
      TpmOwned = $(try { [string]$tpm.TpmOwned } catch { $null })
      ManufacturerIdTxt = $(try { [string]$tpm.ManufacturerIdTxt } catch { $null })
      ManufacturerVersion = $(try { [string]$tpm.ManufacturerVersion } catch { $null })
    })
  } catch {
    Add-Issue "Get-Tpm: $($_.Exception.Message)"
  }

  try {
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
    $ssr = Get-CimProp $dg 'SecurityServicesRunning'
    $ssc = Get-CimProp $dg 'SecurityServicesConfigured'
    $surface.DeviceGuard = New-Object psobject -Property ([ordered]@{
      VirtualizationBasedSecurityStatus = Get-CimProp $dg 'VirtualizationBasedSecurityStatus'
      CodeIntegrityPolicyEnforcementStatus = Get-CimProp $dg 'CodeIntegrityPolicyEnforcementStatus'
      UsermodeCodeIntegrityPolicyEnforcementStatus = Get-CimProp $dg 'UsermodeCodeIntegrityPolicyEnforcementStatus'
      SecurityServicesRunning = $(if ($ssr) { ($ssr -join ',') } else { $null })
      SecurityServicesConfigured = $(if ($ssc) { ($ssc -join ',') } else { $null })
      AvailableSecurityProperties = $(try { ((Get-CimProp $dg 'AvailableSecurityProperties') -join ',') } catch { $null })
      RequiredSecurityProperties = $(try { ((Get-CimProp $dg 'RequiredSecurityProperties') -join ',') } catch { $null })
    })
  } catch {
    Add-Issue "Win32_DeviceGuard: $($_.Exception.Message)"
  }

  try {
    $mm = Get-MMAgent -ErrorAction Stop
    $surface.MMAgent = New-Object psobject -Property ([ordered]@{
      MemoryCompression = [string]$mm.MemoryCompression
      ApplicationLaunchPrefetching = [string]$mm.ApplicationLaunchPrefetching
      OperationAPI = [string]$mm.OperationAPI
      PageCombining = [string]$mm.PageCombining
      ApplicationPreLaunch = $(try { [string]$mm.ApplicationPreLaunch } catch { $null })
    })
  } catch {
    Add-Issue "Get-MMAgent: $($_.Exception.Message)"
  }

  Write-Host '[9/14] Policy registry, features, programs...'
  $policySpecs = @(
    @{ Path = 'HKCU:\Control Panel\Desktop'; Name = 'MenuShowDelay'; Note = 'Start menu / UI delay (ms).' }
    @{ Path = 'HKCU:\Control Panel\Desktop'; Name = 'DragFullWindows'; Note = '1 = show window contents while dragging.' }
    @{ Path = 'HKCU:\Control Panel\Desktop'; Name = 'FontSmoothing'; Note = 'Font smoothing.' }
    @{ Path = 'HKCU:\Control Panel\Desktop'; Name = 'UserPreferencesMask'; Note = 'Visual effects bitmask (hex).' }
    @{ Path = 'HKCU:\Control Panel\Desktop'; Name = 'WaitToKillAppTimeout'; Note = 'App shutdown timeout ms.' }
    @{ Path = 'HKCU:\Control Panel\Desktop'; Name = 'HungAppTimeout'; Note = 'Hung app timeout ms.' }
    @{ Path = 'HKCU:\Control Panel\Desktop'; Name = 'AutoEndTasks'; Note = 'Auto-end hung GUI tasks.' }
    @{ Path = 'HKCU:\Control Panel\Desktop\WindowMetrics'; Name = 'MinAnimate'; Note = 'Minimize/maximize animation.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'; Name = 'VisualFXSetting'; Note = '0 Windows-choose, 1 appearance, 2 performance, 3 custom.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name = 'EnableTransparency'; Note = 'Acrylic/transparency.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\DWM'; Name = 'EnableAeroPeek'; Note = 'Aero Peek.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'TaskbarDa'; Note = 'Widgets button (Win11).' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'TaskbarMn'; Note = 'Chat/Teams button.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'ShowCopilotButton'; Note = 'Copilot taskbar button.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'LaunchTo'; Note = 'Explorer start: 1 This PC, 2 Quick Access.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize'; Name = 'StartupDelayInMSec'; Note = 'Startup delay; 0 = no delay.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Name = 'BingSearchEnabled'; Note = 'Search highlights / web.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Name = 'CortanaConsent'; Note = 'Cortana consent.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Name = 'SearchboxTaskbarMode'; Note = 'Search box vs icon.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SilentInstalledAppsEnabled'; Note = 'Silent Store app installs.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SystemPaneSuggestionsEnabled'; Note = 'Suggested apps in Start.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'OemPreInstalledAppsEnabled'; Note = 'OEM suggested apps.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'PreInstalledAppsEnabled'; Note = 'Preinstalled app suggestions.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SoftLandingEnabled'; Note = 'Windows tips.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-338388Enabled'; Note = 'Start suggestions.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContent-338389Enabled'; Note = 'Tips about Windows.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'; Name = 'GlobalUserDisabled'; Note = '1 = background Store apps off.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications'; Name = 'ToastEnabled'; Note = 'Toast notifications.' }
    @{ Path = 'HKCU:\System\GameConfigStore'; Name = 'GameDVR_Enabled'; Note = 'Game DVR / captures.' }
    @{ Path = 'HKCU:\System\GameConfigStore'; Name = 'GameDVR_FSEBehaviorMode'; Note = 'Fullscreen optimizations related.' }
    @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR'; Name = 'AppCaptureEnabled'; Note = 'Game Bar capture.' }
    @{ Path = 'HKCU:\SOFTWARE\Microsoft\GameBar'; Name = 'AllowAutoGameMode'; Note = 'Auto Game Mode.' }
    @{ Path = 'HKCU:\SOFTWARE\Microsoft\GameBar'; Name = 'AutoGameModeEnabled'; Note = 'Game Mode enabled.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'; Name = 'HwSchMode'; Note = 'HAGS: 2 on, 1 off. GPU-dependent.' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'; Name = 'NetworkThrottlingIndex'; Note = 'Multimedia network throttle. 0xFFFFFFFF = off.' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'; Name = 'SystemResponsiveness'; Note = 'MMCSS reserved CPU % (default 20).' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'; Name = 'GPU Priority'; Note = 'Games MMCSS GPU priority.' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'; Name = 'Priority'; Note = 'Games MMCSS CPU priority.' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'; Name = 'Scheduling Category'; Note = 'Games MMCSS category.' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'; Name = 'SFIO Priority'; Note = 'Games MMCSS disk priority.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'; Name = 'EnablePrefetcher'; Note = '0 off, 1 app, 2 boot, 3 both.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'; Name = 'EnableSuperfetch'; Note = 'SysMain/Superfetch. SSD vs HDD matters.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Name = 'DisablePagingExecutive'; Note = 'Report only. Do not flip blindly.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Name = 'LargeSystemCache'; Note = 'Report only. Server-oriented.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Name = 'ClearPageFileAtShutdown'; Note = '1 slows shutdown.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Name = 'FeatureSettings'; Note = 'Mitigations. REPORT ONLY. Do not disable for FPS.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Name = 'FeatureSettingsOverride'; Note = 'Spectre/Meltdown override. REPORT ONLY. Never recommend disabling.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Name = 'FeatureSettingsOverrideMask'; Note = 'Paired with FeatureSettingsOverride. REPORT ONLY.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'; Name = 'NtfsDisableLastAccessUpdate'; Note = 'NTFS last-access stamp. SSD-friendly when disabled by system.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'; Name = 'NtfsDisable8dot3NameCreation'; Note = '8.3 names on NTFS.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'; Name = 'HiberbootEnabled'; Note = 'Fast startup.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'; Name = 'HibernateEnabled'; Note = 'Hibernate / hiberfil.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control'; Name = 'WaitToKillServiceTimeout'; Note = 'Service stop timeout ms.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl'; Name = 'Win32PrioritySeparation'; Note = 'Foreground vs background CPU.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling'; Name = 'PowerThrottlingOff'; Note = '1 = EcoQoS/power throttling off. Laptop vs desktop.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'; Name = 'EnableVirtualizationBasedSecurity'; Note = 'VBS. Do not disable as a FPS trick.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'; Name = 'Enabled'; Note = 'HVCI / memory integrity. Do not disable as a FPS trick.' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'; Name = 'VulnerableDriverBlocklistEnable'; Note = 'Vulnerable driver blocklist.' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name = 'AllowTelemetry'; Note = '0 Security (Ent), 1 Basic, 2 Enhanced, 3 Full.' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Note = 'Policy telemetry override.' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'; Name = 'DODownloadMode'; Note = 'Delivery Optimization mode.' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'AllowCortana'; Note = 'Policy Cortana.' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'DisableWebSearch'; Note = 'Policy disable web search.' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'; Name = 'AllowNewsAndInterests'; Note = 'Widgets / news policy.' }
    @{ Path = 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot'; Name = 'TurnOffWindowsCopilot'; Note = 'Copilot policy.' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'StartupBoostEnabled'; Note = 'Edge startup boost policy.' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'BackgroundModeEnabled'; Note = 'Edge background mode policy.' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'; Name = 'DisableSR'; Note = 'System Restore disabled if 1.' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'; Name = '01'; Note = 'Storage Sense on (1).' }
  )
  foreach ($spec in $policySpecs) {
    $val = Get-RegValue -RegPath $spec.Path -Name $spec.Name
    $surface.Policy += New-Object psobject -Property ([ordered]@{
      Path = $spec.Path
      Name = $spec.Name
      Value = $(if ($null -eq $val) { '(absent)' } else { [string]$val })
      Note = $spec.Note
    })
  }

  $approvedRoots = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
  )
  foreach ($ar in $approvedRoots) {
    if (-not (Test-Path -LiteralPath $ar)) { continue }
    try {
      $item = Get-Item -LiteralPath $ar -ErrorAction Stop
      foreach ($vn in $item.GetValueNames()) {
        $raw = $item.GetValue($vn)
        $state = 'unknown'
        if ($raw -is [byte[]] -and $raw.Length -ge 1) {
          $b0 = [int]$raw[0]
          if ($b0 -eq 2 -or $b0 -eq 6) { $state = 'enabled' }
          elseif ($b0 -eq 3 -or $b0 -eq 7) { $state = 'disabled' }
          else { $state = ('byte0=' + $b0) }
        }
        $surface.StartupApproved += New-Object psobject -Property ([ordered]@{
          Hive = $ar
          Name = $vn
          State = $state
        })
      }
    } catch { }
  }

  try {
    Import-Module Dism -ErrorAction Stop
    $allFeat = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop)
    foreach ($f in $allFeat) {
      $surface.Features += New-Object psobject -Property ([ordered]@{
        FeatureName = [string]$f.FeatureName
        State = [string]$f.State
      })
    }
  } catch {
    Add-Issue "Get-WindowsOptionalFeature: $($_.Exception.Message)"
    $dism = Join-Path $env:SystemRoot 'System32\dism.exe'
    $dismOut = Invoke-CaptureCmd -FileName $dism -Arguments '/Online /Get-Features /Format:Table' -TimeoutMs 50000
    if ($dismOut) {
      $curName = $null
      foreach ($ln in ($dismOut -split "`r?`n")) {
        if ($ln -match '(?i)Feature Name\s*:\s*(.+)\s*$' -or $ln -match '(?i)Nombre de la caracter.+\s*:\s*(.+)\s*$') {
          $curName = $Matches[1].Trim()
        } elseif ($curName -and ($ln -match '(?i)^(?:State|Estado)\s*:\s*(.+)\s*$')) {
          $surface.Features += New-Object psobject -Property ([ordered]@{
            FeatureName = $curName
            State = $Matches[1].Trim()
          })
          $curName = $null
        }
      }
    }
  }
  $surface.Features = @($surface.Features | Sort-Object State, FeatureName)

  if (-not $SkipHeavy) {
    $uninstRoots = @(
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
      'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $uninstRoots) {
      if (-not (Test-Path -LiteralPath $root)) { continue }
      try {
        Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object {
          $dn = $_.GetValue('DisplayName')
          if ([string]::IsNullOrWhiteSpace($dn)) { return }
          $surface.Programs += New-Object psobject -Property ([ordered]@{
            DisplayName = [string]$dn
            Publisher = [string]$_.GetValue('Publisher')
            Version = [string]$_.GetValue('DisplayVersion')
            InstallDate = [string]$_.GetValue('InstallDate')
            EstimatedSizeKb = $_.GetValue('EstimatedSize')
            Hive = $root
          })
        }
      } catch {
        Add-Issue "Uninstall $root : $($_.Exception.Message)"
      }
    }
    $surface.Programs = @($surface.Programs | Sort-Object DisplayName)

    try {
      $pkgs = $null
      if ($IsAdmin) {
        try {
          $pkgs = @(Get-AppxPackage -AllUsers -ErrorAction Stop)
          $surface.AppXAllUsers = $true
        } catch {
          $pkgs = @(Get-AppxPackage -ErrorAction Stop)
        }
      } else {
        $pkgs = @(Get-AppxPackage -ErrorAction Stop)
      }
      foreach ($pkg in $pkgs) {
        $surface.AppX += New-Object psobject -Property ([ordered]@{
          Name = [string]$pkg.Name
          Version = [string]$pkg.Version
          Publisher = [string]$pkg.Publisher
          SignatureKind = [string]$pkg.SignatureKind
          NonRemovable = [string]$pkg.NonRemovable
          IsFramework = [string]$pkg.IsFramework
          InstallLocation = [string]$pkg.InstallLocation
        })
      }
      $surface.AppX = @($surface.AppX | Sort-Object Name)
    } catch {
      Add-Issue "Get-AppxPackage: $($_.Exception.Message)"
    }
  }

  Write-Host '[10/14] Events, Defender, problem devices...'
  try {
    $pnp = @(Get-PnpDevice -ErrorAction Stop | Where-Object {
        $_.Status -and $_.Status -ne 'OK' -and $_.Status -ne 'Unknown'
      })
    foreach ($d in $pnp) {
      $surface.ProblemDevices += New-Object psobject -Property ([ordered]@{
        Status = [string]$d.Status
        Class = [string]$d.Class
        FriendlyName = [string]$d.FriendlyName
        InstanceId = [string]$d.InstanceId
        Problem = $(try { [string]$d.Problem } catch { $null })
      })
    }
  } catch {
    try {
      $ents = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop | Where-Object {
          $ec = Get-CimProp $_ 'ConfigManagerErrorCode'
          $ec -and [int]$ec -ne 0
        })
      foreach ($d in $ents) {
        $surface.ProblemDevices += New-Object psobject -Property ([ordered]@{
          Status = Get-CimProp $d 'Status'
          Class = Get-CimProp $d 'PNPClass'
          FriendlyName = Get-CimProp $d 'Name'
          InstanceId = Get-CimProp $d 'PNPDeviceID'
          Problem = Get-CimProp $d 'ConfigManagerErrorCode'
        })
      }
    } catch {
      Add-Issue "Problem devices: $($_.Exception.Message)"
    }
  }

  try {
    $drvs = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop)
    $surface.DriversByPublisher = @(
      $drvs | Group-Object Manufacturer | Sort-Object Count -Descending | ForEach-Object {
        New-Object psobject -Property ([ordered]@{
          Manufacturer = $_.Name
          Drivers = $_.Count
        })
      }
    )
  } catch {
    Add-Issue "Win32_PnPSignedDriver: $($_.Exception.Message)"
  }

  $since = (Get-Date).AddDays(-7)
  $eventLogs = @(
    (New-Object psobject -Property @{ Log = 'System'; Key = 'EventsSystemError' }),
    (New-Object psobject -Property @{ Log = 'Application'; Key = 'EventsAppError' })
  )
  foreach ($el in $eventLogs) {
    $log = [string]$el.Log
    $key = [string]$el.Key
    try {
      $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Level = 2; StartTime = $since } -MaxEvents 250 -ErrorAction Stop)
      $surface[$key] = @(
        $ev | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
          New-Object psobject -Property ([ordered]@{
            Provider = $_.Name
            Errors7d = $_.Count
          })
        }
      )
    } catch {
      Add-Issue "Get-WinEvent $log : $($_.Exception.Message)"
    }
  }

  try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $surface.Defender = New-Object psobject -Property ([ordered]@{
      AMServiceEnabled = [string]$mp.AMServiceEnabled
      AntispywareEnabled = [string]$mp.AntispywareEnabled
      AntivirusEnabled = [string]$mp.AntivirusEnabled
      RealTimeProtectionEnabled = [string]$mp.RealTimeProtectionEnabled
      IoavProtectionEnabled = [string]$mp.IoavProtectionEnabled
      NISEnabled = [string]$mp.NISEnabled
      IsTamperProtected = [string]$mp.IsTamperProtected
      AntivirusSignatureAge = [string]$mp.AntivirusSignatureAge
      QuickScanAge = [string]$mp.QuickScanAge
      FullScanAge = [string]$mp.FullScanAge
    })
  } catch {
    Add-Issue "Get-MpComputerStatus: $($_.Exception.Message)"
  }

  try {
    $avs = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
    foreach ($a in $avs) {
      $surface.AvProducts += New-Object psobject -Property ([ordered]@{
        DisplayName = Get-CimProp $a 'displayName'
        PathToSignedProductExe = Get-CimProp $a 'pathToSignedProductExe'
        ProductState = Get-CimProp $a 'productState'
      })
    }
  } catch { }

  try {
    $fwp = @(Get-NetFirewallProfile -ErrorAction Stop)
    foreach ($p in $fwp) {
      $surface.FirewallProfiles += New-Object psobject -Property ([ordered]@{
        Name = [string]$p.Name
        Enabled = [string]$p.Enabled
        DefaultInboundAction = [string]$p.DefaultInboundAction
        DefaultOutboundAction = [string]$p.DefaultOutboundAction
      })
    }
  } catch { }

  try {
    $bl = @(Get-BitLockerVolume -ErrorAction Stop)
    foreach ($v in $bl) {
      $surface.BitLocker += New-Object psobject -Property ([ordered]@{
        MountPoint = [string]$v.MountPoint
        VolumeStatus = [string]$v.VolumeStatus
        ProtectionStatus = [string]$v.ProtectionStatus
        EncryptionPercentage = [string]$v.EncryptionPercentage
        VolumeType = [string]$v.VolumeType
      })
    }
  } catch { }

  try {
    $hf = @(Get-HotFix -ErrorAction Stop)
    $surface.HotFixes = @(
      $hf | Sort-Object @{ Expression = { try { [datetime]$_.InstalledOn } catch { [datetime]::MinValue } }; Descending = $true } |
        Select-Object -First 20 |
        ForEach-Object {
          New-Object psobject -Property ([ordered]@{
            HotFixID = [string]$_.HotFixID
            Description = [string]$_.Description
            InstalledOn = $(try { $_.InstalledOn.ToString('yyyy-MM-dd') } catch { [string]$_.InstalledOn })
            InstalledBy = [string]$_.InstalledBy
          })
        }
    )
  } catch { }

  $surface.Env += New-Object psobject -Property ([ordered]@{ Name = 'OS'; Value = [string][Environment]::OSVersion })
  $surface.Env += New-Object psobject -Property ([ordered]@{ Name = 'CLR'; Value = [string]$PSVersionTable.CLRVersion })
  $surface.Env += New-Object psobject -Property ([ordered]@{ Name = 'PATH_length'; Value = $env:Path.Length })
  $surface.Env += New-Object psobject -Property ([ordered]@{ Name = 'TEMP'; Value = [string]$env:TEMP })
  $surface.Env += New-Object psobject -Property ([ordered]@{ Name = 'PROCESSOR_IDENTIFIER'; Value = [string]$env:PROCESSOR_IDENTIFIER })
  $surface.Env += New-Object psobject -Property ([ordered]@{ Name = 'NUMBER_OF_PROCESSORS'; Value = [string]$env:NUMBER_OF_PROCESSORS })
  $surface.Env += New-Object psobject -Property ([ordered]@{ Name = 'Culture'; Value = [string](Get-Culture) })
  $surface.Env += New-Object psobject -Property ([ordered]@{ Name = 'UICulture'; Value = [string](Get-UICulture) })

  $listKeys = @(
    'Cpu', 'Enclosure', 'Gpu', 'Disks', 'PhysicalDisks', 'Volumes', 'PageFileSettings',
    'Battery', 'Adapters', 'NicAdvanced', 'Policy', 'Features', 'Programs', 'AppX',
    'ProblemDevices', 'DriversByPublisher', 'EventsSystemError', 'EventsAppError',
    'AvProducts', 'FirewallProfiles', 'BitLocker', 'HotFixes', 'StartupApproved', 'Env'
  )
  foreach ($k in $listKeys) {
    $surface[$k] = @($surface[$k])
  }

  $pct = 0
  try { if ($null -ne $surface.PcSystemType) { $pct = [int]$surface.PcSystemType } } catch { }
  $hasBat = $surface.Battery.Count -gt 0
  if ($pct -eq 2 -or $hasBat) { $surface.ChassisHint = 'laptop' }
  elseif ($pct -eq 1 -or $pct -eq 3) { $surface.ChassisHint = 'desktop' }
  elseif ($pct -gt 0) { $surface.ChassisHint = ('pcsystemtype-' + $pct) }

  $media = @($surface.PhysicalDisks | ForEach-Object { [string]$_.MediaType })
  $bus = @($surface.PhysicalDisks | ForEach-Object { [string]$_.BusType })
  $uniqM = @($media | Where-Object { $_ } | Select-Object -Unique)
  if ($bus -contains 'NVMe') { $surface.DiskHint = 'nvme' }
  elseif ($uniqM.Count -gt 1) { $surface.DiskHint = 'mixed' }
  elseif ($uniqM -contains 'SSD') { $surface.DiskHint = 'ssd' }
  elseif ($uniqM -contains 'HDD') { $surface.DiskHint = 'hdd' }
  elseif ($surface.PhysicalDisks.Count -gt 0) { $surface.DiskHint = ($uniqM -join ',') }

  $gpuNames = @($surface.Gpu | ForEach-Object { [string]$_.Name })
  $blob = ($gpuNames -join ' ').ToLowerInvariant()
  $hasNv = $blob -match 'nvidia'
  $hasAmdD = $blob -match 'radeon' -and $blob -notmatch '780m|760m|680m|graphics'
  $hasIgp = $blob -match 'uhd|iris|radeon 7|780m|graphics'
  if ($hasNv -and $hasIgp) { $surface.GpuHint = 'hybrid' }
  elseif ($hasNv -or $hasAmdD) { $surface.GpuHint = 'discrete' }
  elseif ($gpuNames.Count -gt 0) { $surface.GpuHint = 'integrated' }

  if ($hasBat) {
    $bs = Get-CimProp $surface.Battery[0] 'BatteryStatus'
    if ($bs -eq 2) { $surface.PowerHint = 'ac' }
    elseif ($bs -eq 1) { $surface.PowerHint = 'dc' }
    else { $surface.PowerHint = ('battery-status-' + $bs) }
  } else {
    $surface.PowerHint = 'ac-desktop-assumed'
  }

  return $surface
}

function Write-SystemSurfaceMarkdown {
  param($Sb, $Surface)

  [void]$Sb.AppendLine("## Decision facts for universal tweaks")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine("The analyzing agent must emit **IF-THEN** rules keyed by these facts so the same advice can be reused on other PCs. Do not emit a single blind .reg pack.")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine("| Fact | Value |")
  [void]$Sb.AppendLine("| --- | --- |")
  [void]$Sb.AppendLine("| ChassisHint | $(Escape-MdCell $Surface.ChassisHint) |")
  [void]$Sb.AppendLine("| DiskHint | $(Escape-MdCell $Surface.DiskHint) |")
  [void]$Sb.AppendLine("| GpuHint | $(Escape-MdCell $Surface.GpuHint) |")
  [void]$Sb.AppendLine("| PowerHint | $(Escape-MdCell $Surface.PowerHint) |")
  [void]$Sb.AppendLine("| PCSystemType | $(Escape-MdCell $Surface.PcSystemType) |")
  [void]$Sb.AppendLine("| AutomaticManagedPagefile | $(Escape-MdCell $Surface.AutomaticManagedPagefile) |")
  [void]$Sb.AppendLine()

  [void]$Sb.AppendLine("## CPU")
  [void]$Sb.AppendLine()
  Write-MdTable $Sb @('Name', 'Manufacturer', 'Cores', 'Logical', 'MaxClockMHz', 'CurrentClockMHz', 'L2', 'L3', 'VirtualizationFirmwareEnabled', 'Socket') $Surface.Cpu @('Name', 'Manufacturer', 'Cores', 'Logical', 'MaxClockMHz', 'CurrentClockMHz', 'L2', 'L3', 'VirtualizationFirmwareEnabled', 'Socket')

  [void]$Sb.AppendLine("## Firmware and board")
  [void]$Sb.AppendLine()
  if ($Surface.Bios) {
    [void]$Sb.AppendLine("| Field | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    [void]$Sb.AppendLine("| BIOS manufacturer | $(Escape-MdCell $Surface.Bios.Manufacturer) |")
    [void]$Sb.AppendLine("| SMBIOSBIOSVersion | $(Escape-MdCell $Surface.Bios.SMBIOSBIOSVersion) |")
    [void]$Sb.AppendLine("| BIOS date | $(Escape-MdCell $Surface.Bios.ReleaseDate) |")
    if ($Surface.Board) {
      [void]$Sb.AppendLine("| Board | $(Escape-MdCell $Surface.Board.Manufacturer) $(Escape-MdCell $Surface.Board.Product) $(Escape-MdCell $Surface.Board.Version) |")
    }
    if ($Surface.Product) {
      [void]$Sb.AppendLine("| Product | $(Escape-MdCell $Surface.Product.Vendor) $(Escape-MdCell $Surface.Product.Name) |")
    }
    [void]$Sb.AppendLine("| Secure Boot | $(Escape-MdCell $Surface.SecureBoot) |")
    [void]$Sb.AppendLine()
  }
  if ($Surface.Enclosure.Count -gt 0) {
    Write-MdTable $Sb @('Manufacturer', 'ChassisTypes', 'SerialNumber', 'SMBIOSAssetTag') $Surface.Enclosure @('Manufacturer', 'ChassisTypes', 'SerialNumber', 'SMBIOSAssetTag')
  }

  [void]$Sb.AppendLine("## GPU and display")
  [void]$Sb.AppendLine()
  Write-MdTable $Sb @('Name', 'AdapterCompatibility', 'DriverVersion', 'DriverDate', 'AdapterRAM', 'CurrentH', 'CurrentV', 'RefreshHz', 'BitsPerPixel', 'Status') $Surface.Gpu @('Name', 'AdapterCompatibility', 'DriverVersion', 'DriverDate', 'AdapterRAM', 'CurrentH', 'CurrentV', 'RefreshHz', 'BitsPerPixel', 'Status')
  if ($Surface.NvidiaSmi) {
    [void]$Sb.AppendLine("nvidia-smi:")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine('```')
    [void]$Sb.AppendLine($Surface.NvidiaSmi.Trim())
    [void]$Sb.AppendLine('```')
    [void]$Sb.AppendLine()
  }

  [void]$Sb.AppendLine("## Storage")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine("Win32_DiskDrive:")
  [void]$Sb.AppendLine()
  $diskView = $Surface.Disks | ForEach-Object {
    New-Object psobject -Property ([ordered]@{
      Model = $_.Model
      InterfaceType = $_.InterfaceType
      MediaType = $_.MediaType
      Size = (Format-Bytes $_.Size)
      Status = $_.Status
    })
  }
  Write-MdTable $Sb @('Model', 'InterfaceType', 'MediaType', 'Size', 'Status') $diskView @('Model', 'InterfaceType', 'MediaType', 'Size', 'Status')
  if ($Surface.PhysicalDisks.Count -gt 0) {
    [void]$Sb.AppendLine("Get-PhysicalDisk:")
    [void]$Sb.AppendLine()
    $pdView = $Surface.PhysicalDisks | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        FriendlyName = $_.FriendlyName
        MediaType = $_.MediaType
        BusType = $_.BusType
        Health = $_.HealthStatus
        Op = $_.OperationalStatus
        Size = (Format-Bytes $_.Size)
        Spindle = $_.SpindleSpeed
        FW = $_.FirmwareVersion
      })
    }
    Write-MdTable $Sb @('FriendlyName', 'MediaType', 'BusType', 'Health', 'Op', 'Size', 'Spindle', 'FW') $pdView @('FriendlyName', 'MediaType', 'BusType', 'Health', 'Op', 'Size', 'Spindle', 'FW')
  }
  $volView = $Surface.Volumes | ForEach-Object {
    New-Object psobject -Property ([ordered]@{
      DeviceID = $_.DeviceID
      DriveType = $_.DriveType
      FileSystem = $_.FileSystem
      VolumeName = $_.VolumeName
      Size = (Format-Bytes $_.Size)
      Free = (Format-Bytes $_.FreeSpace)
      Compressed = $_.Compressed
    })
  }
  Write-MdTable $Sb @('DeviceID', 'DriveType', 'FileSystem', 'VolumeName', 'Size', 'Free', 'Compressed') $volView @('DeviceID', 'DriveType', 'FileSystem', 'VolumeName', 'Size', 'Free', 'Compressed')
  if ($Surface.PageFileSettings.Count -gt 0) {
    [void]$Sb.AppendLine("Page file settings (0/0 usually means system-managed):")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('Name', 'InitialSize', 'MaximumSize') $Surface.PageFileSettings @('Name', 'InitialSize', 'MaximumSize')
  }

  [void]$Sb.AppendLine("## Battery")
  [void]$Sb.AppendLine()
  if ($Surface.Battery.Count -eq 0) {
    [void]$Sb.AppendLine("No Win32_Battery instance (typical desktop).")
    [void]$Sb.AppendLine()
  } else {
    Write-MdTable $Sb @('Name', 'Status', 'BatteryStatus', 'EstimatedChargeRemaining', 'EstimatedRunTime', 'DesignCapacity', 'Chemistry') $Surface.Battery @('Name', 'Status', 'BatteryStatus', 'EstimatedChargeRemaining', 'EstimatedRunTime', 'DesignCapacity', 'Chemistry')
    [void]$Sb.AppendLine("BatteryStatus 1 = discharging (DC), 2 = AC plugged in (common mapping).")
    [void]$Sb.AppendLine()
  }

  [void]$Sb.AppendLine("## Power")
  [void]$Sb.AppendLine()
  $powerBlocks = @(
    (New-Object psobject -Property @{ Title = 'Active scheme'; Text = $Surface.PowerActive }),
    (New-Object psobject -Property @{ Title = 'Scheme list'; Text = $Surface.PowerList }),
    (New-Object psobject -Property @{ Title = 'Available sleep states'; Text = $Surface.PowerAvailable })
  )
  foreach ($pb in $powerBlocks) {
    [void]$Sb.AppendLine("### $($pb.Title)")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine('```')
    if ($pb.Text) { [void]$Sb.AppendLine(([string]$pb.Text).Trim()) } else { [void]$Sb.AppendLine('(none / failed)') }
    [void]$Sb.AppendLine('```')
    [void]$Sb.AppendLine()
  }
  [void]$Sb.AppendLine("### powercfg /query SCHEME_CURRENT (truncated)")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine('```')
  if ($Surface.PowerQuery) { [void]$Sb.AppendLine(([string]$Surface.PowerQuery).Trim()) } else { [void]$Sb.AppendLine('(none / failed)') }
  [void]$Sb.AppendLine('```')
  [void]$Sb.AppendLine()

  [void]$Sb.AppendLine("## Boot configuration (bcdedit /enum current)")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine('```')
  if ($Surface.BcdCurrent) { [void]$Sb.AppendLine(([string]$Surface.BcdCurrent).Trim()) } else { [void]$Sb.AppendLine('(none / needs admin or failed)') }
  [void]$Sb.AppendLine('```')
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine("fsutil last-access:")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine('```')
  if ($Surface.FsutilLastAccess) { [void]$Sb.AppendLine(([string]$Surface.FsutilLastAccess).Trim()) } else { [void]$Sb.AppendLine('(none / failed)') }
  [void]$Sb.AppendLine('```')
  [void]$Sb.AppendLine()

  [void]$Sb.AppendLine("## Security posture (report only)")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine("Do not recommend turning these off for FPS.")
  [void]$Sb.AppendLine()
  if ($Surface.Tpm) {
    [void]$Sb.AppendLine("| TPM field | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    [void]$Sb.AppendLine("| TpmPresent | $(Escape-MdCell $Surface.Tpm.TpmPresent) |")
    [void]$Sb.AppendLine("| TpmReady | $(Escape-MdCell $Surface.Tpm.TpmReady) |")
    [void]$Sb.AppendLine("| TpmEnabled | $(Escape-MdCell $Surface.Tpm.TpmEnabled) |")
    [void]$Sb.AppendLine("| Manufacturer | $(Escape-MdCell $Surface.Tpm.ManufacturerIdTxt) $(Escape-MdCell $Surface.Tpm.ManufacturerVersion) |")
    [void]$Sb.AppendLine()
  }
  if ($Surface.DeviceGuard) {
    [void]$Sb.AppendLine("| Device Guard | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    [void]$Sb.AppendLine("| VBS status | $(Escape-MdCell $Surface.DeviceGuard.VirtualizationBasedSecurityStatus) |")
    [void]$Sb.AppendLine("| CI enforcement | $(Escape-MdCell $Surface.DeviceGuard.CodeIntegrityPolicyEnforcementStatus) |")
    [void]$Sb.AppendLine("| UMCI | $(Escape-MdCell $Surface.DeviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus) |")
    [void]$Sb.AppendLine("| SecurityServicesRunning | $(Escape-MdCell $Surface.DeviceGuard.SecurityServicesRunning) |")
    [void]$Sb.AppendLine("| SecurityServicesConfigured | $(Escape-MdCell $Surface.DeviceGuard.SecurityServicesConfigured) |")
    [void]$Sb.AppendLine()
  }
  if ($Surface.MMAgent) {
    [void]$Sb.AppendLine("| MMAgent | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    [void]$Sb.AppendLine("| MemoryCompression | $(Escape-MdCell $Surface.MMAgent.MemoryCompression) |")
    [void]$Sb.AppendLine("| ApplicationLaunchPrefetching | $(Escape-MdCell $Surface.MMAgent.ApplicationLaunchPrefetching) |")
    [void]$Sb.AppendLine("| PageCombining | $(Escape-MdCell $Surface.MMAgent.PageCombining) |")
    [void]$Sb.AppendLine("| OperationAPI | $(Escape-MdCell $Surface.MMAgent.OperationAPI) |")
    [void]$Sb.AppendLine()
  }

  [void]$Sb.AppendLine("## Network adapters")
  [void]$Sb.AppendLine()
  Write-MdTable $Sb @('Name', 'InterfaceDescription', 'Status', 'LinkSpeed', 'MediaType', 'PhysicalMediaType', 'DriverVersion') $Surface.Adapters @('Name', 'InterfaceDescription', 'Status', 'LinkSpeed', 'MediaType', 'PhysicalMediaType', 'DriverVersion')
  if ($Surface.Offload) {
    [void]$Sb.AppendLine("| Offload | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    [void]$Sb.AppendLine("| RSS | $(Escape-MdCell $Surface.Offload.ReceiveSideScaling) |")
    [void]$Sb.AppendLine("| TaskOffload | $(Escape-MdCell $Surface.Offload.TaskOffload) |")
    [void]$Sb.AppendLine("| NetworkDirect | $(Escape-MdCell $Surface.Offload.NetworkDirect) |")
    [void]$Sb.AppendLine("| PacketDirect | $(Escape-MdCell $Surface.Offload.PacketDirect) |")
    [void]$Sb.AppendLine()
  }
  if ($Surface.NicAdvanced.Count -gt 0) {
    [void]$Sb.AppendLine("NIC advanced (power/offload/RSS/jumbo subset):")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('Name', 'DisplayName', 'DisplayValue', 'RegistryKeyword', 'RegistryValue') $Surface.NicAdvanced @('Name', 'DisplayName', 'DisplayValue', 'RegistryKeyword', 'RegistryValue')
  }

  [void]$Sb.AppendLine("## Performance-related policy (current values)")
  [void]$Sb.AppendLine()
  Write-MdTable $Sb @('Path', 'Name', 'Value', 'Note') $Surface.Policy @('Path', 'Name', 'Value', 'Note')

  [void]$Sb.AppendLine("## StartupApproved (enabled vs disabled in Task Manager Startup)")
  [void]$Sb.AppendLine()
  if ($Surface.StartupApproved.Count -eq 0) {
    [void]$Sb.AppendLine("None readable.")
    [void]$Sb.AppendLine()
  } else {
    Write-MdTable $Sb @('Hive', 'Name', 'State') $Surface.StartupApproved @('Hive', 'Name', 'State')
  }

  [void]$Sb.AppendLine("## Windows optional features")
  [void]$Sb.AppendLine()
  if ($Surface.Features.Count -eq 0) {
    [void]$Sb.AppendLine("None returned. Get-WindowsOptionalFeature / DISM need Administrator; re-run via Run-Snapshot.bat elevated.")
    [void]$Sb.AppendLine()
  } else {
    Write-MdTable $Sb @('FeatureName', 'State') $Surface.Features @('FeatureName', 'State')
  }

  [void]$Sb.AppendLine("## Installed programs (Uninstall registry)")
  [void]$Sb.AppendLine()
  if ($Surface.Programs.Count -eq 0) {
    [void]$Sb.AppendLine("_Skipped by -SkipHeavy or none found._")
    [void]$Sb.AppendLine()
  } else {
    Write-MdTable $Sb @('DisplayName', 'Publisher', 'Version', 'InstallDate', 'EstimatedSizeKb', 'Hive') $Surface.Programs @('DisplayName', 'Publisher', 'Version', 'InstallDate', 'EstimatedSizeKb', 'Hive')
  }

  [void]$Sb.AppendLine("## AppX / Store packages")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine("AllUsers=$($Surface.AppXAllUsers). Do not remove NonRemovable or Framework packages.")
  [void]$Sb.AppendLine()
  if ($Surface.AppX.Count -eq 0) {
    [void]$Sb.AppendLine("_Skipped by -SkipHeavy or none found._")
    [void]$Sb.AppendLine()
  } else {
    Write-MdTable $Sb @('Name', 'Version', 'SignatureKind', 'NonRemovable', 'IsFramework', 'InstallLocation') $Surface.AppX @('Name', 'Version', 'SignatureKind', 'NonRemovable', 'IsFramework', 'InstallLocation')
  }

  [void]$Sb.AppendLine("## Problem devices")
  [void]$Sb.AppendLine()
  if ($Surface.ProblemDevices.Count -eq 0) {
    [void]$Sb.AppendLine("None with Status other than OK/Unknown.")
    [void]$Sb.AppendLine()
  } else {
    Write-MdTable $Sb @('Status', 'Class', 'FriendlyName', 'InstanceId', 'Problem') $Surface.ProblemDevices @('Status', 'Class', 'FriendlyName', 'InstanceId', 'Problem')
  }

  [void]$Sb.AppendLine("## Drivers by publisher")
  [void]$Sb.AppendLine()
  Write-MdTable $Sb @('Manufacturer', 'Drivers') $Surface.DriversByPublisher @('Manufacturer', 'Drivers')

  [void]$Sb.AppendLine("## Event log errors (7 days, top providers, max 250 events each)")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine("### System")
  [void]$Sb.AppendLine()
  if ($Surface.EventsSystemError.Count -eq 0) {
    [void]$Sb.AppendLine("None collected.")
    [void]$Sb.AppendLine()
  } else {
    Write-MdTable $Sb @('Provider', 'Errors7d') $Surface.EventsSystemError @('Provider', 'Errors7d')
  }
  [void]$Sb.AppendLine("### Application")
  [void]$Sb.AppendLine()
  if ($Surface.EventsAppError.Count -eq 0) {
    [void]$Sb.AppendLine("None collected.")
    [void]$Sb.AppendLine()
  } else {
    Write-MdTable $Sb @('Provider', 'Errors7d') $Surface.EventsAppError @('Provider', 'Errors7d')
  }

  [void]$Sb.AppendLine("## Defender and other AV")
  [void]$Sb.AppendLine()
  if ($Surface.Defender) {
    [void]$Sb.AppendLine("| Field | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    [void]$Sb.AppendLine("| AMServiceEnabled | $(Escape-MdCell $Surface.Defender.AMServiceEnabled) |")
    [void]$Sb.AppendLine("| AntivirusEnabled | $(Escape-MdCell $Surface.Defender.AntivirusEnabled) |")
    [void]$Sb.AppendLine("| RealTimeProtectionEnabled | $(Escape-MdCell $Surface.Defender.RealTimeProtectionEnabled) |")
    [void]$Sb.AppendLine("| NISEnabled | $(Escape-MdCell $Surface.Defender.NISEnabled) |")
    [void]$Sb.AppendLine("| IsTamperProtected | $(Escape-MdCell $Surface.Defender.IsTamperProtected) |")
    [void]$Sb.AppendLine("| AntivirusSignatureAge | $(Escape-MdCell $Surface.Defender.AntivirusSignatureAge) |")
    [void]$Sb.AppendLine("| QuickScanAge | $(Escape-MdCell $Surface.Defender.QuickScanAge) |")
    [void]$Sb.AppendLine("| FullScanAge | $(Escape-MdCell $Surface.Defender.FullScanAge) |")
    [void]$Sb.AppendLine()
  }
  if ($Surface.AvProducts.Count -gt 0) {
    Write-MdTable $Sb @('DisplayName', 'PathToSignedProductExe', 'ProductState') $Surface.AvProducts @('DisplayName', 'PathToSignedProductExe', 'ProductState')
  }

  [void]$Sb.AppendLine("## Firewall profiles")
  [void]$Sb.AppendLine()
  Write-MdTable $Sb @('Name', 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction') $Surface.FirewallProfiles @('Name', 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction')

  [void]$Sb.AppendLine("## BitLocker")
  [void]$Sb.AppendLine()
  if ($Surface.BitLocker.Count -eq 0) {
    [void]$Sb.AppendLine("None readable (module missing, or no volumes).")
    [void]$Sb.AppendLine()
  } else {
    Write-MdTable $Sb @('MountPoint', 'VolumeStatus', 'ProtectionStatus', 'EncryptionPercentage', 'VolumeType') $Surface.BitLocker @('MountPoint', 'VolumeStatus', 'ProtectionStatus', 'EncryptionPercentage', 'VolumeType')
  }

  [void]$Sb.AppendLine("## Recent hotfixes (up to 20)")
  [void]$Sb.AppendLine()
  Write-MdTable $Sb @('HotFixID', 'Description', 'InstalledOn', 'InstalledBy') $Surface.HotFixes @('HotFixID', 'Description', 'InstalledOn', 'InstalledBy')

  [void]$Sb.AppendLine("## Environment")
  [void]$Sb.AppendLine()
  Write-MdTable $Sb @('Name', 'Value') $Surface.Env @('Name', 'Value')
}
