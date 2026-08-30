#requires -Version 5.1
<#
  Extended read-only system telemetry for process-deglose. Dot-sourced from
  snapshot.ps1. Uses helpers defined there: Add-Issue, Get-RegValue,
  Escape-MdCell, Write-MdTable.

  Everything here is READ-ONLY: network layer 2/3 state, local accounts,
  groups, shares, logon sessions, thermal zones, battery wear, audio devices,
  monitors, and OS facts. Nothing is changed on the machine.
#>

function Get-LogonTypeName {
  param($Type)
  switch ([int]$Type) {
    2 { return 'Interactive' }
    3 { return 'Network' }
    4 { return 'Batch' }
    5 { return 'Service' }
    7 { return 'Unlock' }
    8 { return 'NetworkCleartext' }
    9 { return 'NewCredentials' }
    10 { return 'RemoteInteractive' }
    11 { return 'CachedInteractive' }
    default { return [string]$Type }
  }
}

function Collect-ExtendedSurface {
  $e = [ordered]@{}
  $e.Facts = [ordered]@{}
  $e.Routes = @()
  $e.Neighbors = @()
  $e.DnsCache = @()
  $e.DnsServers = @()
  $e.AdapterStats = @()
  $e.UdpEndpoints = @()
  $e.Users = @()
  $e.Groups = @()
  $e.Shares = @()
  $e.LogonSessions = @()
  $e.Thermal = @()
  $e.BatteryWear = $null
  $e.Audio = @()
  $e.Monitors = @()

  # --- OS facts ---
  $os = $null
  try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { }
  if ($os) {
    try {
      if ($os.InstallDate) { $e.Facts.InstallDate = ([datetime]$os.InstallDate).ToString('o') }
      if ($os.LastBootUpTime) {
        $uptime = (Get-Date) - ([datetime]$os.LastBootUpTime)
        $e.Facts.UptimeSeconds = [int64]$uptime.TotalSeconds
      }
    } catch { }
  }
  $ubr = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
  $build = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'CurrentBuildNumber'
  if ($ubr -ne $null) { $e.Facts.UBR = $ubr }
  if ($build -ne $null) { $e.Facts.CurrentBuild = $build }
  try {
    $tz = Get-TimeZone -ErrorAction Stop
    $e.Facts.TimeZone = "$($tz.Id) ($($tz.DisplayName))"
  } catch { }

  # --- Network layer 2/3 ---
  Write-Host '       network L2/L3...'
  try {
    $e.Routes = @(Get-NetRoute -ErrorAction Stop | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        DestinationPrefix = [string]$_.DestinationPrefix
        NextHop = [string]$_.NextHop
        RouteMetric = $_.RouteMetric
        InterfaceAlias = [string]$_.InterfaceAlias
        AddressFamily = [string]$_.AddressFamily
        State = [string]$_.State
      })
    })
  } catch { Add-Issue "Get-NetRoute: $($_.Exception.Message)" }
  try {
    $e.Neighbors = @(Get-NetNeighbor -ErrorAction Stop | Select-Object -First 300 | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        IPAddress = [string]$_.IPAddress
        LinkLayerAddress = [string]$_.LinkLayerAddress
        State = [string]$_.State
        InterfaceAlias = [string]$_.InterfaceAlias
        AddressFamily = [string]$_.AddressFamily
      })
    })
  } catch { Add-Issue "Get-NetNeighbor: $($_.Exception.Message)" }
  try {
    $e.DnsCache = @(Get-DnsClientCache -ErrorAction Stop | Select-Object -First 300 | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Entry = [string]$_.Entry
        Data = [string]$_.Data
        Type = [string]$_.Type
        TimeToLive = $_.TimeToLive
        Status = [string]$_.Status
      })
    })
  } catch { Add-Issue "Get-DnsClientCache: $($_.Exception.Message)" }
  try {
    $e.DnsServers = @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        InterfaceAlias = [string]$_.InterfaceAlias
        AddressFamily = [string]$_.AddressFamily
        ServerAddresses = ([string]::Join(', ', @($_.ServerAddresses)))
      })
    })
  } catch { Add-Issue "Get-DnsClientServerAddress: $($_.Exception.Message)" }
  try {
    $e.AdapterStats = @(Get-NetAdapterStatistics -ErrorAction Stop | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Name = [string]$_.Name
        ReceivedBytes = [int64]$_.ReceivedBytes
        SentBytes = [int64]$_.SentBytes
        ReceivedDiscards = [int64]$_.ReceivedDiscards
        ReceivedErrors = [int64]$_.ReceivedErrors
        OutboundDiscards = [int64]$_.OutboundDiscards
        OutboundErrors = [int64]$_.OutboundErrors
      })
    })
  } catch { Add-Issue "Get-NetAdapterStatistics: $($_.Exception.Message)" }
  try {
    $e.UdpEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop | Select-Object -First 300 | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        LocalAddress = [string]$_.LocalAddress
        LocalPort = [int]$_.LocalPort
        OwningProcess = [int]$_.OwningProcess
      })
    })
  } catch { Add-Issue "Get-NetUDPEndpoint: $($_.Exception.Message)" }

  # --- Accounts, groups, shares, logon sessions ---
  Write-Host '       accounts / groups / shares...'
  try {
    $e.Users = @(Get-CimInstance -ClassName Win32_UserAccount -ErrorAction Stop | Where-Object { $_.LocalAccount } | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Name = [string]$_.Name
        FullName = [string]$_.FullName
        Disabled = [bool]$_.Disabled
        Lockout = [bool]$_.Lockout
        SID = [string]$_.SID
      })
    })
  } catch { Add-Issue "Win32_UserAccount: $($_.Exception.Message)" }
  try {
    $e.Groups = @(Get-CimInstance -ClassName Win32_Group -ErrorAction Stop | Where-Object { $_.LocalAccount } | Select-Object -First 250 | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Name = [string]$_.Name
        SID = [string]$_.SID
      })
    })
  } catch { Add-Issue "Win32_Group: $($_.Exception.Message)" }
  try {
    $e.Shares = @(Get-CimInstance -ClassName Win32_Share -ErrorAction Stop | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Name = [string]$_.Name
        Path = [string]$_.Path
        Type = [int]$_.Type
        Description = [string]$_.Description
      })
    })
  } catch { Add-Issue "Win32_Share: $($_.Exception.Message)" }
  try {
    $e.LogonSessions = @(Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop | Select-Object -First 100 | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        LogonId = [string]$_.LogonId
        LogonType = (Get-LogonTypeName $_.LogonType)
        StartTime = $(if ($_.StartTime) { ([datetime]$_.StartTime).ToString('o') } else { $null })
        AuthenticationPackage = [string]$_.AuthenticationPackage
      })
    })
  } catch { Add-Issue "Win32_LogonSession: $($_.Exception.Message)" }

  # --- Thermal zones (best effort, root\wmi) ---
  Write-Host '       thermal / battery wear...'
  try {
    $e.Thermal = @(Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | ForEach-Object {
      $c = $null
      if ($_.CurrentTemperature -ne $null) {
        $c = [math]::Round(([double]$_.CurrentTemperature / 10.0) - 273.15, 1)
      }
      New-Object psobject -Property ([ordered]@{
        Instance = [string]$_.InstanceName
        TemperatureC = $c
      })
    })
  } catch { Add-Issue "MSAcpi_ThermalZoneTemperature: $($_.Exception.Message)" }

  try {
    $fullCap = Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1
    $staticData = Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1
    if ($fullCap -and $staticData -and $staticData.DesignedCapacity -and $fullCap.FullChargedCapacity) {
      $designed = [double]$staticData.DesignedCapacity
      $full = [double]$fullCap.FullChargedCapacity
      if ($designed -gt 0) {
        $e.BatteryWear = [ordered]@{
          DesignedCapacityMWh = [int64]$designed
          FullChargedCapacityMWh = [int64]$full
          WearPercent = [math]::Round(100.0 * (1.0 - ($full / $designed)), 1)
        }
      }
    }
  } catch { Add-Issue "Battery wear (root\wmi): $($_.Exception.Message)" }

  # --- Audio and monitors ---
  Write-Host '       audio / monitors...'
  try {
    $e.Audio = @(Get-CimInstance -ClassName Win32_SoundDevice -ErrorAction Stop | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Name = [string]$_.Name
        Manufacturer = [string]$_.Manufacturer
        Status = [string]$_.Status
      })
    })
  } catch { Add-Issue "Win32_SoundDevice: $($_.Exception.Message)" }
  try {
    $e.Monitors = @(Get-CimInstance -ClassName Win32_DesktopMonitor -ErrorAction Stop | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Name = [string]$_.Name
        ScreenWidth = $_.ScreenWidth
        ScreenHeight = $_.ScreenHeight
        Status = [string]$_.Status
      })
    })
  } catch { Add-Issue "Win32_DesktopMonitor: $($_.Exception.Message)" }

  return $e
}

function Write-ExtendedSurfaceMarkdown {
  param($Sb, $Extended)
  if ($null -eq $Extended) { return }

  [void]$Sb.AppendLine("## Extended telemetry")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine("More read-only system data: network layer 2/3, accounts/groups/shares/logon, thermal, battery wear, audio, monitors, OS facts. Nothing is changed.")
  [void]$Sb.AppendLine()

  if ($Extended.Facts -and $Extended.Facts.Count -gt 0) {
    [void]$Sb.AppendLine("### OS facts")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine("| Field | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    foreach ($k in $Extended.Facts.Keys) {
      $v = $Extended.Facts[$k]
      if ($k -eq 'UptimeSeconds' -and $v -ne $null) { $v = "$v s" }
      [void]$Sb.AppendLine("| $(Escape-MdCell $k) | $(Escape-MdCell $v) |")
    }
    [void]$Sb.AppendLine()
  }

  if ($Extended.AdapterStats -and $Extended.AdapterStats.Count -gt 0) {
    [void]$Sb.AppendLine("### Network adapter statistics (since counters reset)")
    [void]$Sb.AppendLine()
    $av = $Extended.AdapterStats | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Adapter = $_.Name
        Received = (Format-Bytes $_.ReceivedBytes)
        Sent = (Format-Bytes $_.SentBytes)
        RxDiscards = $_.ReceivedDiscards
        RxErrors = $_.ReceivedErrors
        TxDiscards = $_.OutboundDiscards
        TxErrors = $_.OutboundErrors
      })
    }
    Write-MdTable $Sb @('Adapter', 'Received', 'Sent', 'RxDiscards', 'RxErrors', 'TxDiscards', 'TxErrors') $av @('Adapter', 'Received', 'Sent', 'RxDiscards', 'RxErrors', 'TxDiscards', 'TxErrors')
  }

  if ($Extended.Routes -and $Extended.Routes.Count -gt 0) {
    [void]$Sb.AppendLine("### Routes (top 40 of $($Extended.Routes.Count))")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('DestinationPrefix', 'NextHop', 'RouteMetric', 'InterfaceAlias', 'AddressFamily', 'State') @($Extended.Routes | Select-Object -First 40) @('DestinationPrefix', 'NextHop', 'RouteMetric', 'InterfaceAlias', 'AddressFamily', 'State')
  }

  if ($Extended.Neighbors -and $Extended.Neighbors.Count -gt 0) {
    [void]$Sb.AppendLine("### ARP / ND neighbors (top 60 of $($Extended.Neighbors.Count))")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('IPAddress', 'LinkLayerAddress', 'State', 'InterfaceAlias', 'AddressFamily') @($Extended.Neighbors | Select-Object -First 60) @('IPAddress', 'LinkLayerAddress', 'State', 'InterfaceAlias', 'AddressFamily')
  }

  if ($Extended.DnsCache -and $Extended.DnsCache.Count -gt 0) {
    [void]$Sb.AppendLine("### DNS client cache (top 100 of $($Extended.DnsCache.Count))")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('Entry', 'Data', 'Type', 'TimeToLive', 'Status') @($Extended.DnsCache | Select-Object -First 100) @('Entry', 'Data', 'Type', 'TimeToLive', 'Status')
  }

  if ($Extended.DnsServers -and $Extended.DnsServers.Count -gt 0) {
    [void]$Sb.AppendLine("### DNS servers per adapter")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('InterfaceAlias', 'AddressFamily', 'ServerAddresses') $Extended.DnsServers @('InterfaceAlias', 'AddressFamily', 'ServerAddresses')
  }

  if ($Extended.UdpEndpoints -and $Extended.UdpEndpoints.Count -gt 0) {
    [void]$Sb.AppendLine("### UDP endpoints (top 100 of $($Extended.UdpEndpoints.Count))")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('LocalAddress', 'LocalPort', 'OwningProcess') @($Extended.UdpEndpoints | Select-Object -First 100) @('LocalAddress', 'LocalPort', 'OwningProcess')
  }

  if ($Extended.Users -and $Extended.Users.Count -gt 0) {
    [void]$Sb.AppendLine("### Local user accounts ($($Extended.Users.Count))")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('Name', 'FullName', 'Disabled', 'Lockout', 'SID') $Extended.Users @('Name', 'FullName', 'Disabled', 'Lockout', 'SID')
  }

  if ($Extended.Groups -and $Extended.Groups.Count -gt 0) {
    [void]$Sb.AppendLine("### Local groups (top 100 of $($Extended.Groups.Count))")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('Name', 'SID') @($Extended.Groups | Select-Object -First 100) @('Name', 'SID')
  }

  if ($Extended.Shares -and $Extended.Shares.Count -gt 0) {
    [void]$Sb.AppendLine("### SMB / admin shares")
    [void]$Sb.AppendLine()
    $sv = $Extended.Shares | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Name = $_.Name
        Path = $_.Path
        Type = $_.Type
        Description = $_.Description
      })
    }
    Write-MdTable $Sb @('Name', 'Path', 'Type', 'Description') $sv @('Name', 'Path', 'Type', 'Description')
  }

  if ($Extended.LogonSessions -and $Extended.LogonSessions.Count -gt 0) {
    [void]$Sb.AppendLine("### Logon sessions (top 60 of $($Extended.LogonSessions.Count))")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('LogonId', 'LogonType', 'StartTime', 'AuthenticationPackage') @($Extended.LogonSessions | Select-Object -First 60) @('LogonId', 'LogonType', 'StartTime', 'AuthenticationPackage')
  }

  if ($Extended.Thermal -and $Extended.Thermal.Count -gt 0) {
    [void]$Sb.AppendLine("### Thermal zones (ACPI, best effort)")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine("Temperature in Celsius (from MSAcpi_ThermalZoneTemperature, tenths of Kelvin). May be missing on many machines.")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('Instance', 'TemperatureC') $Extended.Thermal @('Instance', 'TemperatureC')
  }

  if ($Extended.BatteryWear) {
    [void]$Sb.AppendLine("### Battery wear (root\wmi)")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine("| Field | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    [void]$Sb.AppendLine("| Designed capacity | $($Extended.BatteryWear.DesignedCapacityMWh) mWh |")
    [void]$Sb.AppendLine("| Full charge now | $($Extended.BatteryWear.FullChargedCapacityMWh) mWh |")
    [void]$Sb.AppendLine("| Wear | $($Extended.BatteryWear.WearPercent) % |")
    [void]$Sb.AppendLine()
  }

  if ($Extended.Audio -and $Extended.Audio.Count -gt 0) {
    [void]$Sb.AppendLine("### Audio devices")
    [void]$Sb.AppendLine()
    Write-MdTable $Sb @('Name', 'Manufacturer', 'Status') $Extended.Audio @('Name', 'Manufacturer', 'Status')
  }

  if ($Extended.Monitors -and $Extended.Monitors.Count -gt 0) {
    [void]$Sb.AppendLine("### Monitors")
    [void]$Sb.AppendLine()
    $mv = $Extended.Monitors | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Name = $_.Name
        Width = $_.ScreenWidth
        Height = $_.ScreenHeight
        Status = $_.Status
      })
    }
    Write-MdTable $Sb @('Name', 'Width', 'Height', 'Status') $mv @('Name', 'Width', 'Height', 'Status')
  }

  [void]$Sb.AppendLine()
}
