#requires -Version 5.1
<#
  Communication-surface telemetry for process-deglose. Dot-sourced from
  snapshot.ps1. Uses helpers defined there: Add-Issue, Get-RegValue,
  Escape-MdCell, Format-Bytes, Write-MdTable, and script-scope data:
  $rows (processes), $netRows (TCP), $svcByPid (services per PID),
  $extended (UDP endpoints).

  Everything here is READ-ONLY: named pipes, firewall rules, hosts file,
  system proxy, per-process connection summaries, services on listening ports.
  Nothing is changed on the machine.
#>

function Collect-CommunicationSurface {
  $c = [ordered]@{}
  $c.WindowsFacts = [ordered]@{}
  $c.NamedPipes = @()
  $c.FirewallRules = @()
  $c.FirewallSummary = [ordered]@{}
  $c.Hosts = $null
  $c.HostsLines = 0
  $c.Proxy = [ordered]@{}
  $c.TopTalkers = @()
  $c.ServicesOnPorts = @()
  $c.UdpSummary = @()

  # --- Windows edition facts ---
  try {
    $c.WindowsFacts.ProductName = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'ProductName'
    $c.WindowsFacts.DisplayVersion = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion'
    $c.WindowsFacts.EditionID = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'EditionID'
    $c.WindowsFacts.ReleaseId = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'ReleaseId'
  } catch { }

  # --- Named pipes (active IPC endpoints) ---
  Write-Host '       named pipes...'
  try {
    $pipes = @([System.IO.Directory]::GetFiles('\\.\pipe\'))
    if ($pipes) {
      $c.NamedPipes = @($pipes | Select-Object -First 500 | ForEach-Object {
        $n = [string]$_
        if ($n -match '^\\\\.\\pipe\\(.+)$') { $n = $Matches[1] }
        New-Object psobject -Property ([ordered]@{ Name = $n })
      })
    }
  } catch {
    Add-Issue "Named pipes: $($_.Exception.Message)"
  }

  # --- Windows Firewall rules (joined with port + application filters) ---
  Write-Host '       firewall rules...'
  try {
    $rules = @(Get-NetFirewallRule -ErrorAction Stop | Select-Object -First 1200)
    $portMap = @{}
    try {
      foreach ($pf in @(Get-NetFirewallPortFilter -ErrorAction Stop) | Select-Object -First 1200) {
        $pid_ = [string]$pf.InstanceID
        if (-not $portMap.ContainsKey($pid_)) {
          $portMap[$pid_] = [ordered]@{
            Protocol = [string]$pf.Protocol
            LocalPort = ([string]::Join(', ', @($pf.LocalPort)))
            RemotePort = ([string]::Join(', ', @($pf.RemotePort)))
          }
        }
      }
    } catch { }
    $appMap = @{}
    try {
      foreach ($af in @(Get-NetFirewallApplicationFilter -ErrorAction Stop) | Select-Object -First 1200) {
        $aid = [string]$af.InstanceID
        if (-not $appMap.ContainsKey($aid)) { $appMap[$aid] = [string]$af.Program }
      }
    } catch { }
    $ruleRows = @()
    $enabled = 0
    $block = 0
    $allow = 0
    foreach ($r in $rules) {
      $inst = [string]$r.InstanceID
      $isEnabled = [bool]$r.Enabled
      if ($isEnabled) { $enabled++ }
      $act = [string]$r.Action
      if ($act -eq 'Block') { $block++ } elseif ($act -eq 'Allow') { $allow++ }
      $pfv = $null
      if ($portMap.ContainsKey($inst)) { $pfv = $portMap[$inst] }
      $prog = $null
      if ($appMap.ContainsKey($inst)) { $prog = $appMap[$inst] }
      $ruleRows += New-Object psobject -Property ([ordered]@{
        DisplayName = [string]$r.DisplayName
        Name = $inst
        Enabled = $isEnabled
        Direction = [string]$r.Direction
        Action = $act
        Profile = [string]$r.Profile
        Protocol = $(if ($pfv) { $pfv.Protocol } else { $null })
        LocalPort = $(if ($pfv) { $pfv.LocalPort } else { $null })
        RemotePort = $(if ($pfv) { $pfv.RemotePort } else { $null })
        Program = $prog
      })
    }
    $c.FirewallRules = $ruleRows
    $c.FirewallSummary.Total = $rules.Count
    $c.FirewallSummary.Enabled = $enabled
    $c.FirewallSummary.Allow = $allow
    $c.FirewallSummary.Block = $block
  } catch {
    Add-Issue "Firewall rules: $($_.Exception.Message)"
  }

  # --- Hosts file ---
  Write-Host '       hosts / proxy...'
  try {
    $hostsPath = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hostsPath) {
      $all = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop)
      $meaningful = @($all | Where-Object { $_.Length -gt 0 -and -not $_.TrimStart().StartsWith('#') })
      $c.HostsLines = $meaningful.Count
      $c.Hosts = (@($all | Select-Object -First 150) -join "`n")
    }
  } catch {
    Add-Issue "Hosts file: $($_.Exception.Message)"
  }

  try {
    $ie = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $hk = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    $c.Proxy.ProxyEnable = (Get-RegValue $ie 'ProxyEnable' -Default $null)
    $c.Proxy.ProxyServer = (Get-RegValue $ie 'ProxyServer' -Default $null)
    $c.Proxy.ProxyOverride = (Get-RegValue $ie 'ProxyOverride' -Default $null)
    $c.Proxy.AutoConfigURL = (Get-RegValue $ie 'AutoConfigURL' -Default $null)
    $c.Proxy.MachineProxyServer = (Get-RegValue $hk 'ProxyServer' -Default $null)
    $c.Proxy.HttpProxy = $env:HTTP_PROXY
    $c.Proxy.HttpsProxy = $env:HTTPS_PROXY
    $c.Proxy.NoProxy = $env:NO_PROXY
  } catch { }

  # --- Top network talkers (processes by TCP + UDP connection counts) ---
  Write-Host '       top talkers...'
  try {
    $pidRow = @{}
    foreach ($r in $rows) {
      try { if (-not $pidRow.ContainsKey([int]$r.Pid)) { $pidRow[[int]$r.Pid] = $r } } catch { }
    }
    $tcpAgg = @{}
    foreach ($n in $netRows) {
      $p = [int]$n.Pid
      if (-not $tcpAgg.ContainsKey($p)) { $tcpAgg[$p] = [ordered]@{ Listen = 0; Established = 0 } }
      if ($n.State -eq 'Listen') { $tcpAgg[$p].Listen++ }
      elseif ($n.State -eq 'Established') { $tcpAgg[$p].Established++ }
    }
    $udpAgg = @{}
    if ($extended -and $extended.UdpEndpoints) {
      foreach ($u in $extended.UdpEndpoints) {
        $p = [int]$u.OwningProcess
        if ($udpAgg.ContainsKey($p)) { $udpAgg[$p]++ } else { $udpAgg[$p] = 1 }
      }
    }
    $talkers = @()
    foreach ($p in $tcpAgg.Keys) {
      $name = $null
      $path = $null
      $hint = $null
      if ($pidRow.ContainsKey($p)) {
        $name = $pidRow[$p].Name
        $path = $pidRow[$p].Path
        $hint = $pidRow[$p].IntegrityHint
      }
      $total = ($tcpAgg[$p].Listen + $tcpAgg[$p].Established)
      if ($udpAgg.ContainsKey($p)) { $total += [int]$udpAgg[$p] }
      $talkers += New-Object psobject -Property ([ordered]@{
        Pid = $p
        Process = $name
        Path = $path
        Hint = $hint
        Listen = $tcpAgg[$p].Listen
        Established = $tcpAgg[$p].Established
        Udp = $(if ($udpAgg.ContainsKey($p)) { [int]$udpAgg[$p] } else { 0 })
        Total = $total
      })
    }
    $c.TopTalkers = @($talkers | Sort-Object Total -Descending | Select-Object -First 60)
  } catch {
    Add-Issue "Top talkers: $($_.Exception.Message)"
  }

  # --- Services listening on TCP ports ---
  Write-Host '       services on ports...'
  try {
    $svcRows = @()
    foreach ($n in $netRows) {
      if ($n.State -ne 'Listen') { continue }
      $p = [int]$n.Pid
      $svcNames = $null
      if ($svcByPid -and $svcByPid.ContainsKey($p)) { $svcNames = ($svcByPid[$p] -join ', ') }
      $procName = $null
      if ($pidRow.ContainsKey($p)) { $procName = $pidRow[$p].Name }
      $svcRows += New-Object psobject -Property ([ordered]@{
        Service = $svcNames
        Process = $procName
        Pid = $p
        Port = [int]$n.LocalPort
        LocalAddress = [string]$n.LocalAddress
      })
    }
    $c.ServicesOnPorts = @($svcRows | Sort-Object Service, Port | Select-Object -First 200)
  } catch {
    Add-Issue "Services on ports: $($_.Exception.Message)"
  }

  return $c
}

function Write-CommunicationSurfaceMarkdown {
  param($Sb, $Communication)
  if ($null -eq $Communication) { return }

  [void]$Sb.AppendLine("## Communication surface")
  [void]$Sb.AppendLine()
  [void]$Sb.AppendLine("Read-only view of how processes talk: named pipes, firewall rules, hosts file, system proxy, per-process connection summaries, and services listening on ports. For live flows use the ETW trace with -KernelTraceDeep.")
  [void]$Sb.AppendLine()

  if ($Communication.WindowsFacts -and $Communication.WindowsFacts.Count -gt 0) {
    [void]$Sb.AppendLine("### Windows edition facts")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine("| Field | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    foreach ($k in $Communication.WindowsFacts.Keys) {
      [void]$Sb.AppendLine("| $(Escape-MdCell $k) | $(Escape-MdCell $Communication.WindowsFacts[$k]) |")
    }
    [void]$Sb.AppendLine()
  }

  if ($Communication.NamedPipes -and $Communication.NamedPipes.Count -gt 0) {
    [void]$Sb.AppendLine("### Named pipes ($($Communication.NamedPipes.Count) active)")
    [void]$Sb.AppendLine()
    $pv = @($Communication.NamedPipes | Select-Object -First 120) | ForEach-Object {
      New-Object psobject -Property ([ordered]@{ Pipe = $_.Name })
    }
    Write-MdTable $Sb @('Pipe') $pv @('Pipe')
    if ($Communication.NamedPipes.Count -gt 120) {
      [void]$Sb.AppendLine("_... and $($Communication.NamedPipes.Count - 120) more pipes (all in JSON)._")
      [void]$Sb.AppendLine()
    }
  }

  if ($Communication.FirewallRules -and $Communication.FirewallRules.Count -gt 0) {
    [void]$Sb.AppendLine("### Windows Firewall rules ($($Communication.FirewallRules.Count) rules; enabled $($Communication.FirewallSummary.Enabled), allow $($Communication.FirewallSummary.Allow), block $($Communication.FirewallSummary.Block))")
    [void]$Sb.AppendLine()
    $fw = @($Communication.FirewallRules | Where-Object { $_.Enabled } | Select-Object -First 250) | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        DisplayName = $_.DisplayName
        Direction = $_.Direction
        Action = $_.Action
        Profile = $_.Profile
        Protocol = $_.Protocol
        LocalPort = $_.LocalPort
        RemotePort = $_.RemotePort
        Program = $_.Program
      })
    }
    Write-MdTable $Sb @('DisplayName', 'Direction', 'Action', 'Profile', 'Protocol', 'LocalPort', 'RemotePort', 'Program') $fw @('DisplayName', 'Direction', 'Action', 'Profile', 'Protocol', 'LocalPort', 'RemotePort', 'Program')
  }

  if ($Communication.Hosts) {
    [void]$Sb.AppendLine("### Hosts file ($($Communication.HostsLines) active entries)")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine('```')
    [void]$Sb.AppendLine([string]$Communication.Hosts)
    [void]$Sb.AppendLine('```')
    [void]$Sb.AppendLine()
  }

  if ($Communication.Proxy -and $Communication.Proxy.Count -gt 0) {
    [void]$Sb.AppendLine("### System proxy")
    [void]$Sb.AppendLine()
    [void]$Sb.AppendLine("| Field | Value |")
    [void]$Sb.AppendLine("| --- | --- |")
    foreach ($k in $Communication.Proxy.Keys) {
      [void]$Sb.AppendLine("| $(Escape-MdCell $k) | $(Escape-MdCell $Communication.Proxy[$k]) |")
    }
    [void]$Sb.AppendLine()
  }

  if ($Communication.TopTalkers -and $Communication.TopTalkers.Count -gt 0) {
    [void]$Sb.AppendLine("### Top network talkers (processes by open sockets)")
    [void]$Sb.AppendLine()
    $tv = $Communication.TopTalkers | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Process = $_.Process
        Pid = $_.Pid
        Listen = $_.Listen
        Established = $_.Established
        Udp = $_.Udp
        Total = $_.Total
        Hint = $_.Hint
        Path = $_.Path
      })
    }
    Write-MdTable $Sb @('Process', 'Pid', 'Listen', 'Established', 'Udp', 'Total', 'Hint', 'Path') $tv @('Process', 'Pid', 'Listen', 'Established', 'Udp', 'Total', 'Hint', 'Path')
  }

  if ($Communication.ServicesOnPorts -and $Communication.ServicesOnPorts.Count -gt 0) {
    [void]$Sb.AppendLine("### Services listening on TCP ports (top 200)")
    [void]$Sb.AppendLine()
    $spv = $Communication.ServicesOnPorts | ForEach-Object {
      New-Object psobject -Property ([ordered]@{
        Service = $_.Service
        Process = $_.Process
        Pid = $_.Pid
        Port = $_.Port
        LocalAddress = $_.LocalAddress
      })
    }
    Write-MdTable $Sb @('Service', 'Process', 'Pid', 'Port', 'LocalAddress') $spv @('Service', 'Process', 'Pid', 'Port', 'LocalAddress')
  }

  [void]$Sb.AppendLine()
}
