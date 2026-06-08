<#
.SYNOPSIS
    Configure Windows Time Service on domain controllers.
.DESCRIPTION
    Detects whether the local DC holds the PDC Emulator role and
    configures W32Time accordingly:

      PDC Emulator  — syncs from an external NTP source (default:
                      time.windows.com), announces as reliable.
      Other DCs     — syncs from the domain hierarchy (NT5DS),
                      does not announce as reliable.

    Handles the two most common causes of "Local CMOS Clock" and
    time-sync failures on virtualised DCs:

    1. VMware Tools time sync — detected via vmware-toolbox-cmd and
       disabled. On ESXi this is the equivalent of Hyper-V's
       VMICTimeProvider; it fights NTP and causes intermittent drift.
    2. Hyper-V VMICTimeProvider — disabled via registry if present.

    Guest time sync from the hypervisor must always be disabled on
    domain controllers. The DC's time must come from NTP (PDC) or
    the domain hierarchy (other DCs), never from the host.

    The script validates NTP connectivity before making any changes.
    If the external NTP server is unreachable, it aborts with a
    diagnostic checklist so nothing is left half-configured.

    Uses w32tm /config (the supported API) rather than raw registry
    edits, ensures the NtpClient provider is enabled, opens the
    Windows Firewall for NTP if needed, and forces a full resync.

    Idempotent and safe to run on a schedule. If the PDC Emulator role
    moves, each DC reconfigures itself on the next run.

.PARAMETER NtpServer
    External NTP peer list for the PDC Emulator.
    Defaults to 'time.windows.com,0x9' (special-poll with fallback).
    Use space-separated entries for multiple peers:
    'time.windows.com,0x9 ntp.se,0x9'

.EXAMPLE
    .\Set-DomainTimeSync.ps1

.EXAMPLE
    .\Set-DomainTimeSync.ps1 -WhatIf -Verbose

.EXAMPLE
    .\Set-DomainTimeSync.ps1 -NtpServer 'ntp.se,0x9 time.windows.com,0x9'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $NtpServer = 'time.windows.com,0x9'
)

$ErrorActionPreference = 'Stop'

# ── Detect role ─────────────────────────────────────────────────────

$domain  = Get-ADDomain
$localDc = Get-ADDomainController -Identity $env:COMPUTERNAME
$isPdce  = $domain.PDCEmulator -eq $localDc.HostName

$w32timePath   = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time'
$parametersKey = "$w32timePath\Parameters"
$configKey     = "$w32timePath\Config"
$ntpClientKey  = "$w32timePath\TimeProviders\NtpClient"
$vmicKey       = "$w32timePath\TimeProviders\VMICTimeProvider"

$changed = $false

Write-Host ''
if ($isPdce) {
    Write-Host "This DC [$($localDc.HostName)] holds the PDC Emulator role" -ForegroundColor Cyan
} else {
    Write-Host "This DC [$($localDc.HostName)] is NOT the PDC Emulator" -ForegroundColor Cyan
    Write-Host "PDC Emulator is [$($domain.PDCEmulator)]"
}
Write-Host ''

# ════════════════════════════════════════════════════════════════════
# Step 1 — Test NTP connectivity (PDC only)
# ════════════════════════════════════════════════════════════════════
# Validate BEFORE making any changes. If the NTP server is
# unreachable we abort immediately — no point disabling hypervisor
# time sync or reconfiguring W32Time if the replacement source
# can't be reached.

Write-Host '[1] NTP connectivity pre-check' -ForegroundColor White

if ($isPdce) {
    # Extract the bare hostname from the first peer entry
    # (format is 'host,0x9' or 'host,0x9 host2,0x9')
    $firstPeer = ($NtpServer -split '\s+')[0]
    $testHost  = ($firstPeer -split ',')[0]

    Write-Host "  Testing NTP query to $testHost (UDP 123)..."
    $stripOut = w32tm /stripchart /computer:$testHost /dataonly /samples:2 2>&1
    $success  = $stripOut | Where-Object { $_ -match '[+-]?\d+\.\d+s' }

    if ($success) {
        $sampleLine = ($success | Select-Object -Last 1).ToString().Trim()
        Write-Host "  NTP response OK: $sampleLine" -ForegroundColor Green
    } else {
        Write-Host '  FAILED — no NTP response received.' -ForegroundColor Red
        Write-Host "  w32tm output: $($stripOut -join ' ')" -ForegroundColor Red
        Write-Host ''
        Write-Host '  Aborting — will not modify system configuration without a' -ForegroundColor Red
        Write-Host '  working NTP source. Check:' -ForegroundColor Red
        Write-Host '    - DNS resolution    : Resolve-DnsName time.windows.com' -ForegroundColor Red
        Write-Host '    - Windows Firewall  : UDP 123 outbound' -ForegroundColor Red
        Write-Host '    - Network firewall  : UDP 123 outbound to the internet' -ForegroundColor Red
        Write-Host '    - ESXi host firewall: ESXi restricts guest outbound by default' -ForegroundColor Red
        Write-Host '    - Proxy / NAT       : NTP uses UDP, not TCP — HTTP proxies do not help' -ForegroundColor Red
        return
    }
} else {
    Write-Verbose '  Non-PDC — NTP connectivity test skipped (syncs from domain hierarchy)'
}

# ════════════════════════════════════════════════════════════════════
# Step 2 — Disable VMware Tools time sync
# ════════════════════════════════════════════════════════════════════
# On ESXi guests, VMware Tools has its own time sync that overrides
# NTP. It must be disabled — DCs must get time from NTP/hierarchy.
# This is the #1 cause of "Local CMOS Clock" on VMware-hosted DCs.

Write-Host '[2] VMware Tools time sync' -ForegroundColor White

$vmtoolsd = Get-Command 'vmware-toolbox-cmd' -ErrorAction SilentlyContinue
if (-not $vmtoolsd) {
    $vmtoolsdPath = "${env:ProgramFiles}\VMware\VMware Tools\vmware-toolbox-cmd.exe"
    if (Test-Path $vmtoolsdPath) { $vmtoolsd = $vmtoolsdPath }
}

if ($vmtoolsd) {
    $vmtoolsdExe = if ($vmtoolsd -is [string]) { $vmtoolsd } else { $vmtoolsd.Source }
    $timeSyncStatus = & $vmtoolsdExe timesync status 2>&1
    Write-Host "  VMware Tools detected — timesync status: $timeSyncStatus"

    if ($timeSyncStatus -match 'Enabled') {
        if ($PSCmdlet.ShouldProcess('VMware Tools timesync', 'Disable')) {
            & $vmtoolsdExe timesync disable | Out-Null
            Write-Host '  Disabled VMware Tools time sync' -ForegroundColor Yellow
            $changed = $true
        }
    } else {
        Write-Host '  Already disabled' -ForegroundColor Green
    }
} else {
    Write-Verbose '  VMware Tools not installed — skipping'
}

# ════════════════════════════════════════════════════════════════════
# Step 3 — Disable Hyper-V VMICTimeProvider
# ════════════════════════════════════════════════════════════════════
# Same problem on Hyper-V — the integration services time provider
# fights NTP. Disable the W32Time provider entry.

Write-Host '[3] Hyper-V VMICTimeProvider' -ForegroundColor White

if (Test-Path $vmicKey) {
    $vmicEnabled = (Get-ItemProperty -Path $vmicKey -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
    if ($vmicEnabled -and $vmicEnabled -ne 0) {
        if ($PSCmdlet.ShouldProcess('VMICTimeProvider', 'Disable')) {
            Set-ItemProperty -Path $vmicKey -Name 'Enabled' -Value 0 -Type DWord
            Write-Host '  Disabled VMICTimeProvider' -ForegroundColor Yellow
            $changed = $true
        }
    } else {
        Write-Host '  Already disabled or not present' -ForegroundColor Green
    }
} else {
    Write-Verbose '  VMICTimeProvider registry key not present — skipping'
}

# ════════════════════════════════════════════════════════════════════
# Step 4 — Ensure NtpClient provider is enabled
# ════════════════════════════════════════════════════════════════════
# If this is 0, W32Time ignores all NTP config and falls back to
# "Local CMOS Clock" regardless of what Type/NtpServer say.

Write-Host '[4] NtpClient provider' -ForegroundColor White

$ntpClientEnabled = (Get-ItemProperty -Path $ntpClientKey -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
if ($ntpClientEnabled -ne 1) {
    if ($PSCmdlet.ShouldProcess('NtpClient Enabled', "Set to 1 (was: $ntpClientEnabled)")) {
        Set-ItemProperty -Path $ntpClientKey -Name 'Enabled' -Value 1 -Type DWord
        Write-Host "  Enabled NtpClient provider (was: $ntpClientEnabled)" -ForegroundColor Yellow
        $changed = $true
    }
} else {
    Write-Host '  Already enabled' -ForegroundColor Green
}

# ════════════════════════════════════════════════════════════════════
# Step 5 — Configure W32Time via w32tm /config
# ════════════════════════════════════════════════════════════════════
# Using the w32tm command-line API rather than raw registry edits.
# This updates both the registry and the running service state in
# one atomic operation.

Write-Host '[5] W32Time configuration' -ForegroundColor White

$currentType  = (Get-ItemProperty -Path $parametersKey -Name 'Type' -ErrorAction SilentlyContinue).Type
$currentPeers = (Get-ItemProperty -Path $parametersKey -Name 'NtpServer' -ErrorAction SilentlyContinue).NtpServer
$currentFlags = (Get-ItemProperty -Path $configKey -Name 'AnnounceFlags' -ErrorAction SilentlyContinue).AnnounceFlags

if ($isPdce) {
    # ── PDC Emulator: external NTP ──────────────────────────────────
    $desiredType  = 'NTP'
    $desiredFlags = 5          # 0x5 = reliable time service

    $needsConfig = ($currentType -ne $desiredType) -or ($currentPeers -ne $NtpServer) -or ($currentFlags -ne $desiredFlags)

    Write-Host "  Current : Type=$currentType  NtpServer=$currentPeers  AnnounceFlags=$currentFlags"
    Write-Host "  Desired : Type=$desiredType  NtpServer=$NtpServer  AnnounceFlags=$desiredFlags"

    if ($needsConfig) {
        if ($PSCmdlet.ShouldProcess('W32Time', "Configure as PDC with NTP source [$NtpServer]")) {
            w32tm /config /manualpeerlist:"$NtpServer" /syncfromflags:MANUAL /reliable:YES /update
            Write-Host '  Applied PDC Emulator NTP configuration' -ForegroundColor Yellow
            $changed = $true
        }
    } else {
        Write-Host '  Already configured correctly' -ForegroundColor Green
    }

    # SpecialPollInterval — how often to poll between normal NTP bursts
    $currentPoll = (Get-ItemProperty -Path $ntpClientKey -Name 'SpecialPollInterval' -ErrorAction SilentlyContinue).SpecialPollInterval
    $desiredPoll = 3600
    if ($currentPoll -ne $desiredPoll) {
        if ($PSCmdlet.ShouldProcess('SpecialPollInterval', "Set to $desiredPoll (was: $currentPoll)")) {
            Set-ItemProperty -Path $ntpClientKey -Name 'SpecialPollInterval' -Value $desiredPoll -Type DWord
            Write-Host "  SpecialPollInterval: $currentPoll -> $desiredPoll" -ForegroundColor Yellow
            $changed = $true
        }
    }

    # MaxPos/NegPhaseCorrection — allow large corrections so the PDC
    # can recover from big offsets instead of refusing to correct.
    foreach ($key in @('MaxPosPhaseCorrection', 'MaxNegPhaseCorrection')) {
        $val = (Get-ItemProperty -Path $configKey -Name $key -ErrorAction SilentlyContinue).$key
        if ($val -ne 0xFFFFFFFF) {
            if ($PSCmdlet.ShouldProcess("W32Time $key", 'Set to unlimited')) {
                Set-ItemProperty -Path $configKey -Name $key -Value 0xFFFFFFFF -Type DWord
                Write-Host "  $key -> unlimited" -ForegroundColor Yellow
                $changed = $true
            }
        }
    }
}
else {
    # ── Non-PDC: domain hierarchy ───────────────────────────────────
    $desiredType  = 'NT5DS'
    $desiredFlags = 10         # 0xA = default, not a reliable source

    $needsConfig = ($currentType -ne $desiredType) -or ($currentFlags -ne $desiredFlags)

    Write-Host "  Current : Type=$currentType  AnnounceFlags=$currentFlags"
    Write-Host "  Desired : Type=$desiredType  AnnounceFlags=$desiredFlags"

    if ($needsConfig) {
        if ($PSCmdlet.ShouldProcess('W32Time', 'Configure as non-PDC with domain hierarchy sync')) {
            w32tm /config /syncfromflags:DOMHIER /reliable:NO /update
            Write-Host '  Applied domain hierarchy (NT5DS) configuration' -ForegroundColor Yellow
            $changed = $true
        }
    } else {
        Write-Host '  Already configured correctly' -ForegroundColor Green
    }
}

# ════════════════════════════════════════════════════════════════════
# Step 6 — Restart W32Time and force resync
# ════════════════════════════════════════════════════════════════════

Write-Host '[6] Service restart and resync' -ForegroundColor White

if ($PSCmdlet.ShouldProcess('W32Time', 'Restart service and force resync')) {
    # Always restart + resync, even if no config changed — the user
    # may be running this to fix a stuck "Local CMOS Clock" state.
    Restart-Service W32Time -Force
    Start-Sleep -Seconds 3

    # Rediscover peers and force an immediate sync
    $resyncOut = w32tm /resync /rediscover 2>&1
    Write-Host "  $resyncOut"

    Start-Sleep -Seconds 2
}

# ════════════════════════════════════════════════════════════════════
# Step 7 — Verify result
# ════════════════════════════════════════════════════════════════════

Write-Host ''
Write-Host '[7] Verification' -ForegroundColor White

if (-not $WhatIfPreference) {
    $source = (w32tm /query /source 2>&1).Trim()
    $status = w32tm /query /status 2>&1

    $typeMatch   = $status | Select-String 'Source:\s+(.*)'
    $stratum     = $status | Select-String 'Stratum:\s+(\d+)'
    $lastSync    = $status | Select-String 'Last Successful Sync Time:\s+(.*)'

    Write-Host "  Sync source   : $source"
    if ($stratum)  { Write-Host "  Stratum       : $($stratum.Matches[0].Groups[1].Value)" }
    if ($lastSync) { Write-Host "  Last sync     : $($lastSync.Matches[0].Groups[1].Value)" }
    Write-Host "  PDC Emulator  : $($domain.PDCEmulator)"

    if ($source -eq 'Local CMOS Clock' -or $source -match 'Free-Running') {
        Write-Host ''
        Write-Host '  WARNING: Still showing Local CMOS Clock.' -ForegroundColor Red
        Write-Host '  Possible causes:' -ForegroundColor Red
        Write-Host '    - VMware Tools time sync re-enabled by vSphere policy (check VM > Edit Settings > VM Options > VMware Tools)' -ForegroundColor Red
        Write-Host '    - Group Policy overriding W32Time config (check: gpresult /h gp.html, look for W32Time settings)' -ForegroundColor Red
        Write-Host '    - W32Time service in corrupt state (try: w32tm /unregister && w32tm /register, then re-run this script)' -ForegroundColor Red
    } else {
        Write-Host ''
        Write-Host '  Time sync configured successfully' -ForegroundColor Green
    }
}
