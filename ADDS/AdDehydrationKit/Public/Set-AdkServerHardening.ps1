# OS-level hardening for a domain controller. Must run on every DC
# individually (registry and service settings are machine-local).
#
# Registry:
#   - NTDS TCP/IP Port = 49151         (fix port for host-based firewall rules)
#   - Netlogon DCTcpipPort = 49150     (fix Netlogon RPC port)
#   - kdc\KdcExtraLogLevel = 0x1F      (Kerberos diagnostic events in System log)
#   - NTDS LDAPServerIntegrity = 2     (require LDAP signing on all SASL binds)
#   - NTDS LdapEnforceChannelBinding = 2 (require channel binding tokens on LDAPS)
#
# Services:
#   - Disables high-risk / unnecessary services (Spooler, WebClient, etc.)
#
# All registry and service changes are idempotent: each value is read
# first and only written when it differs from the desired state.
# This avoids disrupting Netlogon on reruns (the LDAP hardening
# settings take effect immediately and can tear down active sessions).

function Set-AdkServerHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    # -- Read server hardening toggles from context (Settings.psd1) ---------
    $sh = if ($Context.ServerHardening) { $Context.ServerHardening } else { @{} }

    # -- Helper: set a DWORD only when it differs from the desired value --
    # Returns $true when a write was performed, $false when already correct.
    function Set-RegistryDword {
        param(
            [string] $Path,
            [string] $Name,
            [int]    $Value
        )
        $cur = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $cur -and $cur.$Name -eq $Value) {
            Write-AdkLog "  [$Name] already $Value"
            return $false
        }
        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord | Out-Null
            Write-AdkLog "  [$Name] set to $Value" -Warning
            return $true
        }
        return $false
    }

    # ------------------------------------------------------------------ #
    # Registry: fixed RPC/Netlogon ports
    # Values are configurable integers; $false = skip.
    # ------------------------------------------------------------------ #
    Write-AdkLog 'Fixed RPC ports..'
    $ntdsPort = $sh.NtdsRpcPort
    if ($ntdsPort -ne $false -and $null -ne $ntdsPort) {
        $null = Set-RegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'TCP/IP Port' ([int]$ntdsPort)
    } else { Write-AdkLog '  NtdsRpcPort skipped (disabled in Settings.psd1)' }
    $nlPort = $sh.NetlogonRpcPort
    if ($nlPort -ne $false -and $null -ne $nlPort) {
        $null = Set-RegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'DCTcpipPort' ([int]$nlPort)
    } else { Write-AdkLog '  NetlogonRpcPort skipped (disabled in Settings.psd1)' }

    # ------------------------------------------------------------------ #
    # Registry: KDC extra logging
    # Configurable bitmask; $false = skip.
    #   0x01 - KDC errors and pre-authentication failures
    #   0x02 - ticket request details
    #   0x04 - pre-authentication data type info
    #   0x08 - extended error info on TGS/TGT failures
    #   0x10 - client IP address included in logged events
    # ------------------------------------------------------------------ #
    $kdcLevel = $sh.KdcExtraLogLevel
    if ($kdcLevel -ne $false -and $null -ne $kdcLevel) {
        Write-AdkLog "KDC extra logging (0x$([Convert]::ToString([int]$kdcLevel, 16).ToUpper())).."
        $null = Set-RegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\kdc' 'KdcExtraLogLevel' ([int]$kdcLevel)
    } else { Write-AdkLog 'Skipping KdcExtraLogLevel (disabled in Settings.psd1)' }

    # ------------------------------------------------------------------ #
    # Registry: LDAP security hardening (NTDS\Parameters)
    # Each setting is individually configurable; $false = skip.
    #
    # LDAPServerIntegrity:       0=off, 1=negotiate, 2=require (Event 2886)
    # LdapEnforceChannelBinding: 0=never, 1=when supported, 2=always (Event 3041)
    #
    # Both take effect immediately and can disrupt Netlogon's active LDAP
    # session. Only written when the value differs from the desired state.
    # CVE-2021-42291 (Events 3051/3054) is controlled by dSHeuristics
    # positions 28-29, set in Set-AdkDomainHardening.
    # ------------------------------------------------------------------ #
    Write-AdkLog 'LDAP security hardening..'
    $ntdsParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    foreach ($entry in @(
        @{ Key = 'LDAPServerIntegrity';       Setting = 'LDAPServerIntegrity' }
        @{ Key = 'LdapEnforceChannelBinding'; Setting = 'LdapEnforceChannelBinding' }
    )) {
        $val = $sh[$entry.Setting]
        if ($val -ne $false -and $null -ne $val) {
            $null = Set-RegistryDword $ntdsParams $entry.Key ([int]$val)
        } else {
            Write-AdkLog "  $($entry.Setting) skipped (disabled in Settings.psd1)"
        }
    }

    # ------------------------------------------------------------------ #
    # Services: disable unnecessary / high attack-surface services.
    # Each service is individually controllable via Settings.psd1
    # ServerHardening.DisableServices.<ServiceName> = $true/$false.
    # Missing keys default to $true (disable). Set to $false to skip.
    #
    # N.B. Computer Browser (service name "Browser") is NOT listed here.
    # Get-Service resolves that name to the bowser mini-redirector driver
    # which has Netlogon as a dependent -- stopping it kills Netlogon.
    # ------------------------------------------------------------------ #
    $serviceDescriptions = [ordered]@{
        'Spooler'          = 'Print Spooler (PrintNightmare / SpoolFool)'
        'PrintNotify'      = 'Printer Extensions and Notifications'
        'RemoteRegistry'   = 'Remote Registry'
        'WebClient'        = 'WebDAV client (NTLM relay / coercion surface)'
        'SSDPSRV'          = 'SSDP Discovery (UPnP)'
        'upnphost'         = 'UPnP Device Host'
        'Fax'              = 'Fax service'
        'TapiSrv'          = 'Telephony'
        'WSearch'          = 'Windows Search indexing'
        'DiagTrack'        = 'Connected User Experiences and Telemetry'
        'dmwappushservice' = 'WAP Push Message Routing service'
        'MapsBroker'       = 'Downloaded Maps Manager'
        'lfsvc'            = 'Geolocation service'
        'RetailDemo'       = 'Retail Demo service'
        'PhoneSvc'         = 'Phone service'
        'icssvc'           = 'Windows Mobile Hotspot service'
        'WpnService'       = 'Windows Push Notifications System service'
        'PushToInstall'    = 'Windows PushToInstall service'
    }

    $svcToggles = $sh.DisableServices
    if ($svcToggles -eq $false) {
        Write-AdkLog 'Skipping DisableServices (disabled in Settings.psd1)'
    } else {
        if ($svcToggles -isnot [hashtable]) { $svcToggles = @{} }
        Write-AdkLog 'Disabling unnecessary services..'
        foreach ($kv in $serviceDescriptions.GetEnumerator()) {
            $enabled = $svcToggles[$kv.Key]
            if ($enabled -eq $false) {
                Write-AdkLog "  [$($kv.Key)] skipped (disabled in Settings.psd1)"
                continue
            }
            $svc = Get-Service -Name $kv.Key -ErrorAction SilentlyContinue
            if ($null -eq $svc) {
                Write-AdkLog "  [$($kv.Key)] not installed"
                continue
            }
            if ($svc.StartType -eq 'Disabled') {
                Write-AdkLog "  [$($kv.Key)] already disabled"
                continue
            }
            if (-not $PSCmdlet.ShouldProcess($kv.Key, "Disable service ($($kv.Value))")) { continue }
            try {
                if ($svc.Status -eq 'Running') {
                    Stop-Service -Name $kv.Key -Force -ErrorAction SilentlyContinue
                }
                Set-Service -Name $kv.Key -StartupType Disabled
                Write-AdkLog "  [$($kv.Key)] disabled  # $($kv.Value)" -Warning
            } catch {
                if ($_.Exception.Message -like '*does not exist as an installed service*') {
                    Write-AdkLog "  [$($kv.Key)] not installed"
                } else {
                    Write-AdkLog "  Could not disable [$($kv.Key)]: $($_.Exception.Message)" -IsError
                }
            }
        }
    }
    # ------------------------------------------------------------------ #
    # Netlogon safety check.
    # If a future service-list change accidentally introduces a service
    # with Netlogon as a dependent, catch and recover here.
    # ------------------------------------------------------------------ #
    $nlSvc = Get-Service -Name Netlogon
    if ($nlSvc.Status -ne 'Running') {
        if ($PSCmdlet.ShouldProcess('Netlogon', 'Restart service')) {
            Write-AdkLog 'Netlogon not running - restarting..' -Warning
            Start-Service -Name Netlogon
            Start-Sleep -Seconds 3
            Write-AdkLog '  forcing Netlogon DNS re-registration..'
            $nlOut = nltest /dsregdns 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-AdkLog "  nltest /dsregdns returned exit code $LASTEXITCODE" -Warning
            } else {
                Write-AdkLog '  Netlogon restarted and DNS records re-registered'
            }
        }
    }

    Write-AdkLog 'Server hardening complete.' -Success
}
