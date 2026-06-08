# Set the root DNS zones to Forest-wide replication scope.
#
# Only operates on the forest root domain (guards against running in a
# child domain). Waits for each zone to leave the Legacy replication
# state before changing scope to Forest.
#
# After changing scope the DNS Server reloads each zone from the new
# application partition. During this reload the zone is briefly
# unavailable for dynamic updates, which causes Netlogon's periodic
# SRV registration (ForestDnsZones / DomainDnsZones records) to fail
# with Event 5781. If the outage lasts long enough, Netlogon's secure
# channel validation degrades and the service stops.
#
# To prevent this the function waits for each zone to become queryable
# after the scope change, then forces a Netlogon DNS re-registration
# so the SRV records are current before subsequent steps run.

function Set-AdkDnsReplication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    $rdse = Get-ADRootDSE
    $dom  = Get-ADDomain

    if ($rdse.rootDomainNamingContext -ne $dom.DistinguishedName) {
        Write-AdkLog '  Not the forest root domain - skipping DNS replication change.' -Step
        return
    }

    $scopeChanged = $false

    foreach ($zoneName in @($dom.DNSRoot, "_msdcs.$($dom.DNSRoot)")) {
        try {
            $zone = $null
            do {
                $zone = Get-DnsServerZone -Name $zoneName -ErrorAction Stop
                if ($zone.ReplicationScope -eq 'Legacy') {
                    Write-AdkLog "  waiting for zone [$zoneName] to leave Legacy replication.."
                    Start-Sleep -Seconds 5
                }
            } while ($zone.ReplicationScope -eq 'Legacy')

            if ($zone.ReplicationScope -ne 'Forest') {
                if ($PSCmdlet.ShouldProcess($zoneName, 'Set DNS zone replication scope to Forest')) {
                    Set-DnsServerPrimaryZone -Name $zone.ZoneName -ReplicationScope Forest
                    Write-AdkLog "  zone [$zoneName] set to Forest replication"
                    $scopeChanged = $true
                }
            } else {
                Write-AdkLog "  zone [$zoneName] already Forest-scoped"
            }
        } catch {
            Write-AdkLog "  failed to set replication scope on zone [$zoneName]: $($_.Exception.Message)" -Warning
        }
    }

    # -- Wait for zones to become queryable after the scope change --------
    # Moving a zone between application partitions causes the DNS Server
    # to unload and reload it. Until the reload completes the zone won't
    # answer queries, and Netlogon's SRV registration will fail (5781).
    if ($scopeChanged) {
        Write-AdkLog '  waiting for DNS zones to stabilize after scope change..'
        $domDns     = $dom.DNSRoot
        $waitMax    = 60    # seconds
        $waitStart  = [DateTime]::UtcNow
        $stable     = $false
        while (-not $stable -and ([DateTime]::UtcNow - $waitStart).TotalSeconds -lt $waitMax) {
            try {
                # SOA proves the zone is loaded and serving; SRV proves
                # the ForestDnsZones subdomain is reachable for updates.
                Resolve-DnsName $domDns -Type SOA -DnsOnly -ErrorAction Stop | Out-Null
                Resolve-DnsName "_ldap._tcp.$domDns" -Type SRV -DnsOnly -ErrorAction Stop | Out-Null
                $stable = $true
            } catch {
                Start-Sleep -Seconds 3
            }
        }
        if ($stable) {
            Write-AdkLog '  DNS zones responding after scope change'
        } else {
            Write-AdkLog "  DNS zones did not stabilize within ${waitMax}s - Netlogon may log 5781 warnings" -Warning
        }

        # Force Netlogon to re-register SRV records now that the zones
        # are back. Without this, Netlogon waits for its next periodic
        # cycle (up to 24h) and may encounter failures in the interim.
        if ($PSCmdlet.ShouldProcess('Netlogon', 'Force DNS re-registration (nltest /dsregdns)')) {
            Write-AdkLog '  forcing Netlogon DNS re-registration..'
            $nlOut = nltest /dsregdns 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-AdkLog "  nltest /dsregdns returned exit code $LASTEXITCODE" -Warning
            } else {
                Write-AdkLog '  Netlogon DNS records re-registered'
            }
        }
    }

    Write-AdkLog 'DNS zone replication configured' -Success
}
