<#
.SYNOPSIS
Remove DNS service records from AD DNS for all DCs except the current one.

.NOTES
Author mj4591
Updated by anders.runesson@enfogroup.com

#>
[CmdletBinding(
    SupportsShouldProcess = $True,
    ConfirmImpact = "High"
)]
Param()

$ErrorActionPreference = "Stop"

Try {
    $RestoredServerRecord = Resolve-DnsName (&HOSTNAME)
    $RestoredServer = ($RestoredServerRecord | where { $_.Type -eq "A" }).Name

    $DomainControllers = Get-ADDomain | Select -ExpandProperty ReplicaDirectoryServers | Sort

    If($DomainControllers -notcontains $RestoredServer) {
        Write-Error "This server does not appear to ba a domain controller. Please run this script on a DC."
    }

    $FQDNDomain = (Get-ADDomain).DNSRoot
    $FQDNForest = (Get-ADForest).Name
    $FQDNMsdcs = "_msdcs.$FQDNForest"

    $HasMsdcsZone = (Get-DnsServerZone | Where-Object { $_.ZoneName -eq $FQDNMsdcs } | Measure-Object | Select -ExpandProperty Count) -gt 0
    $HostedZoneNames = Get-DnsServerZone | Where-Object { -Not $_.IsReverseLookupZone } | Select -ExpandProperty ZoneName
    
    # Ensure _msdcs delegation has this server as name server - but only on root domain server

    If($FqdnForest -eq $FQDNDomain) {
        Try {
            $MsdcsNSRecs = Get-DnsServerZoneDelegation -Name $FQDNForest -ChildZoneName "_msdcs" | select -ExpandProperty NameServer | Select -ExpandProperty RecordData | Select -ExpandProperty NameServer
            if(($MsdcsNSRecs | Where-Object { $_ -like "$RestoredServer." } | Measure-Object | Select -ExpandProperty Count) -lt 1) {
                Add-DnsServerZoneDelegation -Name $FQDNForest -ChildZoneName "_msdcs" -NameServer "$RestoredServer." -IPAddress ($RestoredServerRecord | Where { $_.Type -eq "A" } | Select -ExpandProperty IpAddress)
            }
        } Catch {
            Write-Error "Delegation to _msdcs may be broken. Check delegation to _msdcs in domain zone and check that each listed name server has an 'A' record in the domain zone."
        }
    }
    $Search = ""

    $dnsrecords = Get-DnsServerResourceRecord -ZoneName $FQDNDomain | ForEach-Object { New-Object PSObject @{ 'ZoneName' = $FQDNDomain; 'Record' = $_} }
    $dnsrecords += Get-DnsServerResourceRecord -ZoneName $FQDNMsdcs | ForEach-Object { New-Object PSObject @{ 'ZoneName' = $FQDNMsdcs; 'Record' = $_} }

    $Counter = 1

    $FoundDNSRecords = @()

    foreach ($DomainController in $DomainControllers) {
	    $percentComplete = ($Counter / $DomainControllers.Count) * 100
	    Write-Progress -Activity 'Searching for DNS records...' -Status "Domain controller $DomainController" -PercentComplete $percentComplete -Id 1

        Try {
	        $DNSEntry = Resolve-DnsName $DomainController | where { $_.Type -eq "A" }
            If ($DNSEntry.Name -ne $RestoredServer) {
		        $FoundDNSRecords += $dnsrecords | where { 
                    $dotName = $DNSEntry.Name + "."
                    $Dt = $_.Record.RecordData
                    $Dt.IPv4Address -eq $DNSEntry.IPAddress -or $Dt.NameServer -eq $DNSEntry.Name + "." -or $Dt.DomainName -eq $DNSEntry.Name + "." 
                }
	        }
	        $Counter++
        } Catch {
            Write-Host "Found no DNS A record for $DomainController"
            #Write-Error $_Exception.Message
        }
    }

    Write-Progress -Activity 'Searching for DNS records...' -Completed -Id 1

    $Counter = 1
    $Removed = 0

    foreach ($dnr in $FoundDNSRecords | Sort-Object RecordType -Descending) {
        $dnsrecord = $Dnr.Record

	    $percentComplete = ($Counter / $FoundDNSRecords.Count) * 100
	    Write-Progress -Activity 'Removing DNS records...' -Status "$($($dnsrecord).HostName)" -PercentComplete $percentComplete -Id 1

        $ZoneName = $dnr.ZoneName
        
        If($PSCmdlet.ShouldProcess($dnsRecord.HostName, "Remove DNS record from zone $ZoneName")) {
            Try {
    	        $dnsrecord | Remove-DnsServerResourceRecord -ZoneName $ZoneName -force
                $Removed++
                Write-Host ("Removed record {0} {1} from {2}" -f $dnsrecord.RecordType, $dnsrecord.HostName, $ZoneName) -ForegroundColor Green
            } Catch {
                Write-Host ("Error removing DNS record for {0} {1} from zone {2}: {3}" -f $dnsrecord.HostName, $dnsrecord.RecordType, $ZoneName, $_.Exception.Message)
                #Write-Error $_Exception.Message
            }
        }
	    $Counter++
    }

    Write-Progress -Activity 'Removing DNS records...' -Completed -Id 1

    If($Removed -gt 0) {
        Write-Host "Restarting DNS & netlogon services.."
        Restart-Service DNS
        Restart-Service Netlogon
    }
} Catch {
    Write-Host "Error removing record $dnsrecord"
    Write-Host $_.Exception.Message
}

If(-Not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}