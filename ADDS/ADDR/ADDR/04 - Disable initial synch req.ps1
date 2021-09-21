<#
.SYNOPSIS
Normally a DC requires inbound and outbound replication before advertising as DC.
This script disables this requirement.

.NOTES
Author anders.runesson@enfogroup.com
#>
[CmdletBinding(
    SupportsShouldProcess = $True,
    ConfirmImpact = "High"
)]
Param()

$ErrorActionPreference = "Stop"

Try {

    $Hostname = hostname
    $ForestDN = Get-ADForest | Select-Object -ExpandProperty RootDomain
    
    If($PSCmdlet.ShouldProcess($Hostname, "Disable Initial Synchronization requirement for DC $hostname")) {
        Write-Host "Disabling 'Initial Synchronizations' requirement for this server.."

        # Setting this value to 0 will allow DC to advertise without replication to all partners.
        Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "Repl Perform Initial Synchronizations" -Value 0
        
    }
} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}

