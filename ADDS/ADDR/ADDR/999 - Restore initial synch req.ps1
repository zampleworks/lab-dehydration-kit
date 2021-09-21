<#
.SYNOPSIS
Normally a DC requires inbound and outbound replication before advertising as DC.
This script enables this requirement.

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
    
    If($PSCmdlet.ShouldProcess($Hostname, "Restore Initial Synchronization requirement for DC $hostname")) {
        Write-Host "Restoring 'Initial Synchronizations' requirement for this server.."

        # Setting this value to 1 will require DC to replicate with all partners before advertising as DC.
        Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "Repl Perform Initial Synchronizations" -Value 1
        # Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "Repl Perform Initial Synchronizations"
    }
} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}

