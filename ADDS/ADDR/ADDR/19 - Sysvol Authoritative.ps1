<#
.SYNOPSIS
Set this servers' SYSVOL copy to be the authoritative source

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

    $Dcs = Get-ADDomainController -Filter *
    If($Dcs.Count -gt 1) {
        Write-Warning "Multiple domain controllers found. This script should ONLY be run"
        Write-Warning "on the first restored DC in each domain. If this is the first restored"
        Write-Warning "DC in this domain, clean metadata first to remove old DC references."
        Return
    }

    $Hostname = hostname
    $Dn = get-adcomputer (hostname) | select -expand distinguishedname

    If($PSCmdlet.ShouldProcess($Hostname, "Mark this servers SYSVOL as authoritative copy")) {
        Write-Host "Will mark SYSVOL on server $Dn as authoritative"

        $SysvolSub = Get-ADObject -searchbase $dn -filter { cn -eq "SYSVOL Subscription" } -SearchScope subtree -Properties msdfsr-options
        If($SysvolSub.'msDFSR-Options' -eq 1) {
            Write-Host "SYSVOL is already authoritative on selected server. No change performed." -ForegroundColor Green
        
            if(-not $psISE) {
                Write-Host ""
                Read-Host "Press play on tape"
            }

            Return
        }

        Set-ADObject $SysvolSub -Replace @{'msDFSR-Options' = 1}
        Write-Host ""
        Write-Host "Updated SYSVOL" -ForegroundColor Green
        Get-ADObject -searchbase $dn -filter { cn -eq "SYSVOL Subscription" } -SearchScope subtree -Properties msdfsr-options | Select DistinguishedName, msDFSR-Options | fl
    }
} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
