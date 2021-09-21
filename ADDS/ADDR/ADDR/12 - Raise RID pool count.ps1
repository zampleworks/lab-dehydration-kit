<#
.SYNOPSIS
Increment RID pool start by 100000 and invalidate RID pool

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

    $DomainDN = Get-ADDomain | Select -ExpandProperty DistinguishedName
    $Increment = 100000
    
    If($PSCmdlet.ShouldProcess($DomainDN, "Increment RID pool")) {
        $currentRidPool = Get-ADObject "CN=RID Manager$,CN=System,$DomainDN" -Properties rIDAvailablePool | select -ExpandProperty rIDAvailablePool
        Set-ADObject "CN=RID Manager$,CN=System,$DomainDN" -Replace @{ ridavailablePool = ($currentRidPool + $Increment) }

        $Domain = New-Object System.DirectoryServices.DirectoryEntry
        $DomainSid = $Domain.objectSid

        $RootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $RootDSE.UsePropertyCache = $false
        $RootDSE.Put("invalidateRidPool", $DomainSid.Value)
        $RootDSE.SetInfo()

        Write-Host "RID pool increased by $increment" -ForegroundColor Green
    }
} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
