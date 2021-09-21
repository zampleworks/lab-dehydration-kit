<#
.SYNOPSIS
Update DNS records for Infrastructure Master FSMO role

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
    $Domain = Get-ADDomain
    $DomainDN = $Domain | Select -ExpandProperty DistinguishedName
    
    If($PSCmdlet.ShouldProcess("FSMO role holders in DNS zones")) {
        If ($Domain.ParentDomain -eq $Null) { 
            # This command will not work in child domain during recovery
            $ForestDN = Get-ADForest | Select -ExpandProperty RootDomain | Get-ADDomain | Select -ExpandProperty DistinguishedName         
            Set-ADObject -Identity "CN=Infrastructure,DC=ForestDnsZones,$ForestDN" -Replace @{ fSMORoleOwner = (Get-ADDomainController ((Get-ADDomain).InfrastructureMaster)).NTDSSettingsObjectDN } 
            Set-ADObject -Identity "CN=Infrastructure,DC=DomainDnsZones,$DomainDN" -Replace @{ fSMORoleOwner = (Get-ADDomainController ((Get-ADDomain).InfrastructureMaster)).NTDSSettingsObjectDN } 
        } Else {
            Set-ADObject -Identity "CN=Infrastructure,DC=DomainDnsZones,$DomainDN" -Replace @{ fSMORoleOwner = (Get-ADDomainController ((Get-ADDomain).InfrastructureMaster)).NTDSSettingsObjectDN } 
        }

        Write-Host "Updated FSMO Role Owner in DNS" -ForegroundColor Green
    }
} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
