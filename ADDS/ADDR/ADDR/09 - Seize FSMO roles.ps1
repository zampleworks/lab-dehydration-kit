<#
.SYNOPSIS
Seize all FSMO roles 

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

    If($PSCmdlet.ShouldProcess($Hostname, "Seize FSMO Roles to this server")) {
        Write-Host "Current role owners: "
        netdom /query fsmo
    
        Write-Host ""
        Write-Host "Seizing roles. This may take a long time."
        
        If (-Not (Get-ADDomain).ParentDomain) { 
            Move-ADDirectoryServerOperationMasterRole -Identity $(&HOSTNAME) -OperationMasterRole 0, 1, 2, 3, 4 -Force -Confirm:$False 
            Write-Host "This server is now role holder for all FSMO roles in domain and forest." -ForegroundColor Green
        } Else { 
            Move-ADDirectoryServerOperationMasterRole -Identity $(&HOSTNAME) -OperationMasterRole 0, 1, 2 -Force -Confirm:$False 
            Write-Host "This server is now role holder for all FSMO roles in this domain." -ForegroundColor Green
        }

        Write-Host ""
        Write-Host "Done."
        Write-Host "New role owners: "
        netdom /query fsmo
    }

} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
