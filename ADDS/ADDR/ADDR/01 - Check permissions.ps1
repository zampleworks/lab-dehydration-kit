<#
.SYNOPSIS
Check that the user running this script is a member of Schema Admins, Enterprise Admins,
and Domain Admins, and automatically add the user to groups that are missing.

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
    $User = Get-ADUser ($env:USERNAME)

    If($PSCmdlet.ShouldProcess($User, "Add to admin groups")) {
        $DomainAdmins = Get-ADGroup "Domain Admins" -Properties Members
        
        $Added = $False

        If($DomainAdmins.members -notcontains $User.distinguishedname) {
            Write-Host "Domain admins missing"
            Add-ADGroupMember -Identity $DomainAdmins -Members $User
            $Added = $True
        }

        # Check if in root domain, if so add EA/Schema admins
        If((Get-ADDomain).ParentDomain -eq $Null) {
            $EnterpriseAdmins = Get-ADGroup "Enterprise Admins" -Properties Members
            $SchemaAdmins = Get-ADGroup "Schema Admins" -Properties Members

            If($EnterpriseAdmins.members -notcontains $User.distinguishedname) {
                Write-Host "Enterprise admins missing"
                Add-ADGroupMember -Identity $EnterpriseAdmins -Members $User
                $Added = $True
            }

            If($SchemaAdmins.members -notcontains $User.distinguishedname) {
                Write-Host "Schema admins missing"
                Add-ADGroupMember -Identity $SchemaAdmins -Members $User
                $Added = $True
            }
        }
        If($Added) {
            Write-Host ""
            Write-Warning "Current user added to new groups. You have to log out then back in to proceed."
        } Else {
            Write-Host ""
            Write-Host "You're already a member of the important groups." -ForegroundColor Green
        }
    }
} Catch {
    Write-Host $_.Exception.Message
$_.Exception
}

If(-Not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
