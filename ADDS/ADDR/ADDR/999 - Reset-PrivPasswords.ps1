<#
.SYNOPSIS
Reset password for all accounts that are members of Domain Admins, Enterprise Admins, or Administrators. 

.NOTES
Author anders.runesson@enfogroup.com
#>
[CmdletBinding(
    SupportsShouldProcess = $True,
    ConfirmImpact = "High"
)]
Param()

$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
Generate random password containing alphanumeric characters and the following set: !@#$%^&*()_-+=[{]};:<>|./?
#>
Function New-RandomPassword {
    param(
        [Parameter()]
        [int]$Length = 128,
        [Parameter()]
        [int]$NumberOfNonAlphaNumericCharacters = 5,
        [Parameter()]
        [switch]$ConvertToSecureString
    )
    
    Add-Type -AssemblyName 'System.Web'
    $password = [System.Web.Security.Membership]::GeneratePassword($Length,$NumberOfNonAlphaNumericCharacters)
    if ($ConvertToSecureString.IsPresent) {
        ConvertTo-SecureString -String $password -AsPlainText -Force
    } else {
        $password
    }
}

If(-Not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    Set-Location $PSScriptRoot
}

Try {
    $Dom = Get-ADDomain
    $Forest = Get-ADForest

    # In root domain, get EA + DA + Administrators. In child domains, skip EA.
    If($Dom.ParentDomain -eq $Null) {
        $Groups = "Domain Admins", "Enterprise Admins", "Administrators"    
    } Else {
        $Groups = "Domain Admins", "Administrators"
    }

    # Get all privileged groups members, but filter out users from other domains. Note, member objects could be computers so only filter out group objects.
    $Users = $Groups | Get-ADGroupMember -Recursive | Sort-Object -Unique | Where-Object { $_.objectClass -ne "group" -And $_.SID -like "$($Dom.DomainSID)-*" }
    "{0,-24}Password" -f "User" | Out-File "new_user_passwords.txt" -Force

    Foreach($User in $Users) {
        If($PSCmdlet.ShouldProcess($User, "Reset password")) {
            $Pw = New-RandomPassword -Length 32
            $PwSec = ConvertTo-SecureString $Pw -AsPlainText -Force
            Set-ADAccountPassword $User -NewPassword $PwSec -Reset -Confirm:$False 
            "{0,-24}{1}" -f $User.SamAccountName, $Pw | Out-File "new_user_passwords.txt" -Force -Append
        }
    }
} Catch {
    Write-Host ("Error changing password for {0}" -f $User.SamAccountName) -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
