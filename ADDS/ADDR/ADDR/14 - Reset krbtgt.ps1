<#
.SYNOPSIS
Reset password for krbtgt account. 
Only for recovery scenarios! Do NOT use this script for scheduled reset of krbtgt password in production!

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

Try {

    Write-Host ""
    Write-Host "Updating password on krbtgt account, twice in a row. You should see pwdLastSet changing in the output." -ForegroundColor Yellow
    Write-Host ""

    $Krbtgt = Get-ADUser krbtgt -Properties pwdLastSet

    If($PSCmdlet.ShouldProcess($Krbtgt, "Update password")) {
        Write-Host ("Pwdlastset before 1st change: {0}" -f [DateTime]::FromFileTime($Krbtgt.pwdLastSet).ToString("s"))
        $Pw = New-RandomPassword -Length 128 -ConvertToSecureString
        Set-ADAccountPassword -Identity $Krbtgt -NewPassword $Pw -Reset

        Start-Sleep -Seconds 2

        $Krbtgt = Get-ADUser krbtgt -Properties pwdLastSet
        Write-Host ("Pwdlastset after 1st change:  {0}" -f [DateTime]::FromFileTime($Krbtgt.pwdLastSet).ToString("s"))
        $Pw = New-RandomPassword -Length 128 -ConvertToSecureString
        Set-ADAccountPassword -Identity $Krbtgt -NewPassword $Pw -Reset

        $Krbtgt = Get-ADUser krbtgt -Properties pwdLastSet
        Write-Host ("Pwdlastset after 2nd change:  {0}" -f [DateTime]::FromFileTime($Krbtgt.pwdLastSet).ToString("s"))

        Write-Host "Restarting ADDS services.."
        Restart-Service ntds -force
        Restart-Service ADWS

        Write-Host "Password of krbtgt account reset twice and ADDS services restarted." 
    }
} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
