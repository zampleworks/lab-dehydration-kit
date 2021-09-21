<#
.SYNOPSIS
Reset password for krbtgt account and restarts ADDS.

.NOTES
Author anders.runesson@enfogroup.com
#>
[CmdletBinding(
    SupportsShouldProcess = $True,
    ConfirmImpact = "High"
)]
Param(
    [switch]
    $RestartAdds
)

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
        [int]$NumberOfAlphaNumericCharacters = 5,
        [Parameter()]
        [switch]$ConvertToSecureString
    )
    
    Add-Type -AssemblyName 'System.Web'
    $password = [System.Web.Security.Membership]::GeneratePassword($Length,$NumberOfAlphaNumericCharacters)
    if ($ConvertToSecureString.IsPresent) {
        ConvertTo-SecureString -String $password -AsPlainText -Force
    } else {
        $password
    }
}

Try {
    $Krbtgt = Get-ADUser krbtgt -Properties pwdLastSet
    $PwLastSet = [DateTime]::FromFileTime($Krbtgt.pwdLastSet)

    If(((Get-Date) - $PwLastSet).TotalDays -lt 3) {
        Write-Warning "krbtgt password changed very recently. Not doing anything."
        return
    }

    If($PSCmdlet.ShouldProcess($Krbtgt, "Reset password")) {
        Write-Verbose ""
        Write-Verbose "Updating password on krbtgt account, twice in a row. You should see pwdLastSet changing in the output."
        Write-Verbose ""
        Write-Verbose ("Pwdlastset before change: {0}" -f $PwLastSet.ToString("s"))
        
        $Pw = New-RandomPassword -Length 128 -ConvertToSecureString
    
        Set-ADAccountPassword -Identity $Krbtgt -NewPassword $Pw -Reset
        Start-Sleep -Seconds 2

        $Krbtgt = Get-ADUser krbtgt -Properties pwdLastSet
        $PwLastSet = [DateTime]::FromFileTime($Krbtgt.pwdLastSet)
        Write-Verbose ("Pwdlastset after change:  {0}" -f $PwLastSet.ToString("s"))

        If($RestartAdds) {
            Write-Verbose "Restarting ADDS services.."
            Restart-Service ntds -force
        }
        
    } Else {
        Write-Host "User cancelled, not doing anything."
    }
} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
