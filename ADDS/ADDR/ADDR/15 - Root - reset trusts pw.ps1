<#
.SYNOPSIS
Reset password for trusts. 

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
    $ThisDomain = Get-ADDomain | Select -expand DnsRoot

    Foreach($Trust in (Get-ADTrust -Filter *)) {
        Write-Host ("Creating batch scripts for resetting password for trust {0}" -f $Trust.Name)
        $Pw = (New-RandomPassword -Length 128).Replace("%", "/").Replace("^", "\").Replace("=", "(").Replace(">", ")").Replace("<", "_")
        
        $FileName = "$($Trust.Name)-root.bat"
        $FileNameChild = "$($Trust.Name)-child.bat"
        
        # Create bat file for root side of trust (run on this server)
        
        "@echo This script will reset trust password for child domain $($Trust.name)." | Out-file $FileName -Force -encoding ascii
        "@pause"  | Out-file $FileName -Append -Force -encoding ascii
        "netdom trust $ThisDomain /domain:$($Trust.name) /resetOneSide /passwordT:`"$Pw`"" | Out-File $FileName -Append -Force -encoding ascii
        #"netdom trust $ThisDomain /domain:$($Trust.name) /resetOneSide /passwordT:`"$Pw`" /userO:Administrator /passwordO:*" | Out-File $FileName -Append -Force -encoding ascii
        "@pause" | Out-file $FileName -Append -Force -encoding ascii
        
        # Create bat file for child side of trust (run on DC in child domain)
        "@echo This script will reset trust password for root domain $($Trust.name)." | Out-file $FileNameChild -Force -encoding ascii
        "@pause" | Out-file $FileNameChild -Append -Force -encoding ascii
        "netdom trust $($Trust.name) /domain:$($ThisDomain) /resetOneSide /passwordT:`"$Pw`"" | Out-File $FileNameChild -Append -Force -encoding ascii
        #"netdom trust $($Trust.name) /domain:$($ThisDomain) /resetOneSide /passwordT:`"$Pw`" /userO:Administrator /passwordO:*" | Out-File $FileNameChild -Append -Force -encoding ascii
        "@pause" | Out-file $FileNameChild -Append -Force -encoding ascii
        
        Write-Host " > Please run this bat file on THIS server to reset trust PW: " -NoNewLine
        Write-Host "[$FileName]" -ForegroundColor Yellow
        Write-Host " > Please run this bat file on DC in child domain $($Trust.name) to reset trust PW: " -NoNewLine
        Write-Host "[$FileNameChild]" -ForegroundColor Yellow
    }
} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
