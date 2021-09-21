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

$Domain = "ad04.zwks.xyz"
$IfmPath = "C:\ADDS\IFM"

Write-Host "Checking connectivity to domain $Domain"
$Dns = Resolve-DnsName $Domain 
Test-NetConnection -ComputerName $Domain | Out-Null

Write-Host "OK, domain resolves and can be pinged."

$DrPw = New-RandomPassword -Length 127 -ConvertToSecureString
$DomainCred = Get-Credential -Message "Please enter credentials for an account with Domain Admin permissions"

Add-WindowsFeature AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment

Install-ADDSDomainController -DomainName $Domain -SafeModeAdministratorPassword $DrPw -Credential $DomainCred -InstallationMediaPath $IfmPath -SysvolPath C:\ADDS\SYSVOL -DatabasePath C:\ADDS\Db -LogPath C:\ADDS\DbLog -confirm:$False



