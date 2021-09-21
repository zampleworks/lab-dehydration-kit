<#
.SYNOPSIS
Display current time source, and ask user to select a new one if required.
If new time source is selected, change w32time service settings.

.NOTES
Author anders.runesson@enfogroup.com
#>

$ErrorActionPreference = "Stop"

Write-Host 
Write-Host "This script will update time source on this server."
Write-Host "You should configure your PDC emulator in the root domain"
Write-Host "to sync to a reliable time source, and all other DCs to sync"
Write-Host "to the domain."
Write-Host ""

Write-Host "Example time sources:"
Write-Host "time.windows.com"
Write-Host "se.pool.ntp.org"
Write-Host "0.pool.ntp.org"
Write-Host "1.pool.ntp.org"
Write-Host "domain (to sync from AD)"    
Write-Host ""

Write-Host "Current time source: "
w32tm /query /source
Write-Host ""

Try {

    $NtpServer = ""
    Do {
        $NtpServer = Read-Host "Type in NTP server to set (do NOT include flags like ',0x1')"
    } While([string]::IsNullOrWhiteSpace($NtpServer))

    Write-Host "Setting NTP source to [$NtpServer]"

    If($NtpServer.ToLower() -ne "domain") {
        $Dns = Resolve-DnsName $NtpServer
    }

    Stop-Service w32time | Out-Null
    w32tm /unregister | Out-Null
    w32tm /register | Out-Null
    Start-Service w32time | Out-Null

    If($NtpServer.ToLower() -ne "domain") {
        w32tm /config /syncfromflags:manual /reliable:yes /manualpeerlist:"$NtpServer,0x1" /update | Out-Null
    } Else {
        w32tm /config /syncfromflags:domhier /update | Out-Null
    }

    Restart-Service w32time

    # w32tm /config /update
    w32tm /resync
    Write-Host "Time source: "
    w32tm /query /source

} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
