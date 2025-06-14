#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

If($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "This script requires powershell 5 or newer to run"
}

$LocalDir = Get-Location | Select-Object -ExpandProperty Path
If($LocalDir -like "C:\Windows\*") {
    Write-Host "Current Path is $($LocalDir). This script must be run from the directory containing the script and data files. Please change directory." -ForegroundColor Red
    Write-Error "Path is in the windows directory: $LocalDir"
}

$LocalObjectsPath = Get-Item .\Objects | Select-Object -ExpandProperty FullName

If(-Not (Test-Path "$LocalObjectsPath\OU.csv" -PathType Leaf)) {
    Throw "File OU.csv is missing from $LocalObjectsPath"
}

Start-Transcript -Path "$LocalDir\pstranscript.txt" -Append -Force

Try {

    Write-Progress -Activity "Creating AD Contents" -CurrentOperation "Waiting for AD to be available.."
    Write-Host "Creating AD Contents - Waiting for AD to be available.."

    $AdStarted = $False
    $i = -1
    While(-Not $AdStarted) {
        If($i++ -eq 2) {
            $s = ".."
            $i = 0
        } Else {
            $s = "."
        }

        Try {
            Import-Module ActiveDirectory | Out-Null
            Get-ChildItem AD:\ | Out-Null
            $AdStarted = $True
        } Catch {
            Try { Remove-Module ActiveDirectory | Out-Null } Catch {}
            Write-Progress -Activity "Creating AD Contents" -Status "Waiting for ADWS to respond$s"
            Start-Sleep -seconds 2
        }
    }

    Import-Module ActiveDirectory, GroupPolicy

    Write-Progress -Activity "Creating AD Contents" -Status "Removing built-in delegations"
    Write-Host "Removing built-in delegations"
    .\Reset-BuiltinDelegation.ps1 -Verbose

    Start-Sleep -Seconds 3

    Write-Progress -Activity "Creating AD Contents" -Status "Creating objects"
    Write-Host "Creating objects"
    .\Create-ADContent.ps1 -Verbose

    Write-Progress -Activity "Creating AD Contents" -Status "Creating delegations"
    Write-Host "Creating delegations"
    .\Create-Delegation.ps1 -Verbose

    Write-Progress -Activity "Creating AD Contents" -Status "Importing GPOs"
    Write-Host "Importing GPOs"
    
    .\Import-Gpos.ps1 -Verbose

    Write-Progress -Activity "AD Configuration" -Status "Enabling Recycle bin"
    Write-Host "Enabling Recycle bin"

    $Bin = Get-ADOptionalFeature "Recycle Bin Feature"
    If($Null -ne $Bin.EnabledScopes -and $Bin.EnabledScopes.Count -gt 0) {
        Write-Host "Recycle bin already enabled"
    } Else {
        $ForestDns = Get-ADForest | Select-Object -ExpandProperty RootDomain
        Enable-ADOptionalFeature "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target $ForestDns -Confirm:$false
    }

    Write-Progress -Activity "AD Configuration" -Status "Create KDS Root Key.."
    Write-Host "Create KDS Root Key.."
    Add-KdsRootKey -EffectiveImmediately

    $Is2019OrGreater = [System.Environment]::OSVersion.Version.Major -ge 10 -and [System.Environment]::OSVersion.Version.Build -ge 17763
    
    If($Is2019OrGreater) {
        Write-Progress -Activity "AD Configuration" -Status "Update LAPS schema.."
        Write-Host "Update LAPS Schema.."
        try {
            Import-Module LAPS
            Update-LapsADSchema
        } catch {
            Write-Warning "Update LAPS Schema failed - LAPS PS module not found"
        }
    }

    Write-Progress -Activity "AD Configuration" -Status "Updating root DNS zone to replicate forest wide"
    Write-Host "Updating root DNS zone to replicate forest wide"
    
    $Rdse = Get-ADRootDSE
    $Dom = Get-ADDomain
    $DomDnsZoneName = $Dom.DNSRoot

    If($Rdse.rootDomainNamingContext -eq $Dom.DistinguishedName) {
        Try {
            Do {
                $DomZone = Get-DnsServerZone -Name $DomDnsZoneName
                If($DomZone.ReplicationScope -eq "Legacy") {
                    $DnsSrv = Get-DnsServer 
                    $DnsSrv.ServerSetting.DsAvailable
                    $DnsSrv.ServerZone | Select-Object ZoneName, ReplicationScope | Format-Table
                    Write-Host "DNS zone $DomDnsZoneName is not ready yet. Waiting for zone start up to be finished"
                    Start-Sleep -Seconds 5
                }
                
            } While($DomZone.ReplicationScope -eq "Legacy")

            If($DomZone.ReplicationScope -ne "Forest") {
                Set-DnsServerPrimaryZone -Name $DomZone.ZoneName -ReplicationScope Forest
            }

            $DomDnsZoneName = "_msdcs.$DomDnsZoneName"
            Do {
                $mcdsZone = Get-DnsServerZone -Name $DomDnsZoneName
                If($mcdsZone.ReplicationScope -eq "Legacy") {
                    $DnsSrv = Get-DnsServer 
                    $DnsSrv.ServerSetting.DsAvailable
                    $DnsSrv.ServerZone | Select-Object ZoneName, ReplicationScope | Format-Table
                    Write-Host "DNS zone $DomDnsZoneName is not ready yet. Waiting for zone start up to be finished"
                    Start-Sleep -Seconds 5
                }
                
            } While($mcdsZone.ReplicationScope -eq "Legacy")

            If($mcdsZone.ReplicationScope -ne "Forest") {
                Set-DnsServerPrimaryZone -Name $mcdsZone.ZoneName -ReplicationScope Forest
            }
        } Catch {
            Write-Host "Failed to set DNS Zones $($DomZone.ZoneName) and/or $($mcdsZone.ZoneName) as forest replicated: $($_.Exception.Message)"
            $DnsSrv = Get-DnsServer 
            $DnsSrv.ServerSetting.DsAvailable
            $DnsSrv.ServerZone | Select-Object ZoneName, ReplicationScope | Format-Table
        }
    }

    Write-Progress -Activity "AD Configuration" -Status "Creating authentication policies"
    Write-Host "Creating authentication policies.."

    $T0Paw = Get-AdGroup "Role T0 Device PAW" | Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value
    
    $T0SrvADSaw = Get-AdGroup "Role T0 AD SAW Server" | Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value
    $T0SrvADMgmt = Get-AdGroup "Role T0 AD Mgmt Server" | Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value

    $ClaimSC = Get-AdGroup "Claim SmartCardLogon" | Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value
    $T0Users = Get-ADGroup "Claim T0 User"  | Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value

    $T0AdAdmins = Get-ADGroup "Role T0 AD Admin"  | Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value
    $T0AdUsers = Get-ADGroup "Role T0 AD User"  | Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value

    $T0PawAPAuthToSddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID($ClaimSC)}) && (Member_of {SID($T0Users)})))"
    $T0AdUserAPAuthFromSddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID($T0Paw), SID($T0SrvADSaw)}))"
    $T0AdAdminAPAuthFromSddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID($T0SrvADSaw), SID($T0SrvADMgmt)}))"
    $T0AdSawAPAuthToSddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID($ClaimSC)}) && (Member_of_any {SID($T0AdAdmins), SID($T0AdUsers)})))"
    $T0AdSrvAPAuthToSddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID($ClaimSC)}) && (Member_of {SID($T0AdAdmins)})))"
    
    New-ADAuthenticationPolicy -Name "AP-T0-Device-PAW" -ComputerAllowedToAuthenticateTo $T0PawAPAuthToSddl -ComputerTGTLifetimeMins 240 -ProtectedFromAccidentalDeletion $True
    
    New-ADAuthenticationPolicy -Name "AP-T0-AD-User-Admin" -UserTGTLifetimeMins 240 -UserAllowedToAuthenticateFrom $T0AdAdminAPAuthFromSddl -RollingNTLMSecret Required -ProtectedFromAccidentalDeletion $True
    New-ADAuthenticationPolicy -Name "AP-T0-AD-User-Std" -UserTGTLifetimeMins 240 -UserAllowedToAuthenticateFrom $T0AdUserAPAuthFromSddl -RollingNTLMSecret Required -ProtectedFromAccidentalDeletion $True
    New-ADAuthenticationPolicy -Name "AP-T0-AD-Srv-SAW" -ComputerAllowedToAuthenticateTo $T0AdSawAPAuthToSddl -ComputerTGTLifetimeMins 240 -ProtectedFromAccidentalDeletion $True
    New-ADAuthenticationPolicy -Name "AP-T0-AD-Srv" -ComputerAllowedToAuthenticateTo $T0AdSrvAPAuthToSddl -ComputerTGTLifetimeMins 240 -ProtectedFromAccidentalDeletion $True

    Write-Progress -Activity "Creating AD Contents" -Status "Removing delegations to built-in principals on new objects"
    Write-Host "Removing delegations to built-in principals on new objects.."
    .\Reset-BuiltinDelegation.ps1 -Verbose

    Write-Progress -Activity "AD Configuration" -Status "Setting NTDS and Netlogon ports"
    Write-Host "Setting NTDS and Netlogon ports.."

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "TCP/IP Port" -Value 49151 | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DCTcpipPort" -Value 49150 | Out-Null

} Catch {
    $Ex = $_.Exception
    While($Ex) {
        Write-Host ""
        Write-Host $Ex.Message -ForegroundColor Red
        $Ex = $Ex.InnerException
    }

    Read-Host "Press key to continue"
} Finally {
    Stop-Transcript
}