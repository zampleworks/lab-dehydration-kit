Param(

    [Parameter(Mandatory = $False)]
    [string]
    $DomainDnsName,

    [Parameter(Mandatory = $False)]
    [string]
    $DomainNetBiosName,

    [Parameter(Mandatory = $False)]
    [string]
    $DbPath,

    [Parameter(Mandatory = $False)]
    [string]
    $LogPath,

    [Parameter(Mandatory = $False)]
    [string]
    $SysvolPath,
    
    [Parameter(Mandatory = $False)]
    [string]
    $DsrmPwd
)

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

. .\Functions.ps1

If($Null -ne $DsrmPwd) {
    $DsrmPw = $DsrmPwd
} Else {
    $DsrmPw = New-RandomPassword -Length 32
}

# On old versions of Windows you need to manually load the ServerManager module
$ServerManModule = Get-Module ServerManager
If($Null -ne $ServerManModule) {
    Import-Module $ServerManModule
}

# OSVersion is deprecated
# $OsVersion = [environment]::OSVersion.Version

$OsVersion = New-Object System.Version (Get-CimInstance Win32_OperatingSystem).Version

If($OsVersion.Major -lt 6 -or ($OsVersion.Major -eq 6 -and $OsVersion.Minor -le 1)) {
    # Windows Server 2008R2 or older
    Add-WindowsFeature AD-Domain-Services, GPMC
} Else {
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
}

If($Null -eq $DomainDnsName) {
    $Name = hostname

    If($Name -match "(\d+)") {
        $SequenceNum = $Matches[$Matches.Count - 1]
    } Else {
        $SequenceNum = Get-Random -Minimum 100 -Maximum 999
    }

    $SubDomain = "ad$SequenceNum"
    $DomainDnsName = "{0}.zwks.xyz" -f $SubDomain
} Else {
    $SubDomain = $DomainDnsName.Substring(0, $DomainDnsName.IndexOf("."))
}

If($null -eq $DomainNetBiosName) {
    $DomainNetBiosName = $SubDomain.ToUpper()
}

If($Null -eq $DbPath) {
    $AddsDbPath = "C:\ADDS\NTDS"
} Else {
    $AddsDbPath = $DbPath
}
If($Null -eq $LogPath) {
    $AddsLogPath = "C:\ADDS\NTDS"
} Else {
    $AddsLogPath = $LogPath
}
If($Null -eq $SysvolPath) {
    $AddsSysvolPath = "C:\ADDS\NTDS"
} Else {
    $AddsSysvolPath = $SysvolPath
}
$AddsAdminFilesPath = "C:\ADDS\Install"

If(-Not (Test-Path $AddsDbPath)) {
    New-Item $AddsDbPath -ItemType Directory | Out-Null
}

If(-Not (Test-Path $AddsLogPath)) {
    New-Item $AddsLogPath -ItemType Directory | Out-Null
}

If(-Not (Test-Path $AddsSysvolPath)) {
    New-Item $AddsSysvolPath -ItemType Directory | Out-Null
}

If(-Not (Test-Path $AddsAdminFilesPath)) {
    New-Item $AddsAdminFilesPath -ItemType Directory | Out-Null
}

regsvr32 C:\Windows\System32\schmmgmt.dll

$AddsDeploymentModule = Get-Module addsdeployment -ListAvailable
If($Null -eq $AddsDeploymentModule) {
    # 1 = 2000, 2 = 2003, 3 = 2008, 4 = 2008R2, 5 = 2012, 6 = 2012R2, 7 = 2016/threshold
    $DomainLevel = 4
    $ForestLevel = 4

    $AnswerFilePath = "$AddsAdminFilesPath\$DomainName.dcpromo.txt"

    "[DCINSTALL]" | Out-File "$AnswerFilePath" -Force
    
    "" | Out-File "$AnswerFilePath" -Append
    
    "InstallDNS=yes" | Out-File "$AnswerFilePath" -Append
    "CreateDNSDelegation=no" | Out-File "$AnswerFilePath" -Append
    
    "" | Out-File "$AnswerFilePath" -Append
    
    "DatabasePath=$AddsDbPath" | Out-File "$AnswerFilePath" -Append
    "LogPath=$AddsLogPath" | Out-File "$AnswerFilePath" -Append
    "SysvolPath=$AddsSysvolPath" | Out-File "$AnswerFilePath" -Append
    
    "" | Out-File "$AnswerFilePath" -Append
    
    "ConfirmGC=yes" | Out-File "$AnswerFilePath" -Append
    "NewDomain=forest" | Out-File "$AnswerFilePath" -Append
    "ReplicaOrNewDomain=domain" | Out-File "$AnswerFilePath" -Append
    "NewDomainDNSName=$DomainDNSName" | Out-File "$AnswerFilePath" -Append
    "DomainLevel=$DomainLevel" | Out-File "$AnswerFilePath" -Append
    "ForestLevel=$ForestLevel" | Out-File "$AnswerFilePath" -Append
    "DomainNetBiosName=$DomainNetBiosName" | Out-File "$AnswerFilePath" -Append
    
    "" | Out-File "$AnswerFilePath" -Append
    
    "Password=$Pw" | Out-File "$AnswerFilePath" -Append
    "SafeModeAdminPassword=$DsrmPw" | Out-File "$AnswerFilePath" -Append

    "" | Out-File "$AnswerFilePath" -Append
   
    "RebootOnCompletion=no" | Out-File "$AnswerFilePath" -Append
    
    dcpromo /unattend:"$AnswerFilePath"

} Else {
    $SecPwd = ConvertTo-SecureString $DsrmPw -AsPlainText -Force
    Import-Module addsdeployment
    
    Install-ADDSForest -DomainName $DomainDNSName -DomainNetbiosName $DomainNetBiosName -SkipPreChecks -SafeModeAdministratorPassword $SecPwd -InstallDns -Confirm:$False -NoRebootOnCompletion
}

If($Null -eq $DsrmPwd) {
    Write-Host "************************************************************************************" -ForegroundColor DarkYellow
    Write-Host "* PASSWORD HAVE BEEN AUTO GENERATED FOR DSRM!                                      *" -ForegroundColor DarkYellow
    Write-Host "* There is no way to retrieve it later. Write them down right now.                 *" -ForegroundColor DarkYellow
    Write-Host "* Password for DSRM:                                                               *" -ForegroundColor DarkYellow
    Write-Host "* $DsrmPw                                                                          *" -ForegroundColor DarkYellow
    Write-Host "************************************************************************************" -ForegroundColor DarkYellow
    Read-Host "Write down passwords, and press enter to continue"
}