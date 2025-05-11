
$Pw = "P@ssw0rd"

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

$RandomNum = Get-Random -Minimum 100 -Maximum 999
$DomainName = "AD$RandomNum"
$DomainDNSName = "AD$RandomNum.zwks.xyz"

# 1 = 2000, 2 = 2003, 3 = 2008, 4 = 2008R2
$DomainLevel = 4
$ForestLevel = 4

$AddsFileRootPath = "C:\ADDS"
$AddsDbPath = "$AddsFileRootPath\NTDS"
$AddsLogPath = "$AddsFileRootPath\NTDS"
$AddsSysvolPath = "$AddsFileRootPath\SYSVOL"
$AddsAdminFilesPath = "$AddsFileRootPath\Install"

If(-Not (Test-Path $AddsFileRootPath)) {
    New-Item $AddsFileRootPath -ItemType Directory | Out-Null
}

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

$AddsDeploymentModule = Get-Module addsdeployment -ListAvailable
If($Null -eq $AddsDeploymentModule) {
    
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
    "DomainNetBiosName=$DomainName" | Out-File "$AnswerFilePath" -Append
    
    "" | Out-File "$AnswerFilePath" -Append
    
    "Password=$Pw" | Out-File "$AnswerFilePath" -Append
    "SafeModeAdminPassword=$Pw" | Out-File "$AnswerFilePath" -Append

    "" | Out-File "$AnswerFilePath" -Append
    
    "RebootOnCompletion=no" | Out-File "$AnswerFilePath" -Append

    dcpromo /unattend:"$AnswerFilePath"

} Else {
    $SecPwd = ConvertTo-SecureString $Pw -AsPlainText -Force
    Import-Module addsdeployment
    Install-ADDSForest -DomainName $DomainDNSName -DomainNetbiosName $DomainName -SkipPreChecks -SafeModeAdministratorPassword $SecPwd -InstallDns -Confirm:$False
}

