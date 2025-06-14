<#
    Generate migration table for T0/T1 GPOs based on migtable template
#>

$ErrorActionPreference = "Stop"

If($Null -eq $LocalObjectsPath) {
    $LocalObjectsPath = Get-Item .\Objects | Select-Object -ExpandProperty FullName
}

If(-Not (Test-Path "$LocalObjectsPath\OU.csv" -PathType Leaf)) {
    Throw "File OU.csv is missing from $LocalObjectsPath"
}

$DomainDnsName = Get-ADDomain | Select-Object -ExpandProperty DNSRoot
$OuDefinitions = Import-csv "$LocalObjectsPath\OUStructure.csv" -Delimiter ";"

$GpoDefinitions = @(
    @{ Tier = "T0"; Service = "AD"; Type = "Servers"; Ou = "%DSControlADServersOU%"; BackupGpoBaseName = "T0 SoD AD Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T0"; Service = "AD"; Type = "SAW"; Ou = "%DSControlADSAWServersOU%"; BackupGpoBaseName = "T0 SoD AD SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T0"; Service = "PKI"; Type = "Servers"; Ou = "%DSControlPKIServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T0"; Service = "PKI"; Type = "SAW"; Ou = "%DSControlPKISAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T0"; Service = "IDM"; Type = "Servers"; Ou = "%DSControlIDMServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T0"; Service = "IDM"; Type = "SAW"; Ou = "%DSControlIDMSAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T0"; Service = "EDR"; Type = "Servers"; Ou = "%DSControlEDRServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T0"; Service = "EDR"; Type = "SAW"; Ou = "%DSControlEDRSAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T0"; Service = "Monitoring"; Type = "Servers"; Ou = "%DSControlMonitoringServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T0"; Service = "Monitoring"; Type = "SAW"; Ou = "%DSControlMonitoringSAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T0"; Service = "DB"; Type = "Servers"; Ou = "%DSControlDBServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T0"; Service = "DB"; Type = "SAW"; Ou = "%DSControlDBSAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T1"; Service = "EDR"; Type = "Servers"; Ou = "%T1EDRServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T1"; Service = "EDR"; Type = "SAW"; Ou = "%T1EDRSAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T1"; Service = "DB"; Type = "Servers"; Ou = "%T1DBServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T1"; Service = "DB"; Type = "SAW"; Ou = "%T1DBSAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T1"; Service = "Monitoring"; Type = "Servers"; Ou = "%T1MonitoringServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T1"; Service = "Monitoring"; Type = "SAW"; Ou = "%T1MonitoringSAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T1"; Service = "SAP"; Type = "Servers"; Ou = "%T1SAPServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T1"; Service = "SAP"; Type = "SAW"; Ou = "%T1SAPSAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T1"; Service = "Sharepoint"; Type = "Servers"; Ou = "%T1SharepointServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T1"; Service = "Sharepoint"; Type = "SAW"; Ou = "%T1SharepointSAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}
    @{ Tier = "T1"; Service = "Web"; Type = "Servers"; Ou = "%T1WebServersOU%"; BackupGpoBaseName = "T0 SoD DB Servers"; PmGroupPattern = "Pm AD %Tier% Server %Svc%"}
    @{ Tier = "T1"; Service = "Web"; Type = "SAW"; Ou = "%T1WebSAWServersOU%"; BackupGpoBaseName = "T0 SoD DB SAW"; PmGroupPattern = "Pm AD %Tier% Server %Svc% SAW"}

    @{ Tier = "T0"; Service = "PAW"; Type = "PAW"; Ou = "%DSControlPAWDeviceOU%"; BackupGpoBaseName = "T0 SoD PAW"; PmGroupPattern = "Pm AD %Tier% Device PAW"}
    @{ Tier = "T1"; Service = "PAW"; Type = "PAW"; Ou = "%T1PAWOU%"; BackupGpoBaseName = "T0 SoD PAW"; PmGroupPattern = "Pm AD %Tier% Device PAW"}
)

Write-Progress -Activity "AD Configuration" -Status "Importing GPOs" -CurrentOperation "Preparing import data"
Write-Host "Import GPOs - create migration tables"

$GpoBackupsPath = Get-Item .\gpobackup | Select-Object -ExpandProperty FullName
$MigTableTemplate = Get-ChildItem ".\MigTable-SoD.template" | Select-Object -ExpandProperty FullName

# Update server/SAW GPO definitions with proper OU DN's. Read from OUDefinitions.csv
Foreach($GpoDef in $GpoDefinitions) {
    $Ou = $OuDefinitions | Where-Object { $_.Name -eq $GpoDef.Ou } | Select-Object -ExpandProperty DN
    
    if($Null -eq $Ou) {
        throw "OU not defined for [$($GpoDef.Tier)] - [$($GpoDef.Service)]"
    }

    $GpoDef.Ou = $Ou
}

# Generate migration tables
Foreach($GpoDef in $GpoDefinitions) {
    $Tier = $GpoDef.Tier
    $Svc = $GpoDef.Service
    $Type = $GpoDef.Type

    $Slg = "$($GpoDef.PmGroupPattern.Replace("%Tier%", $Tier).Replace("%Svc%", $Svc)) ServiceLogon"  #  "Pm AD $t Server $Svc ServiceLogon"
    $Lag = "$($GpoDef.PmGroupPattern.Replace("%Tier%", $Tier).Replace("%Svc%", $Svc)) LocalAdmin" #"Pm AD $t Server $Svc LocalAdmin"
    $Ilg = "$($GpoDef.PmGroupPattern.Replace("%Tier%", $Tier).Replace("%Svc%", $Svc)) InteractiveLogon" #"Pm AD $t Server $Svc InteractiveLogon"
    $Rdg = "$($GpoDef.PmGroupPattern.Replace("%Tier%", $Tier).Replace("%Svc%", $Svc)) RdpLogon" #"Pm AD $t Server $Svc RdpLogon"

    $MigData = Get-Content $MigTableTemplate
    $MigData = $MigData.Replace("%ServiceLogonGroup%", $Slg)
    $MigData = $MigData.Replace("%LocalAdminGroup%", $Lag)
    $MigData = $MigData.Replace("%InteractiveLogonGroup%", $Ilg)
    $MigData = $MigData.Replace("%RdpLogonGroup%", $Rdg)


    $MigData = $MigData.Replace("%DomainDNSName%", $DomainDnsName)

    If($Type -eq "PAW") {
        $MigTableName = "$Tier SoD $Type.migtable"
    } Else {
        $MigTableName = "$Tier SoD $Svc $Type.migtable"
    }

    $MigData | Out-File "$GpoBackupsPath\$MigTableName" -Force
}

foreach($GpoDef in $GpoDefinitions) {
    $Tier = $GpoDef.Tier
    $Svc = $GpoDef.Service
    $Type = $GpoDef.Type
    $BackupGpo = $GpoDef.BackupGpoBaseName

    If($Type -eq "PAW") {
        $GpoName = "$Tier SoD $Type"
        $MigTableName = "$GpoName.migtable"
    } Else {
        $GpoName = "$Tier SoD $Svc $Type"
        $MigTableName = "$GpoName.migtable"
    }
    
    Write-Progress -Activity "AD Configuration" -Status "Importing GPOs" -CurrentOperation "Importing [$GpoName]"
    
    Write-Verbose "Import GPO [$GpoName]"
    Try {
        Import-Gpo -BackupGpoName $BackupGpo -Path $GpoBackupsPath -TargetName $GpoName -CreateIfNeeded -MigrationTable "$GpoBackupsPath\$MigTableName" | Out-Null
    } Catch {
        Write-Warning "Error importing [$GpoName]: $($_.Exception.Message)"
    }

    Try {
        New-GPLink -Name $GpoName -Target $GpoDef.Ou -LinkEnabled Yes | Out-Null
    } Catch {}
    
}

$GpoName = "Default Domain Controllers Policy"

Write-Progress -Activity "AD Configuration" -Status "Importing GPOs" -CurrentOperation "Importing [$GpoName]"
Write-Verbose "Import GPO [$GpoName]"

Try {
    Import-Gpo -BackupGpoName $GpoName -Path $GpoBackupsPath -TargetName $GpoName | Out-Null
} catch {
    Write-Warning "Error importing $($GpoName): $($_.Exception.Message)"
}

$GpoName = "Default Domain Policy"

Write-Progress -Activity "AD Configuration" -Status "Importing GPOs" -CurrentOperation "Importing [$GpoName]"
Write-Verbose "Import GPO [$GpoName]"

Try {
    Import-Gpo -BackupGpoName $GpoName -Path $GpoBackupsPath -TargetName $GpoName | Out-Null
} catch {
    Write-Warning "Error importing $($GpoName): $($_.Exception.Message)"
}
