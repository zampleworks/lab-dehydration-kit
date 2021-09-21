
$Pw = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force

Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
Import-Module addsdeployment

$DNSName = "zwks.xyz"
$NBName = "ZWCORP"

Install-ADDSForest -DomainName $DNSName -DomainNetbiosName $NBName -SkipPreChecks -SafeModeAdministratorPassword $Pw -InstallDns -Confirm:$False

