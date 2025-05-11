Set-Location $PSScriptRoot

Set-ExecutionPolicy RemoteSigned -Force

Import-Module ActiveDirectory, GroupPolicy

.\Reset-BuiltinDelegation.ps1

.\Create-ADContent.ps1

.\Create-Delegation.ps1

$Domain = Get-ADDomain

$GpoDir = Get-ChildItem .\gpobackup | Select-Object -First 1
$MigTablePath = "$($GpoDir.FullName)\MigrationTable.migtable"
$MigTableContent = Get-Content $MigTablePath
$MigTableContent = $MigTableContent.Replace("@zwks.xyz", "@$($Domain.DNSRoot)")
$MigTableContent | Out-File $MigTablePath -Force

.\Import_GPOs.ps1 -domain $Domain.DNSRoot -backupFolder $GpoDir.FullName -MigTable

$ClientsGPO = Get-GPO -Name "Clients GPO"
$ClientsOU = Get-ADOrganizationalUnit -SearchBase (Get-ADDomain).DistinguishedName -SearchScope Subtree -Filter { Name -eq "Clients" }
New-GPLink -Guid $ClientsGPO.Id -Target $ClientsOU.DistinguishedName -LinkEnabled Yes | Out-Null

$ServersGPO = Get-GPO -Name "Servers GPO"
$ServersOU = Get-ADOrganizationalUnit -SearchBase (Get-ADDomain).DistinguishedName -SearchScope Subtree -Filter { Name -eq "Servers" }
New-GPLink -Guid $ServersGPO.Id -Target $ServersOU.DistinguishedName -LinkEnabled Yes | Out-Null
