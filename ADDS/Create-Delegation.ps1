
$ErrorActionPreference = "stop"

Set-Location $PSScriptRoot

. .\Delegation-Functions.ps1

If($Null -eq $LocalObjectsPath) {
    $LocalObjectsPath = Get-Item .\Objects | Select-Object -ExpandProperty FullName
}

If(-Not (Test-Path "$LocalObjectsPath\OU.csv" -PathType Leaf)) {
    Throw "File OU.csv is missing from $LocalObjectsPath"
}

$Delegations = Import-csv "$LocalObjectsPath\Delegations.csv" -Delimiter ";"

$VerbosePreference = "continue"
    
Foreach($Dlg in $Delegations) {
    $Dg = $Dlg.Delegation
    
    Write-Verbose "Setting [$Dg] for [$($Dlg.RoleName)] in [$($Dlg.OuName)]"

    $Role = Get-ADGroup $Dlg.RoleName 
    $Ou = Import-csv "$LocalObjectsPath\OUStructure.csv" -Delimiter ";" | Where-Object { $_.Name -eq $Dlg.OuName } | Select-Object -ExpandProperty DN
    
    Try {
        Get-ADOrganizationalUnit $Ou | Out-Null

        $VerbosePreference = "SilentlyContinue"
        
        If($Dlg.Delegation -eq "FullControl") {
            Set-FullControlDelegation -ObjectDN $Ou -SubjectDN $Role.DistinguishedName -Inherit
        } Elseif($Dlg.Delegation -eq "ManageUsers") {
            Set-ManageUsersDelegation -ObjectDN $Ou -SubjectDN $Role.DistinguishedName -Inherit
        } Elseif($Dlg.Delegation -eq "ManageComputers") {
            Set-ManageComputersDelegation -ObjectDN $Ou -SubjectDN $Role.DistinguishedName -Inherit
        } Elseif($Dlg.Delegation -eq "ManageGroups") {
            Set-ManageGroupsDelegation -ObjectDN $Ou -SubjectDN $Role.DistinguishedName -Inherit
        } Elseif($Dlg.Delegation -eq "ResetPwd") {
            Set-ManageGroupsDelegation -ObjectDN $Ou -SubjectDN $Role.DistinguishedName -Inherit
        }
        
        $VerbosePreference = "continue"

    } catch {
        Write-Host "Error: $($_.exception.Message)"
        Write-Host $_.Exception.StackTrace
    }
}