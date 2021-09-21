
$ErrorActionPreference = "stop"

Set-Location $PSScriptRoot

. .\Delegation-Functions.ps1

$Delegations = Import-csv .\Objects\Delegations.csv -Delimiter ";"

$VerbosePreference = "continue"
    
Foreach($Dlg in $Delegations) {
    $Dg = $Dlg.Delegation
    
    Write-Verbose "Setting [$Dg] for [$($Dlg.RoleName)] in [$($Dlg.OuName)]"

    $Role = Get-ADGroup $Dlg.RoleName 
    $Ou = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq $Dlg.OuName } | select -ExpandProperty DN
    
    Try {
        $AdOu = Get-ADOrganizationalUnit $Ou

        $VerbosePreference = "SilentlyContinue"
        
        If($Dlg.Delegation -eq "FullControl") {
            Set-FullControlDelegation -ObjectDN $Ou -SubjectDN $Role.DistinguishedName -Inherit
        } Elseif($Dlg.Delegation -eq "ManageUsers") {
            Set-ManageUsersDelegation -ObjectDN $Ou -SubjectDN $Role.DistinguishedName -Inherit
        } Elseif($Dlg.Delegation -eq "ManageComputers") {
            Set-ManageComputersDelegation -ObjectDN $Ou -SubjectDN $Role.DistinguishedName -Inherit
        } Elseif($Dlg.Delegation -eq "ManageGroups") {
            Set-ManageGroupsDelegation -ObjectDN $Ou -SubjectDN $Role.DistinguishedName -Inherit
        }
        
        $VerbosePreference = "continue"

    } catch {
        Write-Host "Error: $($_.exception.Message)"
        Write-Host $_.Exception.StackTrace
    }
}