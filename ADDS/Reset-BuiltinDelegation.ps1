$ErrorActionPreference = "Stop"

If($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "This script requires powershell 5 or newer to run"
}

Set-Location $PSScriptRoot

Import-Module ActiveDirectory

. .\Delegation-Functions.ps1

$SchemaDn = Get-ADRootDSE | Select-Object -ExpandProperty schemaNamingContext
$Domain = Get-ADDomain
$DomainNc = $Domain.DistinguishedName

$BuiltinIdentities = @{
    "AO" = "BUILTIN\Account Operators"
    "BO" = "BUILTIN\Backup Operators"
    "PO" = "BUILTIN\Print Operators"
    "SO" = "BUILTIN\Server Operators"
    "PW2K" = "BUILTIN\Pre-Windows 2000 Compatible Access"
}

# Remove unwanted ACEs (print operators, account operators etc) from schema classes default Security Descriptor 
Write-Host "Removing built-in delegations on Schema classes"
Get-ADObject -filter { objectClass -eq "classSchema" } -SearchBase $SchemaDN -Properties defaultSecurityDescriptor,ldapDisplayName | ForEach-Object {
    $o1 = $_
    If(-Not [string]::IsNullOrWhiteSpace($o1.defaultSecurityDescriptor)) {
        $newSddl = Remove-BuiltinFromSDDLACE -RemoveIdentities $BuiltinIdentities -SddlAce $o1.defaultSecurityDescriptor
        If($newSddl -ne $_.defaultSecurityDescriptor) {
            Try {
                Set-ADObject $o1 -Replace @{ 'defaultSecurityDescriptor' = $newSddl}
                Write-Host "Updated default security on class [$($o1.LdapDisplayName)]"
            } Catch {
                Write-Host "Failed to update ACL on $($o1.DistinguishedName): $($_.Exception.Message)"
            }
        }
    }
}

# Remove unwanted ACEs (print operators, account operators etc) from domain partition objects
Write-Host "Removing built-in delegations on domain partition objects"

$Ids = $BuiltinIdentities.Values
Get-ADObject -filter * -SearchBase $DomainNc -SearchScope Subtree | ForEach-Object {
    $o1 = $_
    
    $p = "AD:\$($o1.DistinguishedName)"
    $Acl = Get-Acl $p
    $Modified = $false
    Foreach($Ace in $Acl.Access) {
        If(-Not $Ace.IsInherited) {
            #Write-host "$($Ace.IdentityReference.value)"
            If($Ids -contains $Ace.IdentityReference.Value) {
                Write-Verbose "Found explicit ACE on $($o1.Name) with id: [$($Ace.IdentityReference.Value)]"
                $Acl.RemoveAccessRule($Ace) | Out-Null
                $Modified = $True
            }
        }
    }

    If($Modified) {
        Try {
            Write-Verbose "Saving new ACL for $($o1.Name)"
            Set-Acl $p -AclObject $Acl
        } catch {
            If($o1.DistinguishedName -ne "CN=LostAndFound,$DomainNc") {
                Write-Host "Failed to modify ACL on $($o1.DistinguishedName)."
                Write-Host $_.Exception.Message
            }
        }
    }
}
