$ErrorActionPreference = "stop"

Set-Location $PSScriptRoot

Import-Module ActiveDirectory

. .\Delegation-Functions.ps1

$SchemaDn = (Get-ADRootDSE).schemaNamingContext
$Domain = Get-ADDomain

$BuiltinIdentities = @{
    "AO" = "BUILTIN\Account Operators"
    "BO" = "BUILTIN\Backup Operators"
    "PO" = "BUILTIN\Print Operators"
    "SO" = "BUILTIN\Server Operators"
    "RU" = "BUILTIN\Pre-Windows 2000 Compatible Access"
}

# Remove unwanted ACEs (print operators, account operators etc) from schema classes default Security Descriptor 
$Objs = Get-ADObject -filter { objectClass -eq "classSchema" } -SearchBase $SchemaDN -Properties defaultSecurityDescriptor,ldapDisplayName
$Objs | ForEach-Object {
    $o1 = $_
    If($o1.defaultSecurityDescriptor -ne $Null -And (-Not [string]::IsNullOrWhiteSpace($o1.defaultSecurityDescriptor))) {
        $newSddl = Remove-IdsFromSDDLACE -RemoveIdentities $BuiltinIdentities -SddlAce $o1.defaultSecurityDescriptor
        If($newSddl -ne $o1.defaultSecurityDescriptor) {
            Try {
                Set-ADObject $o1 -Replace @{ 'defaultSecurityDescriptor' = $newSddl}
                Write-Host "Updated default security descriptor on class [$($o1.LdapDisplayName)]"
            } Catch {
                Write-Warning "Couldn't update default security descriptor on class [$($o1.LdapDisplayName)]"
            }
        }
    }
}

# Remove unwanted ACEs (print operators, account operators etc) from domain partition objects
$Ids = $BuiltinIdentities.Values

$Objs = Get-ADObject -filter * -SearchBase $Domain.DistinguishedName -SearchScope Subtree 
$Objs | ForEach-Object {
    $o1 = $_
    
    $p = "AD:\$($o1.DistinguishedName)"
    $Acl = Get-Acl $p
    $Updated = $False
    Foreach($Ace in $Acl.Access) {
        If(-Not $Ace.IsInherited) {
            If($Ids -contains $Ace.IdentityReference.Value) {
                Write-Host "Removing ACE on $($o1.DistinguishedName) for: [$($Ace.IdentityReference.Value)]"
                $Acl.RemoveAccessRule($Ace) | Out-Null
                $Updated = $True
            }
        }
    }
    If($Updated) {
        Try {
            Set-Acl $p -AclObject $Acl
        } catch {
            Write-Host "Failed to modify ACL on $($o1.DistinguishedName): "
            Write-Host $_.Exception.Message
        }
    }
}
