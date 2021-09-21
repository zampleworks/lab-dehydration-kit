$ErrorActionPreference = "stop"

Set-Location $PSScriptRoot

Import-Module ActiveDirectory

. .\Delegation-Functions.ps1

$SchemaRef = Get-adobject -filter { name -eq "Enterprise Schema" } -searchbase (get-adforest | select -expand partitionscontainer) -properties ncname
$SchemaDn = $SchemaRef.nCName

$BuiltinIdentities = @{
    "AO" = "BUILTIN\Account Operators"
    "BO" = "BUILTIN\Backup Operators"
    "PO" = "BUILTIN\Print Operators"
    "SO" = "BUILTIN\Server Operators"
}

# Remove unwanted ACEs (print operators, account operators etc) from schema classes default Security Descriptor 
Get-ADObject -filter { objectClass -eq "classSchema" } -SearchBase $SchemaDN -Properties defaultSecurityDescriptor,ldapDisplayName | % {
    $o1 = $_
    If($o1.defaultSecurityDescriptor -ne $Null -And (-Not [string]::IsNullOrWhiteSpace($o1.defaultSecurityDescriptor))) {
        $newSddl = Remove-BuiltinFromSDDLACE -RemoveIdentities $BuiltinIdentities -SddlAce $o1.defaultSecurityDescriptor
        If($newSddl -ne $_.defaultSecurityDescriptor) {
            Set-ADObject $o1 -Replace @{ 'defaultSecurityDescriptor' = $newSddl}
            Write-Host "Updated default security on class [$($o1.LdapDisplayName)]"
        }
    }
}

# Remove unwanted ACEs (print operators, account operators etc) from domain partition objects
$Ids = $BuiltinIdentities.Values

Get-ADObject -filter * -SearchBase $Domain.DistinguishedName -SearchScope Subtree | % {
    $o1 = $_
    
    $p = "AD:\$($o1.DistinguishedName)"
    $Acl = Get-Acl $p
    $Updated = $False
    Foreach($Ace in $Acl.Access) {
        If(-Not $Ace.IsInherited) {
            #Write-host "$($Ace.IdentityReference.value)"
            If($Ids -contains $Ace.IdentityReference.Value) {
                Write-Verbose "Found explicit ACE on $($o1.Name) with id: [$($Ace.IdentityReference.Value)]"
                $Acl.RemoveAccessRule($Ace) | Out-Null
                $Updated = $True
            }
        }
    }
    Try {
        Set-Acl $p -AclObject $Acl
    } catch {
        Write-Host "Failed to modify ACL on $($o1.DistinguishedName): "
        Write-Host $_.Exception.Message
    }
}
