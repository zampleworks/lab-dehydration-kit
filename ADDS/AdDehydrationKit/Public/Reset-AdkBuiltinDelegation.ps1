# Strip the built-in pre-2003 operator groups (Account Operators, Backup
# Operators, Print Operators, Server Operators, Pre-Windows 2000
# Compatible Access) from:
#   1) the default security descriptor of every schema class, and
#   2) explicit ACEs anywhere in the domain partition
#
# Idempotent; safe to re-run.

function Reset-AdkBuiltinDelegation {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $rootDse = Get-ADRootDSE
    $schemaDn = $rootDse.SchemaNamingContext
    $domainNc = (Get-ADDomain).DistinguishedName

    $builtin = @{
        'AO'   = 'BUILTIN\Account Operators'
        'BO'   = 'BUILTIN\Backup Operators'
        'PO'   = 'BUILTIN\Print Operators'
        'SO'   = 'BUILTIN\Server Operators'
        'PW2K' = 'BUILTIN\Pre-Windows 2000 Compatible Access'
    }

    Write-AdkLog 'Removing built-in delegations from schema-class default SDs' -Step
    # foreach() - pipeline ForEach-Object with a script block errors when
    # $WhatIfPreference is active in this scope.
    $schemaClasses = Get-ADObject -Filter { objectClass -eq 'classSchema' } `
                                  -SearchBase $schemaDn `
                                  -Properties defaultSecurityDescriptor, ldapDisplayName
    foreach ($obj in $schemaClasses) {
        if ([string]::IsNullOrWhiteSpace($obj.defaultSecurityDescriptor)) { continue }

        $newSddl = Remove-BuiltinFromSDDLACE -RemoveIdentities $builtin -SddlAce $obj.defaultSecurityDescriptor
        if ($newSddl -ne $obj.defaultSecurityDescriptor) {
            if (-not $PSCmdlet.ShouldProcess($obj.DistinguishedName, 'Strip built-in operators from default SD')) { continue }
            try {
                Set-ADObject $obj -Replace @{ defaultSecurityDescriptor = $newSddl }
                Write-AdkLog "  updated default SD on class [$($obj.LdapDisplayName)]"
            } catch {
                Write-AdkLog "  failed to update ACL on $($obj.DistinguishedName): $($_.Exception.Message)" -IsError
            }
        }
    }

    Write-AdkLog 'Removing explicit built-in ACEs from domain partition objects' -Step
    $ids = $builtin.Values
    # foreach (not pipeline ForEach-Object) so $WhatIfPreference in this
    # scope doesn't cause the cmdlet binder to try to bind -WhatIf to
    # the script block (which it doesn't support).
    foreach ($obj in (Get-ADObject -Filter * -SearchBase $domainNc -SearchScope Subtree)) {
        $aclPath = "AD:\$($obj.DistinguishedName)"
        $acl = Get-Acl $aclPath
        $modified = $false

        foreach ($ace in $acl.Access) {
            if ($ace.IsInherited) { continue }
            if ($ids -contains $ace.IdentityReference.Value) {
                Write-Verbose "Found explicit ACE on $($obj.Name) with id: [$($ace.IdentityReference.Value)]"
                [void] $acl.RemoveAccessRule($ace)
                $modified = $true
            }
        }

        if ($modified) {
            if (-not $PSCmdlet.ShouldProcess($obj.DistinguishedName, 'Remove explicit built-in operator ACEs')) { continue }
            try {
                Set-Acl $aclPath -AclObject $acl
            } catch {
                if ($obj.DistinguishedName -ne "CN=LostAndFound,$domainNc") {
                    Write-AdkLog "  failed to modify ACL on $($obj.DistinguishedName): $($_.Exception.Message)" -IsError
                }
            }
        }
    }
}