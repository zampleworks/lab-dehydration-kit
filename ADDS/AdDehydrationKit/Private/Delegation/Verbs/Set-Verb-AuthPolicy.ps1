# Verb: AssignAuthPolicy
#
# Grant write on msDS-AssignedAuthNPolicy (and msDS-AssignedAuthNPolicySilo)
# on User and Computer descendants of an OU. This lets a delegated role
# put accounts in/out of an authentication policy without escalating to
# Domain Admin.

function Set-Verb-AssignAuthPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $schema = Get-AdkSchema
    if (-not $schema.GuidByName.ContainsKey('msDS-AssignedAuthNPolicy')) {
        Write-AdkLog '  Authentication policy schema not present; skipping AssignAuthPolicy' -Warning
        return
    }

    $userClass     = Get-AdkClassGuid -LdapClassName 'User'
    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'
    $apAttr        = Get-AdkAttributeGuid -AttributeName 'msDS-AssignedAuthNPolicy'
    $siloAttr      = if ($schema.GuidByName.ContainsKey('msDS-AssignedAuthNPolicySilo')) {
                         Get-AdkAttributeGuid -AttributeName 'msDS-AssignedAuthNPolicySilo'
                     } else { $null }

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    foreach ($cls in @($userClass, $computerClass)) {
        Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                  -Rights $rw -ObjectType $apAttr `
                  -InheritanceType $inh -InheritObjectType $cls
        if ($siloAttr) {
            Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                      -Rights $rw -ObjectType $siloAttr `
                      -InheritanceType $inh -InheritObjectType $cls
        }
    }
}
