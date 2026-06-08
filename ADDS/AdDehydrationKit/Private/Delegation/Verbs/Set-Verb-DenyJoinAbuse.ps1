# Verb: DenyJoinAbuse
#
# Hardens domain-join delegation against the Shelltrail RBCD attack vector.
# Sets an explicit DENY ACE on descendant computer objects for:
#
#   - Write msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD privilege escalation)
#
# When a delegated join account creates a computer object it becomes the
# Creator-Owner, which grants implicit Write-Account-Restrictions -- enough
# to set RBCD and escalate. The explicit Deny blocks this.
#
# LAPS attributes are NOT denied here. LAPS passwords are protected by the
# confidential bit (requires explicit CONTROL_ACCESS, which Creator-Owner
# does not grant) and access is delegated through explicit Pm groups. A
# LAPS deny would conflict with admins who both join machines and need to
# read LAPS passwords -- deny always trumps allow.
#
# Intended to be set on parent computer OUs (T0/Computers, T1/Computers,
# OrgRoot/Computers, NewComputers, DisabledComputers) targeting the
# deploy Adm groups. Inheritance covers all app sub-OUs so per-app deny
# entries are not required.

function Set-Verb-DenyJoinAbuse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    $schema = Get-AdkSchema
    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All

    # RBCD attribute (always present in 2012+ schema)
    if (-not $schema.GuidByName.ContainsKey('msDS-AllowedToActOnBehalfOfOtherIdentity')) {
        Write-AdkLog "  DenyJoinAbuse: msDS-AllowedToActOnBehalfOfOtherIdentity not found in schema - skipping" -Warning
        return
    }

    $rbcdGuid = Get-AdkAttributeGuid -AttributeName 'msDS-AllowedToActOnBehalfOfOtherIdentity'
    $wp = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
              -RuleType Deny `
              -Rights $wp -ObjectType $rbcdGuid `
              -InheritanceType $inh -InheritObjectType $computerClass
}
