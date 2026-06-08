# Verbs: DomainJoin, DomainRejoin
#
# DomainJoin   - join NEW computers into the OU. No descendant rights;
#                you create a computer object and that's it. Useful for
#                imaging pipelines / provisioning workflows.
#
#                Granted on the OU:
#                  - Create-Child  on Computer class
#                  - On descendant Computer objects:
#                      Validated-DNS-Host-Name extended right
#                      Validated-SPN extended right
#                      Write servicePrincipalName
#                      Write dNSHostName
#                      Write account restrictions (property set)
#
# DomainRejoin - full computer lifecycle. Adds delete + password reset
#                + userAccountControl/displayName/description writes
#                on descendant computers. Suitable for on-site/help-desk
#                admins who replace machines.

function Set-Verb-DomainJoin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'
    $exValidatedDns = Get-AdkExtendedRightGuid -RightName 'Validated-DNS-Host-Name'
    $exValidatedSpn = Get-AdkExtendedRightGuid -RightName 'Validated-SPN'
    $exAccountRestrictions = Get-AdkExtendedRightGuid -RightName 'User-Account-Restrictions'

    $spn         = Get-AdkAttributeGuid -AttributeName 'servicePrincipalName'
    $dnsHostName = Get-AdkAttributeGuid -AttributeName 'dNSHostName'

    # Create-Child on the OU itself (so descendants of the OU can be the
    # object class created). Use ::None for inheritance - the create
    # right belongs on the OU, not on every descendant.
    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                      -ObjectLdapClassName 'Computer' `
                      -Inheritance ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    # Validated writes (these are how a joining computer sets its own
    # SPN / dNSHostName during the netjoin handshake)
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::Self) `
              -ObjectType $exValidatedDns `
              -InheritanceType $inh -InheritObjectType $computerClass

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::Self) `
              -ObjectType $exValidatedSpn `
              -InheritanceType $inh -InheritObjectType $computerClass

    # Property writes on descendant computer objects
    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $spn `
              -InheritanceType $inh -InheritObjectType $computerClass

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $dnsHostName `
              -InheritanceType $inh -InheritObjectType $computerClass

    # Account-Restrictions property set (covers userAccountControl,
    # pwdLastSet, accountExpires, lockoutTime, lockoutDuration, etc.)
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ExtendedRight $exAccountRestrictions `
              -PropertyAccess ([System.DirectoryServices.PropertyAccess]::Read -bor `
                               [System.DirectoryServices.PropertyAccess]::Write) `
              -InheritanceType $inh -InheritObjectType $computerClass
}

function Set-Verb-DomainRejoin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'
    $exForceChange = Get-AdkExtendedRightGuid -RightName 'User-Force-Change-Password'

    $rightUac    = Get-AdkAttributeGuid -AttributeName 'userAccountControl'
    $displayName = Get-AdkAttributeGuid -AttributeName 'displayName'
    $description = Get-AdkAttributeGuid -AttributeName 'description'

    # Everything DomainJoin grants
    Set-Verb-DomainJoin -ObjectDN $ObjectDN -SubjectDN $SubjectDN -Parameters $Parameters

    # Plus delete (so re-joins and decommissions don't leak)
    Set-AdAllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                      -ObjectLdapClassName 'Computer' -Inheritance $inh

    # Password reset on descendants
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ExtendedRight $exForceChange `
              -InheritanceType $inh -InheritObjectType $computerClass

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    foreach ($attr in @($rightUac, $displayName, $description)) {
        Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                  -Rights $rw -ObjectType $attr `
                  -InheritanceType $inh -InheritObjectType $computerClass
    }
}
