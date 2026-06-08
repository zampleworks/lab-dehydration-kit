# Builds (and caches) a snapshot of the AD schema needed by delegation
# verbs: class/attribute GUIDs and extended-right GUIDs, plus the set of
# extended rights that are actually property sets.
#
# The cache is module-scoped ($Script:AdkSchema). Call
# Get-AdkSchema from verb implementations to get it; the cache is
# built lazily on first call.

function Initialize-AdkSchema {
    [CmdletBinding()]
    param(
        [switch] $Force
    )

    if ($Script:AdkSchema -and -not $Force) {
        return $Script:AdkSchema
    }

    $rootDse = Get-ADRootDSE

    $guidByName = @{}
    $nameByGuid = @{}

    # foreach() - pipeline ForEach-Object with script blocks errors when
    # this function is called from a -WhatIf cmdlet (the binder tries to
    # bind -WhatIf to ForEach-Object).
    $schemaObjects = Get-ADObject -SearchBase $rootDse.schemaNamingContext `
                                  -LDAPFilter '(schemaidguid=*)' `
                                  -Properties ldapdisplayname, schemaidguid
    foreach ($so in $schemaObjects) {
        $g = [guid] $so.SchemaIdGuid
        $n = $so.LdapDisplayName
        $guidByName[$n] = $g
        $nameByGuid[$g] = $n
    }

    $extendedRights = @{}
    $erObjects = Get-ADObject -SearchBase "CN=Extended-Rights,$($rootDse.configurationNamingContext)" `
                              -LDAPFilter '(objectClass=controlAccessRight)' `
                              -Properties cn, appliesTo, rightsGuid, validAccesses
    foreach ($er in $erObjects) {
        $entry = [PSCustomObject] @{
            Name          = $er.cn
            AppliesTo     = $er.appliesTo
            RightsGuid    = [guid] $er.rightsGuid
            ValidAccesses = $er.validAccesses
        }
        $extendedRights[$er.cn] = $entry
        $nameByGuid[[guid] $er.rightsGuid] = $er.cn
    }

    # The well-known property-set extended rights (validAccesses includes
    # property read/write bits, not just ControlAccess). The old code
    # listed these explicitly; keep that list for stability.
    $propertySetNames = @(
        'DNS-Host-Name-Attributes'
        'Domain-Other-Parameters'
        'Domain-Password'
        'Email-Information'
        'General-Information'
        'Membership'
        'MS-TS-GatewayAccess'
        'Personal-Information'
        'Private-Information'
        'Public-Information'
        'RAS-Information'
        'Terminal-Server-License-Server'
        'User-Account-Restrictions'
        'User-Logon'
        'Web-Information'
        'Exchange-Information'
        'Exchange-Personal-Information'
    )

    $propertySetGuids = @{}
    foreach ($n in $propertySetNames) {
        if ($extendedRights.ContainsKey($n)) {
            $propertySetGuids[[guid] $extendedRights[$n].RightsGuid] = $n
        }
    }

    $Script:AdkSchema = [PSCustomObject] @{
        RootDse          = $rootDse
        DomainDn         = (Get-ADDomain).DistinguishedName
        GuidByName       = $guidByName
        NameByGuid       = $nameByGuid
        ExtendedRights   = $extendedRights
        PropertySetGuids = $propertySetGuids
    }

    return $Script:AdkSchema
}

function Get-AdkSchema {
    [CmdletBinding()]
    param()

    if (-not $Script:AdkSchema) {
        return (Initialize-AdkSchema)
    }
    return $Script:AdkSchema
}

function Get-AdkClassGuid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LdapClassName
    )

    $schema = Get-AdkSchema
    if (-not $schema.GuidByName.ContainsKey($LdapClassName)) {
        throw "Unknown LDAP class name: [$LdapClassName]"
    }
    return $schema.GuidByName[$LdapClassName]
}

function Get-AdkAttributeGuid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $AttributeName
    )

    $schema = Get-AdkSchema
    if (-not $schema.GuidByName.ContainsKey($AttributeName)) {
        throw "Unknown attribute name: [$AttributeName]"
    }
    return $schema.GuidByName[$AttributeName]
}

function Get-AdkExtendedRightGuid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $RightName
    )

    $schema = Get-AdkSchema
    if (-not $schema.ExtendedRights.ContainsKey($RightName)) {
        throw "Unknown extended right name: [$RightName]"
    }
    return [guid] $schema.ExtendedRights[$RightName].RightsGuid
}

# Returns $true when the supplied GUID identifies a property-set extended
# right (one of the well-known sets listed in $propertySetNames above).
# Used by Set-AdAce to decide whether an ExtendedRight-typed delegation
# should be built with PropertySetAccessRule (property read/write) or
# ExtendedRightAccessRule (control access).
function Test-AdkIsPropertySet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid] $Guid
    )
    $schema = Get-AdkSchema
    return $schema.PropertySetGuids.ContainsKey($Guid)
}