# LAPS verbs. Cover both legacy LAPS (ms-Mcs-Adm*) and Windows LAPS
# (msLAPS-*). The verbs detect which schema attributes are present.
#
# LapsReadPwd      Read the clear-text password attribute.
# LapsResetPwd     Force a password reset by writing the expiration time.
# LapsDecryptPwd   Read the encrypted password attribute (Windows LAPS only;
#                  decryption requires the AD-stored DPAPI key access).

function _LapsAttrs {
    $schema = Get-AdkSchema
    $attrs = [PSCustomObject] @{
        Pwd       = $null  # plaintext (legacy: ms-Mcs-AdmPwd; modern: msLAPS-Password)
        ExpTime   = $null  # exp (legacy: ms-Mcs-AdmPwdExpirationTime; modern: msLAPS-PasswordExpirationTime)
        EncPwd    = $null  # encrypted (Windows LAPS only: msLAPS-EncryptedPassword)
        IsModern  = $false
    }

    if ($schema.GuidByName.ContainsKey('msLAPS-Password')) {
        $attrs.IsModern = $true
        $attrs.Pwd     = Get-AdkAttributeGuid -AttributeName 'msLAPS-Password'
        $attrs.ExpTime = Get-AdkAttributeGuid -AttributeName 'msLAPS-PasswordExpirationTime'
        if ($schema.GuidByName.ContainsKey('msLAPS-EncryptedPassword')) {
            $attrs.EncPwd = Get-AdkAttributeGuid -AttributeName 'msLAPS-EncryptedPassword'
        }
    } elseif ($schema.GuidByName.ContainsKey('ms-Mcs-AdmPwd')) {
        $attrs.Pwd     = Get-AdkAttributeGuid -AttributeName 'ms-Mcs-AdmPwd'
        $attrs.ExpTime = Get-AdkAttributeGuid -AttributeName 'ms-Mcs-AdmPwdExpirationTime'
    }

    return $attrs
}

function Set-Verb-LapsReadPwd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'Descendents' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $attrs = _LapsAttrs
    if (-not $attrs.Pwd) {
        Write-AdkLog '  LAPS schema not present; skipping LapsReadPwd' -Warning
        return
    }
    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'

    # Read on the plaintext password attribute
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) `
              -ObjectType $attrs.Pwd `
              -InheritanceType $inh -InheritObjectType $computerClass

    # Also grant Control_Access for the All-Extended-Rights (this is what
    # the LAPS UI requires to actually surface the password). Without it,
    # the read-property grant is filtered out by AD's confidentiality flag.
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ObjectType $attrs.Pwd `
              -InheritanceType $inh -InheritObjectType $computerClass
}

function Set-Verb-LapsResetPwd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'Descendents' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $attrs = _LapsAttrs
    if (-not $attrs.ExpTime) {
        Write-AdkLog '  LAPS schema not present; skipping LapsResetPwd' -Warning
        return
    }
    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $attrs.ExpTime `
              -InheritanceType $inh -InheritObjectType $computerClass
}

function Set-Verb-LapsDecryptPwd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'Descendents' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $attrs = _LapsAttrs
    if (-not $attrs.IsModern -or -not $attrs.EncPwd) {
        Write-AdkLog '  Windows LAPS (encrypted) schema not present; skipping LapsDecryptPwd' -Warning
        return
    }
    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) `
              -ObjectType $attrs.EncPwd `
              -InheritanceType $inh -InheritObjectType $computerClass

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ObjectType $attrs.EncPwd `
              -InheritanceType $inh -InheritObjectType $computerClass
}
