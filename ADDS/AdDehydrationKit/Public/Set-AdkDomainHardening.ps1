# Domain-level hardening for a freshly-promoted AD forest.
# Run once per forest (not per DC).
#
# Groups:
#   - Clears membership of Pre-Windows 2000 Compatible Access (anonymous enumeration risk).
#   - Strips AdminCount from operator groups (Account/Print/Backup/Server Operators)
#     so sdprop does not lock out helpdesk from managing those accounts.
#   - Empties Schema Admins if the LAPS schema has been applied (Schema Admins should
#     be populated on demand and emptied immediately afterwards).
#
# Domain:
#   - Sets ms-DS-MachineAccountQuota to 0 (non-admins cannot join computers).
#   - Redirects the default Users and Computers containers to the OUs defined by
#     %NewUsersOU% and %NewComputersOU% in OUStructure.csv.
#
# Directory Service:
#   - dSHeuristics position 7 = '0'   (block anonymous LDAP; existing positions preserved)
#
# Caller is responsible for calling Reset-AdkBuiltinDelegation separately before
# invoking this cmdlet if delegation reset is also needed.

function Set-AdkDomainHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    # -- Read hardening toggles from context (Settings.psd1) ----------------
    $h = if ($Context.Hardening) { $Context.Hardening } else { @{} }

    # ------------------------------------------------------------------ #
    # Groups: Pre-Windows 2000 Compatible Access + operator AdminCount
    # ------------------------------------------------------------------ #
    if ($h.ClearPreWin2000 -ne $false) {
        Write-AdkLog 'Clearing Pre-Windows 2000 Compatible Access membership..'
        Set-ADGroup 'Pre-Windows 2000 Compatible Access' -Clear member -Confirm:$false
    } else { Write-AdkLog 'Skipping ClearPreWin2000 (disabled in Settings.psd1)' }

    if ($h.ClearBuiltinGroupsAdminCount -ne $false) {
        Write-AdkLog 'Clearing AdminCount on built-in operator groups..'
        foreach ($g in @('Account Operators', 'Print Operators', 'Backup Operators', 'Server Operators')) {
            Set-ADGroup $g -Clear AdminCount
        }
    } else { Write-AdkLog 'Skipping ClearBuiltinGroupsAdminCount (disabled in Settings.psd1)' }

    # ------------------------------------------------------------------ #
    # Domain: MachineAccountQuota
    # ------------------------------------------------------------------ #
    $dom = Get-ADDomain
    if ($h.ZeroMachineAccountQuota -ne $false) {
        Write-AdkLog 'Setting ms-DS-MachineAccountQuota = 0..'
        Set-ADDomain -Identity $dom -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }
    } else { Write-AdkLog 'Skipping ZeroMachineAccountQuota (disabled in Settings.psd1)' }

    # ------------------------------------------------------------------ #
    # Container redirect (redirusr / redircmp)
    # ------------------------------------------------------------------ #
    if ($h.RedirectDefaultContainers -eq $false) {
        Write-AdkLog 'Skipping RedirectDefaultContainers (disabled in Settings.psd1)'
    } else {
    Write-AdkLog 'Redirecting default user/computer containers..'
    $ouCsvPath = Join-Path $Context.DataPath 'OUStructure.csv'
    $ouMap     = @{}
    if (Test-Path $ouCsvPath -PathType Leaf) {
        foreach ($row in (Import-Csv $ouCsvPath -Delimiter ';')) {
            if (-not [string]::IsNullOrWhiteSpace($row.Name) -and
                -not [string]::IsNullOrWhiteSpace($row.DN)) {
                $ouMap[$row.Name] = $row.DN
            }
        }
    }
    foreach ($pair in @(
        @{ Token = '%NewUsersOU%';     Tool = 'redirusr.exe' }
        @{ Token = '%NewComputersOU%'; Tool = 'redircmp.exe' }
    )) {
        if (-not $ouMap.ContainsKey($pair.Token)) {
            Write-Verbose "  $($pair.Token) not found in OUStructure.csv - skipping $($pair.Tool)"
            continue
        }
        $dn = $ouMap[$pair.Token]
        if (-not $PSCmdlet.ShouldProcess($dn, "Run $($pair.Tool) to redirect default container")) { continue }
        try {
            & $pair.Tool $dn | Out-Null
            Write-Verbose "  $($pair.Tool) -> $dn"
        } catch {
            Write-AdkLog "Failed to run $($pair.Tool): $($_.Exception.Message)" -Warning
        }
    }
    } # end RedirectDefaultContainers

    # ------------------------------------------------------------------ #
    # Schema Admins: empty after LAPS schema applied
    # Always detect from live AD - does not depend on whether the
    # ForestFeatures step ran in this session.
    # ------------------------------------------------------------------ #
    if ($h.EmptySchemaAdmins -ne $false) {
        $schemaCtx         = (Get-ADRootDSE).schemaNamingContext
        $lapsSchemaApplied = $null -ne (Get-ADObject `
            -Filter "lDAPDisplayName -eq 'msLAPS-PasswordExpirationTime'" `
            -SearchBase $schemaCtx -ErrorAction SilentlyContinue)

        if ($lapsSchemaApplied) {
            Write-AdkLog 'Emptying Schema Admins (LAPS schema confirmed applied)..'
            try {
                $schemaAdmins = Get-ADGroup 'Schema Admins' -Properties members
                foreach ($m in $schemaAdmins.Members) {
                    if ($PSCmdlet.ShouldProcess('Schema Admins', "Remove member [$m]")) {
                        Remove-ADGroupMember 'Schema Admins' -Members $m -Confirm:$false
                    }
                }
                Write-AdkLog 'Schema Admins membership cleared. Re-populate manually before any future schema change.' -Warning
            } catch {
                Write-AdkLog "Could not empty Schema Admins: $($_.Exception.Message)" -Warning
            }
        } else {
            Write-AdkLog 'Schema Admins NOT emptied (LAPS schema extension not detected). Empty manually after applying LAPS schema.' -Warning
        }
    } else { Write-AdkLog 'Skipping EmptySchemaAdmins (disabled in Settings.psd1)' }

    # ------------------------------------------------------------------ #
    # dSHeuristics - forest-wide Directory Service behaviour flags.
    # Each character position controls a specific feature. Existing
    # characters at other positions are preserved; absent positions
    # default to '0' (same as not set).
    #
    # Configurable positions (via Settings.psd1 -> Hardening.DsHeuristics):
    #   BlockAnonLdap           -> Position  7 (index  6)
    #   EnforceOwnerCheck       -> Position 28 (index 27) CVE-2021-42291
    #   EnforceAddAttributeAuth -> Position 29 (index 28) CVE-2021-42291
    #
    # Sentinel positions (10, 20) are always auto-set when the string
    # is long enough; do not override them in settings.
    # ------------------------------------------------------------------ #
    $dsH = $h.DsHeuristics
    if (-not $dsH -or $dsH -isnot [hashtable]) {
        Write-AdkLog 'Skipping dSHeuristics (no DsHeuristics table in Settings.psd1)'
    } else {
    Write-AdkLog 'Configuring dSHeuristics..'
    $configNC = (Get-ADRootDSE).configurationNamingContext
    $dsSvcDn  = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
    $dsObj    = Get-ADObject $dsSvcDn -Properties dSHeuristics
    $current  = if ([string]::IsNullOrEmpty($dsObj.dSHeuristics)) { '' } else { $dsObj.dSHeuristics }
    $padded   = $current.PadRight(29, '0')
    $arr      = $padded.ToCharArray()

    # Map friendly names to (0-based index, value).
    $posMap = @{
        BlockAnonLdap           = 6    # position  7
        EnforceOwnerCheck       = 27   # position 28
        EnforceAddAttributeAuth = 28   # position 29
    }
    foreach ($name in $posMap.Keys) {
        $idx = $posMap[$name]
        $val = $dsH[$name]
        if ($null -ne $val -and $val -ne '') {
            if ($arr[$idx] -ne [char]$val) {
                Write-AdkLog "  dSHeuristics position $($idx + 1) ($name): '$($arr[$idx])' -> '$val'" -Step
            }
            $arr[$idx] = [char]$val
        }
    }

    # Required sentinels when the string extends past these lengths.
    $arr[9]  = '1'   # position 10: sentinel for string >= 10 chars
    $arr[19] = '2'   # position 20: sentinel for string >= 20 chars

    $newDsH = -join $arr
    if ($newDsH -ne $current) {
        if ($PSCmdlet.ShouldProcess($dsSvcDn, "Set dSHeuristics [$newDsH]")) {
            Set-ADObject $dsSvcDn -Replace @{ dSHeuristics = $newDsH }
            Write-AdkLog "  dSHeuristics: [$current] -> [$newDsH]" -Warning
        }
    } else {
        Write-AdkLog "  dSHeuristics already correct [$current]"
    }
    } # end DsHeuristics

    # ------------------------------------------------------------------ #
    # Admin accounts: AccountNotDelegated (cannot be delegated)
    # ------------------------------------------------------------------ #
    # Prevents Kerberos delegation from impersonating admin accounts.
    # Covers built-in Administrator and all accounts in tiered admin OUs.
    if ($h.EnforceAccountNotDelegated -eq $false) {
        Write-AdkLog 'Skipping EnforceAccountNotDelegated (disabled in Settings.psd1)'
    } else {
    Write-AdkLog 'Enforcing AccountNotDelegated on admin accounts..'

    # Built-in Administrator (RID 500)
    $adminSid = "$($dom.DomainSID)-500"
    $builtinAdmin = Get-ADUser -Identity $adminSid -Properties AccountNotDelegated
    if (-not $builtinAdmin.AccountNotDelegated) {
        if ($PSCmdlet.ShouldProcess($builtinAdmin.SamAccountName, 'Set AccountNotDelegated')) {
            Set-ADUser $builtinAdmin -AccountNotDelegated $true
            Write-AdkLog "  $($builtinAdmin.SamAccountName): set AccountNotDelegated" -Warning
        }
    }

    # All users in tiered admin OUs
    $ouMap = Get-AdkOuMap -DataPath $Context.DataPath
    $adminOuTokens = @('%T0AdminsOU%', '%T1AdminsOU%', '%EAAdminsOU%')
    $fixedCount = 0
    $checkedCount = 0
    foreach ($token in $adminOuTokens) {
        if (-not $ouMap.ContainsKey($token)) {
            Write-AdkLog "  $token not found in OU map -- skipping" -Warning
            continue
        }
        $ouDn = $ouMap[$token]
        try { [void](Get-ADObject -Identity $ouDn -ErrorAction Stop) }
        catch {
            Write-AdkLog "  $token ($ouDn) does not exist yet -- skipping" -Warning
            continue
        }
        try {
            $users = @(Get-ADUser -SearchBase $ouDn -SearchScope OneLevel `
                         -Filter * -Properties AccountNotDelegated -ErrorAction Stop)
        } catch {
            Write-AdkLog "  Failed to query $token ($ouDn): $($_.Exception.Message)" -IsError
            continue
        }
        foreach ($u in $users) {
            $checkedCount++
            if (-not $u.AccountNotDelegated) {
                if ($PSCmdlet.ShouldProcess($u.SamAccountName, 'Set AccountNotDelegated')) {
                    Set-ADUser $u -AccountNotDelegated $true
                    $fixedCount++
                }
            }
        }
    }
    if ($fixedCount -gt 0) {
        Write-AdkLog "  Set AccountNotDelegated on $fixedCount of $checkedCount admin accounts" -Warning
    } elseif ($checkedCount -eq 0) {
        Write-AdkLog "  No admin accounts found in admin OUs" -Warning
    } else {
        Write-AdkLog "  All $checkedCount admin accounts already protected"
    }
    } # end EnforceAccountNotDelegated

    # ------------------------------------------------------------------ #
    # Service accounts: enforce AES Kerberos encryption
    # ------------------------------------------------------------------ #
    # msDS-SupportedEncryptionTypes = 24 (0x18) enables AES128 + AES256.
    # New-AdkUsers sets this at creation via -KerberosEncryptionType, but
    # this sweep catches accounts created before the flag was enforced or
    # modified manually (e.g. RC4 re-enabled for troubleshooting).
    if ($h.EnforceAesEncryption -eq $false) {
        Write-AdkLog 'Skipping EnforceAesEncryption (disabled in Settings.psd1)'
    } else {
    Write-AdkLog 'Enforcing AES encryption types on service accounts..'
    $svcOuTokens = @('%T0SvcAcctsOU%', '%T1SvcAcctsOU%', '%EASvcAcctsOU%')
    $aesDesired  = 0x18   # AES128_HMAC_SHA1 + AES256_HMAC_SHA1
    $aesFixed    = 0
    $aesChecked  = 0
    foreach ($token in $svcOuTokens) {
        if (-not $ouMap.ContainsKey($token)) {
            Write-AdkLog "  $token not found in OU map -- skipping" -Warning
            continue
        }
        $ouDn = $ouMap[$token]
        try { [void](Get-ADObject -Identity $ouDn -ErrorAction Stop) }
        catch {
            Write-AdkLog "  $token ($ouDn) does not exist yet -- skipping" -Warning
            continue
        }
        try {
            $svcUsers = @(Get-ADUser -SearchBase $ouDn -SearchScope OneLevel `
                             -Filter * -Properties 'msDS-SupportedEncryptionTypes' -ErrorAction Stop)
        } catch {
            Write-AdkLog "  Failed to query $token ($ouDn): $($_.Exception.Message)" -IsError
            continue
        }
        foreach ($u in $svcUsers) {
            $aesChecked++
            $curEnc = $u.'msDS-SupportedEncryptionTypes'
            if ($null -eq $curEnc -or $curEnc -ne $aesDesired) {
                if ($PSCmdlet.ShouldProcess($u.SamAccountName, "Set msDS-SupportedEncryptionTypes = $aesDesired")) {
                    Set-ADUser $u -Replace @{ 'msDS-SupportedEncryptionTypes' = $aesDesired }
                    $aesFixed++
                }
            }
        }
    }
    if ($aesFixed -gt 0) {
        Write-AdkLog "  Set AES encryption on $aesFixed of $aesChecked service accounts" -Warning
    } elseif ($aesChecked -eq 0) {
        Write-AdkLog "  No service accounts found in service account OUs" -Warning
    } else {
        Write-AdkLog "  All $aesChecked service accounts already have AES encryption"
    }
    } # end EnforceAesEncryption

    # ------------------------------------------------------------------ #
    # krbtgt: reset password to update pwdLastSet timestamp
    # ------------------------------------------------------------------ #
    # In a freshly promoted forest the krbtgt password dates from dcpromo.
    # Resetting it sets pwdLastSet to now, avoiding audit tool false
    # positives for stale krbtgt credentials.
    if ($h.ResetKrbtgt -eq $false) {
        Write-AdkLog 'Skipping ResetKrbtgt (disabled in Settings.psd1)'
    } else {
    Write-AdkLog 'Resetting krbtgt password..'
    try {
        $krbtgt = Get-ADUser 'krbtgt' -Properties PasswordLastSet
        $oldPwdSet = $krbtgt.PasswordLastSet
        if ($PSCmdlet.ShouldProcess('krbtgt', 'Reset password')) {
            $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $bytes = New-Object byte[] 64
            $rng.GetBytes($bytes)
            $rng.Dispose()
            $newPwd = ConvertTo-SecureString ([Convert]::ToBase64String($bytes)) -AsPlainText -Force
            Set-ADAccountPassword -Identity 'krbtgt' -Reset -NewPassword $newPwd
            Write-AdkLog "  krbtgt password reset (was last set: $oldPwdSet)" -Warning
        }
    } catch {
        Write-AdkLog "  Failed to reset krbtgt password: $($_.Exception.Message)" -IsError
    }
    } # end ResetKrbtgt

    # ------------------------------------------------------------------ #
    # Domain Controllers OU: accidental deletion protection
    # ------------------------------------------------------------------ #
    if ($h.ProtectDcOu -eq $false) {
        Write-AdkLog 'Skipping ProtectDcOu (disabled in Settings.psd1)'
    } else {
    Write-AdkLog 'Protecting Domain Controllers OU from accidental deletion..'
    $dcOu = Get-ADOrganizationalUnit -Identity "OU=Domain Controllers,$($dom.DistinguishedName)"
    $acl  = Get-Acl "AD:\$($dcOu.DistinguishedName)"
    $denyDeleteRule = $acl.Access | Where-Object {
        $_.AccessControlType -eq 'Deny' -and
        $_.ActiveDirectoryRights -match 'DeleteTree|Delete' -and
        $_.IdentityReference -eq 'Everyone'
    }
    if (-not $denyDeleteRule) {
        if ($PSCmdlet.ShouldProcess($dcOu.DistinguishedName, 'Enable accidental deletion protection')) {
            Set-ADOrganizationalUnit $dcOu.DistinguishedName -ProtectedFromAccidentalDeletion $true
            Write-AdkLog '  Enabled accidental deletion protection on Domain Controllers OU' -Warning
        }
    } else {
        Write-AdkLog '  Domain Controllers OU already protected'
    }
    } # end ProtectDcOu

    Write-AdkLog 'Domain hardening complete.' -Success
}
