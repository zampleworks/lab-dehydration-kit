# Create Authentication Policies driven by AuthPolicies.csv and Apps.csv.
#
# AuthPolicies.csv (optional) defines:
#   _AppDefault rows  - set defaults (TGT, mode, RollingNTLMSecret) for
#                       per-app generated policies
#   Named rows        - explicit general policies with AuthCondition
#
# When AuthPolicies.csv is absent, the function falls back to the
# original hardcoded tier-level PAW device policies.
#
# Per-app policies are always derived from Apps.csv using structural
# SDDL patterns. Apps with HasAuthPolicy=false are skipped.
#
# AuthCondition syntax (resolved by ConvertTo-AdkAuthSddl):
#   GroupName           single group membership
#   SmartCard           shorthand for Claim-SmartCardLogon
#   A AND B             both required
#   A OR B              either suffices
#   SmartCard AND A OR B    SmartCard AND (A or B)
#
# All policies are created with ProtectedFromAccidentalDeletion.
# Mode=Audit (default) or Mode=Enforce controls the enforcement flag.
#
# Under -WhatIf the source groups may not exist yet, so missing groups
# are tolerated and the affected policies are skipped with a log line.

function Set-AdkAuthPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    # -- Defaults for app-generated policies --------------------------------
    $appDefaults = @{
        User     = @{ Tgt = 240; Mode = 'Audit'; Rolling = 'Required' }
        Computer = @{ Tgt = 240; Mode = 'Audit'; Rolling = '' }
    }

    $forceUpdate = [bool]$Context.Force
    $defs = [System.Collections.Generic.List[hashtable]]::new()

    # -- Load AuthPolicies.csv (optional) -----------------------------------
    $authCsvPath = Join-Path $Context.DataPath 'AuthPolicies.csv'
    $hasAuthCsv  = Test-Path $authCsvPath -PathType Leaf

    if ($hasAuthCsv) {
        $authRows = @(Import-Csv $authCsvPath -Delimiter ';' |
                      Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) })

        # Override defaults from _AppDefault rows
        foreach ($row in ($authRows | Where-Object { $_.Name -eq '_AppDefault' })) {
            $target = $row.Target.Trim()
            if ($appDefaults.ContainsKey($target)) {
                if (-not [string]::IsNullOrWhiteSpace($row.TgtLifetimeMins)) {
                    $appDefaults[$target].Tgt = [int]$row.TgtLifetimeMins
                }
                if (-not [string]::IsNullOrWhiteSpace($row.Mode)) {
                    $appDefaults[$target].Mode = $row.Mode.Trim()
                }
                if (-not [string]::IsNullOrWhiteSpace($row.RollingNTLMSecret)) {
                    $appDefaults[$target].Rolling = $row.RollingNTLMSecret.Trim()
                }
            }
        }

        # Build defs from general (non-default) rows
        foreach ($row in ($authRows | Where-Object { $_.Name -ne '_AppDefault' })) {
            $name = $row.Name.Trim()
            $target = $row.Target.Trim()
            $cond = $row.AuthCondition
            $tgt  = if (-not [string]::IsNullOrWhiteSpace($row.TgtLifetimeMins)) { [int]$row.TgtLifetimeMins } else { $appDefaults[$target].Tgt }
            $mode = if (-not [string]::IsNullOrWhiteSpace($row.Mode)) { $row.Mode.Trim() } else { 'Audit' }
            $roll = if (-not [string]::IsNullOrWhiteSpace($row.RollingNTLMSecret)) { $row.RollingNTLMSecret.Trim() } else { '' }

            if ([string]::IsNullOrWhiteSpace($cond)) {
                Write-AdkLog "  [$name] has no AuthCondition; skipping" -Warning
                continue
            }

            $sddl = ConvertTo-AdkAuthSddl -AuthCondition $cond.Trim()
            if (-not $sddl) { continue }

            $d = @{
                Name    = $name
                Target  = $target
                Tgt     = $tgt
                Mode    = $mode
                Rolling = $roll
            }
            if ($target -eq 'Computer') { $d.AuthTo = $sddl }
            else { $d.AuthFrom = $sddl }
            $defs.Add($d)
        }
    }

    # -- Load Apps.csv for per-app policies ----------------------------------
    $apps = @()
    $appsCsvPath = Join-Path $Context.DataPath 'Apps.csv'
    if (Test-Path $appsCsvPath -PathType Leaf) {
        $apps = @(Import-Csv $appsCsvPath -Delimiter ';' |
                  Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppName) })
    }

    if ($apps.Count -eq 0 -and $defs.Count -eq 0) {
        Write-AdkLog 'Auth policies skipped: no AuthPolicies.csv general policies and no Apps.csv' -Warning
        return
    }

    # -- Resolve tier-level SIDs (needed for per-app policies) ---------------
    $claimScSid = $null
    $tierSids   = @{}

    # Filter to apps that actually want auth policies
    $appsWithAP = @($apps | Where-Object {
        -not ($_.PSObject.Properties['HasAuthPolicy'] -and $_.HasAuthPolicy -eq 'false')
    })

    if ($appsWithAP.Count -gt 0) {
        try {
            $claimScSid = (Get-ADGroup 'Claim-SmartCardLogon' -ErrorAction Stop).SID.Value
        } catch {
            if ($WhatIfPreference) {
                Write-AdkLog 'Per-app auth policies skipped: Claim-SmartCardLogon not yet present (expected under -WhatIf).'
                $appsWithAP = @()
            } else {
                throw 'Auth policies failed: Claim-SmartCardLogon not found. Run Groups step first or check Groups.csv.'
            }
        }

        $tiers = @($appsWithAP | ForEach-Object { $_.Tier } | Select-Object -Unique)
        foreach ($tier in $tiers) {
            $missing = @()
            $pawSid = $null; $claimUserSid = $null
            try { $pawSid       = (Get-ADGroup "PAW-$tier" -ErrorAction Stop).SID.Value }       catch { $missing += "PAW-$tier" }
            try { $claimUserSid = (Get-ADGroup "Claim-$tier-User" -ErrorAction Stop).SID.Value } catch { $missing += "Claim-$tier-User" }

            if ($missing.Count -gt 0) {
                if ($WhatIfPreference) {
                    Write-AdkLog "  $tier tier skipped: [$($missing -join ', ')] not yet present (expected under -WhatIf)."
                    continue
                }
                throw "Auth policies failed: [$($missing -join ', ')] not found. Run Groups step first or check Groups.csv."
            }
            $tierSids[$tier] = @{ PAW = $pawSid; ClaimUser = $claimUserSid }
        }

        # Legacy: generate tier-level PAW device policies if no AuthPolicies.csv
        if (-not $hasAuthCsv -and $claimScSid) {
            foreach ($tier in $tierSids.Keys) {
                $tg = $tierSids[$tier]
                $defs.Add(@{
                    Name    = "AP-$tier-Device-PAW"
                    AuthTo  = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID($claimScSid)}) && (Member_of {SID($($tg.ClaimUser))})))"
                    Target  = 'Computer'
                    Tgt     = $appDefaults['Computer'].Tgt
                    Mode    = $appDefaults['Computer'].Mode
                    Rolling = ''
                })
            }
        }
    }

    # -- Per-app policies ----------------------------------------------------
    foreach ($app in $appsWithAP) {
        $tier    = $app.Tier
        $appName = $app.AppName
        $hasSaw  = $app.HasSaw -eq 'true'

        if (-not $tierSids.ContainsKey($tier)) { continue }
        $tg = $tierSids[$tier]

        # Resolve per-app group SIDs
        $missing = @()
        $sids = @{}
        $groupsNeeded = @("Adm-$tier-$appName-Admin", "Srv-$tier-$appName-Mgmt Server")
        if ($hasSaw) { $groupsNeeded += @("SAW-$tier-$appName", "Adm-$tier-$appName-User") }

        foreach ($gn in $groupsNeeded) {
            try { $sids[$gn] = (Get-ADGroup $gn -ErrorAction Stop).SID.Value }
            catch { $missing += $gn }
        }

        if ($missing.Count -gt 0) {
            if ($WhatIfPreference) {
                Write-AdkLog "  [$tier/$appName] skipped: [$($missing -join ', ')] not yet present (expected under -WhatIf)."
                continue
            }
            throw "Auth policies failed: [$($missing -join ', ')] not found for app [$appName]. Run Apps step first or check data files."
        }

        $adminSid = $sids["Adm-$tier-$appName-Admin"]
        $mgmtSid  = $sids["Srv-$tier-$appName-Mgmt Server"]
        $ud = $appDefaults['User']
        $cd = $appDefaults['Computer']

        # User-Admin: admin accounts may only auth from SAW or Mgmt servers
        if ($hasSaw) {
            $sawSid = $sids["SAW-$tier-$appName"]
            $adminAuthFrom = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID($sawSid), SID($mgmtSid)}))"
        } else {
            $adminAuthFrom = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID($mgmtSid)}))"
        }
        $defs.Add(@{
            Name     = "AP-$tier-$appName-User-Admin"
            AuthFrom = $adminAuthFrom
            Target   = 'User'
            Tgt      = $ud.Tgt
            Mode     = $ud.Mode
            Rolling  = $ud.Rolling
        })

        # Srv: servers only accept smart-card admins
        $defs.Add(@{
            Name    = "AP-$tier-$appName-Srv"
            AuthTo  = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID($claimScSid)}) && (Member_of {SID($adminSid)})))"
            Target  = 'Computer'
            Tgt     = $cd.Tgt
            Mode    = $cd.Mode
            Rolling = ''
        })

        if ($hasSaw) {
            $userSid = $sids["Adm-$tier-$appName-User"]

            # User-Std: user accounts may only auth from PAW or SAW
            $defs.Add(@{
                Name     = "AP-$tier-$appName-User-Std"
                AuthFrom = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID($($tg.PAW)), SID($sawSid)}))"
                Target   = 'User'
                Tgt      = $ud.Tgt
                Mode     = $ud.Mode
                Rolling  = $ud.Rolling
            })

            # Srv-SAW: SAW accepts smart-card admins or users
            $defs.Add(@{
                Name    = "AP-$tier-$appName-Srv-SAW"
                AuthTo  = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID($claimScSid)}) && (Member_of_any {SID($adminSid), SID($userSid)})))"
                Target  = 'Computer'
                Tgt     = $cd.Tgt
                Mode    = $cd.Mode
                Rolling = ''
            })
        }
    }

    if ($defs.Count -eq 0) {
        Write-AdkLog 'Auth policies: no policies to create' -Step
        return
    }

    # -- Create / update policies --------------------------------------------
    $created = 0
    $updated = 0
    $existed = 0

    foreach ($d in $defs) {
        $existing = Get-ADAuthenticationPolicy -Filter "Name -eq '$($d.Name)'" `
                        -Properties 'ComputerAllowedToAuthenticateTo','UserAllowedToAuthenticateFrom','UserTGTLifetimeMins','ComputerTGTLifetimeMins' `
                        -ErrorAction SilentlyContinue

        if ($existing) {
            if (-not $forceUpdate) {
                $existed++
                continue
            }

            $dirty = $false
            if ($d.Target -eq 'Computer') {
                if ($existing.ComputerAllowedToAuthenticateTo -ne $d.AuthTo -or
                    $existing.ComputerTGTLifetimeMins -ne $d.Tgt) { $dirty = $true }
            } else {
                if ($existing.UserAllowedToAuthenticateFrom -ne $d.AuthFrom -or
                    $existing.UserTGTLifetimeMins -ne $d.Tgt) { $dirty = $true }
            }

            if ($dirty) {
                if ($PSCmdlet.ShouldProcess($d.Name, 'Update authentication policy')) {
                    $setArgs = @{ Identity = $d.Name }
                    if ($d.Target -eq 'Computer') {
                        $setArgs['ComputerAllowedToAuthenticateTo'] = $d.AuthTo
                        $setArgs['ComputerTGTLifetimeMins']         = $d.Tgt
                    } else {
                        $setArgs['UserAllowedToAuthenticateFrom'] = $d.AuthFrom
                        $setArgs['UserTGTLifetimeMins']           = $d.Tgt
                    }
                    if ($d.Mode -eq 'Enforce') { $setArgs['Enforce'] = $true }
                    Set-ADAuthenticationPolicy @setArgs
                    Write-AdkLog "  updated [$($d.Name)]"
                    $updated++
                }
            } else {
                Write-AdkLog "  [$($d.Name)] up to date" -Step
                $existed++
            }
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($d.Name, 'Create AD Authentication Policy')) { continue }

        $newArgs = @{
            Name                            = $d.Name
            ProtectedFromAccidentalDeletion = $true
        }
        if ($d.Mode -eq 'Enforce') { $newArgs['Enforce'] = $true }

        if ($d.Target -eq 'Computer') {
            $newArgs['ComputerAllowedToAuthenticateTo'] = $d.AuthTo
            $newArgs['ComputerTGTLifetimeMins']         = $d.Tgt
        } else {
            $newArgs['UserAllowedToAuthenticateFrom'] = $d.AuthFrom
            $newArgs['UserTGTLifetimeMins']           = $d.Tgt
            if ($d.Rolling -eq 'Required') {
                $newArgs['RollingNTLMSecret'] = 'Required'
            }
        }

        New-ADAuthenticationPolicy @newArgs | Out-Null
        Write-AdkLog "  created [$($d.Name)]"
        $created++
    }

    Write-AdkLog "Auth policies: $created created, $updated updated, $existed unchanged" -Success
}
