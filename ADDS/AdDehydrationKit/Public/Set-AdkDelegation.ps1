# Read Delegations.csv and apply each row by dispatching to the verb
# registry. Two-phase: (1) validate every row resolves, (2) apply.
#
# Delegations.csv columns:
#   RoleName    The Pm- or Role group that receives the ACE
#   OuName      OU token (e.g. %OrgEmployeeAcctsOU%) - may be blank for
#               verbs that target the domain root or a specific object
#               supplied via Parameters
#   Verb        The verb name (must exist in Get-AdkDelegationVerbs)
#   Parameters  Optional 'key=val;key=val' string passed to the verb

function Set-AdkDelegation {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context,

        [string] $DelegationsCsv,

        [switch] $IgnoreMissingRoles
    )

    if ([string]::IsNullOrWhiteSpace($DelegationsCsv)) {
        $DelegationsCsv = Join-Path $Context.DataPath 'Delegations.csv'
    }
    if (-not (Test-Path $DelegationsCsv -PathType Leaf)) {
        throw "Delegations.csv not found at $DelegationsCsv"
    }

    Initialize-AdkSchema | Out-Null

    $verbMap = Get-AdkDelegationVerbs
    $rows    = Import-Csv $DelegationsCsv -Delimiter ';'

    # ---------- Pre-flight validation ----------
    # In -WhatIf mode, missing roles/OUs are likely forward-references to
    # objects that *would* be created by earlier cmdlets in the pipeline
    # (which themselves ran in -WhatIf and didn't actually create
    # anything). Demote those to warnings rather than failing the run.
    $whatIf = [bool] $WhatIfPreference
    Write-AdkLog "Validating $($rows.Count) delegation rows..$(if ($whatIf) { ' (-WhatIf: forward-references noted, not failed)' })" -Step

    $resolved   = @()
    $errors     = New-Object 'System.Collections.Generic.List[string]'
    $skipped    = 0

    foreach ($row in $rows) {
        $verb = $row.Verb
        if ([string]::IsNullOrWhiteSpace($verb) -and $row.PSObject.Properties['Delegation']) {
            # Back-compat with the original column name
            $verb = $row.Delegation
        }
        $roleName = $row.RoleName
        $ouToken  = $row.OuName
        $paramStr = if ($row.PSObject.Properties['Parameters']) { $row.Parameters } else { '' }

        if (-not $verbMap.ContainsKey($verb)) {
            # Unknown verbs are a real authoring error even in -WhatIf - the
            # verb registry doesn't know about it regardless of state.
            $errors.Add("Unknown verb [$verb] (role=$roleName, ou=$ouToken)")
            continue
        }

        # Resolve role group
        $role = $null
        try {
            $role = Get-ADGroup -Identity $roleName -ErrorAction Stop
        } catch {
            if ($whatIf -or $IgnoreMissingRoles) {
                # WhatIf/IgnoreMissingRoles forward-reference; uncolored
                # so it reads as informational, not as a true warning.
                Write-AdkLog "  skip (would apply if group existed): role [$roleName] not found (verb=$verb, ou=$ouToken)"
                $skipped++
                continue
            }
            $errors.Add("Role group not found: [$roleName] (verb=$verb)")
            continue
        }

        # Resolve OU token (may be optional depending on the verb)
        $ouDn = $null
        if (-not [string]::IsNullOrWhiteSpace($ouToken)) {
            try {
                $ouDn = Resolve-AdkOuToken -Token $ouToken -DataPath $Context.DataPath
            } catch {
                if ($whatIf) {
                    Write-AdkLog "  skip (would apply if OU existed): OU token [$ouToken] unresolved (role=$roleName, verb=$verb)"
                    $skipped++
                    continue
                }
                $errors.Add("OU token unresolved: [$ouToken] (role=$roleName, verb=$verb)")
                continue
            }
        } else {
            # Verb-without-OU is allowed (used by GpoEdit which targets a GPO instead)
            $ouDn = $Context.DomainDn
        }

        # Parse parameters
        $params = @{}
        try {
            $params = ConvertFrom-AdkDelegationParameters -ParametersString $paramStr
        } catch {
            $errors.Add("Bad Parameters [$paramStr] (role=$roleName, verb=$verb): $($_.Exception.Message)")
            continue
        }

        $resolved += [PSCustomObject] @{
            Role     = $role
            RoleDn   = $role.DistinguishedName
            OuToken  = $ouToken
            OuDn     = $ouDn
            Verb     = $verb
            Params   = $params
        }
    }

    if ($errors.Count -gt 0) {
        Write-AdkLog "Validation found $($errors.Count) problem(s):" -IsError
        foreach ($e in $errors) {
            Write-AdkLog "  - $e" -IsError
        }
        throw 'Delegation validation failed. Fix the rows above and re-run.'
    }

    if ($skipped -gt 0) {
        Write-AdkLog "$skipped row(s) skipped due to forward references (see notes above)"
    }

    Write-AdkLog "Applying $($resolved.Count) delegations.." -Step
    $delIndex = 0
    $delTotal = $resolved.Count

    # ---------- Apply ----------
    $applied     = 0
    $applyErrors = New-Object 'System.Collections.Generic.List[string]'
    foreach ($r in $resolved) {
        $delIndex++
        Write-Progress -Id 60 -ParentId 1 -Activity 'Delegations' `
            -Status "$delIndex of $delTotal : $($r.Verb) -> $($r.Role.Name)" `
            -PercentComplete (($delIndex / [Math]::Max($delTotal, 1)) * 100)
        $context = "[$($r.Verb)] [$($r.Role.Name)] on [$($r.OuDn)]"

        if (-not $PSCmdlet.ShouldProcess($r.OuDn, "$($r.Verb) for $($r.Role.Name)")) {
            continue
        }

        try {
            & $verbMap[$r.Verb] $r.OuDn $r.RoleDn $r.Params
            $applied++
        } catch {
            $applyErrors.Add("$context : $($_.Exception.Message)")
            Write-AdkLog "  ! $context : $($_.Exception.Message)" -IsError
        }
    }

    Write-Progress -Id 60 -ParentId 1 -Activity 'Delegations' -Completed

    if ($applyErrors.Count -gt 0) {
        Write-AdkLog "$($applyErrors.Count) delegations failed to apply" -IsError
        throw "Delegation apply phase had $($applyErrors.Count) failures (see above)."
    }

    Write-AdkLog "Delegations: $applied applied, $skipped skipped" -Success
}
