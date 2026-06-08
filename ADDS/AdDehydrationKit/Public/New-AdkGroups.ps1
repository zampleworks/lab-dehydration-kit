# Create the groups described in Groups.csv plus the per-department
# business role groups (e.g. "Role Org Finance Employee") derived from
# the AdventureWorks Department.csv and DeptRoles.csv.
#
# Groups.csv columns: Name;Type;Scope
#   Type drives the destination OU; Scope is Universal/DomainLocal/Global.

function New-AdkGroups {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    Initialize-AdkSchema | Out-Null
    $ouMap = Get-AdkOuMap -DataPath $Context.DataPath

    # Destination OU per group Type. Tokens come straight from
    # OUStructure.csv as written by New-AdkOuTree.
    #
    # DSPermission is special: actual OU depends on the per-row Tier
    # column in Groups.csv. See $tierToPermsOu below.
    $typeToOu = @{
        'Role'         = '%OrgRolesOU%'
        'Permission'   = '%T1PermissionsOU%'
        'ClientGroup'  = '%OrgRolesOU%'
        'DSPermission' = '%T0PermsOU%'   # default; overridden by Tier
        'DSRole'       = '%T0RolesOU%'
        'DSClientGroup'= '%T0RolesOU%'
        'DSServerGroup'= '%T0RolesOU%'
        'OpsServerGroup' = '%T1RolesOU%'
        'Claim'        = '%T0ClaimsOU%'
        'AMA'          = '%T0AmaOU%'
    }

    # Per-Tier perms OU mapping (only used for DSPermission rows).
    # AD-namespace permission groups (whose name carries -AD- or starts
    # Pm-AD-) MUST live in T0 regardless of their target tier; Groups.csv
    # encodes this by storing Tier=T0 for those rows.
    $tierToPermsOu = @{
        'T0' = '%T0PermsOU%'
        'T1' = '%T1PermissionsOU%'
        'EA' = '%EAPermissionsOU%'
    }

    $existingGroups = @{}
    # foreach (not ForEach-Object) - the pipeline form errors under
    # -WhatIf because script blocks don't support -WhatIf binding.
    foreach ($grp in (Get-ADGroup -Filter *)) {
        $existingGroups[$grp.SamAccountName] = $grp
    }

    # ---------- Department-derived business role groups ----------
    # Department names come from the consolidated Employees.csv (one
    # Select-Object -Unique away). DeptRoles.csv gives the suffix list
    # (Management, HR, Employee, Finance, ...).
    $created = 0
    $existed = 0

    $deptRolesCsv = Join-Path $Context.DataPath 'DeptRoles.csv'
    $employeesCsv = Join-Path $Context.DataPath 'Employees.csv'

    if ((Test-Path $deptRolesCsv) -and (Test-Path $employeesCsv)) {
        $deptRoles = Get-Content $deptRolesCsv | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $deptNames = Import-Csv $employeesCsv -Delimiter ';' |
                     Select-Object -ExpandProperty Department -Unique |
                     Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $rolesOu = $ouMap['%OrgRolesOU%']

        Write-AdkLog 'Creating per-department business role groups..' -Step
        $deptArr = @($deptNames)
        $deptIndex = 0
        $deptTotal = $deptArr.Count
        foreach ($deptName in $deptArr) {
            $deptIndex++
            Write-Progress -Id 20 -ParentId 1 -Activity 'Dept role groups' `
                -Status "$deptIndex of $deptTotal : $deptName" `
                -PercentComplete (($deptIndex / [Math]::Max($deptTotal, 1)) * 100)
            foreach ($role in $deptRoles) {
                $gn = "Role-Org-$deptName-$role"
                if ($existingGroups.ContainsKey($gn)) {
                    $existed++
                    continue
                }
                if (-not $PSCmdlet.ShouldProcess($gn, "Create group in $rolesOu")) { continue }
                try {
                    $desc = "Department role: $deptName - $role"
                    $new = New-ADGroup -Name $gn -DisplayName $gn `
                                       -Description $desc `
                                       -GroupCategory Security -GroupScope Global `
                                       -Path $rolesOu -PassThru
                    $existingGroups[$gn] = $new
                    Write-AdkLog "  created [$gn]"
                    $created++
                } catch {
                    Write-AdkLog "  failed creating $gn : $($_.Exception.Message)" -IsError
                }
            }
        }
        Write-Progress -Id 20 -ParentId 1 -Activity 'Dept role groups' -Completed
    }

    # ---------- Groups.csv ----------
    $groupsCsv = Join-Path $Context.DataPath 'Groups.csv'
    if (-not (Test-Path $groupsCsv)) {
        throw "Groups.csv not found at $groupsCsv"
    }

    $groups = Import-Csv $groupsCsv -Delimiter ';' |
              Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }

    Write-AdkLog "Creating $($groups.Count) groups from Groups.csv.." -Step
    $grpIndex = 0
    $grpTotal = $groups.Count
    foreach ($g in $groups) {
        $grpIndex++
        Write-Progress -Id 21 -ParentId 1 -Activity 'Groups.csv' `
            -Status "$grpIndex of $grpTotal : $($g.Name)" `
            -PercentComplete (($grpIndex / [Math]::Max($grpTotal, 1)) * 100)
        if (-not $typeToOu.ContainsKey($g.Type)) {
            Write-AdkLog "  unknown group Type [$($g.Type)] for [$($g.Name)] - skipping" -Warning
            continue
        }

        # DSPermission rows are routed by their Tier column to the right
        # per-tier perms OU. AD-namespace groups are tagged Tier=T0 in the
        # CSV, so they end up in the T0 perms OU automatically.
        if ($g.Type -eq 'DSPermission' -and $g.PSObject.Properties['Tier'] -and $g.Tier) {
            if ($tierToPermsOu.ContainsKey($g.Tier)) {
                $ouToken = $tierToPermsOu[$g.Tier]
            } else {
                Write-AdkLog "  unknown Tier [$($g.Tier)] for [$($g.Name)] - defaulting to T0 perms OU" -Warning
                $ouToken = $tierToPermsOu['T0']
            }
        } else {
            $ouToken = $typeToOu[$g.Type]
        }

        if (-not $ouMap.ContainsKey($ouToken)) {
            Write-AdkLog "  destination OU token [$ouToken] not resolved for group type [$($g.Type)]" -IsError
            continue
        }

        $createIn = $ouMap[$ouToken]
        $name = $g.Name

        if ($existingGroups.ContainsKey($name)) {
            $existed++
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($name, "Create $($g.Scope) group in $createIn")) { continue }
        try {
            $desc = Get-AdkGroupDescription -Name $name
            $params = @{
                Name          = $name
                DisplayName   = $name
                GroupCategory = 'Security'
                GroupScope    = $g.Scope
                Path          = $createIn
                PassThru      = $true
            }
            if ($desc) { $params['Description'] = $desc }
            $new = New-ADGroup @params
            $existingGroups[$name] = $new
            Write-AdkLog "  created [$name]"
            $created++
        } catch {
            Write-AdkLog "  failed creating [$name] : $($_.Exception.Message)" -IsError
        }
    }

    Write-Progress -Id 21 -ParentId 1 -Activity 'Groups.csv' -Completed

    Write-AdkLog "Groups: $created created, $existed already exist" -Success
}