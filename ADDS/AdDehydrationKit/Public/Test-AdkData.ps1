# Pre-flight validation of CSV cross-references.
#
# Builds the set of all group names and user SAMs that WILL be created
# by the toolkit (from CSVs), then checks that every reference in
# GroupMembers.csv, Delegations.csv, FineGrainedPasswordPolicies.csv,
# Departments.csv, Admins.csv, and Employees.csv points to a known
# name. Auth policy group dependencies (derived from Apps.csv) are
# also validated.
#
# Names not found in CSVs get a targeted AD lookup so that built-in /
# well-known groups pass without being declared. Only names that fail
# both CSV and AD resolution are errors.
#
# Read-only -- no AD mutations. Catches typos, missing declarations,
# and stale references before any changes happen.
#
# Called automatically by Install-AdkContent before step execution.
# Can also be run standalone:
#   $ctx = Get-AdkContext -DataPath .\Data -GpoPath .\Gpo\Backups
#   Test-AdkData -Context $ctx
#
# For offline validation (no AD connectivity required):
#   Test-AdkData -DataPath .\Data

function Test-AdkData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Context')]
        [PSObject] $Context,

        [Parameter(Mandatory, ParameterSetName = 'DataPath')]
        [string] $DataPath
    )

    if ($PSCmdlet.ParameterSetName -eq 'DataPath') {
        if (-not (Test-Path $DataPath -PathType Container)) {
            throw "DataPath not found: $DataPath"
        }
        $dataPath    = (Resolve-Path $DataPath).Path
        $offlineMode = $true
    } else {
        $dataPath    = $Context.DataPath
        $offlineMode = $false
    }

    $errors = [System.Collections.Generic.List[string]]::new()

    # ================================================================
    #  Build the set of ALL names that will be created
    # ================================================================

    $knownGroups = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $knownUsers  = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    # -- Groups.csv --
    $groupsCsv = Join-Path $dataPath 'Groups.csv'
    if (Test-Path $groupsCsv) {
        $csvGroups = Import-Csv $groupsCsv -Delimiter ';' |
                     Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }
        foreach ($g in $csvGroups) { [void]$knownGroups.Add($g.Name) }
    }

    # -- Apps.csv -> enumerate all groups each app creates --
    $appsCsv = Join-Path $dataPath 'Apps.csv'
    if (Test-Path $appsCsv) {
        $apps = Import-Csv $appsCsv -Delimiter ';' |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppName) }

        foreach ($app in $apps) {
            $t = $app.Tier
            $n = $app.AppName
            $hasSaw = $app.HasSaw -eq 'true'
            $hasAma = $app.HasAma -eq 'true'

            # Role groups
            [void]$knownGroups.Add("Adm-$t-$n-Admin")
            [void]$knownGroups.Add("Svc-$t-$n-ServiceAccount")
            if ($hasSaw) { [void]$knownGroups.Add("Adm-$t-$n-User") }

            # AMA groups
            if ($hasAma) {
                [void]$knownGroups.Add("Ama-$t-$n-Admin")
                [void]$knownGroups.Add("Ama-$t-$n-User")
            }

            # Server groups
            foreach ($suffix in @('App Server', 'Mgmt Server', 'Db Server')) {
                [void]$knownGroups.Add("Srv-$t-$n-$suffix")
            }
            if ($hasSaw) { [void]$knownGroups.Add("SAW-$t-$n") }

            # Server Pm groups
            $pmSuffixes = @(
                'InteractiveLogon', 'RdpLogon', 'LocalAdmin', 'ServiceLogon',
                'LapsReadPwd', 'LapsResetPwd', 'LapsDecryptPwd'
            )
            foreach ($s in $pmSuffixes) {
                [void]$knownGroups.Add("Pm-$t-$n-Srv-$s")
            }
            if ($hasSaw) {
                foreach ($s in $pmSuffixes) {
                    [void]$knownGroups.Add("Pm-$t-$n-SAW-$s")
                }
            }

            # AD-namespace Pm groups
            [void]$knownGroups.Add("Pm-AD-$t-$n-JoinComputer")
            [void]$knownGroups.Add("Pm-AD-GPO-Edit-$t-$n-Servers")
            if ($hasSaw) { [void]$knownGroups.Add("Pm-AD-GPO-Edit-$t-$n-SAW") }
        }
    }

    # -- Departments.csv -> known department names --
    $deptsCsv = Join-Path $dataPath 'Departments.csv'
    $departments = @()
    $knownDepartments = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $deptsCsv) {
        $departments = Import-Csv $deptsCsv -Delimiter ';' |
                       Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }
        foreach ($d in $departments) { [void]$knownDepartments.Add($d.Name) }
    }

    # -- DeptRoles.csv x Employees.csv departments -> Role-Org-<Dept>-<Role> --
    $deptRolesCsv = Join-Path $dataPath 'DeptRoles.csv'
    $employeesCsv = Join-Path $dataPath 'Employees.csv'
    $employees    = @()

    if (Test-Path $employeesCsv) {
        $employees = Import-Csv $employeesCsv -Delimiter ';' |
                     Where-Object { -not [string]::IsNullOrWhiteSpace($_.Samaccountname) }
        foreach ($emp in $employees) {
            [void]$knownUsers.Add($emp.Samaccountname)
        }
    }

    if ((Test-Path $deptRolesCsv) -and $employees.Count -gt 0) {
        $deptRoles = Get-Content $deptRolesCsv |
                     Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $deptNames = $employees |
                     Select-Object -ExpandProperty Department -Unique |
                     Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        foreach ($dept in $deptNames) {
            foreach ($role in $deptRoles) {
                [void]$knownGroups.Add("Role-Org-$dept-$role")
            }
        }
    }

    # -- ServiceAccounts.csv -> service account SAMs --
    $accountsCsv = Join-Path $dataPath 'ServiceAccounts.csv'
    if (Test-Path $accountsCsv) {
        $svcAccts = Import-Csv $accountsCsv -Delimiter ';' |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_.Samaccountname) }
        foreach ($sa in $svcAccts) {
            [void]$knownUsers.Add($sa.Samaccountname)
        }
    }

    # -- OrgAccounts.csv -> robot / shared / external account SAMs --
    $orgAccountsCsv = Join-Path $dataPath 'OrgAccounts.csv'
    $orgAccounts    = @()
    if (Test-Path $orgAccountsCsv) {
        $orgAccounts = Import-Csv $orgAccountsCsv -Delimiter ';' |
                       Where-Object { -not [string]::IsNullOrWhiteSpace($_.Samaccountname) }
        foreach ($oa in $orgAccounts) {
            [void]$knownUsers.Add($oa.Samaccountname)
        }
    }

    # -- Admins.csv -> derive tiered admin/user account SAMs --
    $adminsCsv = Join-Path $dataPath 'Admins.csv'
    if ((Test-Path $adminsCsv) -and $employees.Count -gt 0) {
        $adminRows = Import-Csv $adminsCsv -Delimiter ';' |
                     Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }

        $deptRows   = $adminRows | Where-Object { $_.Type -eq 'Dept' }
        $personRows = $adminRows | Where-Object { $_.Type -eq 'Person' }

        # Build list of (SAM, Tier) pairs
        $adminPairs = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($row in $deptRows) {
            $deptEmployees = $employees | Where-Object { $_.Department -eq $row.Name }
            foreach ($emp in $deptEmployees) {
                $adminPairs.Add([PSCustomObject]@{ Sam = $emp.Samaccountname; Tier = $row.Tier })
            }
        }
        foreach ($row in $personRows) {
            $adminPairs.Add([PSCustomObject]@{ Sam = $row.Name; Tier = $row.Tier })
        }

        foreach ($pair in $adminPairs) {
            $sam  = $pair.Sam
            $tier = $pair.Tier.ToLower()
            # Admin account: a<tier>-<sam> (max 15 chars)
            $adminSam = "a$tier-$sam"
            if ($adminSam.Length -gt 15) { $adminSam = $adminSam.Substring(0, 15) }
            [void]$knownUsers.Add($adminSam)
            # Tier-user account: <tier>-<sam> (max 15 chars)
            $userSam = "$tier-$sam"
            if ($userSam.Length -gt 15) { $userSam = $userSam.Substring(0, 15) }
            [void]$knownUsers.Add($userSam)
        }
    }

    # Combined lookup: a name is valid if it's a known group OR a known user
    $knownAll = [System.Collections.Generic.HashSet[string]]::new(
        $knownGroups, [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($u in $knownUsers) { [void]$knownAll.Add($u) }

    # ================================================================
    #  Validate naming: no hyphens in group name components
    # ================================================================
    #  Hyphens are reserved as the separator between group name
    #  components (prefix-tier-scope-class-permission). A name that
    #  becomes part of a group name must not contain hyphens, or the
    #  resulting group names become ambiguous and unparseable.

    # Apps.csv: AppName becomes Adm-<T>-<App>-Admin, Pm-<T>-<App>-Srv-*, etc.
    if ($apps.Count -gt 0) {
        foreach ($app in $apps) {
            if ($app.AppName -match '-') {
                $errors.Add("Apps.csv: AppName [$($app.AppName)] contains a hyphen. Hyphens are reserved as group name component separators (e.g. Adm-$($app.Tier)-$($app.AppName)-Admin becomes ambiguous).")
            }
        }
    }

    # Departments.csv: Name becomes Role-Org-<Dept>-<Role>
    if ($departments.Count -gt 0) {
        foreach ($dept in $departments) {
            if ($dept.Name -match '-') {
                $errors.Add("Departments.csv: Name [$($dept.Name)] contains a hyphen. Hyphens are reserved as group name component separators (e.g. Role-Org-$($dept.Name)-Employee becomes ambiguous).")
            }
        }
    }

    # DeptRoles.csv: each role suffix becomes Role-Org-<Dept>-<Role>
    if ((Test-Path $deptRolesCsv) -and $deptRoles.Count -gt 0) {
        foreach ($role in $deptRoles) {
            if ($role -match '-') {
                $errors.Add("DeptRoles.csv: Role [$role] contains a hyphen. Hyphens are reserved as group name component separators (e.g. Role-Org-Finance-$role becomes ambiguous).")
            }
        }
    }

    # ================================================================
    #  Validate GroupMembers.csv
    # ================================================================
    #  Collect unresolved references instead of immediate errors.
    #  After CSV validation, unresolved names get a targeted AD lookup
    #  so that well-known / built-in groups pass without being in CSVs.

    # Key = unresolved name, Value = list of error messages to emit if it stays unresolved
    $unresolvedGroups = @{}   # names that must be groups
    $unresolvedAll    = @{}   # names that can be groups or users

    $membersCsv = Join-Path $dataPath 'GroupMembers.csv'
    if (Test-Path $membersCsv) {
        $memberRows = Import-Csv $membersCsv -Delimiter ';' |
                      Where-Object { -not [string]::IsNullOrWhiteSpace($_.Member) }

        foreach ($row in $memberRows) {
            $member = $row.Member.Trim()

            # Member can be a user SAM or a group name
            if (-not $knownAll.Contains($member)) {
                $msg = "GroupMembers.csv: Member [$member] is not declared in any data file"
                if (-not $unresolvedAll.ContainsKey($member)) { $unresolvedAll[$member] = [System.Collections.Generic.List[string]]::new() }
                $unresolvedAll[$member].Add($msg)
            }

            # MemberOf is comma-separated group names -- every one must be a known group
            $targets = $row.MemberOf -split ',' | ForEach-Object { $_.Trim() } |
                       Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($target in $targets) {
                if (-not $knownGroups.Contains($target)) {
                    $msg = "GroupMembers.csv: MemberOf [$target] (member: $member) is not a declared group"
                    if (-not $unresolvedGroups.ContainsKey($target)) { $unresolvedGroups[$target] = [System.Collections.Generic.List[string]]::new() }
                    $unresolvedGroups[$target].Add($msg)
                }
            }
        }
    }

    # ================================================================
    #  Validate Delegations.csv
    # ================================================================

    $delegationsCsv = Join-Path $dataPath 'Delegations.csv'
    if (Test-Path $delegationsCsv) {
        $delegationRows = Import-Csv $delegationsCsv -Delimiter ';' |
                          Where-Object { -not [string]::IsNullOrWhiteSpace($_.RoleName) }

        foreach ($row in $delegationRows) {
            $roleName = $row.RoleName.Trim()
            if (-not $knownGroups.Contains($roleName)) {
                $msg = "Delegations.csv: RoleName [$roleName] is not a declared group"
                if (-not $unresolvedGroups.ContainsKey($roleName)) { $unresolvedGroups[$roleName] = [System.Collections.Generic.List[string]]::new() }
                $unresolvedGroups[$roleName].Add($msg)
            }
        }
    }

    # ================================================================
    #  Validate FineGrainedPasswordPolicies.csv
    # ================================================================

    $fgppCsv = Join-Path $dataPath 'FineGrainedPasswordPolicies.csv'
    if (Test-Path $fgppCsv) {
        $fgppRows = Import-Csv $fgppCsv -Delimiter ';' |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }

        foreach ($row in $fgppRows) {
            if ([string]::IsNullOrWhiteSpace($row.AppliesTo)) { continue }
            $targets = $row.AppliesTo -split '\|' | ForEach-Object { $_.Trim() } |
                       Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($target in $targets) {
                if (-not $knownAll.Contains($target)) {
                    $msg = "FineGrainedPasswordPolicies.csv: AppliesTo [$target] (policy: $($row.Name)) is not a declared group or user"
                    if (-not $unresolvedAll.ContainsKey($target)) { $unresolvedAll[$target] = [System.Collections.Generic.List[string]]::new() }
                    $unresolvedAll[$target].Add($msg)
                }
            }
        }
    }

    # ================================================================
    #  Validate AuthPolicy group dependencies (derived from Apps.csv)
    # ================================================================
    #  Set-AdkAuthPolicy resolves these groups at runtime by SID.
    #  Apps with HasAuthPolicy=false are excluded from validation.

    # Filter to apps that want auth policies
    $appsWithAP = @()
    if ($apps.Count -gt 0) {
        $appsWithAP = @($apps | Where-Object {
            -not ($_.PSObject.Properties['HasAuthPolicy'] -and $_.HasAuthPolicy -eq 'false')
        })
    }

    if ($appsWithAP.Count -gt 0) {
        # Tier-level: Claim-SmartCardLogon is always needed
        if (-not $knownGroups.Contains('Claim-SmartCardLogon')) {
            $msg = 'AuthPolicy: Claim-SmartCardLogon is required but not declared'
            if (-not $unresolvedGroups.ContainsKey('Claim-SmartCardLogon')) {
                $unresolvedGroups['Claim-SmartCardLogon'] = [System.Collections.Generic.List[string]]::new()
            }
            $unresolvedGroups['Claim-SmartCardLogon'].Add($msg)
        }

        $authTiers = @($appsWithAP | ForEach-Object { $_.Tier } | Select-Object -Unique)
        foreach ($tier in $authTiers) {
            foreach ($gn in @("PAW-$tier", "Claim-$tier-User")) {
                if (-not $knownGroups.Contains($gn)) {
                    $msg = "AuthPolicy: $gn is required for $tier tier policies but not declared"
                    if (-not $unresolvedGroups.ContainsKey($gn)) {
                        $unresolvedGroups[$gn] = [System.Collections.Generic.List[string]]::new()
                    }
                    $unresolvedGroups[$gn].Add($msg)
                }
            }
        }

        # Per-app groups
        foreach ($app in $appsWithAP) {
            $t = $app.Tier
            $n = $app.AppName
            $hasSaw = $app.HasSaw -eq 'true'
            $needed = @("Adm-$t-$n-Admin", "Srv-$t-$n-Mgmt Server")
            if ($hasSaw) { $needed += @("SAW-$t-$n", "Adm-$t-$n-User") }

            foreach ($gn in $needed) {
                if (-not $knownGroups.Contains($gn)) {
                    $msg = "AuthPolicy: $gn is required for [$t/$n] policies but not declared"
                    if (-not $unresolvedGroups.ContainsKey($gn)) {
                        $unresolvedGroups[$gn] = [System.Collections.Generic.List[string]]::new()
                    }
                    $unresolvedGroups[$gn].Add($msg)
                }
            }
        }
    }

    # ================================================================
    #  Validate AuthPolicies.csv (if present)
    # ================================================================

    $authPoliciesCsv = Join-Path $dataPath 'AuthPolicies.csv'
    if (Test-Path $authPoliciesCsv) {
        $authPolicyRows = Import-Csv $authPoliciesCsv -Delimiter ';' |
                          Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }

        foreach ($row in $authPolicyRows) {
            $apName = $row.Name.Trim()

            # Validate Target
            if ($row.Target.Trim() -notin @('User', 'Computer')) {
                $errors.Add("AuthPolicies.csv: [$apName] Target must be User or Computer, got [$($row.Target)]")
            }

            # Validate Mode
            if (-not [string]::IsNullOrWhiteSpace($row.Mode) -and $row.Mode.Trim() -notin @('Audit', 'Enforce')) {
                $errors.Add("AuthPolicies.csv: [$apName] Mode must be Audit or Enforce, got [$($row.Mode)]")
            }

            # Validate TgtLifetimeMins
            $tgtVal = 0
            if (-not [string]::IsNullOrWhiteSpace($row.TgtLifetimeMins)) {
                if (-not [int]::TryParse($row.TgtLifetimeMins.Trim(), [ref]$tgtVal) -or $tgtVal -le 0) {
                    $errors.Add("AuthPolicies.csv: [$apName] TgtLifetimeMins must be a positive integer, got [$($row.TgtLifetimeMins)]")
                }
            }

            # Validate RollingNTLMSecret
            if (-not [string]::IsNullOrWhiteSpace($row.RollingNTLMSecret) -and $row.RollingNTLMSecret.Trim() -notin @('Required', 'Off')) {
                $errors.Add("AuthPolicies.csv: [$apName] RollingNTLMSecret must be Required, Off, or empty, got [$($row.RollingNTLMSecret)]")
            }

            # Validate group references in AuthCondition (skip _AppDefault rows)
            if ($apName -ne '_AppDefault' -and -not [string]::IsNullOrWhiteSpace($row.AuthCondition)) {
                $condTokens = $row.AuthCondition -split '\s+AND\s+|\s+OR\s+' |
                              ForEach-Object { $_.Trim() } |
                              Where-Object { $_ -and $_ -ne 'SmartCard' }
                foreach ($token in $condTokens) {
                    if (-not $knownGroups.Contains($token)) {
                        $msg = "AuthPolicies.csv: [$apName] AuthCondition group [$token] is not a declared group"
                        if (-not $unresolvedGroups.ContainsKey($token)) {
                            $unresolvedGroups[$token] = [System.Collections.Generic.List[string]]::new()
                        }
                        $unresolvedGroups[$token].Add($msg)
                    }
                }
            }
        }
    }

    # ================================================================
    #  Validate Departments.csv cross-references
    # ================================================================

    if ($departments.Count -gt 0) {
        foreach ($dept in $departments) {
            $head = $dept.Head
            if (-not [string]::IsNullOrWhiteSpace($head) -and -not $knownUsers.Contains($head.Trim())) {
                $errors.Add("Departments.csv: Head [$($head.Trim())] (department: $($dept.Name)) is not a declared employee")
            }
        }
    }

    # ================================================================
    #  Validate Employees.csv cross-references
    # ================================================================

    if ($employees.Count -gt 0) {
        foreach ($emp in $employees) {
            # Department must exist in Departments.csv (if Departments.csv is present)
            if ($knownDepartments.Count -gt 0 -and
                -not [string]::IsNullOrWhiteSpace($emp.Department) -and
                -not $knownDepartments.Contains($emp.Department)) {
                $errors.Add("Employees.csv: Department [$($emp.Department)] (employee: $($emp.Samaccountname)) is not declared in Departments.csv")
            }

            # Manager must be a known employee SAM (if specified)
            $mgr = $emp.Manager
            if (-not [string]::IsNullOrWhiteSpace($mgr) -and -not $knownUsers.Contains($mgr.Trim())) {
                $errors.Add("Employees.csv: Manager [$($mgr.Trim())] (employee: $($emp.Samaccountname)) is not a declared employee")
            }
        }
    }

    # ================================================================
    #  Validate Admins.csv cross-references
    # ================================================================

    $adminsCsvPath = Join-Path $dataPath 'Admins.csv'
    if (Test-Path $adminsCsvPath) {
        $adminValidationRows = Import-Csv $adminsCsvPath -Delimiter ';' |
                               Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }

        foreach ($row in $adminValidationRows) {
            $aName = $row.Name.Trim()
            $aType = $row.Type.Trim()

            if ($aType -eq 'Dept') {
                if ($knownDepartments.Count -gt 0 -and -not $knownDepartments.Contains($aName)) {
                    $errors.Add("Admins.csv: Department [$aName] is not declared in Departments.csv")
                }
            } elseif ($aType -eq 'Person') {
                if (-not $knownUsers.Contains($aName)) {
                    $errors.Add("Admins.csv: Person [$aName] is not a declared employee")
                }
            }
        }
    }

    # ================================================================
    #  Validate OrgAccounts.csv cross-references
    # ================================================================

    if ($orgAccounts.Count -gt 0) {
        $validOrgTypes = @('Robot', 'Shared', 'External')
        foreach ($oa in $orgAccounts) {
            $oaSam  = $oa.Samaccountname.Trim()
            $oaType = "$($oa.Type)".Trim()

            # Type must be Robot, Shared, or External
            if ($oaType -notin $validOrgTypes) {
                $errors.Add("OrgAccounts.csv: Type [$oaType] (account: $oaSam) must be Robot, Shared, or External")
            }

            # Manager must be a known user (if specified)
            $oaMgr = "$($oa.Manager)".Trim()
            if (-not [string]::IsNullOrWhiteSpace($oaMgr) -and -not $knownUsers.Contains($oaMgr)) {
                $errors.Add("OrgAccounts.csv: Manager [$oaMgr] (account: $oaSam) is not a declared user")
            }
        }
    }

    # ================================================================
    #  Resolve unresolved names against live AD
    # ================================================================
    #  Only names actually referenced in the config are queried. This
    #  avoids expensive broad searches and tolerates environments where
    #  some well-known groups have been removed or don't exist.

    $allUnresolved = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $unresolvedGroups.Keys) { [void]$allUnresolved.Add($name) }
    foreach ($name in $unresolvedAll.Keys)    { [void]$allUnresolved.Add($name) }

    if ($allUnresolved.Count -gt 0 -and -not $offlineMode) {
        foreach ($name in $allUnresolved) {
            # Try resolving by SAM -- covers built-in groups, prior-run objects, etc.
            try {
                $obj = Get-ADObject -Filter "SamAccountName -eq '$($name -replace "'","''")'" `
                           -Properties objectClass -ErrorAction Stop |
                       Select-Object -First 1
                if ($obj) {
                    if ($obj.objectClass -eq 'group') {
                        [void]$knownGroups.Add($name)
                        [void]$knownAll.Add($name)
                    } else {
                        # Exists but not a group -- satisfies "any object" references
                        [void]$knownAll.Add($name)
                    }
                }
            } catch {
                # AD query failed -- name stays unresolved
            }
        }
    } elseif ($allUnresolved.Count -gt 0 -and $offlineMode) {
        Write-AdkLog "  $($allUnresolved.Count) name(s) could not be resolved offline (built-in groups require AD connectivity)" -Warning
    }

    # Anything still unresolved after the AD check is a real error
    foreach ($name in $unresolvedGroups.Keys) {
        if (-not $knownGroups.Contains($name)) {
            foreach ($msg in $unresolvedGroups[$name]) { $errors.Add($msg) }
        }
    }
    foreach ($name in $unresolvedAll.Keys) {
        if (-not $knownAll.Contains($name)) {
            foreach ($msg in $unresolvedAll[$name]) { $errors.Add($msg) }
        }
    }

    # ================================================================
    #  Report results
    # ================================================================

    if ($errors.Count -eq 0) {
        $mode = if ($offlineMode) { 'offline' } else { 'online' }
        Write-AdkLog "Data validation passed ($mode; $($knownGroups.Count) groups, $($knownUsers.Count) users declared)" -Success
        return $true
    }

    Write-AdkLog "Data validation found $($errors.Count) error(s):" -IsError
    foreach ($err in $errors) {
        Write-AdkLog "  $err" -IsError
    }
    return $false
}
