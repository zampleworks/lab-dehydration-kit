# Create users:
#   1) Service accounts from ServiceAccounts.csv (Class -> tier-specific OU)
#   2) Employee accounts from the AdventureWorks UserDB
#   3) Admin accounts for every employee whose Department or sam matches
#      Admins.csv (one a<tier>_<sam> per match)
#   4) Standard tier user accounts (<tier>_<sam>) for the same set
#
# Random passwords are generated for every account and appended to
# User-pwd.csv (sibling of the data dir). This file MUST be in
# .gitignore.
#
# Email domains are resolved per user through EmailDomains.csv (optional).
# Resolution order: per-user CSV column -> per-type row -> Default row ->
# DomainDnsName. See _ResolveEmailDomain below.

function New-AdkUsers {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context,

        [int] $PasswordLength = 32,

        # Separate length for admin and tier-user accounts so generated
        # passwords satisfy PSO-TieredAccounts (MinPasswordLength=25).
        # Service accounts and employees use $PasswordLength (32).
        [int] $TierAccountPasswordLength = 25,

        [string] $PasswordFile
    )

    # Retry helper for Enable-ADAccount. On a fresh DC the ACL
    # inheritance (sdprop) may not have propagated to newly-created OUs
    # yet, so the first Enable-ADAccount call can fail with "Access is
    # denied". A short retry with backoff resolves the race.
    function Enable-AdkAccountWithRetry {
        param(
            [Parameter(Mandatory)] $Identity,
            [int] $MaxRetries = 3,
            [int] $DelayMs = 2000
        )
        for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
            try {
                Enable-ADAccount $Identity -ErrorAction Stop
                return
            } catch {
                if ($attempt -eq $MaxRetries) { throw }
                Write-Verbose "  Enable-ADAccount attempt $attempt failed, retrying in ${DelayMs}ms..."
                Start-Sleep -Milliseconds $DelayMs
                $DelayMs *= 2
            }
        }
    }

    Initialize-AdkSchema | Out-Null
    $ouMap = Get-AdkOuMap -DataPath $Context.DataPath

    if ([string]::IsNullOrWhiteSpace($PasswordFile)) {
        $PasswordFile = Join-Path $Context.DataPath '..\User-pwd.csv'
    }
    if (-not (Test-Path $PasswordFile -PathType Leaf)) {
        # Always write the header; we never want this skipped under -WhatIf
        # since the file is internal scaffolding, not an AD mutation.
        'Samaccountname;Password' | Out-File $PasswordFile -Force -WhatIf:$false
    }

    # Tier -> { Admins, StdUsers, SvcAccts }. EA included so adding a tier
    # later is a one-row change (see Phase 4).
    $tierOus = @{
        'T0' = @{
            Admins   = $ouMap['%T0AdminsOU%']
            StdUsers = $ouMap['%T0StdUsersOU%']
            SvcAccts = $ouMap['%T0SvcAcctsOU%']
        }
        'T1' = @{
            Admins   = $ouMap['%T1AdminsOU%']
            StdUsers = $ouMap['%T1StdUsersOU%']
            SvcAccts = $ouMap['%T1SvcAcctsOU%']
        }
    }

    if ($ouMap.ContainsKey('%EAAdminsOU%')) {
        $tierOus['EA'] = @{
            Admins   = $ouMap['%EAAdminsOU%']
            StdUsers = $ouMap['%EAStdUsersOU%']
            SvcAccts = $ouMap['%EASvcAcctsOU%']
        }
    }

    $employeesOu  = $ouMap['%OrgEmployeeAcctsOU%']
    $upnDomain    = $Context.DomainDnsName

    # Email domain resolution. Optional EmailDomains.csv maps user types
    # (Default, Employee, ServiceAccount, Admin, TierUser) to email
    # domains. Resolution order per account:
    #   1. Per-user EmailDomain column in source CSV (Employees/Accounts)
    #   2. Per-type row in EmailDomains.csv
    #   3. Default row in EmailDomains.csv
    #   4. DomainDnsName (when no config exists, all types get this)
    # A type row with empty EmailDomain = no email for that type.
    # A missing type row = fall through to Default / DomainDnsName.
    $emailDomainsCsv = Join-Path $Context.DataPath 'EmailDomains.csv'
    $emailDomains = @{}
    if (Test-Path $emailDomainsCsv) {
        foreach ($edRow in (Import-Csv $emailDomainsCsv -Delimiter ';')) {
            $emailDomains[$edRow.Type] = $edRow.EmailDomain
        }
        Write-AdkLog "  loaded email domain config ($($emailDomains.Count) type mapping(s))" -Step
    }

    # Named with underscore prefix to avoid matching the *-Adk*
    # PSDefaultParameterValues WhatIf pattern from Install-AdkContent.
    # Without CmdletBinding the injected -WhatIf can corrupt the return
    # value in PS 5.1, causing null-method errors downstream.
    function _ResolveEmailDomain {
        param([string] $UserType, [string] $CsvOverride)
        # 1. Per-user CSV column
        if (-not [string]::IsNullOrWhiteSpace($CsvOverride)) { return $CsvOverride }
        # 2. Per-type row
        if ($emailDomains.ContainsKey($UserType)) {
            $val = $emailDomains[$UserType]
            if ([string]::IsNullOrWhiteSpace($val)) { return $null }
            return $val
        }
        # 3. Default row
        if ($emailDomains.ContainsKey('Default')) {
            $val = $emailDomains['Default']
            if ([string]::IsNullOrWhiteSpace($val)) { return $null }
            return $val
        }
        # 4. DomainDnsName fallback
        return $upnDomain
    }

    # foreach (not ForEach-Object) - script-block pipelines error when
    # $WhatIfPreference is active in this scope.
    $existingUsers = @{}
    foreach ($u in (Get-ADUser -Filter *)) {
        $existingUsers[$u.SamAccountName] = $u
    }

    # ---------- Service accounts ----------
    $forceUpdate = [bool]$Context.Force
    $svcCreated = 0
    $svcUpdated = 0
    $svcExisted = 0
    Write-AdkLog 'Creating service accounts..' -Step
    $accountsCsv = Join-Path $Context.DataPath 'ServiceAccounts.csv'
    if (Test-Path $accountsCsv) {
        $svcRows = @(Import-Csv $accountsCsv -Delimiter ';')
        $svcIndex = 0
        $svcTotal = $svcRows.Count
        foreach ($a in $svcRows) {
            $svcIndex++
            Write-Progress -Id 40 -ParentId 1 -Activity 'Service accounts' `
                -Status "$svcIndex of $svcTotal : $($a.Samaccountname)" `
                -PercentComplete (($svcIndex / [Math]::Max($svcTotal, 1)) * 100)
            if (-not $tierOus.ContainsKey($a.Class)) {
                Write-AdkLog "  unknown account Class [$($a.Class)] for [$($a.Samaccountname)] - skipping" -Warning
                continue
            }
            $ou = $tierOus[$a.Class].SvcAccts
            $sam = $a.Samaccountname

            if ($existingUsers.ContainsKey($sam)) {
                if ($forceUpdate) {
                    $eu = Get-ADUser $sam -Properties DisplayName -ErrorAction SilentlyContinue
                    if ($eu) {
                        $setArgs = @{}
                        if ($eu.DisplayName -ne $a.Name) { $setArgs['DisplayName'] = $a.Name }
                        if ($setArgs.Count -gt 0) {
                            if ($PSCmdlet.ShouldProcess($sam, "Update service account properties")) {
                                Set-ADUser $eu @setArgs
                                Write-AdkLog "  updated [$sam]"
                                $svcUpdated++
                            }
                        }
                    }
                }
                $svcExisted++
                continue
            }

            if (-not $PSCmdlet.ShouldProcess($sam, "Create service account in $ou")) { continue }
            try {
                $pwd = New-RandomPassword -Length $PasswordLength
                $sec = ConvertTo-SecureString $pwd -AsPlainText -Force
                $u = New-ADUser -Name $a.Name -DisplayName $a.Name `
                                -SamAccountName $sam -UserPrincipalName "$sam@$upnDomain" `
                                -Path $ou -Enabled $false `
                                -KerberosEncryptionType AES128,AES256 `
                                -AccountNotDelegated $true -Confirm:$false `
                                -AccountPassword $sec -PassThru
            } catch {
                Write-AdkLog "  failed creating service account [$sam] in [$ou]: $($_.Exception.Message)" -IsError
                continue
            }
            try {
                Enable-AdkAccountWithRetry $u
                $existingUsers[$sam] = $u
                "$sam;$pwd" | Out-File $PasswordFile -Append -WhatIf:$false
                Write-AdkLog "  created [$sam]"
                $svcCreated++
            } catch {
                Write-AdkLog "  created [$sam] in [$ou] but FAILED to enable: $($_.Exception.Message)" -IsError
                Write-AdkLog "  account exists but is disabled - enable manually or re-run this step" -Warning
            }
        }
        Write-Progress -Id 40 -ParentId 1 -Activity 'Service accounts' -Completed
        Write-AdkLog "Service accounts: $svcCreated created, $svcUpdated updated, $svcExisted unchanged" -Success
    }

    # ---------- Organisation accounts (Robot / Shared / External) ----------
    $orgCreated = 0
    $orgUpdated = 0
    $orgExisted = 0
    Write-AdkLog 'Creating organisation accounts..' -Step
    $orgAccountsCsv = Join-Path $Context.DataPath 'OrgAccounts.csv'
    if (Test-Path $orgAccountsCsv) {
        $orgTypeOuMap = @{
            'Robot'    = $ouMap['%OrgRobotAcctsOU%']
            'Shared'   = $ouMap['%OrgSharedAcctsOU%']
            'External' = $ouMap['%OrgExternalAcctsOU%']
        }
        $orgTypeRoleMap = @{
            'Robot'    = 'Role-Org-Robot'
            'Shared'   = 'Role-Org-Shared'
            'External' = 'Role-Org-External'
        }

        $orgRows = @(Import-Csv $orgAccountsCsv -Delimiter ';' |
                     Where-Object { -not [string]::IsNullOrWhiteSpace($_.Samaccountname) })
        $orgIndex = 0
        $orgTotal = $orgRows.Count
        foreach ($oa in $orgRows) {
            $orgIndex++
            Write-Progress -Id 43 -ParentId 1 -Activity 'Organisation accounts' `
                -Status "$orgIndex of $orgTotal : $($oa.Samaccountname)" `
                -PercentComplete (($orgIndex / [Math]::Max($orgTotal, 1)) * 100)

            $oType = "$($oa.Type)".Trim()
            if (-not $orgTypeOuMap.ContainsKey($oType)) {
                Write-AdkLog "  unknown Type [$oType] for [$($oa.Samaccountname)] - skipping" -Warning
                continue
            }
            $ou  = $orgTypeOuMap[$oType]
            $sam = $oa.Samaccountname.Trim()
            $fn  = "$($oa.FirstName)".Trim()
            $sn  = "$($oa.LastName)".Trim()
            $disp = if (-not [string]::IsNullOrWhiteSpace($sn)) { "$fn $sn" } else { $fn }
            if ([string]::IsNullOrWhiteSpace($disp)) { $disp = $sam }

            if ($existingUsers.ContainsKey($sam)) {
                if ($forceUpdate) {
                    $eu = Get-ADUser $sam -Properties DisplayName, Description, Office, Company -ErrorAction SilentlyContinue
                    if ($eu) {
                        $setArgs = @{}
                        if ($eu.DisplayName -ne $disp)       { $setArgs['DisplayName'] = $disp }
                        $desc = "$($oa.Description)".Trim()
                        if (-not [string]::IsNullOrWhiteSpace($desc) -and $eu.Description -ne $desc) {
                            $setArgs['Description'] = $desc
                        }
                        $office = "$($oa.Office)".Trim()
                        if (-not [string]::IsNullOrWhiteSpace($office) -and $eu.Office -ne $office) {
                            $setArgs['Office'] = $office
                        }
                        $company = "$($oa.Company)".Trim()
                        if (-not [string]::IsNullOrWhiteSpace($company) -and $eu.Company -ne $company) {
                            $setArgs['Company'] = $company
                        }
                        if ($setArgs.Count -gt 0) {
                            if ($PSCmdlet.ShouldProcess($sam, "Update org account properties ($($setArgs.Keys -join ', '))")) {
                                Set-ADUser $eu @setArgs
                                Write-AdkLog "  updated [$sam] ($($setArgs.Keys -join ', '))"
                                $orgUpdated++
                            }
                        }
                    }
                }
                $orgExisted++
                continue
            }

            if (-not $PSCmdlet.ShouldProcess($sam, "Create $oType account [$disp] in $ou")) { continue }
            try {
                $pwd = New-RandomPassword -Length $PasswordLength
                $sec = ConvertTo-SecureString $pwd -AsPlainText -Force

                $newUserArgs = @{
                    Name                   = $disp
                    DisplayName            = $disp
                    SamAccountName         = $sam
                    UserPrincipalName      = "$sam@$upnDomain"
                    Path                   = $ou
                    Enabled                = $false
                    KerberosEncryptionType = 'AES128','AES256'
                    AccountNotDelegated    = $true
                    Confirm                = $false
                    AccountPassword        = $sec
                    PassThru               = $true
                }
                if (-not [string]::IsNullOrWhiteSpace($fn)) { $newUserArgs.GivenName = $fn }
                if (-not [string]::IsNullOrWhiteSpace($sn)) { $newUserArgs.Surname   = $sn }

                $desc = "$($oa.Description)".Trim()
                if (-not [string]::IsNullOrWhiteSpace($desc)) { $newUserArgs.Description = $desc }

                $office = "$($oa.Office)".Trim()
                if (-not [string]::IsNullOrWhiteSpace($office)) { $newUserArgs.Office = $office }

                $company = "$($oa.Company)".Trim()
                if (-not [string]::IsNullOrWhiteSpace($company)) { $newUserArgs.Company = $company }

                # Manager
                $mgrSam = "$($oa.Manager)".Trim()
                if (-not [string]::IsNullOrWhiteSpace($mgrSam)) {
                    if ($existingUsers.ContainsKey($mgrSam)) {
                        $newUserArgs.Manager = $existingUsers[$mgrSam].DistinguishedName
                    } else {
                        Write-AdkLog "  manager [$mgrSam] not found; will leave manager unset on [$sam]" -Warning
                    }
                }

                $u = New-ADUser @newUserArgs
            } catch {
                Write-AdkLog "  failed creating $oType account [$sam] in [$ou]: $($_.Exception.Message)" -IsError
                continue
            }
            try {
                Enable-AdkAccountWithRetry $u
                $existingUsers[$sam] = $u
                "$sam;$pwd" | Out-File $PasswordFile -Append -WhatIf:$false
                Write-AdkLog "  created [$sam] ($oType)"
                $orgCreated++
            } catch {
                Write-AdkLog "  created [$sam] in [$ou] but FAILED to enable: $($_.Exception.Message)" -IsError
                Write-AdkLog "  account exists but is disabled - enable manually or re-run this step" -Warning
                $existingUsers[$sam] = $u
            }

            # Add to org role group
            $roleGn = $orgTypeRoleMap[$oType]
            try {
                $g = Get-ADGroup $roleGn -Properties members
                if ($g.Members -notcontains $u.DistinguishedName) {
                    if ($PSCmdlet.ShouldProcess($roleGn, "Add member [$sam]")) {
                        Add-ADGroupMember $g -Members $u | Out-Null
                    }
                }
            } catch {
                Write-AdkLog "  could not add [$sam] to [$roleGn]: $($_.Exception.Message)" -Warning
            }
        }
        Write-Progress -Id 43 -ParentId 1 -Activity 'Organisation accounts' -Completed
        Write-AdkLog "Organisation accounts: $orgCreated created, $orgUpdated updated, $orgExisted unchanged" -Success
    }

    # ---------- Employees + admin + tier-user accounts ----------
    # Employees.csv is the pre-joined snapshot of Employee + Person +
    # Department + EmployeeDepartmentHistory. One row per active
    # employee, no join logic required at runtime.
    #
    # Columns: BusinessEntityID;Samaccountname;FirstName;LastName;Initial;Department;Position
    $employees = Import-Csv (Join-Path $Context.DataPath 'Employees.csv') -Delimiter ';'

    $admins = Import-Csv (Join-Path $Context.DataPath 'Admins.csv') -Delimiter ';'
    $adminDeptRows   = $admins | Where-Object { $_.Type -eq 'Dept' }
    $adminPersonRows = $admins | Where-Object { $_.Type -eq 'Person' }

    $adminDeptNames   = @($adminDeptRows   | Select-Object -ExpandProperty Name)
    $adminPersonNames = @($adminPersonRows | Select-Object -ExpandProperty Name)

    # Build the list of (employee-sam, tier, dept) tuples that should
    # get admin + tier-user accounts.
    $adminAccounts = New-Object 'System.Collections.Generic.List[PSObject]'
    foreach ($e in $employees) {
        $sam = $e.Samaccountname

        if ($adminDeptNames -contains $e.Department) {
            $unit = $adminDeptRows | Where-Object { $_.Name -eq $e.Department } | Select-Object -First 1
            $adminAccounts.Add([PSCustomObject] @{
                AccountName      = $sam
                EmployeeTitle    = $e.Position
                Department       = $e.Department
                AdminAccountTier = $unit.Tier
            })
        }

        if ($adminPersonNames -contains $sam) {
            $person = $adminPersonRows | Where-Object { $_.Name -eq $sam } | Select-Object -First 1
            $adminAccounts.Add([PSCustomObject] @{
                AccountName      = $sam
                EmployeeTitle    = $e.Position
                Department       = $e.Department
                AdminAccountTier = $person.Tier
            })
        }
    }

    # ---------- Create employee accounts ----------
    $empCreated = 0
    $empUpdated = 0
    $empExisted = 0
    Write-AdkLog 'Creating employee accounts..' -Step
    $empArr = @($employees)
    $empIndex = 0
    $empTotal = $empArr.Count
    foreach ($e in $empArr) {
        $empIndex++
        Write-Progress -Id 41 -ParentId 1 -Activity 'Employees' `
            -Status "$empIndex of $empTotal : $($e.Samaccountname)" `
            -PercentComplete (($empIndex / [Math]::Max($empTotal, 1)) * 100)
        $fn = "$($e.FirstName)".Trim()
        $sn = "$($e.LastName)".Trim()
        $mn = "$($e.MiddleName)".Trim()
        $initials = "$($e.Initials)".Trim()
        $disp = if (-not [string]::IsNullOrWhiteSpace($mn)) { "$fn $mn $sn" } else { "$fn $sn" }

        $sam = $e.Samaccountname
        $upn = Convert-DiacriticCharacters "$fn.$sn@$upnDomain"
        $deptName = $e.Department

        if ($existingUsers.ContainsKey($sam)) {
            $u = $existingUsers[$sam]
            if ($forceUpdate) {
                $eu = Get-ADUser $sam -Properties DisplayName, Department, Title, GivenName, Surname -ErrorAction SilentlyContinue
                if ($eu) {
                    $setArgs = @{}
                    if ($eu.DisplayName -ne $disp)     { $setArgs['DisplayName'] = $disp }
                    if ($eu.GivenName   -ne $fn)       { $setArgs['GivenName']   = $fn }
                    if ($eu.Surname     -ne $sn)       { $setArgs['Surname']     = $sn }
                    if ($eu.Department  -ne $deptName)  { $setArgs['Department']  = $deptName }
                    if ($eu.Title       -ne $e.Position){ $setArgs['Title']       = $e.Position }
                    if ($setArgs.Count -gt 0) {
                        if ($PSCmdlet.ShouldProcess($sam, "Update employee properties ($($setArgs.Keys -join ', '))")) {
                            Set-ADUser $eu @setArgs
                            Write-AdkLog "  updated [$sam] ($($setArgs.Keys -join ', '))"
                            $empUpdated++
                        }
                    }
                }
            }
            $empExisted++
        } else {
            if (-not $PSCmdlet.ShouldProcess($sam, "Create employee [$disp] in $employeesOu")) {
                # Under -WhatIf, register a stub so the admin/tier-user
                # loops below can resolve the owner without their target
                # employees actually existing.
                $existingUsers[$sam] = [PSCustomObject] @{
                    SamAccountName    = $sam
                    Name              = $disp
                    GivenName         = $fn
                    Surname           = $sn
                    DistinguishedName = "CN=$disp,$employeesOu"
                    UserPrincipalName = $upn
                }
                continue
            }
            try {
                $pwd = New-RandomPassword -Length $PasswordLength
                $sec = ConvertTo-SecureString $pwd -AsPlainText -Force

                # Build splatted arguments so we can omit -Initials and
                # the middleName attribute when they're empty.
                $newUserArgs = @{
                    Name                    = $disp
                    DisplayName             = $disp
                    GivenName               = $fn
                    Surname                 = $sn
                    SamAccountName          = $sam
                    UserPrincipalName       = $upn
                    EmployeeNumber          = $e.BusinessEntityID
                    Department              = $deptName
                    Title                   = $e.Position
                    Path                    = $employeesOu
                    Enabled                 = $false
                    KerberosEncryptionType  = 'AES128','AES256'
                    AccountNotDelegated     = $true
                    Confirm                 = $false
                    AccountPassword         = $sec
                    PassThru                = $true
                }

                if (-not [string]::IsNullOrWhiteSpace($initials)) {
                    # AD initials attribute is capped at 6 chars; trim defensively.
                    $newUserArgs.Initials = $initials.Substring(0, [Math]::Min(6, $initials.Length))
                }

                # middleName and division ride in OtherAttributes - no
                # native New-ADUser parameter for either.
                $other = @{}
                if (-not [string]::IsNullOrWhiteSpace($mn)) {
                    $other['middleName'] = $mn
                }
                $div = if ($e.PSObject.Properties['Division']) { "$($e.Division)".Trim() } else { '' }
                if (-not [string]::IsNullOrWhiteSpace($div)) {
                    $other['division'] = $div
                }
                if ($other.Count -gt 0) {
                    $newUserArgs.OtherAttributes = $other
                }

                # Manager: Employees.csv is sorted by BusinessEntityID so
                # the manager (lower BID by construction in the
                # AdventureWorks hierarchy) is always created before their
                # reports. If they weren't (e.g. earlier row failed), the
                # manager won't be set and a warning is logged.
                $mgrSam = if ($e.PSObject.Properties['Manager']) { "$($e.Manager)".Trim() } else { '' }
                if (-not [string]::IsNullOrWhiteSpace($mgrSam)) {
                    $mgrKey = $mgrSam
                    if ($existingUsers.ContainsKey($mgrKey)) {
                        $newUserArgs.Manager = $existingUsers[$mgrKey].DistinguishedName
                    } else {
                        Write-AdkLog "  manager [$mgrKey] not yet created; will leave manager unset on [$sam]" -Warning
                    }
                }

                $u = New-ADUser @newUserArgs
            } catch {
                Write-AdkLog "  failed creating employee [$sam] [$disp] in [$employeesOu]: $($_.Exception.Message)" -IsError
                continue
            }
            try {
                Enable-AdkAccountWithRetry $u
                "$sam;$pwd" | Out-File $PasswordFile -Append -WhatIf:$false
                $existingUsers[$sam] = $u
                Write-AdkLog "  created [$sam] ($disp)"
                $empCreated++
            } catch {
                Write-AdkLog "  created [$sam] [$disp] in [$employeesOu] but FAILED to enable: $($_.Exception.Message)" -IsError
                Write-AdkLog "  account exists but is disabled - enable manually or re-run this step" -Warning
                $existingUsers[$sam] = $u
            }
        }

        # Add to role groups
        $emplGroupName = 'Role-Org-Employee'
        try {
            $g = Get-ADGroup $emplGroupName -Properties members
            if ($g.Members -notcontains $u.DistinguishedName) {
                if ($PSCmdlet.ShouldProcess($emplGroupName, "Add member [$sam]")) {
                    Add-ADGroupMember $g -Members $u | Out-Null
                }
            }
        } catch {
            Write-AdkLog "  could not add [$sam] to [$emplGroupName]: $($_.Exception.Message)" -Warning
        }

        $deptGroupName = "Role-Org-$deptName-Employee"
        try {
            $g = Get-ADGroup $deptGroupName -Properties members
            if ($g.Members -notcontains $u.DistinguishedName) {
                if ($PSCmdlet.ShouldProcess($deptGroupName, "Add member [$sam]")) {
                    Add-ADGroupMember $g -Members $u | Out-Null
                }
            }
        } catch {
            Write-AdkLog "  could not add [$sam] to dept group [$deptGroupName] : $($_.Exception.Message)" -Warning
        }
    }
    Write-Progress -Id 41 -ParentId 1 -Activity 'Employees' -Completed
    Write-AdkLog "Employees: $empCreated created, $empUpdated updated, $empExisted unchanged" -Success

    # ---------- Admin accounts + tier-user accounts ----------
    # Both admin and tier-user accounts use a hyphen separator
    # (at0-sam / t0-sam). The 'a' prefix on admin accounts is the only
    # thing that distinguishes them in sam form.
    foreach ($mode in @(
        @{ Label = 'admin'      ; Prefix = 'a' ; Sep = '-' ; UseAdminsOu = $true  }
        @{ Label = 'tier-user'  ; Prefix = ''  ; Sep = '-' ; UseAdminsOu = $false }
    )) {
        $modeCreated = 0
        $modeUpdated = 0
        $modeExisted = 0
        Write-AdkLog "Creating $($mode.Label) accounts.." -Step
        $admIndex = 0
        $admTotal = $adminAccounts.Count
        foreach ($a in $adminAccounts) {
            $admIndex++
            Write-Progress -Id 42 -ParentId 1 -Activity "$($mode.Label) accounts" `
                -Status "$admIndex of $admTotal" `
                -PercentComplete (($admIndex / [Math]::Max($admTotal, 1)) * 100)
            $sam0 = $a.AccountName.Substring($a.AccountName.IndexOf('\') + 1)
            $tier = $a.AdminAccountTier
            $owner = $sam0

            if (-not $tierOus.ContainsKey($tier)) {
                Write-AdkLog "  skip [$sam0] - tier [$tier] has no OU configured" -Warning
                continue
            }
            $targetOu = if ($mode.UseAdminsOu) { $tierOus[$tier].Admins } else { $tierOus[$tier].StdUsers }

            if (-not $existingUsers.ContainsKey($owner)) {
                Write-AdkLog "  owner [$owner] not found - skipping" -Warning
                continue
            }
            $ownerAccount = $existingUsers[$owner]

            $newSam = "$($mode.Prefix)$($tier.ToLower())$($mode.Sep)$sam0"
            if ($newSam.Length -gt 15) {
                $old = $newSam
                $newSam = $newSam.Substring(0, 15)
                Write-AdkLog "  $old too long - trimmed to $newSam" -Warning
            }

            if ($existingUsers.ContainsKey($newSam)) {
                if ($forceUpdate) {
                    $disp = "$tier $($mode.Label) $($ownerAccount.Name)"
                    $eu = Get-ADUser $newSam -Properties DisplayName, GivenName, Surname -ErrorAction SilentlyContinue
                    if ($eu) {
                        $setArgs = @{}
                        if ($eu.DisplayName -ne $disp)                  { $setArgs['DisplayName'] = $disp }
                        if ($eu.GivenName   -ne $ownerAccount.GivenName){ $setArgs['GivenName']   = $ownerAccount.GivenName }
                        if ($eu.Surname     -ne $ownerAccount.Surname)  { $setArgs['Surname']     = $ownerAccount.Surname }
                        if ($setArgs.Count -gt 0) {
                            if ($PSCmdlet.ShouldProcess($newSam, "Update $($mode.Label) properties ($($setArgs.Keys -join ', '))")) {
                                Set-ADUser $eu @setArgs
                                Write-AdkLog "  updated [$newSam] ($($setArgs.Keys -join ', '))"
                                $modeUpdated++
                            }
                        }
                    }
                }
                $modeExisted++
                continue
            }

            if (-not $PSCmdlet.ShouldProcess($newSam, "Create $($mode.Label) account in $targetOu")) {
                # Stub the planned account so future lookups (if any)
                # still resolve under -WhatIf.
                $existingUsers[$newSam] = [PSCustomObject] @{
                    SamAccountName    = $newSam
                    DistinguishedName = "CN=$newSam,$targetOu"
                }
                continue
            }
            try {
                $disp = "$tier $($mode.Label) $($ownerAccount.Name)"
                $pwd = New-RandomPassword -Length $TierAccountPasswordLength
                $sec = ConvertTo-SecureString $pwd -AsPlainText -Force
                # Create disabled, then enable separately. On a fresh DC
                # the combined -Enabled $true operation can fail with
                # "Access is denied" before sdprop has propagated the
                # inherited security descriptors to newly-created OUs.
                $new = New-ADUser -Name $disp -SamAccountName $newSam `
                                  -AccountPassword $sec `
                                  -GivenName $ownerAccount.GivenName `
                                  -Surname $ownerAccount.Surname `
                                  -Path $targetOu -DisplayName $disp `
                                  -Enabled $false `
                                  -KerberosEncryptionType AES128,AES256 `
                                  -AccountNotDelegated $true `
                                  -UserPrincipalName "$newSam@$upnDomain" -PassThru
            } catch {
                Write-AdkLog "  failed creating $($mode.Label) [$newSam] for [$owner] in [$targetOu]: $($_.Exception.Message)" -IsError
                continue
            }
            try {
                Enable-AdkAccountWithRetry $new
                "$newSam;$pwd" | Out-File $PasswordFile -Append -WhatIf:$false
                $existingUsers[$newSam] = $new
                Write-AdkLog "  created [$newSam] for [$owner]"
                $modeCreated++
            } catch {
                Write-AdkLog "  created $($mode.Label) [$newSam] for [$owner] in [$targetOu] but FAILED to enable: $($_.Exception.Message)" -IsError
                Write-AdkLog "  account exists but is disabled - enable manually or re-run this step" -Warning
                $existingUsers[$newSam] = $new
            }
        }
        Write-Progress -Id 42 -ParentId 1 -Activity "$($mode.Label) accounts" -Completed
        # Capitalize first letter for summary
        $modeLabel = $mode.Label.Substring(0,1).ToUpper() + $mode.Label.Substring(1)
        Write-AdkLog "$modeLabel accounts: $modeCreated created, $modeUpdated updated, $modeExisted unchanged" -Success
    }

    # ---------- Set email addresses on all user types ----------
    # Resolves email domain per user (CSV column -> type -> Default ->
    # DomainDnsName) and applies EmailAddress to every account in the
    # relevant OUs. Skips users whose email already matches the target.
    # Under -WhatIf the OUs may not exist yet; tolerate partition errors.
    Write-AdkLog 'Setting email addresses..' -Step

    # Build per-user override lookup from source CSV EmailDomain columns.
    $perUserEmailOverride = @{}
    foreach ($emp in $employees) {
        if ($emp.PSObject.Properties['EmailDomain']) {
            $val = "$($emp.EmailDomain)".Trim()
            if (-not [string]::IsNullOrWhiteSpace($val)) {
                $perUserEmailOverride[$emp.Samaccountname] = $val
            }
        }
    }
    if ($svcRows) {
        foreach ($svc in $svcRows) {
            if ($svc.PSObject.Properties['EmailDomain']) {
                $val = "$($svc.EmailDomain)".Trim()
                if (-not [string]::IsNullOrWhiteSpace($val)) {
                    $perUserEmailOverride[$svc.Samaccountname] = $val
                }
            }
        }
    }
    if ($orgRows) {
        foreach ($oa in $orgRows) {
            if ($oa.PSObject.Properties['EmailDomain']) {
                $val = "$($oa.EmailDomain)".Trim()
                if (-not [string]::IsNullOrWhiteSpace($val)) {
                    $perUserEmailOverride[$oa.Samaccountname] = $val
                }
            }
        }
    }

    # Map each user type to the OUs where those accounts live.
    # Employee local part is derived from UPN (firstname.lastname);
    # all other types use SamAccountName as the local part.
    $emailOuMap = @(
        @{ Type = 'Employee';       OUs = @($employeesOu) }
        @{ Type = 'External';       OUs = @($ouMap['%OrgExternalAcctsOU%']) }
        @{ Type = 'Robot';          OUs = @($ouMap['%OrgRobotAcctsOU%']) }
        @{ Type = 'Shared';         OUs = @($ouMap['%OrgSharedAcctsOU%']) }
        @{ Type = 'ServiceAccount'; OUs = @($tierOus.Values | ForEach-Object { $_.SvcAccts }) }
        @{ Type = 'Admin';          OUs = @($tierOus.Values | ForEach-Object { $_.Admins }) }
        @{ Type = 'TierUser';       OUs = @($tierOus.Values | ForEach-Object { $_.StdUsers }) }
    )

    foreach ($mapping in $emailOuMap) {
        foreach ($searchOu in $mapping.OUs) {
            if ([string]::IsNullOrWhiteSpace($searchOu)) { continue }
            try {
                foreach ($eu in (Get-ADUser -Filter * -SearchBase $searchOu `
                            -Properties EmailAddress, UserPrincipalName -ErrorAction Stop)) {
                    $csvOvr = if ($perUserEmailOverride.ContainsKey($eu.SamAccountName)) {
                        $perUserEmailOverride[$eu.SamAccountName]
                    } else { '' }
                    $resolvedDomain = _ResolveEmailDomain -UserType $mapping.Type -CsvOverride $csvOvr
                    if (-not $resolvedDomain) { continue }

                    # Employee UPNs are firstname.lastname@domain; extract
                    # the local part. Other types just use SAM.
                    $upn = $eu.UserPrincipalName
                    $local = if ($upn -and $upn.Contains('@')) {
                        $upn.Substring(0, $upn.IndexOf('@'))
                    } else {
                        $eu.SamAccountName
                    }
                    $targetEmail = "$local@$resolvedDomain"

                    if ($eu.EmailAddress -eq $targetEmail) { continue }
                    if ($PSCmdlet.ShouldProcess($eu.SamAccountName, "Set EmailAddress=$targetEmail")) {
                        Set-ADUser $eu -EmailAddress $targetEmail
                    }
                }
            } catch {
                Write-AdkLog "  could not enumerate users under [$searchOu]: $($_.Exception.Message)" -Warning
            }
        }
    }

    # ---------- Department ownership (managedBy on Role Org groups) ----------
    # Departments.csv lists Name;Division;Head. For each department, set
    # managedBy on every Role Org <Dept> <Suffix> group (Management / HR
    # / Employee / Finance) to the dept head's DN. This is how the org
    # hierarchy is surfaced without an OU-per-department structure.
    $deptCsv = Join-Path $Context.DataPath 'Departments.csv'
    $deptRolesCsv = Join-Path $Context.DataPath 'DeptRoles.csv'
    if ((Test-Path $deptCsv) -and (Test-Path $deptRolesCsv)) {
        $deptRoles = Get-Content $deptRolesCsv | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        # Under -WhatIf the dept role groups and dept-head users were
        # gated by earlier ShouldProcess calls, so neither exists yet.
        # Pre-check each dependency and emit "would set" verbose lines
        # instead of letting Set-ADGroup throw.
        $inWhatIf = $WhatIfPreference
        $gatedSkip = 0
        Write-AdkLog 'Setting managedBy on department role groups..' -Step
        foreach ($d in (Import-Csv $deptCsv -Delimiter ';')) {
            if ([string]::IsNullOrWhiteSpace($d.Head)) { continue }
            $headSam = $d.Head
            $headUser = $existingUsers[$headSam]
            if (-not $headUser) {
                if ($inWhatIf) {
                    Write-Verbose "  [WhatIf] dept [$($d.Name)] head [$headSam] not yet provisioned; would set managedBy on $($deptRoles.Count) role group(s) once it exists"
                    $gatedSkip += $deptRoles.Count
                } else {
                    Write-AdkLog "  dept [$($d.Name)] head [$headSam] not found - skipping" -Warning
                }
                continue
            }
            foreach ($role in $deptRoles) {
                $gn = "Role-Org-$($d.Name)-$role"
                $g = $null
                try { $g = Get-ADGroup -Identity $gn -ErrorAction Stop } catch { }
                if (-not $g) {
                    if ($inWhatIf) {
                        Write-Verbose "  [WhatIf] would set managedBy=$headSam on [$gn] (group not yet provisioned)"
                        $gatedSkip++
                    } else {
                        Write-AdkLog "  could not set managedBy on [$gn]: group not found" -Warning
                    }
                    continue
                }
                if ($PSCmdlet.ShouldProcess($gn, "Set managedBy=$headSam")) {
                    try {
                        Set-ADGroup -Identity $g -ManagedBy $headUser.DistinguishedName -ErrorAction Stop
                    } catch {
                        Write-AdkLog "  could not set managedBy on [$gn]: $($_.Exception.Message)" -Warning
                    }
                }
            }
        }
        if ($inWhatIf -and $gatedSkip -gt 0) {
            # WhatIf-only informational; uncolored to match PowerShell's
            # native "What if:" output style.
            Write-AdkLog "  [WhatIf] $gatedSkip managedBy set(s) skipped because dependencies don't exist under -WhatIf"
        }
    }

    Write-AdkLog 'User creation complete'
}