# Module-level orchestrator. Builds all AD content in canonical step
# order, resolving inter-step dependencies automatically.
#
# Usage (after module import):
#   $ctx = Get-AdkContext -DataPath .\Data -GpoPath .\Gpo\Backups
#   Install-AdkContent -Context $ctx                      # all steps
#   Install-AdkContent -Context $ctx -Step Groups         # single step
#   Install-AdkContent -Context $ctx -Step WmiFilters,SecurityBaselines
#   Install-AdkContent -Context $ctx -SkipStep ServerHardening
#   Install-AdkContent -Context $ctx -Force               # reimport GPOs
#
# Steps always execute in canonical (dependency-safe) order regardless
# of the order they appear in -Step. Dependencies not included in the
# run list are validated against the live directory; unfulfilled deps
# are automatically added.
#
# -Force: GPO and ADMX steps always check for existing content and skip
#   if present. -Force reimports everything from backup, overwriting
#   current settings.
#
# -SkipStep: exclude steps from the run. If a skipped step is a
#   dependency of a requested step, the dependency resolver will NOT
#   auto-add it. The operator accepts responsibility for the
#   prerequisite being satisfied from a prior run.

function Install-AdkContent {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context,

        [ValidateSet(
            'OuTree','Groups','Apps','Users','Memberships','Fgpp',
            'ForestFeatures','Delegations','SodGpos','DefaultPolicies',
            'WmiFilters','AdmxTemplates','SecurityBaselines','DnsReplication',
            'AuthPolicies','DomainHardening','ServerHardening'
        )]
        [string[]] $Step,

        [ValidateSet(
            'OuTree','Groups','Apps','Users','Memberships','Fgpp',
            'ForestFeatures','Delegations','SodGpos','DefaultPolicies',
            'WmiFilters','AdmxTemplates','SecurityBaselines','DnsReplication',
            'AuthPolicies','DomainHardening','ServerHardening'
        )]
        [string[]] $SkipStep,

        [switch] $Force
    )

    # -- WhatIf propagation -----------------------------------------------
    # Many AD/GPO cmdlets do not inherit $WhatIfPreference from the caller
    # because they are binary cmdlets or are in different module scopes.
    # Inject into PSDefaultParameterValues to ensure full coverage.
    $installedWhatIfKeys = @()
    if ($WhatIfPreference) {
        foreach ($pat in @(
            '*-AD*'
            '*-GP*'
            '*-Adk*'
            'Set-ItemProperty'
            'Add-KdsRootKey'
            'Update-LapsADSchema'
            'Set-DnsServerPrimaryZone'
            'Enable-ADAccount'
            'Enable-ADOptionalFeature'
            'Remove-ADGroupMember'
        )) {
            $key = "${pat}:WhatIf"
            if (-not $global:PSDefaultParameterValues.ContainsKey($key)) {
                $global:PSDefaultParameterValues[$key] = $true
                $installedWhatIfKeys += $key
            }
        }
        Write-Host '*** Running with -WhatIf: AD/GPO changes will be reported, not applied ***'
    }

    try {
        # -- Stamp Force on Context so step cmdlets can read $Context.Force --
        if (-not $Context.PSObject.Properties['Force']) {
            $Context | Add-Member -NotePropertyName Force -NotePropertyValue ([bool]$Force)
        } else {
            $Context.Force = [bool]$Force
        }

        # -- Apply LogLevel from Settings.psd1 to the module-scoped logger --
        if ($Context.LogLevel) {
            $script:AdkLogLevel = $Context.LogLevel
        }

        # -- Step registry + dependency resolution ----------------------------
        $registry = Get-AdkStepRegistry

        if ($Step) {
            $plan       = Resolve-AdkStepRunList -RequestedSteps $Step -Context $Context -StepRegistry $registry
            $stepsToRun = $plan.RunList

            if ($plan.Errors.Count -gt 0) {
                $msg  = "Dependency check failed:`n"
                $msg += ($plan.Errors -join "`n")
                throw $msg
            }
        } else {
            $stepsToRun = [string[]]$registry.Keys
            $plan       = @{ AutoAdded = [ordered]@{} }
        }

        # -- Apply -SkipStep filter ------------------------------------------
        if ($SkipStep) {
            # Warn when skipping a step that was auto-added as a dependency.
            if ($plan.AutoAdded.Count -gt 0) {
                foreach ($dep in $plan.AutoAdded.Keys) {
                    if ($dep -in $SkipStep) {
                        Write-Host "  WARNING: Skipping auto-added dependency [$dep] (required by $($plan.AutoAdded[$dep]))" -ForegroundColor Yellow
                    }
                }
            }
            $stepsToRun = [string[]]($stepsToRun | Where-Object { $_ -notin $SkipStep })
        }

        # -- Static data validation ----------------------------------------------
        $dataOk = Test-AdkData -Context $Context
        if (-not $dataOk) {
            throw 'Data validation failed. Fix the errors above before running the deploy.'
        }

        # -- Run plan summary -------------------------------------------------
        Write-Host "AD deploy starting for domain $($Context.DomainDnsName)"
        if ($Force) { Write-Host '  Mode: -Force (GPOs will be reimported from backup)' -ForegroundColor Yellow }
        if ($Step -or $SkipStep) {
            $runLabels = foreach ($s in $registry.Keys) {
                if ($s -in $stepsToRun) { $registry[$s].Label }
            }
            Write-Host "  Steps: $($runLabels -join ', ')"

            if ($SkipStep) {
                $skipLabels = foreach ($s in $SkipStep) {
                    if ($registry.ContainsKey($s)) { $registry[$s].Label }
                }
                Write-Host "  Skipped: $($skipLabels -join ', ')" -ForegroundColor Yellow
            }

            if ($plan.AutoAdded.Count -gt 0) {
                Write-Host '  Auto-added dependency steps:' -ForegroundColor Cyan
                foreach ($dep in $plan.AutoAdded.Keys) {
                    $label      = $registry[$dep].Label
                    $requiredBy = $plan.AutoAdded[$dep]
                    Write-Host "    + $dep ($label) - required by $requiredBy" -ForegroundColor Cyan
                }
            }
        }

        # -- Progress helper --------------------------------------------------
        $totalSteps = @($stepsToRun).Count
        $prog       = @{ Step = 0 }

        # Nested function for progress updates (uses -Id 1).
        # Uses a hashtable so the counter mutates by reference across scopes
        # (Set-Variable -Scope is unreliable in PS 5.1 nested functions).
        function _Progress {
            param([string] $Label)
            $prog.Step++
            Write-Progress -Id 1 -Activity 'AD deploy' `
                -Status "[$($prog.Step)/$totalSteps] $Label" `
                -PercentComplete ([math]::Min(100, [int](($prog.Step / $totalSteps) * 100)))
        }

        # -- Step execution (canonical order) ---------------------------------

        if ('OuTree' -in $stepsToRun) {
            _Progress 'Creating OU tree'
            New-AdkOuTree -Context $Context
        }

        if ('Groups' -in $stepsToRun) {
            _Progress 'Creating groups'
            New-AdkGroups -Context $Context
        }

        if ('Apps' -in $stepsToRun) {
            _Progress 'Provisioning apps from Apps.csv'
            Invoke-AdkApps -Context $Context
        }

        if ('Users' -in $stepsToRun) {
            _Progress 'Creating users'
            New-AdkUsers -Context $Context
        }

        if ('Memberships' -in $stepsToRun) {
            _Progress 'Applying group memberships'
            Set-AdkGroupMembership -Context $Context
        }

        if ('Fgpp' -in $stepsToRun) {
            _Progress 'Fine-grained password policies'
            New-AdkFineGrainedPasswordPolicies -Context $Context
        }

        if ('ForestFeatures' -in $stepsToRun) {
            _Progress 'Forest features (Recycle Bin, KDS, LAPS)'
            Set-AdkForestFeatures -Context $Context
        }

        if ('Delegations' -in $stepsToRun) {
            _Progress 'Applying delegations'
            Reset-AdkBuiltinDelegation
            Initialize-AdkSchema -Force | Out-Null
            Set-AdkDelegation -Context $Context
        }

        if ('SodGpos' -in $stepsToRun) {
            _Progress 'Importing PAW GPOs'
            try {
                Import-AdkGpos -Context $Context
            } catch {
                Write-AdkLog "  PAW GPO import skipped: $($_.Exception.Message)" -Warning
            }
        }

        if ('DefaultPolicies' -in $stepsToRun) {
            _Progress 'Importing default policies'
            Import-AdkDefaultPolicies -Context $Context
        }

        if ('WmiFilters' -in $stepsToRun) {
            _Progress 'Creating WMI filters'
            New-AdkWmiFilters -Context $Context
        }

        if ('AdmxTemplates' -in $stepsToRun) {
            _Progress 'Deploying ADMX templates to Central Store'
            Install-AdkAdmxTemplates -Context $Context
        }

        if ('SecurityBaselines' -in $stepsToRun) {
            _Progress 'Importing security baselines'
            Import-AdkSecurityBaselines -Context $Context
        }

        if ('DnsReplication' -in $stepsToRun) {
            _Progress 'Setting root DNS zone replication'
            Set-AdkDnsReplication -Context $Context
        }

        if ('AuthPolicies' -in $stepsToRun) {
            _Progress 'Creating authentication policies'
            Set-AdkAuthPolicy -Context $Context
        }

        if ('DomainHardening' -in $stepsToRun) {
            _Progress 'Domain-level hardening'
            Reset-AdkBuiltinDelegation
            Set-AdkDomainHardening -Context $Context
        }

        if ('ServerHardening' -in $stepsToRun) {
            _Progress 'Server hardening'
            Set-AdkServerHardening -Context $Context
        }

        Write-Host 'AD deploy complete' -ForegroundColor Green
    } finally {
        # Clean up WhatIf propagation keys
        foreach ($k in $installedWhatIfKeys) {
            $global:PSDefaultParameterValues.Remove($k) | Out-Null
        }
        Write-Progress -Id 1 -Activity 'AD deploy' -Completed
    }
}
