# Create or update Fine-Grained Password Policies (PSOs) from
# FineGrainedPasswordPolicies.csv and apply them to the listed groups.
#
# Column reference:
#   Name                          - PSO name in AD
#   Precedence                    - integer; lower = higher priority when
#                                   multiple PSOs apply to the same account
#   MinPasswordLength             - minimum number of characters
#   PasswordHistoryCount          - number of previous passwords remembered
#   ComplexityEnabled             - true/false
#   ReversibleEncryptionEnabled   - true/false (should be false)
#   MinPasswordAgeDays            - 0 = no minimum (allows immediate change)
#   MaxPasswordAgeDays            - 0 = never expires
#   LockoutThreshold              - 0 = lockout disabled
#   LockoutObservationWindowMinutes - observation window for bad-password count
#   LockoutDurationMinutes        - 0 = admin must manually unlock
#   AppliesTo                     - pipe-separated group or user SAM names
#
# The function is idempotent: existing PSOs are updated if any setting
# differs; subjects already attached are left alone.

function New-AdkFineGrainedPasswordPolicies {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    $csvPath = Join-Path $Context.DataPath 'FineGrainedPasswordPolicies.csv'
    if (-not (Test-Path $csvPath -PathType Leaf)) {
        Write-AdkLog '  FineGrainedPasswordPolicies.csv not found - skipping' -Warning
        return
    }

    $policies = @(Import-Csv $csvPath -Delimiter ';' |
                  Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) })

    if ($policies.Count -eq 0) {
        Write-AdkLog '  FineGrainedPasswordPolicies.csv is empty' -Step
        return
    }

    $forceUpdate = [bool]$Context.Force
    $created  = 0
    $updated  = 0
    $upToDate = 0

    foreach ($p in $policies) {
        $name             = $p.Name.Trim()
        $precedence       = [int]$p.Precedence
        $minLen           = [int]$p.MinPasswordLength
        $history          = [int]$p.PasswordHistoryCount
        $complexity       = $p.ComplexityEnabled.Trim() -eq 'true'
        $reversible       = $p.ReversibleEncryptionEnabled.Trim() -eq 'true'
        $minAgeDays       = [int]$p.MinPasswordAgeDays
        $maxAgeDays       = [int]$p.MaxPasswordAgeDays
        $lockoutThreshold = [int]$p.LockoutThreshold
        $lockoutWindowMin = [int]$p.LockoutObservationWindowMinutes
        $lockoutDurMin    = [int]$p.LockoutDurationMinutes

        $minAge          = [TimeSpan]::FromDays($minAgeDays)
        $maxAge          = [TimeSpan]::FromDays($maxAgeDays)   # 0 = never expires
        $lockoutWindow   = [TimeSpan]::FromMinutes($lockoutWindowMin)
        $lockoutDuration = [TimeSpan]::FromMinutes($lockoutDurMin)   # 0 = admin unlock

        # Properties used for both New- and Set-
        $psoProps = @{
            Precedence                  = $precedence
            MinPasswordLength           = $minLen
            PasswordHistoryCount        = $history
            ComplexityEnabled           = $complexity
            ReversibleEncryptionEnabled = $reversible
            MinPasswordAge              = $minAge
            MaxPasswordAge              = $maxAge
            LockoutThreshold            = $lockoutThreshold
            LockoutObservationWindow    = $lockoutWindow
            LockoutDuration             = $lockoutDuration
        }

        $existing = Get-ADFineGrainedPasswordPolicy `
                        -Filter "Name -eq '$name'" `
                        -ErrorAction SilentlyContinue

        if ($existing) {
            # Compare each property; MaxPasswordAge=0 (never) may round-trip
            # as a large negative interval in AD, so normalise to Ticks <= 0.
            $maxAgeMatch = if ($maxAgeDays -eq 0) {
                $existing.MaxPasswordAge.Ticks -le 0
            } else {
                $existing.MaxPasswordAge -eq $maxAge
            }

            $dirty = (
                $existing.Precedence                  -ne $precedence       -or
                $existing.MinPasswordLength           -ne $minLen           -or
                $existing.PasswordHistoryCount        -ne $history          -or
                $existing.ComplexityEnabled           -ne $complexity       -or
                $existing.ReversibleEncryptionEnabled -ne $reversible       -or
                $existing.MinPasswordAge              -ne $minAge           -or
                (-not $maxAgeMatch)                                          -or
                $existing.LockoutThreshold            -ne $lockoutThreshold -or
                $existing.LockoutObservationWindow    -ne $lockoutWindow    -or
                $existing.LockoutDuration             -ne $lockoutDuration
            )

            if ($dirty -and $forceUpdate) {
                if ($PSCmdlet.ShouldProcess($name, 'Update fine-grained password policy')) {
                    Set-ADFineGrainedPasswordPolicy -Identity $existing @psoProps
                    Write-AdkLog "  updated PSO [$name]"
                    $updated++
                }
            } else {
                Write-AdkLog "  PSO [$name] up to date" -Step
                $upToDate++
            }
        } else {
            if ($PSCmdlet.ShouldProcess($name, 'Create fine-grained password policy')) {
                $existing = New-ADFineGrainedPasswordPolicy -Name $name @psoProps -PassThru
                Write-AdkLog "  created PSO [$name]"
                $created++
            }
        }

        # -- Attach subjects (groups or users) --------------------------------
        $desiredSubjects = @(
            $p.AppliesTo -split '\|' |
            ForEach-Object { $_.Trim() } |
            Where-Object   { $_ }
        )
        if ($desiredSubjects.Count -eq 0) { continue }

        # Re-fetch if we just created or updated - existing may be stale.
        $pso = Get-ADFineGrainedPasswordPolicy `
                   -Filter "Name -eq '$name'" `
                   -ErrorAction SilentlyContinue
        if (-not $pso) { continue }

        $currentSams = @(
            Get-ADFineGrainedPasswordPolicySubject -Identity $pso -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty SamAccountName
        )

        foreach ($sam in $desiredSubjects) {
            if ($currentSams -contains $sam) {
                Write-AdkLog "  [$name] -> [$sam] already applied" -Step
                continue
            }

            # Try group first, then user
            $principal = Get-ADGroup -Filter "SamAccountName -eq '$sam'" `
                                     -ErrorAction SilentlyContinue
            if (-not $principal) {
                $principal = Get-ADUser -Filter "SamAccountName -eq '$sam'" `
                                        -ErrorAction SilentlyContinue
            }
            if (-not $principal) {
                if ($WhatIfPreference) {
                    Write-AdkLog "  subject [$sam] not yet present (expected under -WhatIf)" -Step
                } else {
                    throw "FGPP failed: subject [$sam] not found in AD (policy: $name). Check FineGrainedPasswordPolicies.csv or run Groups/Users steps first."
                }
                continue
            }

            if ($PSCmdlet.ShouldProcess($sam, "Apply PSO [$name]")) {
                try {
                    Add-ADFineGrainedPasswordPolicySubject -Identity $pso -Subjects $principal
                    Write-AdkLog "  applied [$name] -> [$sam]" -Step
                } catch {
                    Write-AdkLog "  failed applying [$name] -> [$sam]: $($_.Exception.Message)" -Warning
                }
            }
        }
    }

    Write-AdkLog "Fine-grained password policies: $created created, $updated updated, $upToDate up to date" -Success
}
