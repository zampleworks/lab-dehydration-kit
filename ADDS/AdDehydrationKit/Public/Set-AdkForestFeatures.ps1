# Enable forest-level features: AD Recycle Bin, KDS root key, and
# Windows LAPS schema extension (if the OS build meets the minimum).
# Finishes by refreshing the module-scoped schema cache.
#
# This cmdlet is self-contained: it re-reads the OS build level so it
# can be run standalone (with -Step ForestFeatures) without the external
# script having done the pre-flight check.

function Set-AdkForestFeatures {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    # -- AD Recycle Bin ---------------------------------------------------
    $bin = Get-ADOptionalFeature 'Recycle Bin Feature'
    if (-not $bin.EnabledScopes -or $bin.EnabledScopes.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess('Recycle Bin Feature', 'Enable AD Optional Feature')) {
            $rbEnabled = $false
            for ($rbAttempt = 1; $rbAttempt -le 5; $rbAttempt++) {
                try {
                    Enable-ADOptionalFeature 'Recycle Bin Feature' `
                        -Scope ForestOrConfigurationSet `
                        -Target (Get-ADForest).RootDomain -Confirm:$false
                    $rbEnabled = $true
                    Write-AdkLog '  AD Recycle Bin enabled'
                    break
                } catch {
                    if ($rbAttempt -ge 5) {
                        throw "Enable Recycle Bin failed after $rbAttempt attempts: $($_.Exception.Message)"
                    }
                    Write-AdkLog "  Recycle Bin enable attempt $rbAttempt failed ($(($_.Exception.Message -split "`n")[0])) - retrying in 10s.." -Warning
                    Start-Sleep -Seconds 10
                }
            }
        }
    } else {
        Write-AdkLog '  AD Recycle Bin already enabled'
    }

    # -- KDS Root Key -----------------------------------------------------
    $existingKdsKeys = @(Get-KdsRootKey -ErrorAction SilentlyContinue)
    if ($existingKdsKeys.Count -gt 0 -and -not $Context.Force) {
        Write-AdkLog "  KDS root key already exists ($($existingKdsKeys.Count) key(s))"
    } else {
        if ($PSCmdlet.ShouldProcess('KDS Root Key', 'Add-KdsRootKey -EffectiveImmediately')) {
            Add-KdsRootKey -EffectiveImmediately | Out-Null
            Write-AdkLog '  KDS root key created'
        }
    }

    # -- Windows LAPS schema extension ------------------------------------
    $_reg     = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $osBuild  = [int]$_reg.CurrentBuildNumber
    $osUBR    = [int]$_reg.UBR

    $lapsOsReady = ($osBuild -ge 26100) -or
                   ($osBuild -eq 20348 -and $osUBR -ge 1668) -or
                   ($osBuild -eq 17763 -and $osUBR -ge 4252)

    if (-not $lapsOsReady) {
        Write-AdkLog "  LAPS skipped: OS build $osBuild.$osUBR does not meet the minimum (Server 2022: 20348.1668, Server 2019: 17763.4252)." -Warning
    } else {
        $lapsModule = Get-Module LAPS -ListAvailable -ErrorAction SilentlyContinue
        if ($lapsModule) {
            if ($PSCmdlet.ShouldProcess('AD Schema', 'Update-LapsADSchema')) {
                try {
                    Import-Module LAPS -ErrorAction Stop
                    Update-LapsADSchema -Confirm:$false
                    Write-AdkLog '  LAPS schema extended'
                } catch {
                    Write-AdkLog "  LAPS schema update failed: $($_.Exception.Message)" -Warning
                }
            }
        } elseif ($osBuild -ge 26100) {
            Write-AdkLog '  LAPS module not found on Server 2025 - verify RSAT-AD-Tools is installed.' -Warning
        } else {
            Write-AdkLog "  LAPS module not found at build $osBuild.$osUBR - verify the cumulative update installed correctly and reboot." -Warning
        }
    }

    # -- Refresh schema cache ---------------------------------------------
    Initialize-AdkSchema -Force | Out-Null

    Write-AdkLog 'Forest features enabled' -Success
}
