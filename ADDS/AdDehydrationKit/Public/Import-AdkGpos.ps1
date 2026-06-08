# Import the domain-wide GPOs that are NOT tied to a specific app, namely
# the PAW lockdown policies that apply to the PAW-Devices OUs in T0 and
# T1.
#
# Per-app GPOs (T0 SoD <App> Servers / SAW) are handled by New-AdkApp
# during the Invoke-AdkApps phase - see Apps.csv. This cmdlet covers the
# remainder: PAW GPO backups (one per tier).
#
# Migration tables are generated dynamically from each backup's
# Backup.xml (via New-AdkSodMigTable) so backups from any source domain
# are portable without manual template maintenance.

function Import-AdkGpos {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    $gpoPath = $Context.GpoPath
    if (-not $gpoPath) {
        $gpoPath = Join-Path (Split-Path $Context.DataPath) 'gpobackup'
    }
    if (-not (Test-Path $gpoPath)) {
        throw "GPO backup path not found: $gpoPath"
    }

    $ouMap = Get-AdkOuMap -DataPath $Context.DataPath

    # PAW-only matrix. PmGroupPattern is "Pm-<tier>-PAW"; the four SoD
    # suffixes are appended by New-AdkSodMigTable.
    $gpoDefinitions = @(
        @{ Tier='T0'; Ou='%T0PAWDeviceOU%'; BackupGpoBaseName='T0 SoD PAW'; PmGroupPattern='Pm-T0-PAW' }
        @{ Tier='T1'; Ou='%T1PAWOU%';       BackupGpoBaseName='T0 SoD PAW'; PmGroupPattern='Pm-T1-PAW' }
    )

    foreach ($def in $gpoDefinitions) {
        if (-not $ouMap.ContainsKey($def.Ou)) {
            Write-AdkLog "  PAW OU not resolved: $($def.Ou) - skipping $($def.Tier) PAW GPO" -Warning
            continue
        }
        $def.Ou = $ouMap[$def.Ou]
    }

    $forceImport    = [bool]$Context.Force
    $adminName      = if ($Context.BuiltinAdministratorName) { $Context.BuiltinAdministratorName } else { 'Administrator' }
    $localAdminName = if ($Context.LocalAdministratorName)   { $Context.LocalAdministratorName }   else { 'Administrator' }
    $imported = 0
    $existed  = 0
    $linked   = 0

    foreach ($def in $gpoDefinitions) {
        if (-not ($def.Ou -like 'OU=*')) { continue }  # got skipped above

        $gpoName = "$($def.Tier) SoD PAW"

        # -- Existence check (skip unless -Force) ---
        $existing = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if ($existing -and -not $forceImport) {
            Write-AdkLog "  [$gpoName] already exists"
            $existed++
        } else {
            $migPath = Join-Path $gpoPath "$gpoName.migtable"

            # Build migration table dynamically from the backup's own metadata.
            Write-AdkLog "  generating migration table for [$gpoName]" -Step
            New-AdkSodMigTable -GpoBackupPath $gpoPath `
                               -BackupGpoName $def.BackupGpoBaseName `
                               -PmPattern $def.PmGroupPattern `
                               -DomainDnsName $Context.DomainDnsName `
                               -OutputPath $migPath `
                               -BuiltinAdministratorName $adminName `
                               -LocalAdministratorName $localAdminName

            if ($PSCmdlet.ShouldProcess($gpoName, "Import GPO from backup [$($def.BackupGpoBaseName)]")) {
                try {
                    Import-Gpo -BackupGpoName $def.BackupGpoBaseName `
                               -Path $gpoPath `
                               -TargetName $gpoName -CreateIfNeeded `
                               -MigrationTable $migPath | Out-Null
                    Write-AdkLog "  imported GPO [$gpoName]"
                    $imported++
                } catch {
                    Write-AdkLog "  failed importing $gpoName : $($_.Exception.Message)" -Warning
                }
            }
        }

        # Link is idempotent - always ensure it exists.
        if ($PSCmdlet.ShouldProcess($def.Ou, "Link GPO [$gpoName]")) {
            try {
                New-GPLink -Name $gpoName -Target $def.Ou -LinkEnabled Yes | Out-Null
                Write-AdkLog "  linked [$gpoName] -> $($def.Ou)"
                $linked++
            } catch {
                if ($_.Exception.Message -notlike '*already linked*') {
                    Write-AdkLog "  failed linking [$gpoName] to [$($def.Ou)]: $($_.Exception.Message)" -Warning
                }
            }
        }
    }

    Write-AdkLog "SoD GPOs: $imported imported, $existed unchanged, $linked linked" -Success
}
