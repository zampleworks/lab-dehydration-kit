# Import the Default Domain Policy and Default Domain Controllers Policy
# from the GPO backup store, then set their link order to lowest
# precedence (order 999) so that baseline and tool-specific GPOs always
# override them when settings conflict.

function Import-AdkDefaultPolicies {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    $gpoBackupRoot = $Context.GpoPath
    if (-not $gpoBackupRoot -or -not (Test-Path $gpoBackupRoot -PathType Container)) {
        Write-AdkLog '  No GPO backup path configured; skipping default policy import.' -Warning
        return
    }

    # -- Import from backup -----------------------------------------------
    $forceImport = [bool]$Context.Force
    $adkStamp    = '[ADK-imported]'

    foreach ($g in @('Default Domain Controllers Policy', 'Default Domain Policy')) {
        $gpo = Get-GPO -Name $g -ErrorAction SilentlyContinue
        if ($gpo -and $gpo.Description -like "*$adkStamp*" -and -not $forceImport) {
            Write-AdkLog "  [$g] already imported by ADK"
            continue
        }

        if ($PSCmdlet.ShouldProcess($g, 'Import GPO from backup')) {
            try {
                Import-Gpo -BackupGpoName $g -Path $gpoBackupRoot -TargetName $g | Out-Null
                # Stamp the GPO so subsequent runs can detect the import.
                $gpo = Get-GPO -Name $g
                if ($gpo.Description -notlike "*$adkStamp*") {
                    $gpo.Description = if ($gpo.Description) { "$($gpo.Description) $adkStamp" } else { $adkStamp }
                }
                Write-AdkLog "  imported [$g]"
            } catch {
                Write-AdkLog "  failed importing [$g]: $($_.Exception.Message)" -Warning
            }
        }
    }

    # -- Set link order to lowest precedence ------------------------------
    # Order 999 = last position regardless of how many other GPOs are
    # linked. This ensures baseline and tool-specific GPOs always override
    # the default policies when there are setting conflicts.
    $dom   = Get-ADDomain
    $dcOu  = $dom.DomainControllersContainer
    $domDn = $dom.DistinguishedName

    foreach ($pair in @(
        @{ Name = 'Default Domain Controllers Policy'; Target = $dcOu }
        @{ Name = 'Default Domain Policy';             Target = $domDn }
    )) {
        if ($PSCmdlet.ShouldProcess($pair.Target, "Set GPO link order for [$($pair.Name)]")) {
            try {
                Set-GPLink -Name $pair.Name -Target $pair.Target -Order 999 `
                           -ErrorAction SilentlyContinue | Out-Null
                Write-AdkLog "  [$($pair.Name)] link order set to lowest precedence"
            } catch {
                Write-AdkLog "  could not set link order for [$($pair.Name)]: $($_.Exception.Message)" -Warning
            }
        }
    }

    # -- Fix SYSVOL ACL consistency ----------------------------------------
    # After dcpromo the SYSVOL ACLs on the default GPOs do not match the
    # ACLs stored in AD.  GPMC shows an "inconsistent permissions" warning
    # on first use.  Re-stamping the security descriptor from AD to SYSVOL
    # via the GPMGMT COM object is exactly what the GPMC "OK" button does.
    $defaultGuids = @(
        '{31B2F340-016D-11D2-945F-00C04FB984F9}'   # Default Domain Policy
        '{6AC1786C-016F-11D2-945F-00C04fB984F9}'   # Default Domain Controllers Policy
    )
    try {
        $gpm   = New-Object -ComObject GPMGMT.GPM
        $const = $gpm.GetConstants()
        $gpDom = $gpm.GetDomain($dom.DnsRoot, '', $const.UseAnyDC)
        foreach ($guid in $defaultGuids) {
            if ($PSCmdlet.ShouldProcess($guid, 'Reset SYSVOL permissions to match AD')) {
                $gpObj = $gpDom.GetGPO($guid)
                $gpObj.SetSecurityInfo($gpObj.GetSecurityInfo())
                Write-AdkLog "  [$guid] SYSVOL permissions synchronised with AD"
            }
        }
    } catch {
        Write-AdkLog "  SYSVOL permission fix skipped: $($_.Exception.Message)" -Warning
    }

    Write-AdkLog 'Default policies imported' -Success
}
