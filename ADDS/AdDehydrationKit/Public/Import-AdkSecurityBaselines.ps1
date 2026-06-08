# Import security baseline GPO backups, assign WMI filters, and link
# to the target OUs defined in SecurityBaselines.csv.
#
# Prerequisites:
#   - WMI filters must exist (New-AdkWmiFilters).
#   - GPO backup folders must be present under the GPO backup path.
#     The user creates these from the MS Security Compliance Toolkit
#     or by exporting configured GPOs.
#   - OUs must exist (New-AdkOuTree).
#
# The function is idempotent: existing GPOs are removed and re-created
# from the backup on each run, then WMI filter and links are re-applied.
# Removing first avoids the Access Denied error that Import-GPO can return
# when re-importing over a stale GPT folder in SYSVOL.

function Import-AdkSecurityBaselines {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    $csvPath = Join-Path $Context.DataPath 'SecurityBaselines.csv'
    if (-not (Test-Path $csvPath -PathType Leaf)) {
        Write-AdkLog '  SecurityBaselines.csv not found - skipping security baselines' -Warning
        return
    }

    $gpoPath = $Context.GpoPath
    if (-not $gpoPath -or -not (Test-Path $gpoPath)) {
        Write-AdkLog '  GPO backup path not available - skipping security baselines' -Warning
        return
    }

    $baselines = Import-Csv $csvPath -Delimiter ';'
    if (-not $baselines -or $baselines.Count -eq 0) {
        Write-AdkLog '  SecurityBaselines.csv is empty' -Step
        return
    }

    $ouMap = Get-AdkOuMap -DataPath $Context.DataPath

    # Check which backups are actually present on disk. BackupGpoName
    # must match the DisplayName CDATA in one of the backup folders'
    # Backup.xml. Import-GPO resolves this at runtime; we pre-check
    # so we can give a clear skip message rather than a cryptic error.
    $availableBackups = @{}
    foreach ($dir in (Get-ChildItem $gpoPath -Directory -ErrorAction SilentlyContinue)) {
        $bkup = Join-Path $dir.FullName 'Backup.xml'
        if (Test-Path $bkup) {
            try {
                $raw = Get-Content $bkup -Raw
                if ($raw -match '<DisplayName><!\[CDATA\[(.+?)\]\]></DisplayName>') {
                    $availableBackups[$Matches[1]] = $dir.FullName
                }
            } catch {
                # Skip unparseable backup folders
            }
        }
    }

    $forceImport = [bool]$Context.Force
    $imported    = 0
    $existed     = 0
    $skipped     = 0

    foreach ($bl in $baselines) {
        $gpoName    = $bl.GpoName
        $backupName = $bl.BackupGpoName

        if (-not $availableBackups.ContainsKey($backupName)) {
            Write-AdkLog "  backup not found for [$gpoName] (expected backup named '$backupName') - skipping" -Step
            $skipped++
            continue
        }

        # --- Import the GPO from backup ---
        $existing = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if ($existing -and -not $forceImport) {
            Write-AdkLog "  [$gpoName] already exists"
            $existed++
        } else {
            # Remove any existing GPO first so -CreateIfNeeded always gets a clean
            # GPT folder - re-importing over a stale GPT can fail with Access Denied.
            if ($PSCmdlet.ShouldProcess($gpoName, "Import GPO from backup [$backupName]")) {
                if ($existing) {
                    try {
                        Remove-GPO -Name $gpoName -Confirm:$false
                    } catch {
                        Write-AdkLog "  failed removing existing GPO [$gpoName] before re-import: $($_.Exception.Message)" -Warning
                    }
                }

                try {
                    Import-Gpo -BackupGpoName $backupName -Path $gpoPath `
                               -TargetName $gpoName -CreateIfNeeded | Out-Null
                    Write-AdkLog "  imported GPO [$gpoName]"
                    $imported++
                } catch {
                    Write-AdkLog "  failed importing GPO [$gpoName]: $($_.Exception.Message)" -Warning
                    continue
                }
            }
        }

        # --- Assign WMI filter ---
        if ($bl.WmiFilter) {
            $filterId = Get-AdkWmiFilterId -Name $bl.WmiFilter -DomainDn $Context.DomainDn
            if ($filterId) {
                if ($PSCmdlet.ShouldProcess($gpoName, "Assign WMI filter [$($bl.WmiFilter)]")) {
                    try {
                        $gpo     = Get-GPO -Name $gpoName
                        # gPCWQLFilter on the GPC object links a WMI filter.
                        # Format: [<domain>;<filter {GUID}>;0]
                        $wmiLink = "[$($Context.DomainDnsName);$filterId;0]"
                        $adsi = [ADSI]"LDAP://$($gpo.Path)"
                        $adsi.Put('gPCWQLFilter', $wmiLink)
                        $adsi.SetInfo()
                        Write-AdkLog "  assigned WMI filter [$($bl.WmiFilter)] to [$gpoName]"
                    } catch {
                        Write-AdkLog "  failed assigning WMI filter to [$gpoName]: $($_.Exception.Message)" -Warning
                    }
                }
            } else {
                Write-AdkLog "  WMI filter [$($bl.WmiFilter)] not found - run New-AdkWmiFilters first" -Warning
            }
        }

        # --- Link to target OUs ---
        $linkTargets = $bl.LinkTargets -split '\|'
        foreach ($token in $linkTargets) {
            $token = $token.Trim()
            if (-not $token) { continue }

            if (-not $ouMap.ContainsKey($token)) {
                Write-AdkLog "  OU token $token not resolved - skipping link for [$gpoName]" -Step
                continue
            }
            $targetOu = $ouMap[$token]

            if ($PSCmdlet.ShouldProcess($targetOu, "Link GPO [$gpoName]")) {
                try {
                    New-GPLink -Name $gpoName -Target $targetOu -LinkEnabled Yes | Out-Null
                    Write-AdkLog "  linked [$gpoName] -> $token"
                } catch {
                    # Link probably already exists
                    if ($_.Exception.Message -notlike '*already linked*') {
                        Write-AdkLog "  failed linking [$gpoName] to $token [$targetOu] : $($_.Exception.Message)" -Warning
                    }
                }
            }
        }
    }

    Write-AdkLog "Security baselines: $imported imported, $existed unchanged, $skipped skipped (backup not found)" -Success

    # ------------------------------------------------------------------ #
    # GPO link ordering pass.
    #
    # LinkOrder values in the CSV determine relative precedence per OU:
    #   Lower number = higher precedence (link order 1 in GPMC = top/wins).
    #   Gaps are intentional so similar policies cluster together:
    #     1-9   : specific/tool policies (VBS, Credential Guard, Edge, etc.)
    #     10-19 : OS-version baselines
    #     999   : Default Domain / Default Domain Controllers Policy
    #             (set in the orchestrator's DefaultPolicies step)
    #
    # Algorithm: sort rows for each OU by LinkOrder DESCENDING, then call
    # Set-GPLink -Order 1 for each in that order. The last GPO processed
    # (smallest LinkOrder = highest desired precedence) ends up at position 1.
    # Unmanaged GPOs (e.g. Default DC Policy, linked by a prior step) are
    # naturally pushed to the end and stay there.
    # ------------------------------------------------------------------ #
    $ouLinkOrders = @{}
    foreach ($bl in $baselines) {
        if ([string]::IsNullOrWhiteSpace($bl.LinkOrder)) { continue }
        # Only order GPOs whose backup was available (i.e. they were linked)
        if (-not $availableBackups.ContainsKey($bl.BackupGpoName)) { continue }
        $order = [int]$bl.LinkOrder
        foreach ($token in ($bl.LinkTargets -split '\|')) {
            $token = $token.Trim()
            if (-not $token -or -not $ouMap.ContainsKey($token)) { continue }
            $ouDn = $ouMap[$token]
            if (-not $ouLinkOrders.ContainsKey($ouDn)) {
                $ouLinkOrders[$ouDn] = [System.Collections.Generic.List[PSObject]]::new()
            }
            $ouLinkOrders[$ouDn].Add([PSCustomObject]@{ GpoName = $bl.GpoName; Order = $order })
        }
    }

    if ($ouLinkOrders.Count -gt 0) {
        Write-AdkLog 'Setting GPO link orders..' -Step
        foreach ($ouDn in $ouLinkOrders.Keys) {
            # Sort descending: lowest precedence processed first, highest last.
            # Each Set-GPLink -Order 1 pushes the GPO to the top; the last one
            # processed (smallest Order value) ends up at position 1.
            $sorted = $ouLinkOrders[$ouDn] | Sort-Object Order -Descending
            foreach ($item in $sorted) {
                if (-not $PSCmdlet.ShouldProcess($item.GpoName, "Set link order on $(($ouDn -split ',')[0])")) { continue }
                try {
                    Set-GPLink -Name $item.GpoName -Target $ouDn -Order 1 -ErrorAction SilentlyContinue | Out-Null
                    Write-AdkLog "  ordered [$($item.GpoName)] (priority $($item.Order)) on $(($ouDn -split ',')[0])" -Step
                } catch {
                    Write-AdkLog "  could not set link order for [$($item.GpoName)]: $($_.Exception.Message)" -Warning
                }
            }
        }
    }
}
