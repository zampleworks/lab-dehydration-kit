# Build a SoD (Separation of Duty) migration table dynamically from
# a GPO backup's Backup.xml.
#
# Instead of maintaining a static template with hardcoded source domain
# entries, this function reads the SecurityGroups section of the backup
# to discover every principal the GPO references and the domain it came
# from, then generates a migration table that maps:
#
#   SoD groups  -> destination pattern + target domain
#                  (matched by suffix: InteractiveLogon, RdpLogon,
#                   LocalAdmin, ServiceLogon)
#   Well-known  -> same name in target domain
#   Builtins    -> same as source (no domain qualifier)
#
# This makes GPO backups fully portable across domains.

function New-AdkSodMigTable {
    [CmdletBinding()]
    param(
        # Path containing {GUID} backup sub-folders.
        [Parameter(Mandatory)] [string] $GpoBackupPath,

        # DisplayName of the backup GPO to find (matches CDATA in Backup.xml).
        [Parameter(Mandatory)] [string] $BackupGpoName,

        # Destination group prefix. The four SoD suffixes are appended with
        # a hyphen: <PmPattern>-InteractiveLogon, -RdpLogon, etc.
        [Parameter(Mandatory)] [string] $PmPattern,

        # Target domain DNS name (e.g. ad.contoso.com).
        [Parameter(Mandatory)] [string] $DomainDnsName,

        # Full path for the generated .migtable file.
        [Parameter(Mandatory)] [string] $OutputPath,

        # Override name for the domain built-in Administrator account
        # (RID-500) in migration table destinations. Use when the domain
        # account has been renamed. Default: 'Administrator'.
        [string] $BuiltinAdministratorName = 'Administrator',

        # Override name for the local Administrator account on domain
        # member servers. Used for non-domain entries in the GPO backup
        # (Group Membership, etc.). Default: 'Administrator'.
        [string] $LocalAdministratorName = 'Administrator'
    )

    # --- Locate the backup folder by DisplayName ---
    $backupDir = $null
    foreach ($dir in (Get-ChildItem $GpoBackupPath -Directory)) {
        $bkup = Join-Path $dir.FullName 'Backup.xml'
        if (-not (Test-Path $bkup)) { continue }
        $raw = Get-Content $bkup -Raw
        if ($raw -match '<DisplayName><!\[CDATA\[(.+?)\]\]></DisplayName>' -and
            $Matches[1] -eq $BackupGpoName) {
            $backupDir = $dir.FullName
            break
        }
    }
    if (-not $backupDir) {
        throw "GPO backup '$BackupGpoName' not found in $GpoBackupPath"
    }

    # --- Parse SecurityGroups from Backup.xml ---
    $bkupXml  = Join-Path $backupDir 'Backup.xml'
    $raw      = Get-Content $bkupXml -Raw

    # Known SoD suffixes (the User Rights Assignment groups).
    $sodSuffixes = @('InteractiveLogon', 'RdpLogon', 'LocalAdmin', 'ServiceLogon')

    # Well-known domain principals that need remapping to the target domain.
    # Key = SamAccountName (case-insensitive via -ieq later).
    $wellKnown = @('administrator', 'Enterprise Admins', 'Domain Admins')

    # Collect unique mapping entries keyed by Source string.
    $seen     = @{}
    $mappings = [System.Collections.Generic.List[string]]::new()

    $groupMatches = [regex]::Matches($raw, '<Group[^>]*>.*?</Group>', 'Singleline')

    foreach ($gm in $groupMatches) {
        $xml = $gm.Value

        $sam  = if ($xml -match '<SamAccountName><!\[CDATA\[(.+?)\]\]></SamAccountName>') { $Matches[1] } else { $null }
        $dns  = if ($xml -match '<DnsDomainName><!\[CDATA\[(.+?)\]\]></DnsDomainName>')   { $Matches[1] } else { $null }
        $upn  = if ($xml -match '<UPN><!\[CDATA\[(.+?)\]\]></UPN>')                        { $Matches[1] } else { $null }
        $type = if ($xml -match '<Type><!\[CDATA\[(.+?)\]\]></Type>')                      { $Matches[1] } else { 'Unknown' }

        if (-not $sam) { continue }

        # --- Builtin / local (no domain) ---
        if ([string]::IsNullOrWhiteSpace($dns)) {
            $srcKey = $sam
            if ($seen.ContainsKey($srcKey)) { continue }
            $seen[$srcKey] = $true

            # Local Administrator: map to the configured member-server name
            # when it differs from the backup's original name.
            if ($sam -ieq 'administrator' -and $LocalAdministratorName -ine 'Administrator') {
                $mappings.Add(
                    "    <Mapping>`n" +
                    "        <Type>$type</Type>`n" +
                    "        <Source>$sam</Source>`n" +
                    "        <Destination>$LocalAdministratorName</Destination>`n" +
                    "    </Mapping>"
                )
            } else {
                $mappings.Add(
                    "    <Mapping>`n" +
                    "        <Type>$type</Type>`n" +
                    "        <Source>$sam</Source>`n" +
                    "        <DestinationSameAsSource/>`n" +
                    "    </Mapping>"
                )
            }
            continue
        }

        # Use the UPN from the backup as the Source key. Import-GPO
        # matches Source entries against the backup's UPN field, so the
        # case must match exactly. Fall back to SAM@DNS only when UPN
        # is absent.
        $src = if ($upn) { $upn } else { "$sam@$dns" }

        if ($seen.ContainsKey($src)) { continue }
        $seen[$src] = $true

        # Derive destination local part from the UPN local part (preserves
        # the exact case the backup used). For SAM-only fallback, use SAM.
        $localPart = if ($upn -and $upn.Contains('@')) {
            $upn.Substring(0, $upn.IndexOf('@'))
        } else { $sam }

        # --- Well-known domain principal ---
        $isWellKnown = $false
        foreach ($wk in $wellKnown) {
            if ($sam -ieq $wk) { $isWellKnown = $true; break }
        }
        if ($isWellKnown) {
            # For the RID-500 account, use the configured name instead of
            # the backup's UPN local part. The RID-500 often has no
            # explicit userPrincipalName attribute, so Import-GPO cannot
            # resolve arbitrary names via UPN lookup. The configured name
            # must match the account's actual sAMAccountName in the
            # target domain.
            $destName = if ($sam -ieq 'administrator') {
                $BuiltinAdministratorName
            } else { $localPart }

            $mappings.Add(
                "    <Mapping>`n" +
                "        <Type>$type</Type>`n" +
                "        <Source>$src</Source>`n" +
                "        <Destination>$destName@$DomainDnsName</Destination>`n" +
                "    </Mapping>"
            )
            continue
        }

        # --- SoD group (matched by suffix) ---
        $matched = $false
        foreach ($suffix in $sodSuffixes) {
            if ($sam -like "*-$suffix") {
                $mappings.Add(
                    "    <Mapping>`n" +
                    "        <Type>$type</Type>`n" +
                    "        <Source>$src</Source>`n" +
                    "        <Destination>$PmPattern-$suffix@$DomainDnsName</Destination>`n" +
                    "    </Mapping>"
                )
                $matched = $true
                break
            }
        }
        if ($matched) { continue }

        # --- Unknown domain principal: map name to target domain ---
        $mappings.Add(
            "    <Mapping>`n" +
            "        <Type>$type</Type>`n" +
            "        <Source>$src</Source>`n" +
            "        <Destination>$localPart@$DomainDnsName</Destination>`n" +
            "    </Mapping>"
        )
    }

    # --- Emit migration table XML ---
    $body = $mappings -join "`n"

    $migXml = @"
<?xml version="1.0" encoding="utf-16"?>
<MigrationTable xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/MigrationTable">
$body
</MigrationTable>
"@

    $migXml | Out-File $OutputPath -Force
    Write-Verbose "  migration table written: $OutputPath"
}
