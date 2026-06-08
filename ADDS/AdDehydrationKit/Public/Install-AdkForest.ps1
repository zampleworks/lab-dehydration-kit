# Install the AD-DS role on the local server and promote it to the
# first DC of a new forest. Two paths:
#   1) Modern (Install-ADDSForest from the ADDSDeployment module) when
#      the module is present (Windows Server 2012+).
#   2) Legacy dcpromo /unattend when running on 2008R2 (PS 5.1 era).
#
# The DSRM password is auto-generated when -DsrmPassword is not
# supplied. The legacy path additionally needs a built-in Administrator
# password, also auto-generated. Both are shown on the console at the
# end so the operator can write them down.

function Install-AdkForest {
    # -WhatIf shows the high-level steps that would run (feature install,
    # forest install, answer-file write) but cannot truly preview a
    # forest install - once the role is added there is no rollback. Use
    # -WhatIf only to confirm the target domain name and paths.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string] $DomainDnsName,
        [string] $DomainNetBiosName,
        [string] $DbPath      = 'C:\ADDS\Db',
        [string] $LogPath     = 'C:\ADDS\DbLog',
        [string] $SysvolPath  = 'C:\ADDS\SYSVOL',
        [securestring] $DsrmPassword,
        [int] $DomainLevel = 7,   # Windows Server 2016 minimum
        [int] $ForestLevel = 7
    )

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw 'PowerShell 5 or newer required'
    }

    # Auto-generate DSRM password if not supplied
    $dsrmGenerated = $false
    if (-not $DsrmPassword) {
        $dsrmPlain = New-RandomPassword -Length 32
        $DsrmPassword = ConvertTo-SecureString $dsrmPlain -AsPlainText -Force
        $dsrmGenerated = $true
    } else {
        $dsrmPlain = $null
    }

    # Domain name defaulting from hostname
    if ([string]::IsNullOrWhiteSpace($DomainDnsName)) {
        $name = hostname
        if ($name -match '(\d+)') {
            $seq = $Matches[$Matches.Count - 1]
        } else {
            $seq = Get-Random -Minimum 100 -Maximum 999
        }
        $subDomain = "ad$seq"
        $DomainDnsName = "{0}.zwks.xyz" -f $subDomain
    } else {
        $subDomain = $DomainDnsName.Substring(0, $DomainDnsName.IndexOf('.'))
    }
    if ([string]::IsNullOrWhiteSpace($DomainNetBiosName)) {
        $DomainNetBiosName = $subDomain.ToUpper()
    }

    foreach ($p in @($DbPath, $LogPath, $SysvolPath, 'C:\ADDS\Install')) {
        if (-not (Test-Path $p)) {
            New-Item $p -ItemType Directory | Out-Null
        }
    }

    # The AD-DS + GPMC Windows features (and their management modules)
    # must already be installed before this module loaded, because the
    # manifest declares them as RequiredModules. The wrapper script
    # Install-AddsService.ps1 handles that bootstrap. If you're calling
    # Install-AdkForest directly, ensure the features are installed first:
    #   Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    #   Install-WindowsFeature GPMC

    if ($PSCmdlet.ShouldProcess('schmmgmt.dll', 'Register schema management snap-in')) {
        regsvr32 /s C:\Windows\System32\schmmgmt.dll
    }

    $addsDeploymentModule = Get-Module ADDSDeployment -ListAvailable
    $adminPlain = $null

    if ($null -eq $addsDeploymentModule) {
        # Legacy dcpromo path
        if (-not $PSCmdlet.ShouldProcess($DomainDnsName, 'Promote to first DC of new forest via legacy dcpromo')) {
            return
        }
        $adminPlain = New-RandomPassword -Length 32
        $answerFile = "C:\ADDS\Install\$DomainDnsName.dcpromo.txt"

        @(
            '[DCINSTALL]'
            ''
            'InstallDNS=yes'
            'CreateDNSDelegation=no'
            ''
            "DatabasePath=$DbPath"
            "LogPath=$LogPath"
            "SysvolPath=$SysvolPath"
            ''
            'ConfirmGC=yes'
            'NewDomain=forest'
            'ReplicaOrNewDomain=domain'
            "NewDomainDNSName=$DomainDnsName"
            "DomainLevel=$DomainLevel"
            "ForestLevel=$ForestLevel"
            "DomainNetBiosName=$DomainNetBiosName"
            ''
            "Password=$adminPlain"
            "SafeModeAdminPassword=$([System.Net.NetworkCredential]::new('', $DsrmPassword).Password)"
            ''
            'RebootOnCompletion=no'
        ) | Out-File $answerFile -Force

        & dcpromo /unattend:"$answerFile"
        # DNS self-pointer applied below (shared with modern path)
    } else {
        if (-not $PSCmdlet.ShouldProcess($DomainDnsName, 'Promote to first DC of new forest (Install-ADDSForest)')) {
            return
        }
        Import-Module ADDSDeployment
        $forestParams = @{
            DomainName                    = $DomainDnsName
            DomainNetBIOSName             = $DomainNetBiosName
            DomainMode                    = $DomainLevel
            ForestMode                    = $ForestLevel
            DatabasePath                  = $DbPath
            LogPath                       = $LogPath
            SysvolPath                    = $SysvolPath
            SafeModeAdministratorPassword = $DsrmPassword
            InstallDns                    = $true
            NoRebootOnCompletion          = $true
            Confirm                       = $false
            Force                         = $true
        }
        Install-ADDSForest @forestParams
    }

    # Ensure domain-critical services are non-delayed automatic start.
    # Install-ADDSForest can leave NTDS, DNS, Netlogon, or kdc with
    # DelayedAutoStart=1, which means they start ~2 minutes into boot.
    # Netlogon registers the DC's SRV records in DNS; NLA uses those
    # records to confirm domain network availability; GP waits for NLA.
    # If any of these services is delayed, the chain breaks and GP stalls
    # for the full NLA wait timeout (up to 5+ minutes).
    Write-Host 'Ensuring domain services have non-delayed automatic start..' -ForegroundColor Cyan
    foreach ($svcName in @('NTDS', 'DNS', 'Netlogon', 'kdc')) {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
        if (-not (Test-Path $regPath)) { continue }
        $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        if ($props.DelayedAutoStart -eq 1) {
            Set-ItemProperty $regPath -Name DelayedAutoStart -Value 0 -Type DWord
            Write-Host "  [$svcName] DelayedAutoStart cleared" -ForegroundColor Yellow
        }
        if ($props.Start -ne 2) {
            Set-ItemProperty $regPath -Name Start -Value 2 -Type DWord
            Write-Host "  [$svcName] Start set to Automatic" -ForegroundColor Yellow
        }
    }

    # Point the NIC's DNS client at this server's own IP before rebooting.
    # After dcpromo the local DNS service is authoritative for the domain zone.
    # If the NIC still points at an upstream/DHCP resolver the DC locator
    # cannot find the SRV records on first boot, causing a 2-5 minute stall
    # at "Applying computer settings" while Group Policy retries.
    $ownIp = (Get-NetIPAddress -AddressFamily IPv4 -Type Unicast |
              Where-Object { $_.IPAddress -ne '127.0.0.1' -and
                             $_.IPAddress -notlike '169.254.*' } |
              Select-Object -First 1).IPAddress
    if ($ownIp) {
        Write-Host "Setting DNS client to self ($ownIp) to prevent GP stall on first boot.." -ForegroundColor Cyan
        Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
            try {
                Set-DnsClientServerAddress -InterfaceAlias $_.Name `
                                           -ServerAddresses $ownIp
            } catch {
                # After dcpromo the CIM provider for DNS client can be
                # disrupted. Fall back to netsh which survives the
                # network stack rebuild.
                Write-Host "  Set-DnsClientServerAddress failed on [$($_.Name)], falling back to netsh.." -ForegroundColor Yellow
                netsh interface ipv4 set dnsservers name="$($_.Name)" static $ownIp primary | Out-Null
            }
        }
    } else {
        Write-Host 'WARNING: could not determine own IP - DNS client not updated. You may see a slow first boot.' -ForegroundColor Yellow
    }

    if ($dsrmGenerated) {
        Write-Host '************************************************************************************' -ForegroundColor DarkYellow
        Write-Host '* PASSWORDS HAVE BEEN AUTO GENERATED!                                              *' -ForegroundColor DarkYellow
        Write-Host '* There is no way to retrieve them later. Write them down right now.               *' -ForegroundColor DarkYellow
        Write-Host '* Password for DSRM:                                                               *' -ForegroundColor DarkYellow
        Write-Host "* $dsrmPlain" -ForegroundColor DarkYellow
        if ($null -ne $adminPlain) {
            Write-Host '* Password for built-in Administrator (legacy dcpromo path only):                  *' -ForegroundColor DarkYellow
            Write-Host "* $adminPlain" -ForegroundColor DarkYellow
        }
        Write-Host '************************************************************************************' -ForegroundColor DarkYellow
        Read-Host 'Write down passwords, and press enter to continue'
    }
}
