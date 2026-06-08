@{
    # ------------------------------------------------------------------ #
    # Identity settings
    # ------------------------------------------------------------------ #

    # Name of the domain built-in Administrator account (RID-500).
    # Change this if the domain account has been renamed as a hardening
    # measure. Used in GPO migration tables to resolve the domain
    # principal destination.
    # Default when absent: 'Administrator'
    BuiltinAdministratorName = 'Administrator'

    # Name of the local Administrator account on domain member servers.
    # Change this if the local admin has been renamed via GPO or other
    # mechanism. Used in GPO migration tables for non-domain entries
    # (Group Membership restricted groups, etc.).
    # Default when absent: 'Administrator'
    LocalAdministratorName = 'Administrator'

    # ------------------------------------------------------------------ #
    # Logging
    # ------------------------------------------------------------------ #

    # Controls the verbosity of Write-AdkLog output.
    #   'Normal'  - default: informational, warnings, errors, success
    #   'Verbose' - also emit -Step trace messages (same as -Verbose)
    #   'Quiet'   - only warnings, errors, and success milestones
    LogLevel = 'Normal'

    # ------------------------------------------------------------------ #
    # Domain hardening (Set-AdkDomainHardening)
    # Set to $false to skip individual hardening measures.
    # ------------------------------------------------------------------ #
    Hardening = @{
        # Clear Pre-Windows 2000 Compatible Access membership
        ClearPreWin2000 = $true

        # Set ms-DS-MachineAccountQuota = 0 (block unauthenticated joins)
        ZeroMachineAccountQuota = $true

        # Redirect default user/computer containers (redirusr/redircmp)
        RedirectDefaultContainers = $true

        # Empty Schema Admins after LAPS schema is confirmed applied
        EmptySchemaAdmins = $true

        # Enforce AccountNotDelegated on admin accounts
        EnforceAccountNotDelegated = $true

        # Enforce AES Kerberos encryption on service accounts
        EnforceAesEncryption = $true

        # Reset krbtgt password
        ResetKrbtgt = $true

        # Protect Domain Controllers OU from accidental deletion
        ProtectDcOu = $true

        # Clear AdminCount on built-in groups (Account/Print/Backup/Server Operators)
        ClearBuiltinGroupsAdminCount = $true

        # ---- dSHeuristics (per-position configuration) ----
        # Each position controls a specific Directory Service behaviour.
        # Values: character '0'-'9'. $null = do not touch that position.
        # Sentinel positions (10, 20) are always auto-set; do not override.
        DsHeuristics = @{
            # Position  7: fLDAPBlockAnonOps. '0' = block anonymous LDAP
            #   (default, secure). '2' = allow anonymous LDAP operations.
            BlockAnonLdap                = '0'

            # Position 28: implicit-owner check on nTSecurityDescriptor
            #   writes (CVE-2021-42291 / Event 3054).
            #   '0' = audit only, '1' = enforce (block non-compliant).
            EnforceOwnerCheck            = '1'

            # Position 29: per-attribute authorization on LDAP add
            #   operations (CVE-2021-42291 / Event 3051).
            #   '0' = audit only, '1' = enforce (block non-compliant).
            EnforceAddAttributeAuth      = '1'
        }
    }

    # ------------------------------------------------------------------ #
    # Server hardening (Set-AdkServerHardening)
    # ------------------------------------------------------------------ #
    ServerHardening = @{
        # ---- Fixed RPC ports (for host-based firewall rules) ----
        # Set to $false to skip, or set to a specific port number.
        NtdsRpcPort     = 49151    # NTDS TCP/IP Port ($false to skip)
        NetlogonRpcPort = 49150    # Netlogon DCTcpipPort ($false to skip)

        # ---- KDC diagnostic logging ----
        # Bitmask value for KdcExtraLogLevel. $false to skip.
        #   0x01 - KDC errors and pre-auth failures
        #   0x02 - ticket request details
        #   0x04 - pre-auth data type info
        #   0x08 - extended error info on TGS/TGT failures
        #   0x10 - client IP address in logged events
        #   0x1F - all of the above (default)
        KdcExtraLogLevel = 0x1F

        # ---- LDAP security hardening (per-setting) ----
        # Integer value for each NTDS\Parameters registry key.
        # $false = do not touch that setting.
        #   LDAPServerIntegrity:       0=off, 1=negotiate, 2=require
        #   LdapEnforceChannelBinding: 0=never, 1=when supported, 2=always
        LDAPServerIntegrity       = 2
        LdapEnforceChannelBinding = 2

        # ---- Services to disable ----
        # Each key is a Windows service name. $true = disable it,
        # $false = leave it alone. Missing keys default to $true.
        DisableServices = @{
            Spooler          = $true   # Print Spooler (PrintNightmare / SpoolFool)
            PrintNotify      = $true   # Printer Extensions and Notifications
            RemoteRegistry   = $true   # Remote Registry
            WebClient        = $true   # WebDAV client (NTLM relay / coercion)
            SSDPSRV          = $true   # SSDP Discovery (UPnP)
            upnphost         = $true   # UPnP Device Host
            Fax              = $true   # Fax service
            TapiSrv          = $true   # Telephony
            WSearch          = $true   # Windows Search indexing
            DiagTrack        = $true   # Connected User Experiences and Telemetry
            dmwappushservice = $true   # WAP Push Message Routing
            MapsBroker       = $true   # Downloaded Maps Manager
            lfsvc            = $true   # Geolocation service
            RetailDemo       = $true   # Retail Demo
            PhoneSvc         = $true   # Phone service
            icssvc           = $true   # Mobile Hotspot
            WpnService       = $true   # Windows Push Notifications System
            PushToInstall    = $true   # Windows PushToInstall
        }
    }
}
