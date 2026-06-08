# Central registry of delegation verbs.
#
# Each entry maps a verb name (as used in Delegations.csv) to a
# scriptblock that takes (ObjectDN, SubjectDN, Parameters[hashtable]).
# Add a new verb by:
#   1. Implementing Set-Verb-<Name> in Private/Delegation/Verbs/
#   2. Adding the row below.
# No edit to the dispatch loop in Set-AdkDelegation is required.

function Get-AdkDelegationVerbs {
    [CmdletBinding()]
    param()

    return @{
        # --- Original verb set (Phase 2 port) -----------------------------
        'FullControl'         = { param($o, $s, $p) Set-Verb-FullControl       -ObjectDN $o -SubjectDN $s -Parameters $p }
        'ResetPwd'            = { param($o, $s, $p) Set-Verb-ResetPwd          -ObjectDN $o -SubjectDN $s -Parameters $p }

        'CreateUsers'         = { param($o, $s, $p) Set-Verb-CreateUsers       -ObjectDN $o -SubjectDN $s -Parameters $p }
        'DeleteUsers'         = { param($o, $s, $p) Set-Verb-DeleteUsers       -ObjectDN $o -SubjectDN $s -Parameters $p }
        'FullControlUsers'    = { param($o, $s, $p) Set-Verb-FullControlUsers  -ObjectDN $o -SubjectDN $s -Parameters $p }
        'ManageUsers'         = { param($o, $s, $p) Set-Verb-ManageUsers       -ObjectDN $o -SubjectDN $s -Parameters $p }

        'CreateGroups'        = { param($o, $s, $p) Set-Verb-CreateGroups      -ObjectDN $o -SubjectDN $s -Parameters $p }
        'DeleteGroups'        = { param($o, $s, $p) Set-Verb-DeleteGroups      -ObjectDN $o -SubjectDN $s -Parameters $p }
        'FullControlGroups'   = { param($o, $s, $p) Set-Verb-FullControlGroups -ObjectDN $o -SubjectDN $s -Parameters $p }
        'ManageGroups'        = { param($o, $s, $p) Set-Verb-ManageGroups      -ObjectDN $o -SubjectDN $s -Parameters $p }

        'ManageComputers'     = { param($o, $s, $p) Set-Verb-ManageComputers   -ObjectDN $o -SubjectDN $s -Parameters $p }

        # --- Computer lifecycle (Phase 5) ---------------------------------
        'DomainJoin'          = { param($o, $s, $p) Set-Verb-DomainJoin        -ObjectDN $o -SubjectDN $s -Parameters $p }
        'DomainRejoin'        = { param($o, $s, $p) Set-Verb-DomainRejoin      -ObjectDN $o -SubjectDN $s -Parameters $p }
        'DenyJoinAbuse'       = { param($o, $s, $p) Set-Verb-DenyJoinAbuse     -ObjectDN $o -SubjectDN $s -Parameters $p }

        # --- GPO authoring vs. linking (Phase 6) --------------------------
        # GpoEdit  takes Parameters 'Gpo=<gponame>' ; OU column is unused
        # GpoLink  takes Parameters 'Inheritance=None|All' (default None)
        'GpoEdit'             = { param($o, $s, $p) Set-Verb-GpoEdit           -ObjectDN $o -SubjectDN $s -Parameters $p }
        'GpoLink'             = { param($o, $s, $p) Set-Verb-GpoLink           -ObjectDN $o -SubjectDN $s -Parameters $p }

        # --- Entra Connect / Cloud Sync (Phase 8) -------------------------
        # The Entra service account gets a subset of these via membership.
        # DirSyncRead/All are domain-root verbs (leave OuName empty).
        'EntraDirSyncRead'        = { param($o, $s, $p) Set-Verb-EntraDirSyncRead        -ObjectDN $o -SubjectDN $s -Parameters $p }
        'EntraDirSyncReadAll'     = { param($o, $s, $p) Set-Verb-EntraDirSyncReadAll     -ObjectDN $o -SubjectDN $s -Parameters $p }
        'EntraWriteConsistencyGuid' = { param($o, $s, $p) Set-Verb-EntraWriteConsistencyGuid -ObjectDN $o -SubjectDN $s -Parameters $p }
        'EntraPwWriteback'        = { param($o, $s, $p) Set-Verb-EntraPwWriteback        -ObjectDN $o -SubjectDN $s -Parameters $p }
        'EntraExchangeWriteback'  = { param($o, $s, $p) Set-Verb-EntraExchangeWriteback  -ObjectDN $o -SubjectDN $s -Parameters $p }
        'EntraDeviceWriteback'    = { param($o, $s, $p) Set-Verb-EntraDeviceWriteback    -ObjectDN $o -SubjectDN $s -Parameters $p }
        'EntraGroupWriteback'     = { param($o, $s, $p) Set-Verb-EntraGroupWriteback     -ObjectDN $o -SubjectDN $s -Parameters $p }
        'EntraSeamlessSso'        = { param($o, $s, $p) Set-Verb-EntraSeamlessSso        -ObjectDN $o -SubjectDN $s -Parameters $p }

        # --- LAPS / BitLocker / gMSA / AuthPolicy (Phase 9) ---------------
        'LapsReadPwd'         = { param($o, $s, $p) Set-Verb-LapsReadPwd       -ObjectDN $o -SubjectDN $s -Parameters $p }
        'LapsResetPwd'        = { param($o, $s, $p) Set-Verb-LapsResetPwd      -ObjectDN $o -SubjectDN $s -Parameters $p }
        'LapsDecryptPwd'      = { param($o, $s, $p) Set-Verb-LapsDecryptPwd    -ObjectDN $o -SubjectDN $s -Parameters $p }
        'BitLockerRecovery'   = { param($o, $s, $p) Set-Verb-BitLockerRecovery -ObjectDN $o -SubjectDN $s -Parameters $p }
        'ManageGMSA'          = { param($o, $s, $p) Set-Verb-ManageGMSA        -ObjectDN $o -SubjectDN $s -Parameters $p }
        'AssignAuthPolicy'    = { param($o, $s, $p) Set-Verb-AssignAuthPolicy  -ObjectDN $o -SubjectDN $s -Parameters $p }

        # --- Object-management verbs (Phase 10) ---------------------------
        'ResetComputerPwd'    = { param($o, $s, $p) Set-Verb-ResetComputerPwd  -ObjectDN $o -SubjectDN $s -Parameters $p }
        'MoveUser'            = { param($o, $s, $p) Set-Verb-MoveUser          -ObjectDN $o -SubjectDN $s -Parameters $p }
        'MoveComputer'        = { param($o, $s, $p) Set-Verb-MoveComputer      -ObjectDN $o -SubjectDN $s -Parameters $p }
        'WriteSpn'            = { param($o, $s, $p) Set-Verb-WriteSpn          -ObjectDN $o -SubjectDN $s -Parameters $p }
        'ManageContacts'      = { param($o, $s, $p) Set-Verb-ManageContacts    -ObjectDN $o -SubjectDN $s -Parameters $p }
        'CreateChildOU'       = { param($o, $s, $p) Set-Verb-CreateChildOU     -ObjectDN $o -SubjectDN $s -Parameters $p }
        'ReadAllOnTier'       = { param($o, $s, $p) Set-Verb-ReadAllOnTier     -ObjectDN $o -SubjectDN $s -Parameters $p }
        'ApplyPso'            = { param($o, $s, $p) Set-Verb-ApplyPso          -ObjectDN $o -SubjectDN $s -Parameters $p }
    }
}
