# Verbs: GpoEdit, GpoLink
#
# These verbs are deliberately separate. Editing a GPO and linking a
# GPO are different responsibilities; granting both is granting policy
# authoring AND policy scope, which together is effectively domain
# admin within reach of the linked OU.
#
# GpoEdit  - grant a role the ability to author the contents of a
#            specific GPO. Implemented via Set-GPPermission on the
#            target GPO; not OU-scoped at all. The Delegations.csv row
#            uses the Parameters column to name the GPO:
#                Role T1 DB Admin ; ; GpoEdit ; Gpo=T1 SoD DB Servers
#
# GpoLink  - grant a role the ability to link/unlink any GPO at a
#            specific OU. Writes gPLink and gPOptions on the OU
#            object. Inheritance defaults to None (just that OU).

function Set-Verb-GpoEdit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,    # Ignored; this verb targets the GPO, not the OU
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    if (-not $Parameters.ContainsKey('Gpo')) {
        throw "GpoEdit verb requires Parameters 'Gpo=<gponame>'"
    }
    $gpoName = $Parameters['Gpo']

    $role = Get-ADObject $SubjectDN -Properties sAMAccountName
    $roleSam = $role.sAMAccountName

    Write-Verbose "Granting GpoEdit on [$gpoName] to [$roleSam]"

    # Set-GPPermission is itself idempotent (-Replace overwrites existing
    # ACE rather than adding). Wrap any failure for a clearer message.
    try {
        Set-GPPermission -Name $gpoName -TargetName $roleSam `
                         -TargetType Group -PermissionLevel GpoEdit `
                         -Replace -ErrorAction Stop | Out-Null
    } catch {
        throw "Failed to grant GpoEdit on [$gpoName] to [$roleSam]: $($_.Exception.Message)"
    }
}

function Set-Verb-GpoLink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'None' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $gPLink    = Get-AdkAttributeGuid -AttributeName 'gPLink'
    $gPOptions = Get-AdkAttributeGuid -AttributeName 'gPOptions'

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $gPLink -InheritanceType $inh

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $gPOptions -InheritanceType $inh
}
