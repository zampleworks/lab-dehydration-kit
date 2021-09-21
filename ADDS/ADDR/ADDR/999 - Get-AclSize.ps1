<#
.SYNOPSIS
This script will enumerate AD objects with ACL size above 60000.

.DESCRIPTION
An ACL on an AD object must not exceed 64Kb in size. If such an ACL
is created the object cannot be replicated to other DCs and the DC
will not be able to calculate permissions on the object.

This script enumerates objects that are close to the limit.

.NOTES
Author anders.runesson@enfogroup.com
#>

Param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("container","organizationalunit","user","computer","*")]
    [string]
    $ObjectType = "OrganizationalUnit",

    [Parameter(Mandatory=$False)]
    [string]
    $SearchBase = "Root",

    [Parameter(Mandatory=$False)]
    [ValidateSet("base", "subtree","onelevel")]
    [string]
    $SearchScope = "Subtree"

)

$ErrorActionPreference = "Stop"

Function Get-DaclSize {
    Param(
        [String]
        [Parameter(ValueFromPipeLine=$True, Mandatory = $True)]
        $Object
    )
    Process {
        # Max size is 65535 bytes
        $AclSize = -1
        $AceCount = -1

        Try {
            $Sddl = (dsquery * $Object -scope base -attr ntSecurityDescriptor | Select-Object -Skip 1).Trim()
            $Acl = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $Acl.SetSecurityDescriptorSddlForm($Sddl)
            $Raw = $Acl.GetSecurityDescriptorBinaryForm()
            
            $DaclOffset = ([int]$Raw[19] -shl 24) + ([int]$Raw[18] -shl 16) + ([int]$Raw[17] -shl 8) + $Raw[16]
            If($DaclOffset -eq 0) {
                Write-Host "No DACL in security descriptor"
                return
            }

            $AclSize = ([int]$Raw[$DaclOffset + 3] -shl 8) + $Raw[$DaclOffset + 2]
            $AceCount = ([int]$Raw[$DaclOffset + 5] -shl 8) + $Raw[$DaclOffset + 4]

        } Catch {
            Write-Host "Failed to read ntSecurityDescriptor for object [$Object]" -ForegroundColor Red
            Write-Host (" > {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
        
        $O = New-Object PSObject -Property @{
            'Object' = $Object
            'DaclBinarySize' = $AclSize
            'AceCount' = $AceCount
            'ntSecDescSddlTextSize' = $Sddl.Length
        }

        Write-Output $O
    }
}

If($SearchBase -eq "root") {
    $Sb = (Get-ADDomain | Select -ExpandProperty DistinguishedName)
} Else {
    $Sb = $SearchBase
}

Write-Host "Enumerating $ObjectType objects in ($SearchScope) [$Sb]"

$Objects = Get-ADObject -ldapfilter "(objectClass=$ObjectType)" -SearchBase $Sb -SearchScope $SearchScope | ` 
    Get-DaclSize | Where-Object { $_.DaclBinarySize -gt 60000 -or $_.DaclBinarySize -eq -1 }

$Objects | ft -Property DaclBinarySize, AceCount, ntSecDescSDDLTextSize, Object

return

<#

$Object = "CN=DEDNT27,OU=Servers,OU=3570,DC=lab,DC=sandvik,DC=com"
$Object = "CN=DEPPC82,OU=Shopfloors,OU=Workstations,OU=3570,DC=lab,DC=sandvik,DC=com"

& '.\999 - Get-AclSize.ps1' -ObjectType computer -SearchBase "OU=Shopfloors,OU=Workstations,OU=3570,DC=lab,DC=sandvik,DC=com"
& '.\999 - Get-AclSize.ps1' -ObjectType computer -SearchBase "OU=Shopfloors,OU=Workstations,OU=3570,DC=lab,DC=sandvik,DC=com"

& '.\999 - Get-AclSize.ps1' -ObjectType * -SearchBase "OU=3570,DC=lab,DC=sandvik,DC=com"

#>

