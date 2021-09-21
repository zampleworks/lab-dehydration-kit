
Function Get-DaclSize {
    Param(
        [String]
        [Parameter(ValueFromPipeLine=$True, Mandatory = $True)]
        $Object
    )
    Process {
        $ntSec = get-adobject $Object -properties ntSecurityDescriptor | select -expand ntsecuritydescriptor
        $Raw = $ntSec.GetSecurityDescriptorBinaryForm()
        #$RawHex = ($Raw | % ToString X2) -join ''

        $DaclOffset = ([int]$Raw[19] -shl 24) + ([int]$Raw[18] -shl 16) + ([int]$Raw[17] -shl 8) + $Raw[16]
        If($DaclOffset -eq 0) {
            Write-Host "No DACL in security descriptor"
            return
        }

        $AclSize = ([int]$Raw[$DaclOffset + 3] -shl 8) + $Raw[$DaclOffset + 2]
        $AceCount = ([int]$Raw[$DaclOffset + 5] -shl 8) + $Raw[$DaclOffset + 4]

        $O = New-Object PSObject -Property @{
            'Object' = $Object
            'DaclSize' = $AclSize
            'AceCount' = $AceCount
        }

        Write-Output $O
    }
}



Get-ADObject -ldapfilter "(objectClass=OrganizationalUnit)" -SearchBase (Get-ADDomain | Select -ExpandProperty DistinguishedName) -SearchScope Subtree | ` 
    Where-Object { $_.Name -match "[0-9].*" } | Get-DaclSize | Where-Object { $_.DaclSize -gt 6000 }


