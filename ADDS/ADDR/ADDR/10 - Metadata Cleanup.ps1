<#
.SYNOPSIS
Removes DC metadata for all DCs in the domain, except the server
the script is running on.

.NOTES
Author Unknown
Updated by anders.runesson@enfogroup.com
#>
[CmdletBinding(
    SupportsShouldProcess = $True,
    ConfirmImpact = "High"
)]
Param()

$ErrorActionPreference = "Stop"

Try {

    $FQDNDomain = (Get-ADDomain).DNSRoot
    $DomainDN = (Get-ADDomain).DistinguishedName
    $Fqdn = "{0}.{1}" -f (Get-WmiObject win32_computersystem).DNSHostName, (Get-WmiObject win32_computersystem).Domain

    Write-Warning "Metadata will be removed for all domain controllers except $Fqdn in $FQDNDomain, performing this activity in a production environment will be catastrophic."


    $Dcs = Get-ADDomainController -Filter *
    $DcHostnames = $Dcs | Select-Object -ExpandProperty Hostname
    If($DcHostnames -notcontains $Fqdn) {
        Write-Error "This script must be run on a DC!"
    }

    $Dcs | where { $_.Hostname -notmatch $(&HOSTNAME) } | ForEach-Object {
        If($PSCmdlet.ShouldProcess($_.Name, "Cleanup metadata")) {
            $sername = $_.name
	        $sitename = $_.site
		
            $DomainNum = "FailedToFindDomain" 
            $domains = ntdsutil "metadata cleanup" "con" "con to dom $FQDNDomain" q "sel op ta" "list do"  q q q	
            switch -regex ($domains) { "^(\d+) - $domaindn"{ $DomainNum = $matches[1]; break; } }

	        $sitenum = "FailedTofindSite"; 
            $sites = ntdsutil "metadata cleanup" "con" "con to dom $FQDNDomain" q "sel op ta" "list do" "select do $DomainNum" "list sites" q q q
	        switch -regex ($sites) { "^(\d+) - .+$sitename"{ $sitenum = $matches[1]; break; } }
		
            $servers = ntdsutil "metadata cleanup" "con" "con to dom $FQDNDomain" q "sel op ta" "list do" "select do $DomainNum" "list sites" "sel site $sitenum" "list ser for dom in site" q q q
	        $servnum = "FailedToFindServer"; 
            switch -regex ($servers) { "^(\d+).+$sername"{ $servnum = $matches[1]; break; } }
		
            Write-Host "Executing cleanup metadata $sername from $sitename : ntdsutil `"metadata cleanup`" `"con`" `"con to dom $FQDNDomain`" q `"sel op ta`" `"list do`" `"select do $DomainNum`" `"list sites`" `"sel site $sitenum`" `"list ser for dom in site`" `"sel ser $servnum`" q `"rem sel server`" q q"
	        $result = ntdsutil "metadata cleanup" "con" "con to dom $FQDNDomain" q "sel op ta" "list do" "select do $DomainNum" "list sites" "sel site $sitenum" "list ser for dom in site" "sel ser $servnum" q "rem sel server" q q
	        if ($result -match "removed from server")
	        {
		        Write-Host ($_.name + " Metadata cleanup complete") -ForegroundColor Green
	        }
        }
    }

} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}
