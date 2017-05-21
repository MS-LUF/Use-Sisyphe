#
# Created by: lucas.cueff[at]lucas-cueff.com
#
# Released on: 04/2017
#
#'(c) 2017 lucas-cueff.com - Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).'
<#
	.SYNOPSIS 
	commandline interface to use sisyphe.io web service

	.DESCRIPTION
	use-sisyphe.psm1 module provides a commandline interface to sisyphe.io web service.
	Require PoshRSJob PowerShell module to use multithreading option of get-sisypheinfo function.
	
	.EXAMPLE
	C:\PS> import-module use-sisyphe.psm1
#>
function Get-SisypheInfo {
  [cmdletbinding()]
  Param (
  [parameter(Mandatory=$false)]
    [ValidatePattern("(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])")]
    [string[]]$IP,
  [parameter(Mandatory=$false)]
    [ValidatePattern("([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-3][0-9]|6553[0-5])")]
	[string[]]$Port,
  [parameter(Mandatory=$false)]
    [ValidatePattern("\w+")]
	[string[]]$OS,
  [parameter(Mandatory=$false)]
    [ValidatePattern("([a-zA-Z]){2}")]
	[string[]]$Country,
  [parameter(Mandatory=$false)]
    $fromcsv,
  [parameter(Mandatory=$false)]
	[switch]$multithreading
  )
  <#
	.SYNOPSIS 
	Get IP information from sisyphe.io web service

	.DESCRIPTION
	get various ip data information from sisyphe.io web service

	.PARAMETER IP
	-IP string
	look for an ip address in sisyphe database

	.PARAMETER port
	-Port string
	look for an tcp or udp port in sisyphe database. Could be used with other information (os and/or country)
	
	.PARAMETER os
	-Port string
	look for an OS in sisyphe database. Must be be used with "port" parameter and could be used with "country" parameter
	
	.PARAMETER country
	-Port string
	look for an country in sisyphe database. Must be be used with "port" parameter and could be used with "os" parameter
	
	.PARAMETER multithreading
	-multithreading switch
	 use .Net RunSpace to run invoke-websisypherequest in parallel to decrease execution time.
	 warning : do not provide more than 10 requests in a csv using this option or some of your requests could be blocked by rate limiting feature of the web server.
	
	.OUTPUTS
	TypeName: System.Collections.Hashtable
	
	Name                           Value
	----                           -----
	port-3389_country-FR           {sample, os, total_ip, port...}
	port-3389_os-windows           {sample, os, total_ip, port...}
	ip-188.241.140.222             {geoloc, ip, resolver, threatlist...}
	country-FR_os-windows_port-... {sample, os, total_ip, port...}
	port-25_os-linux               {sample, os, total_ip, port...}
	port-22                        {sample, os, total_ip, port...}
	port-443_country-FR            {sample, os, total_ip, port...}
	ip-31.13.24.2                  {geoloc, ip, resolver, threatlist...}
	ip-31.13.24.1                  {geoloc, ip, resolver, threatlist...}
	ip-192.168.1.5                 {geoloc, ip, resolver, threatlist...}
	ip-31.13.24.3                  {geoloc, ip, resolver, threatlist...}
	ip-77.75.111.22                {geoloc, ip, resolver, threatlist...}
	ip-202.181.243.2               {geoloc, ip, resolver, threatlist...}
	ip-31.13.24.4                  {geoloc, ip, resolver, threatlist...}

	.EXAMPLE
	C:\PS> Get-sisypheinfo -fromcsv .\input.csv -multithreading
	C:\PS> Get-sisypheinfo -fromcsv .\input.csv
	C:\PS> Get-sisypheinfo -IP 192.168.1.5
	C:\PS> Get-sisypheinfo -port 3389 -os windows -country FR
#>
  Begin {
	$global:Result = @{}
	if ($fromcsv) {$global:FromcsvType = $fromcsv | Get-Member | Select-Object -ExpandProperty TypeName -Unique}
  } Process {
	if ($fromcsv) {
		if (($global:FromcsvType -eq 'System.String') -and (test-path $fromcsv)) {
			$csvcontent = import-csv $fromcsv -delimiter ";"
			if (-not($csvcontent | select-string ";")) {
				write-warning "please use a semicolon separator in $($fromcsv) CSV file - exit"
				return -1
			}
		} ElseIf (($global:FromcsvType -eq 'System.Management.Automation.PSCustomObject') -and ($fromcsv.ip -or $fromcsv.port -or $fromcsv.country -or $fromcsv.os)) {
			$csvcontent = $fromcsv
		} Else {
			if ($debug -or $verbose) {
				write-warning "provide a valid csv file as input or valid System.Management.Automation.PSCustomObject object"
				write-warning "please use a semicolon separator in your CSV file"
				write-warning "please use the following column in your file : ip, port, os, country"
			}
			return @{"error" = "System.Management.Automation.PSCustomObject"}
		}
		If ($multithreading) {
			try {
				import-module PoshRSJob
			} catch {
				if ($debug -or $verbose) {
					write-warning "please install PoshRSJob module to manage .Net RunSpace"
					write-warning "to install it from powershell gallery :"
					write-host "==> Install-Module -Name PoshRSJob" -foreground 'Green'
				}
				return @{"error" = "PoshRSJOB"}
			}
			$global:currentmodulepath = join-path (Get-ScriptDirectory) "Use-Sisyphe.psm1"
		}
		foreach ($entry in $csvcontent) {
			If ($entry.ip) {
				If ($multithreading) {
					$ip = $entry.ip
					start-rsjob -ModulesToImport $currentmodulepath -scriptblock {invoke-websisypherequest -IP $using:ip} | out-null
				} Else {
					$global:Result += invoke-websisypherequest -IP $entry.ip
				}
			} ElseIf ($entry.port -and -not ($entry.os -or $entry.country)) {
				If ($multithreading) {
					$port = $entry.port
					start-rsjob -ModulesToImport $currentmodulepath -scriptblock {invoke-websisypherequest -Port $using:port} | out-null
				} Else {
					invoke-websisypherequest -Port $entry.port
					$global:Result += invoke-websisypherequest -Port $entry.port
				}
			} Else {
				If (($entry.port) -and ($entry.os)) {
					If ($multithreading) {
						$port = $entry.port
						$os = $entry.os
						start-rsjob -ModulesToImport $currentmodulepath -scriptblock {invoke-websisypherequest -Port $using:port -OS $using:os} | out-null
					} Else {
						invoke-websisypherequest -Port $entry.port -OS $entry.os
						$global:Result += invoke-websisypherequest -Port $entry.port -OS $entry.os
					}
				}
				If (($entry.port) -and ($entry.country)) {
					If ($multithreading) {
						$port = $entry.port
						$country = $entry.country
						start-rsjob -ModulesToImport $currentmodulepath -scriptblock {invoke-websisypherequest -Port $using:port -Country $using:country} | out-null
					} Else {
						$global:Result += invoke-websisypherequest -Port $entry.port -Country $entry.country
					}
				}
				If (($entry.os) -and ($entry.country) -and ($entry.port)) {
					If ($multithreading) {
						$port = $entry.port
						$os = $entry.os
						$country = $entry.country
						start-rsjob -ModulesToImport $currentmodulepath -scriptblock {invoke-websisypherequest -OS $using:os -Country $using:country -port $using:port} | out-null
					} Else {
						$global:Result += invoke-websisypherequest -OS $entry.os -Country $entry.country -port $entry.port
					}
				}
			}
		}
	} Else {
		If ($ip) {
			$global:Result += invoke-websisypherequest -IP $ip
		} ElseIf ($port -and -not ($os -or $country)) {
			$global:Result += invoke-websisypherequest -Port $port
		} Else {
			If (($port) -and ($os)) {
				$global:Result += invoke-websisypherequest -Port $port -OS $OS
			}
			If (($port) -and ($country)) {
				$global:Result += invoke-websisypherequest -Port $port -Country $country
			}
			If (($os) -and ($country) -and ($port)) {
				$global:Result += invoke-websisypherequest -OS $os -Country $country -port $port
			}
		}
	}
  } End {
	If ($multithreading) {
		get-rsjob | wait-rsjob | out-null
		$global:Result = get-rsjob | receive-rsjob
		get-rsjob | remove-rsjob | out-null
		write-warning "when using multithreading option some of your requests could be blocked because of rate limiting feature used by sisyphe.io (no more than 10 requests at the same time)"
		return $global:Result.GetEnumerator() | sort-object -property Name
	} Else {
		return $global:Result.GetEnumerator() | sort-object -property Name
	}
  }
}

function Invoke-WebSisypheRequest {
  [cmdletbinding()]
  Param (
  [parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,Mandatory=$false)]
    [ValidatePattern("(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])")]
    [string[]]$IP,
  [parameter(Mandatory=$false)]
    [ValidatePattern("([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-3][0-9]|6553[0-5])")]
	[string[]]$Port,
  [parameter(Mandatory=$false)]
    [ValidatePattern("\w+")]
	[string[]]$OS,
  [parameter(Mandatory=$false)]
    [ValidatePattern("([a-zA-Z]){2}")]
	[string[]]$Country
  )
 <#
	.SYNOPSIS 
	Get IP information from sisyphe.io web service

	.DESCRIPTION
	send HTTP request to sisyphe.io web service and convert back JSON information to an hashtable

	.PARAMETER IP
	-IP string
	look for an ip address in sisyphe database

	.PARAMETER port
	-Port string
	look for an tcp or udp port in sisyphe database. Could be used with other information (os and/or country)
	
	.PARAMETER os
	-Port string
	look for an OS in sisyphe database. Must be be used with "port" parameter and could be used with "country" parameter
	
	.PARAMETER country
	-Port string
	look for an country in sisyphe database. Must be be used with "port" parameter and could be used with "os" parameter
	
	.OUTPUTS
	TypeName: System.Collections.Hashtable
	
	Name                           Value
	----                           -----
	ip-31.13.24.4                  {geoloc, ip, resolver, threatlist...}

	.EXAMPLE
	C:\PS> Invoke-WebSisypheRequest -ip 192.168.1.5
	C:\PS> Invoke-WebSisypheRequest -port 3389
	C:\PS> Invoke-WebSisypheRequest -port 3389 -os windows -country FR
#>

	Begin {
		$global:sisypheurl = "https://www.sisyphe.io/search/?query="
	} Process {
			If ($IP) {
				$request = "$($IP)"
				$hname = "ip-$($IP)"
			} ElseIf ($Port -and -not ($OS -or $country)) {
				$request = "port:$($Port)"
				$hname = "port-$($Port)"
			} Else {
				If (($Port) -and ($OS)) {
					$request = "port:$($Port)+os:$($OS)"
					$hname = "port-$($Port)_os-$($OS)"
				}
				If (($Port) -and ($Country)) {
					$request = "port:$($Port)+country:$($Country)"
					$hname = "port-$($Port)_country-$($Country)"
				}
				If (($OS) -and ($Country) -and ($Port)) {
					$request = "country:$($Country)+os:$($OS)+port:$($Port)"
					$hname = "country-$($Country)_os-$($OS)_port-$($Port)"
				}
			}
			try {
				$sisypheresult = invoke-webrequest "$($global:sisypheurl)$($request)&output=json"
			} catch {
				if ($debug -or $verbose) {
					write-warning "Not able to use Sisyphe online service - KO"
					write-warning "Note : proxified connection not managed currently"
					write-warning "Error Type: $($_.Exception.GetType().FullName)"
					write-warning "Error Message: $($_.Exception.Message)"
					write-warning "HTTP error code:$($_.Exception.Response.StatusCode.Value__)"
					write-warning "HTTP error message:$($_.Exception.Response.StatusDescription)"
				}
				$errorvalue = @{}
				$errorvalue.add("code:$($_.Exception.Response.StatusCode.Value__)","info:$($_.Exception.Response.StatusDescription)")
			}
			if (-not $errorvalue) {
				try {
					
					$temp = $sisypheresult.Content | convertfrom-json
					$temp = Fix-JSONHash $temp
				} catch {
					if ($debug -or $verbose) {
						write-warning "unable to convert result into a powershell object - json error"
						write-warning "Error Type: $($_.Exception.GetType().FullName)"
						write-warning "Error Message: $($_.Exception.Message)"
					}
					$errorvalue = @{}
					if ($sisypheresult.Content -match "Enough is enough"){
						$errorvalue.add("rate limit exceeded","error message : enough is enough")
						if ($debug -or $verbose) {
							write-warning "rate limit exceeded - error message : enough is enough"
						}
					} else {
						$errorvalue.add("$($_.Exception.GetType().FullName)","$($_.Exception.Message) : $($sisypheresult.Content)")
					}
				}
			}
	} End {
		if ($temp) {return @{"$($hname)"= $temp}}
		if ($errorvalue) {return @{"$($hname)"= $errorvalue}}
	}
}

function Fix-JSONHash {
    [cmdletbinding()]
	param(
        [parameter(Mandatory=$true)]
		$ObjToFix
    )
<#
	.SYNOPSIS 
	fix convertfrom-json issue

	.DESCRIPTION
	fix convertfrom-json issue

#>
		$hash = @{}
		$keys = $ObjToFix | gm -MemberType NoteProperty | select -exp Name
		$keys | foreach-object {
			$key=$_
			$obj=$ObjToFix.$($_)
			if($obj -match "@{"){
				$nesthash=Fix-JSONHash $obj
				$hash.add($key,$nesthash)
			} else {
			   $hash.add($key,$obj)
			}
		}
		return $hash
}

Function Get-ScriptDirectory {
<#
	.SYNOPSIS 
	retrieve current script directory

	.DESCRIPTION
	retrieve current script directory

#>
	#$Invocation = (Get-Variable MyInvocation -Scope 1).Value
	#Split-Path $Invocation.MyCommand.Path
	Split-Path -Parent $PSCommandPath
}

Export-ModuleMember -Function Invoke-WebSisypheRequest, Fix-JSONHash, Get-SisypheInfo, Get-ScriptDirectory 
