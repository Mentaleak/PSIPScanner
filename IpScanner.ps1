 
 
function new-IPRange(){ 
	param( 
		[parameter(Mandatory=$true, ParameterSetName="Octets")] 
		[Alias("AS")][ValidateRange(0,255)][Int]$octetAStart, 
		[Alias("BS")][ValidateRange(0,255)][Int]$octetBStart, 
		[Alias("CS")][ValidateRange(0,255)][Int]$octetCStart, 
		[Alias("DS")][ValidateRange(0,255)][Int]$octetDStart, 
		[Alias("AE")][ValidateRange(0,255)][Int]$octetAend, 
		[Alias("BE")][ValidateRange(0,255)][Int]$octetBend, 
		[Alias("CE")][ValidateRange(0,255)][Int]$octetCend, 
		[Alias("DE")][ValidateRange(0,255)][Int]$octetDend, 
		 
		[parameter(Mandatory=$true, ParameterSetName="Mask")] 
		[ValidateScript({$octets = $_.split(".") 
				if($octets.count -ne 4){return $false} 
				foreach($octet in $octets){ 
					if($octet -notmatch "^\d+$"){return $false} 
					if([int]$octet -lt 0 -or [int]$octet -gt 255){return $false} 
				} 
		return $true })] [string]$IP, 
		[ValidateScript({$octets = $_.split(".") 
				if($octets.count -ne 4){return $false} 
				foreach($octet in $octets){ 
					if($octet -notmatch "^\d+$"){return $false} 
					if([int]$octet -lt 0 -or [int]$octet -gt 255){return $false} 
				} 
		return $true })] [string]$Mask, 
		 
		[parameter(Mandatory=$true, ParameterSetName="Range")] 
		[ValidateScript({$octets = $_.split(".") 
				if($octets.count -ne 4){return $false} 
				foreach($octet in $octets){ 
					if($octet -notmatch "^\d+$"){return $false} 
					if([int]$octet -lt 0 -or [int]$octet -gt 255){return $false} 
				} 
		return $true })] [string]$IPBase, 
		[ValidateScript({$octets = $_.split(".") 
				if($octets.count -ne 4){return $false} 
				foreach($octet in $octets){ 
					if($octet -notmatch "^\d+$"){return $false} 
					if([int]$octet -lt 0 -or [int]$octet -gt 255){return $false} 
				} 
		return $true })] [string]$IPMax 
	) 
	 
	switch ($PsCmdlet.ParameterSetName) 
	{ 
		"Octets" { 
			 
			if((!($octetAend -ge $octetAStart)) -or (!($octetBend -ge $octetBStart)) -or (!($octetCend -ge $octetCStart)) -or (!($octetDend -ge $octetDStart))) 
			{ 
				Write-Error "The Start of an Octet cannot be after the end" 
				return $null 
			} 
			 
			$ips=@() 
			for($A=$octetAStart; $A -le $octetAend; $A++){ 
				for($B=$octetBStart; $B -le $octetBend; $B++){ 
					for($C=$octetCStart; $C -le $octetCend; $C++){ 
						for($D=$octetDStart; $D -le $octetDend; $D++){ 
							$ipS+="$($A).$($B).$($C).$($D)" 
							 
						} 
						 
					} 
				} 
			} 
			 
			return $ips 
		} 
		 
		"Mask" { 
			$IPOctets = $ip.split(".") 
			$MaskOctets = $Mask.split(".") 
			[int]$MaskACount=255-[int]$MaskOctets[0]-[int]$IPOctets[0] 
			[int]$MaskBCount=255-[int]$MaskOctets[1]-[int]$IPOctets[1] 
			[int]$MaskCCount=255-[int]$MaskOctets[2]-[int]$IPOctets[2] 
			[int]$MaskDCount=255-[int]$MaskOctets[3]-[int]$IPOctets[3] 
			if($MaskACount -lt 0){$MaskACount =0} 
			if($MaskBCount -lt 0){$MaskBCount =0} 
			if($MaskCCount -lt 0){$MaskCCount =0} 
			if($MaskDCount -lt 0){$MaskDCount =0} 
			 
			$ips=@() 
			for($A=0; $A -le $MaskACount; $A++){ 
				for($B=0; $B -le $MaskBCount; $B++){ 
					for($C=0; $C -le $MaskCCount; $C++){ 
						for($D=0; $D -le $MaskDCount; $D++){ 
							$ipS+="$($A+[int]$IPOctets[0]).$($B+[int]$IPOctets[1]).$($C+[int]$IPOctets[2]).$($D+[int]$IPOctets[3])" 
							 
						} 
						 
					} 
				} 
			} 
			 
			return $ips 
			 
			 
		} 
		"Range" { 
			$IPOctets = $ipbase.split(".") 
			$MaxOctets = $ipmax.split(".") 
			for($i=0; $i -lt 4; $i++){ 
				if($MaxOctets[$i] -lt $IPOctets[$i]){ 
					$MaxOctets[$i] = $IPOctets[$i] 
				} 
			} 
			 
			 
			$ips=@() 
			for($A=[int]$IPOctets[0]; $A -le $MaxOctets[0]; $A++){ 
				for($B=[int]$IPOctets[1]; $B -le $MaxOctets[1]; $B++){ 
					for($C=[int]$IPOctets[2]; $C -le $MaxOctets[2]; $C++){ 
						for($D=[int]$IPOctets[3]; $D -le $MaxOctets[3]; $D++){ 
							$ipS+="$($A).$($B).$($C).$($D)" 
							 
						} 
						 
					} 
				} 
			} 
			 
			return $ips 
			 
			 
		} 
	} 
	 
} 
 
 
function get-netinfo(){ 
	param( 
		[parameter(Mandatory=$true)][ValidateScript({$octets = $_.split(".") 
				if($octets.count -ne 4){return $false} 
				foreach($octet in $octets){ 
					if($octet -notmatch "^\d+$"){return $false} 
					if([int]$octet -lt 0 -or [int]$octet -gt 255){return $false} 
				} 
		return $true })] [string]$IP 
	) 
	 
	$IPtest = Test-NetConnection $IP 
	 
	if($IPtest.PingSucceeded) 
	{ 
		$dnsinfo=[System.Net.Dns]::gethostentry($IP) 
		$ipinfo=[pscustomobject]@{ 
			IP=$IP 
			Hostname=$dnsinfo.hostname 
			DNSInfo=$dnsinfo 
			NetConnection=$IPtest 
			HTTP_80=(TEST-NetConnection $IP -CommonTCPPort HTTP -InformationLevel Quiet) 
			HTTPS_443=(TEST-NetConnection $IP -Port 443 -InformationLevel Quiet) 
			SSH_22=(TEST-NetConnection $IP -Port 22 -InformationLevel Quiet) 
			Telnet_23=(TEST-NetConnection $IP -Port 23 -InformationLevel Quiet) 
			SMB_445=(TEST-NetConnection $IP -CommonTCPPort SMB -InformationLevel Quiet) 
			RDP_3389=(TEST-NetConnection $IP -CommonTCPPort RDP -InformationLevel Quiet) 
			WinRM_5985=(TEST-NetConnection $IP -CommonTCPPort WINRM -InformationLevel Quiet) 
		} 
		$protocols=@() 
		if($ipinfo.http_80){$protocols+="HTTP"} 
		if($ipinfo.https_443){$protocols+="HTTPS"} 
		if($ipinfo.SSH_22){$protocols+="SSH"} 
		if($ipinfo.Telnet_23){$protocols+="TELNET"} 
		if($ipinfo.SMB_445){$protocols+="SMB"} 
		if($ipinfo.RDP_3389){$protocols+="RDP"} 
		if($ipinfo.WINRM_5985){$protocols+="WINRM"} 
		Add-Member -InputObject $ipinfo -MemberType NoteProperty -Name "Protocols" -Value $protocols 
		$defaultDisplaySet=@("IP","HostName", "Protocols") 
		$defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet (‘DefaultDisplayPropertySet’,[string[]]$defaultDisplaySet) 
		$PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet) 
		$IPinfo | Add-Member MemberSet PSStandardMembers $PSStandardMembers 
		 
		Return $IPinfo 
	} 
	return $null 
	 
	 
} 


function new-ScanIP(){
param(
    [string[]]$ips
)
$results=@() 
$jobs=@()
write-host "There are $($IPS.count) Jobs to be created"
$jobcounter=0
foreach($ip in $IPS){
$jobcounter++
    write-progress -activity "Creating Jobs" -status "$jobcounter of $($IPS.count)" -percentComplete (($jobcounter/$($IPS.count))*100)
	$Jobs+=start-job -name "get-netinfo_$($ip)" -ScriptBlock { 
		param([string]$ip) 
		function get-netinfo(){ 
			param( 
				[parameter(Mandatory=$true)][ValidateScript({$octets = $_.split(".") 
						if($octets.count -ne 4){return $false} 
						foreach($octet in $octets){ 
							if($octet -notmatch "^\d+$"){return $false} 
							if([int]$octet -lt 0 -or [int]$octet -gt 255){return $false} 
						} 
				return $true })] [string]$IP 
			) 
			 
			$IPtest = Test-NetConnection $IP 
			 
			if($IPtest.PingSucceeded) 
			{ 
				$dnsinfo=[System.Net.Dns]::gethostentry($IP) 
				$ipinfo=[pscustomobject]@{ 
					IP=$IP 
					Hostname=$dnsinfo.hostname 
					DNSInfo=$dnsinfo 
					NetConnection=$IPtest 
					HTTP_80=(TEST-NetConnection $IP -CommonTCPPort HTTP -InformationLevel Quiet) 
					HTTPS_443=(TEST-NetConnection $IP -Port 443 -InformationLevel Quiet) 
					SSH_22=(TEST-NetConnection $IP -Port 22 -InformationLevel Quiet) 
					Telnet_23=(TEST-NetConnection $IP -Port 23 -InformationLevel Quiet) 
					SMB_445=(TEST-NetConnection $IP -CommonTCPPort SMB -InformationLevel Quiet) 
					RDP_3389=(TEST-NetConnection $IP -CommonTCPPort RDP -InformationLevel Quiet) 
					WinRM_5985=(TEST-NetConnection $IP -CommonTCPPort WINRM -InformationLevel Quiet) 
				} 
				$protocols=@() 
				if($ipinfo.http_80){$protocols+="HTTP"} 
				if($ipinfo.https_443){$protocols+="HTTPS"} 
				if($ipinfo.SSH_22){$protocols+="SSH"} 
				if($ipinfo.Telnet_23){$protocols+="TELNET"} 
				if($ipinfo.SMB_445){$protocols+="SMB"} 
				if($ipinfo.RDP_3389){$protocols+="RDP"} 
				if($ipinfo.WINRM_5985){$protocols+="WINRM"} 
				Add-Member -InputObject $ipinfo -MemberType NoteProperty -Name "Protocols" -Value $protocols 
				$defaultDisplaySet=@("IP","HostName", "Protocols") 
				$defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet (‘DefaultDisplayPropertySet’,[string[]]$defaultDisplaySet) 
				$PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet) 
				$IPinfo | Add-Member MemberSet PSStandardMembers $PSStandardMembers 
				 
				Return $IPinfo 
			} 
			return $null 
			 
			 
		} 
		return get-netinfo $ip 
	}-ArgumentList ($ip) 
} 


$stopwatch =  [system.diagnostics.stopwatch]::StartNew()
$lastprocesscount=(get-job |where {$_.name -match "get-netinfo" -and $_.State -eq "Running"}).count
while((get-job |where {$_.name -match "get-netinfo"}).State -contains "Running"){
    $RunningProcesseCount=(get-job |where {$_.name -match "get-netinfo" -and $_.State -eq "Running"}).count
    $processChange=($lastprocesscount-$RunningProcesseCount)
    if($processChange -gt 0){
    $proctime=$stopwatch.Elapsed.TotalSeconds
    $estproctime=$stopwatch.Elapsed.TotalSeconds / ($IPS.count - $RunningProcesseCount)
    #Write-Host "$proctime to complete $processChange processes; $estproctime ea"
    $timeremaining =$estproctime * $RunningProcesseCount
    #Write-Host "$RunningProcesseCount processes remaining totaling $timeremaining"
    $timeRem="$([math]::Truncate($timeremaining/60).ToString("00")):$(($timeremaining % 60).ToString("00"))"
    #write-host "Time Remaining: $timeRem"
    }
    $completion=(1-($RunningProcesseCount/$IPS.count))*100
    Write-Progress -Activity "Checking IP Addresses $($RunningProcesseCount) of $($IPS.count) Remaining" -Status "Estimated Time Remaining: $timeRem" -PercentComplete $completion
    start-sleep -Seconds 1
$lastprocesscount=$RunningProcesseCount
}

Write-host $stopwatch.elapsed.TotalSeconds

foreach($job in $jobs){
$results+=Receive-Job $job
}

return $results

}
 
 
  
