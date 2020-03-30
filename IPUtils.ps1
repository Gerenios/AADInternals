# Some ip related utility functions

# Gets the ip location info from ipgeolocationapi.com
function Get-IPLocationInfo
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName="IPText", Mandatory=$true)]
        [String]$IpAddress,
        [Parameter(ParameterSetName="Host", Mandatory=$true)]
        [String]$HostName,
        [Parameter(ParameterSetName="IPBytes", Mandatory=$true)]
        [byte[]]$IpBytes,
        [switch]$Short
    )
    Process
    {
        if($IpBytes -ne $null)
        {
            if($IpBytes.Length -ne 4)
            {
                Throw "IpBytes must be exactly 4 bytes long!"
            }
            $IpAddress = "$($IpBytes[0]).$($IpBytes[1]).$($IpBytes[2]).$($IpBytes[3])"
        }
        elseif(![string]::IsNullOrEmpty($HostName))
        {
            $IpAddresses = Resolve-DnsName -Name $HostName -ErrorAction SilentlyContinue
            $entry = $null
            if($IpAddresses.Count -gt 1)
            {
                $entry = $IpAddresses[$IpAddresses.count-1]
            }
            else
            {
                $entry = $IpAddresses
            }
            if([string]::IsNullOrEmpty($entry.IPAddress))
            {
                if(![string]::IsNullOrEmpty($entry.IP4Address))
                {
                    $IpAddress = $entry.IP4Address
                }
                else
                {
                    Throw "No ipv address found for $HostName"
                }
            }
            else
            {
                $IpAddress = $entry.IPAddress
            }
        }

        $response = Invoke-RestMethod -Uri "https://api.ipgeolocationapi.com/geolocate/$IpAddress" -Headers @{"Accept" = "application/json; charset=utf-8"}

        if($Short)
        {
            return @($response.name, $response.subregion, $response.region)
        }
        else
        {
            return $response
        }
    }
}