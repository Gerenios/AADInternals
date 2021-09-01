# This file contains utility functions for Compliance API

# Invokes request for the given compliance API call
# Aug 31st 2021
function Invoke-ComplianceAPIRequest
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [psobject]$Cookies,
        [Parameter(Mandatory=$True)]
        [String]$api,
        [Parameter(Mandatory=$False)]
        [String]$Method = "Get",
        [Parameter(Mandatory=$False)]
        [String]$Body = $null,
        [Parameter(Mandatory=$False)]
        [String]$ContentType = "application/json; charset=utf-8",
        [Parameter(Mandatory=$False)]
        [Hashtable]$Headers=@{}
    )
    Process
    {
        # Check the cookies
        if(!($Cookies.'XSRF-TOKEN' -and $Cookies.sccauth))
        {
            Throw "XSRF-TOKEN and sccauth cookies required!"
        }

        $url = "https://compliance.microsoft.com/api/$api"

        # First, add XSRF-TOKEN to headers
        $Headers["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($Cookies.'XSRF-TOKEN')

        # Create a web session for the cookies
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $session.Cookies.Add([System.Net.Cookie]::new("XSRF-TOKEN",$Cookies.'XSRF-TOKEN',"/","compliance.microsoft.com"))
        $session.Cookies.Add([System.Net.Cookie]::new("sccauth",   $Cookies.sccauth     ,"/","compliance.microsoft.com"))
        $session.Cookies.MaxCookieSize=65536

        # Invoke the command
        if($Method -eq "Put" -or $Method -eq "Post")
        {
            Invoke-RestMethod -UseBasicParsing -Method $Method -Uri $url -Headers $Headers -WebSession $session -Body $body -ContentType $ContentType
        }
        else
        {
            Invoke-RestMethod -UseBasicParsing -Method $Method -Uri $url -Headers $Headers -WebSession $session -ContentType $ContentType
        }
    }
}