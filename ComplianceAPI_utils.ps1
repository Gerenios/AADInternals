# This file contains utility functions for Compliance API

# Invokes request for the given compliance API call
# Aug 31st 2021
function Invoke-ComplianceAPIRequest
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
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
        $url = "https://compliance.microsoft.com/api/$api"

        $headers["Authorization"] = "Bearer $AccessToken"

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