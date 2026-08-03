# This file contains utility functions for Teams Admin (Cs) operations.

# Invokes the internal Teams Admin (Cs) API
# Aug 1st 2026, Stefan Wey
function Invoke-TeamsAdminAPI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Url,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Get','Post','Put','Patch')]
        [String]$Method="Get",
        [Parameter(Mandatory=$False)]
        $Body
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "48ac35b8-9aa8-4d74-927d-1f4a14a0b239" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
        }

        if($Body)
        {
            Invoke-RestMethod -UseBasicParsing -Method $Method -Uri "https://api.interfaces.records.teams.microsoft.com/$Url" -Headers $headers -Body ($Body | ConvertTo-Json -Depth 5) -ContentType "application/json"
        }
        else
        {
            Invoke-RestMethod -UseBasicParsing -Method $Method -Uri "https://api.interfaces.records.teams.microsoft.com/$Url" -Headers $headers
        }
    }
}
