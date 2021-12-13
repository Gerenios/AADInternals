# This file contains utility functions for MS Partner operations.

# Invoke Admin API
# Dec 11th 2021
function Invoke-AdminAPI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        $Body,
        [Parameter(Mandatory=$True)]
        [String]$Url,
        [Parameter(Mandatory=$True)]
        [ValidateSet('Get','Post','Patch','Put','Delete')]
        [String]$Method
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://admin.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        # Create a web session because the returned cookies exceeds the normal maximum size 4096
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $session.Cookies.MaxCookieSize=65536

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method $Method -Uri "https://admin.microsoft.com/$Url" -Headers $headers -Body $body -WebSession $session

        $response
    }
}
