# This file contains utility functions for Admin operations.

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
        [String]$Method,
        [Parameter(Mandatory=$False)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession
    )
    Process
    {
        $headers=@{}

        # If we got WebSession, no need for Access Token
        if($WebSession -eq $null)
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://admin.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            
            # Set the headers
            $headers["Authorization"] = "Bearer $AccessToken"

            # Create a new web session
            $WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        }

        # Set cookie maximun size the returned cookies exceeds the normal maximum size 4096
        $WebSession.Cookies.MaxCookieSize=65536

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method $Method -Uri "https://admin.microsoft.com/$Url" -Headers $headers -Body $body -WebSession $WebSession

        $response
    }
}
