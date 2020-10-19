# Gets Teams service information
# Oct 16th 2020
function Get-TeamsInformation
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        Invoke-RestMethod -Method Post -Uri "https://teams.microsoft.com/api/authsvc/v1.0/authz" -Headers @{"Authorization"="Bearer $AccessToken"}

    }
}