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

        Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://teams.microsoft.com/api/authsvc/v1.0/authz" -Headers @{"Authorization"="Bearer $AccessToken"}

    }
}

# Gets Teams recipients info
# May 11th 2021
function Get-TeamsRecipients
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String[]]$Recipients
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        # Must be a proper array, so add element if only one provided
        if($Recipients.Count -eq 1)
        {
            $Recipients += ""
        }
        
        # Get the settings
        $teamsSettings = Get-TeamsInformation -AccessToken $AccessToken
        $chatService =   $teamsSettings.regionGtms.chatService
        $apiUrl =        $teamsSettings.regionGtms.middleTier
        $skypeToken =    $teamsSettings.tokens.SkypeToken

        # Construct the headers
        $headers = @{
            "Authorization" =       "Bearer $AccessToken"
            "User-Agent" =          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "Authentication" =      "skypetoken=$skypeToken"
            "x-ms-client-version" = "27/1.0.0.2020101241"
        }

        
        $recipientInfo = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$apiUrl/beta/users/fetch?isMailAddress=true&canBeSmtpAddress=false&enableGuest=true&includeIBBarredUsers=true&skypeTeamsInfo=true" -Headers $headers -Body ([String[]]$Recipients|ConvertTo-Json) -ContentType "application/json"
        $msgRecipients = $recipientInfo.Value
            
        return $msgRecipients
    }
}