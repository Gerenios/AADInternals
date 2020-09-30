# Creates a new Cloud Shell
# Sep 8th 2020
function New-CloudShell
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$PreferredLocation="westeurope"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"

        $headers=@{
            "x-ms-console-preferred-location" = $PreferredLocation
            "Content-Type" =                    "application/json"
            "Authorization" =                   "Bearer $AccessToken"
        }

        $body = '{"properties":{"osType":"linux"}}'

        $response = Invoke-RestMethod -Uri "https://management.azure.com/providers/Microsoft.Portal/consoles/default?api-version=2020-04-01-preview" -Method Put -Body $body -Headers $headers -ErrorAction SilentlyContinue
        
        # return
        return $response.properties

    }
}

# Gets cloud shell authorization token
# Sep 8th 2020
function Get-CloudShellAuthToken
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Url
    )
    Process
    {
        # Create headers
        $headers=@{
            "Content-Type" =  "application/json"
            "Authorization" = "Bearer $AccessToken"
        }

        # Empty body
        $body = '{}'

        # Fix the url
        $url = $url.Replace(":443","")

        $response = Invoke-RestMethod -Uri "$url/authorize" -Method Post -Body $body -Headers $headers
        
        # return
        return $response.token

    }
}

# Gets cloud shell settings
# Sep 8th 2020
function Get-CloudShellSettings
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Url,
        [Parameter(Mandatory=$False)]
        [String]$Shell="pwsh"
    )
    Process
    {
        # Create headers
        $headers=@{
            "Content-Type" =  "application/json"
            "Authorization" = "Bearer $AccessToken"
        }

        # Get the window size
        $rows = [console]::WindowHeight
        $cols = [console]::WindowWidth

        if($Shell -ne "Bash")
        {
            $Shell = "pwsh"
        }

        # Empty body
        $body = '{}'

        # Fix the url
        $url = $url.Replace(":443","")

        $response = Invoke-RestMethod -Uri "$url/terminals?cols=$cols&rows=$rows&version=2019-01-01&shell=$Shell" -Method Post -Body $body -Headers $headers
        
        # return
        return $response

    }
}