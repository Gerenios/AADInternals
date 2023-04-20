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
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "00000006-0000-0ff1-ce00-000000000000"

        $headers=@{
            "x-ms-console-preferred-location" = $PreferredLocation
            "Content-Type" =                    "application/json"
            "Authorization" =                   "Bearer $AccessToken"
        }

        $body = '{"properties":{"osType":"linux"}}'

        $response = Invoke-RestMethod -UseBasicParsing -Uri "https://management.azure.com/providers/Microsoft.Portal/consoles/default?api-version=2020-04-01-preview" -Method Put -Body $body -Headers $headers -ErrorAction SilentlyContinue
        
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

        $response = Invoke-RestMethod -UseBasicParsing -Uri "$url/authorize" -Method Post -Body $body -Headers $headers
        
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

        $response = Invoke-RestMethod -UseBasicParsing -Uri "$url/terminals?cols=$cols&rows=$rows&version=2019-01-01&shell=$Shell" -Method Post -Body $body -Headers $headers
        
        # return
        return $response

    }
}


# Gets user's cloud shell settings
# Jan 1st 2023
function Get-UserCloudShellSettings
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Create headers
        $headers=@{
            "Content-Type" =  "application/json"
            "Authorization" = "Bearer $AccessToken"
        }

        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Uri "https://management.azure.com/providers/Microsoft.Portal/userSettings/cloudconsole?api-version=2020-04-01-preview" -Headers $headers
        }
        catch{}
        
        # return
        return $response

    }
}

# Gets user's cloud shell settings
# Jan 1st 2023
function Set-UserCloudShellSettings
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$StorageAccountId,
        [Parameter(Mandatory=$True)]
        [String]$FileShareName
    )
    Process
    {
        # Create headers
        $headers=@{
            "Content-Type" =  "application/json"
            "Authorization" = "Bearer $AccessToken"
        }

        try
        {
            # Create the body
            $body = @{
                "properties" = @{
                    "preferredOsType" = "Linux"
                    "preferredLocation" = "westeurope"
                    "storageProfile" = @{
                      "storageAccountResourceId" = $StorageAccountId
                      "fileShareName" = $fileShareName
                      "diskSizeInGB" = 5
                    }
                    "terminalSettings" = @{
                      "fontSize" = "Medium"
                      "fontStyle" = "Monospace"
                    }
                    "preferredShellType" = "pwsh"
                    "vnetSettings" = @{}
                    "networkType" = "Default"
                }
            }

            $response = Invoke-RestMethod -UseBasicParsing -Uri "https://management.azure.com/providers/Microsoft.Portal/userSettings/cloudconsole?api-version=2020-04-01-preview" -Headers $headers -Method Put -Body $($body | ConvertTo-Json -Depth 4)
        }
        catch
        {}
        
        # return
        return $response

    }
}

# Remove user's cloud shell settings
# Jan 1st 2023
function Remove-UserCloudShellSettings
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Create headers
        $headers=@{
            "Content-Type" =  "application/json"
            "Authorization" = "Bearer $AccessToken"
        }

        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Uri "https://management.azure.com/providers/Microsoft.Portal/userSettings/cloudconsole?api-version=2020-04-01-preview" -Headers $headers -Method Delete
        }
        catch
        {}
        
        # return
        return $response

    }
}