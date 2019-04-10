# Utilities for Outlook Rest API

# Escapes string to Json
function Escape-StringToJson
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$String
    )

    Process
    {
        # ConvertTo-Json escapes strings automatically
        $String | ConvertTo-Json
    }
}

# Calls Outlook Rest API
function Call-OutlookAPI
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        $Request,
        [Parameter(Mandatory=$True)]
        [String]$Command,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Get','Post','Patch','Delete')]
        [String]$Method="Get",
        [Parameter(Mandatory=$False)]
        [ValidateSet('v1.0','v2.0','beta')]
        [String]$Api="v2.0"
    )

    Process
    {
    
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Accept" = "text/*, multipart/mixed, application/xml, application/json; odata.metadata=none"
            "Content-Type" = "application/json; charset=utf-8"
            "X-AnchorMailbox" = (Read-Accesstoken $AccessToken).upn
            "Prefer" = 'exchange.behavior="ActivityAccess"'
        }

    
        $url="https://outlook.office.com/api/$Api/$Command"    

        if($Method -ne "Post" -and $Method -ne "Patch")
        {
            $response=Invoke-RestMethod -Uri $Url -Method $Method -Headers $headers 
        }
        else
        {
            $response=Invoke-RestMethod -Uri $Url -Method $Method -Headers $headers -Body $Request
        }
        $response.value
    }
}



