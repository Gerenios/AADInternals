# This script contains utility functions for Graph API at https://graph.windows.net
# Office 365 / Azure AD v2, a.k.a. AzureAD module uses this API



# Calls the provisioning SOAP API
function Call-GraphAPI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Command,
        [Parameter(Mandatory=$False)]
        [String]$ApiVersion="1.61-internal",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Put','Get','Post','Delete','Patch')]
        [String]$Method="Get",
        [Parameter(Mandatory=$False)]
        $Body,
        [Parameter(Mandatory=$False)]
        $Headers,
        [Parameter(Mandatory=$False)]
        [String]$QueryString
    )
    Process
    {
        # Set the required variables
        $TenantID = (Read-Accesstoken $AccessToken).tid

        if($Headers -eq $null)
        {
            $Headers=@{}
        }
        $Headers["Authorization"] = "Bearer $AccessToken"

        # Call the API
        $response = Invoke-RestMethod -Uri "https://graph.windows.net/$TenantId/$Command`?api-version=$ApiVersion$(if(![String]::IsNullOrEmpty($QueryString)){"&$QueryString"})" -ContentType "application/json; charset=utf-8" -Method $Method -Body $Body -Headers $Headers -ErrorAction SilentlyContinue

        # Return
        if($response.value)
        {
            return $response.value 
        }
        else
        {
            return $response
        }

    }
}

