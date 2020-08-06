# This script contains utility functions for MSGraph API at https://graph.microsoft.com



# Calls the provisioning SOAP API
function Call-MSGraphAPI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$API,
        [Parameter(Mandatory=$False)]
        [String]$ApiVersion="beta",
        [Parameter(Mandatory=$False)]
        [String]$Method="GET",
        [Parameter(Mandatory=$False)]
        $Body,
        [Parameter(Mandatory=$False)]
        $Headers,
        [Parameter(Mandatory=$False)]
        [String]$QueryString,
        [Parameter(Mandatory=$False)]
        [int]$MaxResults=1000
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

        # Create the url
        $url = "https://graph.microsoft.com/$($ApiVersion)/$($API)?$(if(![String]::IsNullOrEmpty($QueryString)){"&$QueryString"})"

        # Call the API
        $response = Invoke-RestMethod -Uri $url -ContentType "application/json" -Method $Method -Body $Body -Headers $Headers

        # Check if we have more items to fetch
        if($response.psobject.properties.name -match '@odata.nextLink')
        {
            $items=$response.value.count

            # Loop until finished or MaxResults reached
            while(($url = $response.'@odata.nextLink') -and $items -lt $MaxResults)
            {
                # Return
                $response.value
                     
                $response = Invoke-RestMethod -Uri $url -ContentType "application/json" -Method $Method -Body $Body -Headers $Headers
                $items+=$response.value.count
            }

            # Return
            $response.value
            
        }
        else
        {

            # Return
            if($response.psobject.properties.name -match "Value")
            {
                return $response.value 
            }
            else
            {
                return $response
            }
        }

    }
}

