# This file contains functions for MS Commerce

# List self-service-purchase products
# Aug 27th 2021
function Get-SelfServicePurchaseProducts
{
<#
    .SYNOPSIS
    Lists the status of self-service purchase products

    .DESCRIPTION
    Lists the status of self-service purchase products

    .Parameter AccessToken
    The access token used to get the status of the self-service purchase products.

    .Example
    PS C:\>Get-AADIntAccessTokenForMSCommerce -SaveToCache
    PS C:\>Get-AADIntSelfServicePurchaseProducts

    Product                                          Id           Status 
    -------                                          --           ------ 
    Windows 365 Enterprise                           CFQ7TTC0HHS9 Enabled
    Windows 365 Business with Windows Hybrid Benefit CFQ7TTC0HX99 Enabled
    Windows 365 Business                             CFQ7TTC0J203 Enabled
    Power Automate per user                          CFQ7TTC0KP0N Enabled
    Power Apps per user                              CFQ7TTC0KP0P Enabled
    Power Automate RPA                               CFQ7TTC0KXG6 Enabled
    Power BI Premium (standalone)                    CFQ7TTC0KXG7 Enabled
    Visio Plan 2                                     CFQ7TTC0KXN8 Enabled
    Visio Plan 1                                     CFQ7TTC0KXN9 Enabled
    Project Plan 3                                   CFQ7TTC0KXNC Enabled
    Project Plan 1                                   CFQ7TTC0KXND Enabled
    Power BI Pro                                     CFQ7TTC0L3PB Enabled
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "aeb86249-8ea3-49e2-900b-54cc8e308f85" -ClientId "3d5cffa9-04da-4657-8cab-c7f074657cad"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://licensing.m365.microsoft.com/v1.0/policies/AllowSelfServicePurchase/products" -Headers $headers

        # Return the products
        foreach($item in $response.items)
        {
            New-Object psobject -Property ([ordered]@{
                "Product"   = $item.productName
                "Id"        = $item.productID
                "Status"    = $item.policyValue
            })
        }
        
    }
}

# Change the status of self-service-purchase products
# Aug 27th 2021
function Set-SelfServicePurchaseProduct
{
<#
    .SYNOPSIS
    Change the status of the given self-service purchase product

    .DESCRIPTION
    Change the status of the given self-service purchase product

    .Parameter AccessToken
    The access token used to change the status of the self-service purchase product.

    .Example
    PS C:\>Get-AADIntAccessTokenForMSCommerce -SaveToCache
    PS C:\>Set-AADIntSelfServicePurchaseProduct -Id CFQ7TTC0L3PB -Enabled $false

    Product      Id           Status 
    -------      --           ------ 
    Power BI Pro CFQ7TTC0L3PB Disabled

    .Example
    Get-AADIntSelfServicePurchaseProducts | Set-AADIntSelfServicePurchaseProduct -Enabled $false

    Product                                          Id           Status  
    -------                                          --           ------  
    Windows 365 Enterprise                           CFQ7TTC0HHS9 Disabled
    Windows 365 Business with Windows Hybrid Benefit CFQ7TTC0HX99 Disabled
    Windows 365 Business                             CFQ7TTC0J203 Disabled
    Power Automate per user                          CFQ7TTC0KP0N Disabled
    Power Apps per user                              CFQ7TTC0KP0P Disabled
    Power Automate RPA                               CFQ7TTC0KXG6 Disabled
    Power BI Premium (standalone)                    CFQ7TTC0KXG7 Disabled
    Visio Plan 2                                     CFQ7TTC0KXN8 Disabled
    Visio Plan 1                                     CFQ7TTC0KXN9 Disabled
    Project Plan 3                                   CFQ7TTC0KXNC Disabled
    Project Plan 1                                   CFQ7TTC0KXND Disabled
    Power BI Pro                                     CFQ7TTC0L3PB Disabled
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
        [String]$Id,
        [Parameter(Mandatory=$True)]
        [Boolean]$Enabled
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "aeb86249-8ea3-49e2-900b-54cc8e308f85" -ClientId "3d5cffa9-04da-4657-8cab-c7f074657cad"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        if($Enabled)
        {
            $policyValue = "Enabled"
        }
        else
        {
            $policyValue = "Disabled"
        }

        $body = @{ "policyValue" = $policyValue}

        # Invoke the command
        try
        { 
            $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri "https://licensing.m365.microsoft.com/v1.0/policies/AllowSelfServicePurchase/products/$Id" -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json; charset=utf-8"

            # Return
            New-Object psobject -Property ([ordered]@{
                "Product"   = $response.productName
                "Id"        = $response.productID
                "Status"    = $response.policyValue
            })
        }
        catch
        {
            throw $_
        }

        
    }
}