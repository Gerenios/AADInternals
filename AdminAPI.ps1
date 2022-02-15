# This file contains functions utilising https://admin.microsoft.com API

# Approves the delegated admin request
# Sep 22nd 2021
function Approve-MSPartnerDelegatedAdminRequest
{
<#
    .SYNOPSIS
    Assigns Delegated Admin Permissions (DAP) for the given partner organisation.

    .DESCRIPTION
    Assigns Delegated Admin Permissions (DAP) for the given partner organisation.

    .Parameter TenantId
    TenantId of the partner organisation.

    .Parameter Domain
    Any registered domain of the partner organisation.

    .Example
    PS C:\>Get-AADIntAccessTokenForAdmin -SaveToCache
    PS C:\>Approve-AADIntMSPartnerDelegatedAdminRequest -Domain company.com
    
    responseCode message
    ------------ -------
    success 

    .Example
    PS C:\>Get-AADIntAccessTokenForAdmin -SaveToCache
    PS C:\>Approve-AADIntMSPartnerDelegatedAdminRequest -TenantId c7e52a77-e461-4f2e-a652-573305414be9
    
    responseCode message
    ------------ -------
    success 
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='TenantId',Mandatory=$True)]
        [guid]$TenantId,
        [Parameter(ParameterSetName='Domain',Mandatory=$True)]
        [String]$Domain,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        if($Domain)
        {
            $TenantId = Get-TenantID -Domain $Domain
        }

        $body = @{
            "authorizeDelegateAdminData" = [ordered]@{
		        "msppId"         = 0
		        "partnerId"      = $TenantId
		        "companyName"    = " "
		        "indirectCSPId"  = ""
		        "userTenantId"   = (Read-Accesstoken $AccessToken).tid
		        "enableDap"      = $true
		        "invitationType" = "Administration"
		        "address"        = $null
		        "roles" = @(
			        "62e90394-69f5-4237-9190-012177145e10" # Global Administrator
			        "729827e3-9c14-49f7-bb1b-9608f156bbb8" # Helpdesk Administrator
                )
		        "userPrincipalName" = $null
	        }

        }

        try
        {
            $response = Invoke-AdminAPI -Method Post -AccessToken $AccessToken -Url "fd/commerceMgmt/partnermanage/partners/csp/delegatedaccess?api-version=2.1" -Body ($body | ConvertTo-Json)
        }
        catch
        {
            Write-Error ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
            return
        }
        
        $response
    }
}

# Gets the list of partners
# Dec 9th 2021
function Get-MSPartners
{
<#
    .SYNOPSIS
    Shows organisation's partners.

    .DESCRIPTION
    Shows organisation's partners using Admin API.

    .Parameter AccessToken
    Access token to retrieve partners.

    .Example
    PS C:\>Get-AADIntAccessTokenForAdmin -SaveToCache
    PS C:\>Get-AADIntMSPartners
    
    Identity         : b1f6d5cc-f1d3-41d9-b88c-1d177aaf171b
    DisplayName      : Partner Ltd
    Email            : pmanager@company.com
    Website          : http://www.company.com
    Phone            : +1234567890
    Relationship     : Indirect Reseller and Admin
    TypeDetail       : PartnerAdmin
    CanDelete        : False
    CanRemoveDap     : True
    AllDataRetrieved : True
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        try
        {
            $response = Invoke-AdminAPI -AccessToken $AccessToken -Url "admin/api/Partners/GetPartners" -Method Post
        }
        catch
        {
            if($_.ErrorDetails.Message)
            {
                throw $_.ErrorDetails.Message
            }
            else
            {
                throw $_.Exception.Message
            }
            return
        }
        
        $response
    }
}

# Returns access token for the requested resource
# Dec 9th 2021
function Get-AccessTokenUsingAdminAPI
{
<#
    .SYNOPSIS
    Gets access token for the requested resource using Admin API.

    .DESCRIPTION
    Gets access token for the requested resource using Admin API.

    .Parameter Access
    Some supported type of access token.

    .Parameter TokenType
    The type of the access token to return

    .Example
    PS C:\>Get-AADIntAccessTokenForAdmin -SaveToCache
    PS C:\>$at = Get-AADIntAccessTokenUsingAdminAPI -TokenType PortalAT

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet('PortalAT','BusinessStoreAT')]
        [String]$TokenType="PortalAT",
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        Invoke-AdminAPI -AccessToken $AccessToken -Url "admin/api/users/getuseraccesstoken?tokenType=$TokenType" -Method Get 
    }
}


# Approves the delegated admin request
# Dec 11th 2021
function Remove-MSPartnerDelegatedAdminRoles
{
<#
    .SYNOPSIS
    Removes Delegated Admin Permissions (DAP) from the given partner organisation.

    .DESCRIPTION
    Removes Delegated Admin Permissions (DAP) from the given partner organisation.

    .Parameter TenantId
    TenantId of the partner organisation.

    .Parameter Domain
    Any registered domain of the partner organisation.

    .Example
    PS C:\>Get-AADIntAccessTokenForAdmin -SaveToCache
    PS C:\>Remove-AADIntMSPartnerDelegatedAdminRoles -Domain company.com
    
    responseCode message
    ------------ -------
    success 

    .Example
    PS C:\>Get-AADIntAccessTokenForAdmin -SaveToCache
    PS C:\>Remove-AADIntMSPartnerDelegatedAdminRoles -TenantId c7e52a77-e461-4f2e-a652-573305414be9
    
    responseCode message
    ------------ -------
    success 
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='TenantId',Mandatory=$True)]
        [guid]$TenantId,
        [Parameter(ParameterSetName='Domain',Mandatory=$True)]
        [String]$Domain,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        if($Domain)
        {
            $TenantId = Get-TenantID -Domain $Domain
        }

        try
        {
            $response = Invoke-AdminAPI -Method Delete -AccessToken $AccessToken -Url "fd/commerceMgmt/partnermanage/partners/csp/$TenantId/delegatedaccess?api-version=2.1"
        }
        catch
        {
            Write-Error ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
            return
        }
        
        $response
    }
}