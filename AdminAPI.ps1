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
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession
    )
    Process
    {
        Invoke-AdminAPI -AccessToken $AccessToken -Url "admin/api/users/getuseraccesstoken?tokenType=$TokenType" -Method Get -WebSession $WebSession
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

# Returns tenant organisation information 
# Jan 26th 2022
function Get-TenantOrganisationInformation
{
<#
    .SYNOPSIS
    Returns organisation information for the given tenant.

    .DESCRIPTION
    Returns organisation information for the given tenant using commercial API used to get Partner Tenant information.

    .Parameter AccessToken
    Access Token used to fetch information. Can be any standard user of any tenant.

    .Parameter TenantId
    TenantId of the target tenant.

    .Parameter Domain
    Domain name of the target tenant.

    .Example
    PS C:\>Get-AADIntAccessTokenForAdmin -SaveToCache

    PS C:\>Get-AADIntTenantOrganisationInformation -Domain "company.com"
    
    TenantId         : 043050e2-7993-416a-ae66-108ab1951612
    CompanyName      : Company Ltd
    StreetAddress    : 10 Wall Street
    ApartmentOrSuite : 666
    City             : New York
    StateOrProvince  : NY
    PostalCode       : 10005
    CountryCode      : US
    PhoneNumber      : 1234567890
    FirstName        : John
    LastName         : Doe
#>
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='Domain',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='TenantId',Mandatory=$True)]
        [guid]$TenantId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://admin.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        if($Domain)
        {
            [guid]$TenantId = [guid](Get-TenantID -Domain $Domain)
        }

        if($TenantId -eq ([guid](Read-AccessToken $AccessToken).tid))
        {
            Write-Error "Can't query information from your own tenant. Log in to another tenant and try again."
            return
        }

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Accept" = "application/json; charset=utf-8"
        }
        $response = Invoke-WebRequest -UseBasicParsing -uri "https://admin.microsoft.com/fd/commerceMgmt/partnermanage/partners/csp/$($TenantId.toString())/delegatedaccess?invType=Administration&api-version=2.1" -Headers $headers

        # Content is utf-8 encoded json, but response headers don't have encoding information
        $responseBytes = New-Object byte[] $response.RawContentLength
        $response.RawContentStream.Read($responseBytes,0,$response.RawContentLength)
        $responseObj = ConvertFrom-Json -InputObject ([text.encoding]::UTF8.GetString($responseBytes))
        
        $tenantInfo = $responseObj.authorizeDelegateAdminData

        $attributes = [ordered]@{
            "TenantId"         = $tenantInfo.partnerId
            "CompanyName"      = $tenantInfo.companyName
            "StreetAddress"    = $tenantInfo.address.line1
            "ApartmentOrSuite" = $tenantInfo.address.line2
            #"Line3"            = $tenantInfo.address.line3
            "City"             = $tenantInfo.address.city
            "StateOrProvince"  = $tenantInfo.address.state
            "PostalCode"       = $tenantInfo.address.postalCode
            "CountryCode"      = $tenantInfo.address.countryCode
            "PhoneNumber"      = $tenantInfo.address.phoneNumber
            "FirstName"        = $tenantInfo.address.firstName
            "LastName"         = $tenantInfo.address.lastName
        }

        New-Object psobject -Property $attributes
    }
}