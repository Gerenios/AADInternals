# This contains functions for getting Azure AD access tokens

# Tries to get access token from cache unless provided as parameter
# Refactored Jun 8th 2020
function Get-AccessTokenFromCache
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$ClientID,
        [Parameter(Mandatory=$True)]
        [String]$Resource,
        [switch]$IncludeRefreshToken,
        [boolean]$Force=$false
    )
    Process
    {
        # Check if we got the AccessToken as parameter
        if([string]::IsNullOrEmpty($AccessToken))
        {
            # Check if cache entry is empty
            if([string]::IsNullOrEmpty($Script:tokens["$ClientId-$Resource"]))
            {
                # Empty, so throw the exception
                Throw "No saved tokens found. Please call Get-AADIntAccessTokenFor<service> -SaveToCache"
            }
            else
            {
                $retVal=$Script:tokens["$ClientId-$Resource"]
            }
        }
        else
        {
            # Check that the audience of the access token is correct
            $audience=(Read-Accesstoken -AccessToken $AccessToken).aud

            # Strip the trailing slashes
            if($audience.EndsWith("/"))
            {
                $audience = $audience.Substring(0,$audience.Length-1)
            }
            if($Resource.EndsWith("/"))
            {
                $Resource = $Resource.Substring(0,$Resource.Length-1)
            }

            if(($audience -ne $Resource) -and ($Force -eq $False))
            {
                # Wrong audience
                Write-Verbose "ACCESS TOKEN HAS WRONG AUDIENCE: $audience. Exptected: $resource."
                Throw "The audience of the access token ($audience) is wrong. Should be $resource!"
            }
            else
            {
                # Just return the passed access token
                $retVal=$AccessToken
            }
        }

        # Check the expiration
        if(Is-AccessTokenExpired($retVal))
        {
            Write-Verbose "ACCESS TOKEN HAS EXPRIRED. Trying to get a new one with RefreshToken."
            $retVal = Get-AccessTokenWithRefreshToken -Resource $Resource -ClientId $ClientID -RefreshToken $script:refresh_tokens["$ClientId-$Resource"] -TenantId (Read-Accesstoken -AccessToken $retVal).tid -SaveToCache $true -IncludeRefreshToken $IncludeRefreshToken
        }

        # Return
        return $retVal
    }
}

# Gets the access token for AAD Graph API
function Get-AccessTokenForAADGraph
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for AAD Graph

    .DESCRIPTION
    Gets OAuth Access Token for AAD Graph, which is used for example in Provisioning API.
    If credentials are not given, prompts for credentials (supports MFA).

    .Parameter Credentials
    Credentials of the user. If not given, credentials are prompted.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos ticket

    .Parameter KerberosTicket
    Kerberos token of the user.

    .Parameter UseDeviceCode
    Use device code flow.

    .Parameter Resource
    Resource, defaults to "https://graph.windows.net"
    
    .Example
    Get-AADIntAccessTokenForAADGraph
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForAADGraph -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [switch]$SaveToCache,
        [ValidateSet("https://graph.windows.net", "urn:ms-drs:enterpriseregistration.windows.net","urn:ms-drs:enterpriseregistration.microsoftonline.us")]
        [String]$Resource="https://graph.windows.net"
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource $Resource -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -SAMLToken $SAMLToken -Tenant $Tenant -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode 
    }
}

# Gets the access token for MS Graph API
function Get-AccessTokenForMSGraph
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Microsoft Graph

    .DESCRIPTION
    Gets OAuth Access Token for Microsoft Graph, which is used in Graph API.
    If credentials are not given, prompts for credentials (supports MFA).

    .Parameter Credentials
    Credentials of the user. If not given, credentials are prompted.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user.

    .Example
    Get-AADIntAccessTokenForMSGraph
    
    .Example
    $cred=Get-Credential
    Get-AADIntAccessTokenForMSGraph -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode 
    }
}

# Gets the access token for enabling or disabling PTA
function Get-AccessTokenForPTA
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for PTA

    .DESCRIPTION
    Gets OAuth Access Token for PTA, which is used for example to enable or disable PTA.

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Example
    Get-AADIntAccessTokenForPTA
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForPTA -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "https://proxy.cloudwebappproxy.net/registerapp" -ClientId "cb1056e2-e479-49de-ae31-7812af012ed8" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode 
    }
}

# Gets the access token for Office Apps
function Get-AccessTokenForOfficeApps
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Office Apps

    .DESCRIPTION
    Gets OAuth Access Token for Office Apps.

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Example
    Get-AADIntAccessTokenForOfficeApps
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForOfficeApps -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "https://officeapps.live.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode 
    }
}

# Gets the access token for Exchange Online
function Get-AccessTokenForEXO
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Exchange Online

    .DESCRIPTION
    Gets OAuth Access Token for Exchange Online

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Example
    Get-AADIntAccessTokenForEXO
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForEXO -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [ValidateSet("https://graph.microsoft.com","https://outlook.office365.com")]
        [String]$Resource="https://outlook.office365.com"
    )
    Process
    {
        # Office app has the required rights to Exchange Online
        Get-AccessToken -Credentials $Credentials -Resource $Resource -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode 
    }
}

# Gets the access token for Exchange Online remote PowerShell
function Get-AccessTokenForEXOPS
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Exchange Online remote PowerShell

    .DESCRIPTION
    Gets OAuth Access Token for Exchange Online remote PowerShell

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Parameter Certificate
    x509 device certificate.
    
    .Example
    Get-AADIntAccessTokenForEXOPS
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForEXOPS -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache,

        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$False)]
        [string]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword
    )
    Process
    {
        # Office app has the required rights to Exchange Online
        Get-AccessToken -Credentials $Credentials -Resource "https://outlook.office365.com" -ClientId "a0c73c16-a7e3-4564-9a95-2bdf47383716" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -UserPrincipalName $UserPrincipalName -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode 
    }
}

# Gets the access token for SARA
# Jul 8th 2019
function Get-AccessTokenForSARA
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for SARA

    .DESCRIPTION
    Gets OAuth Access Token for Microsoft Support and Recovery Assistant (SARA)

    .Parameter KerberosTicket
    Kerberos token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token. 
    
    .Example
    Get-AADIntAccessTokenForSARA
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForSARA -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$KerberosTicket,
        [Parameter(Mandatory=$False)]
        [String]$Domain,
        [switch]$SaveToCache
    )
    Process
    {
        # Office app has the required rights to Exchange Online
        Get-AccessToken -Resource "https://api.diagnostics.office.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode 
    }
}

# Gets an access token for OneDrive
# Nov 26th 2019
function Get-AccessTokenForOneDrive
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for OneDrive

    .DESCRIPTION
    Gets OAuth Access Token for OneDrive Sync client

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Example
    Get-AADIntAccessTokenForOneDrive
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForOneDrive -Tenant "company" -Credentials $cred
#>
    [cmdletbinding()]
    Param(
    [Parameter(Mandatory=$True)]
        [String]$Tenant,
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache
    )
    Process
    {
        Get-AccessToken -Resource "https://$Tenant-my.sharepoint.com/" -ClientId "ab9b8c07-8f02-4f72-87fa-80105867a763" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials  -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode 
    }
}

# Gets an access token for OfficeApps
# Nov 26th 2019
function Get-AccessTokenForOfficeApps
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Office Apps

    .DESCRIPTION
    Gets OAuth Access Token for Office Apps

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token
    
    .Example
    Get-AADIntAccessTokenForOneOfficeApps
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForOneOfficeApps -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache
    )
    Process
    {
        Get-AccessToken -Resource "https://officeapps.live.com" -ClientId "ab9b8c07-8f02-4f72-87fa-80105867a763" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode 
    }
}

# Gets an access token for Azure Core Management
# May 29th 2020
function Get-AccessTokenForAzureCoreManagement
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Azure Core Management

    .DESCRIPTION
    Gets OAuth Access Token for Azure Core Management

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token
    
    .Example
    Get-AADIntAccessTokenForOneOfficeApps
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForAzureCoreManagement -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [String]$Tenant
    )
    Process
    {
        Get-AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode
    }
}

# Gets an access token for SPO
# Jun 10th 2020
function Get-AccessTokenForSPO
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for SharePoint Online

    .DESCRIPTION
    Gets OAuth Access Token for SharePoint Online Management Shell, which can be used with any SPO requests.

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter Tenant
    The tenant name of the organization, ie. company.onmicrosoft.com -> "company"

    .Parameter Admin
    Get the token for admin portal
    
    .Example
    Get-AADIntAccessTokenForSPO
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForSPO -Credentials $cred -Tenant "company"
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [Parameter(Mandatory=$True)]
        [String]$Tenant,
        [switch]$SaveToCache,
        [switch]$Admin
    )
    Process
    {
        if($Admin)
        {
            $prefix = "-admin"
        }
        Get-AccessToken -Resource "https://$Tenant$prefix.sharepoint.com/" -ClientId "9bc3ab49-b65d-410a-85ad-de819febfddc" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode 
    }
}

# Gets the access token for My Signins
# Jul 1st 2020
function Get-AccessTokenForMySignins
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for My Signins

    .DESCRIPTION
    Gets OAuth Access Token for My Signins, which is used for example when registering MFA.
   
    .Example
    PS C:\>Get-AADIntAccessTokenForMySignins
#>
    [cmdletbinding()]
    Param(
        [switch]$SaveToCache
    )
    Process
    {
        return Get-AccessToken -ClientId 1b730954-1685-4b74-9bfd-dac224a7b894 -Resource "0000000c-0000-0000-c000-000000000000" -ForceMFA $true -SaveToCache $SaveToCache
    }
}


# Gets an access token for Azure AD Join
# Aug 26th 2020
function Get-AccessTokenForAADJoin
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Azure AD Join

    .DESCRIPTION
    Gets OAuth Access Token for Azure AD Join, allowing users' to register devices to Azure AD.

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.

    .Parameter BPRT
    Bulk PRT token, can be created with New-AADIntBulkPRTToken
    
    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter Tenant
    The tenant name of the organization, ie. company.onmicrosoft.com -> "company"
    
    .Example
    Get-AADIntAccessTokenForAADJoin
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForAADJoin -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$False)]
        [Switch]$Device,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [Parameter(ParameterSetName='BPRT',Mandatory=$True)]
        [string]$BPRT,
        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [switch]$SaveToCache
    )
    Process
    {
        if($Device)
        {
            Get-AccessTokenWithDeviceSAML -SAML $SAMLToken -SaveToCache $SaveToCache
        }
        else
        {
            Get-AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -ForceMFA $true -BPRT $BPRT
        }
    }
}

# Gets an access token for Intune MDM
# Aug 26th 2020
function Get-AccessTokenForIntuneMDM
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Intune MDM

    .DESCRIPTION
    Gets OAuth Access Token for Intune MDM, allowing users' to enroll their devices to Intune.

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter BPRT
    Bulk PRT token, can be created with New-AADIntBulkPRTToken

    .Parameter Tenant
    The tenant name of the organization, ie. company.onmicrosoft.com -> "company"

    .Parameter Certificate
    x509 device certificate.

    .Parameter PfxFileName
    File name of the .pfx device certificate.

    .Parameter PfxPassword
    The password of the .pfx device certificate.

    .Parameter Resource
    The resource to get access token to, defaults to "https://enrollment.manage.microsoft.com/". To get access to AAD Graph API, use "https://graph.windows.net"
    
    .Example
    Get-AADIntAccessTokenForIntuneMDM
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForIntuneMDM -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [Parameter(ParameterSetName='BPRT',Mandatory=$True)]
        [string]$BPRT,

        [switch]$SaveToCache,

        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$False)]
        [string]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [string]$Resource="https://enrollment.manage.microsoft.com/"
    )
    Process
    {
        Get-AccessToken -ClientId "29d9ed98-a469-4536-ade2-f981bc1d605e" -Resource $Resource -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -Certificate $Certificate -PfxFileName $PfxFileName -PfxPassword $PfxPassword -BPRT $BPRT
    }
}

# Gets an access token for Azure Cloud Shell
# Sep 9th 2020
function Get-AccessTokenForCloudShell
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Azure Cloud Shell

    .DESCRIPTION
    Gets OAuth Access Token for Azure Cloud Shell

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token
    
    .Example
    Get-AADIntAccessTokenForOneOfficeApps
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForCloudShell -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [String]$Tenant
    )
    Process
    {
        Get-AccessToken -Resource "https://management.core.windows.net/" -ClientId "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode
    }
}

# Gets an access token for Teams
# Oct 3rd 2020
function Get-AccessTokenForTeams
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Teams

    .DESCRIPTION
    Gets OAuth Access Token for Teams

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token
    
    .Example
    Get-AADIntAccessTokenForTeams
    
    .Example
    PS C:\>Get-AADIntAccessTokenForTeams -SaveToCache
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [ValidateSet("https://api.spaces.skype.com", "https://outlook.com", "https://*.microsoftstream.com")]
        [String]$Resource="https://api.spaces.skype.com"
    )
    Process
    {
        Get-AccessToken -Resource $Resource -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode
    }
}


# Gets an access token for Azure AD Management API
# Nov 11th 2020
function Get-AccessTokenForAADIAMAPI
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Azure AD IAM API

    .DESCRIPTION
    Gets OAuth Access Token for Azure AD IAM API

    .Parameter Credentials
    Credentials of the user.

    .Parameter PRT
    PRT token of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Parameter UseDeviceCode
    Use device code flow.
    
    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token
    
    .Example
    Get-AccessTokenForAADIAMAPI
    
    .Example
    PS C:\>Get-AccessTokenForAADIAMAPI -SaveToCache
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [String]$Tenant
    )
    Process
    {
        # First get the access token for AADGraph
        $AccessTokens = Get-AccessToken -Resource "https://graph.windows.net" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -IncludeRefreshToken $True

        # Get the actual token
        $AccessToken = Get-AccessTokenWithRefreshToken -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -SaveToCache $SaveToCache -RefreshToken $AccessTokens[1] -TenantId (Read-AADIntAccesstoken $AccessTokens[0]).tid

        if(!$SaveToCache)
        {
            return $AccessToken
        }
    }
}

# Gets the access token for provisioning API and stores to cache
# Refactored Jun 8th 2020
function Get-AccessToken
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$False)]
        [String]$PRTToken,
        [Parameter(Mandatory=$False)]
        [String]$SAMLToken,
        [Parameter(Mandatory=$True)]
        [String]$Resource,
        [Parameter(Mandatory=$True)]
        [String]$ClientId,
        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [String]$KerberosTicket,
        [Parameter(Mandatory=$False)]
        [String]$Domain,
        [Parameter(Mandatory=$False)]
        [bool]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [bool]$IncludeRefreshToken=$false,
        [Parameter(Mandatory=$False)]
        [bool]$ForceMFA=$false,
        [Parameter(Mandatory=$False)]
        [bool]$UseDeviceCode=$false,
        [Parameter(Mandatory=$False)]
        [string]$BPRT,
        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$False)]
        [string]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword
    )
    Begin
    {
        # List of clients requiring the same client id
        $requireClientId=@(
            "cb1056e2-e479-49de-ae31-7812af012ed8" # Pass-through authentication
            "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" # Azure Admin web ui
            "1fec8e78-bce4-4aaf-ab1b-5451cc387264" # Teams
            "d3590ed6-52b3-4102-aeff-aad2292ab01c" # Office, ref. https://docs.microsoft.com/en-us/office/dev/add-ins/develop/register-sso-add-in-aad-v2
            "a0c73c16-a7e3-4564-9a95-2bdf47383716" # EXO Remote PowerShell
            "389b1b32-b5d5-43b2-bddc-84ce938d6737" # Office Management API Editor https://manage.office.com
            "ab9b8c07-8f02-4f72-87fa-80105867a763" # OneDrive Sync Engine
            "9bc3ab49-b65d-410a-85ad-de819febfddc" # SPO
            "29d9ed98-a469-4536-ade2-f981bc1d605e" # MDM
            "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa" # Azure Android App
            "6c7e8096-f593-4d72-807f-a5f86dcc9c77" # MAM
            "4813382a-8fa7-425e-ab75-3b753aab3abb" # Microsoft authenticator
            "8c59ead7-d703-4a27-9e55-c96a0054c8d2"
            "c7d28c4f-0d2c-49d6-a88d-a275cc5473c7" # https://www.microsoftazuresponsorships.com/
        )
    }
    Process
    {
        
        if(![String]::IsNullOrEmpty($KerberosTicket)) # Check if we got the kerberos token
        {
            # Get token using the kerberos token
            $OAuthInfo = Get-AccessTokenWithKerberosTicket -KerberosTicket $KerberosTicket -Domain $Domain -Resource $Resource -ClientId $ClientId
            $access_token = $OAuthInfo.access_token
        }
        elseif(![String]::IsNullOrEmpty($PRTToken)) # Check if we got a PRT token
        {
            # Get token using the PRT token
            $OAuthInfo = Get-AccessTokenWithPRT -Cookie $PRTToken -Resource $Resource -ClientId $ClientId
            $access_token = $OAuthInfo.access_token
        }
        elseif($UseDeviceCode) # Check if we want to use device code flow
        {
            # Get token using device code
            $OAuthInfo = Get-AccessTokenUsingDeviceCode -Resource $Resource -ClientId $ClientId -Tenant $Tenant
            $access_token = $OAuthInfo.access_token
        }
        elseif(![String]::IsNullOrEmpty($BPRT)) # Check if we got a BPRT
        {
            # Get token using BPRT
            $OAuthInfo = @{
                "refresh_token" = $BPRT
                "access_token"  = Get-AccessTokenWithRefreshToken -Resource "urn:ms-drs:enterpriseregistration.windows.net" -ClientId "b90d5b8f-5503-4153-b545-b31cecfaece2" -TenantId "Common" -RefreshToken $BPRT
                }
            $access_token = $OAuthInfo.access_token
        }
        else
        {
            
            # Check if we got credentials
            if([string]::IsNullOrEmpty($Credentials) -and [string]::IsNullOrEmpty($SAMLToken))
            {
                # No credentials given, so prompt for credentials
                if(  $ClientId -eq "d3590ed6-52b3-4102-aeff-aad2292ab01c" <# Office #> -or 
                     $ClientId -eq "a0c73c16-a7e3-4564-9a95-2bdf47383716" <# EXO #>    -or 
                    ($ClientId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" -and $Resource -eq "https://enrollment.manage.microsoft.com/") <# MDM #>
                )  
                {
                    $OAuthInfo = Prompt-Credentials -Resource $Resource -ClientId $ClientId -Tenant $Tenant -ForceMFA $ForceMFA
                    
                }
                else
                {
                    $OAuthInfo = Prompt-Credentials -Resource "https://graph.windows.net" -ClientId $ClientId -Tenant $Tenant -ForceMFA $ForceMFA
                }
                
            }
            else
            {
                # Get OAuth info for user
                if(![string]::IsNullOrEmpty($SAMLToken))
                {
                    $OAuthInfo = Get-OAuthInfoUsingSAML -SAMLToken $SAMLToken -ClientId $ClientId -Resource "https://graph.windows.net"
                }
                else
                {
                    if($requireClientId -contains $ClientId)
                    {
                        # Requires same clientId
                        $OAuthInfo = Get-OAuthInfo -Credentials $Credentials -ClientId $ClientId -Resource "https://graph.windows.net"
                    }
                    else
                    {
                        # "Normal" flow
                        $OAuthInfo = Get-OAuthInfo -Credentials $Credentials -Resource "https://graph.windows.net"
                    }
                }
            }

            if([String]::IsNullOrEmpty($OAuthInfo))
            {
                throw "Could not get OAuthInfo!"
            }
            
            # We need to get access token using the refresh token

            # Save the refresh token and other variables
            $RefreshToken= $OAuthInfo.refresh_token
            $ParsedToken=  Read-Accesstoken($OAuthInfo.access_token)
            $tenant_id =   $ParsedToken.tid

            # Save the tokens to cache
            if($SaveToCache)
            {
                Write-Verbose "ACCESS TOKEN: SAVE TO CACHE"
                $Script:tokens["$ClientId-https://graph.windows.net"] =         $OAuthInfo.access_token
                $Script:refresh_tokens["$ClientId-https://graph.windows.net"] = $OAuthInfo.refresh_token
            }

            # Get the access token from response
            $access_token = Get-AccessTokenWithRefreshToken -Resource $Resource -ClientId $ClientId -TenantId $tenant_id -RefreshToken $RefreshToken -SaveToCache $SaveToCache
            
        }

        $refresh_token = $OAuthInfo.refresh_token

        # Check whether we want to get the deviceid and (possibly) mfa in mra claim
        if(($Certificate -ne $null -and [string]::IsNullOrEmpty($PfxFileName)) -or ($Certificate -eq $null -and [string]::IsNullOrEmpty($PfxFileName) -eq $false))
        {
            try
            {
                Write-Verbose "Trying to get new tokens with deviceid claim."
                $deviceTokens = Set-AccessTokenDeviceAuth -AccessToken $access_token -RefreshToken $refresh_token -Certificate $Certificate -PfxFileName $PfxFileName -PfxPassword $PfxPassword -BPRT $([string]::IsNullOrEmpty($BPRT) -eq $False)
            }
            catch
            {
                Write-Warning "Could not get tokens with deviceid claim: $($_.Exception.Message)"
            }

            if($deviceTokens.access_token)
            {
                $access_token =  $deviceTokens.access_token
                $refresh_token = $deviceTokens.refresh_token

                $claims = Read-Accesstoken $access_token
                Write-Verbose "Tokens updated with deviceid: ""$($claims.deviceid)"" and amr: ""$($claims.amr)"""
            }
        }

        if($SaveToCache -and $OAuthInfo -ne $null -and $access_token -ne $null)
        {
            $script:tokens["$ClientId-$Resource"] =          $access_token
            $script:refresh_tokens["$ClientId-$Resource"] =  $refresh_token
        }

        # Return
        if([string]::IsNullOrEmpty($access_token))
        {
            Throw "Could not get Access Token!"
        }

        # Don't print out token if saved to cache!
        if($SaveToCache)
        {
            $pat = Read-Accesstoken -AccessToken $access_token
            $attributes=[ordered]@{
                "Tenant" =   $pat.tid
                "User" =     $pat.unique_name
                "Resource" = $Resource
                "Client" =   $ClientID
            }
            Write-Host "AccessToken saved to cache."
            return New-Object psobject -Property $attributes
        }
        else
        {
            if($IncludeRefreshToken) # Include refreshtoken
            {
                return @($access_token,$OAuthInfo.refresh_token)
            }
            else
            {
                return $access_token
            }
        }
    }
}

# Gets the access token using a refresh token
# Jun 8th 2020
function Get-AccessTokenWithRefreshToken
{
    [cmdletbinding()]
    Param(
        [String]$Resource,
        [Parameter(Mandatory=$True)]
        [String]$ClientId,
        [Parameter(Mandatory=$True)]
        [String]$TenantId,
        [Parameter(Mandatory=$True)]
        [String]$RefreshToken,
        [Parameter(Mandatory=$False)]
        [bool]$SaveToCache = $false,
        [Parameter(Mandatory=$False)]
        [bool]$IncludeRefreshToken = $false
    )
    Process
    {
        # Set the body for API call
        $body = @{
            "resource"=      $Resource
            "client_id"=     $ClientId
            "grant_type"=    "refresh_token"
            "refresh_token"= $RefreshToken
            "scope"=         "openid"
        }

        if($ClientId -eq "ab9b8c07-8f02-4f72-87fa-80105867a763") # OneDrive Sync Engine
        {
            $url = "https://login.windows.net/common/oauth2/token"
        }
        else
        {
            $url = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        }

        # Debug
        Write-Debug "ACCESS TOKEN BODY: $($body | Out-String)"
        
        # Set the content type and call the API
        $contentType="application/x-www-form-urlencoded"
        $response=Invoke-RestMethod -Uri $url -ContentType $contentType -Method POST -Body $body

        # Debug
        Write-Debug "ACCESS TOKEN RESPONSE: $response"

        # Save the tokens to cache
        if($SaveToCache)
        {
            Write-Verbose "ACCESS TOKEN: SAVE TO CACHE"
            $Script:tokens["$ClientId-$Resource"] =         $response.access_token
            $Script:refresh_tokens["$ClientId-$Resource"] = $response.refresh_token
        }

        # Return
        if($IncludeRefreshToken)
        {
            return @($response.access_token, $response.refresh_token)
        }
        else
        {
            return $response.access_token    
        }
    }
}

# Gets access token using device code flow
# Oct 13th 2020
function Get-AccessTokenUsingDeviceCode
{
    [cmdletbinding()]
    Param(
        
        [Parameter(Mandatory=$True)]
        [String]$ClientId,
        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [String]$Resource="https://graph.windows.net"
    )
    Process
    {
        # Check the tenant
        if([string]::IsNullOrEmpty($Tenant))
        {
            $Tenant="Common"
        }

        # Create a body for the first request
        $body=@{
            "client_id" = $ClientId
            "resource" =  $Resource
        }

        # Invoke the request to get device and user codes
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$tenant/oauth2/devicecode?api-version=1.0" -Body $body

        Write-Host $authResponse.message

        $continue = $true
        $interval = $authResponse.interval
        $expires =  $authResponse.expires_in

        # Create body for authentication subsequent requests
        $body=@{
            "client_id" =  $ClientId
            "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
            "code" =       $authResponse.device_code
            "resource" =   $Resource
        }


        # Loop while pending or until timeout exceeded
        while($continue)
        {
            Start-Sleep -Seconds $interval
            $total += $interval

            if($total -gt $expires)
            {
                Write-Error "Timeout occurred"
                return
            }
                        
            # Try to get the response. Will give 40x while pending so we need to try&catch
            try
            {
                $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token?api-version=1.0 " -Body $body -ErrorAction SilentlyContinue
            }
            catch
            {
                # This normal flow, always returns 40x unless successful
                $details=$_.ErrorDetails.Message | ConvertFrom-Json
                $continue = $details.error -eq "authorization_pending"
                Write-Verbose $details.error
                Write-Host "." -NoNewline

                if(!$continue)
                {
                    # Not authorization_pending so this is a real error :(
                    Write-Error $details.error_description
                    return
                }
            }

            # If we got response, all okay!
            if($response)
            {
                Write-Host "" 
                return $response
            }
        }

    }
}

# Gets the access token using an authorization code
# Feb 12th 2021
function Get-AccessTokenWithAuthorizationCode
{
    [cmdletbinding()]
    Param(
        [String]$Resource,
        [Parameter(Mandatory=$True)]
        [String]$ClientId,
        [Parameter(Mandatory=$True)]
        [String]$TenantId,
        [Parameter(Mandatory=$True)]
        [String]$AuthorizationCode,
        [Parameter(Mandatory=$False)]
        [bool]$SaveToCache = $false,
        [Parameter(Mandatory=$False)]
        [bool]$IncludeRefreshToken = $false,
        [Parameter(Mandatory=$False)]
        [String]$RedirectUri,
        [Parameter(Mandatory=$False)]
        [String]$CodeVerifier
    )
    Process
    {
        $headers = @{
        }

        # Set the body for API call
        $body = @{
            "resource"=      $Resource
            "client_id"=     $ClientId
            "grant_type"=    "authorization_code"
            "code"=          $AuthorizationCode
            "scope"=         "openid profile email"
        }
        if(![string]::IsNullOrEmpty($RedirectUri))
        {
            $body["redirect_uri"] = $RedirectUri
            $headers["Origin"] = $RedirectUri
        }

        if(![string]::IsNullOrEmpty($CodeVerifier))
        {
            $body["code_verifier"] = $CodeVerifier
            $body["code_challenge_method"] = "S256"
        }

        if($ClientId -eq "ab9b8c07-8f02-4f72-87fa-80105867a763") # OneDrive Sync Engine
        {
            $url = "https://login.windows.net/common/oauth2/token"
        }
        else
        {
            $url = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        }
        
        # Debug
        Write-Debug "ACCESS TOKEN BODY: $($body | Out-String)"
        
        # Set the content type and call the API
        $contentType = "application/x-www-form-urlencoded"
        $response =    Invoke-RestMethod -Uri $url -ContentType $contentType -Method POST -Body $body -Headers $headers

        # Debug
        Write-Debug "ACCESS TOKEN RESPONSE: $response"

        # Save the tokens to cache
        if($SaveToCache)
        {
            Write-Verbose "ACCESS TOKEN: SAVE TO CACHE"
            $Script:tokens["$ClientId-$Resource"] =         $response.access_token
            $Script:refresh_tokens["$ClientId-$Resource"] = $response.refresh_token
        }

        # Return
        return $response.access_token    
    }
}

# Gets the access token using device SAML token
# Feb 18th 2021
function Get-AccessTokenWithDeviceSAML
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$SAML,
        [Parameter(Mandatory=$False)]
        [bool]$SaveToCache
    )
    Process
    {
        $headers = @{
        }

         
        $ClientId = "1b730954-1685-4b74-9bfd-dac224a7b894" #"dd762716-544d-4aeb-a526-687b73838a22"
        $Resource = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" #"urn:ms-drs:enterpriseregistration.windows.net"

        # Set the body for API call
        $body = @{
            "resource"=      $Resource
            "client_id"=     $ClientId
            "grant_type"=    "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
            "assertion"=     Convert-TextToB64 -Text $SAML
            "scope"=         "openid"
        }
        
        # Debug
        Write-Debug "ACCESS TOKEN BODY: $($body | Out-String)"
        
        # Set the content type and call the API
        $contentType = "application/x-www-form-urlencoded"
        $response =    Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType $contentType -Method POST -Body $body -Headers $headers

        # Debug
        Write-Debug "ACCESS TOKEN RESPONSE: $response"

        # Save the tokens to cache
        if($SaveToCache)
        {
            Write-Verbose "ACCESS TOKEN: SAVE TO CACHE"
            $Script:tokens["$ClientId-$Resource"] =         $response.access_token
            $Script:refresh_tokens["$ClientId-$Resource"] = $response.refresh_token
        }
        else
        {
            # Return
            return $response.access_token    
        }
    }
}

# Logins to SharePoint Online and returns an IdentityToken
# TODO: Research whether can be used to get access_token to AADGraph
# TODO: Add support for Google?
# FIX: Web control stays logged in - clear cookies somehow?
# Aug 10th 2018
function Get-IdentityTokenByLiveId
{
<#
    .SYNOPSIS
    Gets identity_token for SharePoint Online for External user

    .DESCRIPTION
    Gets identity_token for SharePoint Online for External user using LiveId.

    .Parameter Tenant
    The tenant name to login in to WITHOUT .sharepoint.com part
    
    .Example
    PS C:\>$id_token=Get-AADIntIdentityTokenByLiveId -Tenant mytenant
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Tenant
    )
    Process
    {
        # Set variables
        $auth_redirect="https://login.microsoftonline.com/common/federation/oauth2" # When to close the form
        $url="https://$Tenant.sharepoint.com"

        # Create the form
        $form=Create-LoginForm -Url $url -auth_redirect $auth_redirect

        # Show the form and wait for the return value
        if($form.ShowDialog() -ne "OK") {
            Write-Verbose "Login cancelled"
            return $null
        }

        $web=$form.Controls[0]

        $code=$web.Document.All["code"].GetAttribute("value")
        $id_token=$web.Document.All["id_token"].GetAttribute("value")
        $session_state=$web.Document.All["session_state"].GetAttribute("value")

        return Read-Accesstoken($id_token)
    }
}

# Tries to generate access token using cached AADGraph token
# Jun 15th 2020
function Get-AccessTokenUsingAADGraph
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Resource,
        [Parameter(Mandatory=$True)]
        [String]$ClientId,
        [switch]$SaveToCache
    )
    Process
    {
        # Try to get AAD Graph access token from the cache
        $AccessToken = Get-AccessTokenFromCache -AccessToken $null -Resource "https://graph.windows.net" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Get the tenant id
        $tenant = (Read-Accesstoken -AccessToken $AccessToken).tid
                
        # Get the refreshtoken
        $refresh_token=$script:refresh_tokens["1b730954-1685-4b74-9bfd-dac224a7b894-https://graph.windows.net"]

        if([string]::IsNullOrEmpty($refresh_token))
        {
            Throw "No refreshtoken found! Use Get-AADIntAccessTokenForAADGraph with -SaveToCache switch."
        }

        # Create a new AccessToken for Azure AD management portal API
        $AccessToken = Get-AccessTokenWithRefreshToken -Resource $Resource -ClientId $ClientId -TenantId $tenant -RefreshToken $refresh_token -SaveToCache $SaveToCache

        # Return
        $AccessToken
    }
}