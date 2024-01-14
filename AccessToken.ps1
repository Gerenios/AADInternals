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
        # Strip the trailing slash
        $tResource = $Resource.TrimEnd("/")

        # Check if we got the AccessToken as parameter
        if([string]::IsNullOrEmpty($AccessToken))
        {
            # Check if cache entry is empty
            if([string]::IsNullOrEmpty($Script:tokens["$ClientId-$tResource"]))
            {
                # If token not found, try to find other tokens with the same resource
                Write-Verbose "Access token for $ClientId-$tResource not found. Trying to find other clients for the resource"
                foreach($key in $Script:tokens.Keys)
                {
                    if($key.EndsWith($tResource))
                    {
                        Write-Verbose "Found token for ClientId $($key.Substring(0,36))"
                        $retVal=$Script:tokens[$key]
                        break
                    }
                }

                # If FOCI client, try to find refresh token for other FOCI client
                if([string]::IsNullOrEmpty($retVal) -and (IsFOCI -ClientId $ClientID))
                {
                    Write-Verbose "Access token for $ClientId-$tResource not found. Trying to find refresh token for other FOCI clients"
                    # Loop through cached refresh tokens
                    foreach($key in $Script:refresh_tokens.Keys)
                    {
                        # Extract the client id
                        [guid]$rtClientId = $key.Substring(0,36)
                        
                        if(IsFOCI -ClientId $rtClientId)
                        {
                            Write-Verbose "Using refresh token for ClientId $rtClientId"
                            # If FOCI client, get access token with it's refresh_token
                            $tenantId  = (Read-Accesstoken -AccessToken $Script:tokens[$key]).tid
                            $refresh_token = $Script:refresh_tokens[$key]
                            $retVal = Get-AccessTokenWithRefreshToken -Resource $Resource -ClientId $ClientID -RefreshToken $refresh_token -TenantId $tenantId -SaveToCache $True
                            break
                        }
                    }
                }

                if([string]::IsNullOrEmpty($retVal))
                {
                    # Empty, so throw the exception
                    Throw "No saved tokens found. Please call Get-AADIntAccessTokenFor<service> -SaveToCache"
                }
            }
            else
            {
                $retVal=$Script:tokens["$ClientId-$tResource"]
            }
        }
        else
        {
            # Check that the audience of the access token is correct
            $tAudience=(Read-Accesstoken -AccessToken $AccessToken).aud.TrimEnd("/")

            if(($tAudience -ne $tResource) -and ($Force -eq $False))
            {
                # Wrong audience
                Write-Verbose "ACCESS TOKEN HAS WRONG AUDIENCE: $tAudience. Exptected: $tResource."
                Throw "The audience of the access token ($tAudience) is wrong. Should be $tResource!"
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
            # Use the same client id as the expired token
            $ClientID = (Read-Accesstoken -AccessToken $retVal).appid

            Write-Verbose "ACCESS TOKEN HAS EXPRIRED. Trying to get a new one with RefreshToken."
            $retVal = Get-AccessTokenWithRefreshToken -Resource $Resource -ClientId $ClientID -RefreshToken (Get-RefreshTokenFromCache -AccessToken $retVal) -TenantId (Read-Accesstoken -AccessToken $retVal).tid -SaveToCache $true -IncludeRefreshToken $IncludeRefreshToken
        }

        # Return
        return $retVal
    }
}

# Returns refresh token from cache
# Apr 25th 2023
function Get-RefreshTokenFromCache
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='AccessToken',Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='ClientAndResource', Mandatory=$True)]
        [String]$ClientID,
        [Parameter(ParameterSetName='ClientAndResource', Mandatory=$True)]
        [String]$Resource
    )
    Process
    {
        # Get clientid and resource from access token if provided
        if($AccessToken)
        {
            $parsedToken = Read-AccessToken -AccessToken $AccessToken
            $ClientID = $parsedToken.appid
            $Resource = $parsedToken.aud
        }

        # Strip the trailing slash
        $Resource = $Resource.TrimEnd("/")
                
        return $Script:refresh_tokens["$ClientId-$Resource"]
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
        [String]$Resource="https://graph.windows.net",
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP

    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource $Resource -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -SAMLToken $SAMLToken -Tenant $Tenant -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -Tenant $Tenant -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "https://proxy.cloudwebappproxy.net/registerapp" -ClientId "cb1056e2-e479-49de-ae31-7812af012ed8" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "https://officeapps.live.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [ValidateSet("https://graph.microsoft.com","https://outlook.office365.com","https://outlook.office.com","https://substrate.office.com")]
        [String]$Resource="https://outlook.office365.com",
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        # Office app has the required rights to Exchange Online
        Get-AccessToken -Credentials $Credentials -Resource $Resource -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [string]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        # Office app has the required rights to Exchange Online
        Get-AccessToken -Credentials $Credentials -Resource "https://outlook.office365.com" -ClientId "a0c73c16-a7e3-4564-9a95-2bdf47383716" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -Domain $Domain -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        # Office app has the required rights to Exchange Online
        Get-AccessToken -Resource "https://api.diagnostics.office.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -KerberosTicket $KerberosTicket -Domain $Domain -Credentials $Credentials -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -Resource "https://$Tenant-my.sharepoint.com/" -ClientId "ab9b8c07-8f02-4f72-87fa-80105867a763" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials  -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        # Get access and refresh tokens
        #$clientId = "fdd7719f-d61e-4592-b501-793734eb8a0e" # SharePoint Migration Tool
        #$clientId = "9bc3ab49-b65d-410a-85ad-de819febfddc" # SPO Management shell
        $clientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c" # Microsoft Office

        $graphTokens = Get-AccessToken -Resource "https://graph.microsoft.com" -ClientId $clientId -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -IncludeRefreshToken $True -OTPSecretKey $OTPSecretKey -TAP $TAP

        # Get SPO root site url
        $response = Call-MSGraphAPI -AccessToken $graphTokens[0] -ApiVersion Beta -API "sites/root" -QueryString "select=webUrl"
        $SPOUrl = $response.webUrl.TrimEnd("/")
        $tenant = $SPOUrl.Split(".")[0]

        # Get SPO tokens 
        $SPOtokens = Get-AccessTokenWithRefreshToken       -Resource "$($tenant).sharepoint.com"       -ClientId $clientId -RefreshToken $graphTokens[1] -IncludeRefreshToken $true -TenantId "Common"
        $SPOtokens_my = Get-AccessTokenWithRefreshToken    -Resource "$($tenant)-my.sharepoint.com"    -ClientId $clientId -RefreshToken $graphTokens[1] -IncludeRefreshToken $true -TenantId "Common"
        $SPOtokens_admin = Get-AccessTokenWithRefreshToken -Resource "$($tenant)-admin.sharepoint.com" -ClientId $clientId -RefreshToken $graphTokens[1] -IncludeRefreshToken $true -TenantId "Common"

        if($SaveToCache)
        {
            # Add tokens to cache
            Add-AccessTokenToCache -AccessToken $graphTokens[0]     -RefreshToken $graphTokens[1]     -ShowCache $false
            Add-AccessTokenToCache -AccessToken $SPOtokens[0]       -RefreshToken $SPOtokens[1]       -ShowCache $false
            Add-AccessTokenToCache -AccessToken $SPOtokens_my[0]    -RefreshToken $SPOtokens_my[1]    -ShowCache $false
            Add-AccessTokenToCache -AccessToken $SPOtokens_admin[0] -RefreshToken $SPOtokens_admin[1] -ShowCache $false
        }
        else
        {
            return @($SPOtokens[0],$SPOtokens_my[0],$SPOtokens_admin[0])
        }
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
    
    .Parameter Credentials
    Credentials of the user.
   
    .Example
    PS C:\>Get-AADIntAccessTokenForMySignins
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [switch]$SaveToCache,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        return Get-AccessToken -ClientId 1b730954-1685-4b74-9bfd-dac224a7b894 -Resource "0000000c-0000-0000-c000-000000000000" -ForceMFA $true -Credentials $Credentials -SaveToCache $SaveToCache -KerberosTicket $KerberosTicket -Domain $Domain -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [switch]$SaveToCache,
        [switch]$ForceMFA,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        if($Device)
        {
            Get-AccessTokenWithDeviceSAML -SAML $SAMLToken -SaveToCache $SaveToCache
        }
        else
        {
            Get-AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -ForceMFA $ForceMFA -BPRT $BPRT -OTPSecretKey $OTPSecretKey -TAP $TAP
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

    .Parameter TransportKeyFileName
    File name of the transport key

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
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [switch]$ForceMFA,
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
        [string]$TransportKeyFileName,

        [Parameter(Mandatory=$False)]
        [string]$Resource="https://enrollment.manage.microsoft.com/",
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -ClientId "29d9ed98-a469-4536-ade2-f981bc1d605e" -Resource $Resource -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -Certificate $Certificate -PfxFileName $PfxFileName -PfxPassword $PfxPassword -BPRT $BPRT -ForceMFA $ForceMFA -TransportKeyFileName $TransportKeyFileName -OTPSecretKey $OTPSecretKey -TAP $TAP
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
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        # First, get an access token for admin.microsoft.com
        $response = Get-AccessToken -Resource "https://admin.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP

        if([string]::IsNullOrEmpty($response.Tenant))
        {
            $access_token = $response
        }

        # Get access token for management.core.windows.net using Admin API
        Get-AccessTokenUsingAdminAPI -AccessToken $access_token -Resource "https://management.core.windows.net/" -SaveToCache $SaveToCache
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
        [ValidateSet("https://api.spaces.skype.com", "https://outlook.com", "https://*.microsoftstream.com", "https://graph.microsoft.com")]
        [String]$Resource="https://api.spaces.skype.com",
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -Resource $Resource -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
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
    Get-AADIntAccessTokenForAADIAMAPI
    
    .Example
    PS C:\>Get-AADIntAccessTokenForAADIAMAPI -SaveToCache
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
        [string]$TAP
    )
    Process
    {
        # First get the access token for AADGraph
        $AccessTokens = Get-AccessToken -Resource "https://graph.windows.net" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -IncludeRefreshToken $True

        # Get the actual token
        $AccessToken = Get-AccessTokenWithRefreshToken -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -SaveToCache $SaveToCache -RefreshToken $AccessTokens[1] -TenantId (Read-Accesstoken $AccessTokens[0]).tid

        if(!$SaveToCache)
        {
            return $AccessToken
        }
    }
}

# Gets an access token for MS Commerce
# Aug 27th 2021
function Get-AccessTokenForMSCommerce
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for MS Commerce

    .DESCRIPTION
    Gets OAuth Access Token for MS Commerce

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
    Get-AADIntAccessTokenForMSCommerce
    
    .Example
    PS C:\>Get-AADIntAccessTokenForMSCommerce -SaveToCache
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
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -Resource "aeb86249-8ea3-49e2-900b-54cc8e308f85" -ClientId "3d5cffa9-04da-4657-8cab-c7f074657cad" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
    }
}

# Gets an access token for MS Partner
# Sep 22nd 2021
function Get-AccessTokenForMSPartner
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for MS Partner

    .DESCRIPTION
    Gets OAuth Access Token for MS Partner

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
    Get-AADIntAccessTokenForMSCommerce
    
    .Example
    PS C:\>Get-AADIntAccessTokenForMSPartner -SaveToCache
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
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        # The correct client id would be 4990cffe-04e8-4e8b-808a-1175604b879f but that flow doesn't work :(
        Get-AccessToken -Resource "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
    }
}

# Gets an access token for admin.microsoft.com
# Sep 22nd 2021
function Get-AccessTokenForAdmin
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for admin.microsoft.com

    .DESCRIPTION
    Gets OAuth Access Token for admin.microsoft.com

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
    Get-AADIntAccessTokenForAdmin
    
    .Example
    PS C:\>Get-AADIntAccessTokenForAdmin -SaveToCache
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
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -Resource "https://admin.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
    }
}

# Gets an access token for onenote.com
# Feb 2nd 2022
function Get-AccessTokenForOneNote
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for onenote.com

    .DESCRIPTION
    Gets OAuth Access Token for onenote.com

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
    Get-AADIntAccessTokenForOneNote
    
    .Example
    PS C:\>Get-AADIntAccessTokenForOneNote -SaveToCache
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
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -Resource "https://onenote.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
    }
}

# Gets an access token for for Access Packages
# Apr 24th 2023
function Get-AccessTokenForAccessPackages
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Access Packages

    .DESCRIPTION
    Gets OAuth Access Token for Access Packages

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
    Get-AADIntAccessTokenForAccessPackages
    
    .Example
    PS C:\>Get-AADIntAccessAccessPackages -SaveToCache
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
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        Get-AccessToken -Resource "https://elm.iga.azure.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -SaveToCache $SaveToCache -Tenant $Tenant -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -OTPSecretKey $OTPSecretKey -TAP $TAP
    }
}

# Gets an access token for Windows Hello for Business
# May 20th 2023
function Get-AccessTokenForWHfB
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Windows Hello for Business

    .DESCRIPTION
    Gets OAuth Access Token for Windows Hello for Business, allowing users to register WHfB key.

    .Parameter PRT
    PRT token of the user.

    .Example
    $prttoken = Get-AADIntUserPRTToken -Method TokenProvider
    Get-AADIntAccessTokenForWHfB -PRTToken $prttoken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [switch]$SaveToCache,
        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
    )
    Process
    {
        # Prompt credentials as that's the only allowed method
        $response = Prompt-Credentials -ClientID "dd762716-544d-4aeb-a526-687b73838a22" -Resource "urn:ms-drs:enterpriseregistration.windows.net" -RefreshTokenCredential $PRTToken -ForceNGCMFA $True -Credentials $Credentials -OTPSecretKey $OTPSecretKey -TAP $TAP

        $parsedAccessToken = Read-Accesstoken -AccessToken $response.access_token
        if([string]::IsNullOrEmpty($parsedAccessToken.DeviceId))
        {
            Write-Warning "No DeviceId claim present, device authentication failed. Expired PRT token?"
        }

        # Save to cache or return
        if($SaveToCache)
        {
            Add-AccessTokenToCache -AccessToken $response.access_token -RefreshToken $response.refresh_token -ShowCache $true
        }
        else
        {
            return $response.access_token
        }
    }
}

# Gets the access token for provisioning API and stores to cache
# Refactored Jun 8th 2020
function Get-AccessToken
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for the given client and resource. Using the given authentication method. If not provided, uses interactive logon.

    .DESCRIPTION
    Gets OAuth Access Token for the given client and resource. Using the given authentication method. If not provided, uses interactive logon.
    
    .Example
    $at=Get-AADIntAccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://graph.microsoft.com" 
    
    .Example
    Get-AADIntAccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://graph.microsoft.com" -SaveToCache $true -IncludeRefreshToken $true
    AccessToken saved to cache.

    Tenant   : 9779e97e-de19-45be-87ab-a7ed3e86fa62
    User     : user@company.com
    Resource : https://graph.microsoft.com
    Client   : d3590ed6-52b3-4102-aeff-aad2292ab01c
#>
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
        [bool]$ForceNGCMFA=$false,
        [Parameter(Mandatory=$False)]
        [bool]$UseDeviceCode=$false,
        [Parameter(Mandatory=$False)]
        [bool]$UseIMDS=$false,
        [Parameter(Mandatory=$False)]
        [String]$MsiResId,
        [Parameter(Mandatory=$False)]
        [String]$MsiClientId,
        [Parameter(Mandatory=$False)]
        [String]$MsiObjectId,
        [Parameter(Mandatory=$False)]
        [string]$BPRT,
        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$False)]
        [string]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [string]$TransportKeyFileName,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP
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
            "d3590ed6-52b3-4102-aeff-aad2292ab01c" # SPO
            "29d9ed98-a469-4536-ade2-f981bc1d605e" # MDM
            "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa" # Azure Android App
            "6c7e8096-f593-4d72-807f-a5f86dcc9c77" # MAM
            "4813382a-8fa7-425e-ab75-3b753aab3abb" # Microsoft authenticator
            "8c59ead7-d703-4a27-9e55-c96a0054c8d2"
            "c7d28c4f-0d2c-49d6-a88d-a275cc5473c7" # https://www.microsoftazuresponsorships.com/
            "04b07795-8ddb-461a-bbee-02f9e1bf7b46" # Azure CLI
            "ecd6b820-32c2-49b6-98a6-444530e5a77a" # Edge
            "1950a258-227b-4e31-a9cf-717495945fc2" # Microsoft Azure PowerShell
        )
    }
    Process
    {

        
        
        if(![String]::IsNullOrEmpty($KerberosTicket)) # Check if we got the kerberos token
        {
            # Get token using the kerberos token
            if([string]::IsNullOrEmpty($Tenant))
            {
                $Tenant = "common"
            }
            $OAuthInfo = Get-AccessTokenWithKerberosTicket -KerberosTicket $KerberosTicket -Domain $Domain -Resource $Resource -ClientId $ClientId -Tenant $Tenant
            $access_token = $OAuthInfo.access_token
        }
        elseif(![String]::IsNullOrEmpty($PRTToken)) # Check if we got a PRT token
        {
            # Get token using the PRT token
            $OAuthInfo = Get-AccessTokenWithPRT -Cookie $PRTToken -Resource $Resource -ClientId $ClientId  -Tenant $Tenant
            $access_token = $OAuthInfo.access_token
        }
        elseif($UseDeviceCode) # Check if we want to use device code flow
        {
            # Get token using device code
            $OAuthInfo = Get-AccessTokenUsingDeviceCode -Resource $Resource -ClientId $ClientId -Tenant $Tenant
            $access_token = $OAuthInfo.access_token
        }
        elseif($UseIMDS) # Check if we want to use IMDS
        {
            # Get token using Azure Instance Metadata Service (IMDS)
            $access_token = Get-AccessTokenUsingIMDS -ClientId $MsiClientId -ObjectId $MsiObjectId -AzureResourceId $MsiResId -Resource $Resource
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
        else # Authorization code grant flow - can use SAML or interactive prompt
        {
            if(![string]::IsNullOrEmpty($SAMLToken))
            {
                # Get token using SAML token
                $OAuthInfo = Get-OAuthInfoUsingSAML -SAMLToken $SAMLToken -ClientId $ClientId -Resource "https://graph.windows.net"
            }
            else
            {
                # Prompt for credentials
                if(  $ClientId -eq "d3590ed6-52b3-4102-aeff-aad2292ab01c" <# Office #> -or 
                     $ClientId -eq "a0c73c16-a7e3-4564-9a95-2bdf47383716" <# EXO #>    -or 
                    ($ClientId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" -and $Resource -eq "https://enrollment.manage.microsoft.com/") <# MDM #>
                )  
                {
                    $OAuthInfo = Prompt-Credentials -Resource $Resource -ClientId $ClientId -Tenant $Tenant -ForceMFA $ForceMFA -ForceNGCMFA $ForceNGCMFA -Credentials $Credentials -OTPSecretKey $OTPSecretKey -TAP $TAP
                }
                else
                {
                    $OAuthInfo = Prompt-Credentials -Resource "https://graph.windows.net" -ClientId $ClientId -Tenant $Tenant -ForceMFA $ForceMFA -ForceNGCMFA $ForceNGCMFA -Credentials $Credentials -OTPSecretKey $OTPSecretKey -TAP $TAP
                }

                # Just return null
                if(!$OAuthInfo)
                {
                    return $null
                }
                
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
				Add-AccessTokenToCache -AccessToken $OAuthInfo.access_token -RefreshToken $OAuthInfo.refresh_token -ShowCache $false
            }

            # Get the access token from response
            $access_token = Get-AccessTokenWithRefreshToken -Resource $Resource -ClientId $ClientId -TenantId $tenant_id -RefreshToken $RefreshToken -SaveToCache $SaveToCache
            
        }

        # Check is this current, new, or deprecated FOCI client
        IsFOCI -ClientId (Read-Accesstoken -AccessToken $OAuthInfo.access_token).appid -FOCI $OAuthInfo.foci | Out-Null
        $refresh_token = $OAuthInfo.refresh_token

        # Check whether we want to get the deviceid and (possibly) mfa in mra claim
        if(($Certificate -ne $null -and [string]::IsNullOrEmpty($PfxFileName)) -or ($Certificate -eq $null -and [string]::IsNullOrEmpty($PfxFileName) -eq $false))
        {
            try
            {
                Write-Verbose "Trying to get new tokens with deviceid claim."
                $deviceTokens = Set-AccessTokenDeviceAuth -AccessToken $access_token -RefreshToken $refresh_token -Certificate $Certificate -PfxFileName $PfxFileName -PfxPassword $PfxPassword -BPRT $([string]::IsNullOrEmpty($BPRT) -eq $False) -TransportKeyFileName $TransportKeyFileName
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
			Add-AccessTokenToCache -AccessToken $access_token -RefreshToken $refresh_token -ShowCache $false
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
<#
    .SYNOPSIS
    Gets OAuth Access Token for the given client and resource using the given refresh token.

    .DESCRIPTION
    Gets OAuth Access Token for the given client and resource using the given refresh token.
    For FOCI refresh tokens, i.e.,Family Refresh Tokens (FRTs), you can use any FOCI client id.
    
    .Example
    PS:\>$tokens=Get-AADIntAccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://graph.microsoft.com" -IncludeRefreshToken $true
    PS:\>$at=Get-AADIntAccessTokenWithRefreshToken -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -Resource "https://graph.windows.net" -TenantId "company.com" -RefreshToken $tokens[1] 
#>
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
        try 
        {
            $response=Invoke-RestMethod -UseBasicParsing -Uri $url -ContentType $contentType -Method POST -Body $body    
        }
        catch
        {
            $errorMessage = "Unable to get tokens using refresh token"
            try 
            {
                $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                if(-not [string]::IsNullOrEmpty($errorDetails.error_description))
                {
                    $errorMessage = $errorDetails.error_description.Split("`n")[0]
                }
            }
            catch {}
            throw $errorMessage
        }
        

        # Debug
        Write-Debug "ACCESS TOKEN RESPONSE: $response"

        # Check is this current, new, or deprecated FOCI client
        IsFOCI -ClientId (Read-Accesstoken -AccessToken $response.access_token).appid -FOCI $response.foci | Out-Null

        # Save the tokens to cache
        if($SaveToCache)
        {
            Write-Verbose "ACCESS TOKEN: SAVE TO CACHE"
			Add-AccessTokenToCache -AccessToken $response.access_token -RefreshToken $response.refresh_token -ShowCache $false
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
        $response = $null
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
        $response =    Invoke-RestMethod -UseBasicParsing -Uri $url -ContentType $contentType -Method POST -Body $body -Headers $headers

        # Debug
        Write-Debug "ACCESS TOKEN RESPONSE: $response"

        # Save the tokens to cache
        if($SaveToCache)
        {
            Write-Verbose "ACCESS TOKEN: SAVE TO CACHE"
			Add-AccessTokenToCache -AccessToken $response.access_token -RefreshToken $response.refresh_token -ShowCache $false
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
        $response =    Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType $contentType -Method POST -Body $body -Headers $headers

        # Debug
        Write-Debug "ACCESS TOKEN RESPONSE: $response"

        # Save the tokens to cache
        if($SaveToCache)
        {
            Write-Verbose "ACCESS TOKEN: SAVE TO CACHE"
			Add-AccessTokenToCache -AccessToken $response.access_token -RefreshToken $response.refresh_token -ShowCache $false
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
        $refresh_token = Get-RefreshTokenFromCache -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

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

# Apr 22th 2022
function Unprotect-EstsAuthPersistentCookie
{
<#
    .SYNOPSIS
    Decrypts and dumps users stored in ESTSAUTHPERSISTENT 

    .DESCRIPTION
    Decrypts and dumps users stored in ESTSAUTHPERSISTENT using login.microsoftonline.com/forgetUser

    .Parameter Cookie
    Value of ESTSAUTHPERSISTENT cookie
    
    .Example
    PS C:\>Unprotect-AADIntEstsAuthPersistentCookie -Cookie 0.ARMAqlCH3MZuvUCNgTAd4B7IRffhvoluXopNnz3s1gEl...

    name       : Some User
    login      : user@company.com
    imageAAD   : work_account.png
    imageMSA   : personal_account.png
    isLive     : False
    isGuest    : False
    link       : user@company.com
    authUrl    : 
    isSigned   : True
    sessionID  : 1fb5e6b3-09a4-4ceb-bcad-3d6d0ee89bf7
    domainHint : 
    isWindows  : False

    name       : Another User
    login      : user2@company.com
    imageAAD   : work_account.png
    imageMSA   : personal_account.png
    isLive     : False
    isGuest    : False
    link       : user2@company.com
    authUrl    : 
    isSigned   : False
    sessionID  : 1fb5e6b3-09a4-4ceb-bcad-3d6d0ee89bf7
    domainHint : 
    isWindows  : False
#>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [String]$Cookie
    )
    Process
    {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        
        $session.Cookies.Add((New-Object System.Net.Cookie("ESTSAUTHPERSISTENT", $Cookie, "/", ".login.microsoftonline.com")))
        Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/forgetuser?sessionid=$((New-Guid).toString())" -WebSession $session
    }
}


# Returns access token using Azure Instance Metadata Service (IMDS)
# Nov 8th 2022

function Get-AccessTokenUsingIMDS
{
<#
    .SYNOPSIS
    Gets access token using Azure Instance Metadata Service (IMDS)

    .DESCRIPTION
    Gets access token using Azure Instance Metadata Service (IMDS). 
    The ClientId of the token is the (Enterprise) Application ID of the managed identity.

    .Parameter Resource
    The App ID URI of the target resource. It also appears in the aud (audience) claim of the issued token. 

    .Parameter ObjectId
    The ObjectId of the managed identity you would like the token for. Required, if your VM has multiple user-assigned managed identities.

    .Parameter ClientId
    The ClientId of the managed identity you would like the token for. Required, if your VM has multiple user-assigned managed identities.

    .Parameter AzureResourceId
    The Azure Resource ID of the managed identity you would like the token for. Required, if your VM has multiple user-assigned managed identities.
    
    .Example
    PS C:\>Get-AADIntAccessTokenUsingIMDS -Resource https://management.core.windows.net | Add-AADIntAccessTokenToCache
    
    Name            : 
    ClientId        : 686d728a-2838-458d-9038-2d9808781b9a
    Audience        : https://management.core.windows.net
    Tenant          : ef35ef41-6e54-43f8-bdf0-b89827a3a991
    IsExpired       : False
    HasRefreshToken : False
    AuthMethods     : 
    Device          : 

    PS C:\>Get-AADIntAzureSubscriptions

    subscriptionId                       displayName state  
    --------------                       ----------- -----  
    233cd967-f2d4-41eb-897a-47ac77c7393d Production  Enabled

    PS C:\>Get-AADIntAzureResourceGroups -SubscriptionId "233cd967-f2d4-41eb-897a-47ac77c7393d"

    name                           location      tags
    ----                           --------      ----
    Production-Norway              norwayeast
    Production-Germany             westeurope
    Production-US-West             westus3
    Production-Sweden              swedencentral     
    Production-US-East             eastus            
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Resource,
        [Parameter(Mandatory=$False)]
        [String]$ClientId,
        [Parameter(Mandatory=$False)]
        [String]$ObjectId,
        [Parameter(Mandatory=$False)]
        [String]$AzureResourceId,
        [Parameter(Mandatory=$False)]
        [String]$ApiVersion="2018-02-01"
    )
    Process
    {
        # Construct the url
        # Ref: https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token#get-a-token-using-http

        $url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=$($ApiVersion)&resource=$($Resource)"
        if($ClientId)
        {
            $url += "&client_id=$ClientId"
        }
        if($ObjectId)
        {
            $url += "&object_id=$ObjectId"
        }
        if($AzureResourceId)
        {
            $url += "&msi_res_id=$AzureResourceId"
        }

        # Create the header
        $headers = @{
                "Metadata" = "true"
            }

        # Invoke the request. Short timeout as this may be a computer not able to access IMDS.
        $response = Invoke-RestMethod -UseBasicParsing -Uri $url -Method Get -Headers $headers -TimeoutSec 1
        
        # Return
        $response.access_token
    }
}