# This script contains functions for Graph API at https://graph.windows.net
# Office 365 / Azure AD v2, a.k.a. AzureAD module uses this API

function Get-AADUsers
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$SearchString,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
        
    )
    Process
    {
        if(![string]::IsNullOrEmpty($SearchString))
        {
            $queryString="`$filter=(startswith(displayName,'$SearchString') or startswith(userPrincipalName,'$SearchString'))"
        }
        elseif(![string]::IsNullOrEmpty($UserPrincipalName))
        {
            $queryString="`$filter=userPrincipalName eq '$UserPrincipalName'"
        }

        $results=Call-GraphAPI -AccessToken $AccessToken -Command users -QueryString $queryString

        return $results
    }
}

# Gets the tenant details 
function Get-TenantDetails
{
<#
    .SYNOPSIS
    Extract tenant details using the given Access Token

    .DESCRIPTION
    Extract tenant details using the given Access Token

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.
    
    .Example
    PS C:\>$token=Get-AADIntAccessTokenForAADGraph
    PS C:\>Get-AADIntTenantDetails -AccessToken $token

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Call the API
        $response=Call-GraphAPI -AccessToken $AccessToken -Command tenantDetails 
        
        # Verbose
        Write-Verbose "TENANT INFORMATION: $($response.value | Out-String)"

        # Return
        $response
    }
}

# Gets the tenant devices
# Jun 24th 2020 
function Get-Devices
{
<#
    .SYNOPSIS
    Extracts tenant devices using the given Access Token

    .DESCRIPTION
    Extracts tenant devices using the given Access Token

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.
    
    .Example
    PS C:\>$token=Get-AADIntAccessTokenForAADGraph
    PS C:\>Get-AADIntDevices -AccessToken $token

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Call the API
        $response=Call-GraphAPI -AccessToken $AccessToken -Command devices -QueryString "`$expand=registeredOwner"
        
        # Return
        $response
    }
}

# Gets detailed information about the given user
# Jun 24th 2020 
function Get-UserDetails
{
<#
    .SYNOPSIS
    Extracts detailed information of the given user

    .DESCRIPTION
    Extracts detailed information of the given user

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.

    .Parameter UserPrincipalName
    The user principal name of the user whose details is to be extracted
    
    .Example
    PS C:\>$token=Get-AADIntAccessTokenForAADGraph
    PS C:\>Get-AADIntUserDetails -AccessToken $token

    odata.type                            : Microsoft.DirectoryServices.User
    objectType                            : User
    objectId                              : cd5676ad-ba80-4782-bdcb-ff5de37fc347
    deletionTimestamp                     : 
    acceptedAs                            : 
    acceptedOn                            : 
    accountEnabled                        : True
    ageGroup                              : 
    alternativeSecurityIds                : {}
    signInNames                           : {user@company.com}
    signInNamesInfo                       : {}
    appMetadata                           : 
    assignedLicenses                      : {@{disabledPlans=System.Object[]; skuId=c7df2760-2c81-4ef7-b578-5b5392b571df}, @{disabledPlans=System.Object[]; skuId=b05e124f-c7cc-45a0-a6aa-8cf78c946968}}
    assignedPlans                         : {@{assignedTimestamp=2019-12-02T07:41:59Z; capabilityStatus=Enabled; service=MultiFactorService; servicePlanId=8a256a2b-b617-496d-b51b-e76466e88db0}, @{assignedTimestamp=2019-12-02T07
                                            :41:59Z; capabilityStatus=Enabled; service=exchange; servicePlanId=34c0d7a0-a70f-4668-9238-47f9fc208882}, @{assignedTimestamp=2019-12-02T07:41:59Z; capabilityStatus=Enabled; service=P
                                            owerBI; servicePlanId=70d33638-9c74-4d01-bfd3-562de28bd4ba}, @{assignedTimestamp=2019-12-02T07:41:59Z; capabilityStatus=Enabled; service=WhiteboardServices; servicePlanId=4a51bca5-1ef
                                            f-43f5-878c-177680f191af}...}
    city                                  : 
    cloudAudioConferencingProviderInfo    : <acpList>
                                              <acpInformation default="true">
                                                <tollNumber>18728886261</tollNumber>
                                                <participantPassCode>0</participantPassCode>
                                                <domain>resources.lync.com</domain>
                                                <name>Microsoft</name>
                                                <url>https://dialin.lync.com/c73270cd-afd0-4f70-8328-747f36508d85</url>
                                              </acpInformation>
                                            </acpList>
    cloudMSExchRecipientDisplayType       : 1073741824
    cloudMSRtcIsSipEnabled                : True
    cloudMSRtcOwnerUrn                    : 
    ...


#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$UserPrincipalName
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        # Call the API
        $response=Call-GraphAPI -AccessToken $AccessToken -Command "users/$UserPrincipalName" 
        
        # Return
        $response
    }
}

# Gets tenant's Azure AD settings
# Jun 24th 2020 
function Get-Settings
{
<#
    .SYNOPSIS
    Extracts Azure AD settings

    .DESCRIPTION
    Extracts Azure AD settings

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.

    .Example
    PS C:\>$token=Get-AADIntAccessTokenForAADGraph
    PS C:\>Get-AADIntSettings -AccessToken $token

    id                                   displayName            templateId                           values                                                                                                                        
    --                                   -----------            ----------                           ------                                                                                                                        
    8b16b029-bb31-48c8-b4df-5ee419596688 Password Rule Settings 5cf42378-d67d-4f36-ba46-e8b86229381d {@{name=BannedPasswordCheckOnPremisesMode; value=Audit}, @{name=EnableBannedPasswordCheckOnPremises; value=True}, @{name=En...


#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Call the API
        $response=Call-GraphAPI -AccessToken $AccessToken -Command "settings"
        
        # Return
        $response
    }
}

# Gets tenant's OAuth grants
# Jun 24th 2020 
function Get-OAuthGrants
{
<#
    .SYNOPSIS
    Extracts Azure AD OAuth grants

    .DESCRIPTION
    Extracts Azure AD OAuth grants

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.

    .Example
    PS C:\>$token=Get-AADIntAccessTokenForAADGraph
    PS C:\>Get-AADIntOAuthGrants -AccessToken $token

    id                                   displayName            templateId                           values                                                                                                                        
    --                                   -----------            ----------                           ------                                                                                                                        
    8b16b029-bb31-48c8-b4df-5ee419596688 Password Rule Settings 5cf42378-d67d-4f36-ba46-e8b86229381d {@{name=BannedPasswordCheckOnPremisesMode; value=Audit}, @{name=EnableBannedPasswordCheckOnPremises; value=True}, @{name=En...


#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Call the API
        $response=Call-GraphAPI -AccessToken $AccessToken -Command "oauth2PermissionGrants"
        
        # Return
        $response
    }
}

# Gets tenant's OAuth grants
# Jun 24th 2020 
function Get-ServicePrincipals
{
<#
    .SYNOPSIS
    Extracts Azure AD service principals

    .DESCRIPTION
    Extracts Azure AD service principals

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.

    .Example
    PS C:\>$token=Get-AADIntAccessTokenForAADGraph
    PS C:\>Get-AADIntServicePrincipals -AccessToken $token

    odata.type                          : Microsoft.DirectoryServices.ServicePrincipal
    objectType                          : ServicePrincipal
    objectId                            : 3f3d070e-e5ac-4c5b-b23d-3313955df685
    deletionTimestamp                   : 
    accountEnabled                      : True
    addIns                              : {}
    alternativeNames                    : {}
    appBranding                         : 
    appCategory                         : 
    appData                             : 
    appDisplayName                      : Microsoft Dynamics 365 Apps Integration
    appId                               : 44a02aaa-7145-4925-9dcd-79e6e1b94eff
    applicationTemplateId               : 
    appMetadata                         : 
    appOwnerTenantId                    : f8cdef31-a31e-4b4a-93e4-5f571e91255a
    appRoleAssignmentRequired           : False
    appRoles                            : {}
    authenticationPolicy                : 
    displayName                         : Microsoft Dynamics 365 Apps Integration
    errorUrl                            : 
    homepage                            : 
    informationalUrls                   : @{termsOfService=; support=; privacy=; marketing=}
    keyCredentials                      : {}
    logoutUrl                           : https://msteamstabintegration.crm.dynamics.com
    managedIdentityResourceId           : 
    microsoftFirstParty                 : True
    notificationEmailAddresses          : {}
    oauth2Permissions                   : {@{adminConsentDescription=Allows the application to access Microsoft Dynamics 365 Apps Integration acting as users in the organization; adminConsentDisplayName=Access Dynamics 365 Apps
                                           Integration as organization user; id=f43389c9-db90-4009-be93-f3251d41f11f; isEnabled=True; lang=; origin=Application; type=User; userConsentDescription=Allows the application to access


#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Call the API
        $response=Call-GraphAPI -AccessToken $AccessToken -Command "servicePrincipals" -QueryString "`$top=999"
        
        # Return
        $response
    }
}