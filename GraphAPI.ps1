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

# Gets tenant's service principals
# Jun 24th 2020 
function Get-ServicePrincipals
{
<#
    .SYNOPSIS
    Extracts Azure AD service principals

    .DESCRIPTION
    Extracts Azure AD service principals. If client id(s) are provided, show detailed information.

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.

    .Parameter ClientIds
    List of client ids to get detailed information.

    .Example
    PS C:\>Get-AADIntAccessTokenForAADGraph -SaveToCache
    PS C:\>Get-AADIntServicePrincipals

    AccountEnabled        : true
    Addresses             :
    AppPrincipalId        : d32c68ad-72d2-4acb-a0c7-46bb2cf93873
    DisplayName           : Microsoft Activity Feed Service
    ObjectId              : 321e7bdd-d7b0-4a64-8eb3-38c259c1304a
    ServicePrincipalNames : ServicePrincipalNames
    TrustedForDelegation  : false

    AccountEnabled        : true
    Addresses             : Addresses
    AppPrincipalId        : 0000000c-0000-0000-c000-000000000000
    DisplayName           : Microsoft App Access Panel
    ObjectId              : a9e03f2f-4471-41f2-96c5-589d5d7117bc
    ServicePrincipalNames : ServicePrincipalNames
    TrustedForDelegation  : false

    AccountEnabled        : true
    Addresses             :
    AppPrincipalId        : dee7ba80-6a55-4f3b-a86c-746a9231ae49
    DisplayName           : Microsoft AppPlat EMA
    ObjectId              : ae0b81fc-c521-4bfd-9eaa-04c520b4b5fd
    ServicePrincipalNames : ServicePrincipalNames
    TrustedForDelegation  : false

    AccountEnabled        : true
    Addresses             : Addresses
    AppPrincipalId        : 65d91a3d-ab74-42e6-8a2f-0add61688c74
    DisplayName           : Microsoft Approval Management
    ObjectId              : d8ec5b95-e5f6-416e-8e7c-c6c52ec5a11f
    ServicePrincipalNames : ServicePrincipalNames
    TrustedForDelegation  : false
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String[]]$ClientIds
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # If client id(s) are provided, get only those (with extra information)
        if($ClientIds)
        {
            $body = @{
                "appIds" = $ClientIds
            }

            # Call the API
            Call-GraphAPI -AccessToken $AccessToken -Command "getServicePrincipalsByAppIds" -Body ($body | ConvertTo-Json) -Method Post -QueryString "`$Select="
        }
        else
        {
            # Call the Provisioning API
            Get-ServicePrincipals2 -AccessToken $AccessToken
        }

    }
}

