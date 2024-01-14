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

# Gets tenant's conditional access policies
# Apr 8th 2021
function Get-ConditionalAccessPolicies
{
<#
    .SYNOPSIS
    Shows conditional access policies.

    .DESCRIPTION
    Shows conditional access policies.

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.

    .Example
    PS C:\>Get-AADIntAccessTokenForAADGraph -SaveToCache
    PS C:\>Get-AADIntConditionalAccessPolicies

    odata.type          : Microsoft.DirectoryServices.Policy
    objectType          : Policy
    objectId            : 1a6a3b84-7d6d-4398-9c26-50fab315be8b
    deletionTimestamp   : 
    displayName         : Default Policy
    keyCredentials      : {}
    policyType          : 18
    policyDetail        : {{"Version":0,"State":"Disabled"}}
    policyIdentifier    : 2022-11-18T00:16:20.2379877Z
    tenantDefaultPolicy : 18

    odata.type          : Microsoft.DirectoryServices.Policy
    objectType          : Policy
    objectId            : 7f6ac8e5-bd21-4091-ae4c-0e48e0f4db04
    deletionTimestamp   : 
    displayName         : Block NestorW
    keyCredentials      : {}
    policyType          : 18
    policyDetail        : {{"Version":1,"CreatedDateTime":"2022-11-18T00:16:19.461967Z","State":"Enabled
                          ","Conditions":{"Applications":{"Include":[{"Applications":["None"]}]},"Users"
                          :{"Include":[{"Users":["8ab3ed0d-6668-49f7-a108-c50bb230c870"]}]}},"Controls":
                          [{"Control":["Block"]}],"EnforceAllPoliciesForEas":true,"IncludeOtherLegacyCli
                          entTypeForEvaluation":true}}
    policyIdentifier    : 
    tenantDefaultPolicy : 
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Return conditional access policies
        Get-AzureADPolicies -AccessToken $AccessToken | Where policyType -eq 18
    }
}

# Gets tenant's Azure AD Policies
# Nov 17th 2022
function Get-AzureADPolicies
{
<#
    .SYNOPSIS
    Shows Azure AD policies.

    .DESCRIPTION
    Shows Azure AD policies.

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.

    .Example
    PS C:\>Get-AADIntAccessTokenForAADGraph -SaveToCache
    PS C:\>Get-AADIntAzureADPolicies

    odata.type          : Microsoft.DirectoryServices.Policy
    objectType          : Policy
    objectId            : e35e4cd3-53f8-4d65-80bb-e3279c2c1b71
    deletionTimestamp   : 
    displayName         : On-Premise Authentication Flow Policy
    keyCredentials      : {**}
    policyType          : 8
    policyDetail        : {**}
    policyIdentifier    : 
    tenantDefaultPolicy : 8

    odata.type          : Microsoft.DirectoryServices.Policy
    objectType          : Policy
    objectId            : 259b810f-fb50-4e57-925b-ec2292c17883
    deletionTimestamp   : 
    displayName         : 2/5/2021 5:53:07 AM
    keyCredentials      : {}
    policyType          : 10
    policyDetail        : {{"SecurityPolicy":{"Version":0,"SecurityDefaults":{"IgnoreBaselineProtectionPolicies":true,"I
                          sEnabled":false}}}}
    policyIdentifier    : 
    tenantDefaultPolicy : 10
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
        Call-GraphAPI -AccessToken $AccessToken -Command "policies" -Method Get
    }
}

# Gets tenant's Azure AD Policies
# Nov 17th 2022
function Set-AzureADPolicyDetails
{
<#
    .SYNOPSIS
    Sets Azure AD policy details.

    .DESCRIPTION
    Sets Azure AD policy details.

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.

    .PARAMETER ObjectId
    Object ID of the policy

    .PARAMETER PolicyDetail
    Policy details.

    .PARAMETER DisplayName
    New displayname of the policy

    .Example
    PS C:\>Get-AADIntAccessTokenForAADGraph -SaveToCache
    PS C:\>Set-AADIntAzureADPolicyDetail -ObjectId "e35e4cd3-53f8-4d65-80bb-e3279c2c1b71" -PolicyDetail '{{"SecurityPolicy":{"Version":0,"SecurityDefaults":{"IgnoreBaselineProtectionPolicies":true,"IsEnabled":false}}}}'

    .Example
    PS C:\>Get-AADIntAccessTokenForAADGraph -SaveToCache
    PS C:\>Set-AADIntAzureADPolicyDetail -ObjectId "e35e4cd3-53f8-4d65-80bb-e3279c2c1b71" -PolicyDetail '{{"SecurityPolicy":{"Version":0,"SecurityDefaults":{"IgnoreBaselineProtectionPolicies":true,"IsEnabled":false}}}}' -displayName "My Policy"

    
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [Guid]$ObjectId,
        [Parameter(Mandatory=$True)]
        [String]$PolicyDetail,
        [Parameter(Mandatory=$False)]
        [String]$DisplayName
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"
        
        $body = @{
            "policyDetail" = @($PolicyDetail)
        }
        if(![string]::IsNullOrEmpty($DisplayName))
        {
            $body["displayName"] = $DisplayName
        }

        # Call the API
        Call-GraphAPI -AccessToken $AccessToken -Command "policies/$($ObjectId)" -Method Patch -Body ($body | ConvertTo-Json)
    }
}

# Get Azure AD features
# Aug 23 2023
function Get-AzureADFeatures
{
<#
    .SYNOPSIS
    Show the status of Azure AD features.

    .DESCRIPTION
    Show the status of Azure AD features using Azure AD Graph internal API.
    Requires Global Administrator role
    
    .Parameter AccessToken
    Access Token

    .Example
    Get-AADIntAccessTokenForAADGraph -SaveToCache
    PS C:\>Get-AADIntAzureADFeatures 

    Feature                                             Enabled
    -------                                             -------
    AllowEmailVerifiedUsers                                True
    AllowInvitations                                       True
    AllowMemberUsersToInviteOthersAsMembers               False
    AllowUsersToChangeTheirDisplayName                    False
    B2CFeature                                            False
    BlockAllTenantAuth                                    False
    ConsentedForMigrationToPublicCloud                    False
    CIAMFeature                                           False
    CIAMTrialFeature                                      False
    CIAMTrialUpgrade                                      False
    EnableExchangeDualWrite                               False
    EnableHiddenMembership                                False
    EnableSharedEmailDomainApis                           False
    EnableWindowsLegacyCredentials                        False
    EnableWindowsSupplementalCredentials                  False
    ElevatedGuestsAccessEnabled                           False
    ExchangeDualWriteUsersV1                              False
    GuestsCanInviteOthersEnabled                           True
    InvitationsEnabled                                     True
    LargeScaleTenant                                      False
    TestTenant                                            False
    USGovTenant                                           False
    DisableOnPremisesWindowsLegacyCredentialsSync         False
    DisableOnPremisesWindowsSupplementalCredentialsSync   False
    RestrictPublicNetworkAccess                           False
    AutoApproveSameTenantRequests                         False
    RedirectPpeUsersToMsaInt                              False
    LegacyTlsExceptionForEsts                             False
    LegacyTlsBlockForEsts                                 False
    TenantAuthBlockReasonFraud                            False
    TenantAuthBlockReasonLifecycle                        False
    TenantExcludeDeprecateAADLicenses                     False
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Begin
    {
        $features = @(
            "AllowEmailVerifiedUsers"
            "AllowInvitations"
            "AllowMemberUsersToInviteOthersAsMembers"
            "AllowUsersToChangeTheirDisplayName"
            "B2CFeature"
            "BlockAllTenantAuth"
            "ConsentedForMigrationToPublicCloud"
            "CIAMFeature"
            "CIAMTrialFeature"
            "CIAMTrialUpgrade"
            "EnableExchangeDualWrite"
            "EnableHiddenMembership"
            "EnableSharedEmailDomainApis"
            "EnableWindowsLegacyCredentials"
            "EnableWindowsSupplementalCredentials"
            "ElevatedGuestsAccessEnabled"
            "ExchangeDualWriteUsersV1"
            "GuestsCanInviteOthersEnabled"
            "InvitationsEnabled"
            "LargeScaleTenant"
            "TestTenant"
            "USGovTenant"
            "DisableOnPremisesWindowsLegacyCredentialsSync"
            "DisableOnPremisesWindowsSupplementalCredentialsSync"
            "RestrictPublicNetworkAccess"
            "AutoApproveSameTenantRequests"
            "RedirectPpeUsersToMsaInt"
            "LegacyTlsExceptionForEsts"
            "LegacyTlsBlockForEsts"
            "TenantAuthBlockReasonFraud"
            "TenantAuthBlockReasonLifecycle"
            "TenantExcludeDeprecateAADLicenses"
        )
    }
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        $retVal = @()

        # Loop through the features
        foreach($feature in $features)
        {
            try
            {
                $value = Get-AzureADFeature -AccessToken $AccessToken -Feature $feature

                $retVal += [pscustomobject][ordered]@{
                    "Feature" = $feature
                    "Enabled" = $value
                }
            }
            catch
            {
            }
        }

        $retVal
        
        
    }
}

# Get Azure AD feature status
# Aug 23 2023
function Get-AzureADFeature
{
<#
    .SYNOPSIS
    Show the status of given Azure AD feature.

    .DESCRIPTION
    Show the status of given Azure AD feature using Azure AD Graph internal API.
    Requires Global Administrator role
    
    .Parameter AccessToken
    Access Token

    .PARAMETER Feature
    The name of the feature. Should be one of:

    AllowEmailVerifiedUsers
    AllowInvitations
    AllowMemberUsersToInviteOthersAsMembers
    AllowUsersToChangeTheirDisplayName
    B2CFeature
    BlockAllTenantAuth
    ConsentedForMigrationToPublicCloud
    CIAMFeature
    CIAMTrialFeature
    CIAMTrialUpgrade
    EnableExchangeDualWrite
    EnableHiddenMembership
    EnableSharedEmailDomainApis
    EnableWindowsLegacyCredentials
    EnableWindowsSupplementalCredentials
    ElevatedGuestsAccessEnabled
    ExchangeDualWriteUsersV1
    GuestsCanInviteOthersEnabled
    InvitationsEnabled
    LargeScaleTenant
    TestTenant
    USGovTenant
    DisableOnPremisesWindowsLegacyCredentialsSync
    DisableOnPremisesWindowsSupplementalCredentialsSync
    RestrictPublicNetworkAccess
    AutoApproveSameTenantRequests
    RedirectPpeUsersToMsaInt
    LegacyTlsExceptionForEsts
    LegacyTlsBlockForEsts
    TenantAuthBlockReasonFraud
    TenantAuthBlockReasonLifecycle
    TenantExcludeDeprecateAADLicenses

    .Example
    Get-AADIntAccessTokenForAADGraph -SaveToCache
    PS C:\>Get-AADIntAzureADFeature -Feature "B2CFeature"

    True
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [ValidateSet('AllowEmailVerifiedUsers','AllowInvitations','AllowMemberUsersToInviteOthersAsMembers','AllowUsersToChangeTheirDisplayName','B2CFeature','BlockAllTenantAuth','ConsentedForMigrationToPublicCloud','CIAMFeature','CIAMTrialFeature','CIAMTrialUpgrade','EnableExchangeDualWrite','EnableHiddenMembership','EnableSharedEmailDomainApis','EnableWindowsLegacyCredentials','EnableWindowsSupplementalCredentials','ElevatedGuestsAccessEnabled','ExchangeDualWriteUsersV1','GuestsCanInviteOthersEnabled','InvitationsEnabled','LargeScaleTenant','TestTenant','USGovTenant','DisableOnPremisesWindowsLegacyCredentialsSync','DisableOnPremisesWindowsSupplementalCredentialsSync','RestrictPublicNetworkAccess','AutoApproveSameTenantRequests','RedirectPpeUsersToMsaInt','LegacyTlsExceptionForEsts','LegacyTlsBlockForEsts','TenantAuthBlockReasonFraud','TenantAuthBlockReasonLifecycle','TenantExcludeDeprecateAADLicenses')]
        [Parameter(Mandatory=$True)]
        [String]$Feature
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        $body = @{
            "directoryFeature" = $feature
        }

        # Call the API
        try
        {
            $response = Call-GraphAPI -AccessToken $AccessToken -Command "isDirectoryFeatureEnabled" -Method Post -Body ($body | ConvertTo-Json)

            $enabled = $false;

            # For some reason True is returned as boolean but False as object with value attribute
            if($response -isnot [boolean])
            {
                $enabled = $response.Value
            }
            else
            {
                $enabled = $response
            }
            
            return $enabled
        }
        catch
        {
            $stream = $_.Exception.Response.GetResponseStream()
            $responseBytes = New-Object byte[] $stream.Length

            $stream.Position = 0
            $stream.Read($responseBytes,0,$stream.Length) | Out-Null
            
            $response = [text.encoding]::UTF8.GetString($responseBytes) | ConvertFrom-Json
            
            throw $response.'odata.error'.message.value
        }
    }
}

# Enable or Disable Azure AD feature
# Aug 23 2023
function Set-AzureADFeature
{
<#
    .SYNOPSIS
    Enables or disables the given Azure AD feature.

    .DESCRIPTION
    Enables or disables the given Azure AD feature using Azure AD Graph internal API.
    Requires Global Administrator role
    
    .Parameter AccessToken
    Access Token

    .PARAMETER Feature
    The name of the feature. Should be one of:

    AllowEmailVerifiedUsers
    AllowInvitations
    AllowMemberUsersToInviteOthersAsMembers
    AllowUsersToChangeTheirDisplayName
    B2CFeature
    BlockAllTenantAuth
    ConsentedForMigrationToPublicCloud
    CIAMFeature
    CIAMTrialFeature
    CIAMTrialUpgrade
    EnableExchangeDualWrite
    EnableHiddenMembership
    EnableSharedEmailDomainApis
    EnableWindowsLegacyCredentials
    EnableWindowsSupplementalCredentials
    ElevatedGuestsAccessEnabled
    ExchangeDualWriteUsersV1
    GuestsCanInviteOthersEnabled
    InvitationsEnabled
    LargeScaleTenant
    TestTenant
    USGovTenant
    DisableOnPremisesWindowsLegacyCredentialsSync
    DisableOnPremisesWindowsSupplementalCredentialsSync
    RestrictPublicNetworkAccess
    AutoApproveSameTenantRequests
    RedirectPpeUsersToMsaInt
    LegacyTlsExceptionForEsts
    LegacyTlsBlockForEsts
    TenantAuthBlockReasonFraud
    TenantAuthBlockReasonLifecycle
    TenantExcludeDeprecateAADLicenses

    .Example
    Get-AADIntAccessTokenForAADGraph -SaveToCache
    PS C:\>Set-AADIntAzureADFeature -Feature "B2CFeature" -Enable $true

    Feature      Enabled
    -------      -------
    B2CFeature      True

    .Example
    Get-AADIntAccessTokenForAADGraph -SaveToCache
    PS C:\>Set-AADIntAzureADFeature -Feature "B2CFeature" -Enable $false

    Feature      Enabled
    -------      -------
    B2CFeature     False
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [ValidateSet('AllowEmailVerifiedUsers','AllowInvitations','AllowMemberUsersToInviteOthersAsMembers','AllowUsersToChangeTheirDisplayName','B2CFeature','BlockAllTenantAuth','ConsentedForMigrationToPublicCloud','CIAMFeature','CIAMTrialFeature','CIAMTrialUpgrade','EnableExchangeDualWrite','EnableHiddenMembership','EnableSharedEmailDomainApis','EnableWindowsLegacyCredentials','EnableWindowsSupplementalCredentials','ElevatedGuestsAccessEnabled','ExchangeDualWriteUsersV1','GuestsCanInviteOthersEnabled','InvitationsEnabled','LargeScaleTenant','TestTenant','USGovTenant','DisableOnPremisesWindowsLegacyCredentialsSync','DisableOnPremisesWindowsSupplementalCredentialsSync','RestrictPublicNetworkAccess','AutoApproveSameTenantRequests','RedirectPpeUsersToMsaInt','LegacyTlsExceptionForEsts','LegacyTlsBlockForEsts','TenantAuthBlockReasonFraud','TenantAuthBlockReasonLifecycle','TenantExcludeDeprecateAADLicenses')]
        [Parameter(Mandatory=$True)]
        [String]$Feature,
        [Parameter(Mandatory=$True)]
        [bool]$Enabled
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        $isEnabled = Get-AzureADFeature -Feature $feature -AccessToken $AccessToken

        if($Enabled)
        {
            # Check if already enabled
            if($isEnabled)
            {
                Write-Warning "Feature $feature is already enabled."
                return
            }
            $command = "enableDirectoryFeature"
        }
        else
        {
            # Check if already disabled
            if(!$isEnabled)
            {
                Write-Warning "Feature $feature is already disabled."
                return
            }
            $command = "disableDirectoryFeature"
        }

        $body = @{
            "directoryFeature" = $feature
        }

        # Call the API
        try
        {
            Call-GraphAPI -AccessToken $AccessToken -Command $command -Method Post -Body ($body | ConvertTo-Json)
        }
        catch
        {
            $stream = $_.Exception.Response.GetResponseStream()
            $responseBytes = New-Object byte[] $stream.Length

            $stream.Position = 0
            $stream.Read($responseBytes,0,$stream.Length) | Out-Null
            
            $response = [text.encoding]::UTF8.GetString($responseBytes) | ConvertFrom-Json
            
            throw $response.'odata.error'.message.value
        }

        
        [pscustomobject][ordered]@{
            "Feature" = $feature
            "Enabled" = Get-AzureADFeature -AccessToken $AccessToken -Feature $feature
        }
        
    }
}


# Adds Microsoft.Azure.SyncFabric service principal
# Dec 4th 2023
function Add-SyncFabricServicePrincipal
{
<#
    .SYNOPSIS
    Adds Microsoft.Azure.SyncFabric service principal needed to create BPRTs.

    .DESCRIPTION
    Adds Microsoft.Azure.SyncFabric service principal needed to create BPRTs. 
    
    Requires Application Administrator, Cloud Application Administrator, Directory Synchronization Accounts, Hybrid Identity Administrator, or Global Administrator permissions.

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.

    .Example
    PS C:\>Get-AADIntAccessTokenForAADGraph -SaveToCache
    PS C:\>Add-AADIntSyncFabricServicePrincipal

    DisplayName                AppId                                ObjectId                            
    -----------                -----                                --------                            
    Microsoft.Azure.SyncFabric 00000014-0000-0000-c000-000000000000 138018f7-6aa2-454c-a103-a7e682e17d6b
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        
        $body = @{
            "accountEnabled"            = "True"
	        "appId"                     = "00000014-0000-0000-c000-000000000000"
	        "appRoleAssignmentRequired" = $false
	        "displayName"               = "Microsoft.Azure.SyncFabric"
	        "tags"                      = @( "WindowsAzureActiveDirectoryIntegratedApp" )
        }

        # Call the API
        $result = Call-GraphAPI -AccessToken $AccessToken -Command "servicePrincipals" -Body ($body | ConvertTo-Json) -Method Post

        if($result)
        {
            [pscustomobject]@{
                "DisplayName" = $result.displayName
                "AppId"       = $result.appId
                "ObjectId"    = $result.objectId
            }
        }
        

    }
}