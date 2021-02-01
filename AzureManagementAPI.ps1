

# Get users using Azure Management API
# Oct 23rd 2018
function Get-AzureManagementUsers
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AccessToken
    )
    Process
    {
        $response=Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "Users?searchText=&top=100&nextLink=&orderByThumbnails=false&maxThumbnailCount=999&filterValue=All&state=All&adminUnit="
        return $response.items
    }
}

# Creates an user using Azure Management API
# Oct 23rd 2018
function New-AzureManagementUser
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$UserPrincipalnName,
        [Parameter(Mandatory=$True)]
        [string]$DisplayName,
        [Parameter(Mandatory=$True)]
        [string]$Password,
        [switch]$GlobalAdmin
    )
    Process
    {

        $pwdProfile=@{
            "forceChangePasswordNextLogin"="False"
            "password"=$Password
        }

        $rolesEntity=""
        if($GlobalAdmin)
        {
            $rolesEntity=@{
                "adminType"="3" # Global Admin
                "enabledRoles"=""
            }
        }

        $Body=@{
            "displayName" = $DisplayName
            "userPrincipalName" = $UserPrincipalnName
            "passwordProfile" = $pwdProfile
            "rolesEntity" = $rolesEntity

        }

        return Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "UserDetails" -Body $Body -Method "Post"
    }
}


# Removes the given user using Azure Management API
# Oct 23rd 2018
function Remove-AzureManagementUser
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$ObjectId
    )
    Process
    {
        return Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "Users/$ObjectId" -Method Delete
    }
}

# Removes the given users using Azure Management API
# Oct 23rd 2018
function Remove-AzureManagementUsers
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AccessToken,
        [Parameter(Mandatory=$True)]
        [string[]]$ObjectIds
    )
    Process
    {
        return Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "Users" -Method Delete -Body $ObjectIds
    }
}

# Checks whether the external user is unique or already exists in AAD
# Oct 23rd 2018
function Is-ExternalUserUnique
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$EmailAddress
        
    )
    Process
    {
        return Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "Users/IsUPNUniqueOrPending/$EmailAddress" 
    }
}


# Invites an external user to AAD
# Oct 23rd 2018
function New-GuestInvitation
{

<#
    .SYNOPSIS
    Invites an user to AAD

    .DESCRIPTION
    Invites an user to AAD using Azure Management API

    .Parameter AccessToken
    Auth Token

    .Parameter EmailAddress
    Email address of the guest user

    .Parameter Message
    The message to be sent with the invitation

    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForAADIAMAPI -Credentials $cred
    PS C:\>New-AADIntGuestInvitation -EmailAddress someone@company.com -Message "Welcome to our Tenant!"

    accountEnabled                        : True
    usageLocation                         : 
    mailNickname                          : someone_company.com#EXT#
    passwordProfile                       : 
    rolesEntity                           : 
    selectedGroupIds                      : 
    streetAddress                         : 
    city                                  : 
    state                                 : 
    country                               : 
    telephoneNumber                       : 
    mobile                                : 
    physicalDeliveryOfficeName            : 
    postalCode                            : 
    authenticationPhoneNumber             : 
    authenticationAlternativePhoneNumber  : 
    authenticationEmail                   : 
    strongAuthenticationDetail            : @{verificationDetail=}
    defaultImageUrl                       : 
    ageGroup                              : 
    consentProvidedForMinor               : 
    legalAgeGroupClassification           : 
    objectId                              : e550c8f5-aff3-4eea-9d68-cff019fa850e
    objectType                            : User
    displayName                           : someone
    userPrincipalName                     : someone_company.com#EXT#@company.onmicrosoft.com
    thumbnailPhoto@odata.mediaContentType : 
    givenName                             : 
    surname                               : 
    mail                                  : someone@company.com
    dirSyncEnabled                        : 
    alternativeSecurityIds                : {}
    signInNamesInfo                       : {}
    signInNames                           : {someone_company.com#EXT#@company.onmicrosoft.com}
    ownedDevices                          : 
    jobTitle                              : 
    department                            : 
    displayUserPrincipalName              : 
    hasThumbnail                          : False
    imageUrl                              : 
    imageDataToUpload                     : 
    source                                : 
    sources                               : 
    sourceText                            : 
    userFlags                             : 
    deletionTimestamp                     : 
    permanentDeletionTime                 : 
    alternateEmailAddress                 : 
    manager                               : 
    userType                              : Guest
    isThumbnailUpdated                    : 
    isAuthenticationContactInfoUpdated    : 
    searchableDeviceKey                   : {}
    displayEmail                          : 
    creationType                          : Invitation
    userState                             : PendingAcceptance
    otherMails                            : {someone@company.com}
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$EmailAddress,
        [Parameter(Mandatory=$False)]
        [string]$Message
        
    )
    Process
    {
        
        $UserToInvite = @{
            "displayName"=$EmailAddress
            "userPrincipalName" = $EmailAddress
            "givenName" = "null"
            "surname" = "null" 
            "jobTitle" = "null" 
            "department" = "null" 
            "passwordProfile" = ""
            "selectedGroupIds" = "" 
            "rolesEntity" = ""
        }
        $Body=@{
            "userToInvite"=$UserToInvite
            "inviteMessage"=$Message
        }

        return Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "Users/Invite" -Method "Put" -Body $Body
    }
}

# Sets the user as Global Admin
# Oct 23rd 2018
function Set-AzureManagementAdminRole
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$ObjectId
        
    )
    Process
    {
        $Role=@{
            "62e90394-69f5-4237-9190-012177145e10" = "25b21f4a-977e-49f2-9de4-2c885f30be5d"
        }


        return Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "Roles/User/$ObjectId" -Method "Put" -Body $Role
    }
}

# Gets azure activity log
# Oct 23rd 2018
function Get-AzureActivityLog
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AccessToken,
        [Parameter(Mandatory=$False)]
        [datetime]$Start=$((Get-Date).AddDays(-30)),
        [Parameter(Mandatory=$False)]
        [datetime]$End=$(Get-Date)
    )
    Process
    {

        $Body=@{
            "startDateTime" = $Start.ToUniversalTime().ToString("o")
            "endDateTime" = $End.ToUniversalTime().ToString("o")
        }

        

        $response = Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "Reports/SignInEventsV2" -Method Post -Body $Body

        
        # Return
        $response.items
    }
}

# Get user's Azure AD tenants
# Jul 11th 2019
function Get-UserTenants
{
<#
    .SYNOPSIS
    Returns tenants the given user is member of

    .DESCRIPTION
    Returns tenants the given user is member of using Azure Management API

    .Example
    $at=Get-AccessTokenForAzureMgmtAPI -Credentials $cred
    PS C:\> Get-UserTenants -AccessToken $at
    Get-AADIntLoginInformation -Domain outlook.com

    id               : 3087e687-0d37-4c21-87c5-ecac88f0374a
    domainName       : company.onmicrosoft.com
    displayName      : Company Ltd
    isSignedInTenant : True
    tenantCategory   : 

    id               : 2968be53-ede5-4e30-844a-96d66479fb10
    domainName       : company2.onmicrosoft.com
    displayName      : Company2
    isSignedInTenant : False
    tenantCategory   : 
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $AccessToken
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource azureportal

        $response=Call-AzureManagementAPI -AccessToken $AccessToken -Command "directories/List"
        return $response.tenants
    }
}

# Gets Azure Tenant information as a guest user
# Jun 11th 2020
function Get-AzureInformation
{
<#
    .SYNOPSIS
    Gets some Azure Tenant information. 

    .DESCRIPTION
    Gets some Azure Tenant information, including certain tenant settings and ALL domains. The access token MUST be
    stored to cache! Works also for guest users.

    The Tenant is not required for Access Token but is recommended as some tenants may have MFA.

    .Example
    Get-AADIntAccessTokenForAzureCoreManagement -Tenant 6e3846ee-e8ca-4609-a3ab-f405cfbd02cd -SaveToCache

    Tenant                               User Resource                             Client                              
    ------                               ---- --------                             ------                              
    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd      https://management.core.windows.net/ d3590ed6-52b3-4102-aeff-aad2292ab01c

    PS C:\>Get-AADIntAzureTenants

    Id                                   Country Name                      Domains                                                                                                  
    --                                   ------- ----                      -------                                                                                                  
    221769d7-0747-467c-a5c1-e387a232c58c FI      Firma Oy                  {firma.mail.onmicrosoft.com, firma.onmicrosoft.com, firma.fi}              
    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd US      Company Ltd               {company.onmicrosoft.com, company.mail.onmicrosoft.com,company.com}

    PS C:\>Get-AADIntAzureInformation -Tenant

    objectId                                  : 6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
    displayName                               : Company Ltd
    usersCanRegisterApps                      : True
    isAnyAccessPanelPreviewFeaturesAvailable  : False
    showMyGroupsFeature                       : False
    myGroupsFeatureValue                      : 
    myGroupsGroupId                           : 
    myGroupsGroupName                         : 
    showMyAppsFeature                         : False
    myAppsFeatureValue                        : 
    myAppsGroupId                             : 
    myAppsGroupName                           : 
    showUserActivityReportsFeature            : False
    userActivityReportsFeatureValue           : 
    userActivityReportsGroupId                : 
    userActivityReportsGroupName              : 
    showRegisteredAuthMethodFeature           : False
    registeredAuthMethodFeatureValue          : 
    registeredAuthMethodGroupId               : 
    registeredAuthMethodGroupName             : 
    usersCanAddExternalUsers                  : False
    limitedAccessCanAddExternalUsers          : False
    restrictDirectoryAccess                   : False
    groupsInAccessPanelEnabled                : False
    selfServiceGroupManagementEnabled         : True
    securityGroupsEnabled                     : False
    usersCanManageSecurityGroups              : 
    office365GroupsEnabled                    : False
    usersCanManageOfficeGroups                : 
    allUsersGroupEnabled                      : False
    scopingGroupIdForManagingSecurityGroups   : 
    scopingGroupIdForManagingOfficeGroups     : 
    scopingGroupNameForManagingSecurityGroups : 
    scopingGroupNameForManagingOfficeGroups   : 
    objectIdForAllUserGroup                   : 
    allowInvitations                          : False
    isB2CTenant                               : False
    restrictNonAdminUsers                     : False
    enableLinkedInAppFamily                   : 0
    toEnableLinkedInUsers                     : {}
    toDisableLinkedInUsers                    : {}
    linkedInSelectedGroupObjectId             : 
    linkedInSelectedGroupDisplayName          : 
    allowedActions                            : @{application=System.Object[]; domain=System.Object[]; group=System.Object[]; serviceprincipal=System.Object[]; 
                                                tenantdetail=System.Object[]; user=System.Object[]; serviceaction=System.Object[]}
    skuInfo                                   : @{aadPremiumBasic=False; aadPremium=False; aadPremiumP2=False; aadBasic=False; aadBasicEdu=False; aadSmb=False; 
                                                enterprisePackE3=False; enterprisePremiumE5=False}
    domains                                   : {@{authenticationType=Managed; availabilityStatus=; isAdminManaged=True; isDefault=False; isDefaultForCloudRedirections=False; 
                                                isInitial=False; isRoot=True; isVerified=True; name=company.com; supportedServices=System.Object[]; forceDeleteState=; state=; 
                                                passwordValidityPeriodInDays=; passwordNotificationWindowInDays=}, @{authenticationType=Managed; availabilityStatus=; 
                                                isAdminManaged=True; isDefault=False; isDefaultForCloudRedirections=False; isInitial=True; isRoot=True; isVerified=True; 
                                                name=company.onmicrosoft.com;}...}
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$Tenant
    )
    Begin
    {
        $guestAccessPolicies = @{
            "a0b1b346-4d3e-4e8b-98f8-753987be4970" = "Full"
            "10dae51f-b6af-4016-8d66-8c2a99b929b3" = "Normal"
            "2af84b1e-32c8-42b7-82bc-daa82404023b" = "Restricted"
        }
    }
    Process
    {
        # Get from cache 
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                
        # Get the refreshtoken
        $refresh_token=$script:refresh_tokens["d3590ed6-52b3-4102-aeff-aad2292ab01c-https://management.core.windows.net/"]

        if([string]::IsNullOrEmpty($refresh_token))
        {
            Throw "No refreshtoken found! Use Get-AADIntAccessTokenForAzureCoreManagement with -SaveToCache switch."
        }

        # Get the tenants
        if([string]::IsNullOrEmpty($Tenant))
        {
            $tenants = Get-AzureTenants $AccessToken
        }
        else
        {
            $tenants = @(New-Object psobject -Property @{"Id" = $Tenant})
        }
        
        # Loop through the tenants
        foreach($tenant_info in $tenants)
        {
            # Create a new AccessToken for Azure AD management portal API
            $access_token = Get-AccessTokenWithRefreshToken -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -TenantId $tenant_info.Id -RefreshToken $refresh_token -SaveToCache $true

            # Directory information included in properties
            #$directory =   Call-AzureAADIAMAPI -AccessToken $access_token -Command "Directory"
            $properties =  Call-AzureAADIAMAPI -AccessToken $access_token -Command "Directories/Properties"
            if($properties.restrictNonAdminUsers -ne "True") # If restricted, don't bother trying
            {
                $permissions = Call-AzureAADIAMAPI -AccessToken $access_token -Command "Permissions?forceRefresh=false"
            }
            $skuinfo =     Call-AzureAADIAMAPI -AccessToken $access_token -Command "TenantSkuInfo"

            # Create a new AccessToken for graph.windows.net
            $access_token2 = Get-AccessTokenWithRefreshToken -Resource "https://graph.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -TenantId $tenant_info.Id -RefreshToken $refresh_token -SaveToCache $true

            # Get the domain details
            #$response = Invoke-RestMethod -Method Get -Uri "https://graph.windows.net/myorganization/domains?api-version=1.61-internal" -Headers @{"Authorization"="Bearer $access_token2"}
            #$domains = $response.Value

            # Create a new AccessToken for graph.microsoft.com
            $access_token3 = Get-AccessTokenWithRefreshToken -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -TenantId $tenant_info.Id -RefreshToken $refresh_token -SaveToCache $true

            # Get the directory quota
            $response2 = Invoke-RestMethod -Uri "https://main.iam.ad.ext.azure.com/api/MsGraph/v1.0/organization/?`$select=directorySizeQuota" -Headers @{"Authorization" = "Bearer $access_token3"}

            # Get the domain details
            $domains = Get-MSGraphDomains -AccessToken $access_token3

            # Get the tenant authorization policy
            try
            {
                $authPolicy = Get-TenantAuthPolicy -AccessToken $access_token3
                $guestAccess = $guestAccessPolicies[$authPolicy.guestUserRoleId]
            }
            catch{}
            
            # Construct the return value
            $properties | Add-Member -NotePropertyName "allowedActions"      -NotePropertyValue $permissions.allowedActions
            $properties | Add-Member -NotePropertyName "skuInfo"             -NotePropertyValue $skuInfo
            $properties | Add-Member -NotePropertyName "domains"             -NotePropertyValue $domains
            $properties | Add-Member -NotePropertyName "directorySizeQuota"  -NotePropertyValue $response2.value[0].directorySizeQuota
            $properties | Add-Member -NotePropertyName "authorizationPolicy" -NotePropertyValue $authPolicy
            $properties | Add-Member -NotePropertyName "guestAccess"         -NotePropertyValue $guestAccess

            # Return
            $properties
        }
        
        
    }
}

# Gets Azure Tenant authentication methods
# Jun 30th 2020
function Get-TenantAuthenticationMethods
{
<#
    .SYNOPSIS
    Gets Azure tenant authentication methods. 

    .DESCRIPTION
    Gets Azure tenant authentication methods. 

    
    .Example
    Get-AADIntAccessTokenForAADIAMAPI

    Tenant                               User Resource                             Client                              
    ------                               ---- --------                             ------                              
    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd      74658136-14ec-4630-ad9b-26e160ff0fc6 d3590ed6-52b3-4102-aeff-aad2292ab01c

    PS C:\>Get-AADIntTenantAuthenticationMethods

    id                : 297c50d5-e789-40f7-8931-b3694713cb4d
    type              : 6
    state             : 0
    includeConditions : {@{type=group; id=9202b94b-5381-4270-a3cb-7fcf0d40fef1; isRequired=False; useForSignIn=True}}
    voiceSettings     : 
    fidoSettings      : @{allowSelfServiceSetup=False; enforceAttestation=False; keyRestrictions=}
    enabled           : True
    method            : FIDO2 Security Key

    id                : 3d2c4b8f-f362-4ce4-8f4b-cc8726b80106
    type              : 8
    state             : 1
    includeConditions : {@{type=group; id=all_users; isRequired=False; useForSignIn=True}}
    voiceSettings     : 
    fidoSettings      : 
    enabled           : False
    method            : Microsoft Authenticator passwordless sign-in

    id                : d7716fe0-7c2e-4b52-a5cd-394f8999176b
    type              : 5
    state             : 1
    includeConditions : {@{type=group; id=all_users; isRequired=False; useForSignIn=True}}
    voiceSettings     : 
    fidoSettings      : 
    enabled           : False
    method            : Text message

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache 
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Get the authentication methods
        $response =  Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "AuthenticationMethods/AuthenticationMethodsPolicy"

        $methods = $response.authenticationMethods
        foreach($method in $methods)
        {
            $strType="unknown"
            switch($method.type)
            {
                6 {$strType = "FIDO2 Security Key"}
                8 {$strType = "Microsoft Authenticator passwordless sign-in"}
                5 {$strType = "Text message"}
            }

            $method | Add-Member -NotePropertyName "enabled" -NotePropertyValue ($method.state -eq 0)
            $method | Add-Member -NotePropertyName "method"  -NotePropertyValue $strType

        }

        return $methods
        
    }
}


# Gets Azure Tenant applications
# Nov 11th 2020
function Get-TenantApplications
{
<#
    .SYNOPSIS
    Gets Azure tenant applications.

    .DESCRIPTION
    Gets Azure tenant applications.
    
    .Example
    Get-AADIntAccessTokenForAADIAMAPI -SaveToCache

    Tenant                               User Resource                             Client                              
    ------                               ---- --------                             ------                              
    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd      https://management.core.windows.net/ d3590ed6-52b3-4102-aeff-aad2292ab01c

    PS C:\>Get-AADIntTenantApplications

    
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache 
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        $body = @{
            "accountEnabled" =       $null
            "isAppVisible" =         $null
            "appListQuery"=          0
            "top" =                  999
            "loadLogo" =             $false
            "putCachedLogoUrlOnly" = $true
            "nextLink" =             ""
            "usedFirstPartyAppIds" = $null
            "__ko_mapping__" = @{
                "ignore" = @()
                "include" = @("_destroy")
                "copy" = @()
                "observe" = @()
                "mappedProperties" = @{
                    "accountEnabled" =       $true
                    "isAppVisible" =         $true
                    "appListQuery" =         $true
                    "searchText" =           $true
                    "top" =                  $true
                    "loadLogo" =             $true
                    "putCachedLogoUrlOnly" = $true
                    "nextLink" =             $true
                    "usedFirstPartyAppIds" = $true
                }
                "copiedProperties" = @{}
            }
        }

        # Get the applications
        $response =  Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "ManagedApplications/List" -Body $body -Method Post

        return $response.appList
       
    }
}

# Get the status of AAD Connect
# Jan 7th 2021
function Get-AADConnectStatus
{
<#
    .SYNOPSIS
    Shows the status of Azure AD Connect (AAD Connect).

    .DESCRIPTION
    Shows the status of Azure AD Connect (AAD Connect).

    .Example
    Get-AADIntAccessTokenForAADIAMAPI -SaveToCache
    PS C:\>Get-AADIntAADConnectStatus

    verifiedDomainCount              : 4
    verifiedCustomDomainCount        : 3
    federatedDomainCount             : 2
    numberOfHoursFromLastSync        : 0
    dirSyncEnabled                   : True
    dirSyncConfigured                : True
    passThroughAuthenticationEnabled : True
    seamlessSingleSignOnEnabled      : True
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $AccessToken
    )
    Process
    {
        # Get from cache 
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Get the applications
        $response =  Call-AzureAADIAMAPI -AccessToken $AccessToken -Command "Directories/ADConnectStatus" 

        return $response
    }
}