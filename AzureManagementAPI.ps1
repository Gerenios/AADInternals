

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