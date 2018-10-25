

# Get users using Azure Management API
# Oct 23rd 2018
function Get-AzureManagementUsers
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AuthToken
    )
    Process
    {
        $response=Call-AzureManagementAPI -AuthToken $AuthToken -Command "Users?searchText=&top=100&nextLink=&orderByThumbnails=false&maxThumbnailCount=999&filterValue=All&state=All&adminUnit="
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
        $AuthToken,
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

        return Call-AzureManagementAPI -AuthToken $AuthToken -Command "UserDetails" -Body $Body -Method "Post"
    }
}


# Removes the given user using Azure Management API
# Oct 23rd 2018
function Remove-AzureManagementUser
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AuthToken,
        [Parameter(Mandatory=$True)]
        [string]$ObjectId
    )
    Process
    {
        return Call-AzureManagementAPI -AuthToken $AuthToken -Command "Users/$ObjectId" -Method Delete
    }
}

# Removes the given users using Azure Management API
# Oct 23rd 2018
function Remove-AzureManagementUsers
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AuthToken,
        [Parameter(Mandatory=$True)]
        [string[]]$ObjectIds
    )
    Process
    {
        return Call-AzureManagementAPI -AuthToken $AuthToken -Command "Users" -Method Delete -Body $ObjectIds
    }
}

# Checks whether the external user is unique or already exists in AAD
# Oct 23rd 2018
function Is-ExternalUserUnique
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AuthToken,
        [Parameter(Mandatory=$True)]
        [string]$EmailAddress
        
    )
    Process
    {
        return Call-AzureManagementAPI -AuthToken $AuthToken -Command "Users/IsUPNUniqueOrPending/$EmailAddress" 
    }
}


# Invites an external user go AAD
# Oct 23rd 2018
function New-GuestInvitation
{

<#
    .SYNOPSIS
    Invites an user to AAD

    .DESCRIPTION
    Invites an user to AAD using Azure Management API

    .Parameter AuthToken
    Auth Token

    .Parameter EmailAddress
    Email address of the guest user

    .Parameter Message
    The message to be sent with the invitation

    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAuthTokenForAADIAMAPI -Credentials $cred
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
        $AuthToken,
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

        return Call-AzureManagementAPI -AuthToken $AuthToken -Command "Users/Invite" -Method "Put" -Body $Body
    }
}

# Sets the user as Global Admin
# Oct 23rd 2018
function Set-AzureManagementAdminRole
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AuthToken,
        [Parameter(Mandatory=$True)]
        [string]$ObjectId
        
    )
    Process
    {
        $Role=@{
            "62e90394-69f5-4237-9190-012177145e10" = "25b21f4a-977e-49f2-9de4-2c885f30be5d"
        }


        return Call-AzureManagementAPI -AuthToken $AuthToken -Command "Roles/User/$ObjectId" -Method "Put" -Body $Role
    }
}

# Sets the user as Global Admin
# Oct 23rd 2018
function Get-AzureActivityLog
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $AuthToken,
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

        

        $response = Call-AzureManagementAPI -AuthToken $AuthToken -Command "Reports/SignInEventsV2" -Method Post -Body $Body

        
        # Return
        $response.items
    }
}