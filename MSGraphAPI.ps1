# This script contains functions for MSGraph API at https://graph.microsoft.com

# Returns the 50 latest signin entries or the given entry
# Jun 9th 2020
function Get-AzureSignInLog
{
    <#
    .SYNOPSIS
    Returns the 50 latest entries from Azure AD sign-in log or single entry by id

    .DESCRIPTION
    Returns the 50 latest entries from Azure AD sign-in log or single entry by id

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Get-AADIntAzureSignInLog

    createdDateTime              id                                   ipAddress      userPrincipalName             appDisplayName                   
    ---------------              --                                   ---------      -----------------             --------------                   
    2020-05-25T05:54:28.5131075Z b223590e-8ba1-4d54-be54-03071659f900 199.11.103.31  admin@company.onmicrosoft.com Azure Portal                     
    2020-05-29T07:56:50.2565658Z f6151a97-98cc-444e-a79f-a80b54490b00 139.93.35.110  user@company.com              Azure Portal                     
    2020-05-29T08:02:24.8788565Z ad2cfeff-52f2-442a-b8fc-1e951b480b00 11.146.246.254 user2@company.com             Microsoft Docs                   
    2020-05-29T08:56:48.7857468Z e0f8e629-863f-43f5-a956-a4046a100d00 1.239.249.24   admin@company.onmicrosoft.com Azure Active Directory PowerShell

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Get-AADIntAzureSignInLog

    createdDateTime              id                                   ipAddress      userPrincipalName             appDisplayName                   
    ---------------              --                                   ---------      -----------------             --------------                   
    2020-05-25T05:54:28.5131075Z b223590e-8ba1-4d54-be54-03071659f900 199.11.103.31  admin@company.onmicrosoft.com Azure Portal                     
    2020-05-29T07:56:50.2565658Z f6151a97-98cc-444e-a79f-a80b54490b00 139.93.35.110  user@company.com              Azure Portal                     
    2020-05-29T08:02:24.8788565Z ad2cfeff-52f2-442a-b8fc-1e951b480b00 11.146.246.254 user2@company.com             Microsoft Docs                   
    2020-05-29T08:56:48.7857468Z e0f8e629-863f-43f5-a956-a4046a100d00 1.239.249.24   admin@company.onmicrosoft.com Azure Active Directory PowerShell

    PS C:\>Get-AADIntAzureSignInLog -EntryId b223590e-8ba1-4d54-be54-03071659f900

    id                 : b223590e-8ba1-4d54-be54-03071659f900
    createdDateTime    : 2020-05-25T05:54:28.5131075Z
    userDisplayName    : admin company
    userPrincipalName  : admin@company.onmicrosoft.com
    userId             : 289fcdf8-af4e-40eb-a363-0430bc98d4d1
    appId              : c44b4083-3bb0-49c1-b47d-974e53cbdf3c
    appDisplayName     : Azure Portal
    ipAddress          : 199.11.103.31
    clientAppUsed      : Browser
    userAgent          : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
    ...
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$EntryId,
        [switch]$Export
        
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Select one entry if provided
        if($EntryId)
        {
            $queryString = "`$filter=id eq '$EntryId'"
        }
        else
        {
            $queryString = "`$top=50&`$orderby=createdDateTime"
        }

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "auditLogs/signIns" -QueryString $queryString

        # Return full results
        if($Export)
        {
            return $results
        }
        elseif($EntryId) # The single entry
        {
            return $results
        }
        else # Print out only some info - the API always returns all info as $Select is not supported :(
        {
            $results | select createdDateTime,id,ipAddress,userPrincipalName,appDisplayName | ft
        }
    }
}

# Returns the 50 latest signin entries or the given entry
# Jun 9th 2020
function Get-AzureAuditLog
{
    <#
    .SYNOPSIS
    Returns the 50 latest entries from Azure AD sign-in log or single entry by id

    .DESCRIPTION
    Returns the 50 latest entries from Azure AD sign-in log or single entry by id

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Get-AADIntAzureAuditLog

    id                                                            activityDateTime             activityDisplayName   operationType result  initiatedBy   
    --                                                            ----------------             -------------------   ------------- ------  -----------   
    Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545 2020-05-29T07:57:51.4037921Z Add service principal Add           success @{user=; app=}
    Directory_f830a9d4-e746-48dc-944c-eb093364c011_1ZJAE_22273050 2020-05-29T07:57:51.6245497Z Add service principal Add           failure @{user=; app=}
    Directory_a813bc02-5d7a-4a40-9d37-7d4081d42b42_RKRRS_12877155 2020-06-02T12:49:38.5177891Z Add user              Add           success @{app=; user=}

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Get-AADIntAzureAuditLog

    id                                                            activityDateTime             activityDisplayName   operationType result  initiatedBy   
    --                                                            ----------------             -------------------   ------------- ------  -----------   
    Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545 2020-05-29T07:57:51.4037921Z Add service principal Add           success @{user=; app=}
    Directory_f830a9d4-e746-48dc-944c-eb093364c011_1ZJAE_22273050 2020-05-29T07:57:51.6245497Z Add service principal Add           failure @{user=; app=}
    Directory_a813bc02-5d7a-4a40-9d37-7d4081d42b42_RKRRS_12877155 2020-06-02T12:49:38.5177891Z Add user              Add           success @{app=; user=}

    PS C:\>Get-AADIntAzureAuditLog -EntryId Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545

    id                  : Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545
    category            : ApplicationManagement
    correlationId       : 9af6aff3-dc09-4ac1-a1d3-143e80977b3e
    result              : success
    resultReason        : 
    activityDisplayName : Add service principal
    activityDateTime    : 2020-05-29T07:57:51.4037921Z
    loggedByService     : Core Directory
    operationType       : Add
    initiatedBy         : @{user=; app=}
    targetResources     : {@{id=66ce0b00-92ee-4851-8495-7c144b77601f; displayName=Azure Credential Configuration Endpoint Service; type=ServicePrincipal; userPrincipalName=; 
                          groupType=; modifiedProperties=System.Object[]}}
    additionalDetails   : {}
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$EntryId,
        [switch]$Export
        
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Select one entry if provided
        if($EntryId)
        {
            $queryString = "`$filter=id eq '$EntryId'"
        }
        else
        {
            $queryString = "`$top=50&`$orderby=activityDateTime"
        }

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "auditLogs/directoryAudits" -QueryString $queryString

        # Return full results
        if($Export)
        {
            return $results
        }
        elseif($EntryId) # The single entry
        {
            return $results
        }
        else # Print out only some info - the API always returns all info as $Select is not supported :(
        {
            $results | select id,activityDateTime,activityDisplayName,operationType,result,initiatedBy | ft
        }
    }
}

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

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API users -QueryString $queryString

        return $results
    }
}

# Gets the user's data
# Jun 16th 2020
function Get-MSGraphUser
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName" -ApiVersion "v1.0" -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the user's application role assignments
# Jun 16th 2020
function Get-MSGraphUserAppRoleAssignments
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/appRoleAssignments" -ApiVersion v1.0

        return $results
    }
}

# Gets the user's owned devices
# Jun 16th 2020
function Get-MSGraphUserOwnedDevices
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/ownedDevices" -ApiVersion v1.0

        return $results
    }
}

# Gets the user's registered devices
# Jun 16th 2020
function Get-MSGraphUserRegisteredDevices
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/registeredDevices" -ApiVersion v1.0

        return $results
    }
}

# Gets the user's licenses
# Jun 16th 2020
function Get-MSGraphUserLicenseDetails
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/licenseDetails" -ApiVersion v1.0 

        return $results
    }
}

# Gets the user's groups
# Jun 16th 2020
function Get-MSGraphUserMemberOf
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/memberOf" -ApiVersion v1.0

        return $results
    }
}

# Gets the user's direct reports
# Jun 16th 2020
function Get-MSGraphUserDirectReports
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/directReports" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the user's manager
# Jun 16th 2020
function Get-MSGraphUserManager
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/manager" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the group's owners
# Jun 16th 2020
function Get-MSGraphGroupOwners
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$GroupId
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$GroupId/owners" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the group's members
# Jun 16th 2020
function Get-MSGraphGroupMembers
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$GroupId
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$GroupId/members" -ApiVersion v1.0 -QueryString "`$top=500&`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the group's members
# Jun 17th 2020
function Get-MSGraphRoleMembers
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$RoleId
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "directoryRoles/$RoleId/members" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the tenant domains (all of them)
# Jun 16th 2020
function Get-MSGraphDomains
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "domains" -ApiVersion beta

        return $results
    }
}

# Gets team information
# Jun 17th 2020
function Get-MSGraphTeams
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$GroupId
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "teams/$GroupId" -ApiVersion v1.0

        return $results
    }
}

# Gets team's app information
# Jun 17th 2020
function Get-MSGraphTeamsApps
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$GroupId
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "teams/$GroupId/installedApps?`$expand=teamsAppDefinition" -ApiVersion v1.0

        return $results
    }
}

# Gets the authorizationPolicy
# Sep 18th 2020
function Get-TenantAuthPolicy
{
<#
    .SYNOPSIS
    Gets tenant's authorization policy.

    .DESCRIPTION
    Gets tenant's authorization policy, including user and guest settings.

    .PARAMETER AccessToken
    Access token used to retrieve the authorization policy.

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Get-AADIntTenantAuthPolicy

    id                                                : authorizationPolicy
    allowInvitesFrom                                  : everyone
    allowedToSignUpEmailBasedSubscriptions            : True
    allowedToUseSSPR                                  : True
    allowEmailVerifiedUsersToJoinOrganization         : False
    blockMsolPowerShell                               : False
    displayName                                       : Authorization Policy
    description                                       : Used to manage authorization related settings across the company.
    enabledPreviewFeatures                            : {}
    guestUserRoleId                                   : 10dae51f-b6af-4016-8d66-8c2a99b929b3
    permissionGrantPolicyIdsAssignedToDefaultUserRole : {microsoft-user-default-legacy}
    defaultUserRolePermissions                        : @{allowedToCreateApps=True; allowedToCreateSecurityGroups=True; allowedToReadOtherUsers=True}

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "policies/authorizationPolicy" 


        return $results
    }
}

# Gets the guest account restrictions
# Sep 18th 2020
function Get-TenantGuestAccess
{
<#
    .SYNOPSIS
    Gets the guest access level of the user's tenant.

    .DESCRIPTION
    Gets the guest access level of the user's tenant.

    Inclusive:  Guest users have the same access as members
    Normal:     Guest users have limited access to properties and memberships of directory objects
    Restricted: Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)

    .PARAMETER AccessToken
    Access token used to retrieve the access level.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Get-AADIntTenantGuestAccess

    Access Description                                                                        RoleId                              
    ------ -----------                                                                        ------                              
    Normal Guest users have limited access to properties and memberships of directory objects 10dae51f-b6af-4016-8d66-8c2a99b929b3
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $policy = Get-TenantAuthPolicy -AccessToken $AccessToken

        $roleId = $policy.guestUserRoleId

        
        switch($roleId)
        {
            "a0b1b346-4d3e-4e8b-98f8-753987be4970" {
                $attributes=[ordered]@{
                    "Access" =      "Full"
                    "Description" = "Guest users have the same access as members"
                }
                break
            }
            "10dae51f-b6af-4016-8d66-8c2a99b929b3" {
                $attributes=[ordered]@{
                    "Access" =      "Normal"
                    "Description" = "Guest users have limited access to properties and memberships of directory objects"
                }
                break
            }
            "2af84b1e-32c8-42b7-82bc-daa82404023b" {
                $attributes=[ordered]@{
                    "Access" =      "Restricted"
                    "Description" = "Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)"
                }
                break
            }
        }

        $attributes["RoleId"] = $roleId

        return New-Object psobject -Property $attributes


    }
}

# Sets the guest account restrictions
# Sep 18th 2020
function Set-TenantGuestAccess
{
<#
    .SYNOPSIS
    Sets the guest access level for the user's tenant.

    .DESCRIPTION
    Sets the guest access level for the user's tenant.

    Inclusive:  Guest users have the same access as members
    Normal:     Guest users have limited access to properties and memberships of directory objects
    Restricted: Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)

    .PARAMETER AccessToken
    Access token used to retrieve the access level.

    .PARAMETER Level
    Guest access level. One of Inclusive, Normal, or Restricted.

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Set-AADIntTenantGuestAccess -Level Normal

    Access Description                                                                        RoleId                              
    ------ -----------                                                                        ------                              
    Normal Guest users have limited access to properties and memberships of directory objects 10dae51f-b6af-4016-8d66-8c2a99b929b3
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        
        [Parameter(Mandatory=$True)]
        [ValidateSet('Full','Normal','Restricted')]
        [String]$Level
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"
        
        switch($Level)
        {
            "Full"       {$roleId = "a0b1b346-4d3e-4e8b-98f8-753987be4970"; break}
            "Normal"     {$roleId = "10dae51f-b6af-4016-8d66-8c2a99b929b3"; break}
            "Restricted" {$roleId = "2af84b1e-32c8-42b7-82bc-daa82404023b"; break}
        }
        $body = "{""guestUserRoleId"":""$roleId""}"


        Call-MSGraphAPI -AccessToken $AccessToken -API "policies/authorizationPolicy/authorizationPolicy" -Method "PATCH" -Body $body

        Get-TenantGuestAccess -AccessToken $AccessToken

    }
}


# Enables Msol PowerShell access
# Sep 18th 2020
function Enable-TenantMsolAccess
{
<#
    .SYNOPSIS
    Enables Msol PowerShell module access for the user's tenant.

    .DESCRIPTION
    Enables Msol PowerShell module access for the user's tenant.

    .PARAMETER AccessToken
    Access token used to enable the Msol PowerShell access.

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Enable-AADIntTenantMsolAccess

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $body = '{"blockMsolPowerShell":"false"}'

        Call-MSGraphAPI -AccessToken $AccessToken -API "policies/authorizationPolicy/authorizationPolicy" -Method "PATCH" -Body $body
    }
}

# Disables Msol PowerShell access
# Sep 18th 2020
function Disable-TenantMsolAccess
{
<#
    .SYNOPSIS
    Disables Msol PowerShell module access for the user's tenant.

    .DESCRIPTION
    Disables Msol PowerShell module access for the user's tenant.

    .PARAMETER AccessToken
    Access token used to disable the Msol PowerShell access.

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Disable-AADIntTenantMsolAccess

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $body = '{"blockMsolPowerShell":"true"}'

        Call-MSGraphAPI -AccessToken $AccessToken -API "policies/authorizationPolicy/authorizationPolicy" -Method "PATCH" -Body $body
    }
}

# Get rollout policies 
# Jan 7th 2021
function Get-RolloutPolicies
{
<#
    .SYNOPSIS
    Gets the tenant's rollout policies.

    .DESCRIPTION
    Gets the tenant's rollout policies.

    .PARAMETER AccessToken
    Access token used to get tenant's rollout policies.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Get-AADIntRolloutPolicies

    id                      : cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
    displayName             : passthroughAuthentication rollout policy
    description             : 
    feature                 : passthroughAuthentication
    isEnabled               : True
    isAppliedToOrganization : False

    id                      : 3c89cd34-275c-4cba-8d8e-80338db7df91
    displayName             : seamlessSso rollout policy
    description             : 
    feature                 : seamlessSso
    isEnabled               : True
    isAppliedToOrganization : False
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/featureRolloutPolicies" -ApiVersion beta
    }
}

# Get rollout policy groups 
# Jan 7th 2021
function Get-RolloutPolicyGroups
{
<#
    .SYNOPSIS
    Gets groups of the given rollout policy.

    .DESCRIPTION
    Gets groups of the given rollout policy.

    .PARAMETER AccessToken
    Access token used to get rollout policy groups.

    .PARAMETER PolicyId
    Guid of the rollout policy.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Get-AADIntRolloutPolicyGroups -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d | Select displayName,id

    displayName       id                                  
    -----------       --                                  
    PTA SSO Sales     b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3
    PTA SSO Markering f35d712f-dcdb-4040-a93d-ffd04aff3f75
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [GUID]$PolicyId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $response=Call-MSGraphAPI -AccessToken $AccessToken -API "directory/featureRolloutPolicies/$($PolicyId.ToString())" -QueryString "`$expand=appliesTo" -ApiVersion beta
        $response.appliesTo
    }
}

# Add groups to rollout policy
# Jan 7th 2021
function Add-RolloutPolicyGroups
{
<#
    .SYNOPSIS
    Adds given groups to the given rollout policy.

    .DESCRIPTION
    Adds given groups to the given rollout policy. 
    
    Status meaning:
    204 The group successfully added
    400 Invalid group id
    404 Invalid policy id

    .PARAMETER AccessToken
    Access token used to add rollout policy groups.

    .PARAMETER PolicyId
    Guid of the rollout policy.

    .PARAMETER GroupIds
    List of group guids.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Add-AADIntRolloutPolicyGroups -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d -GroupIds b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3,f35d712f-dcdb-4040-a93d-ffd04aff3f75

    id                                   status
    --                                   ------
    b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3    204
    f35d712f-dcdb-4040-a93d-ffd04aff3f75    204
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [GUID]$PolicyId,
        [Parameter(Mandatory=$True)]
        [GUID[]]$GroupIds
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Build the body
        $requests = @()
        
        foreach($GroupId in $GroupIds)
        {
            $id = $GroupId.toString()
            $request = @{
                "id" =      $id
                "method" =  "POST"
                "url" =     "directory/featureRolloutPolicies/$($PolicyId.toString())/appliesTo/`$ref"
                "body" =    @{ "@odata.id" =    "https://graph.microsoft.com/beta/directoryObjects/$id" }
                "headers" = @{ "Content-Type" = "application/json" }
            }
            $requests += $request
        }

        $body = @{ "requests" = $requests } | ConvertTo-Json -Depth 5

        $response = Call-MSGraphAPI -AccessToken $AccessToken -API "`$batch" -ApiVersion beta -Method "POST" -Body $body

        if($response.responses[0].body.error.message)
        {
            Write-Error $response.responses[0].body.error.message
        }
        else
        {
            $response.responses | select id,status
        }
        
    }
}

# Removes groups from the rollout policy
# Jan 7th 2021
function Remove-RolloutPolicyGroups
{
<#
    .SYNOPSIS
    Removes given groups from the given rollout policy.

    .DESCRIPTION
    Removes given groups from the given rollout policy.
    
    Status meaning:
    204 The group successfully added
    400 Invalid group id
    404 Invalid policy id

    .PARAMETER AccessToken
    Access token used to remove rollout policy groups.

    .PARAMETER PolicyId
    Guid of the rollout policy.

    .PARAMETER GroupIds
    List of group guids.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Remove-AADIntRolloutPolicyGroups -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d -GroupIds b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3,f35d712f-dcdb-4040-a93d-ffd04aff3f75

    id                                   status
    --                                   ------
    b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3    204
    f35d712f-dcdb-4040-a93d-ffd04aff3f75    204
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [GUID]$PolicyId,
        [Parameter(Mandatory=$True)]
        [GUID[]]$GroupIds
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Build the body
        $requests = @()
        
        foreach($GroupId in $GroupIds)
        {
            $id = $GroupId.toString()
            $request = @{
                "id" =      $id
                "method" =  "DELETE"
                "url" =     "directory/featureRolloutPolicies/$($PolicyId.toString())/appliesTo/$id/`$ref"
            }
            $requests += $request
        }

        $body = @{ "requests" = $requests } | ConvertTo-Json -Depth 5

        $response = Call-MSGraphAPI -AccessToken $AccessToken -API "`$batch" -ApiVersion beta -Method "POST" -Body $body

        if($response.responses[0].body.error.message)
        {
            Write-Error $response.responses[0].body.error.message
        }
        else
        {
            $response.responses | select id,status
        }
        
    }
}

# Set rollout policy
# Jan 7th 2021
function Remove-RolloutPolicy
{
<#
    .SYNOPSIS
    Removes the given rollout policy.

    .DESCRIPTION
    Removes the given rollout policy. The policy MUST be disabled before it can be removed.

    .PARAMETER AccessToken
    Access token used to get tenant's rollout policies.

    .PARAMETER PolicyId
    Guid of the rollout policy.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Remove-AADIntRolloutPolicy -PolicyId 3c89cd34-275c-4cba-8d8e-80338db7df91

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [GUID]$PolicyId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/featureRolloutPolicies/$($PolicyId.ToString())" -ApiVersion beta -Method DELETE
    }
}

# Set rollout policy
# Jan 7th 2021
function Set-RolloutPolicy
{
<#
    .SYNOPSIS
    Creates a new rollout policy or edits existing one.

    .DESCRIPTION
    Creates a new rollout policy by name or edits existing one with policy id. 

    .PARAMETER AccessToken
    Access token used to get tenant's rollout policies.

    .PARAMETER PolicyId
    Guid of the rollout policy.

    .PARAMETER Policy
    Name of the rollout policy. Can be one of: passwordHashSync, passthroughAuthentication, or seamlessSso

    .PARAMETER Enable
    Boolean value indicating is the feature enabled or not.

    .PARAMETER EnableToOrganization
    Boolean value indicating is the feature enabled for the whole organization. Currently not supported.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Set-AADIntRolloutPolicy -Policy passthroughAuthentication -Enable $True

    @odata.context          : https://graph.microsoft.com/beta/$metadata#directory/featureRolloutPolicies/$entity
    id                      : 1eec3ce2-5af1-4460-9cc4-1af7a6c15eb1
    displayName             : passthroughAuthentication rollout policy
    description             : 
    feature                 : passthroughAuthentication
    isEnabled               : True
    isAppliedToOrganization : False

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Set-AADIntRolloutPolicy -PolicyId 1eec3ce2-5af1-4460-9cc4-1af7a6c15eb1 -Enable $False

    @odata.context          : https://graph.microsoft.com/beta/$metadata#directory/featureRolloutPolicies/$entity
    id                      : 1eec3ce2-5af1-4460-9cc4-1af7a6c15eb1
    displayName             : passthroughAuthentication rollout policy
    description             : 
    feature                 : passthroughAuthentication
    isEnabled               : True
    isAppliedToOrganization : False

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='id',Mandatory=$True)]
        [GUID]$PolicyId,
        [Parameter(Mandatory=$True)]
        [bool]$Enable,
        [Parameter(ParameterSetName='type',Mandatory=$True)]
        [ValidateSet('passwordHashSync','passthroughAuthentication','seamlessSso')]
        [String]$Policy,
        [Parameter(Mandatory=$False)]
        [bool]$EnableToOrganization = $false
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        try
        {
            if($Policy)
            {
                $body = @{
                    "feature" = "$Policy"
                    "isEnabled" = $Enable 
                    #"isAppliedToOrganization" = $EnableToOrganization
                    "displayName" = "$Policy rollout policy"}

                $response = Call-MSGraphAPI -AccessToken $AccessToken -API "directory/featureRolloutPolicies" -ApiVersion beta -Method POST -Body $($body | ConvertTo-Json -Depth 5)
            }
            else
            {
                $body = @{
                    "isEnabled" = $Enable
                    #"isAppliedToOrganization" = $EnableToOrganization 
                }

                $response = Call-MSGraphAPI -AccessToken $AccessToken -API "directory/featureRolloutPolicies/$($PolicyId.ToString())" -ApiVersion beta -Method PATCH -Body $($body | ConvertTo-Json -Depth 5)
            }
        }
        catch
        {
            $error = $_.ErrorDetails.Message | ConvertFrom-Json 
            Write-Error $error.error.message
        }

         
        $response
    }
}