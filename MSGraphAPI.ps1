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