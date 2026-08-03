# This file contains functions for Teams Admin (Cs) operations, using the
# internal Teams Admin API (api.interfaces.records.teams.microsoft.com).

# Gets the Teams tenant information
# Aug 1st 2026, Stefan Wey
function Get-CsTenant
{
<#
    .SYNOPSIS
    Gets Teams tenant information.

    .DESCRIPTION
    Gets Teams tenant information using the internal Teams Admin API.
    Equivalent to the Get-CsTenant cmdlet of the MicrosoftTeams module, but does not require any Teams admin role.

    .Parameter AccessToken
    The access token used to get the tenant information.

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeamsAdmin -SaveToCache
    PS\:>Get-AADIntCsTenant

    objectId       : dcc7d7bf-e3f5-4778-b6e0-aa7207bdb033
    displayName    : Company Ltd
    dirSyncEnabled : True
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        Invoke-TeamsAdminAPI -AccessToken $AccessToken -Url "Teams.Tenant/tenants"
    }
}

# Gets the Teams tenant federation configuration
# Aug 1st 2026, Stefan Wey
function Get-CsTenantFederationConfiguration
{
<#
    .SYNOPSIS
    Gets Teams tenant federation configuration.

    .DESCRIPTION
    Gets Teams tenant federation configuration using the internal Teams Admin API.
    Equivalent to the Get-CsTenantFederationConfiguration cmdlet of the MicrosoftTeams module, but does not require any Teams admin role.

    .Parameter AccessToken
    The access token used to get the federation configuration.

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeamsAdmin -SaveToCache
    PS\:>Get-AADIntCsTenantFederationConfiguration

    AllowedDomains                 : @{AllowList=System.Object[]}
    BlockedDomains                 : {}
    AllowFederatedUsers            : True
    AllowTeamsConsumer             : True
    AllowTeamsConsumerInbound      : True
    ExternalAccessWithTrialTenants : False

    .NOTES
    See https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat for the meaning of the AllowedDomains/BlockedDomains combinations:
    - AllowedDomains.AllowList=[], BlockedDomains=[]        : All domains allowed
    - AllowedDomains.AllowList=[domains], BlockedDomains=[] : Only listed domains allowed
    - AllowedDomains.AllowList=[], BlockedDomains=[domains] : All domains allowed except listed
    - AllowedDomains=[], BlockedDomains=[]                  : All domains blocked
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        Invoke-TeamsAdminAPI -AccessToken $AccessToken -Url "Skype.Policy/configurations/TenantFederationSettings/configuration/Global"
    }
}

# Gets the Teams external access configuration
# Aug 1st 2026, Stefan Wey
function Get-CsTeamsExternalAccessConfiguration
{
<#
    .SYNOPSIS
    Gets Teams external access configuration.

    .DESCRIPTION
    Gets Teams external access configuration using the internal Teams Admin API.
    Equivalent to the Get-CsTeamsExternalAccessConfiguration cmdlet of the MicrosoftTeams module, but does not require any Teams admin role.

    .Parameter AccessToken
    The access token used to get the external access configuration.

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeamsAdmin -SaveToCache
    PS\:>Get-AADIntCsTeamsExternalAccessConfiguration

    BlockExternalUserAccess : False
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        Invoke-TeamsAdminAPI -AccessToken $AccessToken -Url "Skype.Policy/configurations/TeamsExternalAccessConfiguration/configuration/global"
    }
}

# Gets a summary of the tenant's Teams external chat (federation) configuration
# Aug 1st 2026, Stefan Wey
function Get-TeamsExternalChatConfiguration
{
<#
    .SYNOPSIS
    Gets a summary of the tenant's Teams external chat (federation) configuration.

    .DESCRIPTION
    Gets a summary of the tenant's Teams external chat (federation) configuration, combining the
    results of Get-CsTenant, Get-CsTenantFederationConfiguration, and Get-CsTeamsExternalAccessConfiguration.

    .Parameter AccessToken
    The access token used to get the configuration.

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeamsAdmin -SaveToCache
    PS\:>Get-AADIntTeamsExternalChatConfiguration

    TenantId                       : dcc7d7bf-e3f5-4778-b6e0-aa7207bdb033
    TenantName                     : Company Ltd
    TenantDirSyncEnabled           : True
    ExternalAccessWithTrialTenants : False
    AllowedDomains                 : @{AllowList=System.Object[]}
    BlockedDomains                 : {}
    AllowFederatedUsers            : True
    AllowTeamsConsumer             : True
    AllowTeamsConsumerInbound      : True
    BlockExternalUserAccess        : False
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $tenant =    Get-CsTenant                          -AccessToken $AccessToken
        $fedConfig = Get-CsTenantFederationConfiguration    -AccessToken $AccessToken
        $extConfig = Get-CsTeamsExternalAccessConfiguration -AccessToken $AccessToken

        [PSCustomObject][ordered]@{
            "TenantId"                       = $tenant.objectId
            "TenantName"                     = $tenant.displayName
            "TenantDirSyncEnabled"           = $tenant.dirSyncEnabled
            "ExternalAccessWithTrialTenants" = $fedConfig.ExternalAccessWithTrialTenants
            "AllowedDomains"                 = $fedConfig.AllowedDomains
            "BlockedDomains"                 = $fedConfig.BlockedDomains
            "AllowFederatedUsers"            = $fedConfig.AllowFederatedUsers
            "AllowTeamsConsumer"             = $fedConfig.AllowTeamsConsumer
            "AllowTeamsConsumerInbound"      = $fedConfig.AllowTeamsConsumerInbound
            "BlockExternalUserAccess"        = $extConfig.BlockExternalUserAccess
        }
    }
}
