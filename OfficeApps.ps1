# This script contains functions for OfficeApps
# https://office.microsoft.com/Config15


# Get user Office connections
function Get-UserConnections
{
<#
    .SYNOPSIS
    Returns user's office connections

    .DESCRIPTION
    Returns user's office connections

    .Example
    $cred=Get-Credential
    $at=Get-AADIntAccessTokenForOfficeApps -credentials $cred
    Get-AADIntUserConnections -AccessToken $at
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "ab9b8c07-8f02-4f72-87fa-80105867a763" -Resource "https://officeapps.live.com"

        $headers = @{
            "Authorization"="Bearer $AccessToken"
        }
        
        $response=Invoke-RestMethod -Uri "https://odc.officeapps.live.com/odc/servicemanager/userconnected" -Headers $headers

        return $response.ConnectedServicesResults.ServiceConnections.Connection
    }
}

# Get recently used Office file connections
function Get-RecentLocations
{
<#
    .SYNOPSIS
    Returns user's recent office file locations

    .DESCRIPTION
    Returns user's recent office file locations

    .Example
    $cred=Get-Credential
    $at=Get-AADIntAccessTokenForOfficeApps -credentials $cred
    Get-AADIntRecentLocations -AccessToken $at
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Word','PowerPoint','OneNote','Excel','Visio','Sway','All')]
        [String]$App="All",
        [Parameter(Mandatory=$False)]
        [Int]$Show=100
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "ab9b8c07-8f02-4f72-87fa-80105867a763" -Resource "https://officeapps.live.com"

        $headers = @{
            "Authorization"="Bearer $AccessToken"
        }
        if($App -eq "All")
        {
            $Apps='Word,PowerPoint,OneNote,Excel,Visio,Sway'
        }
        else
        {
            $Apps=$App
        }
        
        Invoke-RestMethod -Uri "https://ocws.officeapps.live.com/ocs/locations/recent?apps=$Apps&show=$Show" -Headers $headers

    }
}

# Gets documents shared with the given user
function Get-SharedWithUser
{
<#
    .SYNOPSIS
    Returns the documents shared with the given user

    .DESCRIPTION
    Returns the documents shared with the given user

    .Example
    $cred=Get-Credential
    $at=Get-AADIntAccessTokenForOfficeApps -credentials $cred
    Get-AADIntSharedWithUser -AccessToken $at
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "ab9b8c07-8f02-4f72-87fa-80105867a763" -Resource "https://officeapps.live.com"

        $headers = @{
            "Authorization"="Bearer $AccessToken"
        }
        
        $response=Invoke-RestMethod -Uri "https://ocws.officeapps.live.com/ocs/docs/v2.0/sharedwithme" -Headers $headers

        return $response.shared_documents
    }
}