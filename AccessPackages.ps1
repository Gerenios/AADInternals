# This file contains functions for accessing access packages

# Gets access packages
# Apr 24 2023
function Get-AccessPackages
{
<#
    .SYNOPSIS
    Returns access packages.

    .DESCRIPTION
    Returns access packages.

    .Parameter AccessToken
    Access token for the target tenant.
    
    .Example
    PS C:\>Get-AADIntAccessTokenForAccessPackages -Tenant company.com -SaveToCache
    PS C:\>Get-AADIntAccessPackages

    id                                     : df9513b4-1686-4434-8c37-cbfaeea51b69
    catalogId                              : 755780b3-9228-4cf6-8919-732c6f0ff026
    displayName                            : Visitors
    description                            : Access package for Visitors
    isHidden                               : False
    isRoleScopesVisible                    : False
    createdBy                              : johnd@company.com
    createdByString                        : johnd@company.com
    createdDateTime                        : 2022-01-02T10:20:44.247Z
    modifiedBy                             : johnd@company.com
    lastModifiedByString                   : johnd@company.com
    modifiedDateTime                       : 2022-01-02T10:20:44.247Z
    lastModifiedDateTime                   : 2022-01-02T10:20:44.247Z
    lastCriticalModificationDateTime       : 
    lastSuccessfulChangeEvaluationDateTime :

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://elm.iga.azure.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Get access packages
        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://elm.iga.azure.com/api/v1/accessPackages/Search()?`$count=true&`$top=999" -Headers @{"Authorization" = "Bearer $AccessToken"}
        }
        catch{}

        return $response.Value
    }
}

# Gets access package catalogs
# Apr 24 2023
function Get-AccessPackageCatalogs
{
<#
    .SYNOPSIS
    Returns access package catalogs.

    .DESCRIPTION
    Returns access package catalogs.

    .Parameter AccessToken
    Access token for the target tenant.
    
    .Example
    PS C:\>Get-AADIntAccessTokenForAccessPackages -Tenant company.com -SaveToCache
    PS C:\>Get-AADIntAccessPackageCatalogs

    id                   : 755780b3-9228-4cf6-8919-732c6f0ff026
    displayName          : Visitors
    description          : Catalog for visitors
    catalogType          : UserManaged
    catalogStatus        : Published
    state                : published
    isExternallyVisible  : True
    createdBy            : johnd@company.com
    createdByString      : johnd@company.com
    createdDateTime      : 2022-01-02T10:20:44.247Z
    modifiedBy           : johnd@company.com
    lastModifiedByString : johnd@company.com
    modifiedDateTime     : 2022-01-02T10:20:44.247Z
    lastModifiedDateTime : 2022-01-02T10:20:44.247Z
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://elm.iga.azure.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Get access packages
        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://elm.iga.azure.com/api/v1/accessPackageCatalogs/Search()?`$count=true&`$top=999" -Headers @{"Authorization" = "Bearer $AccessToken"}
        }
        catch{}

        return $response.Value
    }
}



# Returns access package creators & modifiers
# Apr 24th 2023
function Get-AccessPackageAdmins
{
<#
    .SYNOPSIS
    Returns access packages administrators.

    .DESCRIPTION
    Returns administrators from access package and access package catalog createdBy and modifiedBy fields.

    The returned administrators are Global Administrators, User Administrators (until May 5 2023), or Identity Governance Administrators (since May 2023).

    .Parameter AccessToken
    Access token for the target tenant.
    
    .Example
    PS C:\>Get-AADIntAccessTokenForAccessPackages -Tenant company.com -SaveToCache
    PS C:\>Get-AADIntAccessPackageAdmins

    Acheaduncompany.com
    Alexaneoscompany.com
    Andownlocompany.com
    Anselowslcompany.com
    Babergencompany.com
    Bethportcompany.com
    Brangelocompany.com
    Caranteecompany.com
    Chmenscompany.com
    Conneytrcompany.com
    Crofficompany.com
    Diumficompany.com
    Downtichocompany.com
    Getacewedcompany.com

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get token for access packages
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://elm.iga.azure.com"

        # Get access packages and catalogs
        $accessPackages        = Get-AccessPackages        -AccessToken $AccessToken
        $accessPackageCatalogs = Get-AccessPackageCatalogs -AccessToken $AccessToken

        # Get names
        $names = @()
        $accesspackageCatalogs | Select -ExpandProperty "createdBy"  | %{ $names += $_}
        $accesspackageCatalogs | Select -ExpandProperty "modifiedBy" | %{ $names += $_}
        $accesspackages        | Select -ExpandProperty "createdBy"  | %{ $names += $_}
        $accesspackages        | Select -ExpandProperty "modifiedBy" | %{ $names += $_}

        # Return unique usernames with upn
        $names | Select-String -Pattern "@" | Sort-Object | Get-Unique 
    }
}
