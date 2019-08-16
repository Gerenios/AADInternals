# Add some assemblies
Add-type -AssemblyName System.xml.linq
Add-Type -AssemblyName System.Runtime.Serialization
Add-Type -AssemblyName System.Windows.Forms 
Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System.Web.Extensions 

# Load the .ps1 scripts
$scripts = @(Get-ChildItem -Path $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue)

foreach ($script in $scripts) {
    try {
        Write-Verbose "Importing $($import.FullName)"
        . $script.FullName
    } catch {
        Write-Error "Failed to import $($script.FullName): $_"
    }
}

# Export functions
$functions=@(
    # ADFS_utils.ps1
    "Export-ADFSSigningCertificate"
    "Export-ADFSEncryptionCertificate"
    "New-ADFSSelfSignedCertificates"
    "Restore-ADFSAutoRollover"
    "Update-ADFSFederationSettings"

    # AccessToken_utils.ps1
    "Get-LoginInformation"
    "Get-AccessTokenForAADGraph"
    "Get-AccessTokenForMSGraph"
    "Get-AccessTokenForPTA"
    "Get-AccessTokenForEXO"
    "Get-AccessTokenForSARA"
    "Get-TenantDetails"
    "Read-AccessToken"
    "Get-EndpointInstances"
    "Get-EndpointIps"
    "Get-OpenIDConfiguration"
    "Get-TenantId"

    # ProvisioningAPI.ps1
    "Set-DomainAuthentication"
    "Get-CompanyInformation"
    "Get-SPOServiceInformation"
    "Get-ServiceLocations"
    "Get-CompanyTags"
    "Get-ServicePlans"
    "Get-Subscriptions"
    "Get-Users"
    "Get-User"
    "Remove-User"
    "New-User" # TODO: remove unused parameters
    "Set-User" # TODO: remove unused parameters
    "Get-GlobalAdmins"
    "New-Domain" # TODO: remove unused parameters

    #FederatedIdentityTools.ps1
    "Get-Certificate"
    "New-SAMLToken"
    "New-SAML2Token"
    "Get-ImmutableID"
    "ConvertTo-Backdoor"
    "New-Backdoor"
    "Open-Office365Portal"

    # AzureADConnectAPI.ps1
    "Get-SyncConfiguration"
    "Set-AzureADObject"
    "Remove-AzureADObject"
    "Get-SyncObjects"
    "Set-UserPassword"
    "Reset-ServiceAccount"
    "Set-PassThroughAuthentication"
    "Set-PasswordHashSyncEnabled"

    # AzureManagementAPI_utils.ps1
    "Get-AccessTokenForAADIAMAPI"
    "Get-AccessTokenForAzureMgmtAPI"

    # AzureManagementAPI.ps1
    "New-GuestInvitation"
    "Get-UserTenants"

    # ActiveSync.ps1
    "Get-EASAutoDiscover"
    "Get-EASAutoDiscoverV1"
    "Get-EASOptions"
    "Send-EASMessage"
    "Add-EASDevice"
    "Set-EASSettings"

    # OutlookAPI.ps1
    "Send-OutlookMessage"

    # PSRP.ps1
    "Get-TenantDomains"
    "Get-MobileDevices"

    # AADSyncSettings.ps1
    "Get-SyncCredentials"
    "Update-SyncCredentials"

    # PTASpy.ps1
    "Install-PTASpy"
    "Remove-PTASpy"
    "Get-PTASpyLog"

    # ClientTools.ps1
    "Get-OfficeUpdateBranch"
    "Set-OfficeUpdateBranch"

    # SARA.ps1
    "Get-SARAUserInfo"
    "Get-SARATenantInfo"

    # SPO_utils.ps1
    "Get-SPOAuthenticationHeader"

    # SPO.ps1
    "Get-SPOSiteUsers"
    "Get-SPOSiteGroups"
    "Get-SPOUserProperties"
)
foreach($function in $functions)
{
    Export-ModuleMember -Function $function
}
