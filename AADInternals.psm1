# Add some assemblies
Add-type -AssemblyName System.xml.linq              -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Runtime.Serialization -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Windows.Forms         -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Web                   -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Web.Extensions        -ErrorAction SilentlyContinue

# Set supported TLS methods
[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"

# Print the welcome message
$manifest = Import-PowerShellDataFile "$PSScriptRoot\AADInternals.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle="AADInternals $version"

$logo=@"
    ___    ___    ____  ____      __                        __    
   /   |  /   |  / __ \/  _/___  / /____  _________  ____ _/ /____
  / /| | / /| | / / / // // __ \/ __/ _ \/ ___/ __ \/ __ ``/ / ___/
 / ___ |/ ___ |/ /_/ _/ // / / / /_/  __/ /  / / / / /_/ / (__  ) 
/_/  |_/_/  |_/_____/___/_/ /_/\__/\___/_/  /_/ /_/\__,_/_/____/  
  
 v$version by @NestoriSyynimaa
"@

Write-Host $logo -ForegroundColor Yellow

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
    "Get-AccessTokenForOneDrive"
    "Get-AccessTokenForOfficeApps"
    "Get-AccessTokenForAzureCoreManagement"
    "Get-AccessTokenForSPO"
    "Get-AccessTokenForMySignins"
    "Get-AccessTokenForAADJoin"
    "Get-AccessTokenForIntuneMDM"
    "Get-AccessTokenForCloudShell"
    "Get-AccessTokenForTeams"
    "Read-AccessToken"
    "Get-EndpointInstances"
    "Get-EndpointIps"
    "Get-OpenIDConfiguration"
    "Get-TenantId"
    "Get-TenantDomains"
    "Get-Cache"
    "Clear-Cache"

    # GraphAPI.ps1
    "Get-TenantDetails"
    "Get-Devices"
    "Get-UserDetails"
    "Get-ServicePrincipals"

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
    "Set-ADSyncEnabled"

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
    "Set-PassThroughAuthenticationEnabled"
    "Set-PasswordHashSyncEnabled"
    "Set-DesktopSSOEnabled"
    "Get-DesktopSSO"
    "Set-DesktopSSO"
    "Get-KerberosDomainSyncConfig"
    "Get-WindowsCredentialsSyncConfig"
    "Get-SyncDeviceConfiguration"
    "Join-OnPremDeviceToAzureAD"

    # AzureManagementAPI_utils.ps1
    "Get-AccessTokenForAADIAMAPI"
    "Get-AccessTokenForAzureMgmtAPI"

    # AzureManagementAPI.ps1
    "New-GuestInvitation"
    "Get-AzureInformation"
    "Get-AADConnectStatus"

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
    "Get-MobileDevices"
    "Get-UnifiedAuditLogSettings"
    "Set-UnifiedAuditLogSettings"

    # AADSyncSettings.ps1
    "Get-SyncCredentials"
    "Update-SyncCredentials"
    "Get-SyncEncryptionKeyInfo"
    "Get-SyncEncryptionKey"

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

    # Kerberos.ps1
    "New-KerberosTicket"

    # PTA.ps1
    "Register-PTAAgent"
    "Set-PTACertificate"

    # PTAAgent.ps1
    "Invoke-PTAAgent"

    # OneDrive_utils.ps1
    "New-OneDriveSettings"

    # OneDrive.ps1
    "Get-OneDriveFiles"
    "Send-OneDriveFile"

    # MFA.ps1
    "Get-UserMFA"
    "Set-UserMFA"
    "New-OTP"
    "New-OTPSecret"
    "Get-UserMFAApps"
    "Set-UserMFAApps"
    "Register-MFAApp"

    # SyncAgent.ps1
    "Register-SyncAgent"

    # MSAppProxy_utils.ps1
    "Get-ProxyAgents"
    "Get-ProxyAgentGroups"

    # AD_Utils.ps1
    "Get-DPAPIKeys"
    "Get-LSASecrets"
    "Get-LSABackupKeys"
    "Get-UserMasterkeys"
    "Get-LocalUserCredentials"
    "Get-SystemMasterkeys"

    # AzureCoreManagement.ps1
    "Get-AzureClassicAdministrators"
    "Grant-AzureUserAccessAdminRole"
    "Get-AzureSubscriptions"
    "Set-AzureRoleAssignment"
    "Get-AzureResourceGroups"
    "Get-AzureVMs"
    "Invoke-AzureVMScript"
    "Get-AzureVMRdpSettings"
    "Get-AzureTenants"
    "Get-AzureDiagnosticSettingsDetails"
    "Set-AzureDiagnosticSettingsDetails"
    "Get-AzureDiagnosticSettings"
    "Remove-AzureDiagnosticSettings"

    # MSGraphAPI.ps1
    "Get-AzureSignInLog"
    "Get-AzureAuditLog"
    "Get-TenantAuthPolicy"
    "Get-TenantGuestAccess"
    "Set-TenantGuestAccess"
    "Enable-TenantMsolAccess"
    "Disable-TenantMsolAccess"
    "Get-RolloutPolicies"
    "Get-RolloutPolicyGroups"
    "Add-RolloutPolicyGroups"
    "Remove-RolloutPolicyGroups"
    "Remove-RolloutPolicy"
    "Set-RolloutPolicy"

    # KillChain.ps1
    "Invoke-UserEnumerationAsOutsider"
    "Invoke-ReconAsOutsider"
    "Invoke-ReconAsGuest"
    "Invoke-UserEnumerationAsGuest"
    "Invoke-ReconAsInsider"
    "Invoke-UserEnumerationAsInsider"
    "Invoke-Phishing"

    # WBAWeaponiser.ps1
    "New-InvitationVBA"

    # PRT.ps1
    "Get-UserPRTToken"
    "Get-UserPRTKeys"
    "New-UserPRTToken"
    "Join-DeviceToAzureAD"
    "New-P2PDeviceCertificate"
    "Remove-DeviceFromAzureAD"
    "Get-DeviceRegAuthMethods"
    "Set-DeviceRegAuthMethods"
    "Get-DeviceTransportKey"
    "Set-DeviceTransportKey"
    "New-BulkPRTToken"

    # MDM.ps1
    "Join-DeviceToIntune"
    "Start-DeviceIntuneCallback"
    "Set-DeviceCompliant"
    "Get-DeviceCompliance"

    # CloudShell.ps1
    "Start-CloudShell"

    # CommonUtils.ps1
    "Get-Error"

    # Teams.ps1
    "Get-SkypeToken"
    "Set-TeamsAvailability"
    "Set-TeamsStatusMessage"
    "Search-TeamsUser"
    "Send-TeamsMessage"
    "Get-TeamsMessages"
    "Remove-TeamsMessages"
    "Set-TeamsMessageEmotion"

)
foreach($function in $functions)
{
    Export-ModuleMember -Function $function
}
