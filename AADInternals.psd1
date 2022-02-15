@{

	# Script module or binary module file associated with this manifest.
	RootModule = 'AADInternals.psm1'

	# Version number of this module.
	ModuleVersion = '0.6.6'

	# Supported PSEditions
	# CompatiblePSEditions = @()

	# ID used to uniquely identify this module
	GUID = 'eebccc08-baea-4ac4-9e05-67d16d43e8b1'

	# Author of this module
	Author = 'Dr Nestori Syynimaa'

	# Company or vendor of this module
	CompanyName = 'Gerenios Ltd'

	# Copyright statement for this module
	Copyright = '(c) 2018 - 2022 Nestori Syynimaa (@DrAzureAD). Distributed under MIT license.'

	# Description of the functionality provided by this module
	Description = 'The AADInternals PowerShell Module utilises several internal features of Azure Active Directory, Office 365, and related admin tools.

AADInternals allows you to export ADFS certificates, Azure AD Connect passwords, and modify numerous Azure AD / Office 365 settings not otherwise possible.

DISCLAIMER: Functionality provided through this module are not supported by Microsoft and thus should not be used in a production environment. Use on your own risk! 

'

	# Minimum version of the Windows PowerShell engine required by this module
	# PowerShellVersion = ''

	# Name of the Windows PowerShell host required by this module
	# PowerShellHostName = ''

	# Minimum version of the Windows PowerShell host required by this module
	# PowerShellHostVersion = ''

	# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
	# DotNetFrameworkVersion = ''

	# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
	# CLRVersion = ''

	# Processor architecture (None, X86, Amd64) required by this module
	# ProcessorArchitecture = ''

	# Modules that must be imported into the global environment prior to importing this module
	# RequiredModules = @()

	# Assemblies that must be loaded prior to importing this module
	# RequiredAssemblies = @()

	# Script files (.ps1) that are run in the caller's environment prior to importing this module.
	# ScriptsToProcess = @()

	# Type files (.ps1xml) to be loaded when importing this module
	# TypesToProcess = @()

	# Format files (.ps1xml) to be loaded when importing this module
	# FormatsToProcess = @()

	# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
	NestedModules = @(
        ".\AADSyncSettings.ps1"
        ".\AccessToken.ps1"
        ".\AccessToken_utils.ps1"
        ".\ActiveSync.ps1"
        ".\ActiveSync_utils.ps1"
        ".\ADFS.ps1"
        ".\ADFS_utils.ps1"
        ".\AD_utils.ps1"
        ".\AdminAPI.ps1"
        ".\AdminAPI_utils.ps1"
        ".\AMQP.ps1"
        ".\AzureADConnectAPI.ps1"
        ".\AzureADConnectAPI_utils.ps1"
        ".\AzureCoreManagement.ps1"
        ".\AzureManagementAPI.ps1"
        ".\AzureManagementAPI_utils.ps1"
        ".\ClientTools.ps1"
        ".\CloudShell.ps1"
        ".\CloudShell_utils.ps1"
        ".\CommonUtils.ps1"
        ".\ComplianceAPI.ps1"
        ".\ComplianceAPI_utils.ps1"
        ".\Device.ps1"
        ".\Device_utils.ps1"
        ".\DRS_Utils.ps1"
        ".\FederatedIdentityTools.ps1"
        ".\GraphAPI.ps1"
        ".\GraphAPI_utils.ps1"
        ".\HybridHealthServices.ps1"
        ".\HybridHealthServices_utils.ps1"
        ".\IPUtils.ps1"
        ".\Kerberos.ps1"
        ".\Kerberos_utils.ps1"
        ".\KillChain.ps1"
        ".\KillChain_utils.ps1"
        ".\md4.ps1"
        ".\MDM.ps1"
        ".\MDM_utils.ps1"
        ".\MFA.ps1"
        ".\MFA_utils.ps1"
        ".\MSAppProxy.ps1"
        ".\MSAppProxy_utils.ps1"
        ".\MSCommerce.ps1"
        ".\MSPartner.ps1"
        ".\MSPartner_utils.ps1"
        ".\MSGraphAPI.ps1"
        ".\MSGraphAPI_utils.ps1"
        ".\OfficeApps.ps1"
        ".\OneDrive.ps1"
        ".\OneDrive_utils.ps1"
        ".\OutlookAPI.ps1"
        ".\OutlookAPI_utils.ps1"
        ".\ProcessTools.ps1"
        ".\ProvisioningAPI.ps1"
        ".\ProvisioningAPI_utils.ps1"
        ".\ProxySettings.ps1"
        ".\PRT.ps1"
        ".\PRT_Utils.ps1"
        ".\PSRP.ps1"
        ".\PSRP_utils.ps1"
        ".\PTA.ps1"
        ".\PTAAgent.ps1"
        ".\PTASpy.ps1"
        ".\SARA.ps1"
        ".\SPO.ps1"
        ".\SPO_utils.ps1"
        ".\SyncAgent.ps1"
        ".\Teams.ps1"
        ".\Teams_utils.ps1"
        ".\WBAWeaponiser.ps1"
)

	# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
	FunctionsToExport = @(
    # ADFS.ps1
    "Export-ADFSCertificates"
    "Export-ADFSConfiguration"
    "Export-ADFSEncryptionKey"
    "Set-ADFSConfiguration"
    "Get-ADFSPolicyStoreRules"
    "Set-ADFSPolicyStoreRules"
    "Unprotect-ADFSRefreshToken"
    "New-ADFSRefreshToken"

    # ADFS_utils.ps1
    "New-ADFSSelfSignedCertificates"
    "Restore-ADFSAutoRollover"
    "Update-ADFSFederationSettings"
    "Get-ADFSConfiguration"
    
    # AccessToken.ps1
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
    "Get-AccessTokenForMSCommerce"
    "Get-AccessTokenForMSPartner"
    "Get-AccessTokenForAdmin"
    
    # AccessToken_utils.ps1
    "Get-LoginInformation"
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
    "Get-ConditionalAccessPolicies"

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
    "Get-MSPartnerContracts"

    #FederatedIdentityTools.ps1
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
    "Get-PassThroughAuthenticationStatus"

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
    "Open-OWA"

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
    "Get-AzureDirectoryActivityLog"

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
    "New-Certificate"
    "Get-AzureWireServerAddress"

    # Teams.ps1
    "Get-SkypeToken"
    "Set-TeamsAvailability"
    "Set-TeamsStatusMessage"
    "Search-TeamsUser"
    "Send-TeamsMessage"
    "Get-TeamsMessages"
    "Remove-TeamsMessages"
    "Set-TeamsMessageEmotion"

    # DRS_Utils.ps1
    "Get-ADUserNTHash"
    "Get-ADUserThumbnailPhoto"
    "Get-DesktopSSOAccountPassword"

    # HybridHealthServices.ps1
    "New-HybridHealthService"
    "Get-HybridHealthServices"
    "Remove-HybridHealthService"
    "Get-HybridHealthServiceMembers"
    "New-HybridHealthServiceMember"
    "Remove-HybridHealthServiceMember"
    "Get-HybridHealthServiceMonitoringPolicies"
    "Send-HybridHealthServiceEvents"
    "Register-HybridHealthServiceAgent"

    # HybridHealthServices_utils.ps1
    "New-HybridHealtServiceEvent"
    "Get-HybridHealthServiceAgentInfo"

    # MSCommerce.ps1
    "Get-SelfServicePurchaseProducts"
    "Set-SelfServicePurchaseProduct"

    # ComplianceAPI.ps1
    "Get-ComplianceAPICookies"
    "Search-UnifiedAuditLog"

    # MSPartner.ps1
    "New-MSPartnerDelegatedAdminRequest"
    #"New-MSPartnerTrialOffer"
    #"Get-MSPartnerOffers"
    #"Get-MSPartnerPublishers"
    "Get-MSPartnerOrganizations"
    "Get-MSPartnerRoleMembers"
    "Find-MSPartners"

    # AdminAPI.ps1
    "Approve-MSPartnerDelegatedAdminRequest"
    "Remove-MSPartnerDelegatedAdminRoles"
    "Get-MSPartners"  
    
    # Device.ps1
    "Export-LocalDeviceCertificate"
    "Export-LocalDeviceTransportKey" 
    "Join-LocalDeviceToAzureAD"
    "Get-LocalDeviceJoinInfo"

    # ProxySettings.ps1
    "Set-ProxySettings"
)

	# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
	CmdletsToExport = @()

	# Variables to export from this module
	VariablesToExport = ''

	# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
	AliasesToExport = @()

	# DSC resources to export from this module
	# DscResourcesToExport = @()

	# List of all modules packaged with this module
	# ModuleList = @()

	# List of all files packaged with this module
	# FileList = @()

	# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{

		PSData = @{

			# Tags applied to this module. These help with module discovery in online galleries.
			Tags = @('Office365','Microsoft365','Azure','AAD','Security')

			# A URL to the license for this module.
			# LicenseUri = ''

			# A URL to the main website for this project.
			ProjectURI = 'https://o365blog.com/aadinternals'

			# A URL to an icon representing this module.
			# IconUri = ''

			# ReleaseNotes of this module
			# ReleaseNotes = ''

		} # End of PSData hashtable

	} # End of PrivateData hashtable

	# HelpInfo URI of this module
	# HelpInfoURI = ''

	# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
	DefaultCommandPrefix = 'AADInt'

}

