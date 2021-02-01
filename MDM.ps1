# This file contains functions for Intune MDM

# Enroll device to Intune MDM
# Aug 29th
function Join-DeviceToIntune
{
<#
    .SYNOPSIS
    Registers (enrolls) the given device to Intune.

    .DESCRIPTION
    Enrolls the given device to Intune and generates a corresponding certificate.

    After enrollment, the device is in compliant state (depends on the Intune configuration), which allows bypassing conditional access (CA) restrictions based on the compliance.

    The certificate has no password.

    .Parameter AccessToken
    The access token used to enroll the device. Must have deviceid claim!
    If not given, will be prompted.

    .Parameter DeviceName
    The name of the device to be registered.

    .EXAMPLE
    Get-AADIntAccessTokenForIntuneMDM -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache

    PS C\:>Join-AADIntDeviceToIntune -DeviceName "My computer"

    Intune client certificate successfully created:
      Subject:         "CN=5ede6e7a-7b77-41bd-bfe0-ef29ca70a3fb"
      Issuer:          "CN=Microsoft Intune MDM Device CA"
      Cert thumbprint: A1D407FF66EF05D153B67129B8541058A1C395B1
      Cert file name:  "d03994c9-24f8-41ba-a156-1805998d6dc7-MDM.pfx"
      CA file name :   "d03994c9-24f8-41ba-a156-1805998d6dc7-MDM-CA.der"
      IntMedCA file :  "d03994c9-24f8-41ba-a156-1805998d6dc7-MDM-INTMED-CA.der"

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$DeviceName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "29d9ed98-a469-4536-ade2-f981bc1d605e" -Resource "https://enrollment.manage.microsoft.com/"

        # Get the claims
        $claims = Read-Accesstoken -AccessToken $AccessToken
        
        if(!$claims.deviceid)
        {
            throw "No device id included in access token! Use Get-AADIntAccessTokenForIntuneMDM with the device certificate and try again."
        }

        # If the username starts with package_ assume it be a BPRT
        $BPRT = $claims.upn.StartsWith("package_")
        
        try
        {
            $joinInfo = Enroll-DeviceToMDM -AccessToken $AccessToken -DeviceName $DeviceName -BPRT $BPRT
        }
        catch
        {
            Write-Error $_.ErrorDetails.Message
            return
        }

        # Get the certificates
        $CA =                $joinInfo[0]
        $IntMedCA =          $joinInfo[1]
        $clientCertificate = $joinInfo[2]
        
        $clientCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx) | Set-Content "$($claims.deviceid)-MDM.pfx" -Encoding Byte
        
        $CA       | Set-Content "$($claims.deviceid)-MDM-CA.der"
        $IntMedCA | Set-Content "$($claims.deviceid)-MDM-INTMED-CA.der"

        # Unload the private key
        Unload-PrivateKey -PrivateKey $clientCertificate.privateKey

        # Print out information
        Write-Host "Intune client certificate successfully created:"
        Write-Host "  Subject:         ""$($clientCertificate.Subject)"""
        Write-Host "  Issuer:          ""$($clientCertificate.Issuer)"""
        Write-Host "  Cert thumbprint: $($clientCertificate.Thumbprint)"
        Write-host "  Cert file name:  ""$($claims.deviceid)-MDM.pfx"""
        Write-host "  CA file name :   ""$($claims.deviceid)-MDM-CA.der"""
        Write-host "  IntMedCA file :  ""$($claims.deviceid)-MDM-INTMED-CA.der"""
            
    }
}

# Sep 2nd 2020
function Start-DeviceIntuneCallback
{
<#
    .SYNOPSIS
    Starts a device callback to Intune.

    .DESCRIPTION
    Starts a device callback to Intune. Resets also the name of the device to given device name.
    
    .Parameter DeviceName
    The name the device to be seen in Intune portal.

    .EXAMPLE
    Start-AADIntDeviceIntuneCallback -pfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7MDM.pfx

    .Parameter Certificate
    x509 certificate of the device.

    .Parameter PfxFileName
    File name of the .pfx certificate of the device.

    .Parameter PfxPassword
    The password of the .pfx certificate of the device.
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [string]$PfxPassword,

        [Parameter(Mandatory=$True)]
        [string]$DeviceName,
        [Parameter(Mandatory=$False)]
        [ValidateSet("User","Others","None")]
        [string]$Scope="None",
        [Parameter(Mandatory=$False)]
        [int]$SessionId=1
    )
    Begin
    {
        # CPS Version xml 
        $CSPVersions = @"
<?xml version="1.0" encoding="utf-8"?>
<DeviceManageability Version="com.microsoft/1.1/MDM/DeviceManageability">
	<Capabilities>
		<CSPVersions>
			<CSP Node="./DevDetail" Version="1.1"/>
			<CSP Node="./DevInfo" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/AssignedAccess" Version="4.0"/>
			<CSP Node="./Device/Vendor/MSFT/BitLocker" Version="5.0"/>
			<CSP Node="./Device/Vendor/MSFT/ClientCertificateInstall" Version="1.1"/>
			<CSP Node="./Device/Vendor/MSFT/DMClient" Version="1.5"/>
			<CSP Node="./Device/Vendor/MSFT/DeclaredConfiguration" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/DeviceManageability" Version="2.0"/>
			<CSP Node="./Device/Vendor/MSFT/DeviceUpdateCenter" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/EnrollmentStatusTracking" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/EnterpriseAppVManagement" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/EnterpriseDataProtection" Version="4.0"/>
			<CSP Node="./Device/Vendor/MSFT/EnterpriseDesktopAppManagement" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/EnterpriseModernAppManagement" Version="1.2"/>
			<CSP Node="./Device/Vendor/MSFT/OfflineDomainJoin" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/OptionalFeatures" Version="1.1"/>
			<CSP Node="./Device/Vendor/MSFT/PassportForWork" Version="1.4"/>
			<CSP Node="./Device/Vendor/MSFT/Policy" Version="9.0"/>
			<CSP Node="./Device/Vendor/MSFT/PolicyManager/DeviceLock" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/PolicyManager/Security" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/Reboot" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/RemoteLock" Version="1.1"/>
			<CSP Node="./Device/Vendor/MSFT/RootCATrustedCertificates" Version="1.1"/>
			<CSP Node="./Device/Vendor/MSFT/VPNv2" Version="1.0"/>
			<CSP Node="./Device/Vendor/MSFT/WindowsAdvancedThreatProtection" Version="1.2"/>
			<CSP Node="./Device/Vendor/MSFT/WindowsDefenderApplicationGuard" Version="1.3"/>
			<CSP Node="./Device/Vendor/MSFT/WindowsLicensing" Version="1.3"/>
			<CSP Node="./SyncML/DMAcc" Version="1.0"/>
			<CSP Node="./SyncML/DMS" Version="1.0"/>
			<CSP Node="./User/Vendor/MSFT/ActiveSync" Version="1.0"/>
			<CSP Node="./User/Vendor/MSFT/ClientCertificateInstall" Version="1.1"/>
			<CSP Node="./User/Vendor/MSFT/DMClient" Version="1.5"/>
			<CSP Node="./User/Vendor/MSFT/DMSessionActions" Version="1.1"/>
			<CSP Node="./User/Vendor/MSFT/DeclaredConfiguration" Version="1.0"/>
			<CSP Node="./User/Vendor/MSFT/EMAIL2" Version="1.0"/>
			<CSP Node="./User/Vendor/MSFT/EnrollmentStatusTracking" Version="1.0"/>
			<CSP Node="./User/Vendor/MSFT/EnterpriseAppVManagement" Version="1.0"/>
			<CSP Node="./User/Vendor/MSFT/EnterpriseDesktopAppManagement" Version="1.0"/>
			<CSP Node="./User/Vendor/MSFT/EnterpriseModernAppManagement" Version="1.2"/>
			<CSP Node="./User/Vendor/MSFT/NodeCache" Version="1.2"/>
			<CSP Node="./User/Vendor/MSFT/PassportForWork" Version="1.4"/>
			<CSP Node="./User/Vendor/MSFT/Policy" Version="9.0"/>
			<CSP Node="./User/Vendor/MSFT/PolicyManager/DeviceLock" Version="1.0"/>
			<CSP Node="./User/Vendor/MSFT/PolicyManager/Security" Version="1.0"/>
			<CSP Node="./User/Vendor/MSFT/RootCATrustedCertificates" Version="1.1"/>
			<CSP Node="./User/Vendor/MSFT/VPNv2" Version="1.0"/>
			<CSP Node="./User/Vendor/MSFT/WiFi" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/ActiveSync" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/AppLocker" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/CMPolicy" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/CMPolicyEnterprise" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/CellularSettings" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/CertificateStore" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/CleanPC" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/DMClient" Version="1.5"/>
			<CSP Node="./Vendor/MSFT/DMSessionActions" Version="1.1"/>
			<CSP Node="./Vendor/MSFT/DeclaredConfiguration" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/Defender" Version="1.3"/>
			<CSP Node="./Vendor/MSFT/DeviceLock" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/DeviceStatus" Version="1.5"/>
			<CSP Node="./Vendor/MSFT/DeviceUpdate" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/DiagnosticLog" Version="1.4"/>
			<CSP Node="./Vendor/MSFT/DynamicManagement" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/EMAIL2" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/EnterpriseAPN" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/EnterpriseModernAppManagement" Version="1.2"/>
			<CSP Node="./Vendor/MSFT/Firewall" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/HealthAttestation" Version="1.3"/>
			<CSP Node="./Vendor/MSFT/Maps" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/MultiSIM" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/NetworkProxy" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/NodeCache" Version="1.2"/>
			<CSP Node="./Vendor/MSFT/Office" Version="1.5"/>
			<CSP Node="./Vendor/MSFT/PassportForWork" Version="1.4"/>
			<CSP Node="./Vendor/MSFT/Personalization" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/Policy" Version="9.0"/>
			<CSP Node="./Vendor/MSFT/PolicyManager/DeviceLock" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/PolicyManager/Security" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/RemoteFind" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/RemoteLock" Version="1.1"/>
			<CSP Node="./Vendor/MSFT/RemoteWipe" Version="1.1"/>
			<CSP Node="./Vendor/MSFT/Reporting" Version="2.1"/>
			<CSP Node="./Vendor/MSFT/SUPL" Version="1.1"/>
			<CSP Node="./Vendor/MSFT/SecureAssessment" Version="1.1"/>
			<CSP Node="./Vendor/MSFT/SecurityPolicy" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/SharedPC" Version="1.2"/>
			<CSP Node="./Vendor/MSFT/Storage" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/TPMPolicy" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/TenantLockdown" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/UnifiedWriteFilter" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/Update" Version="1.1"/>
			<CSP Node="./Vendor/MSFT/VPNv2" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/WiFi" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/Win32AppInventory" Version="1.0"/>
			<CSP Node="./Vendor/MSFT/WindowsLicensing" Version="1.3"/>
			<CSP Node="./Vendor/MSFT/eUICCs" Version="1.2"/>
			<CSP Node="./Vendor/MSFT/uefi" Version="1.0"/>
			<CSP Node="./cimv2/MDM_AppInstallJob" Version="1.0"/>
			<CSP Node="./cimv2/MDM_Application" Version="1.0"/>
			<CSP Node="./cimv2/MDM_ApplicationFramework" Version="1.0"/>
			<CSP Node="./cimv2/MDM_ApplicationSetting" Version="1.0"/>
			<CSP Node="./cimv2/MDM_BrowserSecurityZones" Version="1.0"/>
			<CSP Node="./cimv2/MDM_BrowserSettings" Version="1.0"/>
			<CSP Node="./cimv2/MDM_Certificate" Version="1.0"/>
			<CSP Node="./cimv2/MDM_CertificateEnrollment" Version="1.0"/>
			<CSP Node="./cimv2/MDM_Client" Version="1.0"/>
			<CSP Node="./cimv2/MDM_ConfigSetting" Version="1.0"/>
			<CSP Node="./cimv2/MDM_EASPolicy" Version="1.0"/>
			<CSP Node="./cimv2/MDM_MgmtAuthority" Version="1.0"/>
			<CSP Node="./cimv2/MDM_RemoteAppUserCookie" Version="1.0"/>
			<CSP Node="./cimv2/MDM_RemoteApplication" Version="1.0"/>
			<CSP Node="./cimv2/MDM_Restrictions" Version="1.0"/>
			<CSP Node="./cimv2/MDM_RestrictionsUser" Version="1.0"/>
			<CSP Node="./cimv2/MDM_SecurityStatus" Version="1.0"/>
			<CSP Node="./cimv2/MDM_SecurityStatusUser" Version="1.0"/>
			<CSP Node="./cimv2/MDM_SideLoader" Version="1.0"/>
			<CSP Node="./cimv2/MDM_Updates" Version="1.0"/>
			<CSP Node="./cimv2/MDM_VpnApplicationTrigger" Version="1.0"/>
			<CSP Node="./cimv2/MDM_VpnConnection" Version="1.0"/>
			<CSP Node="./cimv2/MDM_WNSChannel" Version="1.0"/>
			<CSP Node="./cimv2/MDM_WNSConfiguration" Version="1.0"/>
			<CSP Node="./cimv2/MDM_WebApplication" Version="1.0"/>
			<CSP Node="./cimv2/MDM_WirelessProfile" Version="1.0"/>
			<CSP Node="./cimv2/MDM_WirelessProfileXml" Version="1.0"/>
			<CSP Node="./cimv2/MSFT_NetFirewallProfile" Version="1.0"/>
			<CSP Node="./cimv2/MSFT_VpnConnection" Version="1.0"/>
			<CSP Node="./cimv2/Win32_DisplayConfiguration" Version="1.0"/>
			<CSP Node="./cimv2/Win32_EncryptableVolume" Version="1.0"/>
			<CSP Node="./cimv2/Win32_InfraredDevice" Version="1.0"/>
			<CSP Node="./cimv2/Win32_LocalTime" Version="1.0"/>
			<CSP Node="./cimv2/Win32_LogicalDisk" Version="1.0"/>
			<CSP Node="./cimv2/Win32_NetworkAdapter" Version="1.0"/>
			<CSP Node="./cimv2/Win32_NetworkAdapterConfiguration" Version="1.0"/>
			<CSP Node="./cimv2/Win32_OperatingSystem" Version="1.0"/>
			<CSP Node="./cimv2/Win32_PhysicalMemory" Version="1.0"/>
			<CSP Node="./cimv2/Win32_PnPDevice" Version="1.0"/>
			<CSP Node="./cimv2/Win32_PortableBattery" Version="1.0"/>
			<CSP Node="./cimv2/Win32_Processor" Version="1.0"/>
			<CSP Node="./cimv2/Win32_QuickFixEngineering" Version="1.0"/>
			<CSP Node="./cimv2/Win32_Registry" Version="1.0"/>
			<CSP Node="./cimv2/Win32_Service" Version="1.0"/>
			<CSP Node="./cimv2/Win32_Share" Version="1.0"/>
			<CSP Node="./cimv2/Win32_SystemBIOS" Version="1.0"/>
			<CSP Node="./cimv2/Win32_SystemEnclosure" Version="1.0"/>
			<CSP Node="./cimv2/Win32_TimeZone" Version="1.0"/>
			<CSP Node="./cimv2/Win32_UTCTime" Version="1.0"/>
			<CSP Node="./cimv2/Win32_WindowsUpdateAgentVersion" Version="1.0"/>
			<CSP Node="./cimv2/WpcAppOverride" Version="1.0"/>
			<CSP Node="./cimv2/WpcGameOverride" Version="1.0"/>
			<CSP Node="./cimv2/WpcGamesSettings" Version="1.0"/>
			<CSP Node="./cimv2/WpcRating" Version="1.0"/>
			<CSP Node="./cimv2/WpcRatingsDescriptor" Version="1.0"/>
			<CSP Node="./cimv2/WpcRatingsSystem" Version="1.0"/>
			<CSP Node="./cimv2/WpcSystemSettings" Version="1.0"/>
			<CSP Node="./cimv2/WpcURLOverride" Version="1.0"/>
			<CSP Node="./cimv2/WpcUserSettings" Version="1.0"/>
			<CSP Node="./cimv2/WpcWebSettings" Version="1.0"/>
		</CSPVersions>
	</Capabilities>
</DeviceManageability>
"@
    }
    Process
    {
        if(!$Certificate)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        # Initialise some variables
        #$sessionId = 1 
        $msgId =     1 # Increased by one per message
        $hwId = (Convert-ByteArrayToHex -Bytes ([System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([text.encoding]::UTF8.GetBytes($DeviceName)))).ToUpper()
        $encDeviceName=[System.Web.HttpUtility]::HtmlEncode($DeviceName)

        $tenantId = (New-Guid).ToString()
        
      
        # The default settings
        $settings = @{
                "./cimv2/Win32_OperatingSystem" = "Win32_OperatingSystem=@"
                "./cimv2/Win32_LogicalDisk" =     "Win32_LogicalDisk.DeviceID=""C:""/Win32_LogicalDisk.DeviceID=""D:"""
                "./cimv2/Win32_OperatingSystem/Win32_OperatingSystem%3D%40/SystemDrive" = "C:"

                "./cimv2/MDM_ConfigSetting/MDM_ConfigSetting.SettingName=%22AccountId%22/SettingValue" = "36684b40-1895-4ebf-b11d-b465be552b2f"
                "./cimv2/MDM_ConfigSetting/MDM_ConfigSetting.SettingName3D%22AccountId%22/SettingValue" = "36684b40-1895-4ebf-b11d-b465be552b2f"
                "./cimv2/MDM_ConfigSetting/MDM_ConfigSetting.SettingName=%22ClientHealthStatus%22/SettingValue" = ""
                "./cimv2/MDM_ConfigSetting/MDM_ConfigSetting.SettingName=%22ClientDeploymentErrorCode%22/SettingValue" = ""
                "./cimv2/MDM_ConfigSetting/MDM_ConfigSetting.SettingName=%22ClientHealthLastSyncTime%22/SettingValue" = ""


                "./DevInfo/DevId" = $DeviceName
                "./DevInfo/Man" =   "Microsoft Corporation"
                "./DevInfo/Mod" =   "Virtual Machine"
                "./DevInfo/DmV" =   "1.3"
                "./DevInfo/Lang" =  "en-US"

                "./DevDetail/SwV" =    "10.0.18363.1016"
                "./DevDetail/FwV" =    "Hyper-V UEFI Release v4.0"
                "./DevDetail/HwV" =    "Hyper-V UEFI Release v4.0"
                "./DevDetail/OEM" =    "Microsoft Corporation"
                "./DevDetail/DevTyp" = "Virtual Machine"

                "./DevDetail/Ext/Microsoft/LocalTime" =             "$((Get-Date).ToString("yyyy-MM-ddTHH:mm:ss").Replace(".",":")).$((Get-Date).ToString("fffffffK"))"
                "./DevDetail/Ext/Microsoft/DeviceName" =            $encDeviceName
                "./DevDetail/Ext/Microsoft/DNSComputerName" =       $encDeviceName
                "./DevDetail/Ext/Microsoft/OSPlatform" =            "Windows 10 Enterprise"
                "./DevDetail/Ext/Microsoft/ProcessorArchitecture" = "9"
                "./DevDetail/Ext/Microsoft/ProcessorType" =         "8664"
                "./DevDetail/Ext/Microsoft/TotalRAM" =              "1"
                "./DevDetail/Ext/Microsoft/TotalStorage" =          "1"
                "./DevDetail/Ext/Microsoft/SMBiosSerialNumber" =    "0000-0000-0000-0000-0000-0000-00"
                "./DevDetail/Ext/Microsoft/MobileID" =              "Not Present"

                "./Vendor/MSFT/eUICCs" = "com.microsoft/1.2/MDM/eUICCs"

                "./Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/nonStore" = "Mimikatz"
                "./Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/AppStore" = ""

                "./Vendor/MSFT/NodeCache/MS%20DM%20Server" =              "CacheVersion/Nodes/ChangedNodes/ChangedNodesData"
                "./Vendor/MSFT/NodeCache/MS%20DM%20Server/CacheVersion" = ""
                "./Vendor/MSFT/NodeCache/MS%20DM%20Server/ChangedNodes" = ""

                "./Vendor/MSFT/WindowsLicensing/Edition" =                     "4"
                "./Vendor/MSFT/WindowsLicensing/Status" =                      "3" # Completed
                "./Vendor/MSFT/WindowsLicensing/SMode/Status" =                "0" # Successfully switched out of S mode

                "./Vendor/MSFT/Update/LastSuccessfulScanTime" =                (Get-Date).AddMinutes(-10).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                "./Vendor/MSFT/Update/InstallableUpdates" =                    ""
                "./Vendor/MSFT/Update/PendingRebootUpdates" =                  ""
                 
                "./Vendor/MSFT/DeviceStatus/NetworkIdentifiers" = "000000000000"
                "./Vendor/MSFT/DeviceStatus/NetworkIdentifiers/000000000000/IPAddressV4" =  "192.168.0.2"
                "./Vendor/MSFT/DeviceStatus/NetworkIdentifiers/000000000000/IPAddressV6" =  ""
                "./Vendor/MSFT/DeviceStatus/NetworkIdentifiers/000000000000/IsConnected" =  "true"
                "./Vendor/MSFT/DeviceStatus/NetworkIdentifiers/000000000000/Type" =         "1" # 1=LAN, 2=WLAN

                "./Vendor/MSFT/DeviceStatus/OS/Mode" =                         "0"
                "./Vendor/MSFT/DeviceStatus/OS/Edition" =                      "4"
                "./Vendor/MSFT/DeviceStatus/CellularIdentities" =               "" 
                "./Vendor/MSFT/DeviceStatus/Compliance/EncryptionCompliance" = "true"

                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/UsePassportForWork" =              "true"
                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/RequireSecurityDevice" =           "true"
                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/PINComplexity/MinimumPINLength" =  "6"
                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/PINComplexity/MaximumPINLength" =  "127"
                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/PINComplexity/UppercaseLetters" =  "1" # 0=allowed, 1=required, 2=not allowed
                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/PINComplexity/LowercaseLetters" =  "1" # 0=allowed, 1=required, 2=not allowed
                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/PINComplexity/SpecialCharacters" = "1" # 0=allowed, 1=required, 2=not allowed
                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/PINComplexity/Digits" =            "1" # 0=allowed, 1=required, 2=not allowed
                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/PINComplexity/History" =           "1" # 0=allowed, 1=required, 2=not allowed
                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/PINComplexity/Expiration" =        "50" # 0-50
                "./Vendor/MSFT/PassportForWork/$tenantId/Policies/Remote/UseRemotePassport" =        "false"

                "./Vendor/MSFT/PassportForWork/Biometrics/UseBiometrics" = "true"
                "./Vendor/MSFT/PassportForWork/Biometrics/FacialFeaturesUseEnhancedAntiSpoofing" = "true"





                "./Vendor/MSFT/DeviceStatus/TPM/SpecificationVersion" = "2.0"

                "./Vendor/MSFT/DeviceStatus/DomainName" = ""

                "./Vendor/MSFT/DeviceStatus/DeviceGuard/LsaCfgCredGuardStatus" =             "0" # Running
                "./Vendor/MSFT/DeviceStatus/DeviceGuard/VirtualizationBasedSecurityHwReq" =  "0" # System meets hardware configuration requirements
                "./Vendor/MSFT/DeviceStatus/DeviceGuard/VirtualizationBasedSecurityStatus" = "0" # Running

                "./Vendor/MSFT/DeviceStatus/Battery/EstimatedRuntime" =         "-1" # AC connected
                "./Vendor/MSFT/DeviceStatus/Battery/EstimatedChargeRemaining" = "-1" # AC

                "./Vendor/MSFT/DeviceInstanceService/PhoneNumber" = "1234567890"

                "./Vendor/MSFT/Defender/Detections" = ""

                "./Vendor/MSFT/Defender/Health" =                              "ProductStatus/ComputerState/DefenderEnabled/RtpEnabled/NisEnabled/QuickScanOverdue/FullScanOverdue/SignatureOutOfDate/RebootRequired/FullScanRequired/EngineVersion/SignatureVersion/DefenderVersion/QuickScanTime/FullScanTime/QuickScanSigVersion/FullScanSigVersion/TamperProtectionEnabled/IsVirtualMachine"
                "./Vendor/MSFT/Defender/Health/ProductStatus" =                "0"
                "./Vendor/MSFT/Defender/Health/ComputerState" =                "0"
                "./Vendor/MSFT/Defender/Health/TamperProtectionEnabled" =      "true"
                "./Vendor/MSFT/Defender/Health/DefenderEnabled" =              "true"
                "./Vendor/MSFT/Defender/Health/RtpEnabled" =                   "true"
                "./Vendor/MSFT/Defender/Health/NisEnabled" =                   "true"
                "./Vendor/MSFT/Defender/Health/QuickScanOverdue" =             "false"
                "./Vendor/MSFT/Defender/Health/FullScanOverdue" =              "false"
                "./Vendor/MSFT/Defender/Health/SignatureOutOfDate" =           "false"
                "./Vendor/MSFT/Defender/Health/RebootRequired" =               "false"
                "./Vendor/MSFT/Defender/Health/FullScanRequired" =             "false"
                "./Vendor/MSFT/Defender/Health/EngineVersion" =                "1.1.17400.5"
                "./Vendor/MSFT/Defender/Health/SignatureVersion" =             "1.323.410.0"
                "./Vendor/MSFT/Defender/Health/DefenderVersion" =              "4.18.2008.9"
                "./Vendor/MSFT/Defender/Health/QuickScanTime" =                (Get-Date).AddHours(-1).ToUniversalTime().ToString("MM/dd/yyyy HH:mm:ss UTC")
                "./Vendor/MSFT/Defender/Health/FullScanTime" =                 (Get-Date).AddHours(-2).ToUniversalTime().ToString("MM/dd/yyyy HH:mm:ss UTC")
                "./Vendor/MSFT/Defender/Health/QuickScanSigVersion" =          "1.321.2151.0"
                "./Vendor/MSFT/Defender/Health/FullScanSigVersion" =           "1.321.2151.0"
                "./Vendor/MSFT/Defender/Health/IsVirtualMachine" =             "true"

                "./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDMID" =       "0"
                "./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDeviceName" = "$encDeviceName mgmt"
                "./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/AADResourceID" = "https://manage.microsoft.com"

                "./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/Poll/IntervalForRemainingScheduledRetries" = "480"
                "./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/Poll/PollOnLogin" =                          "false"

                "./Vendor/MSFT/DMClient/HWDevID" = $hwId

                "./Vendor/MSFT/HealthAttestation/Status" = "3" # DHA-Data is ready for pic up
                "./Vendor/MSFT/Update/FailedUpdates" = ""
                

                "./Vendor/MSFT/Office/Installation/CurrentStatus" = "" # XML of current Office 365 installation status on the device

                "./Device/Vendor/MSFT/DeviceManageability/Capabilities/CSPVersions" = [Security.SecurityElement]::Escape($CSPVersions)
                "./Device/Vendor/MSFT/BitLocker/Status/DeviceEncryptionStatus" = "0" # Compliant

                "./Device/Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/FirstSyncStatus/IsSyncDone" = "true"
                "./Device/Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/FirstSyncStatus/SkipDeviceStatusPage" = "true"
                "./Device/Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/FirstSyncStatus/SkipUserStatusPage" = "true"
                "./Device/Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/FirstSyncStatus/TimeOutUntilSyncFailure" = "60"
                "./Device/Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/FirstSyncStatus/ServerHasFinishedProvisioning" = "true" 
                "./Device/Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/FirstSyncStatus/WasDeviceSuccessfullyProvisioned" = "1" # 0=failure, 1=success, 2=in progress

                
            }

        
        # Initial commands
        $commands = @()
        $commands += New-Object psobject -Property @{"Type" = "Alert"; "Data" = "1201"; CmdID = 1 }
        $commands += New-Object psobject -Property @{"Type" = "Alert"; "Data" = "1224"; CmdID = 2 ; "ItemData"= ($Scope.ToLower()) ; "MetaType"="com.microsoft/MDM/LoginStatus"}
        $attr = [ordered]@{
            Type =  "Replace"
            CmdID = 3 
            Items = @{
                "./DevInfo/DevId" = $DeviceName
                "./DevInfo/Man" =   "Microsoft Corporation"
                "./DevInfo/Mod" =   "Virtual Machine"
                "./DevInfo/DmV" =   "1.3"
                "./DevInfo/Lang" =  "en-US"
            }
        }
        $commands += New-Object psobject -Property $attr

        # Keep looping until no more commands than <Status>
        while($commands.count -ge 1)
        {
            $f=$msgId

            Write-Verbose "=> Sending message   ($f) with $($commands.Count) commands."
            $req = New-SyncMLRequest -commands $commands -DeviceName $encDeviceName -SessionID $sessionId -MsgID ($msgId++)

            # Debug
            if($DebugPreference)
            {
                $req | set-content "req$f.xml"
            }

            $res = Invoke-SyncMLRequest -SyncML $req -Certificate $Certificate
                   
            # Debug
            if($DebugPreference)
            {            
                $res.OuterXml | set-content "res$f.xml"
            }

            $commands = Parse-SyncMLResponse -SyncML $res

            Write-Verbose "   Received response ($f) with $($commands.Count) commands."

            # Response to all with 400 - bad request (except for the things at settings)
            $commands = New-SyncMLAutoresponse -DeviceName $DeviceName -Commands $commands -MsgID $msgId -Settings $settings

        }
        

    }
}

# Remove the device from intune
# Sep 7th
function Remove-DeviceFromIntune
{
<#
    .SYNOPSIS
    Removes (un-enrolls) the given device from Intune.

    .DESCRIPTION
    Removes the given device to from Intune.

    .Parameter Certificate
    x509 certificate of the device.

    .Parameter PfxFileName
    File name of the .pfx certificate of the device.

    .Parameter PfxPassword
    The password of the .pfx certificate of the device.

    .EXAMPLE
    Remove-AADIntAccessDeviceFromIntune -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx 


#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [string]$PfxPassword
    )
    Process
    {
        if(!$Certificate)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        # Get the device id from the certificate
        $deviceId = $Certificate.Subject.Split("=")[1]

        $requestId = (New-Guid).ToString()

        $headers=@{
            "Accept" =                   "application/json1"
            "Accept-Charset" =           "UTF-8"
            "User-Agent" =               "Dsreg/10.0 (Windows 10.0.18363.0)"
            "ocp-adrs-client-name" =     "Dsreg"
            "ocp-adrs-client-version" =  "10.0.18362.0"
            "return-client-request-id" = "true"
            "client-Request-Id" =        $requestId
        }

        try
        {
            Write-Verbose "Removing device $deviceId from Intune. Request Id: $requestId"
            $response = Invoke-WebRequest -UseBasicParsing -Certificate $Certificate -Method Delete -Uri "https://enterpriseregistration.windows.net/EnrollmentServer/device/$($deviceId)?api-version=1.0" -Headers $headers -ErrorAction SilentlyContinue
            Write-Verbose "Device $deviceId removed from Intune."
        }
        catch
        {
            if($_.ErrorDetails.Message)
            {
                throw ($_.ErrorDetails.Message | Convertfrom-Json).message
            }
            else
            {
                throw "Remove failed! $($_.message)"
            }
        }

        return $response
            
    }
}



# Get's device compliance
# Sep 11th 2020
function Get-DeviceCompliance
{
<#
    .SYNOPSIS
    Gets the device compliance status.

    .DESCRIPTION
    Gets the user's device compliance status using AAD Graph API. Does not require admin rights!

    .Parameter AccessToken
    The access token used to set the compliance.

    .Parameter DeviceId
    Azure AD device id of the device.

    .Parameter ObjectId
    Azure AD object id of the device.

    .Parameter All
    Returns all devices.

    .Parameter My
    Returns all user's devices.

    .EXAMPLE
    Get-AADIntAccessTokenForAADGraph -SaveToCache

    PS C\:>Get-AADIntDeviceCompliance -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7"

    displayName     : SixByFour
    objectId        : 2eaa21a1-6362-4d3f-afc4-597592217ef0
    deviceId        : d03994c9-24f8-41ba-a156-1805998d6dc7
    isCompliant     : False
    isManaged       : True
    deviceOwnership : Company

    .EXAMPLE
    Get-AADIntAccessTokenForAADGraph -SaveToCache

    PS C\:>Get-AADIntDeviceCompliance -My | ft

    displayName   objectId                             deviceId                             isCompliant isManaged deviceOwnership deviceTrustType
    -----------   --------                             --------                             ----------- --------- --------------- ---------------
    SixByFour     2eaa21a1-6362-4d3f-afc4-597592217ef0 d03994c9-24f8-41ba-a156-1805998d6dc7       False      True Company         AzureAd
    DESKTOP-X4LCS 8ba68233-4d2b-4331-8b8b-27bc53204d8b c9dcde64-5d0f-4b3c-b711-cb6947837dc2       False      True Company         ServerAd
    SM-1234       c00af9fe-108e-446b-aeee-bf06262973dc 74080692-fb38-4a7b-be25-27d9cbf95705                       Personal        AzureAd
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='DeviceID',Mandatory=$True)]
        [String]$DeviceId,
        [Parameter(ParameterSetName='ObjectID',Mandatory=$True)]
        [String]$ObjectId,
        [Parameter(ParameterSetName='All',Mandatory=$True)]
        [Switch]$All,
        [Parameter(ParameterSetName='My',Mandatory=$True)]
        [Switch]$My
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        $parsedToken = Read-Accesstoken -AccessToken $AccessToken

        $tenantId = $parsedToken.tid

        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Accept" =        "application/json;odata=nometadata"
        }

        
        # Get the object Id if not given
        if(!$All -and !$My -and [string]::IsNullOrEmpty($ObjectId))
        {
            $ObjectId = Get-DeviceObjectId -DeviceId $DeviceId -TenantId $tenantId -AccessToken $AccessToken
        }

        $select="`$select=displayName,objectId,deviceId,isCompliant,isManaged,deviceOwnership,deviceManagementAppId,deviceTrustType"

        if($All)
        {
            $url="https://graph.windows.net/$tenantId/devices?$select&api-version=1.61-internal"
        }
        elseif($My)
        {
            $url="https://graph.windows.net/Me/ownedDevices?$select&api-version=1.61-internal"
        }
        else
        {
            $url="https://graph.windows.net/$tenantId/devices/$($ObjectId)?$select&api-version=1.61-internal"
        }

        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers

        if($response.value)
        {
            return $response.value
        }
        else
        {
            return $response
        }

    }
}




# Set's device compliance
# Sep 11th 2020
function Set-DeviceCompliant
{
<#
    .SYNOPSIS
    Sets the device compliant.

    .DESCRIPTION
    Sets the user's device compliant using AAD Graph API. Does not require admin rights.
    Compliant and managed statuses can be used in conditional access (CA) rules.

    .Parameter AccessToken
    The access token used to set the compliance.

    .Parameter DeviceId
    Azure AD device id of the device.

    .Parameter ObjectId
    Azure AD object id of the device.

    .EXAMPLE
    Get-AADIntAccessTokenForAADGraph -SaveToCache

    PS C\:>Set-AADIntDeviceCompliant -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7"

    displayName     : SixByFour
    objectId        : 2eaa21a1-6362-4d3f-afc4-597592217ef0
    deviceId        : d03994c9-24f8-41ba-a156-1805998d6dc7
    isCompliant     : True
    isManaged       : True
    deviceOwnership : 
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='DeviceID',Mandatory=$True)]
        [String]$DeviceId,
        [Parameter(ParameterSetName='ObjectID',Mandatory=$True)]
        [String]$ObjectId,
        [Switch]$Compliant,
        [Switch]$Managed,
        [Switch]$Intune
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        $parsedToken = Read-Accesstoken -AccessToken $AccessToken

        $tenantId = $parsedToken.tid

        $body=@{}

        if($Compliant) {$body["isCompliant"] = "true"}
        if($Managed)   {$body["isManaged"] =   "true"}
        if($Intune)    {$body["deviceManagementAppId"] = "0000000a-0000-0000-c000-000000000000"}


        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        # Get the object Id if not given
        if([string]::IsNullOrEmpty($ObjectId))
        {
            $ObjectId = Get-DeviceObjectId -DeviceId $DeviceId -TenantId $tenantId -AccessToken $AccessToken
        }

        # Set the device compliance
        Invoke-RestMethod -Method Patch -Uri "https://graph.windows.net/$tenantId/devices/$ObjectId`?api-version=1.61-internal" -Headers $headers -Body ($body|ConvertTo-Json) -ContentType "application/json"

        Get-DeviceCompliance -ObjectId $ObjectId -AccessToken $AccessToken

    }
}

