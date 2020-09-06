# This file contains functions for Intune MDM

# Enroll device to Intune MDM
# Aug 29th
function Join-DeviceToIntune
{
<#
    .SYNOPSIS
    Registers (enrolls) the given device to Azure AD.

    .DESCRIPTION
    Enrolls the given device to Azure AD and generates a corresponding certificate.

    After enrollment, the device is in compliant state, which allows bypassing conditional access (CA) restrictions based on the compliance.

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

        $joinInfo = Enroll-DeviceToMDM -AccessToken $AccessToken -DeviceName $DeviceName

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
        [string]$DeviceName
    )
    Process
    {
        if(!$Certificate)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        # Initialise some variables
        $sessionId = 1 #Get-Random -Minimum 1 -Maximum 256 # Stays the same for the whole "conversation"
        $msgId =     1 # Increased by one per message
        
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
      
        # The default settings
        $settings = @{
                "./DevInfo/DevId" = $DeviceName
                "./DevInfo/Man" =   "Microsoft Corporation"
                "./DevInfo/Mod" =   "Virtual Machine"
                "./DevInfo/DmV" =   "1.3"
                "./DevInfo/Lang" =  "en-US"

                "./DevDetail/SwV" =    "10.0.18363.1016"
                "./DevDetail/OEM" =    "Microsoft"
                "./DevDetail/DevTyp" = "Virtual Machine"

                "./DevDetail/Ext/Microsoft/LocalTime" =             "$((Get-Date).ToString("yyyy-MM-ddTHH:mm:ss").Replace(".",":")).$((Get-Date).ToString("fffffffK"))"
                "./DevDetail/Ext/Microsoft/DeviceName" =            $DeviceName
                "./DevDetail/Ext/Microsoft/DNSComputerName" =       $DeviceName
                "./DevDetail/Ext/Microsoft/OSPlatform" =            "Windows 10 Enterprise"
                "./DevDetail/Ext/Microsoft/ProcessorArchitecture" = "9"
                "./DevDetail/Ext/Microsoft/ProcessorType" =         "8664"
                "./DevDetail/Ext/Microsoft/TotalRAM" =              "1"
                "./DevDetail/Ext/Microsoft/TotalStorage" =          "1"


                "./Vendor/MSFT/WindowsLicensing/Edition" =                     "4"
                "./Vendor/MSFT/Update/LastSuccessfulScanTime" =                (Get-Date).AddMinutes(-10).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                "./Vendor/MSFT/DeviceStatus/OS/Mode" =                         "0"
                "./Vendor/MSFT/DeviceStatus/OS/Edition" =                      "4"
                "./Vendor/MSFT/DeviceStatus/Compliance/EncryptionCompliance" = "true"
                "./Vendor/MSFT/Defender/Health/TamperProtectionEnabled" =      "true"

                "./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDMID" =       "0"
                "./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDeviceName" = "$DeviceName mgmt"

                "./Device/Vendor/MSFT/DeviceManageability/Capabilities/CSPVersions" = [Security.SecurityElement]::Escape($CSPVersions)
            }

        
        # Initial commands
        $commands = @()
        $commands += New-Object psobject -Property @{"Type" = "Alert"; "Data" = "1201"; CmdID = 1 }
        $attr = [ordered]@{
            Type =  "Replace"
            CmdID = 2 
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
            $req = New-SyncMLRequest -commands $commands -DeviceName $DeviceName -SessionID $sessionId -MsgID ($msgId++)

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

