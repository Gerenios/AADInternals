# This file contains functions for local AAD Joined devices

# Exports the device certificate of the local device
# Dec 17th 2021
function Export-LocalDeviceCertificate
{
<#
    .SYNOPSIS
    Exports the device certificate and private key of the local AAD joined/registered device.

    .DESCRIPTION
    Exports the device certificate and private key of the local AAD joined/registered device.
    Certificate filename:      <deviceid>.pfx
    Private key filename:      <deviceid>.pem

    .Example
    PS C\:>Export-AADIntLocalDeviceCertificate

    Certificate exported to   f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx
#>
    [CmdletBinding()]
    param()
    Process
    {
        # Check whether we are running in elevated session
        Test-LocalAdministrator -Warn | Out-Null

        # Get the join info
        if(($joinInfo = Get-LocalDeviceJoinInfo) -eq $null)
        {
            Throw "Device seems not to be joined or registered."
        }

        # Get the certificate
        Write-Verbose "Getting certificate $($joinInfo.CertThumb)"
        $certificate = Get-Item -Path $joinInfo.CertPath
        $binCert     = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)

        # Get the private key
        Write-Verbose "Device key name: $($joinInfo.KeyName)"

        if($joinInfo.JoinType -eq "Joined")
        {
            $keyPath = "$env:ALLUSERSPROFILE"
        }
        else
        {
            Write-Warning "Accessing key in user context will FAIL if already elevated to LOCAL SYSTEM."
            $keyPath = "$env:APPDATA"
        }

        # CryptoAPI and CNG stores keys in different directories
        # https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval
        $paths = @(
            "$keyPath\Microsoft\Crypto\RSA\MachineKeys\$($joinInfo.KeyName)"
            "$keyPath\Microsoft\Crypto\Keys\$($joinInfo.KeyName)"
            )
        foreach($path in $paths)
        {
            $keyBlob = Get-BinaryContent $path -ErrorAction SilentlyContinue
            if($keyBlob)
            {
                Write-Verbose "Key loaded from $path"
                break
            }
        }

        if(!$keyBlob)
        {
            if($joinInfo.KeyName.EndsWith(".PCPKEY"))
            {
                # This machine has a TPM
                Throw "PCP keys are not supported, unable to export private key!"
            }
            else
            {
                Throw "Error accessing key. If you are already elevated to LOCAL SYSTEM, restart PowerShell and try again."
            }
            return
        }
        
        # Parse the key blob
        $blobType = [System.BitConverter]::ToInt32($keyBlob,0)
        switch($blobType)
        {
            1 { $deviceKey = Parse-CngBlob  -Data $keyBlob -Decrypt }
            2 { $deviceKey = Parse-CapiBlob -Data $keyBlob -Decrypt }
            default { throw "Unsupported key blob type" }
        }

        $fileName = "$($joinInfo.deviceId).pfx"
        Set-BinaryContent -Path $fileName -Value (New-PfxFile -RSAParameters $deviceKey.RSAParameters -X509Certificate $binCert)
        Write-Host "Device certificate exported to $fileName"
    }
}

# Exports the transport key of the local device
# Dec 18th 2021
function Export-LocalDeviceTransportKey
{
<#
    .SYNOPSIS
    Exports the transport key of the local AAD joined/registered device.

    .DESCRIPTION
    Exports the transport key of the local AAD joined/registered device. 
    Filename:                  <deviceid>_tk.pem

    .Example
    PS C\:>Export-AADIntLocalDeviceTransportKey

    Transport key exported to f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem
#>
    [CmdletBinding()]
    param()
    Process
    {
        # Check whether we are running in elevated session
        Test-LocalAdministrator -Warn | Out-Null

        # Get the join info
        if(($joinInfo = Get-LocalDeviceJoinInfo) -eq $null)
        {
            Throw "Device seems not to be joined or registered."
        }

        # Get the private key
        Write-Verbose "Getting transport key"
        $transportKeys = Get-LocalDeviceTransportKeys -JoinType $joinInfo.JoinType -IdpDomain $joinInfo.idpDomain -TenantId $joinInfo.tenantId -UserEmail $joinInfo.UserEmail

        $fileName = "$($joinInfo.deviceId)_tk.pem"
        Set-Content $fileName -Value (Convert-RSAToPEM -RSAParameters $transportKeys.RSAParameters)
        Write-Host "Transport key exported to $fileName"

    }
}

# Joins the local device to Azure AD
# Dec 20th 2021
function Join-LocalDeviceToAzureAD
{
<#
    .SYNOPSIS
    Joins the local Windows device to Azure AD using the given certificate.

    .DESCRIPTION
    Joins the local Windows device to Azure AD using the given certificate created earlier with AADInternals.

    Creates required registry keys and values, saves transport key to SystemKeys, and starts related scheduled tasks.
    
    .Parameter OSVersion
    The operating system version of the device. Defaults to "10.0.18363.0"

    .Parameter PfxFileName
    File name of the .pfx device certificate.

    .Parameter PfxPassword
    The password of the .pfx device certificate.

    .Parameter TransportKeyFileName
    File name of the transportkey

    .Parameter UserPrincipalName
    The user principal name of the user.

    .EXAMPLE
    PS\:>Export-AADIntLocalDeviceCertificate

    Certificate exported to   f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx

    PS C\:>Export-AADIntLocalDeviceTransportKey

    Transport key exported to f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem

    PS\:>Join-AADIntLocalDeviceToAzureAD -UserPrincipalName JohnD@company.com -PfxFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx -TransportKeyFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem

    Device configured. To confirm success, restart and run: dsregcmd /status

    .EXAMPLE
    $token = Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS\:>Join-AADIntDeviceToAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"

    Device successfully registered to Azure AD:
      DisplayName:     "My computer"
      DeviceId:        d03994c9-24f8-41ba-a156-1805998d6dc7
      Cert thumbprint: 78CC77315A100089CF794EE49670552485DE3689
      Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
    Local SID:
      S-1-5-32-544
    Additional SIDs:
      S-1-12-1-797902961-1250002609-2090226073-616445738
      S-1-12-1-3408697635-1121971140-3092833713-2344201430
      S-1-12-1-2007802275-1256657308-2098244751-2635987013

    PS\:>Join-AADIntLocalDeviceToAzureAD -UserPrincipalName JohnD@company.com -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx

    Device configured. To confirm success, restart and run: dsregcmd /status

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$UserPrincipalName,
        [Parameter(Mandatory=$True)]
        [String]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [String]$TransportKeyFileName,
        [Parameter(Mandatory=$False)]
        [String]$OSVersion = "10.0.19044.1288"
    )
    Begin
    {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $WAM_AAD = "B16898C6-A148-4967-9171-64D755DA8520"
        $WAM_MSA = "D7F9888F-E3FC-49b0-9EA6-A85B5F392A4F"
    }
    Process
    {
        # Check whether we are running in elevated session
        Test-LocalAdministrator -Throw | Out-Null

        # Import the certificate to LocalMachine's Personal store
        if($PfxPassword)
        {
            $certificate = Import-PfxCertificate -FilePath $PfxFileName -Password ($PfxPassword | ConvertTo-SecureString -AsPlainText -Force) -CertStoreLocation Cert:\LocalMachine\My -Exportable
        }
        else
        {
            $certificate = Import-PfxCertificate -FilePath $PfxFileName -CertStoreLocation Cert:\LocalMachine\My -Exportable
        }
        Write-Verbose "Certificate ($($certificate.Subject)) imported to CERT:\LocalMachine\My\$($certificate.Thumbprint)"
        
        # Collect the required information
        $thumbprint = $certificate.Thumbprint
        $oids = Parse-CertificateOIDs -Certificate $certificate
        $tenantId = $oids.TenantId
        $deviceId = $oids.DeviceId

        Write-Verbose "Thumbprint:       $thumbprint"
        Write-Verbose "Device ID:        $deviceId"
        Write-Verbose "Tenant ID:        $tenantId"
        Write-Verbose "Auth User Obj ID: $($oids.AuthUserObjectId)"
        Write-Verbose "Region:           $($oids.Region)"
        Write-Verbose "Join Type:        $($oids.JoinType)"

        if($oids.JoinType -eq 0)
        {
            # Certificates for AAD Registered devices won't work :(
            Remove-Item $certificate -Force
            Throw "Unable to join: Provided certificate is for AAD Registered device."
        }

        # Generate P2P cert and CA & import to correct stores
        Write-Verbose "Generating P2P certificate & CA"
        New-P2PDeviceCertificate -PfxFileName $PfxFileName -TenantId $tenantId -DeviceName (Get-ComputerName) 

        $P2P = Import-PfxCertificate -FilePath ".\$($deviceId)-P2P.pfx" -CertStoreLocation "Cert:\LocalMachine\My" -Exportable
        Write-Verbose "Certificate ($($P2P.Subject)) imported to CERT:\LocalMachine\My\$($P2P.Thumbprint)"

        if(-not (Test-Path "Cert:\LocalMachine\AAD Token Issuer"))
        {
            New-Item -Path "Cert:\LocalMachine" -Name "AAD Token Issuer" -ItemType "directory" -Force 
        }

        $P2PCA = Import-Certificate -FilePath ".\$($deviceId)-P2P-CA.der" -CertStoreLocation "Cert:\LocalMachine\AAD Token Issuer"
        Write-Verbose "Certificate ($($P2PCA.Subject)) imported to CERT:\LocalMachine\AAD Token Issuer\$($P2PCA.Thumbprint)"

        # Generate the transport key using device id as name
        if($TransportKeyFileName)
        {
            # Use the provided tkpriv
            $tkPEM = (Get-Content $TransportKeyFileName) -join "`n"
            $tkParameters = Convert-PEMToRSA -PEM $tkPEM
        }
        else
        {
            # Use dkpriv from the certificate
            $tkParameters = $certificate.PrivateKey.ExportParameters($true)
        }
        $transportKeyName   = $deviceId
        $RSAFULLPRIVATEBLOB = New-KeyBLOB -Parameters $tkParameters -Type RSA3

        $cngParameters=[System.Security.Cryptography.CngKeyCreationParameters]::new()
        $cngParameters.KeyCreationOptions = 0x20 -bor 0x80 # Create machine key | overwrite
        $cngParameters.Parameters.Add([System.Security.Cryptography.CngProperty]::new("Length",[System.BitConverter]::GetBytes(2048),"None"))
        $cngParameters.Parameters.Add([System.Security.Cryptography.CngProperty]::new("RSAFULLPRIVATEBLOB",$RSAFULLPRIVATEBLOB,"None"))
        $cngParameters.ExportPolicy = 0x01 -bor 0x02 # Allow export, allow plaintext export
        $transportKey = [System.Security.Cryptography.CngKey]::Create("RSA",$transportKeyName,$cngParameters)

        Write-Verbose "TransportKey name:      $($transportKey.KeyName)"
        Write-Verbose "TransportKey file name: $($transportKey.UniqueName)"

        # Copy the private key to SystemKeys folder & delete from the current location
        Copy-Item -Path "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys\$($transportKey.UniqueName)" -Destination "$env:ALLUSERSPROFILE\Microsoft\Crypto\SystemKeys" -Force
        Write-Verbose "Transport key stored to $env:ALLUSERSPROFILE\Microsoft\Crypto\SystemKeys\$($transportKey.UniqueName)"
        $transportKey.Delete()

        # Create the registry keys
        $CloudDomainJoinRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin"

        New-Item -Path "$CloudDomainJoinRoot"            -Name "JoinInfo"   -Force | Out-Null
        New-Item -Path "$CloudDomainJoinRoot\JoinInfo"   -Name $thumbprint  -Force | Out-Null
        New-Item -Path "$CloudDomainJoinRoot"            -Name "TenantInfo" -Force | Out-Null
        New-Item -Path "$CloudDomainJoinRoot\TenantInfo" -Name $TenantId    -Force | Out-Null

        # Set join info
        $joinInfo = @{
            "IdpDomain"          = "login.windows.net"
            "TenantId"           = $TenantId
            "UserEmail"          = $UserPrincipalName
            "AttestationLevel"   = 0
            "AikCertStatus"      = 0
            "TransportKeyStatus" = 0
            "DeviceDisplayName"  = Get-ComputerName
            "OsVersion"          = $OSVersion
            "DdidUpToDate"       = 0
            "LastSyncTime"       = [int]((Get-Date).ToUniversalTime()-$epoch).TotalSeconds
        }

        Write-Verbose "Created key $CloudDomainJoinRoot\JoinInfo\$thumbprint"

        foreach($key in $joinInfo.Keys)
        {
            Set-ItemProperty -Path "$CloudDomainJoinRoot\JoinInfo\$thumbprint" -Name $key -Value $joinInfo[$key] | Out-Null
            Write-Verbose "  $key = $($joinInfo[$key])"
            
        }

        # Set tenant info
        $tenantInfo = @{
            "DisplayName"                    = $UserPrincipalName.split("@")[1].Split(".")[0]
            "MdmEnrollmentUrl"               = ""
            "MdmTermsOfUseUrl"               = ""
            "MdmComplianceUrl"               = ""
            "UserSettingSyncUrl"             = ""
            "DrsServiceVersion"              = "1.0"
            "DrsEndpoint"                    = "https://enterpriseregistration.windows.net/EnrollmentServer/DeviceEnrollmentWebService.svc"
            "DrsResourceId"                  = "urn:ms-drs:enterpriseregistration.windows.net"
            "AuthCodeUrl"                    = "https://login.microsoftonline.com/$tenantId/oauth2/authorize"
            "AccessTokenUrl"                 = "https://login.microsoftonline.com/$tenantId/oauth2/token"
            "CdjServiceVersion"              = "2.0"
            "CdjEndpoint"                    = "https://enterpriseregistration.windows.net/EnrollmentServer/device/"
            "CdjResourceId"                  = "urn:ms-drs:enterpriseregistration.windows.net"
            "NgcServiceVersion"              = "1.0"
            "NgcEndpoint"                    = "https://enterpriseregistration.windows.net/EnrollmentServer/key/"
            "NgcResourceId"                  = "urn:ms-drs:enterpriseregistration.windows.net"
            "WebAuthnServiceVersion"         = "1.0"
            "WebAuthnEndpoint"               = "https://enterpriseregistration.windows.net/webauthn/$tenantId/"
            "WebAuthnResourceId"             = "urn:ms-drs:enterpriseregistration.windows.net"
            "DeviceManagementServiceVersion" = "1.0"
            "DeviceManagementEndpoint"       = "https://enterpriseregistration.windows.net/manage/$tenantId/"
            "DeviceManagementResourceId"     = "urn:ms-drs:enterpriseregistration.windows.net"
            "RbacPolicyEndpoint"             = "https://pas.windows.net"
        }

        Write-Verbose "Created key $CloudDomainJoinRoot\TenantInfo\$tenantId"
        foreach($key in $tenantInfo.Keys)
        {
            Set-ItemProperty -Path "$CloudDomainJoinRoot\TenantInfo\$tenantId" -Name $key -Value $tenantInfo[$key] | Out-Null
            Write-Verbose " $key = $($tenantInfo[$key])"
            
        }

        # Calculate registry key parts for transportkey
        $idp    = Convert-ByteArrayToHex -Bytes ($sha256.ComputeHash([text.encoding]::Unicode.GetBytes("login.windows.net")))
        $tenant = Convert-ByteArrayToHex -Bytes ($sha256.ComputeHash([text.encoding]::Unicode.GetBytes($TenantId)))

        # Set the transport key name
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey\PerDeviceKeyTransportKey" -Name ""  -Force | Out-Null
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey\PerDeviceKeyTransportKey\$idp" -Name $tenant  -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey\PerDeviceKeyTransportKey\$idp\$tenant" -Name "SoftwareKeyTransportKeyName" -Value $transportKeyName -Force | Out-Null

        Write-Verbose "Transport key set: HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey\PerDeviceKeyTransportKey\$idp\$tenant\SoftwareKeyTransportKeyName = $transportKeyName"

        # Set some registry values
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\LoadParameters\{$WAM_AAD}" -Name "LoginUri" -Value "https://login.microsoftonline.com" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\LoadParameters\{$WAM_AAD}" -Name "Enabled" -Value 1 | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicy" -Name "AutopilotMode" -Value 0 -Force | Out-Null

        # Restart Software Protection Platform 
        Start-ScheduledTask  -TaskPath "\Microsoft\Windows\SoftwareProtectionPlatform\" -TaskName "SvcRestartTask"
        Write-Verbose "Restarted Software Protection Platform task."

        # Enable and start AAD Device-Sync
        Enable-ScheduledTask -TaskPath "\Microsoft\Windows\Workplace Join\" -TaskName "Device-Sync" | Out-Null
        Start-ScheduledTask  -TaskPath "\Microsoft\Windows\Workplace Join\" -TaskName "Device-Sync"
        Write-Verbose "Enabled and started Device-Sync task."

        # Run  RegisterDeviceProtectionStateChanged
        Start-ScheduledTask  -TaskPath "\Microsoft\Windows\DeviceDirectoryClient\" -TaskName "RegisterDeviceProtectionStateChanged"
        Write-Verbose "Ran RegisterDeviceProtectionStateChanged task."

        Write-Host "Device configured. To confirm success, restart and run: dsregcmd /status"
    }
    End
    {
        $sha256.Dispose()
    }
}

# Gets the join info of the local device
# Dec 23rd 2021
function Get-LocalDeviceJoinInfo
{
<#
    .SYNOPSIS
    Shows the Azure AD Join information of the local device.

    .DESCRIPTION
    Shows the Azure AD Join information of the local device.

    .Example
    PS C\:>Get-AADIntLocalDeviceJoinInfo

    JoinType           : Joined
    RegistryRoot       : HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin
    CertThumb          : CEC55C2566633AC8DA3D9E3EAD98A599084D0C4C
    CertPath           : Cert:\LocalMachine\My\CEC55C2566633AC8DA3D9E3EAD98A599084D0C4C
    TenantId           : afdb4be1-057f-4dc1-98a9-327ffa079cca
    DeviceId           : f4a4ea70-b196-4305-9531-018c3bcfc112
    AuthUserObjectId   : d625e2e9-8465-4513-b6c9-8d34a3735d41
    KeyName            : 8bff0b7f02f6256b521de95a77d4e70d_934bc9f7-04ef-43d8-a343-610b736a4030
    KeyFriendlyName    : Device Identity Key
    IdpDomain          : login.windows.net
    UserEmail          : JohnD@company.com
    AttestationLevel   : 0
    AikCertStatus      : 0
    TransportKeyStatus : 0
    DeviceDisplayName  : WIN-JohnD
    OsVersion          : 10.0.19044.1288
    DdidUpToDate       : 0
    LastSyncTime       : 1643370347

    .Example
    PS C\:>Get-AADIntLocalDeviceJoinInfo
    WARNING: This device has a TPM, exporting keys probably does not work!

    JoinType           : Joined
    RegistryRoot       : HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin
    CertThumb          : FFDABA36622C66F1F9104703D77603AE1964E92B
    CertPath           : Cert:\LocalMachine\My\FFDABA36622C66F1F9104703D77603AE1964E92B
    TenantId           : afdb4be1-057f-4dc1-98a9-327ffa079cca
    DeviceId           : e4c56ee8-419a-4421-bff4-1d3cb1c85ead
    AuthUserObjectId   : b62a31e9-8268-485f-aba8-69696cdf3048
    KeyName            : C:\ProgramData\Microsoft\Crypto\PCPKSP\[redacted]\[redacted].PCPKEY
    KeyFriendlyName    : Device Identity Key
    IdpDomain          : login.windows.net
    UserEmail          : package_c1b50acc-82f6-4a19-ba87-e62e5f7fbeee@company.com
    AttestationLevel   : 0
    AikCertStatus      : 0
    TransportKeyStatus : 3
    DeviceDisplayName  : cloudpc-80153
    OsVersion          : 10.0.19044.1469
    DdidUpToDate       : 0
    LastSyncTime       : 1643622945
#>
    [CmdletBinding()]
    param()
    Process
    {
        $AADJoinRoot       = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin"
        $AADRegisteredRoot = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin"

        # Check the join type and construct return value
        if(Test-Path -Path "$AADJoinRoot\JoinInfo")
        {
            $joinRoot = $AADJoinRoot
            $certRoot = "LocalMachine"
            $attributes = [ordered]@{
                "JoinType"     = "Joined"
                "RegistryRoot" = $AADJoinRoot
            }
        }
        elseif(Test-Path -Path "$AADRegisteredRoot\JoinInfo")
        {
            $joinRoot = $AADRegisteredRoot
            $certRoot = "CurrentUser"
            $attributes = [ordered]@{
                "JoinType"     = "Registered"
                "RegistryRoot" = $AADRegisteredRoot
            }
        }
        else
        {
            return $null
        }
        
        # Get the Device certificate thumbnail from registery (assuming the device can only be joined once)
        $regItem = (Get-ChildItem -Path "$joinRoot\JoinInfo\").Name
        $certThumbnail = $regItem.Substring($regItem.LastIndexOf("\")+1)
        $certificate   = Get-Item -Path "Cert:\$certRoot\My\$certThumbnail"

        $oids = Parse-CertificateOIDs -Certificate $certificate

        $attributes["CertThumb"       ] = "$certThumbnail"
        $attributes["CertPath"        ] = "Cert:\$certRoot\My\$certThumbnail"
        $attributes["TenantId"        ] = $oids.TenantId
        $attributes["DeviceId"        ] = $oids.DeviceId
        $attributes["AuthUserObjectId"] = $oids.AuthUserObjectId

        # This will fail for DeviceTransportKey because running as Local System
        try
        {
            $attributes["KeyName"        ] = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate).key.uniquename
            $attributes["KeyFriendlyName"] = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate).key.uipolicy.FriendlyName
        }
        catch
        {
            # Okay
        }

        # Read the join info
        $regItem = Get-Item -Path "$joinRoot\JoinInfo\$certThumbnail"
        $valueNames = $regItem.GetValueNames()
        foreach($name in $valueNames)
        {
            $attributes[$name] = $regItem.GetValue($name)
        }

        # Check the TPM
        if($attributes["TransportKeyStatus"] -eq 3)
        {
            Write-Warning "Transport key stored to TPM, exporting not possible!"
        }

        return New-Object psobject -Property $attributes
    }
}