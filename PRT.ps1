# This file contains functions for Persistent Refresh Token and related device operations

# Creates a new PRT token
# Aug 26th 2020
function New-UserPRTToken
{
<#
    .SYNOPSIS
    Creates a new PRT JWT token.

    .DESCRIPTION
    Creates a new Primary Refresh Token (PRT) as JWT to be used to sign-in as the user.

    .Parameter RefreshToken
    Primary Refresh Token (PRT) or the user.

    .Parameter SessionKey
    The session key of the user

    .Parameter Context
    The context used = B64 encoded byte array (size 24)

    .Parameter Settings
    PSObject containing refresh_token and session_key attributes.

    .Parameter Nonce
    Nonce to be added to the token.

    .Parameter GetNonce
    Get nonce automatically by connecting to Azure AD.

    .EXAMPLE
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS C:\>Join-AADIntAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"

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

    PS C:\>$creds = Get-Credential

    PS C:\>$prtKeys = Get-UserAADIntPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -Credentials $cred

    PS C:\>$prtToken = New-AADIntUserPRTToken -RefreshToken $prtKeys.refresh_token -SessionKey $prtKeys.session_key -GetNonce

    PS C:\>$at = Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken

    .EXAMPLE
    PS C:\>New-AADIntUserPRTToken -RefreshToken "AQABAAAAAAAGV_bv21oQQ4ROqh0_1-tAHenMcJD..." -SessionKey "O1g9LD9+jiE5yFulMcIeCPZrttzfEHyIPtF5X17cA5+=" 

    eyJhbGciOiJIUzI1NiIsICJjdHgiOiJBQUFBQUFBQUFBQUF...

    .EXAMPLE
    PS C:\>New-AADIntUserPRTToken -Settings $prtKeys -GetNonce

    eyJhbGciOiJIUzI1NiIsICJjdHgiOiJBQUFBQUFBQUFBQUF...
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='TokenAndKey',Mandatory=$True)]
        [String]$RefreshToken,
        [Parameter(ParameterSetName='TokenAndKey',Mandatory=$True)]
        [String]$SessionKey,
        [Parameter(Mandatory=$False)]
        [String]$Context,
        [Parameter(Mandatory=$False)]
        [String]$Nonce,
        [Parameter(ParameterSetName='Settings',Mandatory=$True)]
        $Settings,
        [switch]$GetNonce,
        [bool]$KdfV2 = $true
    )
    Process
    {
        if($Settings)
        {
            if([string]::IsNullOrEmpty($Settings.refresh_token) -or [string]::IsNullOrEmpty($Settings.session_key))
            {
                throw "refresh_token and/or session_key missing!"
            }
            $RefreshToken = $Settings.refresh_token
            $SessionKey =   $Settings.session_key
        }

        if(!$Context)
        {
            # Create a random context
            $ctx = New-Object byte[] 24
            ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($ctx)
        }
        else
        {
            $ctx = Convert-B64ToByteArray -B64 $Context
        }
        
        $sKey = Convert-B64ToByteArray -B64 $SessionKey
        $iat = [int]((Get-Date).ToUniversalTime() - $epoch).TotalSeconds

        # Create the header and body
        $hdr = [ordered]@{
            "alg" = "HS256"
            "typ" = "JWT"
            "ctx" = (Convert-ByteArrayToB64 -Bytes $ctx)
        }

        $pld = [ordered]@{
            "refresh_token" = $RefreshToken
            "is_primary" =    "true"
            "iat" =           $iat
        }

        # Derive the key from session key and context
        if($KdfV2)
        {
            $hdr["kdf_ver"] = 2
            $derivedContext = Get-KDFv2Context -Context $ctx -Payload $pld
        }
        else
        {
            $derivedContext = $ctx
        }

        $key = Get-PRTDerivedKey -Context $derivedContext -SessionKey $sKey

        # Fetch the nonce if not provided
        if([string]::IsNullOrEmpty($Nonce))
        {
            $Nonce = (Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token" -Body "grant_type=srv_challenge").Nonce
        }
        $pld["request_nonce"] = $Nonce
        

        # As the payload may have changed due to nonce, derive the key again if needed
        if($KdfV2)
        {
            $derivedContext = Get-KDFv2Context -Context $ctx -Payload $pld
            $key = Get-PRTDerivedKey -Context $derivedContext -SessionKey $sKey
        }

        # Create the JWT
        $jwt = New-JWT -Key $key -Header $hdr -Payload $pld

        # Return
        return $jwt
    }
}

# Register the device to Azure AD
# Aug 20th 2020
function Join-DeviceToAzureAD
{
<#
    .SYNOPSIS
    Emulates Azure AD Join or Azure AD Hybrid Join by registering the given device to Azure AD.

    .DESCRIPTION
    Emulates Azure AD Join or Azure AD Hybrid Join by registering the given device to Azure AD and generates a corresponding certificate.

    You may use any name, type or OS version you like. 
    
    For Hybrid Join, the SID, tenant ID, and the certificate of the existing synced device must be provided - no access token needed.

    The generated certificate can be used to create a Primary Refresh Token and P2P certificates. The certificate has no password.

    .Parameter AccessToken
    The access token used to join the device. To get MFA claim to PRT, the access token needs to be get using MFA.
    If not given, will be prompted.

    .Parameter DeviceName
    The name of the device to be registered.

    .Parameter DeviceType
    The type of the device to be registered. Defaults to "Windows"

    .Parameter OSVersion
    The operating system version of the device to be registered. Defaults to "10.0.18363.0"

    .Parameter Certificate
    x509 device's user certificate.

    .Parameter PfxFileName
    File name of the .pfx device certificate.

    .Parameter PfxPassword
    The password of the .pfx device certificate.

    .Parameter DomainControllerName
    The fqdn of the domain controller from where the device information is "fetched". Defaults to "dc.aadinternals.com"

    .Parameter DomainName
    The domain name of the target Azure AD tenant. Defaults to "dc.aadinternals.com"

    .Parameter TenantId
    The tenant id of the target Azure AD tenant where the hybrid join device exists.

    .Parameter SID
    The SID of the device. Must be a valid SID and match the SID of the existing AAD device object.

    .Parameter JoinType
    The join type "Join" or "Register". Defaults to Join.

    .EXAMPLE
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS\:>Join-AADIntDeviceToAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"

    Device successfully registered to Azure AD:
      DisplayName:      "My computer"
      DeviceId:         d03994c9-24f8-41ba-a156-1805998d6dc7
      AuthUserObjectId: afdeac87-b32a-41a0-95ad-0a555a91f0a4
      TenantId:         8aeb6b82-6cc7-4e33-becd-97566b330f5b
      Cert thumbprint:  78CC77315A100089CF794EE49670552485DE3689
      Cert file name :  "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
    Local SID:
      S-1-5-32-544
    Additional SIDs:
      S-1-12-1-797902961-1250002609-2090226073-616445738
      S-1-12-1-3408697635-1121971140-3092833713-2344201430
      S-1-12-1-2007802275-1256657308-2098244751-2635987013

    .EXAMPLE
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS\:>Join-AADIntDeviceToAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64" -JoinType Register

    Device successfully registered to Azure AD:
      DisplayName:      "My computer"
      DeviceId:         d03994c9-24f8-41ba-a156-1805998d6dc7
      AuthUserObjectId: afdeac87-b32a-41a0-95ad-0a555a91f0a4
      TenantId:         8aeb6b82-6cc7-4e33-becd-97566b330f5b
      Cert thumbprint:  78CC77315A100089CF794EE49670552485DE3689
      Cert file name :  "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
    Local SID:
      S-1-5-32-544
    Additional SIDs:
      S-1-12-1-797902961-1250002609-2090226073-616445738
      S-1-12-1-3408697635-1121971140-3092833713-2344201430
      S-1-12-1-2007802275-1256657308-2098244751-2635987013

    .EXAMPLE
    PS C\:>Join-AADIntDeviceToAzureAD -DeviceName "My computer" -SID "S-1-5-21-685966194-1071688910-211446493-3729" -PfxFileName .\f24f116f-6e80-425d-8236-09803da7dfbe-user.pfx -TenantId 40cb9912-555c-42b8-80e9-3b3ad50dda8a

    Device successfully registered to Azure AD:
      DisplayName:      "My computer"
      DeviceId:         f24f116f-6e80-425d-8236-09803da7dfbe
      AuthUserObjectId: afdeac87-b32a-41a0-95ad-0a555a91f0a4
      TenantId:         8aeb6b82-6cc7-4e33-becd-97566b330f5b
      Cert thumbprint:  A531B73CFBAB2BA26694BA2AD31113211CC2174A
      Cert file name :  "f24f116f-6e80-425d-8236-09803da7dfbe.pfx"

#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName="Hybrid",     Mandatory=$True)]
        [String]$PfxFileName,
        [Parameter(ParameterSetName="Hybrid",     Mandatory=$False)]
        [String]$PfxPassword,
        [Parameter(ParameterSetName="HybridCert", Mandatory=$True)]
        [Parameter(ParameterSetName="Hybrid",     Mandatory=$True)]
        [String]$SID,
        [Parameter(ParameterSetName="HybridCert", Mandatory=$True)]
        [Parameter(ParameterSetName="Hybrid",     Mandatory=$True)]
        [GUID]$TenantId,
        [Parameter(ParameterSetName="HybridCert", Mandatory=$False)]
        [Parameter(ParameterSetName="Hybrid",     Mandatory=$False)]
        [Parameter(ParameterSetName="Normal",     Mandatory=$False)]
        [String]$DomainName,
        [Parameter(ParameterSetName="HybridCert", Mandatory=$False)]
        [Parameter(ParameterSetName="Hybrid",     Mandatory=$False)]
        [String]$DomainControllerName="dc.aadinternals.com",

        [Parameter(ParameterSetName="HybridCert", Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName="Normal",     Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName="Normal",     Mandatory=$False)]
        [ValidateSet('Join','Register')]
        [String]$JoinType="Join",
        [Parameter(ParameterSetName="Normal",     Mandatory=$True)]
        [Parameter(ParameterSetName="Hybrid",     Mandatory=$True)]
        [Parameter(ParameterSetName="HybridCert", Mandatory=$True)]
        [String]$DeviceName,
        [Parameter(ParameterSetName="Normal",     Mandatory=$False)]
        [Parameter(ParameterSetName="Hybrid",     Mandatory=$False)]
        [Parameter(ParameterSetName="HybridCert", Mandatory=$False)]
        [String]$DeviceType="Windows",
        [Parameter(ParameterSetName="Normal",     Mandatory=$False)]
        [Parameter(ParameterSetName="Hybrid",     Mandatory=$False)]
        [Parameter(ParameterSetName="HybridCert", Mandatory=$False)]
        [String]$OSVersion="10.0.19041.804"
    )
    Process
    {
        
        if(!$TenantId)
        {
            # Get from cache if not provided
            try
            {
                # Try first with access token retrieved with BPRT
                $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "b90d5b8f-5503-4153-b545-b31cecfaece2" -Resource "urn:ms-drs:enterpriseregistration.windows.net"
            }
            catch
            {
                $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"
            }

            # Get the domain and tenant id
            $tenantId = (Read-Accesstoken -AccessToken $AccessToken).tid
        }

        # Load the Certificate for Hybrid Join if not provided
        if($PfxFileName)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        # Register the Device
        $DeviceCertResponse = Register-DeviceToAzureAD -AccessToken $AccessToken -DeviceName $DeviceName -DeviceType $DeviceType -OSVersion $OSVersion -Certificate $Certificate -DomainController $DomainControllerName -SID $SID -TenantId $TenantId -DomainName $DomainName -RegisterOnly ($JoinType -eq "Register")

        if(!$DeviceCertResponse)
        {
            # Something went wrong :(
            return
        }

        [System.Security.Cryptography.X509Certificates.X509Certificate2]$deviceCert = $DeviceCertResponse[0]
        $regResponse = $DeviceCertResponse[1]

        # Parse certificate information
        $oids = Parse-CertificateOIDs -Certificate $deviceCert
        $deviceId = $oids.DeviceId.ToString()
        $tenantId = $oids.TenantId.ToString()
        $authUserObjectId = $oids.AuthUserObjectId.ToString()

        # Write the device certificate to disk
        Set-BinaryContent -Path "$deviceId.pfx" -Value $deviceCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)

        # Remove the private key from the store
        Unload-PrivateKey -PrivateKey $deviceCert.PrivateKey

        Write-Host "Device successfully $($JoinType)ed to Azure AD:"
        Write-Host "  DisplayName:      ""$DeviceName"""
        Write-Host "  DeviceId:         $deviceId"
        Write-Host "  AuthUserObjectId: $authUserObjectId"
        Write-Host "  TenantId:         $tenantId"
        Write-Host "  Cert thumbprint:  $($regResponse.Certificate.Thumbprint)"
        Write-host "  Cert file name :  ""$deviceId.pfx"""

        foreach($change in $regResponse.MembershipChanges)
        {
            Write-Host "Local SID:"
            Write-Host "  $($change.LocalSID) $(if($change.LocalSID -eq "S-1-5-32-544"){"(Local administrators)"})"
            Write-Host "Additional SIDs:"
            foreach($sid in $change.AddSIDs)
            {
                Write-Host "  $sid $(Convert-SIDtoObjectID -SID $sid)"
            }
        }

    }
}

# Generates a new set of PRT keys for the user.
# Aug 21st 2020
function Get-UserPRTKeys
{
<#
    .SYNOPSIS
    Creates a new set of session key and refresh_token (PRT) for the user and saves them to json file.

    .DESCRIPTION
    Creates a new set of Primary Refresh Token (PRT) keys for the user, including a session key and a refresh_token (PRT).
    Keys are saved to a json file.

    .Parameter Certificate
    x509 certificate used to sign the certificate request.

    .Parameter PfxFileName
    File name of the .pfx certificate used to sign the certificate request.

    .Parameter PfxPassword
    The password of the .pfx certificate used to sign the certificate request.

    .Parameter Credentials
    Credentials of the user.
    
    .Parameter OSVersion
    The operating system version of the device. Defaults to "10.0.18363.0"

    .Parameter UseRefreshToken
    Uses cached refresh token instead of credentials. Use Get-AADIntAccessTokenForMDM with -SaveToCache switch.

    .Parameter TransportKeyFileName
    Name of the .PEM file containing the transport key

    .Parameter WHfBKeyFileName
    Name of the .PEM file containing the Windows Hello for Business (WHfB) key.
    If provided, AADInternals is trying to use WHfB key as the proof-of-identity

    .Parameter UseDeviceCertForWHfB
    If set, AADInternals is trying to use the provided device certificate key as WHfB key.

    .Parameter SAMLToken
    Uses the provided SAML token instead of credentials. 

    .EXAMPLE
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS C:\>Join-AADIntAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"

    Device successfully registered to Azure AD:
      DisplayName:      "My computer"
      DeviceId:         d03994c9-24f8-41ba-a156-1805998d6dc7
      AuthUserObjectId: afdeac87-b32a-41a0-95ad-0a555a91f0a4
      TenantId:         8aeb6b82-6cc7-4e33-becd-97566b330f5b
      Cert thumbprint:  78CC77315A100089CF794EE49670552485DE3689
      Cert file name :  "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
    Local SID:
      S-1-5-32-544
    Additional SIDs:
      S-1-12-1-797902961-1250002609-2090226073-616445738
      S-1-12-1-3408697635-1121971140-3092833713-2344201430
      S-1-12-1-2007802275-1256657308-2098244751-2635987013

    PS C:\>$creds = Get-Credential

    PS C:\>$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -Credentials $cred

    PS C:\>$prttoken = New-AADIntUserPRTToken -Settings $prtkeys

    .EXAMPLE
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS C:\>Join-AADIntAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"

    Device successfully registered to Azure AD:
      DisplayName:      "My computer"
      DeviceId:         d03994c9-24f8-41ba-a156-1805998d6dc7
      AuthUserObjectId: afdeac87-b32a-41a0-95ad-0a555a91f0a4
      TenantId:         8aeb6b82-6cc7-4e33-becd-97566b330f5b
      Cert thumbprint:  78CC77315A100089CF794EE49670552485DE3689
      Cert file name :  "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
    Local SID:
      S-1-5-32-544
    Additional SIDs:
      S-1-12-1-797902961-1250002609-2090226073-616445738
      S-1-12-1-3408697635-1121971140-3092833713-2344201430
      S-1-12-1-2007802275-1256657308-2098244751-2635987013

    PS C:\>Get-AADIntAccessTokenForIntuneMDM -SaveToCache

    PS C:\>$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -UseRefreshToken

    PS C:\>$prttoken = New-AADIntUserPRTToken -Settings $prtkeys

    .EXAMPLE
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS C:\>Join-AADIntAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"

    Device successfully registered to Azure AD:
      DisplayName:      "My computer"
      DeviceId:         d03994c9-24f8-41ba-a156-1805998d6dc7
      AuthUserObjectId: afdeac87-b32a-41a0-95ad-0a555a91f0a4
      TenantId:         8aeb6b82-6cc7-4e33-becd-97566b330f5b
      Cert thumbprint:  78CC77315A100089CF794EE49670552485DE3689
      Cert file name :  "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
    Local SID:
      S-1-5-32-544
    Additional SIDs:
      S-1-12-1-797902961-1250002609-2090226073-616445738
      S-1-12-1-3408697635-1121971140-3092833713-2344201430
      S-1-12-1-2007802275-1256657308-2098244751-2635987013

    PS C:\>$saml = New-AADIntSAMLToken -ImmutableID "2Vt0xz0EgESz+vF+8BzxPw==" -Issuer "http://sts.company.com/adfs/services/trust" -PfxFileName .\ADFSSigningCertificate.pfx

    PS C:\>$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SAMLToken $saml

    PS C:\>$prttoken = New-AADIntUserPRTToken -Settings $prtkeys

    .Example
    PS C\:>Export-AADIntLocalDeviceCertificate

    Device certificate exported to f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx

    PS C\:>Export-AADIntLocalDeviceTransportKey

    Transport key exported to f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem
   
    PS C:\>$creds = Get-Credential

    PS C\:>$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx -TransportKeyFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem -Credentials $creds

    PS C:\>$prttoken = New-AADIntUserPRTToken -Settings $prtkeys

    .Example
    PS C\:>Export-AADIntLocalDeviceCertificate

    Device certificate exported to f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx

    PS C\:>Export-AADIntLocalDeviceTransportKey

    Transport key exported to f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem
   
    PS C\:>$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx -TransportKeyFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem

    PS C:\>$prttoken = New-AADIntUserPRTToken -Settings $prtkeys
	
	.Example
	PS C\:>$creds = Get-Credential
    PS C\:>$prtKeys = Get-AADIntUserPRTKeys -CloudAP -Credentials $creds
	
	WARNING: Elevating to LOCAL SYSTEM. You MUST restart PowerShell to restore AzureAD\User1 rights.
	Keys saved to 31abceff-a84c-4f3b-9461-582435d7d448.json

    PS C:\>$prttoken = New-AADIntUserPRTToken -Settings $prtkeys

    .EXAMPLE
    
    PS C:\>$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -UseDeviceCertForWHfB -UserName user@company.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Certificate'      ,Mandatory=$True)]
        [Parameter(ParameterSetName='RTCertificate'    ,Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName='FileAndPassword'  ,Mandatory=$True)]
        [Parameter(ParameterSetName='RTFileAndPassword',Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName='FileAndPassword'  ,Mandatory=$False)]
        [Parameter(ParameterSetName='RTFileAndPassword',Mandatory=$False)]
        [string]$PfxPassword,

        [Parameter(Mandatory=$False)]
        [string]$TransportKeyFileName,

        [Parameter(Mandatory=$False)]
        [string]$WHfBKeyFileName,
        [Parameter(Mandatory=$False)]
        [string]$UserName,
        [Parameter(Mandatory=$False)]
        [switch]$UseDeviceCertForWHfB,

        [Parameter(ParameterSetName='RTFileAndPassword',Mandatory=$True)]
        [Parameter(ParameterSetName='RTCertificate'    ,Mandatory=$True)]
        [switch]$UseRefreshToken,

        [Parameter(Mandatory=$False)]
        [String]$SAMLToken,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,

        [Parameter(Mandatory=$False)]
        [String]$OSVersion="10.0.18363.0",

        [Parameter(Mandatory=$False)]
        [switch]$IncludePartialTGT
    )

    Process
    {
        # Load the certificate if not provided
        if(!$Certificate)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        # Get the private key
        $privateKey = Load-PrivateKey -Certificate $Certificate

        # Get the public key
        $publicKey = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)

        # Parse certificate information
        $oids = Parse-CertificateOIDs -Certificate $Certificate
        $deviceId = $oids.DeviceId.ToString()
        $tenantId = $oids.TenantId.ToString()
        $objectId = $oids.AuthUserObjectId.ToString()

        # Get the nonce
        $nonce = (Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body "grant_type=srv_challenge").Nonce

        # Construct the header
        $headerObj = [ordered]@{
            "alg" = "RS256"
            "typ" = "JWT"
            "x5c" = Convert-ByteArrayToB64 ($publicKey)
        }
        $header = Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.GetBytes(($headerObj | ConvertTo-Json -Compress))) -NoPadding

        # Construct the payload
        $payloadObj=@{
            "client_id"     = "38aa3b87-a06d-4817-b275-7a316988d93b"
            "request_nonce" = "$nonce"
            "scope"         = "openid aza ugs"
            "win_ver"       = "$OSVersion"
        }
        if($SAMLToken)
        {
            $payloadObj["grant_type"] = "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
            $payloadObj["assertion"]  =  Convert-TextToB64 -Text  $SAMLToken
        }
        elseif($Credentials)
        {
            $payloadObj["grant_type"] = "password"
            $payloadObj["username"]   = $Credentials.UserName
            $payloadObj["password"]   = $Credentials.GetNetworkCredential().Password
        }
        elseif($UseRefreshToken)
        {
            # Trying to get the refresh token from the cache
            $refresh_token = Get-RefreshTokenFromCache -ClientID "29d9ed98-a469-4536-ade2-f981bc1d605e" -Resource "https://graph.windows.net"
            if([string]::IsNullOrEmpty($refresh_token))
            {
                Throw "No refresh token found! Use Get-AADIntAccessTokenForIntuneMDM with -SaveToCache switch and try again."
            }
                
            $tokens = Get-AccessTokenWithRefreshToken -RefreshToken $refresh_token -Resource "1b730954-1685-4b74-9bfd-dac224a7b894" -ClientId "29d9ed98-a469-4536-ade2-f981bc1d605e" -TenantId Common -IncludeRefreshToken $true 

            $payloadObj["grant_type"]    = "refresh_token"
            $payloadObj["refresh_token"] = $tokens[1]
            $payloadObj["client_id"]     = "29d9ed98-a469-4536-ade2-f981bc1d605e"
        }
        elseif($WHfBKeyFileName -or $UseDeviceCertForWHfB)
        {
            # Use Device Certificate key as WHfB key
            if($UseDeviceCertForWHfB)
            {
                # Check do we have a user name
                if([string]::IsNullOrEmpty($UserName))
                {
                    throw "User name must be provided with -Username parameter."
                }
                $whfbParameters = $privateKey.ExportParameters($true)
            }
            # Use the provided WHfB key
            else
            {
                # Check do we have a user name
                if([string]::IsNullOrEmpty($UserName))
                {
                    # Try to parse from the file name
                    try
                    {
                        Write-Warning "Username not provided, trying to parse from the filename"
                        $UserName = $WHfBKeyFileName.Split("_")[2]    
                        Write-Verbose "Using $UserName for WHfB assertion."
                    }
                    catch
                    {
                        throw "Could not parse username from the filename, please provide user with -UserName parameter."
                    }
                }
                # Load WHfB key from the PEM file
                $whfbPEM = (Get-Content $WHfBKeyFileName) -join "`n"
                $whfbParameters = Convert-PEMToRSA -PEM $whfbPEM
            }

            # Set the parameters
            $now = (Get-Date).toUniversalTime()
            $assertion_iss = $UserName
            $assertion_kid = Convert-ByteArrayToB64 -Bytes ([System.Security.Cryptography.SHA256]::Create().ComputeHash( (New-KeyBLOB -Parameters $whfbParameters -Type RSA1)))
            $assertion_aud = $TenantId
            $assertion_iat = [int](($now)-$epoch).TotalSeconds
            $assertion_exp = [int](($now).AddMinutes(10)-$epoch).TotalSeconds

            $assertion_hdr = [ordered]@{
                "alg" = "RS256"
                "typ" = "JWT"
                "kid" = $assertion_kid
                "use" = "ngc"
            }

            # Get the nonce
            $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token" -Body "grant_type=srv_challenge"
            $nonce = $response.Nonce

            $assertion_pld = [ordered]@{
                "iss" = $assertion_iss
                "aud" = $assertion_aud
                "iat" = $assertion_iat
                "exp" = $assertion_exp
                "request_nonce" = $nonce
                "scope" = "openid aza ugs"
            }

            # Create and sign the assertion JWT
            $assertion = New-JWT -PrivateKey ([System.Security.Cryptography.RSA]::Create($whfbParameters)) -Header $assertion_hdr -Payload $assertion_pld

            $payloadObj["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            $payloadObj["assertion"]  = $assertion
        }
        else
        {
            # Get access token interactively (supports MFA)
            $tokens = Get-AccessToken -ClientId "29d9ed98-a469-4536-ade2-f981bc1d605e" -PfxFileName $PfxFileName -Resource "1b730954-1685-4b74-9bfd-dac224a7b894" -IncludeRefreshToken $true

            $payloadObj["grant_type"]    = "refresh_token"
            $payloadObj["refresh_token"] = $tokens[1]
            $payloadObj["client_id"]     = "29d9ed98-a469-4536-ade2-f981bc1d605e"
        }

        $payload = Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.GetBytes( ($payloadObj | ConvertTo-Json -Compress ) )) -NoPadding

        # Construct the JWT data to be signed
        $dataBin = [text.encoding]::UTF8.GetBytes(("{0}.{1}" -f $header,$payload))

        # Get the signature
        $sigBin = Sign-JWT -PrivateKey $PrivateKey -Data $dataBin
        $sigB64 = Convert-ByteArrayToB64 $sigBin -UrlEncode -NoPadding

        # B64 URL encode
        $signature = $sigB64

        # Construct the JWT
        $jwt = "{0}.{1}.{2}" -f $header,$payload,$signature

        # Construct the body
        $body = @{
            "windows_api_version" = "2.0"
            "grant_type"          = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            "request"             = "$jwt"
            "client_info"         = "1"
        }

        if ($IncludePartialTGT)
        {
            $body['tgt'] = $true
        }

        # Make the request
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction SilentlyContinue

        if(!$response.token_type)
        {
            throw "Error getting session key. Check your credentials!"
        }

        # Decrypt the session key and add it to return value
        try
        {
            if($TransportKeyFileName)
            {
                # Get the transport key from the provided file 
                $tkPEM = (Get-Content $TransportKeyFileName) -join "`n"
                $tkParameters = Convert-PEMToRSA -PEM $tkPEM
                $privateKey = [System.Security.Cryptography.RSA]::Create($tkParameters)
            }
            $sessionKey = Decrypt-JWE -JWE $response.session_key_jwe -PrivateKey $privateKey
            $response | Add-Member -NotePropertyName "session_key" -NotePropertyValue (Convert-ByteArrayToB64 -Bytes $sessionKey)

            if ($IncludePartialTGT)
            {
                $tgt = Decrypt-JWE -JWE $response.tgt_client_key -SessionKey $sessionKey
                $response | Add-Member -NotePropertyName "decrypted_tgt_client_key" -NotePropertyValue (Convert-ByteArrayToB64 -Bytes $tgt)
            }

        }
        catch
        {
            Write-Error $($_.Exception.Message)
        }

        # Write to file
        $outFileName = "$deviceId.json"
        $response | ConvertTo-Json |Set-Content $outFileName -Encoding UTF8
        Write-Host "Keys saved to $outFileName"

        try
        {
            # Unload the private key
            Unload-PrivateKey -PrivateKey $privateKey    
        }
        catch {}

        # Return
        $response
    }
}

# Removes the device from Azure AD
# Sep 2nd 2020
function Remove-DeviceFromAzureAD
{
<#
    .SYNOPSIS
    Removes the device from Azure AD.

    .DESCRIPTION
    Removes the device from Azure AD using the given device certificate.

    .Parameter Certificate
    x509 certificate used to sign the certificate request.

    .Parameter PfxFileName
    File name of the .pfx certificate used to sign the certificate request.

    .Parameter PfxPassword
    The password of the .pfx certificate used to sign the certificate request.

    .Parameter Force
    Does not ask for "Are your sure?" questions.

    .EXAMPLE
    Remove-AADIntDeviceFromAzureAD -pfxFileName .\85c3252a-3b33-41cf-bd4f-c53b7a94c548.pfx

    The device 85c3252a-3b33-41cf-bd4f-c53b7a94c548 succesfully removed from Azure AD. Attestation result KeyId: 0372f9ab-6103-4a0f-9095-9b49cd399479

#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [string]$PfxPassword,
        [switch]$Force
    )
    Process
    {
        
        if(!$Certificate)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        $deviceID = $Certificate.Subject.Split("=")[1]

        if(!$Force)
        {
            $promptValue = Read-Host "Are you sure you wan't to remove the device $deviceID? from Azure AD? Type YES to continue or CTRL+C to abort"
            if($promptValue -ne "yes")
            {
                Write-Warning "Device removal of device $deviceID cancelled."
                return
            }
        }

        Write-Verbose "Unenrolling device $deviceID"

        $requestId = (New-Guid).ToString()

        $headers=@{
            "User-Agent" =               "Dsreg/10.0 (Windows 10.0.18363.0)"
            "ocp-adrs-client-name" =     "Dsreg"
            "ocp-adrs-client-version" =  "10.0.18362.0"
            "client-Request-Id" =        $requestId
            "return-client-request-id" = "true"
        }

        try
        {
            $response = Invoke-WebRequest -UseBasicParsing -Certificate $Certificate -Method Delete -Uri "https://enterpriseregistration.windows.net/EnrollmentServer/device/$($deviceID)?api-version=1.0" -Headers $headers -ErrorAction SilentlyContinue
        }
        catch
        {
            Write-Error ($_.ErrorDetails.Message | ConvertFrom-Json ).Message
            return
        }

        $keyId = ($response.Content | ConvertFrom-Json).AttestationResult.KeyId

        Write-Host "The device $deviceID succesfully removed from Azure AD. Attestation result KeyId: $keyId"
    }
}


# Get device compliance
# Sep 11th 2020
function Get-DeviceRegAuthMethods
{
<#
    .SYNOPSIS
    Get's the authentication methods used while registering the device.

    .DESCRIPTION
    Get's the authentication methods used while registering the device.

    .Parameter AccessToken
    The access token used to get the methos.

    .Parameter DeviceId
    Azure AD device id of the device.

    .Parameter ObjectId
    Azure AD object id of the device.

    .EXAMPLE
    Get-AADIntAccessTokenForAADGraph -SaveToCache

    PS C\:>Get-AADIntDeviceRegAuthMethods -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7"

    pwd
    mfa
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='DeviceID',Mandatory=$True)]
        [String]$DeviceId,
        [Parameter(ParameterSetName='ObjectID',Mandatory=$True)]
        [String]$ObjectId
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
        if([string]::IsNullOrEmpty($ObjectId))
        {
            $ObjectId = Get-DeviceObjectId -DeviceId $DeviceId -TenantId $tenantId -AccessToken $AccessToken
        }

        # Get the methods
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://graph.windows.net/$tenantId/devices/$ObjectId`?`$select=deviceSystemMetadata&api-version=1.61-internal" -Headers $headers

        $methods = $response.deviceSystemMetadata | Where-Object key -eq RegistrationAuthMethods | Select-Object -ExpandProperty value | ConvertFrom-Json

        return $methods
    }
}


# Set device compliance
# Sep 11th 2020
function Set-DeviceRegAuthMethods
{
<#
    .SYNOPSIS
    Set's the authentication methods.

    .DESCRIPTION
    Set's the authentication methods. Affects what authentication claims the access tokens generated with device certificate or PRT.

    .Parameter AccessToken
    The access token used to set the methods.

    .Parameter DeviceId
    Azure AD device id of the device.

    .Parameter ObjectId
    Azure AD object id of the device.

    .Parameter Methods
    The list of methods. Can be any of "pwd","rsa","otp","fed","wia","mfa","mngcmfa","wiaormfa","none" but only pwd and mfa matters.

    .EXAMPLE
    Get-AADIntAccessTokenForAADGraph -SaveToCache

    PS C\:>Set-AADIntDeviceRegAuthMethods -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" -Methods mfa,pwd

    pwd
    mfa
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='DeviceID',Mandatory=$True)]
        [String]$DeviceId,
        [Parameter(ParameterSetName='ObjectID',Mandatory=$True)]
        [String]$ObjectId,
        [Validateset("pwd","rsa","otp","fed","wia","mfa","mngcmfa","wiaormfa","none")]
        [Parameter(Mandatory=$False)]
        [String[]]$Methods="none"
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
        if([string]::IsNullOrEmpty($ObjectId))
        {
            $ObjectId = Get-DeviceObjectId -DeviceId $DeviceId -TenantId $tenantId -AccessToken $AccessToken
        }

        # Get the current methods
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://graph.windows.net/$tenantId/devices/$ObjectId`?`$select=deviceSystemMetadata&api-version=1.61-internal" -Headers $headers

        # Change the methods and convert to JSON
        $newMethods =           $Methods | ConvertTo-Json -Compress
        $currentMethods =       $response.deviceSystemMetadata | Where-Object key -eq RegistrationAuthMethods
        $currentMethods.value = $newMethods

        # Post the changes to Azure AD
        Invoke-RestMethod -UseBasicParsing -Method Patch -Uri "https://graph.windows.net/$tenantId/devices/$ObjectId`?api-version=1.61-internal" -Headers $headers -Body ($response|ConvertTo-Json) -ContentType "application/json"

        Get-DeviceRegAuthMethods -AccessToken $AccessToken -ObjectId $ObjectId
    }
}


# Get device transport key public key
# Sep 13th 2020
function Get-DeviceTransportKey
{
<#
    .SYNOPSIS
    Get's the public key of transport key of the device.

    .DESCRIPTION
    Get's the public key of transport key of the device.

    .Parameter AccessToken
    The access token used to get the certificate.

    .Parameter DeviceId
    Azure AD device id of the device.

    .Parameter ObjectId
    Azure AD object id of the device.

    .EXAMPLE
    Get-AADIntAccessTokenForAADGraph -SaveToCache

    PS C\:>Get-AADIntDeviceTransportKey -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7"

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='DeviceID',Mandatory=$True)]
        [String]$DeviceId,
        [Parameter(ParameterSetName='ObjectID',Mandatory=$True)]
        [String]$ObjectId
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
        if([string]::IsNullOrEmpty($ObjectId))
        {
            $ObjectId = Get-DeviceObjectId -DeviceId $DeviceId -TenantId $tenantId -AccessToken $AccessToken
        }

        # Get the key information
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://graph.windows.net/$tenantId/devices/$ObjectId`?`$select=deviceId,deviceKey,alternativeSecurityIds,objectId&api-version=1.61-internal" -Headers $headers
        
        $DeviceId = $response.deviceId

        if($response.alternativeSecurityIds -and $response.alternativeSecurityIds.key -and $response.deviceKey)
        {
            Write-Verbose "Current key material: $(Convert-B64ToText -B64 $response.deviceKey[0].keyMaterial)"

            # Get the certificate thumbprint and SHA1
            $keyInfo =    ([text.encoding]::Unicode.GetString( [byte[]](Convert-B64ToByteArray -B64 $response.alternativeSecurityIds.key)) ).split(">")[1]
            $thumbPrint = $keyInfo.Substring(0,40)
            $SHA256 =     $keyInfo.Substring(41) # Should be SHA1 (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dvre/1f2ebba7-7783-42c4-982a-ce9ca76af949)

            $rawKeyMaterial = Convert-B64ToByteArray -B64 $response.deviceKey[0].keyMaterial 

            # Check whether this the raw RSABLOB
            if( (Compare-Object -ReferenceObject ([text.encoding]::ASCII.GetBytes("RSA1")) -DifferenceObject $rawKeyMaterial[0..3]) -eq $null)
            {
                $parsedKey = Parse-KeyBLOB -Key $rawKeyMaterial
                $keyMaterial = @{
                    "kid" = ""
                    "alg" = "RS256"
                    "kty" = "RSA"
                    "e"   = Convert-ByteArrayToB64 -Bytes $parsedKey.Exponent
                    "n"   = Convert-ByteArrayToB64 -Bytes $parsedKey.Modulus
                }

            }
            else
            {
                $keyMaterial = [text.encoding]::UTF8.getString($rawKeyMaterial) | ConvertFrom-Json
            }

            # Export the TKPUB
            $export = @{
                "keyMaterial" = $keyMaterial
                "thumpPrint"  = $thumbPrint
                "hash" =        $SHA256
            }

            $export | ConvertTo-Json | Set-Content "$DeviceId-TKPUB.json" -Encoding UTF8


            # Print out information
            Write-Host "Device TKPUB key successfully exported:"
            Write-Host "  Device ID:             $deviceId"
            Write-Host "  Cert thumbprint:       $($thumbPrint.toLower())"
            Write-Host "  Cert SHA256:           $SHA256"
            Write-host "  Public key file name : ""$DeviceId-TKPUB.json"""
        }
        else
        {
            Write-Error "Could not get TKPUB for device $DeviceId"
        }
    }
}


# Set device transport key public key
# Sep 24th 2020
function Set-DeviceTransportKey
{
<#
    .SYNOPSIS
    Set's the public key of transport key of the device.

    .DESCRIPTION
    Set's the public key of transport key of the device.

    .Parameter AccessToken
    The access token used to get the certificate.

    .Parameter DeviceId
    Azure AD device id of the device.

    .Parameter ObjectId
    Azure AD object id of the device.

    .Parameter Certificate
    A X509 certificate to be used to set the TKPUB.

    .Parameter PfxFileName
    The full path to .pfx file from where to load the certificate

    .Parameter PfxPassword
    The password of the .pfx file

    .Parameter JsonFile
    The full path to .json file containing TKPUB information exported using Get-AADIntDeviceTransportKey

    .Parameter UseBuiltInCertificate
    Uses the internal any.sts certificate

    .EXAMPLE
    Get-AADIntAccessTokenForAADGraph -SaveToCache

    PS C\:>Set-AADIntDeviceTransportKey -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" -UseBuiltInCertificate

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$DeviceId,
        [Parameter(Mandatory=$False)]
        [String]$ObjectId,

        [Parameter(ParameterSetName='UseAnySTS',Mandatory=$True)]
        [switch]$UseBuiltInCertificate,

        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [string]$PfxPassword,

        [Parameter(ParameterSetName='JSON',Mandatory=$True)]
        [string]$JsonFileName
    )
    Process
    {
        

        if([string]::IsNullOrEmpty($ObjectId) -and [string]::IsNullOrEmpty($DeviceId))
        {
            Write-Error "ObjectId or DeviceId required!"
            return
        }
        
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        if($JsonFileName) # JSON file
        {
            $json =        Get-Content $JsonFileName -Encoding UTF8 | ConvertFrom-Json
            $hash =    $json.hash
            $thumpPrint =  $json.thumpPrint
            $keyMaterial = $json.keyMaterial
        }
        else
        {
            if($UseBuiltInCertificate) # Do we use built-in certificate (any.sts)
            {
                [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate = Load-Certificate -FileName "$PSScriptRoot\any_sts.pfx" -Password ""
            }
            elseif($Certificate -eq $null) # Load the certificate
            {
                [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword
            }

            # Create a SHA256 object and calculate hash
            $sha256 =   [System.Security.Cryptography.SHA256]::Create()
            $certHash = $sha256.ComputeHash($Certificate.GetPublicKey())
            $hash =     $(Convert-ByteArrayToB64 -Bytes $certHash)

            # Get the parameters from the certificate and create key material
            $parameters = $Certificate.PublicKey.Key.ExportParameters($false)
            $keyMaterial = @{
                "kty" = "RSA"
                "n" =   Convert-ByteArrayToB64 -Bytes $parameters.Modulus
                "e" =   Convert-ByteArrayToB64 -Bytes $parameters.Exponent
                "alg" = "RS256"
                "kid" = (New-Guid).ToString()
            }

            $thumpPrint = $Certificate.Thumbprint
        }
        Write-Verbose "New key material $(($keyMaterial | ConvertTo-Json -Compress))"
        $kMat = Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.getBytes( ($keyMaterial | ConvertTo-Json -Compress) ))

        $parsedToken = Read-Accesstoken -AccessToken $AccessToken

        $tenantId = $parsedToken.tid

        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Accept" =        "application/json;odata=nometadata"
        }

        # Get the object Id if not given
        if([string]::IsNullOrEmpty($ObjectId))
        {
            $ObjectId = Get-DeviceObjectId -DeviceId $DeviceId -TenantId $tenantId -AccessToken $AccessToken
        }

        # Get the current key information
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://graph.windows.net/$tenantId/devices/$ObjectId`?`$select=deviceKey,alternativeSecurityIds&api-version=1.61-internal" -Headers $headers

        Write-Verbose "Current key material: $(Convert-B64ToText -B64 $response.deviceKey[0].keyMaterial)"

        if([String]::IsNullOrEmpty($response))
        {
            Write-Error "The device $DeviceId has no deviceKey, unable to change."
            return
        }
        
        # Set the new key
        $response.deviceKey[0].keyMaterial = $kMat

        # Set also the alternative security id to match the key. 
        # The documentation states that the hash should be SHA1 https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dvre/1f2ebba7-7783-42c4-982a-ce9ca76af949
        # but the length equals SHA256 so we are using that instead.
        $key = "X509:<SHA1-TP-PUBKEY>$thumpPrint$hash"
        $key = Convert-ByteArrayToB64 -Bytes ([text.encoding]::Unicode.GetBytes($key))
        $response.alternativeSecurityIds[0].key = $key


        Invoke-RestMethod -UseBasicParsing -Method Patch -Uri "https://graph.windows.net/$tenantId/devices/$ObjectId`?api-version=1.61-internal" -Headers $headers -Body ($response | ConvertTo-Json) -ContentType "application/json"

    }
}


# Creates a new BPRT
# Oct 20th 2020
function New-BulkPRTToken
{
<#
    .SYNOPSIS
    Creates a new BPRT (Bulk AAD PRT Token)

    .DESCRIPTION
    Creates a new BPRT (Bulk AAD PRT Token) for registering multiple devices to AAD. 
    Adds a corresponding user to Azure AD with UPN "package_<guid>@<default domain>". The Display Name of the user can be defined.

    .Parameter AccessToken
    Access token to create the BPRT

    .Parameter Expires
    The date when the BPRT expires. Maximum is 180 days.

    .Parameter Name
    The display name of the user to be created. Defaults to "package_<guid>". The upn will always be "package_<guid>@<default domain>".

    .Parameter PackageId
    Package Id of the previously created BPRT. Overwrites the existing user object and creates a new BPRT. If not found, a new one is created.

    .EXAMPLE
    Get-AADIntAccessTokenForAADGraph -Resource urn:ms-drs:enterpriseregistration.windows.net -SaveToCache
    PS C:\> New-AADIntBulkPRTToken -Name "My BPRT user"

    BPRT saved to package_8eb8b873-2b6a-4d55-bd96-27b0abadec6a-BPRT.json   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [DateTime]$Expires=(Get-Date).AddMonths(1),
        [Parameter(Mandatory=$False)]
        [ValidateLength(1, 256)]
        [String]$Name,
        [Parameter(Mandatory=$False)]
        [guid]$PackageId=(New-Guid),
        [switch]$Force
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "urn:ms-drs:enterpriseregistration.windows.net" -Force $Force

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
        }

        if([string]::IsNullOrEmpty($Name))
        {
            $Name = "package_$($PackageId.ToString())"
        }

        $body = @{
            "pid" =  $PackageId.ToString()
            "name" = $Name
            "exp" =  $Expires.ToString("MM/dd/yyyy")
        }

        # Make the first request to get flowToken
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/webapp/bulkaadjtoken/begin" -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json; charset=utf-8"

        if($response.state -like "*Error*")
        {
            $resultData = $response.resultData | ConvertFrom-Json
            throw $resultData.error_description
        }

        # Get the BPRT
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://login.microsoftonline.com/webapp/bulkaadjtoken/poll?flowToken=$($response.flowToken)" -Headers $headers

        $details = $response.resultData | ConvertFrom-Json

        # Check for the errors
        if($details.error_description)
        {
            if($details.error -eq "unauthorized_client")
            {
                Write-Warning "Got unauthorized_client error. Please try again."
            }
            elseif($details.error_description.StartsWith("AADSTS90092"))
            {
                # Missing Microsoft.Azure.SyncFabric service principal?
                try
                {
                    if([string]::IsNullOrEmpty((Get-ServicePrincipals -ClientIds "00000014-0000-0000-c000-000000000000").value))
                    {
                        Write-Warning "Missing Microsoft.Azure.SyncFabric service principal!"
                        Write-Warning "Use Add-AADIntSyncFabricServicePrincipal to add the missing service principal."
                    }

                }
                catch{} # Okay
            }
            throw $details.error_description
        }

        $parsedIdToken = Read-Accesstoken -AccessToken $details.id_token

        $userName = $parsedIdToken.upn

        Write-Verbose "BPRT successfully created. Id = $guid. User name: $userName"

        # Write to file
        $outFileName = "$($userName.Split("@")[0])-BPRT.json"
        $details | ConvertTo-Json |Set-Content $outFileName -Encoding UTF8
        Write-Host "BPRT saved to $outFileName`n"

        return $details.refresh_token
    }
}

# Add WHfB key
# May 5th 2023
function Set-DeviceWHfBKey
{
<#
    .SYNOPSIS
    Sets a Windows Hello for Business (WHfB) key of the device.

    .DESCRIPTION
    Sets a Windows Hello for Business (WHfB) key of the device. Device information is included in the PRT token given as a parameter.

    .Parameter AccessToken
    Access token to register the WHfB key.

    .Parameter Certificate
    x509 certificate which private key is used as WHfB key.
    If not provided, a new WHfB key is created.

    .Parameter PfxFileName
    File name of the .pfx certificate which private key is used as WHfB key.
    If not provided, a new WHfB key is created.

    .Parameter PfxPassword
    The password of the .pfx certificate which private key is used as WHfB key.

    .EXAMPLE
    PS C:\> $prttoken = Get-AADIntUserPRTToken
    PS C:\> Get-AADIntAccessTokenForWHfB -PRTToken $prttoken -SaveToCache
    PS C:\> Set-AADIntDeviceWHfBKey

    Device Window Hello for Business key successfully added to the user:
    DeviceId:       b27db620-2673-4dac-a565-cec81bfafbaa
    Key Id:         a07b4c9c-1515-4d79-9ce2-7f7954049adf
    UPN:            user@company.com
    Key file name : "b27db620-2673-4dac-a565-cec81bfafbaa_a07b4c9c-1515-4d79-9ce2-7f7954049adf_user@company.com_whfb.pem"

    .EXAMPLE
    PS C:\> Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS C:\> Join-AADIntDeviceToAzureAD -JoinType Join -DeviceName "My device"

    Device successfully registered to Azure AD:
        DisplayName:     "My device"
        DeviceId:        b27db620-2673-4dac-a565-cec81bfafbaa
        ObjectId:        4fbbb5f6-1563-4237-974c-dfabcc5c533c
        TenantId:        01a09bec-7584-45a5-8048-e7f1b4181f20
        Cert thumbprint: 593E3D7F8F8CE0DB74725EE3B5AC1B5F58D92994
        Cert file name : "b27db620-2673-4dac-a565-cec81bfafbaa.pfx"
    Local SID:
        S-1-5-32-544
    Additional SIDs:
        S-1-12-1-1173396554-1264637767-1283444156-383767028
        S-1-12-1-727559687-1332680371-478291341-2778853572
        S-1-12-1-1337701878-1110906211-2883538071-1012096204

    PS C:\> $prtkeys = Get-AADIntUserPRTKeys -PfxFileName .\b27db620-2673-4dac-a565-cec81bfafbaa.pfx

    Keys saved to b27db620-2673-4dac-a565-cec81bfafbaa.json

    PS C:\> $prttoken = New-AADIntUserPRTToken -Settings $prtkeys
    PS C:\> Get-AADIntAccessTokenForWHfB -PRTToken $prttoken -SaveToCache
    PS C:\> Set-AADIntDeviceWHfBKey -PfxFileName .\b27db620-2673-4dac-a565-cec81bfafbaa.pfx

    Device Window Hello for Business key successfully added to the user:
    DeviceId:       b27db620-2673-4dac-a565-cec81bfafbaa
    Key Id:         a07b4c9c-1515-4d79-9ce2-7f7954049adf
    UPN:            user@company.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,

        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$False)]
        [string]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword
    )
    Process
    {
        # Get access token from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "dd762716-544d-4aeb-a526-687b73838a22" -Resource "urn:ms-drs:enterpriseregistration.windows.net"

        # Check that we have the required claims
        $parsedAccessToken = Read-Accesstoken -AccessToken $AccessToken
        if([string]::IsNullOrEmpty($parsedAccessToken.DeviceID))
        {
            throw "DeviceID claim not present in the access token."
        }
        if($parsedAccessToken.amr -notcontains "ngcmfa")
        {
            throw "ngcmfa claim not present in the access token."
        }

        # Load the certificate if not provided
        if(!$Certificate)
        {
            # Load only if we have file name
            if($PfxFileName)
            {
                $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
            }
        }
        # Use the private key of provided certificate
        if($Certificate)
        {
            # Get the private key and use it's parameters
            $privateKey = Load-PrivateKey -Certificate $Certificate
            $RSAParameters = $privateKey.ExportParameters($true)
            Unload-PrivateKey -PrivateKey $privateKey
        }

        # Create key pair if not provided
        if($RSAParameters -eq $null)
        {
            $RSAParameters = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048).ExportParameters($true)
        }

        # Create the public key blob
        $keyBlob = New-KeyBLOB -Parameters $RSAParameters -Type RSA1

        # Create the headers and body
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Accept"        = "application/json"
        }
        $body = @{
            "kngc" = Convert-ByteArrayToB64 -Bytes $keyBlob
        }
        
        # Make the request
        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://enterpriseregistration.windows.net/EnrollmentServer/key/?api-version=1.0" -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json; charset=utf-8"    
        }
        catch
        {
            throw ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
        }

        # Check whether we have private key
        if($RSAParameters.P)
        {
            # Write the private key to a file if not using provided certificate
            if(-not $Certificate)
            {
                $fileName = "$($parsedAccessToken.DeviceId)_$($response.kid)_$($response.upn)_whfb.pem"
                Set-Content $fileName -Value (Convert-RSAToPEM -RSAParameters $RSAParameters)
            }
        }
        else
        {
            Write-Warning "The given RSAParameters didn't have private key - unable to save to a file."
        }

        Write-Host "Device Window Hello for Business key successfully added to the user:"
        Write-Host "    DeviceId:       $($parsedAccessToken.DeviceId)"
        Write-Host "    Key Id:         $($response.kid)"
        Write-Host "    UPN:            $($response.upn)"
        if(-not $Certificate)
        {
            Write-Host "    Key file name : `"$fileName`""
        }
    }
}
