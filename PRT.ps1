# Get the PRT token from the current user
# Aug 19th 2020
function Get-UserPRTToken
{
<#
    .SYNOPSIS
    Gets user's PRT token from the Azure AD joined or Hybrid joined computer.

    .DESCRIPTION
    Gets user's PRT token from the Azure AD joined or Hybrid joined computer.
    Uses browsercore.exe to get the PRT token.
#>
    [cmdletbinding()]
    Param()
    Process
    {
        # There are two possible locations
        $locations = @(
            "$($env:ProgramFiles)\Windows Security\BrowserCore\browsercore.exe"
            "$($env:windir)\BrowserCore\browsercore.exe"
        )

        # Check the locations
        foreach($file in $locations)
        {
            if(Test-Path $file)
            {
                $browserCore = $file
            }
        }

        if(!$browserCore)
        {
            throw "Browsercore not found!"
        }

        # Create the process
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo.FileName = $browserCore
        $p.StartInfo.UseShellExecute = $false
        $p.StartInfo.RedirectStandardInput = $true
        $p.StartInfo.RedirectStandardOutput = $true
        $p.StartInfo.CreateNoWindow = $true

        # Create the message body
        $body = @"
        {
            "method":"GetCookies",
            "uri":"https://login.microsoftonline.com/common/oauth2/authorize",
            "sender":"https://login.microsoftonline.com"
        }
"@
        # Start the process
        $p.Start() | Out-Null
        $stdin =  $p.StandardInput
        $stdout = $p.StandardOutput

        # Write the input
        $stdin.BaseStream.Write([bitconverter]::GetBytes($body.Length),0,4) 
        $stdin.Write($body)
        $stdin.Close()

        # Read the output
        $response=""
        while(!$stdout.EndOfStream)
        {
            $response += $stdout.ReadLine()
        }

        Write-Debug "RESPONSE: $response"
        
        $p.WaitForExit()

        # Strip the stuff from the beginning of the line
        $response = $response.Substring($response.IndexOf("{")) | ConvertFrom-Json

        # Check for error
        if($response.status -eq "Fail")
        {
            Throw "Error getting PRT: $($response.code). $($response.description)"
        }

        # Return
        return $response.response.data
    }
}

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

    PS C:\>$prtToken = New-AADIntUserPRTToken -RefreshToken $prtKeys.refresh_token -SessionKey $prtKeys.session_key

    PS C:\>$at = Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken

    .EXAMPLE
    PS C:\>New-AADIntUserPRTToken -RefreshToken "AQABAAAAAAAGV_bv21oQQ4ROqh0_1-tAHenMcJD..." -SessionKey "O1g9LD9+jiE5yFulMcIeCPZrttzfEHyIPtF5X17cA5+="

    eyJhbGciOiJIUzI1NiIsICJjdHgiOiJBQUFBQUFBQUFBQUF...

    .EXAMPLE
    PS C:\>New-AADIntUserPRTToken -Settings $prtKeys

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
        [Parameter(ParameterSetName='Settings',Mandatory=$True)]
        $Settings
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

        # Derived the key from session key and context
        $key = Get-PRTDerivedKey -Context $ctx -SessionKey $sKey

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
    Emulates Azure AD Join by registering the given device to Azure AD.

    .DESCRIPTION
    Emulates Azure AD Join by registering the given device to Azure AD and generates a corresponding certificate.

    You may use any name, type or OS version you like.

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

    .EXAMPLE
    Get-AADIntAccessTokenForAADJoin -SaveToCache
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

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$DeviceName,
        [Parameter(Mandatory=$False)]
        [String]$DeviceType="Windows",
        [Parameter(Mandatory=$False)]
        [String]$OSVersion="10.0.18363.0"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"

        # Get the domain and tenant id
        $tenantId = (Read-Accesstoken -AccessToken $AccessToken).tid

        # Register the Device
        $DeviceCertResponse = Register-DeviceToAzureAD -AccessToken $AccessToken -DeviceName $DeviceName -DeviceType $DeviceType -OSVersion $OSVersion
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$deviceCert = $DeviceCertResponse[0]
        $regResponse = $DeviceCertResponse[1]

        # Write the device certificate to disk
        $deviceId = $deviceCert.Subject.Split("=")[1]
        $deviceCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx) | Set-Content "$deviceId.pfx" -Encoding Byte

        # Remove the private key from the store
        Unload-PrivateKey -PrivateKey $deviceCert.PrivateKey

        Write-Host "Device successfully registered to Azure AD:"
        Write-Host "  DisplayName:     ""$DeviceName"""
        Write-Host "  DeviceId:        $deviceId"
        Write-Host "  Cert thumbprint: $($regResponse.Certificate.Thumbprint)"
        Write-host "  Cert file name : ""$deviceId.pfx"""

        foreach($change in $regResponse.MembershipChanges)
        {
            Write-Host "Local SID:"
            Write-Host "  $($($change.LocalSID))"
            Write-Host "Additional SIDs:"
            foreach($sid in $change.AddSIDs)
            {
                Write-Host "  $sid"
            }
        }

    }
}

# Generates a new P2P certificate
# Aug 21st 2020
function New-P2PDeviceCertificate
{
<#
    .SYNOPSIS
    Creates a new P2P device or user certificate using the device certificate or PRT information.

    .DESCRIPTION
    Creates a new peer-to-peer (P2P) device or user certificate and exports it and the corresponding CA certificate. 
    It can be used to enable RDP trust between devices of the same AAD tenant.

    .EXAMPLE
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS\:>Join-AADIntAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"

    .Parameter Certificate
    x509 certificate used to sign the certificate request.

    .Parameter PfxFileName
    File name of the .pfx certificate used to sign the certificate request.

    .Parameter PfxPassword
    The password of the .pfx certificate used to sign the certificate request.

    .Parameter TenantId
    The tenant id or name of users' tenant.

    .Parameter DeviceName
    The name of the device. Will be added to DNS Names attribute of the certificate.

    .Parameter OSVersion
    The operating system version of the device. Defaults to "10.0.18363.0"

    .Parameter RefreshToken
    Primary Refresh Token (PRT) or the user.

    .Parameter SessionKey
    The session key of the user

    .Parameter Context
    The context used = B64 encoded byte array (size 24)

    .Parameter Settings
    PSObject containing refresh_token and session_key attributes.

    .EXAMPLE
    PS C\:>New-AADIntP2PDeviceCertificate -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -TenantId 4169fee0-df47-4e31-b1d7-5d248222b872 -DeviceName "mypc1.company.com"

    Device certificate successfully created:
      Subject:         "CN=d03994c9-24f8-41ba-a156-1805998d6dc7, DC=4169fee0-df47-4e31-b1d7-5d248222b872"
      DnsName:         "mypc1.company.com"
      Issuer:          "CN=MS-Organization-P2P-Access [2020]"
      Cert thumbprint: 84D7641F9BFA90767EA3456E443E21948FC425E5
      Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7-P2P.pfx"
      CA file name :   "d03994c9-24f8-41ba-a156-1805998d6dc7-P2P-CA.der"

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

    PS C:\>New-AADIntP2PDeviceCertificate -RefreshToken $prtKeys.refresh_token -SessionKey $prtKeys.session_key

    User certificate successfully created:
      Subject:         "CN=TestU@contoso.com, CN=S-1-12-1-xx-xx-xx-xx, DC=0f73eaa6-7fd6-48b8-8897-e382ba96daf4"
      Issuer:          "CN=MS-Organization-P2P-Access [2020]"
      Cert thumbprint: A7F1D1F134569E0234E6AA722354D99C3AA68D0F
      Cert file name : "TestU@contoso.com-P2P.pfx"
      CA file name :   "TestU@contoso.com-P2P-CA.der"

#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [string]$PfxPassword,

        [Parameter(ParameterSetName='TokenAndKey',Mandatory=$True)]
        [String]$RefreshToken,
        [Parameter(ParameterSetName='TokenAndKey',Mandatory=$True)]
        [String]$SessionKey,
        [Parameter(Mandatory=$False)]
        [String]$Context,
        [Parameter(ParameterSetName='Settings',Mandatory=$True)]
        $Settings,
   
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [String]$TenantId,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [String]$DeviceName,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [Parameter(ParameterSetName='Certificate',Mandatory=$False)]
        [String]$OSVersion="10.0.18363.0",
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [Parameter(ParameterSetName='Certificate',Mandatory=$False)]
        [String[]]$DNSNames
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

        if($SessionKey -ne $null -and [string]::IsNullOrEmpty($Context))
        {
            # Create a random context
            $ctx = New-Object byte[] 24
            ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($ctx)
        }
        elseif($Context)
        {
            $ctx = Convert-B64ToByteArray -B64 $Context
        }

        if($Certificate -eq $null -and [string]::IsNullOrEmpty($PfxFileName) -eq $false)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        if(!$DNSNames)
        {
            $DNSNames = @($DeviceName)
        }

        if(!$TenantId)
        {
            $TenantId = (Read-Accesstoken $prtKeys.id_token).tid
        }

        # Get the nonce
        $nonce = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" -Body "grant_type=srv_challenge").Nonce

        # We are doing this with the existing device certificate
        if($Certificate)
        {
            # Get the private key
            $privateKey = Load-PrivateKey -Certificate $Certificate 
        
            # Initialize the Certificate Signing Request object
            $CN =  $Certificate.Subject
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($CN, $privateKey, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        
            # Create the signing request
            $csr = [convert]::ToBase64String($req.CreateSigningRequest())

            # B64 encode the public key
            $x5c = [convert]::ToBase64String(($certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)))

            # Create the header and body
            $hdr = [ordered]@{
                "alg" = "RS256"
                "typ" = "JWT"
                "x5c" = "$x5c"
            }

            $pld = [ordered]@{
                "client_id" =      "38aa3b87-a06d-4817-b275-7a316988d93b"
                "request_nonce" =  $nonce
                "win_ver" =        $OSVersion
                "grant_type" =     "device_auth"
                "cert_token_use" = "device_cert"
                "csr_type" =       "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
                "csr" =            $csr
                "netbios_name" =   $DeviceName
                "dns_names" =      $DNSNames
            }

            # Create the JWT
            $jwt = New-JWT -PrivateKey $privateKey -Header $hdr -Payload $pld
        
            # Construct the body
            $body = @{
                "windows_api_version" = "2.0"
                "grant_type"          = "urn:ietf:params:oauth:grant-type:jwt-bearer"
                "request"             = "$jwt"
            }
        }
        else # We are doing this with the PRT keys information
        {
            # Create a private key and do something with it to get it stored
            $rsa=[System.Security.Cryptography.RSA]::Create(2048)
                
            # Initialize the Certificate Signing Request object
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

            # Create the signing request
            $csr = [convert]::ToBase64String($req.CreateSigningRequest())

            # Create the header and body
            $hdr = [ordered]@{
                "alg" = "HS256"
                "typ" = "JWT"
                "ctx" = (Convert-ByteArrayToB64 -Bytes $ctx)
            }

            $pld = [ordered]@{
                "iss" =            "aad:brokerplugin"
                "grant_type" =     "refresh_token"
                "aud" =            "login.microsoftonline.com"
                "request_nonce" =  $nonce
                "scope" =          "openid aza ugs"
                "refresh_token" =  $RefreshToken
                "client_id" =      "38aa3b87-a06d-4817-b275-7a316988d93b"
                "cert_token_use" = "user_cert"
                "csr_type" =       "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
                "csr" =            $csr
            }

            # Create the JWT
            $jwt = New-JWT -Key (Get-PRTDerivedKey -Context $ctx -SessionKey (Convert-B64ToByteArray $SessionKey))  -Header $hdr -Payload $pld
        
            # Construct the body
            $body = @{
                "grant_type"          = "urn:ietf:params:oauth:grant-type:jwt-bearer"
                "request"             = "$jwt"
            }
        }

        # Make the request to get the P2P certificate
        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Body $body

        # Get the certificate
        $binCert = [byte[]](Convert-B64ToByteArray -B64 $response.x5c)

        # Create a new x509certificate 
        $P2PCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($binCert,"",[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $P2PCert.PrivateKey = $privateKey

        # Write the device P2P certificate to disk
        $certName = $P2PCert.Subject.Split(",")[0].Split("=")[1]
        $P2PCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx) | Set-Content "$certName-P2P.pfx" -Encoding Byte

        # Write the P2P certificate CA to disk
        $CA = @"
-----BEGIN PUBLIC KEY-----
$($response.x5c_ca)
-----END PUBLIC KEY-----
"@
        $CA | Set-Content "$certName-P2P-CA.der"

        if($Certificate)
        {
            # Unload the private key
            Unload-PrivateKey -PrivateKey $privateKey
        }

        # Print out information
        if($Certificate)
        {
            Write-Host "Device certificate successfully created:"
        }
        else
        {
            Write-Host "User certificate successfully created:"
        }
        Write-Host "  Subject:         ""$($P2PCert.Subject)"""
        if($Certificate)
        {
            Write-Host "  DnsNames:        ""$($P2PCert.DnsNameList.Unicode)"""
        }
        Write-Host "  Issuer:          ""$($P2PCert.Issuer)"""
        Write-Host "  Cert thumbprint: $($P2PCert.Thumbprint)"
        Write-host "  Cert file name : ""$certName-P2P.pfx"""
        Write-host "  CA file name :   ""$certName-P2P-CA.der"""

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
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory=$False)]
        [String]$OSVersion="10.0.18363.0"
    )
    Process
    {
        if(!$Certificate)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        # Get the private key
        $privateKey = Load-PrivateKey -Certificate $Certificate
              
        # B64 encode the public key
        $x5c = [convert]::ToBase64String(($certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)))

        # TenantId
        $tenantId = Get-TenantID -Domain $Credentials.UserName.Split("@")[1]

        $body = "grant_type=srv_challenge" 
        
        # Get the nonce
        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -Body $body
        $nonce = $response.Nonce
        Remove-Variable body

        # Construct the header
        $header = Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.GetBytes("{""alg"":""RS256"", ""typ"":""JWT"", ""x5c"":""$($x5c.Replace("/","\/"))""}")) -NoPadding

        # Construct the payload
        $payload = Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.GetBytes("{""client_id"":""38aa3b87-a06d-4817-b275-7a316988d93b"", ""request_nonce"":""$nonce"", ""scope"":""openid aza ugs"", ""win_ver"":""$OSVersion"", ""grant_type"":""password"", ""username"":""$($Credentials.UserName)"", ""password"":""$($Credentials.GetNetworkCredential().Password)""}")) -NoPadding

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
        }

        # Make the request
        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction SilentlyContinue

        if(!$response.token_type)
        {
            throw "Error getting session key. Check your credentials!"
        }

        # Decrypt the session key and add it to return value
        try
        {
            $sessionKey = Decrypt-PRTSessionKey -JWE $response.session_key_jwe -PrivateKey $privateKey
            $response | Add-Member -NotePropertyName "session_key" -NotePropertyValue (Convert-ByteArrayToB64 -Bytes $sessionKey)
        }
        catch
        {
            Write-Error $($_.Exception.Message)
        }

        # Write to file
        $outFileName = "$($Certificate.Subject.Split("=")[1]).json"
        $response | Set-Content $outFileName
        Write-Host "Keys saved to $outFileName"

        # Unload the private key
        Unload-PrivateKey -PrivateKey $privateKey

        # Return
        $response
    }
}