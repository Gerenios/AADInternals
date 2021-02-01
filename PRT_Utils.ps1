# Aug 21st 2020
function Register-DeviceToAzureAD
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$DeviceName,
        [Parameter(Mandatory=$False)]
        [String]$DeviceType,
        [Parameter(Mandatory=$False)]
        [String]$OSVersion,
        [Parameter(Mandatory=$False)]
        [Bool]$SharedDevice=$False,

        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$False)]
        [String]$DomainName,
        [Parameter(Mandatory=$False)]
        [Guid]$TenantId,
        [Parameter(Mandatory=$False)]
        [String]$DomainController,
        [Parameter(Mandatory=$False)]
        [String]$SID
    )
    Process
    {
        # If certificate provided, this is a Hybrid Join
        if($hybrid = $Certificate -ne $null)
        {
            # Load the "user" certificate private key
            try
            {
                $privateKey =  Load-PrivateKey -Certificate $Certificate
            }
            catch
            {
                Write-Error "Could not extract the private key from the given certificate!"
                return
            }

            $deviceId = $certificate.Subject.Split("=")[1]
            try
            {
                $deviceIdGuid = [Guid]$deviceId
            }
            catch
            {
                Write-Error "The certificate subject is not a valid device id (GUID)!"
                return
            }

            # Create the signature blob
            $clientIdentity =  "$($SID).$((Get-Date).ToUniversalTime().ToString("u"))"
            $bClientIdentity = [System.Text.Encoding]::ASCII.GetBytes($clientIdentity)
            $signedBlob =      $privateKey.SignData($bClientIdentity, "SHA256")
            $b64SignedBlob =   Convert-ByteArrayToB64 -Bytes $signedBlob
        }
        else
        {
            # Get the domain and tenant id
            $at_info =  Read-Accesstoken -AccessToken $AccessToken
            if([string]::IsNullOrEmpty($DomainName))
            { 
                $DomainName =   $at_info.upn.Split("@")[1]
            }
            $tenantId = [GUID]$at_info.tid

            $headers=@{"Authorization" = "Bearer $AccessToken"}
        }

        # Create a private key
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)

        # Initialize the Certificate Signing Request object
        $CN = "CN=7E980AD9-B86D-4306-9425-9AC066FB014A" 
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($CN, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        
        # Create the signing request
        $csr = Convert-ByteArrayToB64 -Bytes $req.CreateSigningRequest()

        # Use the public key as a transport key just to make things easier
        $transportKey = Convert-ByteArrayToB64 -Bytes $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)
        
        # Create the request body
        # JoinType 0 = Azure AD join,        transport key = public key
        # JoinType 4 = Azure AD registered,  transport key = RSA
        # JoinType 6 = Azure AD hybrid join, transport key = public key. Hybrid join this way is not supported, there must be an existing device with user cert.

        $body=@{
            "CertificateRequest" = @{
                "Type" = "pkcs10"
                "Data" = $csr
                }
            "Attributes" = @{
                "ReuseDevice" =     $true
                "ReturnClientSid" = $true
                "SharedDevice" =    $SharedDevice
                }
        }
        if($hybrid)
        {
            $body["JoinType"] = 6 # Hybrid Join
            $body["ServerAdJoinData"] = @{
                    "TransportKey" =           $transportKey
	                "TargetDomain" =           $DomainName
	                "DeviceType" =             $DeviceType
	                "OSVersion" =              $OSVersion
	                "DeviceDisplayName" =      $DeviceName
                    "SourceDomainController" = $DomainController
                    "TargetDomainId" =         $tenantId.ToString()
                    "ClientIdentity" =  @{
                        "Type" =               "sha256signed"
                        "Sid" =                $clientIdentity
                        "SignedBlob" =         $b64SignedBlob
                    }
                }
        }
        else
        {
            $body["JoinType"] = 0 # Join
            $body["TransportKey"] =      $transportKey
	        $body["TargetDomain"] =      $DomainName
	        $body["DeviceType"] =        $DeviceType
	        $body["OSVersion"] =         $OSVersion
	        $body["DeviceDisplayName"] = $DeviceName
                   
        }

        
        # Make the enrollment request
        try
        {
            if($hybrid)
            {
                $response = Invoke-RestMethod -Method Put -Uri "https://enterpriseregistration.windows.net/EnrollmentServer/device/$deviceId`?api-version=1.0" -Body $($body | ConvertTo-Json -Depth 5) -ContentType "application/json; charset=utf-8"
            }
            else
            {
                $response = Invoke-RestMethod -Method Post -Uri "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=1.0" -Headers $headers -Body $($body | ConvertTo-Json -Depth 5) -ContentType "application/json; charset=utf-8"
            }
        }
        catch
        {
            Write-Error $_
            return
        }

        Write-Debug "RESPONSE: $response"
        
        # Get the certificate
        $binCert = [byte[]] (Convert-B64ToByteArray -B64 $response.Certificate.RawBody)

        # Create a new x509certificate 
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($binCert,"",[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -band [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

        # Store the private key to so that it can be exported
        $cspParameters = [System.Security.Cryptography.CspParameters]::new()
        $cspParameters.ProviderName =    "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $cspParameters.ProviderType =    24
        $cspParameters.KeyContainerName ="AADInternals"
            
        # Set the private key
        $privateKey = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cspParameters)
        $privateKey.ImportParameters($rsa.ExportParameters($true))
        $cert.PrivateKey = $privateKey

        # Return
        $returnValue=@(
            $cert
            $response
        )
        
        return $returnValue
    }
}

# Aug 21st 2020
function Sign-JWT
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.RSA]$PrivateKey,
        [Parameter(Mandatory=$False)]
        [Byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        if($PrivateKey)
        {
            # Sign the JWT (RS256)
            $signature = $PrivateKey.SignData($Data, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }
        else
        {
            # Sign the JWT (HS256)
            $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList @(,$Key)
            $signature = $hmac.ComputeHash($Data)
        }

        # Return
        return $signature
    }
}

# Aug 22nd 2020
# Parses the JWE and decrypts the session key
function Decrypt-PRTSessionKey
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$JWE,
        [Parameter(Mandatory=$True)]
        [System.Security.Cryptography.RSA]$PrivateKey
    )
    Process
    {
        # Get the encoded key
        $parts =   $JWE.Split(".")
        $header =  [text.encoding]::UTF8.GetString((Convert-B64ToByteArray -B64 $parts[0])) | ConvertFrom-Json
        $encKey =  Convert-B64ToByteArray -B64 $parts[1]
        # The following could be used to decode the encData (and verify the encryption key) but can't do A256GCM with C#
        #$IV =      Convert-B64ToByteArray -B64 $parts[2]
        #$encData = Convert-B64ToByteArray -B64 $parts[3] 
        #$tag =     Convert-B64ToByteArray -B64 $parts[4]

        Write-Verbose "JWE: enc=$($header.enc), alg=$($header.alg)"

        try
        {
            # Do the magic
            $deFormatter = [System.Security.Cryptography.RSAOAEPKeyExchangeDeformatter]::new($privateKey)
            $deckey =      $deFormatter.DecryptKeyExchange($encKey)
        }
        catch
        {
            throw "Decrypting the session key failed: ""$($_.Exception.InnerException.Message)"". Are you using the correct certificate (transport key)?"
        }

        # Return 
        return $decKey
    }
}

# Aug 24th 2020
# Derives a 32 byte key using the given context and session key
function Get-PRTDerivedKey
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Byte',Mandatory=$True)]
        [byte[]]$Context,
        [Parameter(ParameterSetName='Byte',Mandatory=$True)]
        [byte[]]$SessionKey,
        [Parameter(ParameterSetName='B64',Mandatory=$True)]
        [string]$B64Context,
        [Parameter(ParameterSetName='B64',Mandatory=$True)]
        [string]$B64SessionKey,
        [Parameter(ParameterSetName='Hex',Mandatory=$True)]
        [string]$HexContext,
        [Parameter(ParameterSetName='Hex',Mandatory=$True)]
        [string]$HexSessionKey
    )
    Process
    {
        if($B64Context)
        {
            $Context =    Convert-B64ToByteArray $B64Context
            $SessionKey = Convert-B64ToByteArray $B64SessionKey
        }
        elseif($HexContext)
        {
            $Context =    Convert-HexToByteArray $HexContext
            $SessionKey = Convert-HexToByteArray $HexSessionKey
        }

        # Fixed label
        $label = [text.encoding]::UTF8.getBytes("AzureAD-SecureConversation")

        # Derive the decryption key using a standard NIST SP 800-108 KDF
        # As the key size is only 32 bytes (256 bits), no need to loop :)
        $computeValue = @(0x00,0x00,0x00,0x01) + $label + @(0x00) + $Context + @(0x00,0x00,0x01,0x00)
        $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList @(,$SessionKey)
        $hmacOutput = $hmac.ComputeHash($computeValue)

        Write-Verbose "DerivedKey: $(Convert-ByteArrayToHex $hmacOutput)"
        
        # Return
        $hmacOutput
    }
}

# Get the access token with PRT
# Aug 20th 2020
function Get-AccessTokenWithPRT
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Cookie,
        [Parameter(Mandatory=$True)]
        [String]$Resource,
        [Parameter(Mandatory=$True)]
        [String]$ClientId,
        [Parameter(Mandatory=$False)]
        [String]$RedirectUri="urn:ietf:wg:oauth:2.0:oob",
        [switch]$GetNonce
    )
    Process
    {
        $parsedCookie = Read-Accesstoken $Cookie

        # Create parameters
        $mscrid =    (New-Guid).ToString()
        $requestId = $mscrid

        
        # Create url and headers
        $url = "https://login.microsoftonline.com/Common/oauth2/authorize?resource=$Resource&client_id=$ClientId&response_type=code&redirect_uri=$RedirectUri&client-request-id=$requestId&mscrid=$mscrid"

        # Add sso_nonce if exist
        if($parsedCookie.request_nonce)
        {
            $url += "&sso_nonce=$sso_nonce"
        }

        $headers = @{
            "User-Agent" = ""
            "x-ms-RefreshTokenCredential" = $Cookie
            }

        # First, make the request to get the authorisation code (tries to redirect so throws an error)
        $response = Invoke-RestMethod -Uri $url -Headers $headers -MaximumRedirection 0 -ErrorAction SilentlyContinue

        Write-Debug "RESPONSE: $($response.OuterXml)"

        # Try to parse the code from the response
        if($response.html.body.script)
        {
            $values = $response.html.body.script.Split("?").Split("\")
            foreach($value in $values)
            {
                $row=$value.Split("=")
                if($row[0] -eq "code")
                {
                    $code = $row[1]
                    Write-Verbose "CODE: $code"
                    break
                }
            }
        }
        

        if(!$code)
        {
            if($response.html.body.h2.a.href -ne $null)
            {
                $values = $response.html.body.h2.a.href.Split("&")
                foreach($value in $values)
                {
                    $row=$value.Split("=")
                    if($row[0] -eq "sso_nonce")
                    {
                        $sso_nonce = $row[1]
                        if($GetNonce)
                        {
                            # Just return the nonce
                            return $sso_nonce
                        }
                        else
                        {
                            # Invalid PRT, nonce is reuired
                            Write-Warning "Nonce needed. Try New-AADIntUserPRTToken with -GetNonce switch or -Nonce $sso_nonce parameter"
                            break
                        }
                    }
                }
                
            }
            
            throw "Code not received!"
        }

        # Create the body
        $body = @{
            client_id =    $ClientId
            grant_type =   "authorization_code"
            code =         $code
            redirect_uri = $RedirectUri
        }

        # Make the second request to get the access token
        $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body $body -ContentType "application/x-www-form-urlencoded" -Method Post

        Write-Debug "ACCESS TOKEN: $($response.access_token)"
        Write-Debug "REFRESH TOKEN: $($response.refresh_token)"

        # Return
        return $response
            
    }
}

# Get the access token with BPRT
# Jan 10th 2021
function Get-AccessTokenWithBPRT
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$BPRT,
        [Parameter(Mandatory=$True)]
        [String]$Resource,
        [Parameter(Mandatory=$True)]
        [String]$ClientId
    )
    Process
    {
        Get-AccessTokenWithRefreshToken -Resource "urn:ms-drs:enterpriseregistration.windows.net" -ClientId "b90d5b8f-5503-4153-b545-b31cecfaece2" -TenantId "Common" -RefreshToken $BPRT
    }
}

# Get the token with deviceid claim
# Aug 28th
function Set-AccessTokenDeviceAuth
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [bool]$BPRT,
        [Parameter(Mandatory=$False)]
        [string]$AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$RefreshToken,

        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory=$False)]
        [string]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword
    )
    Process
    {
        if(!$Certificate)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        if($BPRT)
        {
            # Fixed values for BPRT to get access token for Intune MDM
            $clientId = "b90d5b8f-5503-4153-b545-b31cecfaece2"
            $resource = "https://enrollment.manage.microsoft.com/" 
        }
        else
        {
            # This is the only supported client id :(
            $clientId = "29d9ed98-a469-4536-ade2-f981bc1d605e"

            # Get the claims from the access token to get the resource
            $claims = Read-Accesstoken -AccessToken $AccessToken
            $resource = $claims.aud
        }
        
        # Get the private key
        $privateKey = Load-PrivateKey -Certificate $Certificate 

        $body=@{
            "grant_type" =          "srv_challenge"
            "windows_api_version" = "2.0"
            "client_id" =           $clientId
            "redirect_uri" =        "ms-appx-web://Microsoft.AAD.BrokerPlugin/DRS"
            "resource" =            $resource
        }

        if($BPRT)
        {
            $body.Remove("redirect_uri")
        }
                
        # Get the nonce
        $nonce = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body $body).Nonce

        # B64 encode the public key
        $x5c = Convert-ByteArrayToB64 -Bytes ($certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

        # Create the header and body
        $hdr = [ordered]@{
            "alg" = "RS256"
            "typ" = "JWT"
            "x5c" = "$x5c"
        }

        $OSVersion="10.0.18362.997"

        $pld = [ordered]@{
            "win_ver" =       $OSVersion
            "resource" =      $resource
            "scope" =         "openid aza"
            "request_nonce" = $nonce
            "refresh_token" = $RefreshToken
            "redirect_uri" =  "ms-appx-web://Microsoft.AAD.BrokerPlugin/DRS"
            "iss" =           "aad:brokerplugin"
            "grant_type" =    "refresh_token"
            "client_id" =     $clientId
        }

        if($BPRT)
        {
            $pld.Remove("redirect_uri")
            $pld["scope"] = "openid"
        }

        # Create the JWT
        $jwt = New-JWT -PrivateKey $privateKey -Header $hdr -Payload $pld
        
        # Construct the body
        $body = @{
            "windows_api_version" = "2.0"
            "grant_type"          = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            "request"             = "$jwt"
        }

        # Make the request to get the new access token
        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        
        if($BPRT)
        {
            $response | Add-Member -NotePropertyName "refresh_token" -NotePropertyValue $RefreshToken
        }

        Write-Debug "ACCESS TOKEN: $($response.access_token)"
        Write-Debug "REFRESH TOKEN: $($response.refresh_token)"

        # Return
        return $response
            
    }
}

function New-JWT
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='PrivateKey', Mandatory=$True)]
        [System.Security.Cryptography.RSA]$PrivateKey,
        [Parameter(ParameterSetName='Key',Mandatory=$True)]
        [Byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [Hashtable]$Header,
        [Parameter(Mandatory=$True)]
        [Hashtable]$Payload
    )
    Process
    {
        # Construct the header
        $txtHeader =  ($Header  | ConvertTo-Json -Compress).Replace("/","\/")
        $txtPayload = ($Payload | ConvertTo-Json -Compress).Replace("/","\/")

        # Convert to B64 and strip the padding
        $b64Header =  (Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.getBytes($txtHeader))).replace("=","")
        $b64Payload = (Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.getBytes($txtPayload))).replace("=","")

        # Construct the JWT data to be signed
        $binData = [text.encoding]::UTF8.GetBytes(("{0}.{1}" -f $b64Header,$b64Payload))

        # Get the signature
        $Binsig = Sign-JWT -PrivateKey $PrivateKey -Key $Key -Data $binData
        $B64sig = Convert-ByteArrayToB64 -Bytes $Binsig -UrlEncode

        # Construct the JWT
        $jwt = "{0}.{1}.{2}" -f $b64Header,$b64Payload,$B64sig

        # Return
        return $jwt
    }
}

function Get-PRTKeyInfo
{
    [cmdletbinding()]
    Param(
        

        [Parameter(ParameterSetName='PrivateKey',Mandatory=$True)]
        [byte[]]$PrivateKey
    )
    Process
    {


        # Create a random context
        $ctx = New-Object byte[] 24
        ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($context)

        # Get the private key
        $privateKey = Load-PrivateKey -Certificate $Certificate 

        $body=@{
            "grant_type" =          "srv_challenge"
            "windows_api_version" = "2.0"
            "client_id" =           $ClientId
            "redirect_uri" =        $RedirectUri
            "resource" =            $Resource
        }
        
        # Get the nonce
        $nonce = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body $body).Nonce

        # B64 encode the public key
        $x5c = Convert-ByteArrayToB64 -Bytes ($certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

        # Create the header and body
        $hdr = [ordered]@{
            "alg" = "RS256"
            "typ" = "JWT"
            "x5c" = "$x5c"
        }

        $OSVersion="10.0.18362.997"

        $pld = [ordered]@{
            "win_ver" =       $OSVersion
            "resource" =      $Resource
            "scope" =         "openid aza"
            "request_nonce" = $nonce
            "refresh_token" = $RefreshToken
            "redirect_uri" =  $RedirectUri
            "iss" =           "aad:brokerplugin"
            "grant_type" =    "refresh_token"
            "client_id" =     $ClientId
        }

        # Create the JWT
        $jwt = New-JWT -PrivateKey $privateKey -Header $hdr -Payload $pld
        
        # Construct the body
        $body = @{
            "windows_api_version" = "2.0"
            "grant_type"          = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            "request"             = "$jwt"
        }

        # Make the request to get the P2P certificate
        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Body $body


        
        Write-Debug "ACCESS TOKEN: $($response.access_token)"
        Write-Debug "REFRESH TOKEN: $($response.refresh_token)"

        # Return
        return $response
            
    }
}