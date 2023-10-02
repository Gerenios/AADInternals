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
        [String]$SID,
        [Parameter(Mandatory=$False)]
        [Bool]$RegisterOnly=$false
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
                if($at_info.upn)
                {
                    $DomainName = $at_info.upn.Split("@")[1]
                }
                else 
                {
                    # Access Token fetched with SAML token so no upn
                    # "unique_name" = "http://<domain>/adfs/services/trust/#"
                    $DomainName = $at_info.unique_name.split("/")[2]
                    $hybridSAML = $true
                }
            }
            $tenantId = [GUID]$at_info.tid

            $headers=@{"Authorization" = "Bearer $AccessToken"}
        }

        # Create a private key
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)

        # Initialize the Certificate Signing Request object
        $CN =  "CN=7E980AD9-B86D-4306-9425-9AC066FB014A" 
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($CN, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        
        # Create the signing request
        $csr = Convert-ByteArrayToB64 -Bytes $req.CreateSigningRequest()

        # Use the device private key as a transport key just to make things simpler
        $transportKey = Convert-ByteArrayToB64 -Bytes $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)
        
        # Create the request body
        # JoinType 0 = Azure AD join,        transport key = device key
        # JoinType 4 = Azure AD registered,  transport key = device key
        # JoinType 6 = Azure AD hybrid join, transport key = device key. Hybrid join this way is not supported, there must be an existing device with user cert.

        $body=@{
            "CertificateRequest" = @{
                "Type" = "pkcs10"
                "Data" = $csr
                }
            "Attributes" = @{
                "ReuseDevice" =     "$true"
                "ReturnClientSid" = "$true"
                "SharedDevice" =    "$SharedDevice"
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
            if($hybridSAML)
            {
                $body["JoinType"] =      6 # Hybrid Join
            }
            elseif($RegisterOnly)
            {
                $body["JoinType"] =      4 # Register
            }
            else
            {
                $body["JoinType"] =      0 # Join
            }
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
                $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri "https://enterpriseregistration.windows.net/EnrollmentServer/device/$deviceId`?api-version=1.0" -Body $($body | ConvertTo-Json -Depth 5) -ContentType "application/json; charset=utf-8"
            }
            else
            {
                $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=1.0" -Headers $headers -Body $($body | ConvertTo-Json -Depth 5) -ContentType "application/json; charset=utf-8"
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
            $hmac.Dispose()
        }

        # Return
        return $signature
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
        [String]$RedirectUri,
        [switch]$GetNonce,
        [Parameter(Mandatory=$False)]
        [String]$Tenant
    )
    Process
    {
        # If no tenant is given, use Common
        if([string]::IsNullOrEmpty($Tenant))
        {
            $Tenant = "Common"
        }

        $parsedCookie = Read-Accesstoken $Cookie

        #Set RedirectURI
        if([string]::IsNullOrEmpty($RedirectUri))
        {
            $RedirectUri = Get-AuthRedirectUrl -ClientID $ClientId -Resource $Resource
        }

        # Create parameters
        $mscrid =    (New-Guid).ToString()
        $requestId = $mscrid
        
        # Create url and headers
        $url = "https://login.microsoftonline.com/$Tenant/oauth2/authorize?resource=$Resource&client_id=$ClientId&response_type=code&redirect_uri=$RedirectUri&client-request-id=$requestId&mscrid=$mscrid"

        # Add sso_nonce if exist
        if($parsedCookie.request_nonce)
        {
            $url += "&sso_nonce=$($parsedCookie.request_nonce)"
        }

        $headers = @{
            "User-Agent" = ""
            "x-ms-RefreshTokenCredential" = $Cookie
            }

        # First, make the request to get the authorisation code (tries to redirect so throws an error)
        $response = Invoke-WebRequest -UseBasicParsing -Uri $url -Headers $headers -MaximumRedirection 0 -ErrorAction SilentlyContinue

        $code = Parse-CodeFromResponse -Response $response
        
        if(!$code)
        {
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
        $response = Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body $body -ContentType "application/x-www-form-urlencoded" -Method Post

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
        [string]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [string]$TransportKeyFileName
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
        if($TransportKeyFileName)
        {       
            # Get the transport key from the provided file 
            $tkPEM = (Get-Content $TransportKeyFileName) -join "`n"
            $tkParameters = Convert-PEMToRSA -PEM $tkPEM
            $privateKey = [System.Security.Cryptography.RSA]::Create($tkParameters)
        }
        else
        {
            $privateKey = Load-PrivateKey -Certificate $Certificate 
        }

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
        $nonce = (Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body $body).Nonce

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
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        
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
        [System.Collections.Specialized.OrderedDictionary]$Header,
        [Parameter(Mandatory=$True)]
        [System.Collections.Specialized.OrderedDictionary]$Payload
    )
    Process
    {
        # Construct the header
        $txtHeader =  $Header  | ConvertTo-Json -Compress
        $txtPayload = $Payload | ConvertTo-Json -Compress

        # Convert to B64 and strip the padding
        $b64Header =  Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.getBytes($txtHeader )) -NoPadding
        $b64Payload = Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.getBytes($txtPayload)) -NoPadding

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
        $nonce = (Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body $body).Nonce

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

        # Make the request to get the PRT key information
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        
        Write-Debug "ACCESS TOKEN: $($response.access_token)"
        Write-Debug "REFRESH TOKEN: $($response.refresh_token)"

        # Return
        return $response
            
    }
}

# Parses the given JWE
# Dec 22nd 2021
Function Parse-JWE
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$True,ValueFromPipeline)]
        [String]$JWE
    )
    process
    {
        $parts = $JWE.Split(".")
        if($parts.Count -ne 5)
        {
            Throw "Invalid JWE: $($parts.Count) parts, expected 5"
        }

        # Decode and parse the header
        $parsedJWT = Convert-B64ToText -B64 $parts[0] | ConvertFrom-Json 
        # Add other parts
        $parsedJWT | Add-Member -NotePropertyName "Key"        -NotePropertyValue $parts[1]
        $parsedJWT | Add-Member -NotePropertyName "Iv"         -NotePropertyValue $parts[2]
        $parsedJWT | Add-Member -NotePropertyName "CipherText" -NotePropertyValue $parts[3]
        $parsedJWT | Add-Member -NotePropertyName "Tag"        -NotePropertyValue $parts[4]
        
        return $parsedJWT
    }
}

# Decrypt the given JWE
# Dec 22nd 2021
Function Decrypt-JWE
{

    [cmdletbinding()]

    param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [String]$JWE,
        [Parameter(Mandatory=$True,ParameterSetName = "RSA")]
        [System.Security.Cryptography.RSA]$PrivateKey,
        [Parameter(Mandatory=$False,ParameterSetName = "RSA")]
        [bool]$returnKey = $true,
        [Parameter(Mandatory=$True,ParameterSetName = "Key")]
        [byte[]]$Key,
        [Parameter(Mandatory=$True,ParameterSetName = "SessionKey")]
        [byte[]]$SessionKey
    )
    process
    {
        $parsedJWE = Parse-JWE -JWE $JWE

        $alg = $parsedJWE.alg

        # If this is refresh_token or code, use RSA-OAEP
        if([string]::IsNullOrEmpty($alg) -and $parsedJWE.ser -eq "1.0")
        {
            $alg = "RSA-OAEP"
        }
        elseif($parsedJWE.enc -ne "A256GCM")
        {
            Throw "Unsupported enc: $enc"
        }

        # Decrypt data using symmetric key
        if($alg -eq "dir") 
        {
            # Derive decryption key from the session key and context
            if($SessionKey)
            {
                if(!$parsedJWE.ctx)
                {
                    Throw "Missing ctx, unable to derive encryption key!"
                }
                $context = Convert-B64ToByteArray -B64 $parsedJWE.ctx
                $key     = Get-PRTDerivedKey -SessionKey $SessionKey -Context $context
            }

            if(!$parsedJWE.Iv -or !$parsedJWE.CipherText)
            {
                Throw "Missing Iv and/or CipherText, unable to decrypt!"
            }
            
            $iv      = Convert-B64ToByteArray -B64 $parsedJWE.Iv
            $encData = Convert-B64ToByteArray -B64 $parsedJWE.CipherText

            # Create the crypto provider. 
            # The data is always encrypted using A256CBC instead of A256GCM, because AesCryptoServiceProvider does not support GCM mode.
            $cryptoProvider     = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
            $cryptoProvider.Key = $Key
            $cryptoProvider.iv  = $iv

            # Create a crypto stream
            $buffer = [System.IO.MemoryStream]::new()
            $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($buffer, $cryptoProvider.CreateDecryptor($Key,$iv),[System.Security.Cryptography.CryptoStreamMode]::Write)

            # Decrypt the data
            $cryptoStream.Write($encData,0,$encData.Count)
            $cryptoStream.FlushFinalBlock()
            $decData = $buffer.ToArray()

            # Clean up
            $cryptoStream.Dispose()
            $cryptoProvider.Dispose()

            return $decData
        }
        elseif($alg -eq "RSA-OAEP") # Decrypt data using encrypted key
        {
            if(!$PrivateKey)
            {
                Throw "PrivateKey required for RSA-OAEP encrypted JWE"
            }

            try
            {
                # Decrypt the content encryption key (CEK)
                $encKey = Convert-B64ToByteArray -B64 $parsedJWE.Key
                $CEK    = [System.Security.Cryptography.RSAOAEPKeyExchangeDeformatter]::new($privateKey).DecryptKeyExchange($encKey)

                # Extract the parameters
                $iv      = Convert-B64ToByteArray -B64 $parsedJWE.Iv
                $encData = Convert-B64ToByteArray -B64 $parsedJWE.CipherText
                $tag     = Convert-B64ToByteArray -B64 $parsedJWE.Tag
                $keyParameter = [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($CEK)

                # Append Tag to Encrypted data
                $buffer = New-Object byte[] ($encData.Count + $tag.Count)
                [Array]::Copy($encData,0,$buffer,0             ,$encData.Count)
                [Array]::Copy($tag    ,0,$buffer,$encData.Count,$tag.Count)
                $encData = $buffer

                # Create & init block cipher. This data is correctly encrypted with A256GCM.
                $AEADParameters = [Org.BouncyCastle.Crypto.Parameters.AeadParameters]::new($keyParameter,128,$iv)
                $GCMBlockCipher = [Org.BouncyCastle.Crypto.Modes.GcmBlockCipher]::new([Org.BouncyCastle.Crypto.Engines.AesFastEngine]::new())
                $GCMBlockCipher.init($false, $AEADParameters)

                # Create an array for the decrypted data
                $decData = New-Object byte[] $GCMBlockCipher.GetOutputSize($encData.Count)

                # Decrypt the data
                $res = $GCMBlockCipher.ProcessBytes($encData, 0, $encData.Count, $decData, 0)
                $res = $GCMBlockCipher.DoFinal($decData, $res)
                
                # Return the key instead of data
                if($returnKey)
                {
                    # With session_key_jwe the decrypted data seems always to be one byte: 32
                    if($decData[0] -ne 32)
                    {
                        Write-Warning "Decrypted data was not 32. Key may be invalid."
                    }

                    $retVal = $CEK
                }
                else
                {
                    # De-deflate
                    if($parsedJWE.zip -eq "Deflate")
                    {
                        $retVal = Get-DeDeflatedByteArray -byteArray $decData
                    }
                    else
                    {
                        $retVal = $decData
                    }
                }

                # Return
                return $retVal
            }
            catch
            {
                throw "Decrypting the key failed: ""$($_.Exception.InnerException.Message)"". Are you using the correct certificate or key?"
            }
        }
        else
        {
            Throw "Unsupported alg: $alg"
        }
    }
}

# Derivate KDFv2 context
# Mar 3rd 2022
function Get-KDFv2Context
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$Context,
        [Parameter(Mandatory=$True)]
        [System.Collections.Specialized.OrderedDictionary]$Payload
    )
    Begin
    {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
    }
    Process
    {
        # KDFv2 (Key Derivation Function v2) uses different context: SHA256(ctx || assertion payload)
        # We need to compute SHA256 hash from a byte array combined from context and payload.
        # Ref: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/89dfb8d6-23b8-4963-8908-91b34340e367

        # Get payload bytes
        $pldBytes = [text.encoding]::UTF8.getBytes(($Payload | ConvertTo-Json -Compress))

        # Create a buffer
        $buffer = New-Object byte[] ($Context.Count + $pldBytes.Count)

        # Copy context and payload to buffer
        [array]::Copy($Context ,0,$buffer,0             ,$Context.Count)
        [array]::Copy($pldBytes,0,$buffer,$Context.Count,$pldBytes.Count)
        
        # Return SHA256 hash
        return $sha256.ComputeHash($buffer)
    }
    End
    {
        $sha256.Dispose()
    }
}

# Parses the Cloud AP Cache Data CacheData
# C:\Windows\system32\config\systemprofile\AppData\local\microsoft\windows\CloudAPCache\AzureAD\<hash>\cache\cachedata
# May 31st 2023
function Parse-CloudAPCacheData
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    
    Process
    {
        # Parse the header
        $p = 0;
        $version =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        if($version -ne 2)
        {
            Throw "Invalid version: $version. Was expecting 2."
        }

        $hash    =  $Data[($p)..($p-1 + 32)];                 $p += 32
        $p       += 8
        $dataLen =  [System.BitConverter]::ToInt64($Data,$p); $p += 8

        Write-Verbose "CacheData version:      $version"
        Write-Verbose "CacheData SHA256:       $(Convert-ByteArrayToHex -Bytes $hash)"
        Write-Verbose "CacheData length:       $dataLen"

        # As I don't know the structure of the header so we need to find values based on what we know.

        # Guid starts at 0x38
        $p = 0x38
        $keyId = [guid][byte[]]$Data[($p)..($p-1 + 16)];     $p += 16

        # The size of the encrypted blob seems to be at 0x60
        $p = 0x60
        $encDataSize = [System.BitConverter]::ToInt32($Data,$p); $p += 4

        # Then we have a part of header we don't know. So we need to find the correct place.
        # Structure is:
        # encKeySize, encKey, encDataSize, encData

        # Length of the key seems to be always 0x30 so let's loop until we found the correct place.
        while($p -lt $dataLen)
        {
            $encKeySize = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            if($encKeySize -eq 0x30)
            {
                # If the encrypted key is followed by the encrypted data size, we found the correct location
                if([System.BitConverter]::ToInt32($Data,$p + 0x30) -eq $encDataSize)
                {
                    break
                }
            }
        }

        Write-Verbose "EncryptedKey length:    $encKeySize"
        $encKey     = $Data[($p)..($p-1 + $encKeySize)];        $p += $encKeySize

        $encDataSize = [System.BitConverter]::ToInt32($Data,$p); $p += 4
        Write-Verbose "EncryptedData length:   $encDataSize"
        $encData     = $Data[($p)..($p-1 + $encDataSize)];       $p += $encDataSize

        Write-Verbose "CacheData key id:       $keyId"

        return [pscustomobject]@{
            "EncryptedKey"  = $encKey
            "EncryptedData" = $encData
            "Id"            = $guid
        }
        
     }
}

# Parses the decrypted data blob from CacheData
# Jun 2nd 2023
function Parse-CloudAPCacheDataBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    
    Process
    {
        # Parse the header
        $p = 0;
        $version =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        if($version -ne 0)
        {
            Throw "Invalid version: $version. Was expecting 0."
        }

        $unk01   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk02   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk03   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk04   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk05   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk06   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk07   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4

        $keyId   =  [guid][byte[]]$Data[($p)..($p-1 + 16)];   $p += 16
        $id1     =  $Data[($p)..($p-1 + 32)];                 $p += 32
        $id2     =  $Data[($p)..($p-1 + 32)];                 $p += 32

        Write-Verbose "CacheData blob version: $version"
        Write-Verbose "CacheData key id:       $keyId"
        Write-Verbose "CacheData blob ID1?:    $(Convert-ByteArrayToHex -Bytes $id1)"
        Write-Verbose "CacheData blob ID2?:    $(Convert-ByteArrayToHex -Bytes $id2)"
        
        # Return the payload
        return $Data[$p..$($Data.Length)]
     }
}

# Decrypts POP Key (Session Key) blob using DPAPI
# May 31st 2023
function Unprotect-POPKeyBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    Begin
    {
        # Load system.security assembly
        Add-Type -AssemblyName System.Security
    }
    Process
    {
        # Parse the header
        $p = 0;
        $version =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $type    =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        Write-Verbose "SessionKey version: $version"
        Write-Verbose "SessionKey type:    $type"
        if($type -ne 1)
        {
            Throw "Only software key (type 1) can be exported."
        }

        # Get the key
        $key = $Data[$p..$($Data.Count)]
        
        # Decrypt using DPAPI
        return [Security.Cryptography.ProtectedData]::Unprotect($key,$null,'LocalMachine')
     }
}

# Get logged in user's PRT and Session key from CloudAP CacheData
# Jun 2nd 2023
function Get-UserPRTKeysFromCloudAP
{
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='Password',Mandatory=$true)]
        [byte[]]$Password,
        [Parameter(ParameterSetName='Password',Mandatory=$true)]
        [string]$Username
    )
    Begin
    {
        $WAM_AAD = "B16898C6-A148-4967-9171-64D755DA8520"
        $WAM_MSA = "D7F9888F-E3FC-49b0-9EA6-A85B5F392A4F"

        # Check that we are administrators
        Test-LocalAdministrator -Throw

        # Elevate to LOCAL SYSTEM
        $CurrentUser = "{0}\{1}" -f $env:USERDOMAIN,$env:USERNAME
        Write-Warning "Elevating to LOCAL SYSTEM. You MUST restart PowerShell to restore $CurrentUser rights."
        try
        {
            $status = [AADInternals.Native]::copyLsassToken()
        }
        catch
        {
            Write-Verbose $_.Exception.InnerException
            Throw "Unable to elevate: $($_.Exception.InnerException.Message). Use -Verbose switch for details."
        }
        
    }
    Process
    {
        if($Credentials)
        {
            $Username = $Credentials.UserName
        }

        # Find the user from registry
        $name2SidPath = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache\$WAM_AAD\Name2Sid\"
        $name2SidKey = Get-Item -Path $name2SidPath -ErrorAction SilentlyContinue
        
        if($name2SidKey)
        {
            $users = $name2SidKey.GetSubKeyNames()
        }

        if($users -eq $null)
        {
            Throw "No users found from CacheData"
        }

        foreach($user in $users)
        {
            if((Get-ItemPropertyValue -Path "$name2SidPath$user" -Name IdentityName) -eq $username)
            {
                # We found the user from registry. Get the cachedir from the key name.
                $cacheDir = (Get-Item -Path "$name2SidPath$user").PSChildName
                Write-Verbose "Cachedir:               $cacheDir"

                # Create the cache data file path
                $cacheDataFile = "$env:SystemRoot\system32\config\systemprofile\AppData\local\microsoft\windows\CloudAPCache\AzureAD\$cacheDir\Cache\CacheData"
                break
            }
        }

        if([string]::IsNullOrEmpty($cacheDataFile))
        {
            Throw "CacheData not found for user $Username"
        }
        
        # Parse CacheData
        $cacheData = Parse-CloudAPCacheData -Data (Get-BinaryContent -Path $cacheDataFile)

        # Get the encrypted blobs
        $encryptedKey  = $cacheData.EncryptedKey
        $encryptedData = $cacheData.EncryptedData
        
        # Hey come on Microsoft..
        $defaultIV = @(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

        if($Password)
        {
            # Derive the key from the given "system" password
            $derivedKey = [AADInternals.Native]::getPBKDF2($Password)
            
            Write-Verbose "Derived key:            $(Convert-ByteArrayToHex -Bytes $derivedKey)"

            # Decrypt the secret using derived key
            $aes     = New-Object -TypeName System.Security.Cryptography.AesCryptoServiceProvider
            $aes.Key = $derivedKey
            $aes.IV  = $defaultIV
            $dc      = $aes.CreateDecryptor()
            $secret  = $dc.TransformFinalBlock($encryptedKey,0,$encryptedKey.Length)
        }
        else
        {
            # The secret is actually derived from the user's password, so we can use that (if known)
            $secret = [AADInternals.Native]::getPBKDF2([text.encoding]::Unicode.GetBytes($Credentials.GetNetworkCredential().Password))
        }

        Write-Verbose "Secret:                 $(Convert-ByteArrayToHex -Bytes $secret)"

        # Decrypt the data blob with the secret
        $aes      = New-Object -TypeName System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key  = $secret
        $aes.IV   = $defaultIV
        $dc       = $aes.CreateDecryptor()
        $dataBlob = $dc.TransformFinalBlock($encryptedData,0,$encryptedData.Length)

        # Parse the data blob
        $prtBytes = Parse-CloudAPCacheDataBlob -Data $dataBlob 
        $prt      = [text.encoding]::UTF8.GetString($prtBytes) | ConvertFrom-Json

        # Decode PRT
        $prt | Add-Member -NotePropertyName "refresh_token" -NotePropertyValue (Convert-B64ToText -B64 $prt.prt)

        # Decrypt POP Key (Session Key) using DPAPI
        $prt | Add-Member -NotePropertyName "session_key" -NotePropertyValue (Convert-ByteArrayToB64 -Bytes (Unprotect-POPKeyBlob -Data (Convert-B64ToByteArray -B64 $prt.ProofOfPossesionKey.KeyValue)))
        
        return $prt
    }
}

# Creates a new JWE
# Sep 12th 2023
Function New-JWE
{

    [cmdletbinding()]

    param(
        [Parameter(Mandatory=$True,ParameterSetName = "RSA")]
        [System.Security.Cryptography.RSA]$PublicKey,
        [Parameter(Mandatory=$True)]
        [byte[]]$Payload,
        [Parameter(Mandatory=$True)]
        [string]$Header,
        [Parameter(Mandatory=$False)]
        [byte[]]$InitialVector = (Get-RandomBytes -Bytes 12),
        [Parameter(Mandatory=$False)]
        [byte[]]$CEK = (Get-RandomBytes -Bytes 32)
    )
    process
    {
        # Parse & create binary header
        $parsedHeader = $header | ConvertFrom-Json
        $binHeader = [text.encoding]::UTF8.getBytes($header)
        
        $alg = $parsedHeader.alg

        # If this is refresh_token or code, use RSA-OAEP
        if([string]::IsNullOrEmpty($alg) -and $parsedHeader.ser -eq "1.0")
        {
            $alg = "RSA-OAEP"
        }
        elseif($parsedJWE.enc -ne "A256GCM")
        {
            Throw "Unsupported enc: $enc"
        }

        # Encrypt data using encrypted key
        if($alg -eq "RSA-OAEP") 
        {
            if(!$PublicKey)
            {
                Throw "PublicKey required for RSA-OAEP encrypted JWE"
            }

            try
            {
                $decData = $Payload

                # Encrypt the CEK
                $encKey = [System.Security.Cryptography.RSAOAEPKeyExchangeFormatter]::new($PublicKey).CreateKeyExchange($CEK)

                $keyParameter = [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($CEK)

                # Create & init block cipher. This data is correctly encrypted with A256GCM.
                $AEADParameters = [Org.BouncyCastle.Crypto.Parameters.AeadParameters]::new($keyParameter,128,$InitialVector)
                $GCMBlockCipher = [Org.BouncyCastle.Crypto.Modes.GcmBlockCipher]::new([Org.BouncyCastle.Crypto.Engines.AesFastEngine]::new())
                $GCMBlockCipher.init($true, $AEADParameters)
            
                # Create an array for the encrypted data
                $tag     = New-Object byte[] 16
                $encData = New-Object byte[] $GCMBlockCipher.GetOutputSize($decData.Count)

                # Encrypt the data
                $res = $GCMBlockCipher.ProcessBytes($decData, 0, $decData.Count, $encData, 0)
                $res = $GCMBlockCipher.DoFinal($encData, $res)
                
                # Last 16 bytes is the tag (in authorization code & refresh token)
                $buffer = New-Object byte[] ($encData.Count - 16)
                [Array]::Copy($encData,                  0,$buffer,0 ,$encData.Count - 16)
                [Array]::Copy($encData,$encData.Count - 16,$tag   ,0 ,$tag.Count)
                $encData = $buffer

                # Return
                return "$((Convert-ByteArrayToB64 -Bytes $binHeader -UrlEncode)).$((Convert-ByteArrayToB64 -Bytes $encKey -UrlEncode)).$((Convert-ByteArrayToB64 -Bytes $InitialVector -UrlEncode)).$((Convert-ByteArrayToB64 -Bytes $encData -UrlEncode)).$((Convert-ByteArrayToB64 -Bytes $tag -UrlEncode))"
            }
            catch
            {
                throw "Encrypting failed: ""$($_.Exception.InnerException.Message)"""
            }
        }
        else
        {
            Throw "Unsupported alg: $alg"
        }
    }
}