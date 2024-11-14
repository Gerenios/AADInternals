# Decrypt ADFS RefreshToken
# Oct 28th 2021
function Unprotect-ADFSRefreshToken
{
<#
    .SYNOPSIS
    Decrypts and verifies the given AD FS generated Refresh Token with the given certificates.

    .DESCRIPTION
    Decrypts and verifies the given AD FS generated Refresh Token with the given certificates.

    .PARAMETER RefreshToken

    AD FS generated RefreshToken.

    .PARAMETER PfxFileName_encryption

    Name of the PFX file of token encryption certificate.

    .PARAMETER PfxPassword_encryption

    Password of the token encryption PFX file. Optional.

    .PARAMETER PfxFileName_signing

    Name of the PFX file of token signing certificate. Optional. If not provided, refresh token is not verified.

    .PARAMETER PfxPassword_signing

    Password of the token signing PFX file. Optional.
    
    .Example
    PS C:\>Unprotect-ADFSRefreshToken -RefreshToken $token -PfxFileName_encryption .\ADFS_encryption.pfx -PfxFileName_signing .\ADFS_signing.pfx

    ClientID           : 5846ec9c-1cd7-4040-8630-6ae82d6cdfd3
    RedirectUri        : 
    Resource           : urn:microsoft:userinfo
    Issuer             : http://sts.company.com/adfs/services/trust
    NotBefore          : 1635414030
    ExpiresOn          : 1635442830
    SingleSignOnToken  : {"TokenType":0,"StringToken":"vVV[redacted]W/gE=","Version":1}
    DeviceFlowDeviceId : 
    IsDeviceFlow       : False
    SessionKeyString   : 
    SSOToken           : <SessionToken>[redacted]</SessionToken>
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeLine)]
        [String]$RefreshToken,
        
        [Parameter(Mandatory=$True)]
        [string]$PfxFileName_encryption,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword_encryption,

        [Parameter(Mandatory=$False)]
        [string]$PfxFileName_signing,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword_signing
    )
    Begin
    {
        $certificate_encryption = Load-Certificate -FileName $PfxFileName_encryption -Password $PfxPassword_encryption -Exportable
        [System.Security.Cryptography.RSACryptoServiceProvider]$privateKey_encryption = Load-PrivateKey -Certificate $certificate_encryption

        if($PfxFileName_signing)
        {
            $certificate_signing = Load-Certificate -FileName $PfxFileName_signing -Password $PfxPassword_signing -Exportable
        }
    }
    Process
    {

        # Separate token and signature
        $tokenParts        = $RefreshToken.Split(".")
        $enc_refresh_token = (Convert-B64ToByteArray -B64 $tokenParts[0])
        $signature         = (Convert-B64ToByteArray -B64 $tokenParts[1])

        # Verify the signature if the signing certificate provided
        if($certificate_signing)
        {
            $valid = $certificate_signing.PublicKey.Key.VerifyData($enc_refresh_token,"SHA256",$signature)
        
            if(!$valid)
            {
                Write-Warning "Invalid signature or signing certificate!"
            }

            Write-Verbose "Refresh token signature validated."
        }

        # Get the refresh token components
        $p = 0
        $hash           = $enc_refresh_token[$p..($p+32-1)] ; $p+=32
        $enc_Key_IV_len = [bitconverter]::ToUInt32($enc_refresh_token[$p..($p+3)],0); $p+=4
        $enc_Key_IV     = $enc_refresh_token[($p)..($p + $enc_Key_IV_len -1)]; $p+= $enc_Key_IV_len
        $enc_token_len  = [bitconverter]::ToUInt32($enc_refresh_token[$p..($p+3)],0); $p+=4
        $enc_token      = $enc_refresh_token[($p)..($p + $enc_token_len -1)]

        # Compare the hash
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $comp_hash = $sha256.ComputeHash([text.encoding]::UTF8.GetBytes($privateKey_encryption.ToXmlString($false)))

        if(Compare-Object -ReferenceObject $hash -DifferenceObject $comp_hash -SyncWindow 0)
        {
            Write-Error "Invalid decryption certificate (hash doesn't match)."
            return
        }
        Write-Verbose "Decryption key hash validated."
        
        # Decrypt Key and IV
        $dec_Key_IV = $privateKey_encryption.Decrypt($enc_Key_IV, $True)
        $dec_Key    = $dec_Key_IV[ 0..31]
        $dec_IV     = $dec_Key_IV[32..48]

        # Decrypt the refresh token
        $Crypto         = [System.Security.Cryptography.RijndaelManaged]::Create()
        $Crypto.Mode    = "CBC"
        $Crypto.Padding = "PKCS7"
        $Crypto.Key     = $dec_Key
        $Crypto.IV      = $dec_IV

        $decryptor = $Crypto.CreateDecryptor()

        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$decryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($enc_token,0,$enc_token.Count)
        $cs.Close()
        $cs.Dispose()

        $dec_refresh_token = [text.encoding]::UTF8.GetString($ms.ToArray())
        $ms.Close()
        $ms.Dispose()
        
        # Convert from json
        $refresh_token = $dec_refresh_token | ConvertFrom-Json
        
        # Get the deflated SSOToken
        [byte[]]$def_SSOToken = Convert-B64ToByteArray(($refresh_token.SingleSignOnToken | ConvertFrom-Json).StringToken)

        # Get the binary xml SSOToken
        $bxml_SSOToken = Get-DeDeflatedByteArray -byteArray $def_SSOToken
        
        # Get the xml SSOTOken
        $xml_SSOToken = BinaryToXml -xml_bytes $bxml_SSOToken -Dictionary (Get-XmlDictionary -type Session)
        
        # Set the SSOToken and return
        $refresh_token | Add-Member -NotePropertyName "SSOToken" -NotePropertyValue $xml_SSOToken.outerxml 
        
        $refresh_token
    }
    End
    {
        Unload-PrivateKey -PrivateKey $privateKey_encryption
    }

}


# Create a new ADFS RefreshToken
# Oct 28th 2021
function New-ADFSRefreshToken
{
<#
    .SYNOPSIS
    Creates a new AD FS Refresh Token with the given certificate.

    .DESCRIPTION
    Creates a new AD FS Refresh Token with the given certificate.

    .PARAMETER NotBefore
    The time after the refresh token is valid. Defaults to current time.

    .PARAMETER ExpiresOn
    The time when the refresh token is invalidated. Defaults to 8 hours from the current time.

    .PARAMETER UserPrincipalName
    UserPrincipalName of the user.

    .PARAMETER Name
    DisplayName of the user. Optional.

    .PARAMETER ClientID
    GUID of the client id. The client MUST be configured in the target AD FS server.

    .PARAMETER Resource
    The resource (uri) of the refresh token.

    .PARAMETER Issuer
    The uri of the issuing party

    .PARAMETER RedirectUri
    The redirect uri. Optional.
        
    .PARAMETER PfxFileName_encryption
     Name of the PFX file of token encryption certificate.

    .PARAMETER PfxPassword_encryption
    Password of the token encryption PFX file. Optional.

    .PARAMETER PfxFileName_signing
    Name of the PFX file of token signing certificate.

    .PARAMETER PfxPassword_signing
    Password of the token signing PFX file. Optional.
    
    .Example
    $refresh_token = New-AADIntADFSRefreshToken -UserPrincipalName "user@company.com" -Resource "urn:microsoft:userinfo" -Issuer "http://sts.company.com/adfs/services/trust" -PfxFileName_encryption .\ADFS_encryption.pfx -PfxFileName_signing .\ADFS_signing.pfx -ClientID "5846ec9c-1cd7-4040-8630-6ae82d6cdfd3"

    $body=@{
             "client_id"     = "5846ec9c-1cd7-4040-8630-6ae82d6cdfd3"
             "refresh_token" = $refresh_token
             "grant_type"    = "refresh_token"
           }

    $response = Invoke-RestMethod -UseBasicParsing -Uri "https://sts.company.com/adfs/services/trust/adfs/oauth2/token" -Method Post -Body $body
    $access_token = $response.access_token
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [DateTime]$NotBefore = (Get-Date),
        [Parameter(Mandatory=$False)]
        [DateTime]$ExpiresOn = ((Get-Date).AddHours(8)),

        [Parameter(Mandatory=$True)]
        [String]$UserPrincipalName,

        [Parameter(Mandatory=$False)]
        [String]$Name,

        [Parameter(Mandatory=$True)]
        [guid]$ClientID,

        [Parameter(Mandatory=$True)]
        [String]$Resource,

        [Parameter(Mandatory=$True)]
        [String]$Issuer,

        [Parameter(Mandatory=$False)]
        [String]$RedirectUri,
        
        [Parameter(Mandatory=$True)]
        [String]$PfxFileName_encryption,
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword_encryption,

        [Parameter(Mandatory=$True)]
        [String]$PfxFileName_signing,
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword_signing
    )
    Begin
    {
        $certificate_encryption = Load-Certificate -FileName $PfxFileName_encryption -Password $PfxPassword_encryption
        $certificate_signing    = Load-Certificate -FileName $PfxFileName_signing    -Password $PfxPassword_signing -Exportable
        $privateKey_signing     = Load-PrivateKey  -Certificate $certificate_signing
    }
    Process
    {
        # Generate Session Token
        $Key = Get-RandomBytes -Bytes 16
        [xml]$xml_SessionToken =@"
<SessionToken>
	<Version>1</Version>
	<SecureConversationVersion>http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512</SecureConversationVersion>
	<Id>_$((New-Guid).ToString())-$(Convert-ByteArrayToHex -Bytes (Get-RandomBytes -Bytes 16))</Id>
	<ContextId>urn:uuid:$((New-Guid).ToString())</ContextId>
	<Key>$(Convert-ByteArrayToB64 -Bytes $Key)</Key>
	<KeyGeneration>urn:uuid:$((New-Guid).ToString())</KeyGeneration>
	<EffectiveTime>$($NotBefore.Ticks)</EffectiveTime>
	<ExpiryTime>$($ExpiresOn.Ticks)</ExpiryTime>
	<KeyEffectiveTime>$($NotBefore.Ticks)</KeyEffectiveTime>
	<KeyExpiryTime>$($ExpiresOn.Ticks)</KeyExpiryTime>
	<ClaimsPrincipal>
		<Identities>
			<Identity NameClaimType="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" RoleClaimType="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
				<ClaimCollection>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.microsoft.com/ws/2014/01/identity/claims/anchorclaimtype"       Value="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"                              ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant" Value="$($NotBefore.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)+".000Z")" ValueType="http://www.w3.org/2001/XMLSchema#dateTime"/>
					<Claim Issuer="LOCAL AUTHORITY" OriginalIssuer="LOCAL AUTHORITY" Type="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"                     Value="$UserPrincipalName"                                                                     ValueType="http://www.w3.org/2001/XMLSchema#string"/>
                    <Claim Issuer="LOCAL AUTHORITY" OriginalIssuer="LOCAL AUTHORITY" Type="http://schemas.microsoft.com/claims/authnmethodsreferences"                    Value="http://schemas.microsoft.com/claims/multipleauthn"                                      ValueType="http://www.w3.org/2001/XMLSchema#string"/>
				</ClaimCollection>
			</Identity>
		</Identities>
	</ClaimsPrincipal>
	<EndpointId/>
</SessionToken>
"@

        $sessionToken = Get-DeflatedByteArray -byteArray (XmlToBinary -xml_doc $xml_SessionToken -Dictionary (Get-XmlDictionary -Type Session))

        # Construct the refresh token
        $refresh_token = [ordered]@{
            "ClientID"          = $ClientID.ToString()
            "RedirectUri"       = $RedirectUri
            "Resource"          = $Resource
            "Issuer"            = $Issuer
            "NotBefore"         = [int]($NotBefore-$epoch).TotalSeconds
            "ExpiresOn"         = [int]($ExpiresOn-$epoch).TotalSeconds
            "SingleSignOnToken" = @{
                                        "TokenType"   = 0
                                        "StringToken" = Convert-ByteArrayToB64 -Bytes $sessionToken
                                        "Version"     = 1
                                  } | ConvertTo-Json -Compress

            "DeviceFlowDeviceId" = $null
            "IsDeviceFlow"       = $false
            "SessionKeyString"   = $null
        } | ConvertTo-Json -Compress

        $dec_token = [text.encoding]::UTF8.GetBytes($refresh_token)

        # Create IV and key
        $dec_IV  = Get-RandomBytes -Bytes 16
        $dec_Key = Get-RandomBytes -Bytes 32

        # Encrypt the refresh token
        $Crypto         = [System.Security.Cryptography.RijndaelManaged]::Create()
        $Crypto.Mode    = "CBC"
        $Crypto.Padding = "PKCS7"
        $Crypto.Key     = $dec_Key
        $Crypto.IV      = $dec_IV

        $decryptor = $Crypto.CreateEncryptor()

        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$decryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($dec_token,0,$dec_token.Count)
        $cs.Close()
        $cs.Dispose()

        $enc_token = $ms.ToArray()
        $ms.Close()
        $ms.Dispose()

        # Encrypt Key Iv block
        $enc_Key_IV = New-Object Byte[] 48
        [Array]::Copy($dec_Key,$enc_Key_IV,32)
        [Array]::Copy($dec_IV,0,$enc_Key_IV,32,16)
        $dec_Key_IV=$certificate_encryption.PublicKey.Key.Encrypt($enc_Key_IV, $True)

        # Get the encryption key hash
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash   = $sha256.ComputeHash([text.encoding]::UTF8.GetBytes($certificate_encryption.PublicKey.Key.ToXmlString($false)))

        # Create the block
        $buffer = New-Object System.IO.MemoryStream
        $buffer.Write($hash,0,$hash.Length)
        $buffer.Write([bitconverter]::GetBytes([uint32]$dec_Key_IV.Length),0,4)
        $buffer.Write($dec_Key_IV,0,$dec_Key_IV.Length)
        $buffer.Write([bitconverter]::GetBytes([uint32]$enc_token.Length),0,4)
        $buffer.Write($enc_token,0,$enc_token.Length)
        $buffer.Flush()
        $enc_refresh_token = $buffer.ToArray()
        $buffer.Dispose()

        # Sign the token
        # Store the public key 
        $cspParameters = [System.Security.Cryptography.CspParameters]::new()
        $cspParameters.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $cspParameters.ProviderType = 24
        $cspParameters.KeyContainerName ="AADInternals"
            
        # Get the private key from the certificate
        $publicKey = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cspParameters)
        $publicKey.ImportParameters($certificate_signing.PublicKey.Key.ExportParameters($False))

        $signature = $privateKey_signing.SignData($enc_refresh_token,"SHA256")
        
        # Return
        return "$(Convert-ByteArrayToB64 -Bytes $enc_refresh_token -UrlEncode).$(Convert-ByteArrayToB64 -Bytes $signature -UrlEncode)"
    }
    End
    {
        Unload-PrivateKey -PrivateKey $privateKey_signing
    }

}

# Create a new ADFS Access Token
# Nov 1st 2021
function New-ADFSAccessToken
{
<#
    .SYNOPSIS
    Creates a new AccessToken and signs it with the given certificates.

    .DESCRIPTION
    Creates a new AccessToken and signs it with the given certificates.


#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [DateTime]$NotBefore = (Get-Date),
        [Parameter(Mandatory=$False)]
        [DateTime]$ExpiresOn = ((Get-Date).AddHours(8)),

        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName,

        [Parameter(Mandatory=$False)]
        [String]$Name,

        [Parameter(Mandatory=$True)]
        [guid]$ClientID,

        [Parameter(Mandatory=$True)]
        [String]$Resource,

        [Parameter(Mandatory=$False)]
        [String]$Scope="openid",

        [Parameter(Mandatory=$True)]
        [String]$Issuer,

        [Parameter(Mandatory=$True)]
        [String]$PfxFileName_signing,
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword_signing
    )
    Begin
    {
        $certificate_signing    = Load-Certificate -FileName $PfxFileName_signing    -Password $PfxPassword_signing -Exportable
        $privateKey_signing     = Load-PrivateKey  -Certificate $certificate_signing
    }
    Process
    {
        
        # Construct the refresh token
        $payLoad = [ordered]@{
            "aud"        = $Resource
            "iss"        = $Issuer
            "iat"        = [int]($NotBefore-$epoch).TotalSeconds
            "nbf"        = [int]($NotBefore-$epoch).TotalSeconds
            "exp"        = [int]($ExpiresOn-$epoch).TotalSeconds
            "sub"        = $Name
            "apptype"    = "Public"
            "appid"      = $ClientID
            "authmethod" = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            "auth_time"  = "$($NotBefore.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)+".000Z")"
            "ver"        = "1.0"
            "scp"        = $Scope
        } 

        $certHash = Convert-ByteArrayToB64 -bytes $certificate_signing.GetCertHash() -UrlEncode -NoPadding

        $header = [ordered]@{
            "typ" = "JWT"
            "alg" = "RS256"
            "x5t" = $certHash
            "kid" = $certHash
        }

        $jwt = New-JWT -PrivateKey $privateKey_signing -Header $header -Payload $payLoad

        return $jwt

    }
    End
    {
        Unload-PrivateKey -PrivateKey $privateKey_signing
    }

}