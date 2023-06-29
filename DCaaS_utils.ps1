# Decrypts the given ADAuthInfo BLOB with the given certificate
# Dec 22nd 2022
function Unprotect-ADAuthInfo
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate
    )
    
    Process
    {
        # Parse the blob
        $ADAuthInfo = Parse-ADAuthInfo -Data $Data

        # Ref: Microsoft.AD.DCaaS.Serialization.ADAuthInfoGenerator::Encrypt
        [Array]::Reverse($ADAuthInfo.Key)

        # This may be encrypted with other (=older) certificate..
        try
        {
            $key = $Certificate.PrivateKey.Decrypt($ADAuthInfo.Key,$true)

            [System.Security.Cryptography.AesCryptoServiceProvider]$aesCryptoServiceProvider = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
            $aesCryptoServiceProvider.KeySize = 256
            $aesCryptoServiceProvider.BlockSize = 128;
            $aesCryptoServiceProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aesCryptoServiceProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aesCryptoServiceProvider.Key = $key
            $aesCryptoServiceProvider.IV = $ADAuthInfo.IV

            [System.IO.MemoryStream]$memoryStream = [System.IO.MemoryStream]::new()
            [System.Security.Cryptography.ICryptoTransform]$cryptoTransform = $aesCryptoServiceProvider.CreateDecryptor()
            [System.Security.Cryptography.CryptoStream]$cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memoryStream,$cryptoTransform,[System.Security.Cryptography.CryptoStreamMode]::Write)
            $cryptoStream.Write($ADAuthInfo.EncryptedData,0,$ADAuthInfo.EncryptedData.Length)
            $cryptoStream.FlushFinalBlock()
            $decryptedData = $memoryStream.ToArray()

            return $decryptedData
        }
        catch
        {
            # Probably just encrypted using other (older) certificate
            return $null
        }
        finally
        {
            if($cryptoStream)             {$cryptoStream.Dispose()}
            if($cryptoTransform)          {$cryptoTransform.Dispose()}
            if($memoryStream)             {$memoryStream.Dispose()}
            if($aesCryptoServiceProvider) {$aesCryptoServiceProvider.Dispose()}
        }
    }
}

# Parses the given ADAuthInfo BLOB and returns the parsed attributes
# Dec 22nd 2022
function Parse-ADAuthInfo
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    
    Process
    {
        # Parse the blob
        $p = 0;
        $version          = [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $reserved         = [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $encKeyAlg        = [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $payloadEncKeyAlg = [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $thumbPrintSize   = [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $encKeySize       = [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $IVSize           = [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $encDataSize      = [System.BitConverter]::ToInt32($Data,$p); $p += 4

        $thumbPrint       = $Data[$p..($p+$thumbPrintSize-1)]; $p += $thumbPrintSize
        $encKey           = $Data[$p..($p+$encKeySize-1)]; $p += $encKeySize
        $IV               = $Data[$p..($p+$IVSize-1)]; $p += $IVSize
        $encData          = $Data[$p..($p+$encDataSize-1)]; $p += $encDataSize

        return [PSCustomObject][ordered]@{
            "ThumbPrint"    = $thumbPrint
            "Key"           = $encKey
            "IV"            = $IV
            "EncryptedData" = $encData
        }
        
    }
}

# Creates a new ADAuthInfo BLOB using the given parameters
# Dec 22nd 2022
function New-ADAuthInfo
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true)]
        [byte[]]$Thumbprint,
        [Parameter(Mandatory=$true)]
        [byte[]]$Key,
        [Parameter(Mandatory=$true)]
        [byte[]]$InitialVector
    )
    
    Process
    {
        # Set the values
        $version          = 1
        $reserved         = 0
        $encKeyAlg        = 1
        $payloadEncKeyAlg = 1
        $thumbPrintSize   = $Thumbprint.Length
        $encKeySize       = $Key.Length
        $IVSize           = $InitialVector.Length
        $encDataSize      = $Data.Length

        [System.IO.MemoryStream]$memoryStream = [System.IO.MemoryStream]::new(0x144 + $encDataSize)

        # Construct the blob
        $memoryStream.Write([System.BitConverter]::GetBytes([Int32]$version         ),0,4)
        $memoryStream.Write([System.BitConverter]::GetBytes([Int32]$reserved        ),0,4)
        $memoryStream.Write([System.BitConverter]::GetBytes([Int32]$encKeyAlg       ),0,4)
        $memoryStream.Write([System.BitConverter]::GetBytes([Int32]$payloadEncKeyAlg),0,4)
        $memoryStream.Write([System.BitConverter]::GetBytes([Int32]$thumbPrintSize  ),0,4)
        $memoryStream.Write([System.BitConverter]::GetBytes([Int32]$encKeySize      ),0,4)
        $memoryStream.Write([System.BitConverter]::GetBytes([Int32]$IVSize          ),0,4)
        $memoryStream.Write([System.BitConverter]::GetBytes([Int32]$encDataSize     ),0,4)

        $memoryStream.Write($thumbPrint   ,0,$thumbPrintSize)
        $memoryStream.Write($Key          ,0,$encKeySize)
        $memoryStream.Write($InitialVector,0,$IVSize)
        $memoryStream.Write($Data         ,0,$encDataSize)

        $blob = $memoryStream.ToArray() 
        return $blob
    }
    End
    {
        $memoryStream.Dispose()
    }
}

# Encrypts the given ADAuthInfo BLOB with the given certificate
# Dec 22nd 2022
function Protect-ADAuthInfo
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    
    Process
    {

        # Create the encryptor 
        [System.Security.Cryptography.AesCryptoServiceProvider]$aesCryptoServiceProvider = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aesCryptoServiceProvider.KeySize = 256
        $aesCryptoServiceProvider.BlockSize = 128;
        $aesCryptoServiceProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesCryptoServiceProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aesCryptoServiceProvider.GenerateKey()
        $aesCryptoServiceProvider.GenerateIV()

        # Ref: Microsoft.AD.DCaaS.Serialization.ADAuthInfoGenerator::Encrypt
        $key = $Certificate.PublicKey.Key.Encrypt($aesCryptoServiceProvider.Key,$true)
        [Array]::Reverse($key)

        [System.IO.MemoryStream]$memoryStream = [System.IO.MemoryStream]::new()
        [System.Security.Cryptography.ICryptoTransform]$cryptoTransform = $aesCryptoServiceProvider.CreateEncryptor()
        [System.Security.Cryptography.CryptoStream]$cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memoryStream,$cryptoTransform,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cryptoStream.Write($Data,0,$Data.Length)
        $cryptoStream.FlushFinalBlock()
        $encryptedData = $memoryStream.ToArray()

        $ADAutInfo = New-ADAuthInfo -Data $encryptedData -Thumbprint (Convert-HexToByteArray -HexString  $Certificate.Thumbprint) -Key $key -InitialVector $aesCryptoServiceProvider.IV
        return $ADAutInfo
    }
    End
    {
        $cryptoStream.Dispose()
        $cryptoTransform.Dispose()
        $memoryStream.Dispose()
        $aesCryptoServiceProvider.Dispose()
    }
}

# Gets access token using Azure AD Domain Services Sync certificate or password
# Dec 22nd 2022
function Get-DCaaSAccessToken
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$False)]
        [string]$Password,
        [Parameter(Mandatory=$True)]
        [guid]$TenantId,
        [Parameter(Mandatory=$True)]
        [guid]$ClientId,
        [Parameter(Mandatory=$False)]
        [string]$Scope = "https://graph.microsoft.com//.default"
    )
    
    Process
    {
        # Use client certificate
        if([string]::IsNullOrEmpty($Password))
        {
            # Load the private key (otherwise signing won't work)
            $privKey = Load-PrivateKey -Certificate $certificate 

            # Create header
            $kid = $certificate.Thumbprint
            $x5t = Convert-ByteArrayToB64 -Bytes (Convert-HexToByteArray -HexString $kid) -UrlEncode
            $x5c = Convert-ByteArrayToB64 -Bytes $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)

            $nbf = [int]((Get-Date).ToUniversalTime() - $epoch).TotalSeconds
            $exp = $nbf + 600 # Valid for 10 minutes

            $header=[ordered]@{
                "x5t" = $x5t
                "kid" = $kid
                "x5c" = $x5c
                "alg" = "RS256"
                "typ" = "JWT"
            }

            # Create payload
            $payload=[ordered]@{
                "aud" = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                "iss" = $ClientId
                "nbf" = $nbf
                "exp" = $exp
                "sub" = $ClientId
                "jti" = (New-Guid).ToString()
            }

            $client_assertion = New-JWT -Header $header -Payload $payload -PrivateKey $privKey

            $body=[ordered]@{
                "client_id"             = $ClientId
                "client_info"           = 1
                "client_assertion_type" = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                "client_assertion"      = $client_assertion
                "scope"                 = $Scope
                "grant_type"            = "client_credentials"
            }

            
        }
        # Use password
        else
        {
            $body=[ordered]@{
                "client_id"     = $ClientId
                "client_secret" = $Password
                "scope"         = $Scope
                "grant_type"    = "client_credentials"
            }
        }
        $response = Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method Post -Body $body

        return $response.access_token
        
    }
    End
    {
        if($privKey)
        {
            Unload-PrivateKey -PrivateKey $privKey
        }
    }
}

