# This script contains common utility functions used in different functions

# Unix epoch time (1.1.1970)
$epoch = Get-Date -Day 1 -Month 1 -Year 1970 -Hour 0 -Minute 0 -Second 0 -Millisecond 0

Function Convert-ByteArrayToB64
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [Byte[]]$Bytes,
        [Switch]$UrlEncode,
        [Switch]$NoPadding
    )

    $b64 = [convert]::ToBase64String($Bytes);

    if($UrlEncode)
    {
        $b64 = $b64.Replace("/","_").Replace("+","-")
    }

    if($NoPadding)
    {
        $b64 = $b64.Replace("=","")
    }

    return $b64
}

Function Convert-B64ToByteArray
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [String]
        $B64
    )
    $B64 = $B64.Replace("_","/").Replace("-","+")

    # Fill the header with padding for Base 64 decoding
    while ($B64.Length % 4)
    {
        $B64 += "="
    }

    return [convert]::FromBase64String($B64)
}

Function Convert-B64ToText
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
        [String]
        $B64
    )

    return [text.encoding]::UTF8.GetString(([byte[]](Convert-B64ToByteArray -B64 $B64)))
}

Function Convert-TextToB64
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
        [String]
        $Text
    )

    return Convert-ByteArrayToB64 -Bytes  ([text.encoding]::UTF8.GetBytes($text))
}

Function Convert-ByteArrayToHex
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [Byte[]]
        $Bytes
    )

    $HexString = [System.Text.StringBuilder]::new($Bytes.Length * 2)

    ForEach($byte in $Bytes){
        $HexString.AppendFormat("{0:x2}", $byte) | Out-Null
    }

    $HexString.ToString()
}


Function Convert-HexToByteArray
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [String]
        $HexString
    )

    $Bytes = [byte[]]::new($HexString.Length / 2)

    For($i=0; $i -lt $HexString.Length; $i+=2){
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    }

    $Bytes
}


# Converts OID string to bytes
function Convert-OidToBytes
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [String]$Oid
    )
    Process
    {
        $digits = $oid.Split(".")
        $bytes =  @()

        # Encode the first byte
        $bytes += ([byte]$digits[0]) * 40 + ([byte]$digits[1])

        # Calculate the rest
        for($pos = 2; $pos -lt $Digits.Count; $pos++)
        {
            [int]$digit = $digits[$pos]

           
            if($digit -gt 127) # Multiple bytes needed
            {
                $mbytes=@()
                $mbytes += [byte]($digit -band 0x7f)

                while($digit -gt 127)
                {
                    $digit = $digit -shr 7

                    $mbytes += [byte](($digit -band 0x7f) -bor 0x80)
                }

                for($a = $mbytes.Count -1 ; $a -ge 0 ; $a--)
                {
                    $bytes += [byte]$mbytes[$a]
                }
            }
            else
            {
                $bytes += [byte]$digit
            }

        }

        # Return
        return [byte[]]$bytes

    }
}

# Converts byte array to oid string
function Convert-BytesToOid
{

    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName = "Bytes",Mandatory=$True,ValueFromPipeline)]
        [byte[]]$Bytes,
        [Parameter(ParameterSetName = "String",Mandatory=$True)]
        [String]$ByteString
    )
    Process
    {
        if($ByteString)
        {
            $Bytes = Convert-HexToByteArray -HexString ($ByteString.Replace("0x","").Replace(",","").Replace(" ",""))
        }
        $pos = 0

        # Check whether we have DER tag. If so, skip the first 2 bytes
        if($Bytes[0] -eq 0x06) 
        {
            $pos=2
        }
        
        # Calculate the first two digits
        $oid="$([byte]($Bytes[$pos]/40)).$([byte]$Bytes[$pos]%40)"

        # Calculate the rest
        for($pos+=1; $pos -lt $Bytes.Count; $pos++)
        {
            $digit = 0
            $mbyte = @()
            while (($Bytes[$pos] -band 0x80) -gt 0)
            {
                $mByte+=($Bytes[$pos])
                $pos++
            }
            if($mByte.Count -gt 0)
            {
                $mByte += $Bytes[$pos]
                for($a = 1; $a -le $mByte.Count ; $a++)
                {
                    $value = $mByte[$a-1] -band 0x7f # Strip the first byte
                    $value *= [math]::pow(128, $mByte.Count-$a)
                    $digit += $value

                }
            }
            else
            {
                $digit = $Bytes[$pos]
            }
            $oid += ".$digit"
        }

        # Return
        $oid
    }
}

# Loads X509 certificate from .pfx file.
function Load-Certificate
{
<#
    .SYNOPSIS
    Loads X509 certificate from the given .pfx file

    .DESCRIPTION
    Loads X509 certificate from the given .pfx file

    .Parameter FileName
    The full path to .pfx file from where to load the certificate

    .Parameter Password
    The password of the .pfx file

    .Parameter Exportable
    Whether the private key should be exportable or not.
    
    .Example
    PS C:\>Load-AADIntCertificate -FileName "MyCert.pfx" -Password -Password "mypassword"

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [String]$FileName,
        [Parameter(Mandatory=$False)]
        [String]$Password="",
        [Switch]$Exportable
    )
    Process
    {
        if(!(Test-Path $FileName))
        {
            throw "Certificate file $FileName not found!"
        }
        
        # Load the certificate
        try
        {
            if($Exportable)
            {
                $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Get-Item $FileName).FullName, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable) -ErrorAction SilentlyContinue
            }
            else
            {
                $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Get-Item $FileName).FullName, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet) -ErrorAction SilentlyContinue
            }
            
        }
        catch
        {
            throw "Error opening certificate: $($_.Exception.InnerException.Message)"""
        }
        
        return $Certificate
    }
}


# Loads the private key from the given Certificate
function Load-PrivateKey
{
<#
    .SYNOPSIS
    Loads the private key from the given x509 certificate

    .DESCRIPTION
    Loads the private key from the given x509 certificate
        
    .Example
    $Certificate = Load-Certificate -Filename "mycert.pfx" -Password "myverysecretpassword"
    PS C:\>$PrivateKey = Load-AADIntPrivateKey -Certificate $Certificate 

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    Process
    {
        # Store the private key to so that it can be exported
        $cspParameters = [System.Security.Cryptography.CspParameters]::new()
        $cspParameters.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $cspParameters.ProviderType = 24
        $cspParameters.KeyContainerName ="AADInternals"
            
        # Get the private key from the certificate
        $privateKey = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cspParameters)
        $privateKey.ImportParameters([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate).ExportParameters($true))
        
        Write-Verbose "Private Key from $($Certificate.Subject) loaded to the certificate store."
        Write-Debug   "PK: $( Convert-ByteArrayToB64 -Bytes (([System.Security.Cryptography.RSA]::Create($privateKey.ExportParameters($true))).key.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)) )"

        return $privateKey
    }
}

# Unloads the private key from the store
function Unload-PrivateKey
{
<#
    .SYNOPSIS
    Unloads the private key from the store

    .DESCRIPTION
    Unloads the private key from the store
        
    .Example
    $Certificate = Load-Certificate -Filename "mycert.pfx" -Password "myverysecretpassword"
    PS C:\>$privateKey = Load-AADIntPrivateKey -Certificate $Certificate 
    PS C:\>Unload-AADIntPrivateKey -PrivateKey $privateKey

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [System.Security.Cryptography.RSA]$PrivateKey
    )
    Process
    {
        try
        {
            # Remove the private key from the store
            $privateKey.PersistKeyInCsp=$false
            $privateKey.Clear()

            Write-Verbose "Private Key unloaded from the certificate store."
        }
        catch
        {
            Write-Verbose "Could not unload Private Key from the certificate store. That's probably just okay: ""$($_.Exception.InnerException.Message)"""
        }
        
    }
}


function Get-CompressedByteArray {

	[CmdletBinding()]
    Param (
	[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
	Process {
        Write-Verbose "Get-CompressedByteArray"
       	[System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
      	$gzipStream.Write( $byteArray, 0, $byteArray.Length )
        $gzipStream.Close()
        $output.Close()
        $tmp = $output.ToArray()
        Write-Output $tmp
    }
}


function Get-DecompressedByteArray {

	[CmdletBinding()]
    Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
	Process {
	    Write-Verbose "Get-DecompressedByteArray"
        $input = New-Object System.IO.MemoryStream( , $byteArray )
	    $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo( $output )
        $gzipStream.Close()
		$input.Close()
		[byte[]] $byteOutArray = $output.ToArray()
        Write-Output $byteOutArray
    }
}

# Parses the given RSA Key BLOB and returns RSAParameters
Function Parse-KeyBLOB
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [Byte[]]$Key
    )
    process
    {
        # https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
        # https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs

        # RSAPUBKEY
        # DWORD magic   ("RSA1" = public, or "RSA2" = private)
        # DWORD bitlen
        # ORD pubex
        $magic  = [text.encoding]::ASCII.GetString($Key[0..3])
        $bitlen = [bitconverter]::ToUInt16($Key,4)
        $publen = [bitconverter]::ToUInt16($Key,8)
        $modlen = [bitconverter]::ToUInt16($Key,12)
        $pri1len = [bitconverter]::ToUInt16($Key,16)
        $pri2len = [bitconverter]::ToUInt16($Key,20)

        $pubex  = $Key[24..(24+$publen-1)]

        $p=24+$publen

        $modulus = $key[($p)..($bitlen/8 + $p)]
        $p += $modlen

        # Private key
        if($magic -eq "RSA2") 
        {
            # RSAPUBKEY rsapubkey;

            # BYTE modulus[rsapubkey.bitlen/8];
            # BYTE prime1[rsapubkey.bitlen/16];
            # BYTE prime2[rsapubkey.bitlen/16];
            # BYTE exponent1[rsapubkey.bitlen/16];
            # BYTE exponent2[rsapubkey.bitlen/16];
            # BYTE coefficient[rsapubkey.bitlen/16];
            # BYTE privateExponent[rsapubkey.bitlen/8];

            $prime1 =           $key[($p)..($p + $bitlen/16)] ; $p += $bitlen/16
            $prime2 =           $key[($p)..($p + $bitlen/16)] ; $p += $bitlen/16
            $exponent1 =        $key[($p)..($p + $bitlen/16)] ; $p += $bitlen/16
            $exponent2 =        $key[($p)..($p + $bitlen/16)] ; $p += $bitlen/16
            $coefficient =      $key[($p)..($p + $bitlen/16)] ; $p += $bitlen/16
            $privateExponent =  $key[($p)..($p + $bitlen/8)] 
            
        }
        
        $attributes=@{
            "D" =        $privateExponent
            "DP" =       $exponent1
            "DQ" =       $exponent2
            "Exponent" = $pubex
            "InverseQ" = $coefficient
            "Modulus" =  $modulus
            "P" =        $prime1
            "Q"=         $prime2
        }

        [System.Security.Cryptography.RSAParameters]$RSAp = New-Object psobject -Property $attributes

        return $RSAp

    }
}

# Converts the given RSAParameters to DER
Function Convert-RSAToDER
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [System.Security.Cryptography.RSAParameters]$RSAParameters,
        [Switch]$PEM
    )
    process
    {
        # Reverse bytes

        $modulus =  $RSAParameters.Modulus[($RSAParameters.Modulus.Length)..0]
        $exponent = $RSAParameters.Exponent[($RSAParameters.Exponent.Length)..0]

        $der = Add-DERSequence -Data @(
                    Add-DERSequence -Data @(
                        # OID
                        Add-DERTag -Tag 0x06 -Data @( 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 )
                    
                        0x05 # Null
                        0x00
                    ) # Sequence
                    Add-DERTag -Tag 0x03 -Data @(
                        0x00 # Number of unused bits

                        Add-DERSequence -Data @(
                            Add-DERInteger -Data $modulus
                            Add-DERInteger -Data $exponent
                        
                        ) # Sequence
                    ) # Tag 0x03
                    
                ) # Sequence

        if($PEM)
        {
            return @"
-----BEGIN PUBLIC KEY-----
$(Convert-ByteArrayToB64 -Bytes $der)
-----END PUBLIC KEY-----
"@
        }                
        else
        {
            return $der
        }

    }
}


# Gets the error description from AzureAD
# Aug 2nd 2020
Function Get-Error
{
    <#
    .SYNOPSIS
    Gets a error description for the given error code.

    .DESCRIPTION
    Gets a error description for the given error code. 

    .Parameter ErrorCode
    Azure AD error code

    .Example
    Get-AADIntError -ErrorCode AADST700019

    700019: Application ID {identifier} cannot be used or is not authorized.

    .Example
    Get-AADIntError -ErrorCode 700019

    700019: Application ID {identifier} cannot be used or is not authorized.
#>
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [String]$ErrorCode
    )
    Process
    {
        # Get the error message
        $response=Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://login.microsoftonline.com/error?code=$ErrorCode"

        if($response.IndexOf("<table>") -gt 0)
        {
            $s=$response.IndexOf("<td>Error Code</td>")+23
            $e=$response.IndexOf("</td>",$s)
            $code=$response.Substring($s,$e-$s)

            $s=$response.IndexOf("<td>Message</td>")+20
            $e=$response.IndexOf("</td>",$s)
            $message=$response.Substring($s,$e-$s)

            Write-Host "$code`: $message"
        }
        else
        {
            Write-Host "Error $ErrorCode not found!"
        }

    }
}

# Create a new self-signed certificate
# Jan 31st 2021
function New-Certificate
{
<#
    .SYNOPSIS
    Creates a new self signed certificate.

    .DESCRIPTION
    Creates a new self signed certificate for the given subject name and returns it as System.Security.Cryptography.X509Certificates.X509Certificate2 or exports directly to .pfx and .cer files.
    The certificate is valid for 100 years.

    .Parameter SubjectName
    The subject name of the certificate, MUST start with CN=

    .Parameter Export
    Export the certificate (PFX and CER) instead of returning the certificate object. The .pfx file does not have a password.
  
    .Example
    PS C:\>$certificate = New-AADIntCertificate -SubjectName "CN=MyCert"

    .Example
    PS C:\>$certificate = New-AADIntCertificate -SubjectName "CN=MyCert"

    PS C:\>$certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx) | Set-Content MyCert.pfx -Encoding Byte

    .Example
    PS C:\>$certificate = New-AADIntCertificate -SubjectName "CN=MyCert"

    PS C:\>$certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) | Set-Content MyCert.cer -Encoding Byte

    .Example
    PS C:\>New-AADIntCertificate -SubjectName "CN=MyCert" -Export

    Certificate successfully exported:
      CN=MyCert.pfx
      CN=MyCert.cer
#>
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidatePattern("[c|C][n|N]=.+")] # Must start with CN=
        [String]$SubjectName,
        [Switch]$Export
    )
    Process
    {
        # Create a private key
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)

        # Initialize the Certificate Signing Request object
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($SubjectName, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
        $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($req.PublicKey,$false))

        # Create a self-signed certificate
        $selfSigned = $req.CreateSelfSigned((Get-Date).ToUniversalTime().AddMinutes(-5),(Get-Date).ToUniversalTime().AddYears(100))
        

        # Store the private key to so that it can be exported
        $cspParameters = [System.Security.Cryptography.CspParameters]::new()
        $cspParameters.ProviderName =    "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $cspParameters.ProviderType =    24
        $cspParameters.KeyContainerName ="AADInternals"
            
        # Set the private key
        $privateKey = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cspParameters)
        $privateKey.ImportParameters($rsa.ExportParameters($true))
        $selfSigned.PrivateKey = $privateKey

        if($Export)
        {
            $selfSigned.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)  | Set-Content "$SubjectName.pfx" -Encoding Byte
            $selfSigned.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) | Set-Content "$SubjectName.cer" -Encoding Byte

            # Print out information
            Write-Host "Certificate successfully exported:"
            Write-Host "  $SubjectName.pfx"
            Write-Host "  $SubjectName.cer"
        }
        else
        {
            return $selfSigned
        }
    }
}

# Creates a new random SID
# Feb 12th 2021
function New-RandomSID
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$False)]
        [ValidateSet(0,1,2,3,4,5,7,9,11,12,15,16,18)]
        [int]$IdentifierAuthority=5,
        [parameter(Mandatory=$False)]
        [ValidateSet(18,21,32,64,80,82,83,90,96)]
        [int]$SubAuthority=21
    )
    Process
    {
        # Create a random SID
        # ref: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-azod/ecc7dfba-77e1-4e03-ab99-114b349c7164
        # ref: https://en.wikipedia.org/wiki/Security_Identifier

        # Identifier Authorities:
        # 0  = Null Authority
        # 1  = World Authority
        # 2  = Local Authority
        # 3  = Creator Authority
        # 4  = Non-unique Authority
        # 5  = NT Authority                 NT AUTHORITY\
        # 7  = Internet$                    Internet$\
        # 9  = Resource Manager Authority
        # 11 = Microsoft Account Authority  MicrosoftAccount\
        # 12 = Azure Active Directory       AzureAD\
        # 15 = Capability SIDS
        # 16 =                              MandatoryLabel\
        # 18 =                              Asserted Identity

        # Sub Authorities:
        # 18 = LocalSystem
        # 21 = Domain
        # 32 = Users
        # 64 = Authentication
        # 80 = NT Service
        # 82 = IIS AppPool
        # 83 = Virtual Machines
        # 90 = Window Manager
        # 96 = Font Driver

        return "S-1-$IdentifierAuthority-$SubAuthority-$(Get-Random -Minimum 1 -Maximum 0x7FFFFFFF)-$(Get-Random -Minimum 1 -Maximum 0x7FFFFFFF)-$(Get-Random -Minimum 1 -Maximum 0x7FFFFFFF)-$(Get-Random -Minimum 1000 -Maximum 9999)"
    }
}

# Returns RCA for given key and data
function Get-RC4{
    Param(
        [Byte[]]$Key,
        [Byte[]]$Data
    )
    Process
    {
        $nk = New-Object byte[] 256
        $s = New-Object byte[] 256

        for ($i = 0; $i -lt 256; $i++)
        {
            $nk[$i] = $Key[($i % $Key.Length)]
            $s[$i] = [byte]$i
        }

        $j = 0

        for ($i = 0; $i -lt 256; $i++)
        {
            $j = ($j + $s[$i] + $nk[$i]) % 256

            $swap = $s[$i]
            $s[$i] = $s[$j]
            $s[$j] = $swap
        }


        $output = New-Object byte[] ($Data.Length)

        $i = 0
        $j = 0

        for ($c = 0; $c -lt $data.Length; $c++)
        {
            $i = ($i + 1) % 256
            $j = ($j + $s[$i]) % 256

            $swap = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $swap;

            $k = $s[(($s[$i] + $s[$j]) % 256)]

            $keyed = $data[$c] -bxor $k

            $output[$c] = [byte]$keyed
        }

        return $output

    }
}


function Parse-Asn1
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$False)]
        [int]$Pos=0,
        [Parameter(Mandatory=$False)]
        [int]$Level=0
    )
    Begin
    {
        
    }
    Process
    {
        # Must be initialized 
        [int]$p =      $pos
        [int]$sBytes = 0
        [int]$size =   0


        # Get the tag
        [int]$tag = $Data[$p]
        
        if(($Data[$p+1] -shr 4) -eq 8) # Get the size
        {
            # Multibyte
            $sBytes = $Data[$p+1] -band 0x0F
            
            for($a = 1 ; $a -le $sBytes; $a++)
            {
                $size += ($Data[$p+1+$a] * [Math]::Pow(256, $sBytes-$a))
            }
            
            $tSize = $size + 2 +$sBytes
        }
        else
        {
            $size = $Data[$p+1]
            $tSize = $size + 2
        }

        
        # Calculate start and end
        $start = $p
        $end =   $p + $tSize - 1

        # Move to the start of the data        
        $p += 2 + $sBytes

        if(($tag -shr 4) -eq 0x06) # Application element
        { 
                $appNum = $tag -band 0x0F
                $tType = "6{0:X}" -f $appNum

                $multiValue = $true
        }
        elseif(($tag -shr 4) -eq 0x0A) # Sequence element
        { 
                $seqNum = $tag -band 0x0F
                $tType = "A{0:X}" -f $seqNum

                $multiValue = $true
        }
        elseif($tag -in 0x10, 0x30) 
        {
                $tType = "SEQUENCE"
                $multiValue = $true
        } 
        elseif($tag -in 0x11, 0x31) 
        {
                $tType = "SET"
                $multiValue = $true
        }
        else
        {
            $multiValue = $false
            
            switch($tag)
            {
                0x01 {
                        $tType = "BOOLEAN"
                        $tData = $Data[$p-1] -ne 0x00
                        $tValue = $tData

                        break
                }
                0x02 {
                        $tType = "INTEGER" 
                        $tData = 0
                        for($a = 1 ; $a -le $size; $a++)
                        {
                            $tData += $Data[$p-1+$a] * [Math]::Pow(256, $size-$a)
                        }
                        $tValue = $tData
                        
                        break
                        }
                0x03 {
                        $tType = "BIT STRING"
                        $tData = $Data[$p..$($p+$size-1)]
                        $tValue = Convert-ByteArrayToHex -Bytes $tData
                        
                        break
                        }
                0x04 {
                        $tType = "OCTET STRING"
                        Write-Verbose "$(("  " * $level ))$tType ($size) $tValue"
                        $tData = $Data[$p..$($p+$size-1)]
                        
                        break
                        } 
                0x05 {
                        $tType = "NULL"
                        $tData = $null
                        $tValue = $tData

                        break
                        }
                0x06 {
                        $tType = "OBJECT IDENTIFIER"
                        $tData = Convert-BytesToOid -Bytes $Data[$p..$($p+$size-1)]
                        $tValue = $tData

                        break
                        }
                0x0A {
                        $tType = "ENUMERATED"
                        $tData = 0
                        for($a = 1 ; $a -le $size; $a++)
                        {
                            $tData += $Data[$p-1+$a] * [Math]::Pow(256, $size-$a)
                        }
                        $tValue = $tData
                        
                        break
                        }
                0x13 {
                        $tType = "PrintableString"
                        $tData = [text.encoding]::ASCII.GetString($Data[$p..$($p+$size-1)])
                        $tValue = $tData
                        
                        break
                        }
                0x16 {
                        $tType = "IA5String"
                        $tData = [text.encoding]::ASCII.GetString($Data[$p..$($p+$size-1)])
                        $tValue = $tData
                        
                        break
                        }
                0x18 {
                        $tType = "DATE TIME"
                        $dStr = [text.encoding]::UTF8.GetString($Data[$p..$($p+$size-1)])

                        $yyyy = [int]$dStr.Substring(0,4)
                        $MM   = [int]$dStr.Substring(4,2)
                        $dd   = [int]$dStr.Substring(6,2)
                        $hh   = [int]$dStr.Substring(8,2)
                        $min  = [int]$dStr.Substring(10,2)
                        $ss   = [int]$dStr.Substring(12,2)

                        $tData = [DateTime]"$($yyyy)-$('{0:D2}' -f $MM)-$('{0:D2}' -f $dd)T$('{0:D2}' -f $hh):$('{0:D2}' -f $min):$('{0:D2}' -f $ss)Z" 

                        $tValue = $tData

                        break
                        }
                0x1B {
                        $tType = "GENERAL STRING"
                        $tData = [text.encoding]::UTF8.GetString($Data[$p..$($p+$size-1)])
                        $tValue = $tData

                        break
                        }
                0x7B {
                        $tType = "EncAPRepPart"
                        Write-Verbose "$(("  " * $level ))$tType ($size) $tValue"
                        try
                        {
                            $tData = Parse-Asn1 -Data $Data[$p..$($p+$size-1)] -Level ($Level+1)
                        }
                        catch
                        {
                            $tData = $Data[$p..$($p+$size-1)]
                        }
                        break
                    }
                0x7E {
                        $tType = "KRB_ERROR"
                        Write-Verbose "$(("  " * $level ))$tType ($size) $tValue"
                        try
                        {
                            $tData = Parse-Asn1 -Data $Data[$p..$($p+$size-1)] -Level ($Level+1)
                        }
                        catch
                        {
                            $tData = $Data[$p..$($p+$size-1)]
                        }
                        break
                        
                    }
                0x80 {
                        $tType = "APPSPECIFIC"
                        $tData = $Data[$p..$($p+$size-1)]
                        
                        break
                        
                    }
                
                default {

                            Throw "Unknown TAG 0x$('{0:X}' -f  $tag) ($size)"
                        }       
            }
        }

        if($Size -eq 0)
        {
            $tData =  $null
            $tValue = $null
        }

        if(($tag -ne 0x04) -and (($tag -shr 4) -ne 0x07))
        {
            Write-Verbose "$(("  " * $level ))$tType ($size) $tValue"
        }

        if($multiValue)
        {
            $tData = @()
            While($p -lt $end)
            {

                $element = Parse-Asn1 -Data $Data -Pos $p -Level ($Level+1) 

                $p += $element.Size
                $tData += $element
                
                
            }
        
        }
        
                

        return New-Object psobject -Property @{ "Type" = $tType; "Data" = $tData ; "DataLength" = $size; "Size" = $tSize}
    }
}

# Encodes object to Asn1 encoded byte array
# Mar 26th 2021
function Encode-Asn1
{
    Param(
        [Parameter(Mandatory=$True)]
        [psobject]$Data,
        [Parameter(Mandatory=$False)]
        [int]$Level = 0
    )
    Begin
    {
        
    }
    Process
    {
        $attributes = $Data | get-member | where MemberType -eq "NoteProperty" | select Name
        if(!$attributes -or (!"Data","Type" -in $attributes))
        {
            Throw "Data object doesn't have Data and Type attributes"
        }

        
        Write-Verbose "$(("  " * $level ))$($Data.Type)"

        switch($Data.Type)
        {
            

            {$_.startsWith("APP #")}{
                    $appNum = [byte]$_.Split("#")[1]
                    $appNum += 0x60

                    $returnValues = @()
                    foreach($value in $Data.Data)
                    {
                        $returnValues += Encode-Asn1 -Data $value -Level ($Level+1)
                    }

                    if($returnValues)
                    {
                        return Add-DERTag -Tag $appNum -Data $returnValues
                    }

                    break
                }
            {$_.startsWith("SEQ #")}{
                    $seqNum = [byte]$_.Split("#")[1]
                    $seqNum += 0xA0

                    $returnValues = @()
                    foreach($value in $Data.Data)
                    {
                        $returnValues += Encode-Asn1 -Data $value -Level ($Level+1)
                    }

                    if($returnValues)
                    {
                        return Add-DERTag -Tag $seqNum -Data $returnValues
                    }

                    break
                }

            "SEQUENCE" {

                    $returnValues = @()
                    foreach($value in $Data.Data)
                    {
                        $returnValues += Encode-Asn1 -Data $value -Level ($Level+1)
                    }

                    if($returnValues)
                    {
                        return Add-DERSequence -Data $returnValues
                    }

                    break
                }
    
            "SET" {
                    $returnValues = @()
                    foreach($value in $Data.Data)
                    {
                        $returnValues += Encode-Asn1 -Data $value
                    }

                    if($returnValues)
                    {
                        return Add-DERSet -Data $returnValues
                    }
                    
                    break
                }
            "BOOLEAN" {
                    return Add-DERBoolean -Value $Data.Data

                    break
                }
            "INTEGER" {
                    return Add-DERInteger -Data ([byte]$Data.Data)

                    break
                }
            "ENUMERATED" {
                    return Add-DERInteger -Data ([byte]$Data.Data)

                    break
                }
            "BIT STRING" {
                    return Add-DERBitString -Data $Data.Data

                    break
                }
            "OCTET STRING" {
                    if($Data.Data -is [System.Array])
                    {
                        return Add-DEROctetString -Data $Data.Data
                    }
                    else
                    {
                        return Add-DEROctetString -Data (Encode-Asn1 -Data $Data.Data -Level ($Level+1))
                    }

                    break
                }
            "NULL" {
                    return Add-DERNull

                    break
                }
            "OBJECT IDENTIFIER" {
                    return Add-DERObjectIdentifier -ObjectIdentifier $Data.Data

                    break
                }
            "GENERAL STRING" {
                    return Add-DERUtf8String -Text $Data.Data

                    break
                }
            "DATE TIME" {
                    return Add-DERDate -Date $Data.Data

                    break
                }
            default {
                Throw "Unknown type: $_"
                }
            
        }
    }
}

# Returns the given number random bytes
function Get-RandomBytes
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [int]$Bytes
    )
    Process
    {
        $returnBytes = New-Object byte[] $Bytes
        

        for($c = 0; $c -lt $Bytes ; $c++)
        {
            $returnBytes[$c] = Get-Random -Minimum 0 -Maximum 0xFF
        }

        return $returnBytes
    }
}

# Computes an SHA1 digest for the given data
function Get-Digest
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Data
    )
    Process
    {
        
        # Compute SHA1 digest        
        $SHA1 =   [System.Security.Cryptography.SHA1Managed]::Create()
        $digest = $SHA1.ComputeHash([text.encoding]::UTF8.GetBytes($Data))
        
        $SHA1.Dispose()

        return $digest
    }
}

# Creates a new random SID
# May 31st 2021
function New-RandomIPv4
{
    [cmdletbinding()]

    param(
    )
    Process
    {
        return "$(Get-Random -Minimum 0 -Maximum 255).$(Get-Random -Minimum 0 -Maximum 255).$(Get-Random -Minimum 0 -Maximum 255).$(Get-Random -Minimum 0 -Maximum 255)"
    }
}