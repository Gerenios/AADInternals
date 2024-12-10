# This script contains common utility functions used in different functions

# Constants
$const_bom = [byte[]]@(0xEF,0xBB,0xBF)

# Unix epoch time (1.1.1970)
$epoch = Get-Date -Day 1 -Month 1 -Year 1970 -Hour 0 -Minute 0 -Second 0 -Millisecond 0

# Configuration settings
$config = @{}

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

    if($NoPadding -or $UrlEncode)
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
    $B64 = $B64.Replace("_","/").Replace("-","+").TrimEnd(0x00,"=")

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
        return $output.ToArray()
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
		return $output.ToArray()
    }
}

function Get-DeflatedByteArray {

	[CmdletBinding()]
    Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
	Process {
	    Write-Verbose "Get-DecompressedByteArray"
	    $output = New-Object System.IO.MemoryStream
        $defStream = New-Object System.IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
	    $defStream.Write( $byteArray, 0, $byteArray.Length )
        $defStream.Close()
		$output.Close()
		return $output.ToArray()
    }
}

function Get-DeDeflatedByteArray {

	[CmdletBinding()]
    Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
	Process {
	    Write-Verbose "Get-DecompressedByteArray"
        $input = New-Object System.IO.MemoryStream( , $byteArray )
	    $output = New-Object System.IO.MemoryStream
        $defStream = New-Object System.IO.Compression.DeflateStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $defStream.CopyTo( $output )
        $defStream.Close()
		$input.Close()
		return $output.ToArray()
    }
}

# Parses the given RSA Key BLOB and returns RSAParameters
Function Parse-KeyBLOB
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$false,ValueFromPipeline)]
        [Byte[]]$Key
    )
    process
    {
        if($key -eq $null)
        {
            return $null
        }
        # https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
        # https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs

        # Parse the header
        $magic   = [text.encoding]::ASCII.GetString($Key[0..3])
        $bitlen  = [bitconverter]::ToUInt32($Key,4)
        $publen  = [bitconverter]::ToUInt32($Key,8)
        $modlen  = [bitconverter]::ToUInt32($Key,12)
        $pri1len = [bitconverter]::ToUInt32($Key,16)
        $pri2len = [bitconverter]::ToUInt32($Key,20)

        $headerLen = 6* [System.Runtime.InteropServices.Marshal]::SizeOf([uint32]::new())

        # BYTE pubexp[publen]
        # BYTE modulus[bitlen/8]
        # BYTE prime1[bitlen/16]
        # BYTE prime2[bitlen/16]
        # BYTE exponent1[bitlen/16]
        # BYTE exponent2[bitlen/16]
        # BYTE coefficient[bitlen/16]
        # BYTE privateExponent[bitlen/8]

        # Parse RSA1 (RSAPUBLICBLOB)
        $p = $headerLen
        $pubexp  = $Key[$headerLen..($headerLen + $publen - 1)]; $p += $publen
        $modulus = $key[($p)..($p-1 + $modlen)];                 $p += $modlen
        
        # Parse RSA2 (RSAPRIVATEBLOB)
        if($magic -eq "RSA2" -or $magic -eq "RSA3") 
        {
            $prime1 =           $key[($p)..($p-1 + $bitlen/16)] ; $p += $bitlen/16
            $prime2 =           $key[($p)..($p-1 + $bitlen/16)] ; $p += $bitlen/16
        }

        # Parse RSA3 (RSAFULLPRIVATEBLOB)
        if($magic -eq "RSA3") 
        {
            $exponent1 =        $key[($p)..($p-1 + $bitlen/16)] ; $p += $bitlen/16
            $exponent2 =        $key[($p)..($p-1 + $bitlen/16)] ; $p += $bitlen/16
            $coefficient =      $key[($p)..($p-1 + $bitlen/16)] ; $p += $bitlen/16
            $privateExponent =  $key[($p)..($p-1 + $bitlen/8)] 
        }
        
        $attributes=@{
            "D" =        $privateExponent
            "DP" =       $exponent1
            "DQ" =       $exponent2
            "Exponent" = $pubexp
            "InverseQ" = $coefficient
            "Modulus" =  $modulus
            "P" =        $prime1
            "Q"=         $prime2
        }

        [System.Security.Cryptography.RSAParameters]$RSAParameters = New-Object psobject -Property $attributes

        return $RSAParameters
    }
}

# Converts the given RSAParameters to PEM
# Feb 6th 2022
Function Convert-RSAToPEM
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [System.Security.Cryptography.RSAParameters]$RSAParameters
    )
    process
    {
        $pemWriter = [Org.BouncyCastle.OpenSsl.PemWriter]::new([System.IO.StringWriter]::new())
        $pemWriter.WriteObject([Org.BouncyCastle.Security.DotNetUtilities]::GetRsaKeyPair($RSAParameters).Private)

        $PEM = $pemWriter.Writer.ToString()

        $pemWriter.Writer.Dispose()

        return $PEM

    }
}

# Converts the given PEM to RSAParameters
# Feb 6th 2022
Function Convert-PEMToRSA
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [String]$PEM
    )
    process
    {
        $pemReader = [Org.BouncyCastle.OpenSsl.PemReader]::new([System.IO.StringReader]::new($PEM))
        $keys = $pemReader.ReadObject()

        $RSAParameters = [Org.BouncyCastle.Security.DotNetUtilities]::ToRSAParameters($keys.Private)

        $pemReader.Reader.Dispose()

        return $RSAParameters

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

        $code    = Get-StringBetween -String $response -Start '<td>Error Code</td><td>' -End '</td>'
        $message = Get-StringBetween -String $response -Start '<td>Message</td><td>'    -End '</td>'
       
        return "$code`: $message"
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

# Create (or use cached) XML dictionary
function Get-XmlDictionary
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet('WCF','Session')]
        [String]$Type="WCF"
    )    
    Begin
    {
        # Create dictionaries array
        $dictionaries = @{
                "WCF"     = New-Object System.Xml.XmlDictionary
                "Session" = New-Object System.Xml.XmlDictionary
            }

        # Dictionary for WCF binary xml
        foreach($element in @("mustUnderstand", "Envelope", "http://www.w3.org/2003/05/soap-envelope", "http://www.w3.org/2005/08/addressing", "Header", "Action", "To", "Body", "Algorithm", "RelatesTo", "http://www.w3.org/2005/08/addressing/anonymous", "URI", "Reference", "MessageID", "Id", "Identifier", "http://schemas.xmlsoap.org/ws/2005/02/rm", "Transforms", "Transform", "DigestMethod", "DigestValue", "Address", "ReplyTo", "SequenceAcknowledgement", "AcknowledgementRange", "Upper", "Lower", "BufferRemaining", "http://schemas.microsoft.com/ws/2006/05/rm", "http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement", "SecurityTokenReference", "Sequence", "MessageNumber", "http://www.w3.org/2000/09/xmldsig#", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", "KeyInfo", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "http://www.w3.org/2001/04/xmlenc#", "http://schemas.xmlsoap.org/ws/2005/02/sc", "DerivedKeyToken", "Nonce", "Signature", "SignedInfo", "CanonicalizationMethod", "SignatureMethod", "SignatureValue", "DataReference", "EncryptedData", "EncryptionMethod", "CipherData", "CipherValue", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Security", "Timestamp", "Created", "Expires", "Length", "ReferenceList", "ValueType", "Type", "EncryptedHeader", "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd", "RequestSecurityTokenResponseCollection", "http://schemas.xmlsoap.org/ws/2005/02/trust", "http://schemas.xmlsoap.org/ws/2005/02/trust#BinarySecret", "http://schemas.microsoft.com/ws/2006/02/transactions", "s", "Fault", "MustUnderstand", "role", "relay", "Code", "Reason", "Text", "Node", "Role", "Detail", "Value", "Subcode", "NotUnderstood", "qname", "", "From", "FaultTo", "EndpointReference", "PortType", "ServiceName", "PortName", "ReferenceProperties", "RelationshipType", "Reply", "a", "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity", "Identity", "Spn", "Upn", "Rsa", "Dns", "X509v3Certificate", "http://www.w3.org/2005/08/addressing/fault", "ReferenceParameters", "IsReferenceParameter", "http://www.w3.org/2005/08/addressing/reply", "http://www.w3.org/2005/08/addressing/none", "Metadata", "http://schemas.xmlsoap.org/ws/2004/08/addressing", "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous", "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault", "http://schemas.xmlsoap.org/ws/2004/06/addressingex", "RedirectTo", "Via", "http://www.w3.org/2001/10/xml-exc-c14n#", "PrefixList", "InclusiveNamespaces", "ec", "SecurityContextToken", "Generation", "Label", "Offset", "Properties", "Cookie", "wsc", "http://schemas.xmlsoap.org/ws/2004/04/sc", "http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk", "http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT", "RenewNeeded", "BadContextToken", "c", "http://schemas.xmlsoap.org/ws/2005/02/sc/dk", "http://schemas.xmlsoap.org/ws/2005/02/sc/sct", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel", "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes128", "http://www.w3.org/2001/04/xmlenc#aes192-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes192", "http://www.w3.org/2001/04/xmlenc#aes256-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes256", "http://www.w3.org/2001/04/xmlenc#des-cbc", "http://www.w3.org/2000/09/xmldsig#dsa-sha1", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments", "http://www.w3.org/2000/09/xmldsig#hmac-sha1", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1", "http://www.w3.org/2001/04/xmlenc#ripemd160", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmlenc#rsa-1_5", "http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmlenc#sha512", "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "http://www.w3.org/2001/04/xmlenc#kw-tripledes", "http://schemas.xmlsoap.org/2005/02/trust/tlsnego#TLS_Wrap", "http://schemas.xmlsoap.org/2005/02/trust/spnego#GSS_Wrap", "http://schemas.microsoft.com/ws/2006/05/security", "dnse", "o", "Password", "PasswordText", "Username", "UsernameToken", "BinarySecurityToken", "EncodingType", "KeyIdentifier", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#HexBinary", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ1510", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID", "Assertion", "urn:oasis:names:tc:SAML:1.0:assertion", "http://docs.oasis-open.org/wss/oasis-wss-rel-token-profile-1.0.pdf#license", "FailedAuthentication", "InvalidSecurityToken", "InvalidSecurity", "k", "SignatureConfirmation", "TokenType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID", "AUTH-HASH", "RequestSecurityTokenResponse", "KeySize", "RequestedTokenReference", "AppliesTo", "Authenticator", "CombinedHash", "BinaryExchange", "Lifetime", "RequestedSecurityToken", "Entropy", "RequestedProofToken", "ComputedKey", "RequestSecurityToken", "RequestType", "Context", "BinarySecret", "http://schemas.xmlsoap.org/ws/2005/02/trust/spnego", " http://schemas.xmlsoap.org/ws/2005/02/trust/tlsnego", "wst", "http://schemas.xmlsoap.org/ws/2004/04/trust", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/CK/PSHA1", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Nonce", "KeyType", "http://schemas.xmlsoap.org/ws/2004/04/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2004/04/trust/PublicKey", "Claims", "InvalidRequest", "RequestFailed", "SignWith", "EncryptWith", "EncryptionAlgorithm", "CanonicalizationAlgorithm", "ComputedKeyAlgorithm", "UseKey", "http://schemas.microsoft.com/net/2004/07/secext/WS-SPNego", "http://schemas.microsoft.com/net/2004/07/secext/TLSNego", "t", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1", "http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce", "RenewTarget", "CancelTarget", "RequestedTokenCancelled", "RequestedAttachedReference", "RequestedUnattachedReference", "IssuedTokens", "http://schemas.xmlsoap.org/ws/2005/02/trust/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel", "http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey", "Access", "AccessDecision", "Advice", "AssertionID", "AssertionIDReference", "Attribute", "AttributeName", "AttributeNamespace", "AttributeStatement", "AttributeValue", "Audience", "AudienceRestrictionCondition", "AuthenticationInstant", "AuthenticationMethod", "AuthenticationStatement", "AuthorityBinding", "AuthorityKind", "AuthorizationDecisionStatement", "Binding", "Condition", "Conditions", "Decision", "DoNotCacheCondition", "Evidence", "IssueInstant", "Issuer", "Location", "MajorVersion", "MinorVersion", "NameIdentifier", "Format", "NameQualifier", "Namespace", "NotBefore", "NotOnOrAfter", "saml", "Statement", "Subject", "SubjectConfirmation", "SubjectConfirmationData", "ConfirmationMethod", "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key", "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches", "SubjectLocality", "DNSAddress", "IPAddress", "SubjectStatement", "urn:oasis:names:tc:SAML:1.0:am:unspecified", "xmlns", "Resource", "UserName", "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName", "EmailName", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "u", "ChannelInstance", "http://schemas.microsoft.com/ws/2005/02/duplex", "Encoding", "MimeType", "CarriedKeyName", "Recipient", "EncryptedKey", "KeyReference", "e", "http://www.w3.org/2001/04/xmlenc#Element", "http://www.w3.org/2001/04/xmlenc#Content", "KeyName", "MgmtData", "KeyValue", "RSAKeyValue", "Modulus", "Exponent", "X509Data", "X509IssuerSerial", "X509IssuerName", "X509SerialNumber", "X509Certificate", "AckRequested", "http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested", "AcksTo", "Accept", "CreateSequence", "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence", "CreateSequenceRefused", "CreateSequenceResponse", "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequenceResponse", "FaultCode", "InvalidAcknowledgement", "LastMessage", "http://schemas.xmlsoap.org/ws/2005/02/rm/LastMessage", "LastMessageNumberExceeded", "MessageNumberRollover", "Nack", "netrm", "Offer", "r", "SequenceFault", "SequenceTerminated", "TerminateSequence", "http://schemas.xmlsoap.org/ws/2005/02/rm/TerminateSequence", "UnknownSequence", "http://schemas.microsoft.com/ws/2006/02/tx/oletx", "oletx", "OleTxTransaction", "PropagationToken", "http://schemas.xmlsoap.org/ws/2004/10/wscoor", "wscoor", "CreateCoordinationContext", "CreateCoordinationContextResponse", "CoordinationContext", "CurrentContext", "CoordinationType", "RegistrationService", "Register", "RegisterResponse", "ProtocolIdentifier", "CoordinatorProtocolService", "ParticipantProtocolService", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContext", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContextResponse", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/Register", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/RegisterResponse", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/fault", "ActivationCoordinatorPortType", "RegistrationCoordinatorPortType", "InvalidState", "InvalidProtocol", "InvalidParameters", "NoActivity", "ContextRefused", "AlreadyRegistered", "http://schemas.xmlsoap.org/ws/2004/10/wsat", "wsat", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Completion", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Durable2PC", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Volatile2PC", "Prepare", "Prepared", "ReadOnly", "Commit", "Rollback", "Committed", "Aborted", "Replay", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Commit", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Rollback", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Committed", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Aborted", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepare", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepared", "http://schemas.xmlsoap.org/ws/2004/10/wsat/ReadOnly", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Replay", "http://schemas.xmlsoap.org/ws/2004/10/wsat/fault", "CompletionCoordinatorPortType", "CompletionParticipantPortType", "CoordinatorPortType", "ParticipantPortType", "InconsistentInternalState", "mstx", "Enlistment", "protocol", "LocalTransactionId", "IsolationLevel", "IsolationFlags", "Description", "Loopback", "RegisterInfo", "ContextId", "TokenId", "AccessDenied", "InvalidPolicy", "CoordinatorRegistrationFailed", "TooManyEnlistments", "Disabled", "ActivityId", "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5APREQSHA1", "http://schemas.xmlsoap.org/ws/2002/12/policy", "FloodMessage", "LinkUtility", "Hops", "http://schemas.microsoft.com/net/2006/05/peer/HopCount", "PeerVia", "http://schemas.microsoft.com/net/2006/05/peer", "PeerFlooder", "PeerTo", "http://schemas.microsoft.com/ws/2005/05/routing", "PacketRoutable", "http://schemas.microsoft.com/ws/2005/05/addressing/none", "http://schemas.microsoft.com/ws/2005/05/envelope/none", "http://www.w3.org/2001/XMLSchema-instance", "http://www.w3.org/2001/XMLSchema", "nil", "type", "char", "boolean", "byte", "unsignedByte", "short", "unsignedShort", "int", "unsignedInt", "long", "unsignedLong", "float", "double", "decimal", "dateTime", "string", "base64Binary", "anyType", "duration", "guid", "anyURI", "QName", "time", "date", "hexBinary", "gYearMonth", "gYear", "gMonthDay", "gDay"))
        {
            $dictionaries["WCF"].Add($element) | Out-Null
        }

        # Dictionary for Identity Claims Session binary xml
        foreach($element in @("Claim","SecurityContextToken","Version","SecureConversationVersion","Issuer","OriginalIssuer","IssuerRef","ClaimCollection","Actor","ClaimProperty","ClaimProperties","Value","ValueType","Label","Type","subjectID","ClaimPropertyName","ClaimPropertyValue","http://www.w3.org/2005/08/addressing/anonymous","http://schemas.xmlsoap.org/ws/2005/05/identity/issuer/self","AuthenticationType","NameClaimType","RoleClaimType","Null", [string]::Empty,"Key","EffectiveTime","ExpiryTime","KeyGeneration","KeyEffectiveTime","KeyExpiryTime","SessionId","Id","ValidFrom","ValidTo","ContextId","SessionToken","SessionTokenCookie","BootStrapToken","Context","ClaimsPrincipal","WindowsPrincipal","WindowIdentity","Identity","Identities","WindowsLogonName","PersistentTrue","SctAuthorizationPolicy","Right","EndpointId","WindowsSidClaim","DenyOnlySidClaim","X500DistinguishedNameClaim","X509ThumbprintClaim","NameClaim","DnsClaim","RsaClaim","MailAddressClaim","SystemClaim","HashClaim","SpnClaim","UpnClaim","UrlClaim","Sid","SessionModeTrue"))
        {
            $dictionaries["Session"].Add($element) | Out-Null
        }
    }
    Process
    {
        return $dictionaries[$Type]
    }
}

# Converts binary xml to XML
function BinaryToXml
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$xml_bytes,
        [Parameter(Mandatory=$True)]
        [System.Xml.XmlDictionary]$Dictionary
    )
    Process
    {
        $xml_doc = New-Object System.Xml.XmlDocument

        [System.Xml.XmlDictionaryReader]$reader = [System.Xml.XmlDictionaryReader]::CreateBinaryReader($xml_bytes,0,$xml_bytes.Length,$Dictionary,[System.Xml.XmlDictionaryReaderQuotas]::Max)

        $xml_doc.Load($reader)

        return $xml_doc
    }
}

# Converts Xml to Binary format
function XmlToBinary
{
[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$xml_doc,
        [Parameter(Mandatory=$True)]
        [System.Xml.XmlDictionary]$Dictionary
    )
    Process
    {
        $ms = New-Object System.IO.MemoryStream

        $writer = [System.Xml.XmlDictionaryWriter]::CreateBinaryWriter($ms,$Dictionary)
        $xml_doc.WriteContentTo($writer);
        $writer.Flush()
        $ms.Position = 0;
        $length=$ms.Length

        [byte[]]$xml_bytes = New-Object Byte[] $length
        $ms.Flush()
        $ms.Read($xml_bytes, 0, $length) | Out-Null
        $ms.Dispose()
        
        return $xml_bytes
    }
}

function Remove-BOM
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$ByteArray
    )
    Process
    {
		if(Compare-Object -ReferenceObject $const_bom -DifferenceObject $ByteArray[0..2] -SyncWindow 0)
		{
			return $ByteArray
		}
		else
		{
			return $ByteArray[3..($ByteArray.length-1)]
		}
    }
}

# removes the given bytes from the given bytearray
function Remove-Bytes
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$ByteArray,
        [Parameter(Mandatory=$True)]
        [Byte[]]$BytesToRemove
    )
    Process
    {
        $retVal = @()

        for($i = 0; $i -le $ByteArray.Count; $i++)
        {
            $AddByte=$true

            for($b = 0; $b -le $BytesToRemove.Count; $b++)
            {
                $ByteToRemove = $BytesToRemove[$b]
                if($ByteArray[$i] -eq $ByteToRemove)
                {
                    $AddByte=$false
                }
            }
            if($AddByte)
            {
                $retVal+=$ByteArray[$i]
            }
        }

        $retVal
    }
}

# Splits the given string to the given line lenght using the given separator
# Dec 17th 2021
function Split-String
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$String,
        [Parameter(Mandatory=$false)]
        [int]$LineLength = 64,
        [Parameter(Mandatory=$false)]
        [string]$Separator = "`n"
    )
    Process
    {
        $retVal = ""
        $p = 0

        while($p -lt $String.Length)
        {
            if($String.Length - $p -lt $LineLength)
            {
                $retVal += $String.Substring($p)
                break
            }
            else
            {
                $retVal += $String.Substring($p, $LineLength)
                $retVal += $Separator
                $p += $LineLength
            }
        }

        return $retVal
    }
}

# Creates a new RSA keyBLOB from the given RSAParameters
# Dec 19th 2021
Function New-KeyBLOB
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [System.Security.Cryptography.RSAParameters]$Parameters,
        [Parameter(Mandatory=$True)]
        [ValidateSet('RSA1','RSA2','RSA3')]
        [String]$Type
    )
    process
    {
        # Set the size information
        $bitlen = $Parameters.Modulus.Length * 8
        $pubLen = $Parameters.Exponent.Length
        $modlen = $Parameters.Modulus.Length
        $pri1len = 0
        $pri2len = 0
        
        # Calculate the needed blob size for RSA1 (RSAPUBLICBLOB)
        $headerLen = 6 * [System.Runtime.InteropServices.Marshal]::SizeOf([uint32]::new())
        $blobLen =  $headerLen + $pubLen + $modLen

        # Check the parameters and choose the type accordingly
        if($Type -eq "RSA3" -and (!$Parameters.DP -or !$Parameters.DQ -or !$Parameters.InverseQ -or !$Parameters.D))
        {
            Write-Warning "No parameters for RSA3, creating RSA2"
            $Type = "RSA2"
        }
        if($Type -eq "RSA2" -and (!$Parameters.P -or !$Parameters.D))
        {
            Write-Warning "No parameters for RSA2, creating RSA1"
            $Type = "RSA1"
        }

        # If RSA2 or RSA3, set the P & Q lenghts
        if($Type -ne "RSA1")
        {
            $pri1len = $Parameters.P.Length
            $pri2len = $Parameters.Q.Length
        }

        # Adjust the total lenght for RSA2 (RSAPRIVATEBLOB)
        if($Type -eq "RSA2")
        {
            $blobLen += $modLen
        }

        # Adjust the total lenght for RSA3 (RSAFULLPRIVATEBLOB)
        if($Type -eq "RSA3")
        {
            $blobLen += $modLen + (5 * $modlen/2)
        }
        
        # Create the blob
        $blob = New-Object byte[] $blobLen

        $magic = [text.encoding]::ASCII.GetBytes($Type)

        $p = 0

        # Set the magic and size information
        [Array]::Copy($magic, 0, $blob, $p, 4); $p += 4
        [Array]::Copy([bitconverter]::GetBytes([UInt32]$bitLen) , 0, $blob, $p, 4); $p += 4
        [Array]::Copy([bitconverter]::GetBytes([UInt32]$pubLen) , 0, $blob, $p, 4); $p += 4
        [Array]::Copy([bitconverter]::GetBytes([UInt32]$modLen) , 0, $blob, $p, 4); $p += 4
        [Array]::Copy([bitconverter]::GetBytes([UInt32]$pri1len), 0, $blob, $p, 4); $p += 4
        [Array]::Copy([bitconverter]::GetBytes([UInt32]$pri2len), 0, $blob, $p, 4); $p += 4

        # Set the public exponent and modulus
        [Array]::Copy($Parameters.Exponent, 0, $blob, $p, $pubLen) ; $p += $pubLen
        [Array]::Copy($Parameters.Modulus , 0, $blob, $p, $modLen) ; $p += $modLen

        # Set the private parameters for RSA2 & RSA3
        if($Type -eq "RSA2" -or $Type -eq "RSA3")
        {
            [Array]::Copy($Parameters.P        , 0, $blob, $p, $pri1len) ; $p += $pri1len
            [Array]::Copy($Parameters.Q        , 0, $blob, $p, $pri2len) ; $p += $pri2len
        }

        # Set the private parameters for RSA3
        if($Type -eq "RSA3")
        {
            [Array]::Copy($Parameters.DP       , 0, $blob, $p, $pri1len) ; $p += $pri1len
            [Array]::Copy($Parameters.DQ       , 0, $blob, $p, $pri2len) ; $p += $pri2len
            [Array]::Copy($Parameters.InverseQ , 0, $blob, $p, $pri2len) ; $p += $pri2len
            [Array]::Copy($Parameters.D        , 0, $blob, $p, $modLen)
        }
        
        return $blob

    }
}

# Creates a new pfx file from the given certificate and private key (RSAParameters)
# Feb 6th 2022
Function New-PfxFile
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
        [System.Security.Cryptography.RSAParameters]$RSAParameters,
        [parameter(Mandatory=$true)]
        [byte[]]$X509Certificate
    )
    Begin
    {
        Add-Type -path "$PSScriptRoot\BouncyCastle.Crypto.dll"
    }
    Process
    {
        # Create X509 and private key entries
        $x509entry       = [Org.BouncyCastle.Pkcs.X509CertificateEntry]::new([Org.BouncyCastle.X509.X509Certificate    ]::new($X509Certificate))
        $privateKeyEntry = [Org.BouncyCastle.Pkcs.AsymmetricKeyEntry  ]::new([Org.BouncyCastle.Security.DotNetUtilities]::GetRsaKeyPair($RSAParameters).Private)

        # Create a PKCS12 store and add entries
        $pkcsStore = [Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder]::new().Build()
        $pkcsStore.SetKeyEntry($null,$privateKeyEntry,$x509entry)

        # Export as byte array
        $stream = [System.IO.MemoryStream]::new()
        $pkcsStore.Save($stream,$null,[Org.BouncyCastle.Security.SecureRandom]::new())
        $pfxFile = $stream.ToArray() 
        $stream.Dispose()
        
        # Return
        return $pfxFile
    }
}

# Gets a substring from a string between given "tags"
# May 23rd 2022
Function Get-Substring
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [string]$String,
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [string]$Start,
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [string]$End
    )
    process
    {
        $s = $String.IndexOf($Start) + $Start.Length
        if($s -lt 0)
        {
            return
        }
        $e = $String.IndexOf($End,$s)
        if($e -lt 0)
        {
            return
        }
        return $String.Substring($s,$e-$s)
    }
}

# Checks whether the multi-byte integer has more bytes
function Check-ContinuationBit
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte]$byteVal
    )

    [byte] $continuationBitmask = 0x80;
    return ($continuationBitmask -band $byteval) -ne 0
}

# Encodes integer as multi-byte integer
function Encode-MultiByteInteger
{
    param(
        [parameter(Mandatory=$true)]
        [int]$value
    )
    Process
    {
        # If integer is 0, just return that
        if($value -eq 0)
        {
            return 0
        }

        $byteList = @()

        $shiftedValue = $value;

        while ($value -gt 0)
        {
            $addByte = [byte]($value -band 0x7F)

            if ($byteList.Count -gt 0)
            {
                    $addByte = $addByte -bor 0x80
            }
            $newList = @()
            $newList += $addByte
            $newList += $byteList
            $byteList = $newList
       

            $value = $value -shr 7;
        }

        return $byteList
    }
}

# Decodes multi-byte integer from the given byte array
# Sep 29th 2022
function Decode-MultiByteInteger
{
    param(
        [parameter(Mandatory=$true)]
        [byte[]]$Data,
        [parameter(Mandatory=$true)]
        [ref]$Position,
        [parameter(Mandatory=$false)]
        [switch]$Reverse,
        [parameter(Mandatory=$false)]
        [switch]$Google
    )
    Process
    {
        $p = $Position.Value

        $nBytes = 1
        $bytes = New-Object Byte[] 8

        if($Google)
        {
            # Ref: https://developers.google.com/protocol-buffers/docs/encoding#varints

            # Strip the continuation bit and add to an array
            while((Check-ContinuationBit($Data[$p])) -and $nBytes -lt 8)
            {
                $bytes[$nBytes-1] = $Data[$p] -band 0x7F
                $p++
                $nBytes++
            }
            $bytes[$nBytes-1] = $Data[$p] -band 0x7F
            $p++

            # Reverse the array
            [Array]::Reverse($bytes)

            # Shift bits
            $n = 7
            while($n -gt 8-$nBytes)
            {
                $shiftedToNext = $bytes[$n-1] -shl $n
                $byte = $bytes[$n] -shr 7-$n
                $bytes[$n] = $shiftedToNext -bor $byte
                $n--
            }
            $bytes[$n] = $bytes[$n] -shr 7-$n

            [Array]::Reverse($bytes)
        }
        else
        {
            # Loop until all bytes are handled
            while((Check-ContinuationBit($Data[$p])) -and $nBytes -lt 8)
            {
                # Strip the continuation bit (not really needed as shifting to left)
                [byte]$byte = $Data[$p] -band 0x7F

                # Shift bits to left 8-$nBytes times
                [byte]$shiftedToNext = $byte -shl (8-$nBytes)

                # Shift bits to right $nBytes times
                $byte = $byte -shr $nBytes

                # Add to byte array by binary or as there might be shifted bits
                $bytes[$nBytes-1] = $bytes[$nBytes-1] -bor $byte

                # Add shifted bits
                $bytes[$nBytes]   = $shiftedToNext
                $nBytes++
                $p++
            }
            # Add to byte array by binary or as there might be shifted bits
            $bytes[$nBytes-1] = $bytes[$nBytes-1] -bor $Data[$p]
            $p++
        }

        # Reverse as needed
        if($Reverse)
        {
            $reversedBytes = New-Object Byte[] 8
            [Array]::Copy($bytes,0,$reversedBytes,8-$nBytes,$nBytes)
            [Array]::Reverse($reversedBytes)
            $bytes = $reversedBytes
        }

        $Position.Value = $p

        return [bitconverter]::ToInt64($bytes,0)
    }
}

# Gets the content of the given file as byte array
# Sep 30th 2022
function Get-BinaryContent
{
    param(
        [parameter(Mandatory=$true, ValueFromPipeline, Position=0)]
        [string]$Path
    )
    Process
    {
        #return [System.IO.File]::ReadAllBytes([System.IO.Path]::GetFullPath($Path))
        if($PSVersionTable.PSVersion.Major -ge 6)
        {
            Get-Content -Path $Path -AsByteStream -Raw
        }
        else
        {
            Get-Content -Path $Path -Encoding Byte
        }
    }
}

# Sets the content of the given file with given byte array
# Sep 30th 2022
function Set-BinaryContent
{
    param(
        [parameter(Mandatory=$true, ValueFromPipeline, Position=0)]
        [string]$Path,
        [parameter(Mandatory=$true, ValueFromPipeline, Position=1)]
        [byte[]]$Value
    )
    Process
    {
        if($PSVersionTable.PSVersion.Major -ge 6)
        {
            Set-Content -Path $Path -Value $Value -AsByteStream
        }
        else
        {
            Set-Content -Path $Path -Value $Value -Encoding Byte
        }
    }
}

# Load the settings from config.json
# May 29th 2023
function Read-Configuration
{
<#
    .SYNOPSIS
    Loads AADInternals settings

    .DESCRIPTION
    Loads AADInternals settings from config.json. All changes made after loading AADInternals module will be lost.

    .Example
    PS C:\>Read-AADIntConfiguration
#>
    [cmdletbinding()]
    param()
    Process
    {
        # Clear the settings
        $Script:config = @{}

        # ConvertFrom-Json -AsHashtable not supported in PowerShell 5.1
        $configObject = Get-Content -Path "$PSScriptRoot\config.json" | ConvertFrom-Json
        foreach($property in $configObject.PSObject.Properties)
        {
            $Script:config[$property.Name] = $property.Value
        }
    }
}

# Save the settings to config.json
# May 29th 2023
function Save-Configuration
{
<#
    .SYNOPSIS
    Saves AADInternals settings

    .DESCRIPTION
    Saves the current AADInternals settings to config.json. Settings will be loaded when AADInternals module is loaded.
    
    .Example
    PS C:\>Save-AADIntConfiguration
#>
    [cmdletbinding()]
    param()
    Process
    {
        $Script:config | ConvertTo-Json | Set-Content -Path "$PSScriptRoot\config.json"

        Write-Host "Settings saved."
    }
}

# Shows the configuration
# May 29th 2023
function Get-Configuration
{
<#
    .SYNOPSIS
    Shows AADInternals settings

    .DESCRIPTION
    Shows AADInternals settings
    
    .Example
    PS C:\>Get-AADIntSettings

    Name                           Value
    ----                           -----
    SecurityProtocol               Tls12
    User-Agent                     AADInternals
#>
    [cmdletbinding()]
    param()
    Process
    {
        $Script:config
    }
}

# Get AADInternals setting
# May 29th 2023
function Get-Setting
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline)]
        [string]$Setting
    )
    Process
    {
        return $Script:config[$Setting]
    }
}

# Sets AADInternals setting value
# May 29th 2023
function Set-Setting
{
    <#
    .SYNOPSIS
    Sets the given setting with given value

    .DESCRIPTION
    Sets the given setting with given value. To persist, use Save-AADIntConfiguration after setting the value.

    .Parameter Setting
    Name of the setting to be set

    .Parameter Value
    Value of the setting
    
    .Example
    PS C:\>Set-AADIntSetting -Setting "User-Agent" -Value "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"

    .Example
    PS C:\>Set-AADIntSetting -Setting "User-Agent" -Value "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
    PS C:\>Save-AADIntConfiguration

    Settings saved.
#>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline, Position=0)]
        [string]$Setting,
        [parameter(Mandatory=$true, ValueFromPipeline, Position=1)]
        [PSObject]$Value
    )
    Process
    {
        $Script:config[$Setting] = $value
    }
}

# Sets AADInternals User-Agent value
# May 29th 2023
function Set-UserAgent
{
    <#
    .SYNOPSIS
    Sets the User-Agent AADInternals will use in requests.

    .DESCRIPTION
    Sets a pre configured User-Agent for a specific device that AADInternals will use in requests. Supported devices: 'Windows','MacOS','Linux','iOS','Android'.
    To persist, use Save-AADIntConfiguration after setting the User-Agent

    .Parameter UserAgent
    One of 'Windows','MacOS','Linux','iOS','Android'
    
    .Example
    PS C:\>Set-AADIntUserAgent -Device Windows

    .Example
    PS C:\>Set-AADIntUserAgent -Device Windows
    PS C:\>Save-AADIntConfiguration

    Settings saved.
#>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [ValidateSet('Windows','MacOS','Linux','iOS','Android')]
        [string]$Device
    )
    Begin
    {
        $userAgents = @{
            "Windows" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            "MacOS"   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4)"
            "Linux"   = "Mozilla/5.0 (X11; Linux x86_64)"
            "iOS"     = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X)"
            "Android" = "Mozilla/5.0 (Linux; Android 10)"
        }
    }
    Process
    {
        Set-Setting -Setting "User-Agent" -Value $userAgents[$Device]
    }
}

# Gets AADInternals User-Agent value
# Feb 13 2024
function Get-UserAgent
{
    
    [cmdletbinding()]
    param()
    Process
    {
        $userAgent = Get-Setting -Setting "User-Agent"
        if($userAgent -eq $null)
        {
            $userAgent = "AADInternals"
        }

        return $userAgent
    }
}


# Return the string between Start and End
# May 29th 2023
function Get-StringBetween
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$String,
        [Parameter(Mandatory=$True)]
        [String]$Start,
        [Parameter(Mandatory=$True)]
        [String]$End,
        [Parameter(Mandatory=$False)]
        [int]$IncludeEndCharacters = 0
    )
    Process
    {

        $s = $String.IndexOf($Start)
        if($s -gt -1)
        {
            $e = $String.IndexOf($End,$s + $Start.Length)
            if($e -gt $s)
            {
                $c = $String.Substring($s + $Start.Length,$e-$s-$Start.Length + $IncludeEndCharacters)
            }
        }
        return $c
    }
}

# Parses code from the response, either location header or body.
# Jun 9th 2023
Function Parse-CodeFromResponse
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [PSObject]$Response
    )
    process
    {
        # Parse the code from the Location header
        # Location: <redirect_uri>?code=<code>&session_state=<state>
        
        # Try first the location header
        $redirect = $Response.Headers["Location"]
        if([string]::IsNullOrEmpty($redirect))
        {
            # Didn't work, so try to parse from the body
            Write-Verbose "Location header empty, parsing from body."

            # Decode \u0026 to &
            $redirect = $response.content.Replace("\u0026","&")
        }
        if(![string]::IsNullOrEmpty($redirect))
        {
            # PS versions >= 6 header values are a string array
            if($redirect -is [String[]])
            {
                $redirect = $redirect[0]
            }
            $authorizationCode = Get-StringBetween -String $redirect -Start 'code=' -End '&'
        }

        if([string]::IsNullOrEmpty($authorizationCode))
        {
            Throw "Authorization code not received!"
        }
        Write-Verbose "Code: $authorizationCode"

        return $authorizationCode
    }
}

# Prompts for password
# Jun 19th 2023
Function Read-HostPassword
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [string]$Prompt
    )
    process
    {
        # Use -MaskInput for PowerShell >= 7.1
        if( ($PSVersionTable.PSVersion.Major -ge 7) -or
            ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -ge 1) )
        {
            $password = Read-Host -Prompt $Prompt -MaskInput
        }
        else
        {
            # Use -AsSecureString for PowerShell < 7.1
            $securePassword = Read-Host -Prompt $Prompt -AsSecureString
            if(!$securePassword)
            {
                return $null
            }
            $securePasswordBytes = Convert-HexToByteArray -HexString (ConvertFrom-SecureString $securePassword)
            $password = [text.encoding]::Unicode.GetString([Security.Cryptography.ProtectedData]::Unprotect($securePasswordBytes,$null,'CurrentUser'))
        }

        return $password
    }
}

# Reads error stream and returns UTF8 string
# Jun 21st 2023
Function Get-ErrorStreamMessage
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [System.IO.MemoryStream]$errorStream
    )
    process
    {
        $errorBytes = New-Object byte[] $errorStream.Length

        $errorStream.Position = 0
        $errorStream.Read($errorBytes,0,$errorStream.Length) | Out-Null

        return [text.encoding]::UTF8.GetString($errorBytes)
    }
}

# PSVersion aware Invoke-WebRequest
# Jun 27th 2023
Function Invoke-WebRequest2
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
        [String]$Uri,
        [parameter(Mandatory=$false)]
        [String]$Method = "GET",
        [parameter(Mandatory=$false)]
        [PSObject]$WebSession,
        [parameter(Mandatory=$false)]
        [PSObject]$Headers,
        [parameter(Mandatory=$false)]
        [PSObject]$Body,
        [parameter(Mandatory=$false)]
        [String]$ContentType = "application/x-www-form-urlencoded",
        [parameter(Mandatory=$false)]
        [int]$MaximumRedirection = 5,
        [parameter(Mandatory=$false)]
        [String]$SessionVariable,
        [parameter(Mandatory=$false)]
        [String]$OutFile
    )
    process
    {
        $arguments = @{
            "UseBasicParsing"    = $true
            "Uri"                = $uri 
            "Method"             = $Method
            "MaximumRedirection" = $MaximumRedirection
            "ErrorAction"        = $ErrorActionPreference
            "Headers"            = $Headers
            "Body"               = $body 
            "ContentType"        = $ContentType
            "OutFile"            = $OutFile
        }

        if(![string]::IsNullOrEmpty($SessionVariable))
        {
            $arguments["SessionVariable"] = $SessionVariable
        }
        elseif($WebSession -ne $null)
        {
            $arguments["WebSession"] = $WebSession
        }

        # PSVersions >= 7 set undeclared OutFile as empty string which makes the Invoke-WebRequest fail
        if(($PSVersionTable.PSVersion.Major -ge 7) -and ($arguments["OutFile"] -eq "")) 
        {
            $arguments.Remove("OutFile")
        }

        # PSVersions >= 7 doesn't respect the ErrorAction SilentlyContinue so we need to use SkipHttpErrorCheck
        if(($PSVersionTable.PSVersion.Major -ge 7) -and ($ErrorActionPreference -eq "SilentlyContinue"))
        {
            $arguments["SkipHttpErrorCheck"] = $true
        }
        Invoke-WebRequest @arguments
    }
}

# Aug 23th 2019
# Calculates MD4 hashes from given passwords
function Get-MD4{
    PARAM(
        [String]$String,
        [Byte[]]$bArray,
        [Switch]$UpperCase,
        [Switch]$AsByteArray # Added by Nestori Syynimaa Aug 23th 2019
    )
    
    # Author: Larry.Song@outlook.com
    # Reference: https://tools.ietf.org/html/rfc1320
    # MD4('abc'): 
    #     a448017aaf21d8525fc10ae87aa6729d UTF-8
    #     e0fba38268d0ec66ef1cb452d5885e53 Unicode
    $Array = [byte[]]@()
    if($String)
    {
        $Array = [System.Text.Encoding]::Unicode.GetBytes($String) # Edited by Nestori Syynimaa Nov 16th 2018
    }
    if($bArray)
    {
        $Array = $bArray
    }
    # padding 100000*** to length 448, last (64 bits / 8) 8 bytes fill with original length
    # at least one (512 bits / 8) 64 bytes array
    $M = New-Object Byte[] (([math]::Floor($Array.Count/64) + 1) * 64)
    # copy original byte array, start from index 0
    $Array.CopyTo($M, 0)
    # padding bits 1000 0000
    $M[$Array.Count] = 0x80
    # padding bits 0000 0000 to fill length (448 bits /8) 56 bytes
    # Default value is 0 when creating a new byte array, so, no action
    # padding message length to the last 64 bits
    @([BitConverter]::GetBytes($Array.Count * 8)).CopyTo($M, $M.Count - 8)

    # message digest buffer (A,B,C,D)
    $A = [Convert]::ToUInt32('0x67452301', 16)
    $B = [Convert]::ToUInt32('0xefcdab89', 16)
    $C = [Convert]::ToUInt32('0x98badcfe', 16)
    $D = [Convert]::ToUInt32('0x10325476', 16)
    
    # There is no unsigned number shift in C#, have to define one.
    Add-Type -TypeDefinition @'
public class Shift
{
  public static uint Left(uint a, int b)
    {
        return ((a << b) | (((a >> 1) & 0x7fffffff) >> (32 - b - 1)));
    }
}
'@

    # define 3 auxiliary functions
    function FF([uint32]$X, [uint32]$Y, [uint32]$Z)
    {
        (($X -band $Y) -bor ((-bnot $X) -band $Z))
    }
    function GG([uint32]$X, [uint32]$Y, [uint32]$Z)
    {
        (($X -band $Y) -bor ($X -band $Z) -bor ($Y -band $Z))
    }
    function HH([uint32]$X, [uint32]$Y, [uint32]$Z){
        ($X -bxor $Y -bxor $Z)
    }
    # processing message in one-word blocks
    for($i = 0; $i -lt $M.Count; $i += 64)
    {
        # Save a copy of A/B/C/D
        $AA = $A
        $BB = $B
        $CC = $C
        $DD = $D

        # Round 1 start
        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0)) -band [uint32]::MaxValue, 19)

        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0)) -band [uint32]::MaxValue, 19)

        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0)) -band [uint32]::MaxValue, 19)

        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0)) -band [uint32]::MaxValue, 19)
        # Round 1 end
        # Round 2 start
        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)
        # Round 2 end
        # Round 3 start
        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)
        # Round 3 end
        # Increment start
        $A = ($A + $AA) -band [uint32]::MaxValue
        $B = ($B + $BB) -band [uint32]::MaxValue
        $C = ($C + $CC) -band [uint32]::MaxValue
        $D = ($D + $DD) -band [uint32]::MaxValue
        # Increment end
    }
    # Output start
    $A = ('{0:x8}' -f $A) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $B = ('{0:x8}' -f $B) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $C = ('{0:x8}' -f $C) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $D = ('{0:x8}' -f $D) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    # Output end

    
    if($AsByteArray)
    {
        return [byte[]]("$A$B$C$D" -replace '..', '0x$&,' -split ',' -ne '')
    }
    else
    {
        if($UpperCase)
        {
            return "$A$B$C$D".ToUpper()
        }
        else
        {
            return "$A$B$C$D"
        }
    }
}

# Sep 25th 2024
# Calculates a thumbprint for the given certificate
function Get-Thumbprint
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName = "String",Mandatory=$True)]
        [String]$Certificate,
        [Parameter(ParameterSetName = "Bytes",Mandatory=$True)]
        [byte[]]$Bytes
    )
    if($Bytes -eq $null)
    {
        if([string]::IsNullOrEmpty($Certificate))
        {
            return $null
        }
        else
        {
            $bytes = [byte[]](Convert-B64ToByteArray -B64 $Certificate)
        }
    }
    
    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes).Thumbprint
}


# Parses the oid values of the given certificate
# Dec 23rd 2021
function Parse-CertificateOIDs
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    Process
    {
        function Get-OidRawValue
        {
            Param([byte[]]$RawValue)
            Process
            {
                # Quick-and-dirty DER decoder
                if($RawValue.Length -gt 3 -and ($RawValue[2] -eq $RawValue.Length-3 ))
                {
                    # 04 81 10 xxx
                    return $RawValue[3..($RawValue.Length-1)] 
                }
                elseif($RawValue.Length -gt 2 -and ($RawValue[1] -eq $RawValue.Length-2 ))
                {
                    # 04 10 xxx
                    return $RawValue[2..($RawValue.Length-1)] 
                }
                else
                {
                    return $RawValue
                }
            }
        }
        $retVal = New-Object psobject
        foreach($ext in $Certificate.Extensions)
        {
            switch($ext.Oid.Value)
            {
               #
               # Device Certificates
               # 
               "1.2.840.113556.1.5.284.2" {
                    $retVal | Add-Member -NotePropertyName "DeviceId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                    break
               }

               # "The objectGuid of the user object ([MS-ADSC] section 2.268) on the directory server that corresponds to the authenticating user."
               # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dvrj/850786b9-2525-4047-a5ff-8c3093b46b88
               # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dvre/76747b5c-06c2-4c73-9207-8ebb6ee891ea
               # I.e. the object ID in AAD of the user who joined/registered the device
               "1.2.840.113556.1.5.284.3" {
                    $retVal | Add-Member -NotePropertyName "AuthUserObjectId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                    break
               }
               "1.2.840.113556.1.5.284.5" {
                    $retVal | Add-Member -NotePropertyName "TenantId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                    break
               }
               "1.2.840.113556.1.5.284.8" {
                    # Tenant region
                    # AF = Africa
                    # AS = Asia
                    # AP = Australia/Pasific
                    # EU = Europe
                    # ME = Middle East
                    # NA = North America
                    # SA = South America
                    $retVal | Add-Member -NotePropertyName "Region" -NotePropertyValue ([text.encoding]::UTF8.getString([byte[]](Get-OidRawValue -RawValue $ext.RawData)))
                    break
               }
               "1.2.840.113556.1.5.284.7" {
                    # JoinType
                    # 0 = Registered
                    # 1 = Joined
                    $retVal | Add-Member -NotePropertyName "JoinType" -NotePropertyValue ([int]([text.encoding]::UTF8.getString([byte[]](Get-OidRawValue -RawValue $ext.RawData))))
                    break
               }

               #
               # Web App Proxy certificates
               #
               "1.3.6.1.4.1.311.82.1"{
                    $retVal | Add-Member -NotePropertyName "AgentId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                    break
               }

               #
               # Intune Certificates Ref. https://github.com/ralish/CertUiExts
               # 
               "1.2.840.113556.5.4" {
                    $retVal | Add-Member -NotePropertyName "IntuneDeviceId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                    break
               }
               "1.2.840.113556.5.6" {
                    $retVal | Add-Member -NotePropertyName "AccountId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                    break
               }
               "1.2.840.113556.5.10" {
                    $retVal | Add-Member -NotePropertyName "AuthUserObjectId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                    break
               }
               "1.2.840.113556.5.11" {
                    $retVal | Add-Member -NotePropertyName "Unknown" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                    break
               }
               "1.2.840.113556.5.14" {
                    $retVal | Add-Member -NotePropertyName "TenantId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                    break
               }
               "1.2.840.113556.5.24" {
                    $retVal | Add-Member -NotePropertyName "Hash" -NotePropertyValue (Convert-ByteArrayToHex -bytes ([byte[]](Get-OidRawValue -RawValue $ext.RawData)))
                    break
               }
            }
        }

        return $retVal
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

# Converts EntraID ObjectID to Security Identifier (SID)
# Dec 3rd 2024 
function Convert-ObjectIDtoSID
{
<#
    .SYNOPSIS
    Converts Entra ID ObjectID to Entra ID SID

    .DESCRIPTION
    Converts Entra ID ObjectID to Entra ID SID used in Entra ID joined devices and access tokens. The resulting SID always starts with S-1-12-1

    .Parameter ObjectID
    Entra ID ObjectID
    
    .Example
    PS C:\>Convert-AADIntObjectIDtoSID -ObjectID "e06e3596-82c0-4f31-ac5a-439a308e3dc2"
    S-1-12-1-3765319062-1328644800-2588105388-3258814000
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [GUID]$ObjectID
    )
    Process
    {
        # Ref: https://github.com/okieselbach/Intune/blob/master/Convert-AzureAdObjectIdToSid.ps1
        $SID = New-Object uint32[] 4
        [System.Buffer]::BlockCopy($ObjectID.ToByteArray(), 0, $SID, 0, 16)

        return "S-1-12-1-$SID".Replace(' ', '-')
    }

}

# Converts EntraID ObjectID to Security Identifier (SID)
# Dec 3rd 2024 
function Convert-SIDtoObjectID
{
<#
    .SYNOPSIS
    Converts Entra ID SID to Entra ID ObjectID

    .DESCRIPTION
    Converts Entra ID SID used in Entra ID joined devices and access tokens to Entra ID ObjectID. The SID must start with S-1-12-1

    .Parameter SID
    Entra ID SID
    
    .Example
    PS C:\>Convert-AADIntSIDtoObjectID -SID "S-1-12-1-3765319062-1328644800-2588105388-3258814000"
    e06e3596-82c0-4f31-ac5a-439a308e3dc2
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [string]$SID
    )
    Process
    {
        # Ref: https://github.com/okieselbach/Intune/blob/master/Convert-AzureAdSidToObjectId.ps1
        $invalidSID = $false
        if(-not $SID.StartsWith("S-1-12-1-"))
        {
            $invalidSID = $true
        }
        else
        {
            try
            {
                $parts = [UInt32[]]$SID.Substring(9).Split('-')
                $guid = New-Object Byte[] 16
                [System.Buffer]::BlockCopy($parts,0,$guid,0,16)

                return [guid]$guid
            }
            catch
            {
                $invalidSID = $true
            }
        }
        if($invalidSID)
        {
            Throw "Invalid SID. SID must start with S-1-12-1"
        }
    }
}