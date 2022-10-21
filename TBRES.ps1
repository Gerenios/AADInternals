# This file contains functions to read and decrypt TBRES files

# Parses TBRES files
# Nov 18 2021
Function Parse-TBRES
{

    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [byte[]]$Data
    )
    
    Process
    {
        # Strip the null terminator, convert to string and parse json.
        $json         = [text.encoding]::Unicode.GetString($Data,0,$Data.Length).TrimEnd(0x00) | ConvertFrom-Json

        # Get the encrypted content
        $txtEncrypted = $json.TBDataStoreObject.ObjectData.SystemDefinedProperties.ResponseBytes.Value

        # Convert B64 to byte array
        $binEncrypted = Convert-B64ToByteArray -B64 $txtEncrypted

        # If protected, decrypt with DPAPI
        if($json.TBDataStoreObject.ObjectData.SystemDefinedProperties.ResponseBytes.IsProtected)
        {
            $binDecrypted = [Security.Cryptography.ProtectedData]::Unprotect($binEncrypted,$null,'CurrentUser')
        }
        else
        {
            $binDecrypted = $binEncrypted
        }

        # Parse the expiration time
        $fileTimeUtc = [BitConverter]::ToUInt64((Convert-B64ToByteArray $json.TBDataStoreObject.ObjectData.SystemDefinedProperties.Expiration.Value),0)
        $expires     = [datetime]::FromFileTimeUtc($fileTimeUtc)

        if((Get-Date).ToUniversalTime() -ge $expires)
        {
            Write-Warning "Token is expired"
            return 
        }
        
        return Parse-TBRESResponseBytes -Data $binDecrypted
    }
}

# Parses ResponseBytes TBRES files
# Nov 18 2021
Function Parse-TBRESResponseBytes
{

    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [byte[]]$Data
    )
    Begin
    {
    }
    Process
    {
        # Parses version number from TBRES response bytes
        # Nov 20 2021
        Function Parse-TBRESVersion
        {

            [cmdletbinding()]
            param(
                [parameter(Mandatory=$true,ValueFromPipeline)]
                [byte[]]$Data,
                [parameter(Mandatory=$true,ValueFromPipeline)]
                [ref]$Position,
                [parameter(Mandatory=$false,ValueFromPipeline)]
                [int[]]$ExpectedVersions = @(1,2)
            )
            Process
            {
                $p = $Position.Value
                $version = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4
                if($ExpectedVersions -notcontains $version)
                {
                    Throw "Invalid version $version, expected one of $($ExpectedVersions -join ',')"
                }

                $Position.Value = $p
            }
        }

        # Parses key-value pairs from decrypted TBRES response bytes
        # Nov 20 2021
        Function Parse-TBRESKeyValue
        {

            [cmdletbinding()]
            param(
                [parameter(Mandatory=$true,ValueFromPipeline)]
                [byte[]]$Data,
                [parameter(Mandatory=$true,ValueFromPipeline)]
                [ref]$Position
            )
            Process
            {
                $p = $Position.Value
                $keyType = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4
                if($keyType -ne 0x0c)
                {
                    Throw "Invalid key type $keyType"
                }
                $keyLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4
                $binKey    = $Data[$p..($p + $keyLength -1)]; $p += $keyLength
                $key       = [text.encoding]::UTF8.GetString($binKey)

                $valueType = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4
                switch($valueType)
                {
                    0x0C # String
                    {
                        $valueLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4
                        $value       = [text.encoding]::UTF8.GetString($Data,$p,$valueLength); $p += $valueLength
                        break
                    }
                    0x04 # UInt 32
                    {
                        $value       = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4
                        break
                    }
                    0x05 # UInt 32
                    {
                        $value       = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4
                        break
                    }
                    0x06 # Timestamp
                    {
                        $timestamp   = [BitConverter]::ToUInt64($Data[($p + 7)..$p],0); $p += 8
                        $value       = [datetime]::FromFileTimeUtc($timestamp)
                        break
                    }
                    0x07 # UInt 64
                    {
                        $value       = [BitConverter]::ToUInt64($Data[($p + 7)..$p],0); $p += 8
                        break
                    }
                    0x0D # Guid
                    {
                        $value       = [guid][byte[]]$Data[$p..($p + 15)]; $p += 16
                        break
                    }
                    1025 # Content identifier?
                    {
                        # This is the second content "identifier" 
                        if($binKey.Length -eq 1 -and $binKey[0] -gt 1)
                        {
                            Write-Verbose "Content identifier $($binKey[0]), getting the next Key-Value."
                            # Read the size
                            $length = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4

                            # Parse version
                            Parse-TBRESVersion -Data $Data -Position ([ref]$p)

                            # Get the next value
                            $next   = Parse-TBRESKeyValue -Data $Data -Position ([ref]$p)
                            $key    = $next.Key
                            $value  = $next.Value
                            break
                        }
                        
                        break
                    }
                    default
                    {
                        Write-Verbose "Unknown value type $valueType"
                        $value = $valueType
                        break
                    }
                }

                $Position.Value = $p

                return [PSCustomObject][ordered]@{
                        "Key"   = $key
                        "Value" = $value
                    }
            }
        }

        # Parses elements from decrypted TBRES response bytes content
        # Nov 20 2021
        Function Parse-TBRESElement
        {

            [cmdletbinding()]
            param(
                [parameter(Mandatory=$true,ValueFromPipeline)]
                [byte[]]$Data,
                [parameter(Mandatory=$true,ValueFromPipeline)]
                [ref]$Position,
                [parameter(Mandatory=$false,ValueFromPipeline)]
                [PSCustomObject]$Element
            )
            Process
            {
                $p = $Position.Value
                $value = $null

                # Parse element & length
                if(!$Element)
                {
                    $element = Parse-TBRESKeyValue -Data $Data ([ref]$p)
                }
                Write-Debug $element

                $elementLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4

                if($element.Key -eq "WTRes_Error")
                {
                    Write-Verbose "WTRes_Error file, skipping.."
                    return $null
                }
                elseif($element.Key -eq "WTRes_Token")
                {
                    Write-Verbose "Parsing WTRes_Token"

                    # We already read the length so adjust
                    $p -= 4
                
                    # Parse status
                    $status = Parse-TBRESKeyValue -Data $Data ([ref]$p)

                    if($status.Value -ne 0)
                    {
                        Write-Warning "WTRes_Token status $($status.Value)"
                    }

                    $value = $element.Value
                }
                # Parse WTRes_PropertyBag and WTRes_Account
                else 
                {
                    $propertyBagStart = $p

                    Write-Verbose "Parsing $($element.Key), $elementLength bytes"
                
                    # Parse version
                    Parse-TBRESVersion -Data $Data -Position ([ref]$p)

                    $properties = [ordered]@{}
                    While($p -lt ( $propertyBagStart + $elementLength))
                    {
                        $property = Parse-TBRESKeyValue -Data $Data ([ref]$p)
                        if($property.Key -eq "WA_Properties" -or $property.Key -eq "WA_Provier")
                        {
                            $property.Value = Parse-TBRESElement -Data $Data ([ref]$p) -Element $property
                        }
                        $properties[$property.Key] = $property.Value
                    }
                    $value = [PSCustomObject]$properties
                }

                $Position.Value = $p

                return [PSCustomObject][ordered]@{
                        "Key"   = $element.Key
                        "Value" = $value
                    }
            }
        }

        $p = 0

        # Parse version
        Parse-TBRESVersion -Data $Data -Position ([ref]$p)

        # Parse expiration timestamp and responses guid
        $expiration = (Parse-TBRESKeyValue -Data $Data ([ref]$p)).value
        $responses  = (Parse-TBRESKeyValue -Data $Data ([ref]$p)).value

        # Total response content length
        $responseLen = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4

        # Parse version
        Parse-TBRESVersion -Data $Data -Position ([ref]$p)
        

        # It seems that sometimes the content have multiple "entries"
        # These start with the following key-value pair:
        # First:  Key = 0x01 and Value = 1025
        # Second: Key = 0x01 and Value = 1025
        # These are handled in Parse-TBRESKeyValue function
        
        $unk = Parse-TBRESKeyValue -Data $Data ([ref]$p)

        #
        # Content
        # 

        # Content length
        $contentLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p],0); $p += 4
        $contentStart  = $p        

        # Parse version
        Parse-TBRESVersion -Data $Data -Position ([ref]$p)
        
        # Return value
        $properties = [ordered]@{}

        while($p -le ($contentStart + $contentLength))
        {
            try
            {
                $element = Parse-TBRESElement -Data $Data -Position ([ref]$p)
                if($element -eq $null)
                {
                    return $null
                }
                $properties[$element.Key] = $element.Value
            }
            catch
            {
                Write-Verbose "Got exception: $($_.Exception.Message)"
                break
            }
        }

        return [PSCustomObject]$properties
    }
}