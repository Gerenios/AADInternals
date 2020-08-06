# This script contains common utility functions used in different functions

Function Convert-ByteArrayToHex
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
        [Byte[]]
        $Bytes
    )

    $HexString = [System.Text.StringBuilder]::new($Bytes.Length * 2)

    ForEach($byte in $Bytes){
        $HexString.AppendFormat("{0:x2}", $byte) | Out-Null
    }

    $HexString.ToString().ToUpper()
}


Function Convert-HexToByteArray
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
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
        [Parameter(Mandatory=$True)]
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

            # Double byte integer needed 
            if($digit -gt 127)
            {
                # Move $b1 seven bits to right and switch the first bit on
                $b1 = (($digit -shr 7) -bor 0x80)
                # Keep only the "first" 8 bits by nullifying others
                $b2 = ($digit -band 0xFF)

                $bytes += [byte]$b1
                $bytes += [byte]$b2
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
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes
    )
    Process
    {
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
            # Double byte integer if first bit is set
            if(($Bytes[$pos] -band 0x80) -gt 0)
            {
                $b1 = $Bytes[$pos]
                $b2 = $Bytes[$pos+1]

                # Add the last bit of $b1 to the first bit of $b2 (shift bits one step to right)
                $b2 = $b2 -bor (($b1 -band 1) -shl 7)
                # Switch the first bit of $b1 to 0 and one bit left
                $b1 = ($b1 -band 0x7F) -shr 1

                # Calculate the digit
                $digit = [int]($b1 * 256  + $b2)
                $pos++
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