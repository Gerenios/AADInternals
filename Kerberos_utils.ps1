# Gets sids from AD or AAD
function Get-Sids{
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$SearchString,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # If we got Access Token, search the Azure AD
        if(![String]::IsNullOrEmpty($AccessToken))
        {
            # Get all Azure AD users, filtered users, or just one with userPrincipalName
            $AADUsers = Get-AADUsers -AccessToken $AccessToken -SearchString $SearchString -UserPrincipalName $UserPrincipalName
            $output=@()
            if($AADUsers -ne $null)
            {
                foreach($AADUser in $AADUsers)
                {
                    $properties=@{}
                    $properties.UserPrincipalName = $AADUser.UserPrincipalName
                    
                    $properties.Sid = $AADUser.onPremisesSecurityIdentifier

                    $properties.FullName = $AADUser.displayName
                    
                    $output+=New-Object PSObject -Property $properties
                }
            }
            else
            {
                Write-Error "$UserPrincipalName not found!"
                return
            }
            $output
        }
        else
        {
            # Make the filter if search string is given
            if(![string]::IsNullOrEmpty($SearchString))
            {
                $Filter = "Name LIKE '$SearchString%' or Fullname LIKE '$SearchString%'"

            }
            # If userprincipalname is given, we can't find user with Get-WmiObject so we need to use the DirectorySearcher
            elseif(![string]::IsNullOrEmpty($UserPrincipalName))
            {
                $ADSearch = New-Object System.DirectoryServices.DirectorySearcher
                $ADSearch.Filter="UserPrincipalName=$UserPrincipalName"

                $AADUser=$ADSearch.FindOne()

                if($AADUser -eq $null)
                {
                    Write-Error "$UserPrincipalName not found!"
                    return
                }
                $bSID=$AADUser.Properties.objectsid[0]
                $SID=(New-Object System.Security.Principal.SecurityIdentifier($bSID,0)).Value

                $properties=@{}
                $properties.UserPrincipalName = $UserPrincipalName
                    
                $properties.Sid = $Sid

                $properties.FullName = $AADUser.Properties.displayname[0]

                return New-Object PSObject -Property $properties
            }

            # Query the AD using Get-WmiObject so we don't have to parse each object as with DirectorySearcher
            Get-WmiObject win32_useraccount -Filter $Filter | Where-Object Disabled -eq $false | Select-Object domain,name,fullname,sid
            
        }
    }
}

# Converts bytearray to datetime
# Aug 31st 2019
function DateBytes2Date
{
    Param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$DateBytes
        
    )
    Process
    {
        return [datetime]::FromFileTimeUtc([System.BitConverter]::ToInt64($DateBytes,0))
    }
}

# Converts datetime to bytearray
# Aug 31st 2019
function Date2DateBytes
{
    Param(
        [Parameter(Mandatory=$True)]
        [DateTime]$Date
        
    )
    Process
    {
        return [System.BitConverter]::GetBytes($Date.ToFileTimeUtc())
    }
}

# Converts "20190829080935Z" type of strings to datetime
# Aug 31st 2019
function DateString2Date
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$DateString
        
    )
    Process
    {
        $y = $DateString.Substring(0,4)
        $m = $DateString.Substring(4,2)
        $d = $DateString.Substring(6,2)
        $h = $DateString.Substring(8,2)
        $mm = $DateString.Substring(10,2)
        $s = $DateString.Substring(12,2)
        $DateString = "$y-$m-$d $h`:$mm`:$s`Z"
        #return Get-Date -Year $y -Month $m -Day $d -Hour $h -Minute $mm -Second $s -Millisecond 0
        return Get-Date -Date $DateString
    }
}

# Converts datetime to "20190829080935Z" type of string
# Aug 31st 2019
function Date2DateString
{
    Param(
        [Parameter(Mandatory=$True)]
        [DateTime]$Date
        
    )
    Process
    {
        return $Date.ToUniversalTime().ToString("yyyyMMddHHmmssZ")
    }
}

# Converts datetime to "20190829080935Z" type of string to bytes
# Aug 31st 2019
function Date2DateStringBytes
{
    Param(
        [Parameter(Mandatory=$True)]
        [DateTime]$Date
        
    )
    Process
    {
        return [text.encoding]::ASCII.GetBytes((Date2DAteString $Date))
    }
}


# Encrypts the kerberos ticket using the given password (=key)
function Encrypt-Kerberos
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$False)]
        [byte[]]$Salt,

        [Parameter(Mandatory=$False)]
        [ValidateSet('Ticket','Authenticator','APRepPart','EncKrbPrivPart')]
        [String]$Type="Ticket",

        [Parameter(Mandatory=$False)]
        [ValidateSet('RC4','AES')]
        [String]$Crypto="RC4"
    )
    Process
    {
        if($Crypto -eq "RC4")
        {
            if(!$Salt)
            {
                if($Type -eq "Ticket")
                {
                    [byte[]]$Salt=@(0x02, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "Authenticator")
                {
                    [byte[]]$Salt=@(0x0B, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "APRepPart")
                {
                    [byte[]]$Salt=@(0x0C, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "EncKrbPrivPart")
                {
                    [byte[]]$Salt=@(0x0D, 0x00, 0x00, 0x00)
                }
                else
                {
                    Throw "Unsupported decryption type"
                }
            }
			 
            $k1=$Key


            # Confounder (8 bytes)
            $stuff = Get-RandomBytes -Bytes 8

            $hmac= [System.Security.Cryptography.HMACMD5]::new($k1)
            $k2=$hmac.ComputeHash($Salt) # Salt

            [byte[]]$plainText = $stuff + $Data
   
            $hmac = [System.Security.Cryptography.HMACMD5]::new($k2)
            $checksum = $hmac.ComputeHash($plainText)

            $k3=$hmac.ComputeHash($checksum)

            [byte[]]$cipherText = Get-RC4 -Key $k3 -Data $plaintext

            [byte[]]$cipherText = $checksum + $cipherText
        }
        else
        {
            $Ke = DK -Key $Key -Usage Ticket -KeyDerivationMode Ke

            # Confounder (16 bytes)
            $stuff = Get-RandomBytes -Bytes 16
            [byte[]]$plainText = $stuff + $Data 

            [byte[]]$cipherText = AES_CTS_Encrypt -PlainText $plainText -Key $Ke 

            # Calculate checksum
            $ki = DK -Key $Key -Usage Ticket -KeyDerivationMode Ki
            $hmacsha1 = [System.Security.Cryptography.HMACSHA1]::new($ki)
            $checksum = ($hmacsha1.ComputeHash($plaintext))[0..11]

            [byte[]]$cipherText = $cipherText+$checksum

        }


        return $cipherText
    }
}

# Decrypts Kerberos data
# Mar 26th 2021
function Decrypt-Kerberos
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$False)]
        [byte[]]$Salt,

        [Parameter(Mandatory=$False)]
        [ValidateSet('Ticket','Authenticator','APRepPart','EncKrbPrivPart')]
        [String]$Type="Ticket",

        [Parameter(Mandatory=$False)]
        [ValidateSet('RC4','AES')]
        [String]$Crypto="RC4"
    )
    Process
    {
        if($Crypto -eq "RC4")
        {
            if(!$Salt)
            {
                if($Type -eq "Ticket")
                {
                    [byte[]]$Salt=@(0x02, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "Authenticator")
                {
                    [byte[]]$Salt=@(0x0B, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "APRepPart")
                {
                    [byte[]]$Salt=@(0x0C, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "EncKrbPrivPart")
                {
                    [byte[]]$Salt=@(0x0D, 0x00, 0x00, 0x00)
                }
                else
                {
                    Throw "Unsupported decryption type"
                }
            }
	 
            $k1=$Key

            $hmac= [System.Security.Cryptography.HMACMD5]::new($k1)
            $k2=$hmac.ComputeHash($Salt) # Salt

            [byte[]]$cipher = $Data[16..$($Data.Count-1)]
   
            $hmac = [System.Security.Cryptography.HMACMD5]::new($k2)
            $checksum = $Data[0..15]

            $k3=$hmac.ComputeHash($checksum)

            [byte[]]$plainText = Get-RC4 -Key $k3 -Data $cipher

            $compare = $hmac.ComputeHash($plainText)

            $plainText = [byte[]]$plainText[8..$($plainText.Count-1)]
        }
        else
        {
            $Ke = DK -Key $Key -Usage Ticket -KeyDerivationMode Ke

            [byte[]]$plainText = AES_CTS_Decrypt -CipherText $Data[0..$($Data.Count - 13)] -Key $Ke 

            # Calculate checksum
            $ki = DK -Key $Key -Usage Ticket -KeyDerivationMode Ki
            $hmacsha1 = [System.Security.Cryptography.HMACSHA1]::new($ki)
            $compare = ($hmacsha1.ComputeHash($plainText))[0..11]
            $checksum = $Data[$($plainText.Count)..$($plainText.Count+12)]

            # Strip the confounder
            $plainText = $plainText[16..($plainText.Count)]
        }


        if(@(Compare-Object $checksum $compare -SyncWindow 0).Length -gt 0)
        {
            Write-Warning "Checksum mismatch"
        }

        return $plainText
    }
}

# Get DER Length Bytes
function Get-DERLengthBytes
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $length = $Data.Length
        if($length -lt 128)
        {
            return $length
        }
        elseif($length -lt 256)
        {
            # We return 1000 0010 = multibyte (1000), one bytes (0001)
            return @(0x81, $length)
        }
        else
        {
            $secondByte = $length % 256
            $firstByte = ($length - $secondByte)/256
            # We return 1000 0010 = multibyte (1000), two bytes (0010)
            return @(0x82, $firstByte, $secondByte)
        }
    }
}

# Returns given der tag, length bytes, and the given data
function Add-DERTag
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte]$Tag,
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $output = @($Tag)
        $output += Get-DERLengthBytes($Data)
        $output += $Data
        return $output
    }
}


function Add-DERSet
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $output = @(0x31)
        $output += Get-DERLengthBytes($Data)
        $output += $Data
        return $output
    }
}
function Add-DERSequence
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $output = @(0x30)
        $output += Get-DERLengthBytes($Data)
        $output += $Data
        return $output
    }
}

function Add-DERUnicodeString
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Text,
        [byte]$Tag=0x04,
        [switch]$LE

    )
    Process
    {
        $data = [system.text.encoding]::Unicode.GetBytes($Text)

        # swap the bytes (little-endian)
        if($LE)
        {
            for($a = 0; $a -lt $data.Length ; $a+=2)
            {
                $t=$data[$a]
                $data[$a]=$data[$a+1]
                $data[$a+1]=$t
            }
        }

        $output = @($Tag)
        $output += Get-DERLengthBytes($data)
        $output += $data
        return $output
    }
}

function Add-DERUtf8String
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Text,
        [byte]$Tag=0x1B
    )
    Process
    {
        $data = [system.text.encoding]::UTF8.GetBytes($Text)
        $output = @($Tag)
        $output += Get-DERLengthBytes($data)
        $output += $data
        return $output
    }
}

function Add-DERIA5String
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Text,
        [byte]$Tag=0x16
    )
    Process
    {
        $data = [system.text.encoding]::ASCII.GetBytes($Text)
        $output = @($Tag)
        $output += Get-DERLengthBytes($data)
        $output += $data
        return $output
    }
}

function Add-DERInteger
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        return Add-DERTag -Tag 0x02 -Data $Data
    }
}

function Add-DERBitString
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        return Add-DERTag -Tag 0x03 -Data $Data
    }
}

function Add-DEROctetString
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        return Add-DERTag -Tag 0x04 -Data $Data
    }
}

function Add-DERObjectIdentifier
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$ObjectIdentifier
    )
    Process
    {
        return Add-DERTag -Tag 0x06 -Data (Convert-OidToBytes -Oid $ObjectIdentifier)
    }
}

function Add-DERNull
{
    Process
    {
        return 0x05
    }
}

function Add-DERDate
{
    Param(
        [Parameter(Mandatory=$True)]
        [DateTime]$Date
    )
    Process
    {
        return Add-DERUtf8String -Text $Date.ToUniversalTime().ToString("yyyyMMddHHmmssZ") -Tag 0x18
    }
}

function Add-DERBoolean
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$Value
    )
    Process
    {
        if($Value)
        {
            return @(0x01, 0xFF)
        }
        else
        {
            return @(0x01, 0x00)
        }
    }
}

# Gets an accesstoken using kerberos ticket
# Aug 25th 2019
function Get-AccessTokenWithKerberosTicket
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(Mandatory=$True)]
        [String]$Domain,
        [Parameter(Mandatory=$False)]
        [String]$Resource="https://graph.windows.net",
        [Parameter(Mandatory=$False)]
        [String]$ClientId="1b730954-1685-4b74-9bfd-dac224a7b894",
        [Parameter(Mandatory=$False)]
        [String]$Tenant="common"
    )
    Process
    {
        $requestId = (New-Guid).ToString()

        # Step 1: Get desktop sso token using kerberos ticket
        $url="https://autologon.microsoftazuread-sso.com/$domain/winauth/trust/2005/windowstransport?client-request-id=$requestId"
        $body=@"
        <?xml version='1.0' encoding='UTF-8'?>
            <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust'>
                <s:Header>
                    <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
                    <wsa:To s:mustUnderstand='1'>https://autologon.microsoftazuread-sso.com/$domain/winauth/trust/2005/windowstransport?client-request-id=$requestId</wsa:To>
                    <wsa:MessageID>urn:uuid:$((New-Guid).ToString())</wsa:MessageID>
                </s:Header>
                <s:Body>
                    <wst:RequestSecurityToken Id='RST0'>
                        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                            <wsp:AppliesTo>
                                <wsa:EndpointReference>
                                    <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                                </wsa:EndpointReference>
                            </wsp:AppliesTo>
                            <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
                    </wst:RequestSecurityToken>
                </s:Body>
            </s:Envelope>
"@
        $headers = @{
            "SOAPAction"="http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"
            "Authorization" = "Negotiate $KerberosTicket"
        }
        try
        {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $url -Method Post -Headers $headers -Body $body
        }
        catch
        {
            Write-Error $_.Exception
            return
        }

        [xml]$message = $response
        $dssoToken = $message.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.Assertion.DesktopSsoToken


        # Step 2: get the access token using dssoToken
        $samlAssertion="<saml:Assertion xmlns:saml=`"urn:oasis:names:tc:SAML:1.0:assertion`"><DesktopSsoToken>$dssoToken</DesktopSsoToken></saml:Assertion>"

        $B64samlAssertion=[convert]::ToBase64String([text.encoding]::UTF8.GetBytes($samlAssertion))
        $body=@{
            "grant_type" = "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
            "assertion" = $B64samlAssertion
            "client_id" = $ClientId
            "resource" = $Resource
            "tbidv2" = "" # Optional, see https://tools.ietf.org/html/draft-ietf-tokbind-protocol-19
            "scope" = "openid"
            "redirect_uri" = Get-AuthRedirectUrl -ClientId $ClientId -Resource $Resource # Originally: "ms-appx-web://Microsoft.AAD.BrokerPlugin/$clientId"
            "win_ver" = "10.0.17763.529"
            "windows_api_version" = "2.0"
            "msafed" = "0"
        }
        
        try
        {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token" -Method Post -Body $body
        }
        catch
        {
            if(![String]::IsNullOrEmpty($_.ErrorDetails.Message))
            {
                $error = $_.ErrorDetails.Message.ToString() | ConvertFrom-Json
                Write-Error $error.error_description
                return
            }
            else
            {
                Write-Error $_.exception
                return
            }
        }

        $token = $response.content | ConvertFrom-Json

        # Return
        return $token
    } 
}

# Calculate the server checksum of PAC
function Get-ServerSignature
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $hmacmd5 = [System.Security.Cryptography.HMACMD5]::new([byte[]]$key)
        $ksign = $hmacmd5.ComputeHash([system.text.Encoding]::ASCII.GetBytes("signaturekey")+@(0x00))

        $md5 = [System.Security.Cryptography.MD5]::Create()
        $tmp = $md5.ComputeHash(@(0x11, 0x00 , 0x00, 0x00)+$Data)

        $hmacmd5 = [System.Security.Cryptography.HMACMD5]::new([byte[]]$ksign)

        $signature = $hmacmd5.ComputeHash($tmp)

        return $signature
    }
}


function Get-NFold
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$True)]
        [int]$Size
    )
    Process
    {
        $inBytesSize = $Data.Length
        $outBytesSize = $size

        $a = $outBytesSize
        $b = $inBytesSize

        while ($b -ne 0)
        {
            $c = $b
            $b = $a % $b
            $a = $c
        }

        $lcm = ($outBytesSize * $inBytesSize) / $a

        $outBytes = New-Object byte[] $outBytesSize

        $tmpByte = 0

        for ($i = $lcm - 1; $i -ge 0; $i--)
        {
            $msbit = (($inBytesSize -shl 3) - 1)

            $msbit += ((($inBytesSize -shl 3) + 13) * ([math]::Truncate($i / $inBytesSize)))
            $msbit += (($inBytesSize - ($i % $inBytesSize)) -shl 3)
            $msbit %= $inBytesSize -shl 3

            $rst = $Data[($inBytesSize - 1 - ($msbit -shr 3)) % $inBytesSize] -band 0xff
            $rst2 = $Data[($inBytesSize - ($msbit -shr 3)) % $inBytesSize] -band 0xff

            $msbit = ((($rst -shl 8) -bor ($rst2)) -shr (($msbit -band 7) + 1)) -band 0xff

            $tmpByte += $msbit
            $msbit = $outBytes[$i % $outBytesSize] -band 0xff
            $tmpByte += $msbit

            $outBytes[$i % $outBytesSize] = [byte]($tmpByte -band 0xff)

            $tmpByte = $tmpByte -shr 8
        }

        if ($tmpByte -ne 0)
        {
            for ($i = $outBytesSize - 1; $i -ge 0; $i--)
            {
                $tmpByte += $outBytes[$i] -band 0xff
                $outBytes[$i] = [byte]($tmpByte -band 0xff)

                $tmpByte = $tmpByte -shr 8
            }
        }

        return $outBytes
    }
}

# Encrypts/Decrypts the given plaintext using the given key
# Mar 29th 2021
function AES_CTS_Transform
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key, 
        [Parameter(Mandatory=$False)]
        [byte[]]$InitialVector = [byte[]](0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0),
        [Parameter(Mandatory=$True)]
        [ValidateSet('Encrypt','Decrypt')]
        [String]$Mode
    )
    Process
    {
        [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Padding = "None"
        $AES.Mode = "CBC"
        if($Mode -eq 'Encrypt')
        {
            $transformer = $AES.CreateEncryptor($Key,$InitialVector)
        }
        else
        {
            $transformer = $AES.CreateDecryptor($Key,$InitialVector)
        }

        # Create a memory stream and write the cipher text to it through CryptoStream
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$transformer,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($data,0,$data.Count)
        $cs.Close()
        $cs.Dispose()

        $transformedData = $ms.ToArray()
        $ms.Close()
        $ms.Dispose()

        return $transformedData
    }
}

# Encrypts the given plaintext using the given key
# Mar 29th 2021
function AES_CTS_Encrypt
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$PlainText,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key, 
        [Parameter(Mandatory=$False)]
        [byte[]]$InitialVector = [byte[]](0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
    )
    Process
    {
        $PadSize = 16 - ($PlainText.Count % 16)
        if($PlainText.Count -lt 16)
        {
            return $PlainText
        }

        if($PadSize -eq 16)
        {
            if($PlainText.Count -gt 16)
            {
                $InitialVector = [byte[]](0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
            }

            $data = $PlainText

        }
        else
        {
            $data = [byte[]]@($PlainText + (New-Object byte[] $PadSize))
        }

        $encData = AES_CTS_Transform -Data $data -Key $Key -InitialVector $InitialVector -Mode Encrypt 

        if($PlainText.Count -ge 32)
        {
            $encData = SwapLastTwoBlocks -Data $encData
        }

        $result = New-Object byte[] $PlainText.Count

        [Array]::Copy($encData, 0, $result, 0, $PlainText.Count)

        return $result
    }
}

# Decrypts the given plaintext using the given key
# Mar 29th 2021
function AES_CTS_Decrypt
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$CipherText,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key, 
        [Parameter(Mandatory=$False)]
        [byte[]]$InitialVector = [byte[]](0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
    )
    Process
    {
        $PadSize = 16 - ($CipherText.Count % 16)
        if($CipherText.Count -lt 16)
        {
            return $CipherText
        }

        if($PadSize -eq 16)
        {
            $data = $CipherText

            if($data.Count -ge 32)
            {
                $data = SwapLastTwoBlocks -Data $data
            }
            
            if($data.Count -gt 16)
            {
                $InitialVector = [byte[]](0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
            }

            $decData = AES_CTS_Transform -Data $data -Key $Key -InitialVector $InitialVector -Mode Decrypt

            return $decData
        }
        else
        {
            $depadded = New-Object byte[] 16
            [Array]::Copy($CipherText,($CipherText.Count - 32 + $PadSize),$depadded,0,16)

            [byte[]]$dn = AES_CTS_Transform -Data $depadded -Key $Key -InitialVector $InitialVector -Mode Decrypt

            $data = New-Object byte[] ($CipherText.Count + $PadSize)
            [Array]::Copy($CipherText,0,$data,0,$CipherText.Count)
            [Array]::Copy($dn,($dn.Count - $PadSize),$data,$CipherText.Count,$PadSize)

            $data = SwapLastTwoBlocks -Data $data
            
            [byte[]]$decData =  AES_CTS_Transform -Data $data -Key $Key -InitialVector $InitialVector -Mode Decrypt

            $result = New-Object byte[] $CipherText.Count

            [Array]::Copy($decData,0,$result,0,$CipherText.Count)

            return $result

            $data = [byte[]]@($PlainText + (New-Object byte[] $PadSize))
        }

        [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Padding = "None"
        $AES.Mode = "CBC"
        $encryptor = $AES.CreateEncryptor($Key,$InitialVector)

        # Create a memory stream and write the cipher text to it through CryptoStream
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$encryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($data,0,$data.Count)
        $cs.Close()
        $cs.Dispose()

        $encData = $ms.ToArray()
        $ms.Close()
        $ms.Dispose()

        if($PlainText.Count -ge 32)
        {
            $PlainText = SwapLastTwoBlocks -Data $PlainText
        }

        $result = New-Object byte[] $PlainText.Count

        [Array]::Copy($encData, 0, $result, 0, $PlainText.Count)

        return $result
    }
}

# Swaps last two blocks of the given data. 
function SwapLastTwoBlocks
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        for($i = 0 ; $i -lt 16; $i++)
        {
            [byte]$temp = $data[$i+$data.Count-32]

            $data[$i + $Data.Count -32] = $data[$i + $Data.Count -16]
            $data[$i + $Data.Count -16] = $temp
        }

        return $Data
    }
}

# Random-octect generation function
# https://tools.ietf.org/html/rfc3961
# Mar 28th 021
function DR
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Constant,
        [Parameter(Mandatory=$False)]
        [int]$KeySize = 32,
        [Parameter(Mandatory=$False)]
        [int]$BlockSize = 16
    )
    Process
    {
        if($KeySize -ne $Key.Count)
        {
            Throw "Invalid key size ($($Key.count) bytes), expected $KeySize bytes)"
        }
        $keyBytes = New-Object byte[] $key.Count

        if($Constant.Count -ne $BlockSize)
        {
            $Ki = Get-NFold -Data $Constant -Size $BlockSize
        }
        else
        {
            $ki = $Constant
        }

        $n = 0
        do
        {
            $ki = AES_CTS_Encrypt -PlainText $ki -Key $Key
            if(($n + $BlockSize) -ge $KeySize)
            {
                [Array]::Copy($Ki,0,$KeyBytes,$n,$KeySize-$n)
                break
            }

            [Array]::Copy($Ki,0,$KeyBytes,$n,$BlockSize)

            $n += $BlockSize
        }while($n -lt $KeySize)

        return $keyBytes
    }
}

# Key derivation function
# https://tools.ietf.org/html/rfc3961
# Mar 28th 021
function DK
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,

        [Parameter(ParameterSetName='KDF',Mandatory=$True)]
        [ValidateSet('Unknown','PaEncTs','Ticket','EncAsRepPart','TgsReqAuthDataSessionKey','TgsReqAuthDataSubSessionKey','PaTgsReqChecksum','PaTgsReqAuthenticator','EncTgsRepPartSessionKey','EncTgsRepPartSubSessionKey','AuthenticatorChecksum','ApReqAuthenticator','EncApRepPart','EncKrbPrivPart','EncKrbCredPart','KrbSafeChecksum','OtherEncrypted','PaForUserChecksum','KrbError','AdKdcIssuedChecksum','MandatoryTicketExtension','AuthDataTicketExtension','Seal','Sign','Sequence','AcceptorSeal','AcceptorSign','InitiatorSeal','InitiatorSign','PaServerReferralData','SamChecksum','SamEncTrackId','PaServerReferral','SamEncNonceSad','PaPkInitEx','AsReq','FastReqChecksum','FastEnc','FastRep','FastFinished','EncChallengeClient','EncChallengeKdc','DigestEncrypt','DigestOpaque','Krb5SignedPath','CanonicalizedPath','HslCookie')]
        [string]$Usage = "Ticket",

        [Parameter(ParameterSetName='KDF',Mandatory=$True)]
        [ValidateSet('Kc','Ke','Ki')]
        [string]$KeyDerivationMode = 'Ke',

        [Parameter(ParameterSetName='Constant',Mandatory=$True)]
        [byte[]]$Constant
    )
    Begin
    {
        $KeyDerivationModes = @{
            'Kc' = 0x99
            'Ke' = 0xAA
            'Ki' = 0x55
            }
        $KeyUsages = @{
            Unknown = 0
            PaEncTs = 1
            Ticket = 2
            EncAsRepPart = 3
            TgsReqAuthDataSessionKey = 4
            TgsReqAuthDataSubSessionKey = 5
            PaTgsReqChecksum = 6
            PaTgsReqAuthenticator = 7
            EncTgsRepPartSessionKey = 8
            EncTgsRepPartSubSessionKey = 9
            AuthenticatorChecksum = 10
            ApReqAuthenticator = 11
            EncApRepPart = 12
            EncKrbPrivPart = 13
            EncKrbCredPart = 14
            KrbSafeChecksum = 15
            OtherEncrypted = 16
            PaForUserChecksum = 17
            KrbError = 18
            AdKdcIssuedChecksum = 19

            MandatoryTicketExtension = 20
            AuthDataTicketExtension = 21
            Seal = 22
            Sign = 23
            Sequence = 24
            AcceptorSeal = 22
            AcceptorSign = 23
            InitiatorSeal = 24
            InitiatorSign = 25
            PaServerReferralData = 22
            SamChecksum = 25
            SamEncTrackId = 26
            PaServerReferral = 26
            SamEncNonceSad = 27
            PaPkInitEx = 44
            AsReq = 56
            FastReqChecksum = 50
            FastEnc = 51
            FastRep = 52
            FastFinished = 53
            EncChallengeClient = 54
            EncChallengeKdc = 55


            DigestEncrypt = -18
            DigestOpaque = -19
            Krb5SignedPath = -21
            CanonicalizedPath = -23
            HslCookie = -25
        }
    }
    Process
    {
        if($Constant)
        {
            # Generate a key
            return DR -Key $Key -KeySize ($Key.Count) -Constant $Constant 
        }
        else
        {
            # Generate a constant from Key Usage and Key Derivation Method
            $Constant = New-Object byte[] 5

            $bytes = [System.BitConverter]::GetBytes([int32]$KeyUsages[$Usage])
            [array]::Reverse($bytes)
            [Array]::Copy($bytes,$Constant,4)

            $constant[4] = [byte]$KeyDerivationModes[$KeyDerivationMode]

            return DK -Key $Key -Constant $constant
        }


    }
}


# Aligns sizes in PAC
Function Align-Size
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [int]$Mask,
        [Parameter(Mandatory=$True)]
        [int]$Size
    )
    Process
    {
        $diff = $Size % $Mask
        if($diff -ne 0)
        {
            $Size += 8 - $diff
        }
        
        return $Size
        
    }
}

# Returns null-bytes used to align data fields in PAC
Function Get-AlignBytes
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [int]$Mask,
        [Parameter(Mandatory=$True)]
        [int]$Size
    )
    Process
    {
        $diff = $Size % $Mask
        if($diff -ne 0)
        {
            return New-Object byte[] (8-$diff)
        }
        else
        {
            return
        }
        
    }
}


# Generates Kerberos encryption key
# Apr 1st 2021
function New-KerberosKey
{
    Param(
        [Parameter(Mandatory=$False)]
        [String]$Password,

        [Parameter(Mandatory=$False)]
        [String]$Hash,

        [Parameter(Mandatory=$False)]
        [ValidateSet('RC4','AES')]
        [String]$Crypto="RC4"
    )
    Process
    {
        if([string]::IsNullOrEmpty($Password) -and [string]::IsNullOrEmpty($Hash))
        {
            Throw "Unable to create Kerberos encryption key. Either Password or Hash must be provided"
        }

        if($Crypto -eq "RC4")
        {

            if([string]::IsNullOrEmpty($Password))
            {
                $key = Convert-HexToByteArray -HexString $Hash
            }
            else
            {
                $key = Get-MD4 -String $Password -AsByteArray
            }
        }
        elseif($Crypto -eq "AES")
        {

            if([string]::IsNullOrEmpty($Password))
            {
                $Key = Convert-HexToByteArray -HexString $Hash
            }
            else
            {
                $iterations =    4096
                $pwdBytes  = [text.encoding]::UTF8.GetBytes($Password)

                $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes([byte[]]$pwdBytes,$Salt,$iterations)

                $random = $pbkdf2.GetBytes(32)
                $Key = DK -Key $random -Constant ([text.encoding]::UTF8.GetBytes("kerberos"))
                    
            }
        }
        else
        {
            Throw "Unsupported crypto: $Crypto"
        }

        return $Key
    }
}