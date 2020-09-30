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

# Decrypts kerberos ticket using the given password
# Aug 20th 2019
function Decrypt-Kerberos
{
    Param(
        [Parameter(ParameterSetName='Password',Mandatory=$True)]
        [String]$Password,
        [Parameter(ParameterSetName='Key',Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Cipher
    )
    Process
    {
        if($Key -ne $null)
        {
            # This used for the second decrypted block (authenticator) using the session key
            $k1=$Key
            [byte[]]$Salt=@(0x0B, 0x00, 0x00, 0x00)
        }
        else
        {
            # This used for the first decrypted block
            $k1=Get-MD4 -String $Password -AsByteArray
            [byte[]]$Salt=@(0x02, 0x00, 0x00, 0x00)
        }

        $hmac= [System.Security.Cryptography.HMACMD5]::new($k1)
        $k2=$hmac.ComputeHash($Salt)
        
        $checksum = $Cipher[0..15]

        $hmac = [System.Security.Cryptography.HMACMD5]::new($k2)
        $k3=$hmac.ComputeHash($checksum)

        $cipher = $Cipher[16..$Cipher.Length]

        [byte[]]$plainText = Get-RC4 -Key $k3 -Data $cipher

        $actualChecksum = $hmac.ComputeHash($plainText)

        if((Compare-Object -ReferenceObject $checksum -DifferenceObject $actualChecksum) -ne $null)
        {
            Throw "Checksums doesn't match!"
        }
        Write-Host "Stuff $($plaintext[0..7] | format-hex))"
        $output = $plaintext[8..$plainText.Length]
 
        return $output
    }
}

# Encrypts the kerberos ticket using the given password (=key)
function Encrypt-Kerberos
{
    Param(
        [Parameter(ParameterSetName='Password',Mandatory=$False)]
        [String]$Password,
        [Parameter(ParameterSetName='Password',Mandatory=$False)]
        [String]$Hash,
        [Parameter(ParameterSetName='Key',Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        # Create some random bytes
        $stuff = (New-Guid).ToByteArray()[0..7]
        if($Key -ne $null)
        {
            $k1=$Key
            [byte[]]$Salt=@(0x0B, 0x00, 0x00, 0x00)
        }
        else
        {
            if([string]::IsNullOrEmpty($Password))
            {
                $k1=Convert-HexToByteArray -HexString $Hash
            }
            else
            {
                $k1=Get-MD4 -String $Password -AsByteArray
            }
            [byte[]]$Salt=@(0x02, 0x00, 0x00, 0x00)
        }

        $hmac= [System.Security.Cryptography.HMACMD5]::new($k1)
        $k2=$hmac.ComputeHash($Salt) # Salt

        [byte[]]$plainText = $stuff + $Data
   
        $hmac = [System.Security.Cryptography.HMACMD5]::new($k2)
        $checksum = $hmac.ComputeHash($plainText)

        $k3=$hmac.ComputeHash($checksum)


        [byte[]]$cipher = Get-RC4 -Key $k3 -Data $plaintext

        return [byte[]]$checksum+$cipher
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
        [String]$ClientId="1b730954-1685-4b74-9bfd-dac224a7b894"
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
            "redirect_uri" = "urn:ietf:wg:oauth:2.0:oob" # Originally: "ms-appx-web://Microsoft.AAD.BrokerPlugin/$clientId"
            "win_ver" = "10.0.17763.529"
            "windows_api_version" = "2.0"
            "msafed" = "0"
        }

        try
        {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Body $body
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