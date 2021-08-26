# Updated Apr 22nd 2021


#May 24th 2019
function New-ADFSSelfSignedCertificates
{
<#
    .SYNOPSIS
    Creates new self-signed Token Signing and Token Decrypt certificates for ADFSService

    .Description
    Disables auto rollover and creates new self-signed Token Signing and Token Decrypt certificates for ADFSService. 
    Certificates are added to ADFS and the service is restarted. Certificates are also saved to the current directory.
  
    .Parameter PfxPassword
    Password for the Token Signing and Token Decrypt .pfx files. Default is "AADInternals".

    .Example
    New-AADIntADFSSelfSignedCertificates
    
    .Example
    New-AADIntADFSSelfSignedCertificates -PfxPassword "MyPassword"
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword="AADInternals",
        [Switch]$Force
    )
    Process
    {

        # Set the password
        $CertificatePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText

        # Check the auto rollover status
        if(!$Force -and !(Get-AdfsProperties).AutoCertificateRollover)
        {
            Write-Error "Certificate Auto Rollover is allready disabled!"
            return
        }

        # Disable auto rollover
        Set-ADFSProperties -AutocertificateRollover $false

        # Get the current certificates
        $Cur_SigningCertificate = Get-AdfsCertificate -CertificateType Token-Signing
        $Cur_DecryptCertificate = Get-AdfsCertificate -CertificateType Token-Decrypting

        # Create new certificates with the same name and store to LocalMachine store
        $New_SigningCertificate = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DnsName $Cur_SigningCertificate.Certificate.DnsNameList[0].Unicode -NotAfter (Get-Date).AddYears(10) -NotBefore $Cur_SigningCertificate.Certificate.NotBefore -KeyExportPolicy Exportable -TextExtension @("2.5.29.37={text}2.5.29.37.0") -KeySpec KeyExchange
        $New_DecryptCertificate = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DnsName $Cur_DecryptCertificate.Certificate.DnsNameList[0].Unicode -NotAfter (Get-Date).AddYears(10) -NotBefore $Cur_DecryptCertificate.Certificate.NotBefore -KeyExportPolicy Exportable -TextExtension @("2.5.29.37={text}2.5.29.37.0") -KeySpec KeyExchange

        # Export the new certificates
        Export-PfxCertificate -FilePath "ADFS_Token_Signing.pfx" -Password $CertificatePassword -Cert $New_SigningCertificate |Out-Null
        Export-PfxCertificate -FilePath "ADFS_Token_Decrypt.pfx" -Password $CertificatePassword -Cert $New_DecryptCertificate |Out-Null

        # Add certificates to ADFS
        Add-AdfsCertificate -CertificateType Token-Signing -Thumbprint $New_SigningCertificate.Thumbprint 
        Add-AdfsCertificate -CertificateType Token-Decrypting -Thumbprint $New_DecryptCertificate.Thumbprint 

        # Set the new ones as primary
        Set-AdfsCertificate -CertificateType Token-Signing -Thumbprint $New_SigningCertificate.Thumbprint -IsPrimary
        Set-AdfsCertificate -CertificateType Token-Decrypting -Thumbprint $New_DecryptCertificate.Thumbprint -IsPrimary

        # Remove the old ones from ADFS
        Remove-AdfsCertificate -CertificateType Token-Signing -Thumbprint $Cur_SigningCertificate.Thumbprint
        Remove-AdfsCertificate -CertificateType Token-Decrypting -Thumbprint $Cur_DecryptCertificate.Thumbprint

        # Get the ADFS service information
        $Service=Get-WMIObject -namespace "root\cimv2" -class Win32_Service -Filter 'Name="ADFSSRV"'

        # Create an accessrule for private keys
        $AccessRule = New-Object Security.AccessControl.FileSystemAccessrule $service.StartName, "read", allow
        $Root = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys"

        # Give read permissions to private key of Signing Certificate
        $rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($New_SigningCertificate)
        $fileName = $rsaCert.key.UniqueName
        $path="$Root\$fileName"
        $permissions = Get-Acl -Path $path
        $permissions.AddAccessRule($AccessRule)
        Set-Acl -Path $path -AclObject $permissions

        # Give read permissions to private key of Decryption Certificate
        $rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($New_DecryptCertificate)
        $fileName = $rsaCert.key.UniqueName
        $path="$Root\$fileName"
        $permissions = Get-Acl -Path $path
        $permissions.AddAccessRule($AccessRule)
        Set-Acl -Path $path -AclObject $permissions

        # Restart ADFS service
        Restart-Service ADFSSrv

        # Output 
        Write-Host "Certificates successfully created and added to ADFS!"
        Write-Host "Certificates also exported to ADFS_Token_Decrypt.pfx and ADFS_Token_Signing.pfx using password `"$PfxPassword`""
        Write-Warning "Remember to update federation settings to Azure AD using Update-AADIntADFSFederationSettings!"
    }
}

#May 24th 2019
function Restore-ADFSAutoRollover
{
<#
    .SYNOPSIS
    Restores ADFS to "normal" mode: Token Signing and Token Decryption certificates are automatically rolled over once a year.

    .Description
    Enables certificate auto rollover, updates Token Signing and Token Decryption certificates and removes the old self-signed certificates.
  
    .Example
    Restore-AADIntADFSAutoRollover
#>
    [cmdletbinding()]
    Param(
        [Switch]$Force
    )
    Process
    {
        # Check the auto rollover status
        if(!$Force -and (Get-AdfsProperties).AutoCertificateRollover)
        {
            Write-Error "Certificate Auto Rollover is allready enabled!"
            return
        }

        # Enable auto rollover
        Set-ADFSProperties -AutocertificateRollover $true

        # Get the current certificates
        $Cur_SigningCertificate = Get-AdfsCertificate -CertificateType Token-Signing
        $Cur_DecryptCertificate = Get-AdfsCertificate -CertificateType Token-Decrypting

        # Update certificates 
        Update-AdfsCertificate -CertificateType Token-Signing -Urgent
        Update-AdfsCertificate -CertificateType Token-Decrypting -Urgent
       
       # Remove the old certificates from the certificate store
        Remove-Item "Cert:\LocalMachine\My\$($Cur_SigningCertificate.Thumbprint)" -ErrorAction SilentlyContinue
        Remove-Item "Cert:\LocalMachine\My\$($Cur_DecryptCertificate.Thumbprint)" -ErrorAction SilentlyContinue

        # Restart ADFS service
        Restart-Service ADFSSrv

        # Output
        Write-Host "Autorollover succesfully turned on and old certificates removed from ADFS and certstore."
        Write-Warning "Remember to update federation settings to Azure AD using Update-AADIntADFSFederationSettings!"
     }
}

#May 25th 2019
function Update-ADFSFederationSettings
{
<#
    .SYNOPSIS
    Updates federation information of the given domain to match the local ADFS server information.

    .Description
    Updates federation information of the given domain to match the local ADFS server information.
  
    .Parameter AccessToken
    Access Token

    .Parameter Domain
    The domain to be updated

    .Example
    Update-AADIntADFSFederationSettings -Domain company.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$DomainName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Get the current settings from cloud
        $FederationSettings = Get-DomainFederationSettings -DomainName $DomainName -AccessToken $AccessToken

        # Get the current certificates
        $Cur_SigningCertificate = Get-AdfsCertificate -CertificateType Token-Signing

        #$Cur_PublicKey = [Convert]::ToBase64String($Cur_SigningCertificate.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12))
        $Cur_PublicKey = [Convert]::ToBase64String($Cur_SigningCertificate.Certificate.GetRawCertData())

        # Check the settings
        if($Cur_PublicKey -eq $FederationSettings.SigningCertificate)
        {
            Write-Host "Settings already up to date!"
            return
        }

        # Update federation settings
        Set-DomainFederationSettings -AccessToken $AccessToken -DomainName $DomainName  `
            -ActiveLogOnUri $FederationSettings.ActiveLogOnUri `
            -FederationBrandName $FederationSettings.FederationBrandName `
            -IssuerUri $FederationSettings.IssuerUri `
            -LogOffUri $FederationSettings.LogOffUri `
            -MetadataExchangeUri $FederationSettings.MetadataExchangeUri `
            -PassiveLogOnUri $FederationSettings.PassiveLogOnUri `
            -PreferredAuthenticationProtocol $FederationSettings.PreferredAuthenticationProtocol `
            -SigningCertificate $Cur_PublicKey

        Write-Host "Federation information updated!"
     }
}

# Parses GSS_Wrap and returns the encrypted data part
# Apr 1st 2021
function Parse-GSS_Wrap
{
    Param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$Data,
        [Parameter(Mandatory=$True)]
        [Byte[]]$SessionKey,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Initiator','Acceptor')]
        [String]$Direction = 'Initiator',
        [Parameter(Mandatory=$True)]
        [Int]$SequenceNumber,
        [Parameter(Mandatory=$False)]
        [Int]$Type = 23 # 23 = rc4-hmac, 18 = aes256-cts-hmac-sha1-96
    )
    Process
    {
        if($Type -eq 18 ) # aes256-cts-hmac-sha1-96
        {
            # TODO: implement support for this
            Throw "Unsupported GSS_WRAP type: $Type"

            $s = 0

            # Get the token header information
            $TOK_ID =   $Data[$s..($s+1)] ; $s+=2
            $Flags =    $Data[        $s] ; $s+=1
            $Filler =   $Data[        $s] ; $s+=1
            $EC =       $Data[$s..($s+1)] ; $s+=2
            $RRC =      $Data[$s..($s+1)] ; $s+=2
            $SND_SEQ =  $Data[$s..($s+7)] ; $s+=8

            [array]::Reverse($RRC)
            $rotations = [bitconverter]::TouInt16($RRC,0)
            

            [array]::Reverse($SND_SEQ)
            if([bitconverter]::TouInt32($SND_SEQ,0) -ne $SequenceNumber)
            {
                Write-Warning "Sequence number mismatch!"
            }

            # Extract token information
            $encData = $Data[$s..($data.Count - 1)]

            # Rotate the data
            for($r = 0; $r -lt $rotations; $r++)
            {
                $t = $encData[$encData.Count-1]
                for($i = $encData.Count-1 ; $i -gt 0; $i--)
                {
                    $encData[$i] = $encData[$i-1]
                }
                $encData[0] = $t

            }
            $encData | Format-Hex
            
            return
        }
        elseif($Type -eq 23) # rc4-hmac
        {

            # Generate the sequence number from the given integer and add "direction" bytes
            $SND_SEQ = [System.BitConverter]::GetBytes([uint32]$SequenceNumber)
            [Array]::Reverse($SND_SEQ)
            if($Direction -eq 'Initiator')
            {
                $SND_SEQ += @(0xff, 0xff, 0xff, 0xff)
            }
            else
            {
                $SND_SEQ += @(0x00, 0x00, 0x00, 0x00)
            }

            # Get object identifier
            $tokLen = $Data[1]
            $oidLen = $Data[3]
            $oid = Convert-BytesToOid -Bytes $Data[4..(4+$oidLen-1)]
            $s = 4+$oidLen

            # Save the header for checksum calculation
            $TOKEN_HEADER = $Data[$s..($s+7)]

            # Get the token header information
            $TOK_ID =   $Data[$s..($s+1)] ; $s+=2
            $SGN_ALG =  $Data[$s..($s+1)] ; $s+=2
            $SEAL_ALG = $Data[$s..($s+1)] ; $s+=2
            $Filler =   $Data[$s..($s+1)] ; $s+=2

            # Extract token information
            $encSND_SEQ =         $Data[$s..($s+7)] ; $s+=8
            $SGN_CHKSUM =         $Data[$s..($s+7)] ; $s+=8
            $encSGN_Confounder =  $Data[$s..($s+7)] ; $s+=8
            $encData =            $Data[$s..($data.Count - 1)]

            # Validation
            # Token id should be 0x0102
            if(($tid=[System.BitConverter]::ToInt16($TOK_ID,0)) -ne 0x102)
            {
                Write-Warning "Unknown TOKEN_ID ($tid), expected 256"
            }
            # Signing algorithm should be HMAC 0x0011
            if(($sgalg=[System.BitConverter]::ToInt16($SGN_ALG,0)) -ne 0x11)
            {
                Write-Warning "Unknown SGN_ALG  ($sgalg), expected HMAC (17)"
            }
            # Encryption algorithm should be RC4 0x0010
            if(($enalg=[System.BitConverter]::ToInt16($SEAL_ALG,0)) -ne 0x10)
            {
                Write-Warning "Unknown SEAL_ALG ($enalg), expected RC4 (16)"
            }

            # Generate signature key by calculating MD5 HMAC from "signaturekey"+0x00 using the session key
            $Ksign = [System.Security.Cryptography.HMACMD5]::New($SessionKey).ComputeHash([text.encoding]::UTF8.GetBytes("signaturekey`0"))

            # Generate decryption keys 
            $Klocal = New-Object byte[] $SessionKey.Count
            for($a = 0 ; $a -lt $SessionKey.Count ; $a++)
            {
                $Klocal[$a] = $SessionKey[$a] -bxor 0xF0
            }

            $Kseq =   [System.Security.Cryptography.HMACMD5]::New($SessionKey).ComputeHash([byte[]]@(0x00, 0x00, 0x00, 0x00))
            $Kseq =   [System.Security.Cryptography.HMACMD5]::New($Kseq      ).ComputeHash($SGN_CHKSUM)

            $Kcrypt = [System.Security.Cryptography.HMACMD5]::New($Klocal    ).ComputeHash([byte[]]@(0x00, 0x00, 0x00, 0x00))        
            $Kcrypt = [System.Security.Cryptography.HMACMD5]::New($Kcrypt    ).ComputeHash($SND_SEQ[0..3])  

            # Decrypt sequence number
            $decSND_SEQ =        Get-RC4 -Key $Kseq   -Data $encSND_SEQ
            if(Compare-Object -ReferenceObject $decSND_SEQ -DifferenceObject $SND_SEQ -SyncWindow 0)
            {
                Write-Warning "Sequence number mismatch!"
            }

            # Decrypt data
            $decSGN_Confounder = Get-RC4 -Key $Kcrypt -Data $encSGN_Confounder
            $decData =           Get-RC4 -Key $Kcrypt -Data @($decSGN_Confounder + $encData)
            $decData =           $decData[8..($decData.Count-1)]
            $decSGN_CHKSUM =     Get-RC4 -Key $Kcrypt -Data $encSGN_CHKSUM

            # Calculate MD5 checksum: Salt + header + confounder + data
            $SGN_CHKSUM2 =  [System.Security.Cryptography.MD5    ]::Create().ComputeHash(@(@(13,0,0,0) + $TOKEN_HEADER + $decSGN_Confounder + $decData))
            $SGN_CHKSUM2 = ([System.Security.Cryptography.HMACMD5]::New($Ksign).ComputeHash($SGN_CHKSUM2))[0..7]

            if(Compare-Object -ReferenceObject $SGN_CHKSUM -DifferenceObject $SGN_CHKSUM2 -SyncWindow 0)
            {
                Write-Warning "Invalid checksum!"
            }

            return $decData
        }
        else
        {
            Throw "Unsupported GSS_WRAP type: $Type"
        }
    }
}

# pHash 
# https://www.ietf.org/rfc/rfc2246.txt
# Apr 5th 2021
function Get-PSHA1
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Secret,
        [Parameter(Mandatory=$True)]
        [byte[]]$Seed,
        [Parameter(Mandatory=$False)]
        [int]$Bytes=32
    )
    Process
    {
        [System.Security.Cryptography.HMACSHA1]$HMAC = [System.Security.Cryptography.HMACSHA1]::New($Secret)
        $PSHA1=@()

        $A = $seed
        $p = 0

        while($p -lt $Bytes)
        {
            $A = $HMAC.ComputeHash($A)
            $PSHA1 += $HMAC.ComputeHash(($A + $Seed))
            $p+=$A.Count
        }
        
        $HMAC.Dispose()

        return [byte[]]($PSHA1[0..($Bytes-1)])
    }
}

# Decrypts the given ciphertext
# Apr 9th 2021
function Decrypt-WSTrustCipherData
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$CipherText,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key
    )
    Process
    {
        # The first 16 bytes are the IV
        $InitialVector = $cipherText[0..15]
        $encText =       $cipherText[16..($cipherText.Count-1)]

        # Decrypt the cipher text
        [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Mode =    "CBC"
        $AES.Key =     $Key
        $AES.IV =      $InitialVector
        $transformer = $AES.CreateDecryptor()

        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$transformer,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($encText,0,$encText.Count)
        $cs.Close()
        $cs.Dispose()

        $transformedData = $ms.ToArray()
        $ms.Close()
        $ms.Dispose()

        return $transformedData
    }
}

# Encrypts the given plaintext
# Apr 10th 2021
function Encrypt-WSTrustCipherData
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$PlainText,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key
    )
    Process
    {
        # Create a random IV
        $InitialVector = Get-RandomBytes -Bytes 16

        # Encrypt the cipher text
        [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Mode =    "CBC"
        $AES.Key =     $Key
        $AES.IV =      $InitialVector
        $transformer = $AES.CreateEncryptor()

        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$transformer,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($PlainText,0,$PlainText.Count)
        $cs.Close()
        $cs.Dispose()

        $transformedData = $ms.ToArray()
        $ms.Close()
        $ms.Dispose()
        
        return [byte[]]($InitialVector+$transformedData)
    }
}


# Derives the key from proof token and nonce
# Apr 9th 2021
function Derive-WSTrustKey
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Nonce,
        [Parameter(Mandatory=$False)]
        [int]$Bytes = 32
    )
    Begin
    {
        # Default label (mis)used by Microsoft
        $Label = [text.encoding]::ASCII.GetBytes("WS-SecureConversationWS-SecureConversation")
    }
    Process
    {
        $derivedKey = Get-PSHA1 -Secret $Key -Seed ($label+$Nonce) -Bytes $Bytes
        
        return $derivedKey
    }
}

# Creates a SOAP envelope for RST
# Apr 13th 2021
function Create-RSTEnvelope
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Server,
        [Parameter(Mandatory=$True)]
        [String]$KerberosTicket
    )
    Process
    {
        $messageId = (New-Guid).ToString()
        $envelope=@"
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	        <s:Header>
		        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
		        <a:MessageID>urn:uuid:$messageId</a:MessageID>
		        <a:ReplyTo>
			        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		        </a:ReplyTo>
		        <a:To s:mustUnderstand="1">http://$Server/adfs/services/policystoretransfer</a:To>
	        </s:Header>
	        <s:Body>
		        <t:RequestSecurityToken Context="uuid-$((New-Guid).ToString())" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
			        <t:TokenType>http://schemas.xmlsoap.org/ws/2005/02/sc/sct</t:TokenType>
			        <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
			        <t:KeySize>256</t:KeySize>
			        <t:BinaryExchange ValueType="http://schemas.xmlsoap.org/ws/2005/02/trust/spnego" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">$KerberosTicket</t:BinaryExchange>
		        </t:RequestSecurityToken>
	        </s:Body>
        </s:Envelope>
"@

        return $envelope
    }
}

# Parse RST response
# Apr 14th 2021
function Parse-RSTR
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$RSTR,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key
    )
    Process
    {
        # Extract information from the RSTR
        $krb_response =  Convert-B64ToByteArray -B64 $RSTR.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse[0].BinaryExchange.'#text'
        $proofToken =    Convert-B64ToByteArray -B64 $RSTR.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse[0].RequestedProofToken.EncryptedKey.CipherData.CipherValue
        $keyIdentifier = [guid](($RSTR.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse[0].RequestedSecurityToken.SecurityContextToken.Identifier).Split(":")[2])
        $context =       $RSTR.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse[0].RequestedSecurityToken.SecurityContextToken.Id

        # Parse the ticket
        $ticket = Parse-Asn1 -Data $krb_response

        # Get the encrypted kerberos ticket
        $encKRB = $ticket.Data.Data[2].Data.Data
        $encKRB = Parse-Asn1 -Data $encKRB
        $encKRB = $encKRB.Data[2].Data.Data[2].Data.Data[1].Data.Data

        # Decrypt the ticket
        $decKRB = Decrypt-Kerberos -Data $encKRB -Key $Key -Type APRepPart -Crypto RC4
        $decKRB = Parse-Asn1 -Data $decKRB

        # Get the sequence number and subkey
        $SequenceNumber = $decKRB.Data.Data[3].Data.Data
        $SubKey =         $decKRB.Data.Data[2].Data.Data[1].Data.Data
        $EncryptionType = $decKRB.Data.Data[2].Data.Data[0].Data.Data

        Write-Verbose "Subkey:        $(Convert-ByteArrayToB64 -Bytes $subKey)"
        Write-Verbose "Sequence num:  $sequenceNumber"

        # Extract the key from the proof token
        $securityKey = (Parse-GSS_Wrap -Type $EncryptionType -Data $proofToken -SessionKey $subKey -Direction Initiator -SequenceNumber $sequenceNumber)[0..31]

        Write-Verbose "Security key:  $(Convert-ByteArrayToB64 -Bytes $securityKey)"
        Write-Verbose "Context:       $context"
        Write-Verbose "Identifier:    $keyIdentifier"

        # Construct the return value
        $retVal = New-Object psobject -Property @{"Context" = $context; "Key" = $securityKey; "Identifier" = $keyIdentifier}

        return $retVal
    }
}

# Creates a SOAP envelope for RST SCT
# Apr 14th 2021
function Create-SCTEnvelope
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$ClientSecret,
        [Parameter(Mandatory=$True)]
        [String]$Context,
        [Parameter(Mandatory=$True)]
        [guid]$KeyIdentifier,
        [Parameter(Mandatory=$True)]
        [string]$Server
    )
    Process
    {
        
        $payload = "<t:RequestSecurityToken xmlns:t=""http://schemas.xmlsoap.org/ws/2005/02/trust""><t:TokenType>http://schemas.xmlsoap.org/ws/2005/02/sc/sct</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:Entropy><t:BinarySecret Type=""http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce"" u:Id=""uuid-$((New-Guid).ToString())"">$(Convert-ByteArrayToB64 -Bytes $ClientSecret)</t:BinarySecret></t:Entropy><t:KeySize>256</t:KeySize></t:RequestSecurityToken>"
        $action = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT"

        $envelope = Create-ADFSSoapEnvelope -Key $Key -Context $Context -KeyIdentifier $KeyIdentifier -Server $Server -Payload $payload -Action $action

        return $envelope
    }
}

# Parse CST response
# Apr 14th 2021
function Parse-SCTR
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$SCTR,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key
    )
    Process
    {
        # Parse the response and fetch the server secret
        [xml]$xPlaintext = Parse-ADFSResponse -Response $SCTR -Key $Key
        $token =           $xPlaintext.RequestSecurityTokenResponse.Entropy.BinarySecret.'#text'
        
        $serverSecret = Convert-B64ToByteArray -B64 $token
        $computedKey =  Get-PSHA1 -Secret $clientSecret -Seed $serverSecret -Bytes 32

        $context =       $xPlaintext.RequestSecurityTokenResponse.RequestedSecurityToken.SecurityContextToken.Id
        $keyIdentifier = [guid](($xPlaintext.RequestSecurityTokenResponse.RequestedSecurityToken.SecurityContextToken.Identifier).Split(":")[2])

        Write-Verbose "Server secret: $(Convert-ByteArrayToB64 -Bytes $serverSecret)"
        Write-Verbose "Computed key:  $(Convert-ByteArrayToB64 -Bytes $computedKey)"
        Write-Verbose "Context:       $context"
        Write-Verbose "Identifier:    $keyIdentifier"

        # Construct the return value
        $retVal = New-Object psobject -Property @{"Context" = $context; "Key" = $computedKey; "Identifier" = $keyIdentifier}

        return $retVal
    }
}

# Checks whether the response is a soap error
# Apr 15th 2021
function Check-SoapError
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$Message
    )
    Process
    {
        # Check for the fault message
        if($Message.Envelope.Body.Fault)
        {
            $Message = $Message.Envelope.Body.Fault.OuterXml
        }

        if($Message.Fault)
        {
            $reason = $Message.Fault.Reason.Text.'#text'
            throw $reason
        }
    }
}

# Parse ADFS Soap response
# Apr 14th 2021
function Parse-ADFSResponse
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$Response,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key
    )
    Process
    {
        # Extract nonce and cipher texts
        # The first nonce is used to derive key used for ENCRYPTING, the second one is for SIGNING
        # The cipher data in header is the signature block, which is not needed here

        #$nonce0 =  Convert-B64ToByteArray -B64 $Response.Envelope.Header.Security.DerivedKeyToken[0].Nonce
        #$cipher0 = Convert-B64ToByteArray -B64 $Response.Envelope.Header.Security.EncryptedData.CipherData.CipherValue
        $nonce1 =  Convert-B64ToByteArray -B64 $Response.Envelope.Header.Security.DerivedKeyToken[1].Nonce
        $cipher1 = Convert-B64ToByteArray -B64 $Response.Envelope.Body.EncryptedData.CipherData.CipherValue

        # Derive the key
        $derivedKey = Derive-WSTrustKey -Key $Key -Nonce $nonce1

        Write-Verbose "Nonce:         $(Convert-ByteArrayToB64 -Bytes $nonce1)"
        Write-Verbose "Derived key:   $(Convert-ByteArrayToB64 -Bytes $derivedKey)"

        # Decrypt the cipher data
        #$bPlainText = Decrypt-WSTrustCipherData -CipherText $cipher0 -Key $derivedKey
        #$plainText =  [text.encoding]::UTF8.GetString($bPlainText)
        $bPlainText = Decrypt-WSTrustCipherData -CipherText $cipher1 -Key $derivedKey
        $plainText =  [text.encoding]::UTF8.GetString($bPlainText)

        Check-SoapError -Message $plainText
        
        return $plainText
    }
}

# Creates a SOAP envelope for ADFS request
# Apr 14th 2021
function Create-ADFSRequest
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [String]$Context,
        [Parameter(Mandatory=$True)]
        [guid]$KeyIdentifier,
        [Parameter(Mandatory=$True)]
        [string]$Server
    )
    Process
    {
        $payload = "<GetState xmlns=""http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore""><serviceObjectType>ServiceSettings</serviceObjectType><mask xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" i:nil=""true""></mask><filter xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" i:nil=""true""></filter><clientVersionNumber>1</clientVersionNumber></GetState>"
        $action = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetState"

        $envelope = Create-ADFSSoapEnvelope -Key $Key -Context $Context -KeyIdentifier $KeyIdentifier -Server $Server -Payload $payload -Action $action

        return $envelope
    }
}

# Invokes a ADFS SOAP request
# Apr 13th 2021
function Invoke-ADFSSoapRequest
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [String]$Context,
        [Parameter(Mandatory=$True)]
        [guid]$KeyIdentifier,
        [Parameter(Mandatory=$True)]
        [string]$Server,
        [Parameter(Mandatory=$True)]
        [string]$Command
    )
    Process
    {
        # Create the envelope
        $payload =  "<GetState xmlns=""http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore""><serviceObjectType>$Command</serviceObjectType><mask xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" i:nil=""true""></mask><filter xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" i:nil=""true""></filter><clientVersionNumber>1</clientVersionNumber></GetState>"
        $action =   "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetState"
        $envelope = Create-ADFSSoapEnvelope -Key $Key -Context $Context -KeyIdentifier $KeyIdentifier -Server $server -Payload $payload -Action $action

        try
        {
            [xml]$response = Invoke-RestMethod -UseBasicParsing -uri "http://$Server/adfs/services/policystoretransfer" -Method Post -Body $envelope -ContentType "application/soap+xml"
        }
        catch
        {
            # Catch the error and try to parse the SOAP document
            $str=$_.Exception.Response.GetResponseStream()
            $buf = new-object byte[] $str.Length
            $str.Position = 0
            $str.Read($buf,0,$str.Length) | Out-Null
            [xml]$response=[text.encoding]::UTF8.GetString($buf)
        }

        return Parse-ADFSResponse -Response $response -Key $Key
    }
}

# Creates a SOAP envelope for the second RST request
# Apr 13th 2021
function Create-ADFSSoapEnvelope
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [String]$Context,
        [Parameter(Mandatory=$True)]
        [guid]$KeyIdentifier,
        [Parameter(Mandatory=$True)]
        [string]$Server,
        [Parameter(Mandatory=$True)]
        [string]$Payload,
        [Parameter(Mandatory=$True)]
        [string]$Action
    )
    Process
    {
        # Set some required variables
        $STSContext =   $Context
        $messageID =    (New-Guid).ToString()
        $STIdentifier = $KeyIdentifier.ToString()
        $TSIdentifier = (New-Guid).ToString()
        $now =          Get-Date
        $exp =          $now.AddMinutes(5)
        $created =      $now.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)+"Z"
        $expires =      $exp.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)+"Z"

        # Create nonce and derive keys for signing and encrypting
        $nonce0 =        Get-RandomBytes -Bytes 16
        $nonce1 =        Get-RandomBytes -Bytes 16
        $signingKey =    Derive-WSTrustKey -Key $Key -Nonce $nonce0 -Bytes 24
        $encryptionKey = Derive-WSTrustKey -Key $Key -Nonce $nonce1 -Bytes 32
        
    
        # Create the SOAP request and encrypt it
        
        $cipherText = Convert-ByteArrayToB64 -Bytes (Encrypt-WSTrustCipherData -PlainText ([text.encoding]::UTF8.GetBytes($Payload)) -Key $encryptionKey)

        #
        # Create required xml elements. 
        # Note! Due to canonicalization MS is using in the back-end, the xml MUST NOT HAVE ANY WHITE SPACES!
        # All xml elements here are already canonicalized with C14N exclusive. So, changing order of any attributes etc. will break the signature!
        #

        # Create a body element
        $xBody = "<s:Body xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_2""><e:EncryptedData xmlns:e=""http://www.w3.org/2001/04/xmlenc#"" Id=""_3"" Type=""http://www.w3.org/2001/04/xmlenc#Content""><e:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#aes256-cbc""></e:EncryptionMethod><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><o:SecurityTokenReference xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""><o:Reference URI=""#_1"" ValueType=""http://schemas.xmlsoap.org/ws/2005/02/sc/dk""></o:Reference></o:SecurityTokenReference></KeyInfo><e:CipherData><e:CipherValue>$cipherText</e:CipherValue></e:CipherData></e:EncryptedData></s:Body>"

        # Create a body element for calculating the digest. MUST BE "expanded" so that the cipher text is in decrypted form.
        $xBody2 = "<s:Body xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_2"">$Payload</s:Body>"
        
        $xTimeStamp = "<u:Timestamp xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""uuid-$TSIdentifier-2""><u:Created>$created</u:Created><u:Expires>$expires</u:Expires></u:Timestamp>"
        $xAction =    "<a:Action xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_4"" s:mustUnderstand=""1"">$Action</a:Action>"
        $xMessageId = "<a:MessageID xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_5"">urn:uuid:$messageID</a:MessageID>"
        $xReplyTo =   "<a:ReplyTo xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_6""><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
        $xTo =        "<a:To xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_7"" s:mustUnderstand=""1"">http://$Server/adfs/services/policystoretransfer</a:To>"

        # Calculate digests and generate the SignedInfo    
        $digest_2 = Convert-ByteArrayToB64 -Bytes (Get-Digest -Data     $xBody2)
        $digest_4 = Convert-ByteArrayToB64 -Bytes (Get-Digest -Data    $xAction)
        $digest_5 = Convert-ByteArrayToB64 -Bytes (Get-Digest -Data $xMessageId)
        $digest_6 = Convert-ByteArrayToB64 -Bytes (Get-Digest -Data   $xReplyTo)
        $digest_7 = Convert-ByteArrayToB64 -Bytes (Get-Digest -Data        $xTo)
        $TSdigest=  Convert-ByteArrayToB64 -Bytes (Get-Digest -Data $xTimeStamp)
        $signedInfo = "<SignedInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></CanonicalizationMethod><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#hmac-sha1""></SignatureMethod><Reference URI=""#_2""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$digest_2</DigestValue></Reference><Reference URI=""#_4""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$digest_4</DigestValue></Reference><Reference URI=""#_5""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$digest_5</DigestValue></Reference><Reference URI=""#_6""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$digest_6</DigestValue></Reference><Reference URI=""#_7""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$digest_7</DigestValue></Reference><Reference URI=""#uuid-$TSIdentifier-2""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$TSdigest</DigestValue></Reference></SignedInfo>"

        # Generate the signature by calculating HMACSHA1 of SignedInfo using the signing key
        $HMAC = [System.Security.Cryptography.HMACSHA1]::new($signingKey)
        $signatureValue = Convert-ByteArrayToB64 -Bytes $HMAC.ComputeHash([text.encoding]::UTF8.getBytes($signedInfo))

        # Generate Signature element and encrypt it using the encryption key
        $xSignature = "<Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">$signedInfo<SignatureValue>$signatureValue</SignatureValue><KeyInfo><o:SecurityTokenReference xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""><o:Reference ValueType=""http://schemas.xmlsoap.org/ws/2005/02/sc/dk"" URI=""#_0""/></o:SecurityTokenReference></KeyInfo></Signature>"
        $encSignature =  Convert-ByteArrayToB64 -Bytes (Encrypt-WSTrustCipherData -PlainText ([text.encoding]::UTF8.GetBytes($xSignature)) -Key $encryptionKey)

        # Create the envelope
        $envelope = @"
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
	        <s:Header>
		        $xAction
		        $xMessageId
		        $xReplyTo
		        $xTo
		        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
			        $xTimeStamp
			        <SecurityContextToken u:Id="$STSContext" xmlns="http://schemas.xmlsoap.org/ws/2005/02/sc">
				        <Identifier>urn:uuid:$STIdentifier</Identifier>
			        </SecurityContextToken>
			        <c:DerivedKeyToken u:Id="_0" xmlns:c="http://schemas.xmlsoap.org/ws/2005/02/sc">
				        <o:SecurityTokenReference>
					        <o:Reference URI="#$STSContext"/>
				        </o:SecurityTokenReference>
				        <c:Offset>0</c:Offset>
				        <c:Length>24</c:Length>
				        <c:Nonce>$(Convert-ByteArrayToB64 -Bytes $nonce0)</c:Nonce>
			        </c:DerivedKeyToken>
			        <c:DerivedKeyToken u:Id="_1" xmlns:c="http://schemas.xmlsoap.org/ws/2005/02/sc">
				        <o:SecurityTokenReference>
					        <o:Reference URI="#$STSContext"/>
				        </o:SecurityTokenReference>
				        <c:Nonce>$(Convert-ByteArrayToB64 -Bytes $nonce1)</c:Nonce>
			        </c:DerivedKeyToken>
			        <e:ReferenceList xmlns:e="http://www.w3.org/2001/04/xmlenc#">
				        <e:DataReference URI="#_3"/>
				        <e:DataReference URI="#_8"/>
			        </e:ReferenceList>
			        <e:EncryptedData Id="_8" Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:e="http://www.w3.org/2001/04/xmlenc#">
				        <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
				        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
					        <o:SecurityTokenReference>
						        <o:Reference ValueType="http://schemas.xmlsoap.org/ws/2005/02/sc/dk" URI="#_1"/>
					        </o:SecurityTokenReference>
				        </KeyInfo>
				        <e:CipherData>
					        <e:CipherValue>$encSignature</e:CipherValue>
				        </e:CipherData>
			        </e:EncryptedData>
		        </o:Security>
	        </s:Header>
            $xBody
        </s:Envelope>
"@

        $HMAC.Dispose()
        return $envelope
    }
}