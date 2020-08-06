# Updated Aug 8th 2019

function Export-ADFSSigningCertificate
{
<#
    .SYNOPSIS
    Exports ADFS token signing certificate

    .Description
    Exports ADFS signing certificate from WID configuration database. Must be run on ADFS server
    as domain administrator or ADFS service user (requires access to DKM container).
    The exported certificate DOES NOT HAVE PASSWORD!
  
    .Parameter fileName
    Filename of the certificate to be exported. Default is ADFSSigningCertificate.pfx.

    .Example
    Export-AADIntADFSSigningCertificate
    
    .Example
    Export-AADIntADFSSigningCertificate -fileName myadfs.pfx
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$fileName="ADFSSigningCertificate.pfx"
    )
    Process
    {
        Export-ADFSCertificate -fileName $fileName -type Signing 
    }
}

function Export-ADFSEncryptionCertificate
{
<#
    .SYNOPSIS
    Exports ADFS token encryption certificate

    .Description
    Exports ADFS encryption certificate from WID configuration database. Must be run on ADFS server
    as domain administrator or ADFS service user (requires access to DKM container).
    The exported certificate DOES NOT HAVE PASSWORD!
  
    .Parameter fileName
    Filename of the certificate to be exported. Default is ADFSEncryptionCertificate.pfx.

    .Example
    Export-AADIntADFSEncryptionCertificate
    
    .Example
    Export-AADIntADFSEncryptionCertificate -fileName myadfs.pfx
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$fileName="ADFSEncryptionCertificate.pfx"
    )
    Process
    {
        Export-ADFSCertificate -fileName $fileName -type Encryption 
    }
}

function Export-ADFSCertificate
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$fileName="ADFSSigningCertificate.pfx",
        [Parameter(Mandatory=$True)]
        [ValidateSet('Encryption','Signing')]
        [String]$type
    )
    Process
    {
        # Check that we are on ADFS server
        if((Get-Service ADFSSRV -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Error "This command needs to be run on ADFS server"
            return
        }

        # Get the database connection string
        $ADFS = Get-WmiObject -Namespace root/ADFS -Class SecurityTokenService
        $conn = $ADFS.ConfigurationDatabaseConnectionString
        Write-Verbose "ConnectionString: $conn"

        # Read the service settings from the database
        $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList $conn
        $SQLclient.Open()
        $SQLcmd = $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings"
        $SQLreader = $SQLcmd.ExecuteReader()
        $SQLreader.Read() | Out-Null
        $settings=$SQLreader.GetTextReader(0).ReadToEnd()
        $SQLreader.Dispose()
        Write-Verbose "Settings: $settings"

        # Read the XML, get the encrypted PFX, and save the bytes to a variable
        [xml]$xml=$settings
        if($type -eq "Signing")
        {
            $encPfx=$xml.ServiceSettingsData.SecurityTokenService.AdditionalSigningTokens.CertificateReference.EncryptedPfx
        }
        else
        {
            $encPfx=$xml.ServiceSettingsData.SecurityTokenService.AdditionalEncryptionTokens.CertificateReference.EncryptedPfx
        }
        $encPfxBytes=[System.Convert]::FromBase64String($encPfx)

         # Get DKM container info
        $group=$xml.ServiceSettingsData.PolicyStore.DkmSettings.Group
        $container=$xml.ServiceSettingsData.PolicyStore.DkmSettings.ContainerName
        $parent=$xml.ServiceSettingsData.PolicyStore.DkmSettings.ParentContainerDn
        $base="CN=$group,$container,$parent"

        # Read the encryption key from AD object
        $ADSearch = New-Object System.DirectoryServices.DirectorySearcher
        $ADSearch.PropertiesToLoad.Add("thumbnailphoto") | Out-Null
        $ADSearch.Filter='(&(objectclass=contact)(!name=CryptoPolicy))'
        $ADUser=$ADSearch.FindOne() 
        $key=[byte[]]$aduser.Properties["thumbnailphoto"][0] 
        Write-Verbose "Key:"
        Write-Verbose "$($key|Format-Hex)"
        Write-Verbose "Key:"
        Write-Verbose "$($key|Format-Hex)"
             
        # Get the key material - some are needed, some not. 
        # Values are Der encoded except cipher text and mac, so the first byte is tag and the second one size of the data. 
        $guid=        $encPfxBytes[8..25]  # 18 bytes
        $KDF_oid=     $encPfxBytes[26..36] # 11 bytes
        $MAC_oid=     $encPfxBytes[37..47] # 11 bytes
        $enc_oid=     $encPfxBytes[48..58] # 11 bytes
        $nonce=       $encPfxBytes[59..92] # 34 bytes
        $iv=          $encPfxBytes[93..110] # 18 bytes
        $ciphertext = $encPfxBytes[115..$($encPfxBytes.Length-33)]
        $cipherMAC =  $encPfxBytes[$($encPfxBytes.Length-32)..$($encPfxBytes.Length)]

        # Create the label
        $label = $enc_oid + $MAC_oid

        # Derive the decryption key using (almost) standard NIST SP 800-108. The last bit array should be the size of the key in bits, but MS is using bytes (?)
        # As the key size is only 16 bytes (128 bits), no need to loop.
        $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList @(,$key)
        $hmacOutput = $hmac.ComputeHash( @(0x00,0x00,0x00,0x01) + $label + @(0x00) + $nonce[2..33] + @(0x00,0x00,0x00,0x30) )
        $decryptionKey = $hmacOutput[0..15]
        Write-Verbose "Decryption key:"
        Write-Verbose "$($decryptionKey|Format-Hex)"
         
        # Create a decryptor and decrypt
        $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create("AES")
        $Crypto.Mode="CBC"
        $Crypto.KeySize = 128
        $Crypto.BlockSize = 128
        $Crypto.Padding = "None"
        $Crypto.Key = $decryptionKey
        $Crypto.IV = $iv[2..17]

        $decryptor = $Crypto.CreateDecryptor()

        # Create a memory stream and write the cipher text to it through CryptoStream
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$decryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($ciphertext,0,$ciphertext.Count)
        $cs.Close()

        # Get the results and export to the file
        $pfx = $ms.ToArray()
        $ms.Close()

        $pfx |  Set-Content $fileName -Encoding Byte 
    }
}

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