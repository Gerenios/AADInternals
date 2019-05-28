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
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

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