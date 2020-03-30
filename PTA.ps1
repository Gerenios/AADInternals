# This script contains utility functions for PTA

# Error codes
$ERROR_ACCESS_DENIED = 5
$ERROR_ACCOUNT_DISABLED = 1331
$ERROR_ACCOUNT_EXPIRED = 1793
$ERROR_ACCOUNT_LOCKED_OUT = 1909
$ERROR_ACCOUNT_RESTRICTION = 1327
$ERROR_AUTHENTICATION_FIREWALL_FAILED = 1935
$ERROR_BAD_ARGUMENTS = 160
$ERROR_DOMAIN_CONTROLLER_NOT_FOUND = 1908
$ERROR_DOMAIN_TRUST_INCONSISTENT = 1810
$ERROR_FILENAME_EXCED_RANGE = 206
$ERROR_INTERNAL_ERROR = 1359
$ERROR_INVALID_ACCESS = 12
$ERROR_INVALID_LOGON_HOURS = 1328
$ERROR_INVALID_SERVER_STATE = 1352
$ERROR_INVALID_WORKSTATION = 1329
$ERROR_LDAP_FILTER_ERROR = 87
$ERROR_LDAP_OPERATIONS_ERROR = 1
$ERROR_LOGON_FAILURE = 1326
$ERROR_LOGON_TYPE_NOT_GRANTED = 1385
$ERROR_NETLOGON_NOT_STARTED = 1792
$ERROR_NOT_ENOUGH_MEMORY = 8
$ERROR_NOT_ENOUGH_SERVER_MEMORY = 1130
$ERROR_NO_LOGON_SERVERS = 1311
$ERROR_NO_SUCH_DOMAIN = 1355
$ERROR_NO_SUCH_PACKAGE = 1364
$ERROR_NO_SUCH_USER = 1317
$ERROR_NO_SYSTEM_RESOURCES = 1450
$ERROR_NO_TRUST_SAM_ACCOUNT = 1787
$ERROR_OUTOFMEMORY = 14
$ERROR_PASSWORD_EXPIRED = 1330
$ERROR_PASSWORD_MUST_CHANGE = 1907
$ERROR_PASSWORD_RESTRICTION = 1325
$ERROR_REQUEST_NOT_SUPPORTED = 50
$ERROR_RPC_S_CALL_FAILED = 1726
$ERROR_RPC_S_SERVER_UNAVAILABLE = 1722
$ERROR_TIME_SKEW = 1398
$ERROR_TOO_MANY_CONTEXT_IDS = 1384
$ERROR_TRUSTED_DOMAIN_FAILURE = 1788
$ERROR_TRUSTED_RELATIONSHIP_FAILURE = 1789
$ERROR_WRONG_PASSWORD = 1323
$SEC_E_SMARTCARD_LOGON_REQUIRED = -2146892994

# Registers PTAAgent to the Azure AD
# Nov 10th 2019
function Register-PTAAgent
{
<#
    .SYNOPSIS
    Registers the PTA agent to Azure AD and creates a client certificate

    .DESCRIPTION
    Registers the PTA agent to Azure AD with given machine name and creates a client certificate

    .Example
    Register-AADIntPTAAgent -MachineName "server1.company.com"

    PTA agent registered as server1.company.com
    Certificate saved to PTA_client_certificate.pfx

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntPTAAgent -AccessToken $pt -MachineName "server1.company.com" -FileName server1.pfx

    PTA agent registered as server1.company.com
    Certificate saved to server1.pfx
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$FileName="PTA_client_certificate.pfx"
    )
    Process
    {
        # Set some variables
        $tenantId = Get-TenantID -AccessToken $AccessToken
        $OSLanguage="1033"
        $OSLocale="0409"
        $OSSku="8"
        $OSVersion="10.0.17763"
        
        # Create a private key and do something with it to get it stored
        $rsa=[System.Security.Cryptography.RSA]::Create(2048)
                
        # Initialize the Certificate Signing Request object
        $CN="" # The name doesn't matter
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($CN, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        
        # Key usage
        $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::NonRepudiation -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DataEncipherment, $false))
        # TLS Web client authentication
        $oidCollection = [System.Security.Cryptography.OidCollection]::new()
        $oidCollection.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.2")) | Out-Null
        $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oidCollection, $true))

        # Add the public Key to the request
        $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($req.PublicKey,$false))

        # Create the signing request and convert to Base 64
        $csr=$req.CreateSigningRequest()
        $b64Csr=[convert]::ToBase64String($csr)

        # Create the request body 
        $body=@"
        <RegistrationRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Registration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
            <Base64Csr>$b64Csr
</Base64Csr>
            <AuthenticationToken>$AccessToken</AuthenticationToken>
            <Base64Pkcs10Csr i:nil="true"/>
            <Feature>ApplicationProxy</Feature>
            <FeatureString>PassthroughAuthentication</FeatureString>
            <RegistrationRequestSettings>
                <SystemSettingsInformation i:type="a:SystemSettings" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RegistrationCommons" xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Utilities.SystemSettings">
                    <a:MachineName>$machineName</a:MachineName>
                    <a:OsLanguage>$OSLanguage</a:OsLanguage>
                    <a:OsLocale>$OSLocale</a:OsLocale>
                    <a:OsSku>$OSSku</a:OsSku>
                    <a:OsVersion>$OSVersion</a:OsVersion>
                </SystemSettingsInformation>
                <PSModuleVersion>1.5.643.0</PSModuleVersion>
                <SystemSettings i:type="a:SystemSettings" xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Utilities.SystemSettings">
                    <a:MachineName>$machineName</a:MachineName>
                    <a:OsLanguage>$OSLanguage</a:OsLanguage>
                    <a:OsLocale>$OSLocale</a:OsLocale>
                    <a:OsSku>$OSSku</a:OsSku>
                    <a:OsVersion>$OSVersion</a:OsVersion>
                </SystemSettings>
            </RegistrationRequestSettings>
            <TenantId>$tenantId</TenantId>
            <UserAgent>PassthroughAuthenticationConnector/1.5.643.0</UserAgent>
        </RegistrationRequest>
"@
        
        # Register the app and get the certificate
        $response = Invoke-RestMethod -Uri "https://$tenantId.registration.msappproxy.net/register/RegisterConnector" -Method Post -Body $body -Headers @{"Content-Type"="application/xml; charset=utf-8"}
        if($response.RegistrationResult.IsSuccessful -eq "true")
        {
            # Get the certificate and convert to byte array
            $b64Cert = $response.RegistrationResult.Certificate
            $binCert = [convert]::FromBase64String($b64Cert)
            
            # Create a new x509certificate 
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($binCert,"",[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -band [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

            # Store the private key so that it can be exported
            $cspParameters = [System.Security.Cryptography.CspParameters]::new()
            $cspParameters.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
            $cspParameters.ProviderType = 24
            $cspParameters.KeyContainerName ="AADInternals"
            
            # Set the private key
            $privateKey = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cspParameters)
            $privateKey.ImportParameters($rsa.ExportParameters($true))
            $cert.PrivateKey = $privateKey

            # Export the certificate to pfx
            $binCert = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
            $binCert | Set-Content $fileName -Encoding Byte

            # Remove the private key from the store
            $privateKey.PersistKeyInCsp=$false
            $privateKey.Clear()

            Write-Host "PTA agent registered as $machineName"
            Write-Host "Certificate saved to $fileName"
        }
        else
        {
            # Something went wrong
            Write-Error $response.RegistrationResult.ErrorMessage
        }
    }
}

# Sets the certificate used by Azure AD Authentication Agent
# Mar 3rd 2020
function Set-PTACertificate
{
<#
    .SYNOPSIS
    Sets the certificate used by Azure AD Authentication Agent

    .DESCRIPTION
    Sets the certificate used by Azure AD Authentication Agent. The certificate must be created with Register-AADIntPTAAgent function.

    .Example
    Set-AADIntPTACertificate -PfxFileName server1.pfx -PfxPassword "password"

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntPTAAgent -MachineName "server1.company.com" -AccessToken $pt

    PTA agent registered as server1.company.com
    Certificate saved to PTA_client_certificate.pfx

    PS C:\>Set-AADIntPTACertificate
    Certification information set, remember to restart the service.
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$PfxFileName="PTA_client_certificate.pfx",
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [String]$TenantId
    )
    Process
    {
        # Check if the file exists
        if(($PfxFile=Get-Item $PfxFileName -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Error "The file ($PfxFile.FullName) does not exist!"
            return
        }
        
        # Get the certificate and serial number
        $cert=Get-Certificate -FileName $PfxFile.FullName -Password $PfxPassword
        $serString = $cert.SerialNumber

        # Convert serial number to byte array
        $s=[byte[]][object[]]::new(16)
        for($a = 0 ; $a -lt 32 ; $a+=2)
        {
            $s[$a/2] = [convert]::ToByte($serString.Substring($a, 2), 16)
        }

        # Convert serial number to GUID
        $InstanceID = ([guid]$s).Tostring()

        # Set the registry value (the registy entry should already exists)
        Write-Verbose "Setting HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent\InstanceID to $InstanceID"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent" -Name "InstanceID" -Value $InstanceID

        if(![string]::IsNullOrEmpty($TenantId))
        {
            Write-Verbose "Setting HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent\TenantID to $TenantId"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent" -Name "TenantID" -Value $TenantId
        }

        # Set the certificate thumb print to config file
        $configFile = "$env:ProgramData\Microsoft\Azure AD Connect Authentication Agent\Config\TrustSettings.xml"
        Write-Verbose "Setting the certificate thumb print to $configFile"
        [xml]$TrustConfig = Get-Content $configFile
        $TrustConfig.ConnectorTrustSettingsFile.CloudProxyTrust.Thumbprint = $cert.Thumbprint
        $TrustConfig.OuterXml | Set-Content $configFile

        Write-Host "Certification information set, remember to restart the service."
    }
}