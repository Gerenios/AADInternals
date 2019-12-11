# This script contains utility functions for Cloud Web Application Proxy 

# Registers an app to Cloud WAP
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
            <Feature>PassthroughAuthentication</Feature>
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

function Get-BootstrapConfiguration
{
<#
    .SYNOPSIS
    Registers an app to Cloud WAP

    .DESCRIPTION
    Registers an app to Cloud Web Application Proxy

    .Example
    Get-AADIntLoginInformation -Domain outlook.com

    

    .Example
    Get-AADIntLoginInformation -UserName someone@company.com

              : 

   
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName="AccessToken", Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(ParameterSetName="TenantId", Mandatory=$True)]
        [String]$TenantId,
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$fileName="PTA_client_certificate.pfx"
    )
    Process
    {
        if(![string]::IsNullOrEmpty($AccessToken))
        {
            $TenantId = Get-TenantID -AccessToken $AccessToken
        }

        $fullPath = (Get-Item $fileName).FullName

        $OSLanguage="1033"
        $OSLocale="0409"
        $OSSku="8"
        $OSVersion="10.0.17763"
      
        $body=@"
        <BootstrapRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	        <BootstrapDataModelVersion>1.5.644.0</BootstrapDataModelVersion>
	        <ConnectorId>12161898-a592-413a-b018-9756e89b71ce</ConnectorId>
	        <ConnectorVersion>1.5.644.0</ConnectorVersion>
	        <ConsecutiveFailures>118</ConsecutiveFailures>
	        <CurrentProxyPortResponseMode>Primary</CurrentProxyPortResponseMode>
	        <FailedRequestMetrics xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel"/>
	        <InitialBootstrap>true</InitialBootstrap>
	        <IsProxyPortResponseFallbackDisabledFromRegistry>true</IsProxyPortResponseFallbackDisabledFromRegistry>
	        <LatestDotNetVersionInstalled>461814</LatestDotNetVersionInstalled>
	        <MachineName>$machineName</MachineName>
	        <OperatingSystemLanguage>$OSLanguage</OperatingSystemLanguage>
	        <OperatingSystemLocale>$OSLocale</OperatingSystemLocale>
	        <OperatingSystemSKU>$OSSku</OperatingSystemSKU>
	        <OperatingSystemVersion>$OSVersion</OperatingSystemVersion>
	        <PerformanceMetrics xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel"/>
	        <ProxyDataModelVersion>1.5.644.0</ProxyDataModelVersion>
	        <RequestId>$((New-Guid).ToString())</RequestId>
	        <SubscriptionId>$TenantId</SubscriptionId>
	        <SuccessRequestMetrics xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel"/>
	        <TriggerErrors/>
	        <UpdaterStatus>Running</UpdaterStatus>
	        <UseServiceBusTcpConnectivityMode>false</UseServiceBusTcpConnectivityMode>
	        <UseSpnegoAuthentication>false</UseSpnegoAuthentication>
        </BootstrapRequest>
"@
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile($fullPath)

        $url="https://$TenantId.bootstrap.msappproxy.net/ConnectorBootstrap"
        # The cert must be "linked" to this web page by IE + it needs to be installed on the personal etc. store.
        $response = Invoke-WebRequest -Uri $url -Method Post -Certificate $cert -Body $body -ContentType "application/xml; charset=utf-8"
        
        [xml]$xmlResponse = $response.Content

        return $xmlResponse.BootstrapResponse.SignalingListenerEndpoints.SignalingListenerEndpointSettings

        
    }
}


function Get-SASToken
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Url,
        [Parameter(Mandatory=$True)]
        [String]$Key,
        [Parameter(Mandatory=$True)]
        [String]$KeyName
    )
    Process
    {
        # Create the HMAC object
        $keyBytes=[Text.Encoding]::UTF8.GetBytes($Key)
        $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)

        # Get the current time
        $expires=([DateTimeOffset]::Now.ToUnixTimeSeconds())

        # Form the string to sign (urlencoded uri + \n + expires)
        $namespace = $url.split("/")[2]
        $urlToSign = [System.Web.HttpUtility]::UrlEncode("https://$namespace/") + "`n" + [string]$expires
        $byteUrl=[Text.Encoding]::UTF8.GetBytes($encUrl)

        # Calculate the signature
        $byteHash = $hmac.ComputeHash($byteUrl)
        $signature = [System.Convert]::ToBase64String($byteHash)

        # Form the token
        $SASToken = "SharedAccessSignature sr=" + [System.Web.HttpUtility]::UrlEncode($Url) + "&sig=" + [System.Web.HttpUtility]::UrlEncode($signature) + "&se=" + $expires + "&skn=" + $KeyName

        return $SASToken
    }
}