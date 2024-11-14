# This file contains functions for Microsoft App Proxy

Add-Type -AssemblyName System.Web

# Registers App proxy agent to the Azure AD
# Apr 2nd 2020
# May 5th 2022: Added UpdateTrust
function Register-ProxyAgent
{
    <#
    .SYNOPSIS
    Registers a new MS App Proxy agent to Azure AD

    .DESCRIPTION
    Registers a new MS App Proxy agent to Azure AD. Currently Sync and PTA agents are supported.

    .PARAMETER MachineName
    Machine name used to register the proxy agent

    .PARAMETER AgentType
    Type of the proxy agent. One of "PTA","Sync"

    .PARAMETER AgentGroup
    The Agent group where to add the new agent.

    .PARAMETER UpdateTrust
    Instead of register a new agent, updates the trust of existing one. As a result, a new proxy certificate is created.

    .PARAMETER Bootstrap
    Filename of existing bootstrap configuration file.

    .PARAMETER PfxFileName
    The name of an existing proxy agent certificate used to update trust.

    .PARAMETER PfxPassword
    Password of the existing proxy agent certificate.

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntProxyAgent -AccessToken $pt -MachineName server1.company.com -AgentType PTA -FileName server1-pta.pfx

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntProxyAgent -AccessToken $pt -MachineName server2.company.com -AgentType Sync -FileName server2-sync.pfx
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$FileName,
        [Parameter(Mandatory=$True)]
        [Validateset("PTA","Sync")]
        [String]$AgentType,
        [Parameter(Mandatory=$False)]
        $AgentGroup,
        [Parameter(Mandatory=$False)]
        [bool]$UpdateTrust,
        [Parameter(Mandatory=$False)]
        [String]$Bootstrap,
        [Parameter(Mandatory=$False)]
        [String]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword
        
    )
    Begin
    {
        $AgentInfo=@{
            "PTA"= @{
                    "FeatureString" = "PassthroughAuthentication"
                    "UserAgent" = "PassthroughAuthenticationConnector/1.5.643.0"

                }
            "Sync"= @{
                    "FeatureString" = "SyncFabric"
                    "UserAgent" = "SyncFabricConnector/1.1.96.0"

                }
            }
    }
    Process
    {
        if($UpdateTrust)
        {
            # Load the old certificate
            $cert = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable

            $tenantId = $cert.Subject.Split("=")[1]
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://proxy.cloudwebappproxy.net/registerapp" -ClientId "cb1056e2-e479-49de-ae31-7812af012ed8"
            $tenantId = Get-TenantID -AccessToken $AccessToken
        }

        # Set some variables
        $OSLanguage="1033"
        $OSLocale="0409"
        $OSSku="8"
        $OSVersion="10.0.17763"
        
        # Create a private key and do something with it to get it stored
        $rsa=[System.Security.Cryptography.RSA]::Create(2048)
                
        # Initialize the Certificate Signing Request object
        $CN="" # The name doesn't matter
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($CN, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        
        if($AgentType -eq "PTA")
        {
            # Key usage
            $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::NonRepudiation -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DataEncipherment, $false))
            # TLS Web client authentication
            $oidCollection = [System.Security.Cryptography.OidCollection]::new()
            $oidCollection.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.2")) | Out-Null
            $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oidCollection, $true))


            # Add the public Key to the request
            $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($req.PublicKey,$false))

            # Create the signing request
            $csr=$req.CreateSigningRequest()
            
        }
        elseif($AgentType -eq "Sync")
        {
            # This must be done this way cause MS CSR classes doesn't support attributes :(
            $csr = NewCSRforSync -MachineName $MachineName -PublicKey $req.PublicKey.EncodedKeyValue.RawData
        }

        $b64Csr=[convert]::ToBase64String($csr)

        # Create the request body 
        if($UpdateTrust)
        {
            if($Bootstrap -and (Test-Path $Bootstrap))
            {
                Write-Verbose "Loading bootstrap from $Bootstrap"
                [xml]$config = Get-Content -Path $Bootstrap -Encoding UTF8
            }
            else 
            {
                Write-Verbose "Getting bootstrap using $($cert.Thumbprint) as $MachineName"
                [xml]$config = Get-BootstrapConfiguration -Certificate $cert -MachineName $MachineName
            }

            if(!$config)
            {
                Write-Error "Could not load bootstrap!"
                return
            }
            
            $trustEndpoint = $config.BootstrapResponse.TrustRenewEndpoint
            
            $body=@"
            <TrustRenewalRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Registration.TrustRenewal" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
                <Base64Csr xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Registration">$b64Csr
</Base64Csr>
                <TrustRenewalRequestSettings>
                    <SystemSettingsInformation i:type="a:SystemSettings" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RegistrationCommons" xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Utilities.SystemSettings">
                        <a:MachineName>$machineName</a:MachineName>
                        <a:OsLanguage>$OSLanguage</a:OsLanguage>
                        <a:OsLocale>$OSLocale</a:OsLocale>
                        <a:OsSku>$OSSku</a:OsSku>
                        <a:OsVersion>$OSVersion</a:OsVersion>
                    </SystemSettingsInformation>
                    <ConnectorVersion>1.5.2482.0</ConnectorVersion>
                </TrustRenewalRequestSettings>
            </TrustRenewalRequest>
"@
            # Renew trust and get the certificate
            $response = Invoke-RestMethod -UseBasicParsing -Uri "$trustEndPoint/RenewTrustCertificate" -Method Post -Body $body -Headers @{"Content-Type"="application/xml; charset=utf-8"} -Certificate $cert

            if($response.TrustRenewalResult.IsSuccessful.'#text' -eq "true")
            {
                # Get the certificate
                $b64Cert = $response.TrustRenewalResult.Certificate.'#text'
            }
            else
            {
                # Something went wrong
                Write-Error $response.TrustRenewalResult.ErrorMessage.'#text'
            }
        }
        else
        {
            $body=@"
            <RegistrationRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Registration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
                <Base64Csr>$b64Csr
</Base64Csr>
                <AuthenticationToken>$AccessToken</AuthenticationToken>
                <Base64Pkcs10Csr i:nil="true"/>
                <Feature>ApplicationProxy</Feature>
                <FeatureString>$($AgentInfo[$AgentType]["FeatureString"])</FeatureString>
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
                <UserAgent>$($AgentInfo[$AgentType]["UserAgent"])</UserAgent>
            </RegistrationRequest>
"@
            # Register the app and get the certificate
            $response = Invoke-RestMethod -UseBasicParsing -Uri "https://$tenantId.registration.msappproxy.net/register/RegisterConnector" -Method Post -Body $body -Headers @{"Content-Type"="application/xml; charset=utf-8"}

            if($response.RegistrationResult.IsSuccessful -eq "true")
            {
                # Get the certificate
                $b64Cert = $response.RegistrationResult.Certificate
            }
            else
            {
                # Something went wrong
                Write-Error $response.RegistrationResult.ErrorMessage
            }
        }
        
        if(![string]::IsNullOrEmpty($b64Cert))
        {
        
            # Convert certificate to byte array
            $binCert = [convert]::FromBase64String($b64Cert)
            
            # Create a new x509certificate 
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($binCert,"",[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -band [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

            # Get the instance Id (=Agent Id)
            foreach($extension in $cert.Extensions)
            {
                if($extension.Oid.Value -eq "1.3.6.1.4.1.311.82.1")
                {
                    $InstanceID = [guid]$extension.RawData
                }
            }

            if([string]::IsNullOrEmpty($FileName))
            {
                $FileName = "$($MachineName)_$($tenantId)_$($InstanceID)_$($cert.Thumbprint).pfx"
            }

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
            Set-BinaryContent -Path $fileName -Value $binCert

            # Remove the private key from the store
            $privateKey.PersistKeyInCsp=$false
            $privateKey.Clear()

            

            if($UpdateTrust)
            {
                Write-Host "$AgentType Agent ($InstanceID) certificate renewed for $MachineName"
            }
            else
            {
                Write-Host "$AgentType Agent ($InstanceID) registered as $MachineName"
            }
            Write-Host "Certificate saved to $FileName"

            # We need to register the agent to a group 
            if($AgentType -eq "Sync" -and [string]::IsNullOrEmpty($AgentGroup) -ne $true)
            {
                Add-ProxyAgentToGroup -AccessToken $AccessToken -Agent $InstanceID -Group $AgentGroup
            }
        }
        

        
    }
}

# Gets list of publishing agents
# Apr 3rd 2020
function Get-ProxyAgents
{
    <#
    .SYNOPSIS
    Shows the list of MS App Proxy agents

    .DESCRIPTION
    Shows the list of MS App Proxy authentication and provisioning agents

    .Example
    Get-AADIntProxyAgents | ft

    id                                   machineName         externalIp     status   supportedPublishingTypes
    --                                   -----------         ----------     ------   ------------------------
    51f3afd9-685b-413a-aafa-bab0d556ea4b this.is.a.fake      67.35.155.73   active   {authentication}        
    51a061a0-968d-48b8-951e-5ae9d9a0441f server1.company.com 93.188.31.116  inactive {authentication}        
    49c9ad46-c067-42f6-a678-dfd938c27789 server2.company.com 102.20.104.213 inactive {provisioning} 

    .Example
    $pt=Get-AADIntAccessTokenForPTA

    PS C:\>Get-AADIntProxyAgents -AccessToken $pt | pt

    id                                   machineName         externalIp     status   supportedPublishingTypes
    --                                   -----------         ----------     ------   ------------------------
    51f3afd9-685b-413a-aafa-bab0d556ea4b this.is.a.fake      67.35.155.73   active   {authentication}        
    51a061a0-968d-48b8-951e-5ae9d9a0441f server1.company.com 93.188.31.116  inactive {authentication}        
    49c9ad46-c067-42f6-a678-dfd938c27789 server2.company.com 102.20.104.213 inactive {provisioning} 
   
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Begin
    {
        $publishingTypes = @(     # Roles that can access the agent
		    #"appProxy"            # ApplicationAdmin, GlobalAdmin
		    "authentication"      # GlobalAdmin
            "provisioning"        # GlobalAdmin
            "exchangeOnline"      # GlobalAdmin
            #"intunePfx"          # GlobalAdmin
            #"oflineDomainJoin"   # GlobalAdmin
            "adAdministration"    # DirSyncAdmin, GlobalAdmin
            #"unknownFutureValue" # 
        )
    }
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://proxy.cloudwebappproxy.net/registerapp" -ClientId "cb1056e2-e479-49de-ae31-7812af012ed8"

        # Get the tenant id and instance id from the certificate
        $TenantId = Get-TenantID -AccessToken $AccessToken
        
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "x-ms-gateway-serviceRoot" =""
        }

        
        foreach($type in $publishingTypes)
        {
            $agents = Invoke-RestMethod -UseBasicParsing -Uri "https://$TenantId.admin.msappproxy.net/onPremisesPublishingProfiles('$type')/agents" -Method Get -Headers $headers -ErrorAction SilentlyContinue

            # Return
            if($agents)
            {        
                $agents.value
            }
        }

    }
}

# Gets list of agent groups
# Apr 6th 2020
function Get-ProxyAgentGroups
{
    <#
    .SYNOPSIS
    Lists MS App Proxy agent groups

    .DESCRIPTION
    Lists MS App Proxy agent groups

    .Example
    Get-AADIntAgentProxyGroups

    TenantId                    : ea664074-37dd-4797-a676-b0cf6fdafcd4
    ConfigurationDisplayName    : company.com
    ConfigurationResourceName   : company.com
    ConfigurationPublishingType : provisioning
    id                          : 4b6ffe82-bfe2-4357-814c-09da95399da7
    displayName                 : Group-company.com-42660f4a-9e66-4a08-ac17-2a2e0d8b993e
    publishingType              : provisioning
    isDefault                   : False

    .Example
    $pt=Get-AADIntAccessTokenForPTA

    PS C:\>Get-AADIntProxyGroups -AccessToken $pt

    TenantId                    : ea664074-37dd-4797-a676-b0cf6fdafcd4
    ConfigurationDisplayName    : company.com
    ConfigurationResourceName   : company.com
    ConfigurationPublishingType : provisioning
    id                          : 4b6ffe82-bfe2-4357-814c-09da95399da7
    displayName                 : Group-company.com-42660f4a-9e66-4a08-ac17-2a2e0d8b993e
    publishingType              : provisioning
    isDefault                   : False
   
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://proxy.cloudwebappproxy.net/registerapp" -ClientId "cb1056e2-e479-49de-ae31-7812af012ed8"

        # Get the tenant id and instance id from the certificate
        $TenantId = Get-TenantID -AccessToken $AccessToken
        
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "x-ms-gateway-serviceRoot" =""
        }

        $response = Invoke-RestMethod -UseBasicParsing -Uri "https://$TenantId.admin.msappproxy.net/onPremisesPublishingProfiles('provisioning')/agentGroups?`$expand=agents" -Method Get -Headers $headers 
        
        # return
        $response.value
    }
}

# Gets the list of proxy configurations
#function Get-ProxyConfigurations

# Creates a new proxy agent group
# Apr 6th 2020
function New-ProxyAgentGroup
{
    <#
    .SYNOPSIS
    Creates an MS App Proxy agent group

    .DESCRIPTION
    Creates an MS App Proxy agent group

    .Example
    Get-AADIntAgentProxyGroups

    TenantId                    : ea664074-37dd-4797-a676-b0cf6fdafcd4
    ConfigurationDisplayName    : company.com
    ConfigurationResourceName   : company.com
    ConfigurationPublishingType : provisioning
    id                          : 4b6ffe82-bfe2-4357-814c-09da95399da7
    displayName                 : Group-company.com-42660f4a-9e66-4a08-ac17-2a2e0d8b993e
    publishingType              : provisioning
    isDefault                   : False

    .Example
    $pt=Get-AADIntAccessTokenForPTA

    PS C:\>Get-AADIntProxyGroups -AccessToken $pt

    TenantId                    : ea664074-37dd-4797-a676-b0cf6fdafcd4
    ConfigurationDisplayName    : company.com
    ConfigurationResourceName   : company.com
    ConfigurationPublishingType : provisioning
    id                          : 4b6ffe82-bfe2-4357-814c-09da95399da7
    displayName                 : Group-company.com-42660f4a-9e66-4a08-ac17-2a2e0d8b993e
    publishingType              : provisioning
    isDefault                   : False
   
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$DisplayName,
        [Parameter(Mandatory=$True)]
        [String]$ConfigurationDisplayName,
        [Parameter(Mandatory=$True)]
        [String]$ConfigurationResourceName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://proxy.cloudwebappproxy.net/registerapp" -ClientId "cb1056e2-e479-49de-ae31-7812af012ed8"

        # Get the tenant id and instance id from the certificate
        $TenantId = Get-TenantID -AccessToken $AccessToken
        
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "x-ms-gateway-serviceRoot" =""
            "Content-Type" = "application/json"
        }

        # First, create the agent group with the given name
        $Body = "{""displayName"":""$DisplayName""}"
        $response  = Invoke-RestMethod -UseBasicParsing -Uri "https://$TenantId.admin.msappproxy.net/onPremisesPublishingProfiles('provisioning')/agentGroups" -Method POST -Headers $headers -Body $Body

        $Body = "{""displayName"":""$ConfigurationDisplayName"",""resourceName"":""$ConfigurationResourceName"",""agentGroups"":[{""id"":""$($response.id)""}]}"
        $response2 = Invoke-RestMethod -UseBasicParsing -Uri "https://$TenantId.admin.msappproxy.net/onPremisesPublishingProfiles('provisioning')/publishedResources" -Method POST -Headers $headers -Body $Body
        
        # Extract the information and create the return value
        $attributes=[ordered]@{}

        $attributes["id"]=$response.id
        $attributes["displayName"]=$response.displayName
        $attributes["publishingType"]=$response.publishingType
        $attributes["isDefault"]=$response.isDefault
        
        $attributes["ConfigurationId"]=$response2.id
        $attributes["ConfigurationDisplayName"]=$response2.displayName
        $attributes["ConfigurationResourceName"]=$response2.resourceName
        $attributes["ConfigurationPublishingType"]=$response2.publishingType
        
        # return
        New-Object PSObject -Property $attributes
    }
}

# Adds the given agent to given group
# Apr 7th 2020
function Add-ProxyAgentToGroup
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [guid]$Agent,
        [Parameter(Mandatory=$True)]
        [guid]$Group
    )
    
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://proxy.cloudwebappproxy.net/registerapp" -ClientId "cb1056e2-e479-49de-ae31-7812af012ed8"

        # Get the tenant id and instance id from the certificate
        $TenantId = Get-TenantID -AccessToken $AccessToken
       
        $body="{""@odata.id"":""https://$TenantId.admin.msappproxy.net:443/onPremisesPublishingProfiles('provisioning')/agentGroups('$($Group.toString())')""}"

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "x-ms-gateway-serviceRoot" =""
            "Content-Type" = "application/json"
        }

        Invoke-RestMethod -UseBasicParsing -Uri "https://$TenantId.admin.msappproxy.net/onPremisesPublishingProfiles('provisioning')/agents('$($Agent.toString())')/agentGroups/`$ref" -Method Post -Headers $headers -Body $body

        Write-Host "Agent ($($Agent.toString())) added to group ($($Group.toString()))"
    }
}

# Export proxy agent bootstraps using the given certificates
# Nov 1st 2022
function Export-ProxyAgentBootstraps
{
    <#
    .SYNOPSIS
    Export bootstraps of the given certificates.

    .DESCRIPTION
    Export boostraps of the given certificates. Uses the FQDN of the current computer as MachineName.
    The filename of the bootstrap is same than the certificate with .xml extension

    .Example
    Export-AADIntProxyAgentBootstraps -Certificates PTA01.company.com_ea664074-37dd-4797-a676-b0cf6fdafcd4_4b6ffe82-bfe2-4357-814c-09da95399da7_A3457AEAE25D4C513BCF37CB138628772BE1B52.pfx

    Bootstrap saved to: PTA01.company.com_ea664074-37dd-4797-a676-b0cf6fdafcd4_4b6ffe82-bfe2-4357-814c-09da95399da7_A3457AEAE25D4C513BCF37CB138628772BE1B52.xml
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String[]]$Certificates
    )

    Process
    {
        foreach($fileName in $Certificates)
        {
            if(Test-Path $fileName)
            {
                try
                {
                    $certificate = Load-Certificate -FileName $fileName -Exportable    

                    # Sleep a sec to get the cert properly loaded
                    Start-Sleep -Seconds 1 

                    $bootStrap = Get-BootstrapConfiguration -MachineName (Get-ComputerName -FQDN) -Certificate $certificate
                            
                    if($bootstrap -eq $null)
                    {
                        Throw "Could not get bootstrap"
                    }
                    $bootStrapFileName = "$($fileName.Substring(0,$fileName.LastIndexOf(".")-1)).xml"
                    Set-Content $bootStrapFileName -Value $bootStrap
                    Write-Host "Bootstrap saved to: $bootStrapFileName"
                }
                catch
                {
                    Write-Warning "Could not get bootstrap for $fileName"
                }
            }
        }
    }
}