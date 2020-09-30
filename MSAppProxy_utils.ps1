# This file contains utility functions related to Microsoft App Proxy


# Get's bootstrap configuration
# Apr 2nd 2020
function Get-BootstrapConfiguration
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    Process
    {

        # Get the tenant id and instance id from the certificate
        $TenantId = $Certificate.Subject.Split("=")[1]
        $InstanceID = [guid]$Certificate.GetSerialNumberString()

        # Actually, it is not the serial number but this oid for Private Enterprise Number. Microsoft = 1.3.6.1.4.1.311
        foreach($extension in $cert.Extensions)
        {
            if($extension.Oid.Value -eq "1.3.6.1.4.1.311.82.1")
            {
                $InstanceID = [guid]$extension.RawData
            }
        }

        $OSLanguage="1033"
        $OSLocale="0409"
        $OSSku="8"
        $OSVersion="10.0.17763"
        $AgentSdkVersion="1.5.1318.0"
        $AgentVersion="1.1.96.0"
      
        $body=@"
        <BootstrapRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
            <AgentSdkVersion>$AgentSdkVersion</AgentSdkVersion>
	        <AgentVersion>$AgentVersion</AgentVersion>
	        <BootstrapDataModelVersion>$AgentSdkVersion</BootstrapDataModelVersion>
	        <ConnectorId>$InstanceId</ConnectorId>
	        <ConnectorVersion>$AgentSdkVersion</ConnectorVersion>
	        <ConsecutiveFailures>0</ConsecutiveFailures>
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
	        <ProxyDataModelVersion>$AgentSdkVersion</ProxyDataModelVersion>
	        <RequestId>$((New-Guid).ToString())</RequestId>
	        <SubscriptionId>$TenantId</SubscriptionId>
	        <SuccessRequestMetrics xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel"/>
	        <TriggerErrors/>
	        <UpdaterStatus>Running</UpdaterStatus>
	        <UseServiceBusTcpConnectivityMode>false</UseServiceBusTcpConnectivityMode>
	        <UseSpnegoAuthentication>false</UseSpnegoAuthentication>
        </BootstrapRequest>
"@

        $url="https://$TenantId.bootstrap.msappproxy.net/ConnectorBootstrap"
        
        $response = Invoke-WebRequest -UseBasicParsing -Uri $url -Method Post -Certificate $Certificate -Body $body -ContentType "application/xml; charset=utf-8"
        
        [xml]$xmlResponse = $response.Content

        return $xmlResponse.OuterXml

        
    }
}

# Registers App proxy agent to the Azure AD
# Apr 2 2020
function Register-Agent
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$True)]
        [String]$FileName,
        [Parameter(Mandatory=$True)]
        [Validateset("PTA","Sync")]
        [String]$AgentType
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

            Write-Host "$AgentType agent registered as $MachineName"
            Write-Host "Certificate saved to $FileName"
        }
        else
        {
            # Something went wrong
            Write-Error $response.RegistrationResult.ErrorMessage
        }
    }
}

# Creates a CSR from the scratch
# Apr 2nd 2020
function NewCSRforSync
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$True)]
        [byte[]]$PublicKey
    )
    process
    {
        $osVersion="6.2.9200.2"
        $ADadminUser ="NotYourBusiness!!"
        $exeName = "AADConnectProvisioningAgentWizard.exe"


        $pksha1=[System.Security.Cryptography.SHA1CryptoServiceProvider]::new().ComputeHash($PublicKey)

        # Construct the CSR for signin
        $CSRToBeSigned=@(
            Add-DERSequence -Data @(                       
                Add-DERInteger -Data 0                          
                0x30, 0x00                                     
                Add-DERSequence -Data @(                  
                    Add-DERSequence -Data @(          
                        Add-DERTag -Tag 0x06 -Data @(           # Object Identifier
                                                                # rsaEncryption (1.2.840.113549.1.1.1)
                            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
                        )
                        0x05, 0x00                              # Null
                    )
                    Add-DERTag -Tag 0x03 -Data @(           # BitString
                        0x00
                        $PublicKey
                    )
            
                )

                Add-DERTag -Tag 0xA0 -Data @(                   # Context specific (block #0)

                    # Attributes: osVersion
                    Add-DERSequence -Data @(               

                        Add-DERTag -Tag 0x06 -Data @(           # Object Identifier
                                                                # osVersion (1.3.6.1.4.1.311.13.2.3)
                            0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0D, 0x02, 0x03
                        )
                        Add-DERSet -Data @(           # SET
                            Add-DERIA5String -Text $osVersion
                        )
                    )

                    # Extension Request
                    Add-DERSequence -Data @(               
                        Add-DERTag -Tag 0x06 -Data @(           # Object Identifier
                                                                # extensionRequest (1.2.840.113549.1.9.14)
                            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E
                        )
                        Add-DERSet -Data @(           
                            Add-DERSequence -Data @(       
                        
                                # Key Usage
                                Add-DERSequence -Data @(   
                                    Add-DERTag -Tag 0x06 -Data @( # Object Identifier
                                        0x55, 0x1D, 0x0F        # keyUsage (2.5.29.15)
                                    )
                                    Add-DERTag 0x01 -Data @(0xFF) # Boolean (true)
                                    Add-DERTag 0x04 -Data @(0x03, 0x02, 0x04, 0xF0) # Octet string
                                )#
                                # Ext Key Usage
                                Add-DERSequence -Data @(   
                                    Add-DERTag -Tag 0x06 -Data @( # Object Identifier
                                        0x55, 0x1D, 0x25        # extKeyUsage
                                    )
                                    Add-DERTag 0x04 -Data @(    # Octet string
                                        0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02
                                    ) 
                                )

                                # Subject Key Identifier
                                Add-DERSequence -Data @(   
                                    Add-DERTag -Tag 0x06 -Data @( # subjectKeyIdentifier
                                        0x55, 0x1D, 0x0E        
                                    )
                                    Add-DERTag 0x04 -Data @(    # Octet string
                                        0x04, 0x14#, 0xEB, 0x4F, 0xD9, 0xFF, 0x3A, 0x20, 0xA9, 0xDB, 0x63, 0xBA, 0x50, 0x2A, 0xF1, 0x5B, 0x96, 0x5F, 0x5C, 0x3C, 0xCD, 0xF4
                                        $pksha1
                                    ) 
                                )
                        
                    
                            )
                        )
                    )

                    # Request Client Info
                    Add-DERSequence -Data @(                    
                        Add-DERTag -Tag 0x06 -Data @(           # Object Identifier
                                                                # requestClientInfo (1.3.6.1.4.1.311.21.20)
                           0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14
                        )
                        Add-DERSet -Data @(           # Set
                            Add-DERSequence -Data @(
                                Add-DERInteger -Data 0x05
                                Add-DERUtf8String -Tag 0x0C -Text $machineName
                                Add-DERUtf8String -Tag 0x0C -Text $ADadminUser
                                Add-DERUtf8String -Tag 0x0C -Text $exeName
                            )
                        )

                    )

                    # Enrolment CSP
                    Add-DERSequence -Data @(                    
                        Add-DERTag -Tag 0x06 -Data @(           # Object Identifier
                                                                # enrolmentCSP (1.3.6.1.4.1.311.13.2.2)
                            0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0D, 0x02, 0x02
                        )
                        Add-DERSet -Data @(           
                            Add-DERSequence -Data @(
                                Add-DERInteger 0x01
                                Add-DERUnicodeString -Tag 0x1E "Microsoft Enhanced RSA and AES Cryptographic Provider" -LE
                                Add-DERTag -Tag 0x03 -Data 0x00 # Bit string
                            )
                        )
                    )

                )
            )

        )

        # Sign the CSR
        $signature = $rsa.SignData($CSRToBeSigned, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

        # Construct the CSR
        $CSR = Add-DERSequence -Data @(
            $CSRToBeSigned
            Add-DERSequence -Data @(
                Add-DERTag -Tag 0x06 -Data @(
                    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
                )
                0x05, 0x00 # null
            )
            Add-DERTag -Tag 0x03 -Data @(
                0x00
                $signature
            )
        
        )
        # return

        return $CSR
    }
}

# Connects to the given bus
function Connect-ToBus
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [PSObject]$BootStrap,
        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )
    Process
    {
        # Import AMQP.ps1
        . "$PSScriptRoot\AMQP.ps1"
        
        # Define AMQP messages
        [byte[]]$AMQP0 = @(
            0x41, 0x4D, 0X51, 0X50, # AMQP
            0x00, # Protocol
            0x01, # Major
            0x00, # Minor
            0x00) # Revision

        [byte[]]$AMQP1 = @(
            0x41, 0x4D, 0X51, 0X50, # AMQP
            0x01, # Protcol = AMQP
            0x01, # Major
            0x00, # Minor
            0x00) # Revision

        [byte[]]$AMQP2 = @(
            0x41, 0x4D, 0X51, 0X50, # AMQP
            0x02, # Protcol = TCP
            0x01, # Major
            0x00, # Minor
            0x00) # Revision

        [byte[]]$AMQP3 = @(
            0x41, 0x4D, 0X51, 0X50, # AMQP
            0x03, # Protocol = SASL
            0x01, # Major
            0x00, # Minor
            0x00) # Revision

        [byte[]]$EmptyAMQPHeader = @(0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00)

        Try
        {
            
            # Define some needed variables
            $NameSpace = $bootStrap.NameSpace
            $url = "$nameSpace.servicebus.windows.net/`$servicebus/websocket"
            $connectionId = (New-Guid).ToString()
            $relayLinkGuid = (New-Guid).ToString()
            $trackingId = (New-Guid).ToString()

            if($status)
            {
                $Status.status = "Connecting to $url"
            }
            else
            {
                Write-Verbose "Connecting to $url"
            }
            #$connector.Status = "Connecting to $url"
            
            # Create the socket
            $socket = New-Object System.Net.WebSockets.ClientWebSocket
            
            # Add wsrelayedamqp as sub protocol 
            $socket.Options.AddSubProtocol("wsrelayedamqp")
            $socket.Options.ClientCertificates.Add($cert) | out-null
            
            # Create the token and open the connection
            $token = New-Object System.Threading.CancellationToken                                                   

            $connection = $socket.ConnectAsync("wss://$url", $token)
            While (!$connection.IsCompleted) { Start-Sleep -Milliseconds 5 }

            if($connection.IsFaulted -eq "True")
            {
                Write-Error $connection.Exception
                return
            }

            #
            # Start the Agent
            #

            # Send SASL version header
            SendToSocket -Socket $socket -Token $token -Bytes ($AMQP3)

            # DEBUG
            $relayOpened=$false

            # Start the loop
            while($socket.state -eq "Open")
            {
                $outMessage = $null

                $response = ReadFromSocket -Socket $socket -Token $token  -KeepAlive
                $inMessage = Parse-BusMessage $response

                $close = $false

                switch($inMessage.Type)
                {
                    "Protocol SASL" {} # Do nothing 
                    "SASL Mechanisms" 
                        {
                            # SASL init
                            $outMessage = New-SASLInit -Mechanics EXTERNAL
                        }
                    "SASL Outcome"
                        {
                            # Change protocol to AMQP
                            $outMessage = $AMQP0
                        }
                    "Protocol AMQP" 
                        {
                            # AMQP Open
                            $outMessage = New-AMQPOpen -ContainerId "RelayConnection_$connectionId" -HostName "$nameSpace-relay.servicebus.windows.net"
                        }
                    "AQMP Open"
                        {
                            # AMQP Begin
                            $outMessage = New-AMQPBegin
                        }
                    "AQMP Begin"
                        {
                            # AMQP Attach handle 0 and 1
                            SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPAttach -Handle 0 -RelayLinkGuid $relayLinkGuid -Direction out -BootStrap $bootStrap -TrackingID $trackingId)
                            SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPAttach -Handle 1 -RelayLinkGuid $relayLinkGuid -Direction in  -BootStrap $bootStrap -TrackingID $trackingId)

                            $outMessage = New-AMQPFlow
                        }
                    "AQMP Attach"
                        {
                            # Nothing to do
                        }
                    "AQMP Flow"
                        {
                            # Send an empty AMQP Header
                            $outMessage = $EmptyAMQPHeader
                            if($status)
                            {
                                $Status.status += "`nWaiting for auth requests.."
                            }
                            else
                            {
                                Write-Verbose "Waiting for auth requests.."
                            }
                        }
                    "AQMP Detach"
                        {
                            # Send AMQP Detach
                            $outMessage = New-AMQPDetach -Handle ($inMessage.Handle)
                            Write-Verbose ($inMessage.Error)
                        }
                    "AQMP End"
                        {
                            # Send AMQP End
                            $outMessage = New-AMQPEnd
                        }
                    "AQMP Close"
                        {
                            # Send AMQP Close
                            $outMessage = New-AMQPClose

                            # Close the socket after sending the last message
                            $close = $True

                            # Set the status
                            if($status)
                            {
                                $Status.status += "`nClosed."
                            }
                            else
                            {
                                Write-Verbose "Closed."
                            }
                        }
                    "OnewaySend"
                        {
                            # Send the disposition message
                            SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPDisposition)

                            # Time to create the relay!
                            if($status)
                            {
                                $Status.status += "`nOpening relay to $($inMessage.RelayAddress)"
                            }
                            else
                            {
                                Write-Verbose "Opening relay to $($inMessage.RelayAddress)"
                            }

                            if(!$relayOpened)
                            {
                                $relayOpened = $true
                                Connect-ToAuthRelay -Hostname $inMessage.RelayAddress -Id $inMessage.RelayId -Certificate $cert
                            }
                        }
                }

                if($outMessage -ne $null)
                {
                    SendToSocket -Socket $socket -Token $token -Bytes $outMessage

                }

                if($close)
                {
                    $socket.Abort()
                }
                
            }

            
        }
        catch
        {
            $Exception = $error[0]
            Write-Host $Exception -ForegroundColor Red
        }
        Finally{

            If ($socket) { 
                Write-Verbose "Closing websocket"
                $socket.Dispose()
            }

        }
        
    }
}

function SendToSocket
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Net.WebSockets.ClientWebSocket]$Socket,
        [Parameter(Mandatory=$True)]
        [System.Threading.CancellationToken]$Token,
        [Parameter(Mandatory=$True, ParameterSetName="Bytes")]
        [byte[]]$Bytes,
        [Parameter(Mandatory=$True, ParameterSetName="Byte")]
        [byte]$Byte
    )
    Process
    {

        if($Bytes -eq $null)
        {
  
            [byte[]]$Bytes = @($Byte)
        }

        $connection = $Socket.SendAsync($Bytes,1,$true,$Token)
        while(!$connection.IsCompleted)
        { 
            Start-Sleep -Milliseconds 5 
        }

    }
}

function ReadFromSocket
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Net.WebSockets.ClientWebSocket]$Socket,
        [Parameter(Mandatory=$True)]
        [System.Threading.CancellationToken]$Token,
        [Parameter(Mandatory=$False)]
        [int]$ArraySize=2048,
        [switch]$KeepAlive,
        [switch]$TimeOut
    )
    Process
    {
        [byte[]]$EmptyAMQPHeader = @(0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00)
        $start = Get-Date

        $buffer = New-Object Byte[] $ArraySize

        $connection = $Socket.ReceiveAsync($buffer, $Token)
        while(!$connection.IsCompleted)
        { 
            # If KeepAlive, send an empty AMQP header after 30 seconds
            if($KeepAlive -and (Get-Date).Subtract($start).Seconds -gt 30)
            {
                SendToSocket -Socket $socket -Token $token -Bytes $EmptyAMQPHeader
                $start = Get-Date
            }
            if($TimeOut -and (Get-Date).Subtract($start).Seconds -gt 5)
            {
                return $null
            }
            Start-Sleep -Milliseconds 5 
        }

        $retVal= $buffer[0..$($connection.Result.Count-1)]

        return $retVal
    }
}

# Creates a SAS token
function Get-SASToken
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Url,
        [Parameter(Mandatory=$True)]
        [String]$Key,
        [Parameter(Mandatory=$True)]
        [String]$KeyName,
        [Parameter(Mandatory=$False)]
        [DateTime]$Expires=(Get-Date).AddDays(1)
    )
    Process
    {
        # Create the HMAC object
        $keyBytes=[Text.Encoding]::UTF8.GetBytes($Key)
        $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)

        # Convert to UNIX time
        $exp=([System.DateTimeOffset]$Expires.ToUniversalTime()).ToUnixTimeSeconds()

        # Form the string to sign (urlencoded uri + \n + expires)
        $namespace = $url.split("/")[2]
        $urlToSign = [System.Web.HttpUtility]::UrlEncode($url) + "`n" + [string]$exp
        $byteUrl=[Text.Encoding]::UTF8.GetBytes($urlToSign)

        # Calculate the signature
        $byteHash = $hmac.ComputeHash($byteUrl)
        $signature = [System.Convert]::ToBase64String($byteHash)
        
        # Form the token
        $SASToken = "SharedAccessSignature sr=" + [System.Web.HttpUtility]::UrlEncode($Url) + "&sig=" + [System.Web.HttpUtility]::UrlEncode($signature) + "&se=" + $exp + "&skn=" + $KeyName

        return $SASToken
    }
}

function Connect-ToAuthRelay
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Hostname,
        [Parameter(Mandatory=$True)]
        [String]$Id,
        [Parameter(Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate

    )
    Process
    {
        
        Try
        {
            $url = "$Hostname/`$servicebus/websocket"

            

            # Create the socket
            $socket = New-Object System.Net.WebSockets.ClientWebSocket
            
            # Add wsrelayedamqp as sub protocol 
            $socket.Options.AddSubProtocol("wsrelayedconnection")
            $socket.Options.ClientCertificates.Add($Certificate) | out-null

            # Create the token and open the connection
            $token = New-Object System.Threading.CancellationToken                                                   

            $connection = $socket.ConnectAsync("wss://$url", $token)
            While (!$connection.IsCompleted) { Start-Sleep -Milliseconds 5 }

            if($connection.IsFaulted -eq "True")
            {
                Write-Error $connection.Exception
                return
            }

            # Send the two initial messages
            SendToSocket -Socket $socket -Token $token -Bytes (New-RelayConnect)

            SendToSocket -Socket $socket -Token $token -Bytes (New-RelayAccept -id $id)

            # Start the conversation loop

            if($status)
            {
                #$Status.status += "`nSocket: $($socket.state)"
            }

            # Define variables
            $SomeId = $null
            $SequenceId = $null
            $ConnectionId = New-Guid
            $RelayUrl = $null
            $ProxyUrl = $null
            $ProxyId = $null
            $SomeId2 = $null
            $ConId = $null

            while($socket.state -eq "Open")
            {
                Remove-Variable outMessage
                $outMessage = $null

                $response = ReadFromSocket -Socket $socket -Token $token  -TimeOut

                if($response -eq $null)
                {
                    return
                }

                $inMessage = Parse-RelayMessage $response

                if($status)
                {
                 #   $Status.status += "`n$hostname InMessage: $($inMessage.Type) $($inMessage.Size). Response: $($response.length)"
                }

                $close = $false

                

                switch($inMessage.Type)
                {
                    "Relay AcceptReply"  {} # Do nothing 
                    "Relay ConnectReply" {} # Do nothing 
                    "Relay Name" 
                        {
                            # Reply
                            SendToSocket -Socket $socket -Token $token -Byte (New-RelayNameReply)
                        }
                    "Relay Ids" 
                        {
                            if($status)
                            {
                                $Status.status += "`nExtracting variables"
                            }
                            # Extract variables
                            $SomeId = $inMessage.SomeId
                            $SequenceId = $inMessage.SequenceId
                            $RelayUrl = $inMessage.Relay

                            if($status)
                            {
                                $Status.status += "`nSending outmessage. SomeId: $someId ConnectionId $ConnectionId SequenceId: $SequenceId Relay $RelayUrl"
                            }
                            # Reply
                            $outMessage = New-RelayIdsReply -SomeId $SomeId -ConnectionId $ConnectionId -Relay $RelayUrl
                        }
                    "Relay ProxyConnect" 
                        {
                            # Extract variables
                            $ProxyUrl = $inMessage.ProxyUrl
                            $ProxyId = $inMessage.ProxyId
                            $SomeId2 = $inMessage.SomeId2
                            $ConId = $inMessage.ConId
                            $ConnectionId = $inMessage.ConnectionId

                            if($status)
                            {
                                $Status.status += "`nProxy. SomeId2: $someId2 SequenceId: $SequenceId ConnectionId: $ConnectionId "
                            }

                            # Reply
                            $outMessage = New-RelayProxyConnectReply -SequenceId $SequenceId -SomeId2 $SomeId2 -ConnectionId $ConnectionId 

                            # Send NetRemote
                            SendToSocket -Socket $socket -Token $token -Bytes New-RelayNetRemote
                        }
                    "Relay NetRemoteReply" 
                        {
                            # Try to connect to the proxy!

                            # Get the ids..
                            $SubscriptionId=([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate).GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
                            $ConnectorId=([guid]([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate).Extensions["1.3.6.1.4.1.311.82.1"].RawData).ToString()

                            $url="https://$proxyUrl/subscriber/websocketconnect?requestId=$((New-Guid).ToString())"

            

            
                            # Create the socket
                            $socket2 = New-Object System.Net.WebSockets.ClientWebSocket

                            $socket2.options.SetRequestHeader("x-cwap-dnscachelookup-result" , "NotUsed")
                            $socket2.options.SetRequestHeader("x-cwap-connector-usesdefaultproxy" , "InUse")
                            $socket2.options.SetRequestHeader("x-cwap-connector-version" , "1.5.1542.0")
                            $socket2.options.SetRequestHeader("x-cwap-datamodel-version" , "1.5.1542.0")
                            $socket2.options.SetRequestHeader("x-cwap-connector-sp-connections" , "0")
                            $socket2.options.SetRequestHeader("x-cwap-transid" , $id)
            
                            $socket2.options.ClientCertificates.Add($cert)

                            # Create the token and open the connection
                            $token2 = New-Object System.Threading.CancellationToken                                                   

                            $connection2 = $socket2.ConnectAsync("wss://$($url.Substring(8))", $token2)
                            While (!$connection2.IsCompleted) { Start-Sleep -Milliseconds 5 }

                            if($connection2.IsFaulted -eq "True")
                            {
                                Write-Error $connection2.Exception
                                return
                            }
                            Write-Host "Connected to $Url" -ForegroundColor Yellow

                            # Send the message
                            $message = [text.encoding]::UTF8.GetBytes( "{`"ConnectionId`":`"$connectionId`",`"MessageType`":0}" )
                            SendToSocket -Socket $socket2 -Token $token -Bytes ($message)            

                            # Loop
                            while($true)
                            {
                                # Get the authentication message
                                $response = ReadFromSocket -Socket $socket2 -Token $token2 -ArraySize 2048
                                # Debug -Step ($step++) -NameSpace $Hostname -Bytes $response -Direction in

                                $authRequest = [text.encoding]::UTF8.GetString($response)
                                Write-Verbose $authRequest
                                $credentials = Decode-PTACredential -AuthRequest $authRequest -Certificate $cert

                                $credentials

           

                                Write-Verbose "Trying to send authentication response"
                                $username="danj@highlandwhiskey.myo365.site"
                                $userClaim="[{`"ClaimType`":`"http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication`",`"Resource`":true,`"Right`":`"http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity`"},{`"ClaimType`":`"http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/name`",`"Resource`":`"$username`",`"Right`":`"http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity`"}]"
                                $backEndResponse = [convert]::ToBase64String([text.encoding]::UTF8.GetBytes($userClaim))

                                $headers = [ordered]@{
                                    "x-cwap-dnscachelookup-result"="NotUsed"
                                    "x-cwap-connector-usesdefaultproxy"="InUse"
                                    "x-cwap-connector-version"="1.5.1542.0"
                                    "x-cwap-datamodel-version"="1.5.1542.0"
                                    "x-cwap-connector-sp-connections"="1"
                                    "x-cwap-transid" = $id
                                    "x-cwap-sessionid"="00000000-0000-0000-0000-000000000000"
                                    "x-cwap-certificate-authentication"="notProcessed"
                                    "x-cwap-headers-size"="0"
                                    "x-cwap-connector-be-latency-ms"="27"
                                    "x-cwap-payload-total-attempts"="0"
                                    "x-cwap-connector-loadfactor"="0"
                                    "x-cwap-response-total-attempts"="1"
                                    "x-cwap-connector-all-latency-ms"="70"
                                    "x-cwap-backend-response" = $backEndResponse
                                    "User-Agent"=""
                                }

                                $url="https://$proxyUrl/subscriber/connection?requestId=$((New-Guid).ToString())"

                                # The cert must be "linked" to this web page by IE + it needs to be installed in the personal store.
                                try
                                {
                                    Invoke-RestMethod -Uri $url -Method Post -Certificate $cert -Headers $headers -ContentType "" -ErrorAction SilentlyContinue
                                    #$response = Invoke-WebRequest -UseBasicParsing -Uri $url -Method Post -Certificate $cert -Headers $headers -ContentType "" -ErrorAction SilentlyContinue
                                }
                                catch
                                {
                                    Write-Error $_.Exception.Message
                                }
                            }
                            
                        }     
                
                }

                if($outMessage -ne $null)
                {
                    if($status)
                    {
                        #$Status.status += "`nSendToSocket. $($outMessage.length). $($outMessage.GetType())"
                    }
                    SendToSocket -Socket $socket -Token $token -Bytes ([byte[]]$outMessage)

                }

                if($close)
                {
                    $socket.Abort()
                }
                
            }
            
        
            
            
        }
        catch
        {
            $Exception = $error[0]
            Write-Host $_
            Write-Host $Exception -ForegroundColor Red

            if($status)
            {
                $Status.status += "`n$($exception.toString())"
            }
        }
        Finally{

            If ($socket) { 
                Write-Verbose "Closing websocket $Namespace"
                $socket.Dispose()
            }


        }
        
    }
}