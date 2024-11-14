# Gets ADHybridHealthService member credentials
# May 26th 2021
function Get-HybridHealthServiceMemberCredentials
{
<#
    .SYNOPSIS
    Gets ADHybridHealthService member credentials

    .DESCRIPTION
    Creates and returns new ADHybridHealthService member credentials

    .Parameter AccessToken
    The access token used to get ADHybridHealthService members.

    .Parameter ServiceName
    Name of the ADHybridHealthService

    .Parameter ServiceMemberId
    Guid of the service member.

    .Example
    Get-AADIntHybridHealthServiceMemberCredentials -ServiceName AdFederationService-sts.company.com -MemberId 0fce7ce0-81a0-4bf7-87fb-fc787dfe13c2

    lastReboot                              : 2021-03-16T08:17:19.0912Z
    lastDisabled                            : 
    lastUpdated                             : 2021-05-06T06:04:20.6537234Z
    activeAlerts                            : 2
    resolvedAlerts                          : 1
    createdDate                             : 0001-01-01T00:00:00
    disabled                                : False
    dimensions                              : 
    additionalInformation                   : 
    tenantId                                : 5b53828e-8e7b-42d1-a5f0-9b34bbd1844a
    serviceId                               : 50abc8f3-243a-4ac1-a3fb-712054d7334b
    serviceMemberId                         : bec07a23-dd4a-4c80-8c92-9b9dc089f75c
    machineId                               : 0cf2774f-a188-4bd3-b4b3-3a690374325d
    machineName                             : STS01
    role                                    : AdfsServer_2016
    status                                  : Error
    properties                              : 
    installedQfes                           : 
    recommendedQfes                         : 
    monitoringConfigurationsComputed        : 
    monitoringConfigurationsCustomized      : 
    osVersion                               : 10.0.17763.0
    osName                                  : Microsoft Windows Server 2019 Standard
    disabledReason                          : 0
    serverReportedMonitoringLevel           : 
    lastServerReportedMonitoringLevelChange : 
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$ServiceName,
        [Parameter(Mandatory=$True)]
        [guid]$ServiceMemberId

    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://management.azure.com/providers/Microsoft.ADHybridHealthService/services/$ServiceName/servicemembers/$($ServiceMemberId.toString())/credentials?api-version=2014-01-01" -Headers $headers

        # Return credentials
        $creds = [ordered]@{}
        foreach($cred in $response)
        {
            # Decode the certificate
            if($cred.identifier -eq "tenant.cert")
            {
                $bCert = Convert-B64ToByteArray -B64 $cred.credentialData

                # Strip the header if exists
                if($bcert[0] -eq 0x01)
                {
                    # First 4 bytes = format
                    # Next 4 bytes = length of the string like "policykeyservice.dc.ad.msft.net"
                    # Total header length = 4 + 4 + length
                    $length = [bitconverter]::ToInt32($bCert[4..7],0)
                    $bCert = $bCert[(4+4+$length)..($bcert.length)]
                }

                $creds[$cred.identifier] = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$bCert)
            }
            else
            {
                $creds[$cred.identifier] = $cred.credentialData
            }
        }

        

        return New-Object psobject -Property $creds
               
    }
}

# Gets ADHybridHealthService access token
# May 26th 2021
function Get-HybridHealthServiceAccessToken
{
<#
    .SYNOPSIS
    Gets ADHybridHealthService access token

    .DESCRIPTION
    Returns ADHybridHealthService access token

    .Parameter AgentKey
    AgentKey of the ADHybridHealthService agent

    .Parameter MachineID
    MachineID of the computer running the ADHybridHealthService agent

    .Parameter TenantID
    Tenant ID.

    .Example
    $at = Get-AADIntHybridHealthServiceAccessToken -AgentKey $agentKey -TenantId $tenantId -MachineId $machineId
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AgentKey,
        [Parameter(Mandatory=$True)]
        [guid]$MachineId,
        [Parameter(Mandatory=$True)]
        [guid]$TenantId
    )
    Process
    {
        # Build a body
        $body=@{
            "grant_type" = "client_credentials"
            "client_secret" = $AgentKey
            "client_id"     = "$($TenantId.ToString())_$($MachineId.ToString())"
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://s1.adhybridhealth.azure.com/oauth2/token" -Body $body

        return $response.access_token
               
    }
}

# Gets ADHybridHealthService Blob upload key
# May 26th 2021
function Get-HybridHealthServiceBlobUploadKey
{
<#
    .SYNOPSIS
    Gets ADHybridHealthService blob upload key

    .DESCRIPTION
    Gets ADHybridHealthService blob upload key. The key is an url used to upload events to Azure blob. Url contains pre-calcuated SAS token.

    .Parameter AccessToken
    The access token used to get ADHybridHealthService blob upload key.

    .Parameter ServiceID
    ServiceID
    
    .Example
    Get-HybridHealthServiceBlobUploadKey -AccessToken $at -ServiceId $serviceId

    https://adhsprodweuaadsynciadata.blob.core.windows.net/adfederationservice-8c11e4fb-299c-42c0-b79a-555c33964b58?sv=2018-03-28&sr=c&sig=pZ056YDtl8iK9PjiNoQED6tLHd3h0EkwDlHY%2Bxf8Znc%3D&se=2021-05-24T06%3A32%3A18Z&sp=w

    .Example
    $blobKey = Get-AADIntHybridHealthServiceBlobUploadKey -AccessToken $at -ServiceId $serviceId
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [guid]$ServiceId
    )
    Process
    {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://s1.adhybridhealth.azure.com/providers/Microsoft.ADHybridHealthService/monitoringpolicies/$($ServiceId.ToString())/keys/BlobUploadKey" -Headers $headers

        # Return upload key
        $response
    }
}

# Gets ADHybridHealthService event hub publisher key
# May 29th 2021
function Get-HybridHealthServiceEventHubPublisherKey
{
<#
    .SYNOPSIS
    Gets ADHybridHealthService event hub publisher key

    .DESCRIPTION
    Gets ADHybridHealthService event hub publisher key. The key includes Service Bus endpoint and SharedAccessSignature.

    .Parameter AccessToken
    The access token used to get ADHybridHealthService event hub publisher key.

    .Parameter ServiceID
    ServiceID
    
    .Example
    Get-AADIntHybridHealthServiceEventHubPublisherKey -AccessToken $at -ServiceId $serviceId

    Endpoint=sb://adhsprodweuehadfsia.servicebus.windows.net/;SharedAccessSignature=SharedAccessSignature sr=sb%3a%2f%2fadhsprodweuehadfsia.servicebus.windows.net%2fadhsprodweuehadfsia%2fPublishers%2f8c77dad6-9932-4bfe-bf9e-58734ccb3e2c&sig=XRKxI%2bR7LEe4pBxe4OZt86dzFxIvSsyqs0UPmlO3hFM%3d&se=1622788339&skn=RootManageSharedAccessKey;EntityPath=adhsprodweuehadfsia;Publisher=8c77dad6-9932-4bfe-bf9e-58734ccb3e2c

    .Example
    $eventKey = Get-AADIntHybridHealthServiceEventHubPublisherKey -AccessToken $at -ServiceId $serviceId
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [guid]$ServiceId
    )
    Process
    {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://s1.adhybridhealth.azure.com/providers/Microsoft.ADHybridHealthService/monitoringpolicies/$($ServiceId.ToString())/keys/EventHubPublisherKey" -Headers $headers

        # Return upload key
        $response
    }
}

# Send the signature to Azure using service bus
# May 26th 2021
function Send-ADFSServiceBusMessage
{

    [cmdletbinding()]

    param(
        [Parameter(Mandatory=$True)]
        [String]$EventHubPublisherKey,
        [Parameter(Mandatory=$True)]
        [String]$BlobAbsoluteUri,
        [Parameter(Mandatory=$True)]
        [guid]$MachineId,
        [Parameter(Mandatory=$True)]
        [guid]$TenantId,
        [Parameter(Mandatory=$True)]
        [guid]$ServiceId,
        [Parameter(Mandatory=$True)]
        [datetime]$SigningTime,
        [Parameter(Mandatory=$True)]
        [String]$HMACSignature
        )
    Try
    {
        # Define some needed variables
        $keyParts   = $EventHubPublisherKey.Split(";")
        $endpoint   = $keyParts[0].Substring($keyParts[0].IndexOf("=")+1).Replace("sb:","wss:")
        $url        = "$endPoint$`servicebus/websocket"

        $SAS        = $keyParts[1].Substring($keyParts[1].IndexOf("=")+1)
        $entityPath = $keyParts[2].Substring($keyParts[2].IndexOf("=")+1)
        $publisher  = $keyParts[3].Substring($keyParts[3].IndexOf("=")+1)
        $SASName    = "$($endpoint.Replace("wss:","amqp:"))$entitypath/Publishers/$publisher"

        # Define headers for the first request
        $headers = @{
            "Connection"             = "Upgrade"
            "Upgrade"                = "websocket"
            "Sec-WebSocket-Key"      = [convert]::ToBase64String((New-Guid).ToByteArray())
            "Sec-WebSocket-Version"  = "13"
            "Sec-WebSocket-Protocol" = "AMQPWSB10"
            "User-Agent"             = ""
        }

        # Create the socket
        $socket = New-Object System.Net.WebSockets.ClientWebSocket
            
        # Add AMQPWSB10 as sub protocol 
        $socket.Options.AddSubProtocol("AMQPWSB10")

        # Create the token and open the connection
        $token = New-Object System.Threading.CancellationToken                                                   

        Write-Verbose "Opening websocket: $url"

        $connection = $socket.ConnectAsync($url, $token)
        While (!$connection.IsCompleted) { Start-Sleep -Milliseconds 100 }

        if($connection.IsFaulted -eq "True")
        {
            Write-Error $connection.Exception
            return
        }

        # Send the first AMQP message
        SendToSocket -Socket $socket -Token $token -Bytes @(
            0x41, 0x4D, 0X51, 0X50, # AMQP
            0x03, # Protocol = SASL
            0x01, # Major
            0x00, # Minor
            0x00)

        # Receive response for the first AMQP message
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 100)

        # Receive SASL mechanism
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 100)

        # Send SASL Init (external)
        SendToSocket -Socket $socket -Token $token -Bytes (New-SASLInit)

        # Receive Welcome!
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 100)

        # Send AMQP init
        SendToSocket -Socket $socket -Token $token -Bytes @(
            0x41, 0x4D, 0X51, 0X50, # AMQP
            0x00, # Protocol
            0x01, # Major
            0x00, # Minor
            0x00) # Revision

        # Receive AMQP init response
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 100)

        # Send AMQP Open
        $id = Convert-ByteArrayToHex (Get-RandomBytes -Bytes 16)
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPOpen -ContainerId $id -HostName ($endpoint.Split("/")[2]))

        # Receive AMQP Open response
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 100)

        # Send AMQP Begin
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPBegin)

        # Receive AMQP Begin response
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 100)

        # Generate the name for Attach message
        $targetNumber = Get-Random -Minimum 1000 -Maximum 65000
        $name = "duplex$($targetNumber):$($targetNumber+2):$($targetNumber+3):"
        $source = '$cbs'
        
        # Send AMQP Attach (out)
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPAttachADFS -Handle 0 -Direction out -Name "$($name)sender" -Target $source)

        # Receive AMQP Attach (out)
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 250)

        # Receive AMQP Flow
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 100)

        # Send AMQP Attach (in)
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPAttachADFS -Handle 1 -Direction in -Name "$($name)receiver" -Target $id -Source $source)

        # Receive AMQP Attach (in)
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 250)

        # Send AMQP Flow
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPFlow)

        # Send SAS key
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPTransferADFSSAS -Name $SASName -Handle 0 -Id $id -SharedAccessSignature $SAS)
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 1000)

        # Send another attach for the insights
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPAttachADFS2 -Handle 2 -Name "$((New-Guid).ToString().replace('-',''));$($targetNumber):$($targetNumber+1):$($targetNumber+6)" -Target "$entitypath/Publishers/$publisher")
        $message = Parse-BusMessage (ReadFromSocket -Socket $socket -Token $token -ArraySize 1000)
                
        # Send the Insights message signature
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPTransferADFSInsights -Handle 2 -TenantId $TenantId -MachineId $MachineId -ServiceId $ServiceId -BlobUri $BlobAbsoluteUri -SigningTime $SigningTime -HmacSignature "$HMACSignature")

        # Close the channels
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPDetach -Handle 0)
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPDetach -Handle 1)
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPDetach -Handle 2)

        # Close the bus
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPEnd)
        SendToSocket -Socket $socket -Token $token -Bytes (New-AMQPClose)

            
    }Finally{

        If ($socket) { 
            Write-Verbose "Closing websocket"
            $socket.Dispose()
        }

    }
}

# Create a fake hybrid health service event
# May 26th 2021
function New-HybridHealtServiceEvent
{
<#
    .SYNOPSIS
    Creates a new ADHybridHealthService event.

    .DESCRIPTION
    Creates a new ADHybridHealthService event with the given parameters. 

    .Parameter UniqueID
    Unique ID of the event. Provide existing Request ID from the sign-in log to overwrite.

    .Parameter Server
    Server name of the AD FS server.
        
    .Parameter EventType
    Event type. Can be one of "NotSet","AppToken","FreshCredential","System","Discovery","Signout","PwdChange","DeviceReg","Resource","Config","ExtranetLockout".
    Defaults to AppToken.

    .Parameter PrimaryAuthentication
    The list of authentication methods. Can be a combination of "NotSet","Forms","Windows","Certificate","Device","Multifactor","Sso","Federated"
    Seems to always require "Sso". Defaults to "Forms","Sso"

    .Parameter RequiredAuthType
    Requires authentication type. Can be one of "NotSet","Primary","Secondary".
    Defaults to Primary

    .Parameter RelayingParty
    Relaying party. Defaults to "urn:federation:MicrosoftOnline"

    .Parameter RelyingPartyName
    Display Name of the relaying party.

    .Parameter Result
    Was the authentication successful or not. Defaults to $True

    .Parameter DeviceAuthentication
    Was device authentication used or not. Defaults to $False
        
    .Parameter URL
    Url. Defaults to "/adfs/ls"

    .Parameter User
    Some user id number. Defaults to 666

    .Parameter UserId
    User Id. Defaults to empty.
        
    .Parameter UserIdType
    User Id type. Can be one of "AnchorID","UPN","WindowsAccountName","PrimarySID","NameID","Email","Name","NotSet"
    Defaults to AnchorID

    .Parameter UPN
    User Principal Name of the user.

    .Parameter Timestamp
    Login time. Defaults to current time.

    .Parameter Protocol
    Authentication protocol used. Can be one of "NotSet","WSFederation","WSFedSamlP","OAuth","SAMLP","WSTrust","MSAdfsPIP","MSISHTTP"
    Defaults to WSFederation. If OAuth is used, the client id can be provided.

    .Parameter NetworkLocationType
    Network type, can be one of "NotSet","Intranet","Extranet"
    Defaults to Intranet. If Extranet is used, Azure AD shows geo location.

    .Parameter AppTokenFailureType
    Reason for login failure. Can be one of "NotAFailure","UPError","LockoutError","ExpiredPassword","DisabledAccount","DeviceAuthError","UserCertAuthError","IssuanceAuthZError","MFAError","ExtranetLockoutError","LogoutError","CredentialValidationError","OtherCredentialError","IssuanceDelegationError","TokenAcceptanceError","ProtocolError","WsFedRequestFailure","InvalidRelyingPartyError","InvalidClientApplicationError","GenericError","OtherError"
    Defaults to NotAFailure
        
    .Parameter IPAddress
    Ip address of the user.

    .Parameter ClaimsProvider
    Claims provider. 
    Defaults to empty.
        
    .Parameter OAuthClientID
    Client ID used in OAuth login.
    Defaults to empty.

    .Parameter OAuthTokenRetrievalMethod
    OAuth token retrieval method.
    Defaults to empty.

    .Parameter MFA
    MFA provider used to perform MFA.
    Defaults to empty.

    .Parameter MFAProviderErrorCode
    Error code provided by the MFA provider.
    Defaults to empty.

    .Parameter .ProxyServer
    Proxy server.
    Defaults to empty.

    .Parameter Endpoint
    AD FS endpoint.
    Defaults to "/adfs/ls/"

    .Parameter UserAgent
    UserAgent. 
    Defaults to "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",

    .Parameter DeviceID
    Device ID used during the login. Can be any device from Azure AD.
    Defaults to empty.

    .Parameter ErrorHitCount
    Number of login errors.
    Defaults to 0.

    .Parameter X509CertificateType
    Type of X509 Certificate.
    Defaults to empty.

    .Parameter $MFAAuthenticationType
    MFA authentication type.
    Defaults to empty.

    .Parameter ActivityId
    Activity Id of the event.
    Defaults to random guid.

    .Parameter ActivityIdAutoGenerated
    Is Activity Id automatically generated or not. Defaults to $False

    .Parameter PrimarySid
    The primary SID of the user.
    Defaults to empty.

    .Parameter ImmutableId
    Immutable Id of the user. Base 64 encoded GUID of the user's AD object.
    Defaults to empty.

    .Example
    PS C:\>$events = @()
    PS C:\>$events += (New-AADIntHybridHealtServiceEvent -Server "Server" -UPN "user@company.com" -IPAddress "192.168.0.2")

    PS C:\>Send-AADIntHybridHealthServiceEventBlob -BlobKey $blobKey -TenantId $tenantId -MachineId $machineId -ServiceId $serviceId -EventPublisherKey $eventKey -Events $events 
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [guid]$UniqueID = (New-Guid),

        [Parameter(Mandatory=$True)]
        [String]$Server,
        
        [Parameter(Mandatory=$False)]
        [ValidateSet("NotSet","AppToken","FreshCredential","System","Discovery","Signout","PwdChange","DeviceReg","Resource","Config","ExtranetLockout")]
        [String]$EventType = "AppToken",

        [Parameter(Mandatory=$False)]
        [ValidateSet("NotSet","Forms","Windows","Certificate","Device","Multifactor","Sso","Federated")]
        [String[]]$PrimaryAuthentication = @("Forms","Sso"),

        [Parameter(Mandatory=$False)]
        [ValidateSet("NotSet","Primary","Secondary")]
        [String]$RequiredAuthType = "Primary",

        [Parameter(Mandatory=$False)]
        [String]$RelyingParty = "urn:federation:MicrosoftOnline",

        [Parameter(Mandatory=$False)]
        [String]$RelyingPartyName = "",

        [Parameter(Mandatory=$False)]
        [bool]$Result = $True,

        [Parameter(Mandatory=$False)]
        [bool]$DeviceAuthentication = $False,
        
        [Parameter(Mandatory=$False)]
        [String]$URL = "/adfs/ls",

        [Parameter(Mandatory=$False)]
        [int]$User = 666,

        [Parameter(Mandatory=$False)]
        [String]$UserId,
        
        [Parameter(Mandatory=$False)]
        [ValidateSet("AnchorID","UPN","WindowsAccountName","PrimarySID","NameID","Email","Name","NotSet")]
        [String]$UserIdType = "AnchorID",

        [Parameter(Mandatory=$True)]
        [String]$UPN,

        [Parameter(Mandatory=$False)]
        [datetime]$Timestamp = (Get-Date),

        [Parameter(Mandatory=$False)]
        [ValidateSet("NotSet","WSFederation","WSFedSamlP","OAuth","SAMLP","WSTrust","MSAdfsPIP","MSISHTTP")]
        [String]$Protocol = "WSFederation",

        [Parameter(Mandatory=$False)]
        [ValidateSet("NotSet","Intranet","Extranet")]
        [String]$NetworkLocationType = "Intranet",

        [Parameter(Mandatory=$False)]
        [ValidateSet("NotAFailure","UPError","LockoutError","ExpiredPassword","DisabledAccount","DeviceAuthError","UserCertAuthError","IssuanceAuthZError","MFAError","ExtranetLockoutError","LogoutError","CredentialValidationError","OtherCredentialError","IssuanceDelegationError","TokenAcceptanceError","ProtocolError","WsFedRequestFailure","InvalidRelyingPartyError","InvalidClientApplicationError","GenericError","OtherError")]
        [String]$AppTokenFailureType = "NotAFailure",
        
        [Parameter(Mandatory=$True)]
        [String]$IPAddress,

        [Parameter(Mandatory=$False)]
        [String]$ClaimsProvider,
        
        [Parameter(Mandatory=$False)]
        [String]$OAuthClientID,

        [Parameter(Mandatory=$False)]
        [String]$OAuthTokenRetrievalMethod,

        [Parameter(Mandatory=$False)]
        [String]$MFA,

        [Parameter(Mandatory=$False)]
        [String]$MFAProviderErrorCode,

        [Parameter(Mandatory=$False)]
        [String]$ProxyServer,

        [Parameter(Mandatory=$False)]
        [String]$Endpoint = "/adfs/ls/",

        [Parameter(Mandatory=$False)]
        [String]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",

        [Parameter(Mandatory=$False)]
        [String]$DeviceID,

        [Parameter(Mandatory=$False)]
        [int]$ErrorHitCount = 0,

        [Parameter(Mandatory=$False)]
        [String]$X509CertificateType,

        [Parameter(Mandatory=$False)]
        [String]$MFAAuthenticationType,

        [Parameter(Mandatory=$False)]
        [guid]$ActivityId = (New-Guid),

        [Parameter(Mandatory=$False)]
        [bool]$ActivityIdAutoGenerated = $False,

        [Parameter(Mandatory=$False)]
        [String]$PrimarySid,

        [Parameter(Mandatory=$False)]
        [String]$ImmutableId
    )
    Begin
    {
        $ADFSEventTypes = [ordered]@{
            "NotSet"          =   0
		    "AppToken"        =   1  # Normal login
		    "FreshCredential" =   2
		    "System"          =   4
		    "Discovery"       =   8
		    "Signout"         =  16
		    "PwdChange"       =  32
		    "DeviceReg"       =  64
		    "Resource"        = 128
		    "Config"          = 256
		    "ExtranetLockout" = 512
        }
        $ADFSAuthTypes = [ordered]@{
		    "NotSet"      =  0
		    "Forms"       =  1
		    "Windows"     =  2
		    "Certificate" =  4
		    "Device"      =  8
		    "Multifactor" = 16
		    "Sso"         = 32
		    "Federated"   = 64
	    }
        $ADFSRequiredAuthType = [ordered]@{
		    "NotSet"    = 0
		    "Primary"   = 1
		    "Secondary" = 2
	}
        $UserIdTypes = [ordered]@{
			"AnchorID"           =   10
			"UPN"                =   20
            "WindowsAccountName" =   30
			"PrimarySID"         =   40
			"NameID"             =   50
			"Email"              =   60
			"Name"               =   70
			"NotSet"             = 1000
		}
        $ADFSProtocolTypes = [ordered]@{
		    "NotSet"       =  0
		    "WSFederation" =  2
		    "WSFedSamlP"   =  4
		    "OAuth"        = 10
		    "SAMLP"        = 20
		    "WSTrust"      = 30
            "MSAdfsPIP"    = 40
		    "MSISHTTP"     = 50
	    }
        $NetworkLocationTypes = [ordered]@{
			"NotSet"   = 0
			"Intranet" = 1
			"Extranet" = 2
		}
        $ADFSFailureTypes = [ordered]@{
		    "NotAFailure"                   =    0
		    "UPError"                       =    1
		    "LockoutError"                  =    2
		    "ExpiredPassword"               =    3
		    "DisabledAccount"               =    4
		    "DeviceAuthError"               =    5
		    "UserCertAuthError"             =   10
		    "IssuanceAuthZError"            =   20
		    "MFAError"                      =   21
		    "ExtranetLockoutError"          =   30
		    "LogoutError"                   =   40
		    "CredentialValidationError"     =   50
		    "OtherCredentialError"          =   70
		    "IssuanceDelegationError"       =   80
		    "TokenAcceptanceError"          =   90
		    "ProtocolError"                 =  100
		    "WsFedRequestFailure"           =  110
		    "InvalidRelyingPartyError"      =  111
		    "InvalidClientApplicationError" =  112
		    "GenericError"                  =  500
		    "OtherError"                    = 1000
	    }
    }
    Process
    {
        # Combine authentication types
        if($PrimaryAuthentication.Count -eq 1)
        {
            $combinedAuthType = $ADFSAuthTypes[$PrimaryAuthentication]
        }
        else
        {
            $combinedAuthType = 0
            foreach($type in $PrimaryAuthentication)
            {
                $combinedAuthType = $combinedAuthType -bor $ADFSAuthTypes[$type]
            }
        }

        $event = [ordered]@{
            "UniqueID"                  = $UniqueID.ToString()
            "Server"                    = $Server
            "EventType"                 = $ADFSEventTypes[$EventType]
            "PrimaryAuthentication"     = $combinedAuthType
            "RequiredAuthType"          = $ADFSRequiredAuthType[$RequiredAuthType]
            "RelyingParty"              = $RelyingParty
            "RelyingPartyName"          = $RelyingPartyName
            "Result"                    = $Result
            "DeviceAuthentication"      = $DeviceAuthentication
            "URL"                       = $URL
            "User"                      = $User
            "UserId"                    = $UserId
            "UserIdType"                = $UserIdTypes[$UserIdType]
            "UPN"                       = $UPN
            "Timestamp"                 = $Timestamp.ToUniversalTime().ToString("o", [cultureinfo]::InvariantCulture)
            "Protocol"                  = $ADFSProtocolTypes[$Protocol]
            "NetworkLocation"           = $NetworkLocationTypes[$NetworkLocationType]
            "AppTokenFailureType"       = $ADFSFailureTypes[$AppTokenFailureType]
            "IPAddress"                 = $IPAddress
            "ClaimsProvider"            = $ClaimsProvider
            "OAuthClientID"             = $OAuthClientID
            "OAuthTokenRetrievalMethod" = $OAuthTokenRetrievalMethod
            "MFA"                       = $MFA
            "MFAProviderErrorCode"      = $MFAProviderErrorCode
            "ProxyServer"               = $ProxyServer
            "Endpoint"                  = $Endpoint
            "UserAgent"                 = $UserAgent
            "DeviceID"                  = $DeviceID
            "ErrorHitCount"             = $ErrorHitCount
            "X509CertificateType"       = $X509CertificateType
            "MFAAuthenticationType"     = $MFAAuthenticationType
            "ActivityId"                = $ActivityId.ToString()
            "ActivityIdAutoGenerated"   = $ActivityIdAutoGenerated
            "PrimarySid"                = $PrimarySid
            "ImmutableId"               = $ImmutableId
        }

        return $event
    }
}