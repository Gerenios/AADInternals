# This file contains utility functions for Intune MDM

# Get MDM discovery information
# Aug 20th
function Get-MDMEnrollmentService
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$UserName="user@alt.none"
    )
    Process
    {
        $messageId =          $(New-Guid).ToString()
        $deviceType =         "CIMClient_Windows"
        $applicationVersion = "10.0.18363.0"
        $OSEdition =          "4"
        
        $body=@"
<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/Discover</a:Action>
		<a:MessageID>urn:uuid:$messageId</a:MessageID>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
		<a:To s:mustUnderstand="1">https://enrollment.manage.microsoft.com:443/enrollmentserver/discovery.svc</a:To>
	</s:Header>
	<s:Body>
		<Discover xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
			<request xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
				<EmailAddress>$UserName</EmailAddress>
				<RequestVersion>4.0</RequestVersion>
				<DeviceType>$deviceType</DeviceType>
				<ApplicationVersion>$applicationVersion</ApplicationVersion>
				<OSEdition>$OSEdition</OSEdition>
				<AuthPolicies>
					<AuthPolicy>OnPremise</AuthPolicy>
					<AuthPolicy>Federated</AuthPolicy>
				</AuthPolicies>
			</request>
		</Discover>
	</s:Body>
</s:Envelope>
"@
        $headers=@{
            "Content-Type" = "application/soap+xml; charset=utf-8"
            "User-Agent"   = "ENROLLClient"
        }

        $response = Invoke-RestMethod -Method Post -Uri "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc" -Body $body -ContentType "application/soap+xml; charset=utf-8" -Headers $headers

        # Get the data
        $activityId = $response.Envelope.Header.ActivityId.'#text'
        $serviceUri = $response.Envelope.Body.DiscoverResponse.DiscoverResult.EnrollmentServiceUrl

        if(!$serviceUri.EndsWith($activityId))
        {
            $serviceUri += "?client-request-id=$activityId"
        }

        # Return
        return $serviceUri
            
    }
}

# Enroll device to MDM
# Aug 28th
function Enroll-DeviceToMDM
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$DeviceName,
        [Parameter(Mandatory=$True)]
        [bool]$BPRT
    )
    Process
    {
        # Get the claims from the access token
        $claims = Read-Accesstoken -AccessToken $AccessToken

        # Construct the values
        $enrollmentUrl =       Get-MDMEnrollmentService -UserName $claims.upn
        $binarySecurityToken = Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.GetBytes($AccessToken))

        $HWDevID = "$($claims.deviceid)$($claims.tid)".Replace("-","")
        $deviceId = $claims.deviceid.Replace("-","")

        # Create a private key
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)

        # Initialize the Certificate Signing Request object
        $CN = "CN=$($claims.deviceid)" 
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($CN, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        
        # Create the signing request
        $csr = Convert-ByteArrayToB64 -Bytes $req.CreateSigningRequest()
        
        $headers=@{
            "Content-Type" = "application/soap+xml; charset=utf-8"
            "User-Agent"   = "ENROLLClient"
        }

        # Create the CSR request body
        $csrBody=@"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512" xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
	<s:Header>
		<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
		<a:MessageID>urn:uuid:$((New-Guid).ToString())</a:MessageID>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
		<a:To s:mustUnderstand="1">$enrollmentUrl</a:To>
		<wsse:Security s:mustUnderstand="1">
			<wsse:BinarySecurityToken ValueType="urn:ietf:params:oauth:token-type:jwt" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">$binarySecurityToken</wsse:BinarySecurityToken>
		</wsse:Security>
	</s:Header>
	<s:Body>
		<wst:RequestSecurityToken>
			<wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</wst:TokenType>
			<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
			<wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">$csr</wsse:BinarySecurityToken>
			<ac:AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">
				<ac:ContextItem Name="UXInitiated">
					<ac:Value>(($BPRT -eq $false).ToString().ToLower())</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="HWDevID">
					<ac:Value>$HWDevID</ac:Value>
				</ac:ContextItem>
                <ac:ContextItem Name="BulkAADJ">
					<ac:Value>$($BPRT.ToString().ToLower())</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="Locale">
					<ac:Value>en-US</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="TargetedUserLoggedIn">
					<ac:Value>$(($BPRT -eq $false).ToString().ToLower())</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="EnrollmentData">
					<ac:Value></ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="OSEdition">
					<ac:Value>4</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="DeviceName">
					<ac:Value>$DeviceName</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="MAC">
					<ac:Value>00-00-00-00-00-00</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="DeviceID">
					<ac:Value>$deviceId</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="EnrollmentType">
					<ac:Value>Device</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="DeviceType">
					<ac:Value>CIMClient_Windows</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="OSVersion">
					<ac:Value>10.0.18363.0</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="ApplicationVersion">
					<ac:Value>10.0.18363.0</ac:Value>
				</ac:ContextItem>
			</ac:AdditionalContext>
		</wst:RequestSecurityToken>
	</s:Body>
</s:Envelope>
"@

        # Clean the url
        $url=$enrollmentUrl.Replace(":443","")

        # The user might not have the lisence
        try
        {
            $response = Invoke-RestMethod -Method Post -Uri $url -Body $csrBody -ContentType "application/soap+xml; charset=utf-8" -Headers $headers
        }
        catch
        {
            throw $_
        }

        # Get the data
        $binSecurityToken = $response.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.BinarySecurityToken.'#text'
        $xmlSecurityToken = [xml][text.encoding]::UTF8.GetString((Convert-B64ToByteArray -B64 $binSecurityToken))

        Write-Debug "BinarySecurityToken: $($xmlSecurityToken.OuterXml)"

        # Get the certificates
        $CA =       $xmlSecurityToken.'wap-provisioningdoc'.characteristic[0].characteristic[0].characteristic.characteristic.Parm.value
        $IntMedCA = $xmlSecurityToken.'wap-provisioningdoc'.characteristic[0].characteristic[1].characteristic.characteristic.Parm.value
        $binCert =  [byte[]](Convert-B64ToByteArray -B64 ($xmlSecurityToken.'wap-provisioningdoc'.characteristic[0].characteristic[2].characteristic.characteristic.Parm.value))

        # Create a new x509certificate 
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($binCert,"",[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

        # Store the private key to so that it can be exported
        $cspParameters = [System.Security.Cryptography.CspParameters]::new()
        $cspParameters.ProviderName =    "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $cspParameters.ProviderType =    24
        $cspParameters.KeyContainerName ="AADInternals"
            
        # Set the private key
        $privateKey = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cspParameters)
        $privateKey.ImportParameters($rsa.ExportParameters($true))
        $cert.PrivateKey = $privateKey

        # Generate the return value
        $joinInfo = @(
            $CA,
            $IntMedCA,
            $cert
        )
        
        return $joinInfo
            
    }
}

# Sep 3rd 2020
# Automatically responses to the given command array
function New-SyncMLAutoresponse
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$DeviceName,
        [Parameter(Mandatory=$True)]
        [Object[]]$Commands,
        [Parameter(Mandatory=$True)]
        [int]$MsgID,
        [Parameter(Mandatory=$True)]
        [Hashtable]$Settings
    )
    Begin
    {
        $response200 = @(
            "Add"
            "Replace"
            "Atomic"
            "Delete"
            "Sequence"
            )
    }
    Process
    {
        $resCommands = @()
        $CmdID = 1

        foreach($command in $commands)
        {
            
            if($command.type -ne "Status")
            {
                # Just answer 400 to (almost) all requests
                $errorCode = 400

                # For NodeCache requests
                if($command.Type -eq "Get" -and $command.LocURI.StartsWith("./Vendor/MSFT/NodeCache/"))
                {
                    $errorCode = 404
                }

                # Status must be 200 for predefined answers
                if($command.type -eq "Get" -and $Settings[$command.LocURI] -ne $null)
                {
                    $errorCode = 200
                }

                # Okay, let's be nice for some commands :)
                if($response200 -contains $command.Type)
                {
                    $errorCode = 200
                }

                # Create the status message
                $attr = [ordered]@{
                    Type="Status"
                    CmdID =  $CmdID++
                    MsgRef = $MsgID-1 # Status is always referring to the previous message
                    CmdRef = $command.CmdID
                    Cmd =    $command.Type
                    Data =   $errorCode
                }

                $resCommands += New-Object psobject -Property $attr

                # Create the results message
                if($command.type -eq "Get" -and $Settings[$command.LocURI] -ne $null)
                {
                    $attr = [ordered]@{
                        Type="Results"
                        CmdID =  $CmdID++
                        MsgRef = $MsgID-1 # Status is always referring to the previous message
                        CmdRef = $command.CmdID
                        Cmd =    $command.Type
                        LocURI = $command.LocURI
                        Data =   $Settings[$command.LocURI]
                    }

                    $resCommands += New-Object psobject -Property $attr
                }

                if($command.type -eq "Get" -and $errorCode -ne 200)
                {
                    #if($VerbosePreference)
                    #{
                        Write-Warning " < No data ($MsgID): $command"
                    #}
                }

            }
            else
            {
                $resCommands += $command
                $CmdID++
            }
        }

        return $resCommands
    }
}

# Sep 2nd 2020
# Create a new SyncML request
function New-SyncMLRequest
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$DeviceName,
        [Parameter(Mandatory=$True)]
        [int]$SessionID,
        [Parameter(Mandatory=$True)]
        [int]$MsgID,
        [Parameter(Mandatory=$False)]
        [string]$VerDTD="1.2",
        [Parameter(Mandatory=$False)]
        [string]$VerProto="DM/1.2",
        [Parameter(Mandatory=$False)]
        [Object[]]$commands
    )
    Process
    {
        $CmdId = 1
        $syncBody=""


        foreach($command in $commands)
        {
            Write-Verbose " > $command"
            switch($command.Type)
            {
                "Alert"
                {
                    if($command.ItemData)
                    {

                        if($command.MetaType)
                        {
                            $meta = @"
				<Meta>
					<Type xmlns="syncml:metinf">$($command.MetaType)</Type> 
				</Meta>
"@
                        }

                        $syncBody += @"
        <Alert>
			<CmdID>$($command.CmdId)</CmdID>
			<Data>$($command.Data)</Data>
            <Item>
$meta
				<Data>$($command.ItemData)</Data> 
			</Item>
		</Alert>
"@
                    }
                    else
                    {
                        $syncBody += @"
        <Alert>
			<CmdID>$($command.CmdId)</CmdID>
			<Data>$($command.Data)</Data>
		</Alert>
"@
                    }
                                        

                    break
                }
                "Replace"
                {
                    
                        $syncBody += @"
        <Replace>
            <CmdID>$($command.CmdId)</CmdID>
"@
                    foreach($key in $command.Items.Keys)
                    {
                        $syncBody += @"
            
			<Item>
				<Source>
					<LocURI>$key</LocURI>
				</Source>
				<Data>$($command.Items[$key])</Data>
			</Item>
"@
                    }
                    $syncBody += "`n        </Replace>"
        

                    break
                }
                "Delete"
                {

                    break
                }
                "Atomic"
                {
                    $syncBody += "`n"
                    $syncBody += @"
        <Status>
			<CmdID>$($command.CmdId)</CmdID>
			<MsgRef>$($command.MsgRef)</MsgRef>
			<CmdRef>$($command.CmdRef)</CmdRef>
			<Cmd>$($command.Cmd)</Cmd>
			<Data>200</Data>
        </Status>
"@
                    break
                }
                "Sequence"
                {
                    $syncBody += "`n"
                    $syncBody += @"
        <Status>
			<CmdID>$($command.CmdId)</CmdID>
			<MsgRef>$($command.MsgRef)</MsgRef>
			<CmdRef>$($command.CmdRef)</CmdRef>
			<Cmd>$($command.Cmd)</Cmd>
			<Data>200</Data>
        </Status>
"@
                    break
                }
                "Final"
                {
                    break
                }
                "Status"
                {
                    $syncBody += "`n"
                    $syncBody += @"
        <Status>
			<CmdID>$($command.CmdId)</CmdID>
			<MsgRef>$($command.MsgRef)</MsgRef>
			<CmdRef>$($command.CmdRef)</CmdRef>
			<Cmd>$($command.Cmd)</Cmd>
			<Data>$($command.Data)</Data>
        </Status>
"@
                    break
                }
                "Results"
                {
                    $syncBody += "`n"
                    $syncBody += @"
        <Results>
			<CmdID>$($command.CmdId)</CmdID>
			<MsgRef>$($command.MsgRef)</MsgRef>
			<CmdRef>$($command.CmdRef)</CmdRef>
			<Item>
				<Source>
					<LocURI>$($command.LocURI)</LocURI>
				</Source>
				<Data>$($command.Data)</Data>
			</Item>
        </Results>
"@
                    break
                }
            }
        }



        # Construct the body

        $syncML = @"
<?xml version = "1.0" encoding = "UTF-8" ?>
<SyncML>
	<SyncHdr>
		<VerDTD>$VerDTD</VerDTD>
		<VerProto>$VerProto</VerProto>
		<SessionID>$SessionID</SessionID>
		<MsgID>$MsgID</MsgID>
		<Target>
			<LocURI>https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx</LocURI>
		</Target>
		<Source>
			<LocURI>$DeviceName</LocURI>
		</Source>
	</SyncHdr>
	<SyncBody>
$syncBody
		<Final/>
	</SyncBody>
</SyncML>
"@

        return $syncML
    }
}

# Sep 2nd 2020
# Parses the SyncML response and returns an array containing all the returned commands
function Parse-SyncMLResponse
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Xml.XmlDocument]$SyncML
    )
    Process
    {
        $commands = @()
        $CmdId = 1
        
        function parseNode
        {
            Param(
                [Parameter(Mandatory=$True)]
                $node,
                [Parameter(Mandatory=$True)]
                [ref]$commands
            )
            Process
            {
                switch($node.Name)
                {
                    "Status"
                    {
                        $attr = [ordered]@{
                            Type="Status"
                            CmdID =  $node.CmdID
                            MsgRef = $node.MsgRef
                            CmdRef = 0
                            Cmd =    $node.Cmd
                            Data =   $node.Data
                        }
                        $commands.value += New-Object psobject -Property $attr
                        break
                    }
                    "Get"
                    {
                        $attr = [ordered]@{
                            Type="Get"
                            CmdID =  $node.CmdID
                            LocURI = $node.Item.Target.LocURI
                        }
                        $commands.value += New-Object psobject -Property $attr
                        break
                    }
                    "Add"
                    {
                        $attr = [ordered]@{
                            Type="Add"
                            CmdID =  $node.CmdID
                            LocURI = $node.Item.Target.LocURI
                        }
                        $commands.value += New-Object psobject -Property $attr
                        break
                    }
                    "Replace"
                    {
                        $attr = [ordered]@{
                            Type="Replace"
                            CmdID =   $node.CmdID
                            LocURI =  $node.Item.Target.LocURI
                            MFormat = $node.Item.Meta.Format.'#text'
                            MType =   $node.Item.Meta.Type.'#text'
                            Data =    $node.Item.Data
                        }
                        $commands.value += New-Object psobject -Property $attr
                        break
                    }
                    "Delete"
                    {
                        $attr = [ordered]@{
                            Type="Delete"
                            CmdID =  $node.CmdID
                            LocURI = $node.Item.Target.LocURI
                        }
                        $commands.value += New-Object psobject -Property $attr
                        break
                    }
                    "Atomic"
                    {
                        # Parse nodes inside this one
                        foreach($inode in $node.ChildNodes)
                        {
                            parseNode -node $inode -commands $commands
                        }

                        $attr = [ordered]@{
                            Type="Atomic"
                            CmdID =  $node.CmdID
                        }
                        $commands.value += New-Object psobject -Property $attr
                        break
                    }
                    "Sequence"
                    {
                        # Parse nodes inside this one
                        foreach($inode in $node.ChildNodes)
                        {
                            parseNode -node $inode -commands $commands
                        }

                        $attr = [ordered]@{
                            Type="Sequence"
                            CmdID =  $node.CmdID
                            LocURI = ""
                        }
                        $commands.value += New-Object psobject -Property $attr
                        break
                    }
                    "Final"
                    {
                        #$commands.value += New-Object psobject -Property @{Type="Final"}
                        break
                    }
                }
            }
        }
        
        foreach($node in $SyncML.SyncML.SyncBody.ChildNodes)
        {
            parseNode -node $node -commands ([ref]$commands)
        }

        if($VerbosePreference)
        {
            foreach($command in $commands)
            {
                Write-Verbose " < $command"
            }
        }

        return $commands
    }
}

# Sep 2nd 2020
# Sends the given SyncML to Intune and returns the response as an xml document
function Invoke-SyncMLRequest
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$SyncML,
        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    Process
    {
        $headers=@{
            "Content-Type" =   "application/vnd.syncml.dm+xml; charset=utf-8"
            "Accept"       =   "application/vnd.syncml.dm+xml, application/octet-stream"
            "Accept-Charset" = "UTF-8"
            "User-Agent" =     "MSFT OMA DM Client/1.2.0.1"
        }

        Write-Debug "Request: $SyncML"

        try
        {
            $response = Invoke-WebRequest -UseBasicParsing -Certificate $Certificate -Method Post -Uri "https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx?mode=Maintenance&Platform=WoA" -Headers $headers -Body $SyncML -ErrorAction SilentlyContinue -ContentType "application/vnd.syncml.dm+xml; charset=utf-8"
            $xml = [xml]$response.content
        }
        catch
        {
            throw "SyncML request failed"
        }

        Write-Debug "Response: $($xml.OuterXml)"

        return $xml
    }
}


# Gets the object id of the device using device id
# Sep 11th 2020

function Get-DeviceObjectId
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$DeviceId,
        [Parameter(Mandatory=$True)]
        [String]$TenantId,
        [Parameter(Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Accept" =        "application/json;odata=nometadata"
        }

        Write-Verbose "Getting objectId for device $DeviceId"
        $devices = Invoke-RestMethod -Method Get -Uri "https://graph.windows.net/$tenantId/devices?`$filter=deviceId eq guid'$DeviceId'&`$select=objectId,displayName,deviceId&api-version=1.61-internal" -Headers $headers

        foreach($device in $devices.value)
        {
            if($device.deviceId -eq $DeviceId)
            {
                $ObjectId = $device.objectId
                break
            }
        }

        if([string]::IsNullOrEmpty($ObjectId))
        {
            throw "Device $DeviceId not found!"
        }

        return $ObjectId
    }
}