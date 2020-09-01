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
        [String]$DeviceName
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
		<a:MessageID>urn:uuid:0d5a1441-5891-453b-becf-a2e5f6ea3749</a:MessageID>
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
					<ac:Value>true</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="HWDevID">
					<ac:Value>$HWDevID</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="Locale">
					<ac:Value>en-US</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="TargetedUserLoggedIn">
					<ac:Value>true</ac:Value>
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

        $response = Invoke-RestMethod -Method Post -Uri $url -Body $csrBody -ContentType "application/soap+xml; charset=utf-8" -Headers $headers

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


