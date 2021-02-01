# Initial AADSync server name
$aadsync_server=        "adminwebservice.microsoftonline.com"
$aadsync_client_version="8.0"
$aadsync_client_build=  "1.5.29.0"

# Dictionary for binary WCF binary xml
$XmlDictKeys=@("mustUnderstand", "Envelope", "http://www.w3.org/2003/05/soap-envelope", "http://www.w3.org/2005/08/addressing", "Header", "Action", "To", "Body", "Algorithm", "RelatesTo", "http://www.w3.org/2005/08/addressing/anonymous", "URI", "Reference", "MessageID", "Id", "Identifier", "http://schemas.xmlsoap.org/ws/2005/02/rm", "Transforms", "Transform", "DigestMethod", "DigestValue", "Address", "ReplyTo", "SequenceAcknowledgement", "AcknowledgementRange", "Upper", "Lower", "BufferRemaining", "http://schemas.microsoft.com/ws/2006/05/rm", "http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement", "SecurityTokenReference", "Sequence", "MessageNumber", "http://www.w3.org/2000/09/xmldsig#", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", "KeyInfo", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "http://www.w3.org/2001/04/xmlenc#", "http://schemas.xmlsoap.org/ws/2005/02/sc", "DerivedKeyToken", "Nonce", "Signature", "SignedInfo", "CanonicalizationMethod", "SignatureMethod", "SignatureValue", "DataReference", "EncryptedData", "EncryptionMethod", "CipherData", "CipherValue", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Security", "Timestamp", "Created", "Expires", "Length", "ReferenceList", "ValueType", "Type", "EncryptedHeader", "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd", "RequestSecurityTokenResponseCollection", "http://schemas.xmlsoap.org/ws/2005/02/trust", "http://schemas.xmlsoap.org/ws/2005/02/trust#BinarySecret", "http://schemas.microsoft.com/ws/2006/02/transactions", "s", "Fault", "MustUnderstand", "role", "relay", "Code", "Reason", "Text", "Node", "Role", "Detail", "Value", "Subcode", "NotUnderstood", "qname", "", "From", "FaultTo", "EndpointReference", "PortType", "ServiceName", "PortName", "ReferenceProperties", "RelationshipType", "Reply", "a", "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity", "Identity", "Spn", "Upn", "Rsa", "Dns", "X509v3Certificate", "http://www.w3.org/2005/08/addressing/fault", "ReferenceParameters", "IsReferenceParameter", "http://www.w3.org/2005/08/addressing/reply", "http://www.w3.org/2005/08/addressing/none", "Metadata", "http://schemas.xmlsoap.org/ws/2004/08/addressing", "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous", "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault", "http://schemas.xmlsoap.org/ws/2004/06/addressingex", "RedirectTo", "Via", "http://www.w3.org/2001/10/xml-exc-c14n#", "PrefixList", "InclusiveNamespaces", "ec", "SecurityContextToken", "Generation", "Label", "Offset", "Properties", "Cookie", "wsc", "http://schemas.xmlsoap.org/ws/2004/04/sc", "http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk", "http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT", "RenewNeeded", "BadContextToken", "c", "http://schemas.xmlsoap.org/ws/2005/02/sc/dk", "http://schemas.xmlsoap.org/ws/2005/02/sc/sct", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel", "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes128", "http://www.w3.org/2001/04/xmlenc#aes192-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes192", "http://www.w3.org/2001/04/xmlenc#aes256-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes256", "http://www.w3.org/2001/04/xmlenc#des-cbc", "http://www.w3.org/2000/09/xmldsig#dsa-sha1", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments", "http://www.w3.org/2000/09/xmldsig#hmac-sha1", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1", "http://www.w3.org/2001/04/xmlenc#ripemd160", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmlenc#rsa-1_5", "http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmlenc#sha512", "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "http://www.w3.org/2001/04/xmlenc#kw-tripledes", "http://schemas.xmlsoap.org/2005/02/trust/tlsnego#TLS_Wrap", "http://schemas.xmlsoap.org/2005/02/trust/spnego#GSS_Wrap", "http://schemas.microsoft.com/ws/2006/05/security", "dnse", "o", "Password", "PasswordText", "Username", "UsernameToken", "BinarySecurityToken", "EncodingType", "KeyIdentifier", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#HexBinary", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ1510", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID", "Assertion", "urn:oasis:names:tc:SAML:1.0:assertion", "http://docs.oasis-open.org/wss/oasis-wss-rel-token-profile-1.0.pdf#license", "FailedAuthentication", "InvalidSecurityToken", "InvalidSecurity", "k", "SignatureConfirmation", "TokenType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID", "AUTH-HASH", "RequestSecurityTokenResponse", "KeySize", "RequestedTokenReference", "AppliesTo", "Authenticator", "CombinedHash", "BinaryExchange", "Lifetime", "RequestedSecurityToken", "Entropy", "RequestedProofToken", "ComputedKey", "RequestSecurityToken", "RequestType", "Context", "BinarySecret", "http://schemas.xmlsoap.org/ws/2005/02/trust/spnego", " http://schemas.xmlsoap.org/ws/2005/02/trust/tlsnego", "wst", "http://schemas.xmlsoap.org/ws/2004/04/trust", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/CK/PSHA1", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Nonce", "KeyType", "http://schemas.xmlsoap.org/ws/2004/04/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2004/04/trust/PublicKey", "Claims", "InvalidRequest", "RequestFailed", "SignWith", "EncryptWith", "EncryptionAlgorithm", "CanonicalizationAlgorithm", "ComputedKeyAlgorithm", "UseKey", "http://schemas.microsoft.com/net/2004/07/secext/WS-SPNego", "http://schemas.microsoft.com/net/2004/07/secext/TLSNego", "t", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1", "http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce", "RenewTarget", "CancelTarget", "RequestedTokenCancelled", "RequestedAttachedReference", "RequestedUnattachedReference", "IssuedTokens", "http://schemas.xmlsoap.org/ws/2005/02/trust/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel", "http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey", "Access", "AccessDecision", "Advice", "AssertionID", "AssertionIDReference", "Attribute", "AttributeName", "AttributeNamespace", "AttributeStatement", "AttributeValue", "Audience", "AudienceRestrictionCondition", "AuthenticationInstant", "AuthenticationMethod", "AuthenticationStatement", "AuthorityBinding", "AuthorityKind", "AuthorizationDecisionStatement", "Binding", "Condition", "Conditions", "Decision", "DoNotCacheCondition", "Evidence", "IssueInstant", "Issuer", "Location", "MajorVersion", "MinorVersion", "NameIdentifier", "Format", "NameQualifier", "Namespace", "NotBefore", "NotOnOrAfter", "saml", "Statement", "Subject", "SubjectConfirmation", "SubjectConfirmationData", "ConfirmationMethod", "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key", "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches", "SubjectLocality", "DNSAddress", "IPAddress", "SubjectStatement", "urn:oasis:names:tc:SAML:1.0:am:unspecified", "xmlns", "Resource", "UserName", "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName", "EmailName", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "u", "ChannelInstance", "http://schemas.microsoft.com/ws/2005/02/duplex", "Encoding", "MimeType", "CarriedKeyName", "Recipient", "EncryptedKey", "KeyReference", "e", "http://www.w3.org/2001/04/xmlenc#Element", "http://www.w3.org/2001/04/xmlenc#Content", "KeyName", "MgmtData", "KeyValue", "RSAKeyValue", "Modulus", "Exponent", "X509Data", "X509IssuerSerial", "X509IssuerName", "X509SerialNumber", "X509Certificate", "AckRequested", "http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested", "AcksTo", "Accept", "CreateSequence", "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence", "CreateSequenceRefused", "CreateSequenceResponse", "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequenceResponse", "FaultCode", "InvalidAcknowledgement", "LastMessage", "http://schemas.xmlsoap.org/ws/2005/02/rm/LastMessage", "LastMessageNumberExceeded", "MessageNumberRollover", "Nack", "netrm", "Offer", "r", "SequenceFault", "SequenceTerminated", "TerminateSequence", "http://schemas.xmlsoap.org/ws/2005/02/rm/TerminateSequence", "UnknownSequence", "http://schemas.microsoft.com/ws/2006/02/tx/oletx", "oletx", "OleTxTransaction", "PropagationToken", "http://schemas.xmlsoap.org/ws/2004/10/wscoor", "wscoor", "CreateCoordinationContext", "CreateCoordinationContextResponse", "CoordinationContext", "CurrentContext", "CoordinationType", "RegistrationService", "Register", "RegisterResponse", "ProtocolIdentifier", "CoordinatorProtocolService", "ParticipantProtocolService", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContext", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContextResponse", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/Register", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/RegisterResponse", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/fault", "ActivationCoordinatorPortType", "RegistrationCoordinatorPortType", "InvalidState", "InvalidProtocol", "InvalidParameters", "NoActivity", "ContextRefused", "AlreadyRegistered", "http://schemas.xmlsoap.org/ws/2004/10/wsat", "wsat", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Completion", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Durable2PC", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Volatile2PC", "Prepare", "Prepared", "ReadOnly", "Commit", "Rollback", "Committed", "Aborted", "Replay", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Commit", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Rollback", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Committed", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Aborted", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepare", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepared", "http://schemas.xmlsoap.org/ws/2004/10/wsat/ReadOnly", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Replay", "http://schemas.xmlsoap.org/ws/2004/10/wsat/fault", "CompletionCoordinatorPortType", "CompletionParticipantPortType", "CoordinatorPortType", "ParticipantPortType", "InconsistentInternalState", "mstx", "Enlistment", "protocol", "LocalTransactionId", "IsolationLevel", "IsolationFlags", "Description", "Loopback", "RegisterInfo", "ContextId", "TokenId", "AccessDenied", "InvalidPolicy", "CoordinatorRegistrationFailed", "TooManyEnlistments", "Disabled", "ActivityId", "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5APREQSHA1", "http://schemas.xmlsoap.org/ws/2002/12/policy", "FloodMessage", "LinkUtility", "Hops", "http://schemas.microsoft.com/net/2006/05/peer/HopCount", "PeerVia", "http://schemas.microsoft.com/net/2006/05/peer", "PeerFlooder", "PeerTo", "http://schemas.microsoft.com/ws/2005/05/routing", "PacketRoutable", "http://schemas.microsoft.com/ws/2005/05/addressing/none", "http://schemas.microsoft.com/ws/2005/05/envelope/none", "http://www.w3.org/2001/XMLSchema-instance", "http://www.w3.org/2001/XMLSchema", "nil", "type", "char", "boolean", "byte", "unsignedByte", "short", "unsignedShort", "int", "unsignedInt", "long", "unsignedLong", "float", "double", "decimal", "dateTime", "string", "base64Binary", "anyType", "duration", "guid", "anyURI", "QName", "time", "date", "hexBinary", "gYearMonth", "gYear", "gMonthDay", "gDay")
[System.Xml.XmlDictionary]$xml_dictionary = $null

# Create (or use cached) XML dictionary
function Get-XmlDictionary
{
    [cmdletbinding()]
    Param()    
    Process
    {
        if([string]::IsNullOrEmpty($Script:xml_dictionary))
        {
            $d=New-Object System.Xml.XmlDictionary
            
            
            # Had to add this way, otherwise treated as an array????
            foreach($add in $Script:XmlDictKeys)
            {
                ([System.Xml.XmlDictionary]$d).Add($add) | Out-Null
            }

            $Script:xml_dictionary=$d

            # Remove the variable
            Remove-Variable -Name XmlDictKeys -Scope Script

        }
        
        return $Script:xml_dictionary
        
    }
}

# Converts WCF binary xml to XML
function BinaryToXml
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$xml_bytes
    )
    Process
    {
        $xml_doc = New-Object System.Xml.XmlDocument

        [System.Xml.XmlDictionaryReader]$reader = [System.Xml.XmlDictionaryReader]::CreateBinaryReader($xml_bytes,0,$xml_bytes.Length,$(Get-XmlDictionary),[System.Xml.XmlDictionaryReaderQuotas]::Max)

        $xml_doc.Load($reader)

        return $xml_doc
    }
}

# Converts Xml to WCF Binary format
function XmlToBinary
{
[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$xml_doc
    )
    Process
    {
        $ms = New-Object System.IO.MemoryStream

        $writer = [System.Xml.XmlDictionaryWriter]::CreateBinaryWriter($ms,$(Get-XmlDictionary))
        $xml_doc.WriteContentTo($writer);
        $writer.Flush()
        $ms.Position = 0;
        $length=$ms.Length

        [byte[]]$xml_bytes = New-Object Byte[] $length
        $ms.Read($xml_bytes, 0, $length) | Out-Null
        $ms.Flush()
        
        return $xml_bytes
    }
}

# Checks whether the response has redirect
function IsRedirectResponse
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$xml_doc

    )
    Process
    {
        try
        {
            $url=$xml_doc.Envelope.Body.Fault.Detail.BindingRedirectionFault.Url        
            if([string]::IsNullOrEmpty($url))
            {
                $message=$xml_doc.Envelope.Body.Fault.Reason.Text.'#text'
                if(![string]::IsNullOrEmpty($url))
                {
                    $Script:aadsync_server=$url.Split('/')[2]
                    Write-Verbose "ISREDIRECTRESPONSE: Changed server to $Script:aadsync_server"
                    return $True
                }
            }
            else
            {
                $Script:aadsync_server=$url.Split('/')[2]
                Write-Verbose "ISREDIRECTRESPONSE: Changed server to $Script:aadsync_server"
                return $True
            }

            return IsErrorResponse($xml_doc)
            
        }
        catch
        {
            throw $_
        }
    }
}

# Checks whether the response has redirect
function IsErrorResponse
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$xml_doc

    )
    Process
    {
        $error=Select-Xml -Xml $xml_doc -XPath "//*[local-name()='ErrorDescription']"
        if([string]::IsNullOrEmpty($error))
        {
            # All good
            return $False
        }
        else
        {
            # Got error, so throw an exception
            throw $error.Node.'#text'
        }
        
    }
}




# Create SOAP envelope for ADSync
function Create-SyncEnvelope
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,

        [Parameter(Mandatory=$True)]
        [String]$Command,

        [Parameter(Mandatory=$True)]
        [String]$Body,

        [Parameter(Mandatory=$True)]
        [String]$Message_id,

        [Parameter()]
        [String]$Server="adminwebservice.microsoftonline.com",

        [Parameter()]
        [switch]$Binary,

        [Parameter()]
        [bool]$IsInstalledOnDc=$False,

        [Parameter()]
        [bool]$RichCoexistenceEnabled=$False,
        
        [Parameter()]
        [int]$Version=1
    )
    Process
    {
        # Set the client ID
        if($Version -eq 2)
        {
            $applicationClient= "6eb59a73-39b2-4c23-a70f-e2e3ce8965b1"
        }
        else
        {
            $applicationClient = "1651564e-7ce4-4d99-88be-0a65050d8dc3"
        }

        # Create the envelope
        $envelope=@"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	        <s:Header>
		        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/online/aws/change/2010/01/IProvisioningWebService/$Command</a:Action>
		        <SyncToken s:role="urn:microsoft.online.administrativeservice" xmlns="urn:microsoft.online.administrativeservice" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
			        <ApplicationId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">$applicationClient</ApplicationId>
			        <BearerToken xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">$AccessToken</BearerToken>
			        <ClientVersion xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">$aadsync_client_version</ClientVersion>
			        <DirSyncBuildNumber xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">$aadsync_client_build</DirSyncBuildNumber>
			        <FIMBuildNumber xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">$aadsync_client_build</FIMBuildNumber>
			        <IsInstalledOnDC xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">$IsInstalledOnDc</IsInstalledOnDC>
			        <IssueDateTime xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">0001-01-01T00:00:00</IssueDateTime>
			        <LanguageId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">en-US</LanguageId>
			        <LiveToken xmlns="http://schemas.microsoft.com/online/aws/change/2010/01"/>
			        <ProtocolVersion xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">2.0</ProtocolVersion>
			        <RichCoexistenceEnabled xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">$RichCoexistenceEnabled</RichCoexistenceEnabled>
			        <TrackingId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">$Message_id</TrackingId>
		        </SyncToken>
		        <a:MessageID>urn:uuid:$message_id</a:MessageID>
		        <a:ReplyTo>
			        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		        </a:ReplyTo>
		        <a:To s:mustUnderstand="1">https://$Server/provisioningservice.svc</a:To>
	        </s:Header>
	        <s:Body>
		        $Body
	        </s:Body>
        </s:Envelope>
"@
        # Verbose
        Write-Verbose "ENVELOPE ($Command): $envelope"

        # Return the envelope as binary if requested
        if($Binary)
        {
            return XmlToBinary $envelope
        }
        else
        {
            $envelope
        }
    }
}

# Calls the ADSync SOAP API
function Call-ADSyncAPI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Envelope,
        [Parameter(Mandatory=$True)]
        [string]$Command,
        [Parameter(Mandatory=$True)]
        [string]$Tenant_id,
        [Parameter(Mandatory=$True)]
        [string]$Message_id,
        [Parameter(Mandatory=$False)]
        [string]$Server="adminwebservice.microsoftonline.com"
    )
    Process
    {
        $headers=@{
            "Host" =                           $Server
            "x-ms-aadmsods-appid"=             "1651564e-7ce4-4d99-88be-0a65050d8dc3"
            "x-ms-aadmsods-apiaction"=         $Command
            "client-request-id"=               $Message_id
            "x-ms-aadmsods-clientversion"=     $aadsync_client_version
            "x-ms-aadmsods-dirsyncbuildnumber"=$aadsync_client_build
            "x-ms-aadmsods-fimbuildnumber"=    $aadsync_client_build
            "x-ms-aadmsods-tenantid"=          $Tenant_id
            "User-Agent"=""
																					 
            
        }
        # Verbose
        Write-Verbose "CALL-ADSYNCAPI HEADERS: $($headers | Out-String)"

        $stream=$null

        # Call the API
        try
        {
            # Sometimes no error at all..?
            $response=Invoke-WebRequest -UseBasicParsing -Uri "https://$Server/provisioningservice.svc" -ContentType "application/soap+msbin1" -Method POST -Body $envelope -Headers $headers
            $stream=$response.RawContentStream
        }
        catch
        {
            # Should give error 500
            $Exception = $_.Exception
            if($Exception.Message -like "*500*")
            {
                $stream=$Exception.Response.GetResponseStream()
            }
            else
            {
                Throw $Exception
            }
        }
        
        $bytes=$stream.toArray()
        $bytes
    }
}

# Utility function for Provision-AzureADSyncObject to add property value 
function Add-PropertyValue
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Key,
        [Parameter(Mandatory=$False)]
        [PSobject]$Value,
        [ValidateSet('string','bool','base64','long','ArrayOfstring','ArrayOfbase64')]
        [String]$Type="string"
    )
    Process
    {
        
        if(![string]::IsNullOrEmpty($Value))
        {
            $PropBlock="<c:KeyValueOfstringanyType><c:Key>$Key</c:Key>"
            switch($Type)
            {
                'long' { $PropBlock += "<c:Value i:type=""d:long"" xmlns:d=""http://www.w3.org/2001/XMLSchema"">$Value</c:Value>" }
                'bool' { $PropBlock += "<c:Value i:type=""d:boolean"" xmlns:d=""http://www.w3.org/2001/XMLSchema"">$($Value.toString().toLower())</c:Value>" }
                'base64'{ $PropBlock += "<c:Value i:type=""d:base64Binary"" xmlns:d=""http://www.w3.org/2001/XMLSchema"">$Value</c:Value>" }
                'ArrayOfstring'{ 
                    $PropBlock += "<c:Value i:type=""c:ArrayOfstring"">"
                    foreach($stringValue in $Value)
                    {
                        $PropBlock += "<c:string>$stringValue</c:string>"
                    }

                    $PropBlock += "</c:Value>" 
                    }
                'ArrayOfbase64'{ 
                    $PropBlock += "<c:Value i:type=""c:ArrayOfbase64Binary"">"
                    foreach($stringValue in $Value)
                    {
                        $PropBlock += "<c:base64Binary>$stringValue</c:base64Binary>"
                    }

                    $PropBlock += "</c:Value>" 
                    }
                default { $PropBlock += "<c:Value i:type=""d:string"" xmlns:d=""http://www.w3.org/2001/XMLSchema"">$Value</c:Value>" }
            }

            $PropBlock+="</c:KeyValueOfstringanyType>"

            return $PropBlock
        }
    }
}

# Creates a AADHash for given password
Function Create-AADHash {

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$false)]
        [String]$Password,
        [parameter(Mandatory=$false)]
        [String]$Hash,
        [parameter(Mandatory=$false)]
        [int]$Iterations=1000
    )
    Process
    {
        if([string]::IsNullOrEmpty($Hash))
        {
            # Calculate MD4 from the password (Unicode)
            $md4 = (Get-MD4 -bArray ([System.Text.UnicodeEncoding]::Unicode.GetBytes($password))).ToUpper()
            
        }
        elseif($Hash.Length -ne 32)
        {
            Throw "Invalid hash length!"
        }
        else
        {
            $md4=$Hash
        }

        $md4bytes = ([System.Text.UnicodeEncoding]::Unicode.GetBytes($md4))
        

        # Generate random 10-byte salt
        $salt=@()
        for($count = 0; $count -lt 10 ; $count++)
        {
            $salt += Get-Random -Minimum 0 -Maximum 0xFF
        }

        # Calculate hash using 1000 iterations and SHA256
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($md4bytes,[byte[]]$salt,$Iterations,"SHA256")
        $bytes = $pbkdf2.GetBytes(32)

        # Convert to hex strings
        $hexbytes=Convert-ByteArrayToHex $bytes
        $hexsalt=Convert-ByteArrayToHex $salt

        # Create the return value
        $retVal = "v1;PPH1_MD4,$hexsalt,$Iterations,$hexbytes;"

        # Verbose
        Write-Verbose $retVal
        
        # Return
        return $retVal
    }
    
}
