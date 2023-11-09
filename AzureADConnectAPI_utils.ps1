# Initial AADSync server name
$aadsync_server=        "adminwebservice.microsoftonline.com"
$aadsync_client_version="8.0"
$aadsync_client_build=  "2.2.8.0"

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
        # Debug
        Write-Debug "ENVELOPE ($Command): $envelope"

        # Return the envelope as binary if requested
        if($Binary)
        {
            return XmlToBinary $envelope -Dictionary (Get-XmlDictionary -Type WCF)
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
        Write-Debug "CALL-ADSYNCAPI HEADERS: $($headers | Out-String)"

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
        Write-Debug $retVal
        
        # Return
        return $retVal
    }
    
}
