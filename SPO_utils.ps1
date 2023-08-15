# Utility functions for SharePoint Online

# Gets the authentication cookie for SPO web interface
# Supports MFA, federation, etc.
# Jul 17th 2019
function Get-SPOAuthenticationHeader
{
<#
    .SYNOPSIS
    Gets authentication header for SharePoint Online

    .DESCRIPTION
    Gets authentication header for SharePoint Online, which is used for example to retrieve site users.

    .Parameter Site
    Url for the SharePoint Online
    
    .Example
    Get-AADIntSPOAuthenticationHeader
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site
    )
    Process
    {
        # Check the site url
		$Site = $Site.Trim("/")

        $siteDomain=$Site.Split("/")[2]
        
        $headers=@{
                "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                "Upgrade-Insecure-Requests" = "1"
                "Accept-Encoding" = "gzip, deflate, br"
                "Accept-Language" = "en-US,en;q=0.9"
                "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"

        }

        # Step 1: Go to the requested site
        $response = Invoke-WebRequest2 -uri $Site -MaximumRedirection 0 -ErrorAction SilentlyContinue
        
        # Step 2: Go to "/_layouts/15/Authenticate.aspx?Source=%2F"
        $url = $response.Headers.'Location'
        $response = Invoke-WebRequest2 -uri $url -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $siteWebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain $siteDomain

        # Step 3: Go to "/_forms/default.aspx?ReturnUrl=%2f_layouts%2f15%2fAuthenticate.aspx%3fSource%3d%252F&Source=cookie"
        $html=$response.Content
        $s=$html.IndexOf('href="')+6
        $e=$html.IndexOf('"',$s)
        $url=$html.Substring($s,$e-$s)
        $url="https://$siteDomain$url"
        $response = Invoke-WebRequest2 -uri $url -MaximumRedirection 0 -WebSession $siteWebSession -ErrorAction SilentlyContinue

        # Create the cookie header for the login form
        $cookieHeaderValue=""
        $cookies = $response.Headers.'Set-Cookie'.Split(";,")
        foreach($cookie in $cookies) 
        {
                
            $name = $cookie.Split("=")[0].trim()
            $value = $cookie.Substring($name.Length+1)
                
            if($name.StartsWith("nSGt") -or $name -eq "RpsContextCookie")
            {
                # If not empty, append the separator
                if(![String]::IsNullOrEmpty($cookieHeaderValue))
                {
                    $cookieHeaderValue+="; "
                }

                $cookieHeaderValue+="$name=$value"

            }
        }

        # Set variables
        $auth_redirect="foobar"#"https://login.microsoftonline.com/common/federation/oauth2"#"https://login.microsoftonline.com/kmsi"
        $url=$response.Headers.Location

        # Create the form
        $form = Create-LoginForm -Url $url -auth_redirect $auth_redirect -Headers "Cookie: $cookieHeaderValue"

        # Show the form and wait for the return value
        if($form.ShowDialog() -ne "OK") {
            # Dispose the control
            $form.Controls[0].Dispose()
            Write-Verbose "Login cancelled"
            return $null
        }

        # Extract the needed parameters
        $forminputs=$form.Controls[0].Document.getElementsByTagName("input")

        $code = $forminputs.GetElementsByName("code")[0].GetAttribute("value")
        $session_state = $forminputs.GetElementsByName("session_state")[0].GetAttribute("value")
        $id_token = $forminputs.GetElementsByName("id_token")[0].GetAttribute("value")
        $correlation_id = $forminputs.GetElementsByName("correlation_id")[0].GetAttribute("value")
        $url=$form.Controls[0].Document.Forms[0].DomElement.action

        # Dispose the control
        $form.Controls[0].Dispose()
        
        # Create the body and get the cookie
        $body=@{
            "code" = $code
            "session_state" = $session_state    
            "id_token" = $id_token
            "correlation_id" = $correlation_id
        }
        $response = Invoke-WebRequest2 -Uri $url -Method Post -Body $body -MaximumRedirection 0 -WebSession $siteWebSession

       

        # Extract the cookies
        $cookieHeader = $response.Headers.'Set-Cookie'
        $cookieHeaderValue=""

        # Clean up the Set-Cookie header
        $cookies = $cookieHeader.Split(";,")
        foreach($cookie in $cookies) 
        {
                
            $name = $cookie.Split("=")[0].trim()
            $value = $cookie.Substring($name.Length+1)
                
            if($name -eq "rtFA" -or $name -eq "FedAuth" -or $name -eq "RpsContextCookie")
            {
                # If not empty, append the separator
                if(![String]::IsNullOrEmpty($cookieHeaderValue))
                {
                    $cookieHeaderValue+="|"
                }

                $cookieHeaderValue+="$name=$value"

            }
        }

        # Return
        return $cookieHeaderValue

    }
}

# Creates a list from xml collection
function Create-ListFromCollection
{
    [cmdletbinding()]
        Param(
            [Parameter(Mandatory=$False)]
            $Collection
        )
        Process
        {
            if($Collection -ne $null)
            {
                $list=@()
                foreach($element in $Collection.element)
                {
                    $list+=$element
                }
                return $list
            }
            else
            {
                return $null
            }
        }
}


function Get-IDCRLToken
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials
        
    )
    Process
    {
        # Get the authentication realm info
        $realmInfo = Get-UserRealmV2 -UserName $Credentials.UserName

        # Create the date strings
        $now=Get-Date
        $created = $now.ToUniversalTime().ToString("o")
        $expires = $now.AddDays(1).ToUniversalTime().ToString("o")

        # Check the realm type. If federated, we must first get the SAML token
        if($realmInfo.NameSpaceType -eq "Federated")
        {
            $url = $realmInfo.STSAuthURL

            # Create the body
            $body=@"
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wssc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
    <s:Header>
        <wsa:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand="1">$url</wsa:To>
        <wsa:MessageID>$((New-Guid).ToString())</wsa:MessageID>
        <ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="PPAuthInfo">
            <ps:HostingApp>Managed IDCRL</ps:HostingApp>
            <ps:BinaryVersion>6</ps:BinaryVersion>
            <ps:UIVersion>1</ps:UIVersion>
            <ps:Cookies></ps:Cookies>
            <ps:RequestParams>AQAAAAIAAABsYwQAAAAxMDMz</ps:RequestParams>
        </ps:AuthInfo>
        <wsse:Security>
            <wsse:UsernameToken wsu:Id="user">
                <wsse:Username>$($Credentials.UserName)</wsse:Username>
                <wsse:Password>$($Credentials.GetNetworkCredential().Password)</wsse:Password>
            </wsse:UsernameToken>
            <wsu:Timestamp Id="Timestamp">
                <wsu:Created>$created</wsu:Created>
                <wsu:Expires>$expires</wsu:Expires>
            </wsu:Timestamp>
        </wsse:Security>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id="RST0">
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
            <wsp:AppliesTo>
                <wsa:EndpointReference>
                    <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                </wsa:EndpointReference>
            </wsp:AppliesTo>
            <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
        </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>

"@
            # Invoke the command to get the SAML token
            $response=Invoke-RestMethod -UseBasicParsing -Method Post -Uri $url -Body $body -ContentType "application/soap+xml; charset=utf-8" -Headers @{"User-Agent"=""} 

            $samlToken = $response.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.InnerXml

            # Oops, got an error?
            if([string]::IsNullOrEmpty($samlToken))
            {
                if($error -eq $response.Envelope.Body.Fault.Detail.error.internalerror.text)
                {
                    Throw $error
                }
            }

            # Create the security block
            $security="$samlToken"
        }
        else
        {
            # Create the security block
            $security=@"
        <wsse:UsernameToken wsu:Id="user">
            <wsse:Username>$($Credentials.UserName)</wsse:Username>
            <wsse:Password>$($Credentials.GetNetworkCredential().Password)</wsse:Password>
        </wsse:UsernameToken>
        <wsu:Timestamp Id="Timestamp">
            <wsu:Created>$created</wsu:Created>
            <wsu:Expires>$expires</wsu:Expires>
        </wsu:Timestamp>                
"@
        }


        $url = "https://login.microsoftonline.com/rst2.srf"

        # Create the body
        $body=@"
<?xml version="1.0" encoding="UTF-8"?>
<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
    <S:Header>
    <wsa:Action S:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
    <wsa:To S:mustUnderstand="1">https://login.microsoftonline.com/rst2.srf</wsa:To>
    <ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/LiveID/SoapServices/v1" Id="PPAuthInfo">
        <ps:BinaryVersion>5</ps:BinaryVersion>
        <ps:HostingApp>Managed IDCRL</ps:HostingApp>
    </ps:AuthInfo>
    <wsse:Security>$security</wsse:Security>
    </S:Header>
    <S:Body>
    <wst:RequestSecurityToken xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" Id="RST0">
        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
        <wsp:AppliesTo>
        <wsa:EndpointReference>
            <wsa:Address>sharepoint.com</wsa:Address>
        </wsa:EndpointReference>
        </wsp:AppliesTo>
        <wsp:PolicyReference URI="MBI"></wsp:PolicyReference>
    </wst:RequestSecurityToken>
    </S:Body>
</S:Envelope>
"@
       
        
        # Invoke the command
        $response=Invoke-RestMethod -UseBasicParsing -Method Post -Uri $url -Body $body -ContentType "application/soap+xml; charset=utf-8" -Headers @{"User-Agent"=""} 

        # Extract the token
        $token = $response.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.BinarySecurityToken.'#text'

        # Ooops, got an error?
        if([string]::IsNullOrEmpty($token))
        {
            if($error -eq $response.Envelope.Body.Fault.Detail.error.internalerror.text)
            {
                Throw $error
            }
        }
        
        # Return
        return $token.Replace("&amp;","&")
    }
}

function Get-IDCRLCookie
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Token,
        [Parameter(Mandatory=$True)]
        [string]$Tenant
    )
    Process
    {
        # Set the headers
        $headers=@{
            "Authorization" =    "BPOSIDCRL $token"
            "X-IDCRL_ACCEPTED" = "t"
            "User-Agent" = ""
        }
        
        # Invoke the API
        $response=Invoke-WebRequest2 -Method Get "https://$Tenant-admin.sharepoint.com/_vti_bin/idcrl.svc/" -Headers $headers

        # Extract the IDCRL cookie
        $cookie=$response.Headers.'Set-Cookie'
        $cookie = $cookie.split(";")[0]

        # Return the cookie header
        return $cookie
    }
}


function Get-SPODigest
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$Cookie,
        [Parameter(Mandatory=$False)]
        [string]$AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$Site
    )
    Process
    {
        # Set the headers
        $headers=@{
            "X-RequestForceAuthentication" = "true"
            "X-FORMS_BASED_AUTH_ACCEPTED"= "f"
            "SOAPAction" = "http://schemas.microsoft.com/sharepoint/soap/GetUpdatedFormDigestInformation"
            "User-Agent" = ""
            "X-ClientService-ClientTag" = "TAPS (16.0.20122.0)"
        }
        
                
        $Body=@"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUpdatedFormDigestInformation xmlns="http://schemas.microsoft.com/sharepoint/soap/" />
  </soap:Body>
</soap:Envelope>
"@
        # Parse the tenant part
        $tenant = $site.Split("/")[2].Split(".")[0]

        if(![string]::IsNullOrEmpty($Cookie))
        {
            $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $webCookie = New-Object System.Net.Cookie
            $webCookie.Name = $Cookie.Split("=")[0]
            $webCookie.Value = $Cookie.Substring($webCookie.Name.Length+1)
            $webCookie.Domain = "$tenant.sharepoint.com"
            $session.Cookies.Add($webCookie)
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant.sharepoint.com/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

            # Update the headers
            $headers["Authorization"]="Bearer $AccessToken"
        }

        # Invoke the API
        $response=Invoke-WebRequest2 -Method Post "$site/_vti_bin/sites.asmx" -Headers $headers -Body $Body -WebSession $session -ContentType "text/xml; charset=utf-8"

        # Extract the Digest
        [xml]$xmlContent=$response.Content
        $digest=$xmlContent.Envelope.Body.GetUpdatedFormDigestInformationResponse.GetUpdatedFormDigestInformationResult.DigestValue
        
        # Return the digest
        return $digest
    }
}

function Get-SPOTenantSettings
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$Cookie,
        [Parameter(Mandatory=$False)]
        [string]$AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$Site
    )
    Process
    {

        
        $Body=@"
<Request AddExpandoFieldTypeSuffix="true" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" ApplicationName="SharePoint Online PowerShell (16.0.20122.0)" xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009">
	<Actions>
		<ObjectPath Id="34" ObjectPathId="33" />
		<ObjectPath Id="36" ObjectPathId="35" />
		<Query Id="37" ObjectPathId="35">
			<Query SelectAllProperties="true">
				<Properties />
			</Query>
		</Query>
	</Actions>
	<ObjectPaths>
		<Constructor Id="33" TypeId="{268004ae-ef6b-4e9b-8425-127220d84719}" />
		<Method Id="35" ParentId="33" Name="GetSitePropertiesByUrl">
			<Parameters>
				<Parameter Type="String">$Site</Parameter>
				<Parameter Type="Boolean">true</Parameter>
			</Parameters>
		</Method>
	</ObjectPaths>
</Request>
"@
        # Invoke ProcessQuery
        $response = Invoke-ProcessQuery -Cookie $Cookie -AccessToken $AccessToken -Site $site -Body $Body

        $content = ($response.content | ConvertFrom-Json)
        
        # Return
        return $content[$content.Count-1]
    }
}

# Invokes ProcessQuery
# Nov 23rd 2022
function Invoke-ProcessQuery
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$Cookie,
        [Parameter(Mandatory=$False)]
        [string]$AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$Site,
        [Parameter(Mandatory=$True)]
        [string]$Body,
        [Parameter(Mandatory=$False)]
        [string]$Digest
    )
    Process
    {
        # Get the digest if not provided
        if([String]::IsNullOrEmpty($Digest))
        {
            $Digest = Get-SPODigest -AccessToken $AccessToken -Cookie $Cookie -Site $Site
        }
        
        # Set the headers
        $headers=@{
            "X-RequestForceAuthentication" = "true"
            "X-FORMS_BASED_AUTH_ACCEPTED"= "f"
            "User-Agent" = ""
            "X-RequestDigest" = $digest
        }
        
        # Parse the tenant part
        $tenant = $site.Split("/")[2].Split(".")[0]

        if(![string]::IsNullOrEmpty($Cookie))
        {
            $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $webCookie = New-Object System.Net.Cookie
            $webCookie.Name = $Cookie.Split("=")[0]
            $webCookie.Value = $Cookie.Substring($webCookie.Name.Length+1)
            $webCookie.Domain = "$tenant.sharepoint.com"
            $session.Cookies.Add($webCookie)
        
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant.sharepoint.com/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

            # Update the headers
            $headers["Authorization"]="Bearer $AccessToken"
        }

        # Invoke the API
        $response = Invoke-WebRequest2 -Method Post "$site/_vti_bin/client.svc/ProcessQuery" -Headers $headers -Body $Body -WebSession $session -ContentType "text/xml; charset=utf-8"

        # Try to check error
        $responseJson = $response.Content | ConvertFrom-Json
        if($responseJson[0].ErrorInfo)
        {
            throw $responseJson[0].ErrorInfo.ErrorMessage
        }

        # return
        $response
    }
}

# Get migration container information
# Nov 22nd 2022
function Get-SPOMigrationContainersInfo
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$Cookie,
        [Parameter(Mandatory=$False)]
        [string]$AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$Site
    )
    Process
    {
        # Get the digest to be used with two next requests
        $digest = Get-SPODigest -AccessToken $AccessToken -Cookie $Cookie -Site $Site

        $Body=@"
<Request AddExpandoFieldTypeSuffix="true" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" ApplicationName=".NET Library" xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009">
	<Actions>
		<ObjectPath Id="2" ObjectPathId="1"/>
		<ObjectPath Id="4" ObjectPathId="3"/>
		<Method Name="ProvisionMigrationContainers" Id="5" ObjectPathId="3"/>
	</Actions>
	<ObjectPaths>
		<StaticProperty Id="1" TypeId="{3747adcd-a3c3-41b9-bfab-4a64dd2f1e0a}" Name="Current"/>
		<Property Id="3" ParentId="1" Name="Site"/>
	</ObjectPaths>
</Request>
"@
   
        # Invoke ProcessQuery to get container info
        $response = Invoke-ProcessQuery -Cookie $Cookie -AccessToken $AccessToken -Site $site -Body $Body -Digest $digest

        $content = ($response.content | ConvertFrom-Json)
        $retVal = $content[$content.Count-1]

        # Parse the encryption key
        $retVal.EncryptionKey = $retVal.EncryptionKey.Split("(")[1].Split(")")[0]

        # Body for migration queue
        $Body=@"
<Request AddExpandoFieldTypeSuffix="true" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" ApplicationName=".NET Library" xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009">
	<Actions>
		<ObjectPath Id="2" ObjectPathId="1"/>
		<ObjectPath Id="4" ObjectPathId="3"/>
		<Method Name="ProvisionMigrationQueue" Id="5" ObjectPathId="3"/>
	</Actions>
	<ObjectPaths>
		<StaticProperty Id="1" TypeId="{3747adcd-a3c3-41b9-bfab-4a64dd2f1e0a}" Name="Current"/>
		<Property Id="3" ParentId="1" Name="Site"/>
	</ObjectPaths>
</Request>
"@
   
        # Invoke ProcessQuery to get migration queue info
        $response = Invoke-ProcessQuery -Cookie $Cookie -AccessToken $AccessToken -Site $site -Body $Body -Digest $digest

        $content = ($response.content | ConvertFrom-Json)

        $retVal | Add-Member -NotePropertyName "JobQueueUri" -NotePropertyValue $content[$content.Count-1].JobQueueUri.Replace(":443","")

        # Return
        return $retVal
    }
}

# Get migration user loginname
# Nov 23rd 2022
function Get-SPOMigrationUser
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$Cookie,
        [Parameter(Mandatory=$False)]
        [string]$AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$Site,
        [Parameter(Mandatory=$True)]
        [string]$UserName
    )
    Process
    {
        $Body=@"
<Request AddExpandoFieldTypeSuffix="true" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" ApplicationName=".NET Library" xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009">
	<Actions>
		<ObjectPath Id="2" ObjectPathId="1"/>
		<ObjectPath Id="4" ObjectPathId="3"/>
		<ObjectPath Id="6" ObjectPathId="5"/>
		<Query Id="7" ObjectPathId="5">
			<Query SelectAllProperties="true">
				<Properties/>
			</Query>
		</Query>
	</Actions>
	<ObjectPaths>
		<StaticProperty Id="1" TypeId="{3747adcd-a3c3-41b9-bfab-4a64dd2f1e0a}" Name="Current"/>
		<Property Id="3" ParentId="1" Name="Web"/>
		<Method Id="5" ParentId="3" Name="EnsureUser">
			<Parameters>
				<Parameter Type="String">$UserName</Parameter>
			</Parameters>
		</Method>
	</ObjectPaths>
</Request>
"@
        
        # Invoke ProcessQuery
        try
        {
            $response = Invoke-ProcessQuery -Cookie $Cookie -AccessToken $AccessToken -Site $site -Body $Body

            $content = ($response.content | ConvertFrom-Json)
        
            $details = $content[$content.Count -1]

            $retVal = [PSCustomObject]@{
                "LoginName"         = $details.LoginName
                "Title"             = $details.Title
                "IsSiteAdmin"       = $details.IsSiteAdmin
                "NameId"            = $details.UserId.NameId
                "ObjectIdentity"    = $details._ObjectIdentity_
                "Email"             = $details.Email
                "UserPrincipalName" = $details.UserPrincipalName
            }
        }
        catch
        {
            $retVal = [PSCustomObject]@{
                "LoginName"         = $UserName
                "Title"             = ""
                "IsSiteAdmin"       = $true
                "NameId"            = $null
                "ObjectIdentity"    = ""
                "Email"             = ""
                "UserPrincipalName" = ""
            }
        }

        # NameId is null for guest users
        if([string]::IsNullOrEmpty($retVal.NameId))
        {
            $retVal.NameId = "0"
        }
        return $retVal
        
    }
}

# Gets SPOIDCRL authentication cookie for SPO web interface
# Supports only username and password! (and legacy BPOSIDCRL)
# Mar 3rd 2023
function Get-SPOIDCRL
{
<#
    .SYNOPSIS
    Gets SPOIDCRL authentication header for SharePoint Online

    .DESCRIPTION
    Gets SharePoint Identity Client Runtime librafy (SPOIDCRL) authentication header for SharePoint Online, 
    which is used for certain SPO APIs, such as /_vti_bin/webpartpages.asmx

    .Parameter Site
    Url of the SharePoint Online site (domain part will do)

    .Parameter UserName
    User's name

    .Parameter Password
    User's password

    .Parameter Credential
    User's credentials in PSCredential object

    .Parameter BPOSIDCRL
    User's BPOSIDCRL cookie
    
    .Example
    PS C:\>$cred = Get-Credential
    PS C:\>Get-AADIntSPOIDCRL -Site "https://company.sharepoint.com/" -Credentials $cred

    77u/PD94bWwgdmVyc2l[redacted]nM2RTJQUFpKSVZXSElKNDgvaTNFVHp4NVlpemdVT2lSUDdQL0JCV1k1NVhHQT09PC9TUD4=
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site,
        [Parameter(ParameterSetName='Credentials',Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='UserNameAndPassword',Mandatory=$True)]
        [String]$UserName,
        [Parameter(ParameterSetName='UserNameAndPassword',Mandatory=$False)]
        [String]$Password,
        [Parameter(ParameterSetName='BPOSIDCRL',Mandatory=$True)]
        [String]$BPOSIDCRL
    )
    Process
    {
        $siteDomain=$Site.Split("/")[2]
        
        # Did we got BPOSIDCRL token?
        if([string]::IsNullOrEmpty($BPOSIDCRL))
        {
            # We didn't. How about user name?
            If([String]::IsNullOrEmpty($UserName))
            {
                # Nope, so parse from credential object
                $UserName = $Credentials.UserName
                $Password = $Credentials.GetNetworkCredential().password
            }
            # Get the BPOSIDCRL token
            $BPOSIDCRL = Get-RSTToken -Url "https://login.microsoftonline.com/RST2.srf" -EndpointAddress "sharepoint.com" -UserName $UserName -Password $Password
        }



        $headers=@{
            "Authorization" = "BPOSIDCRL $BPOSIDCRL"
        }

        # Get the SPOIDCRL cookie
        $response = Invoke-WebRequest2 -uri "https://$siteDomain/_vti_bin/idcrl.svc/" -Headers $headers
        
        $cookies = $response.Headers.'Set-Cookie'.Split(";")
        $SPOIDCRL = $cookies[0].Substring(9)

        # Return
        return $SPOIDCRL
    }
}