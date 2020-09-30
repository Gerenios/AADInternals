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
        if($Site.EndsWith("/"))
        {
            $Site=$Site.Substring(0,$Site.Length-1)
        }

        $siteDomain=$Site.Split("/")[2]
        
        $headers=@{
                "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                "Upgrade-Insecure-Requests" = "1"
                "Accept-Encoding" = "gzip, deflate, br"
                "Accept-Language" = "en-US,en;q=0.9"
                "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"

        }

        # Step 1: Go to the requested site
        $response = Invoke-WebRequest -UseBasicParsing -uri $Site -MaximumRedirection 0 -ErrorAction SilentlyContinue
        
        # Step 2: Go to "/_layouts/15/Authenticate.aspx?Source=%2F"
        $url = $response.Headers.'Location'
        $response = Invoke-WebRequest -UseBasicParsing -uri $url -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $siteWebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain $siteDomain

        # Step 3: Go to "/_forms/default.aspx?ReturnUrl=%2f_layouts%2f15%2fAuthenticate.aspx%3fSource%3d%252F&Source=cookie"
        $html=$response.Content
        $s=$html.IndexOf('href="')+6
        $e=$html.IndexOf('"',$s)
        $url=$html.Substring($s,$e-$s)
        $url="https://$siteDomain/$url"
        $response = Invoke-WebRequest -UseBasicParsing -uri $url -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $siteWebSession

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
        $htmlform=$form.Controls[0].Document.Forms[0].InnerHtml
        $htmlform=$htmlform.Replace('">','"/>')
        [xml]$xmlform="<html>$htmlform</html>"

        $code = $xmlform.SelectSingleNode("//input[@name='code']").value
        $session_state = $xmlform.SelectSingleNode("//input[@name='session_state']").value
        $id_token = $xmlform.SelectSingleNode("//input[@name='id_token']").value
        $correlation_id = $xmlform.SelectSingleNode("//input[@name='correlation_id']").value
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
        $response = Invoke-WebRequest -UseBasicParsing -Uri $url -Method Post -Body $body -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $siteWebSession

       

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
        [xml]$realmInfo = Get-UserRealmV2 -UserName $Credentials.UserName -SPO

        # Create the date strings
        $now=Get-Date
        $created = $now.ToUniversalTime().ToString("o")
        $expires = $now.AddDays(1).ToUniversalTime().ToString("o")

        # Check the realm type. If federated, we must first get the SAML token
        if($realmInfo.RealmInfo.NameSpaceType -eq "Federated")
        {
            $url = $realmInfo.RealmInfo.STSAuthURL

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
            $response=Invoke-RestMethod -Method Post -Uri $url -Body $body -ContentType "application/soap+xml; charset=utf-8" -Headers @{"User-Agent"=""} 

            $samlToken = $response.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.InnerXml

            # Oops, got an error?
            if([string]::IsNullOrEmpty($samlToken))
            {
                if($error=$response.Envelope.Body.Fault.Detail.error.internalerror.text)
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
        $response=Invoke-RestMethod -Method Post -Uri $url -Body $body -ContentType "application/soap+xml; charset=utf-8" -Headers @{"User-Agent"=""} 

        # Extract the token
        $token = $response.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.BinarySecurityToken.'#text'

        # Ooops, got an error?
        if([string]::IsNullOrEmpty($token))
        {
            if($error=$response.Envelope.Body.Fault.Detail.error.internalerror.text)
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
        $response=Invoke-WebRequest -UseBasicParsing -Method Get "https://$Tenant-admin.sharepoint.com/_vti_bin/idcrl.svc/" -Headers $headers

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
            "Content-Type" = "text/xml"
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
            $webCookie.Domain = "$tenant-admin.sharepoint.com"
            $session.Cookies.Add($webCookie)
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant.sharepoint.com/" -ClientId "9bc3ab49-b65d-410a-85ad-de819febfddc"

            # Update the headers
            $headers["Authorization"]="Bearer $AccessToken"
        }

        # Invoke the API
        $response=Invoke-WebRequest -UseBasicParsing -Method Post "https://$tenant.sharepoint.com/_vti_bin/sites.asmx" -Headers $headers -Body $Body -WebSession $session

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
        # Get the digest
        $digest = Get-SPODigest -AccessToken $AccessToken -Cookie $Cookie -Site $Site
        # Set the headers
        $headers=@{
            "Content-Type" = "text/xml"
            "X-RequestForceAuthentication" = "true"
            "X-FORMS_BASED_AUTH_ACCEPTED"= "f"
            "User-Agent" = ""
            "X-RequestDigest" = $digest
        }
        
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
        # Parse the tenant part
        $tenant = $site.Split("/")[2].Split(".")[0]

        if(![string]::IsNullOrEmpty($Cookie))
        {
            $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $webCookie = New-Object System.Net.Cookie
            $webCookie.Name = $Cookie.Split("=")[0]
            $webCookie.Value = $Cookie.Substring($webCookie.Name.Length+1)
            $webCookie.Domain = "$tenant-admin.sharepoint.com"
            $session.Cookies.Add($webCookie)
        
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant.sharepoint.com/" -ClientId "9bc3ab49-b65d-410a-85ad-de819febfddc"

            # Update the headers
            $headers["Authorization"]="Bearer $AccessToken"
        }

        # Invoke the API
        $response=Invoke-WebRequest -UseBasicParsing -Method Post "https://$tenant.sharepoint.com/_vti_bin/client.svc/ProcessQuery" -Headers $headers -Body $Body -WebSession $session

        $content = ($response.content | ConvertFrom-Json)
        
        # Return
        return $content[$content.Count-1]
    }
}