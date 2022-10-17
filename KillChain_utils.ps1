# Checks whether the domain has MX records pointing to MS cloud
# Jun 16th 2020
# Aug 30th 2022: Fixed by maxgrim
function HasCloudMX
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        $results=Resolve-DnsName -Name $Domain -Type MX -DnsOnly -NoHostsFile -NoIdn -ErrorAction SilentlyContinue | select nameexchange | select -ExpandProperty nameexchange
        $filteredResults=$results -like "*.mail.protection.outlook.com"

        return ($filteredResults -eq $true) -and ($filteredResults.Count -gt 0)
    }
}

# Checks whether the domain has SPF records allowing sending from cloud
# Jun 16th 2020
function HasCloudSPF
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        $results=Resolve-DnsName -Name $Domain -Type txt -DnsOnly -NoHostsFile -NoIdn -ErrorAction SilentlyContinue | select strings | select -ExpandProperty strings 

        return ($results -like "*include:spf.protection.outlook.com*").Count -gt 0
    }
}

# Checks whether the domain has SPF records allowing sending from cloud
# Sep 23rd 2020
function HasDMARC
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        try
        {
            $results=Resolve-DnsName -Name "_dmarc.$Domain" -Type txt -DnsOnly -NoHostsFile -NoIdn -ErrorAction SilentlyContinue | select strings | select -ExpandProperty strings 
        }catch{}

        return ($results -like "v=DMARC1*").Count -gt 0
    }
}

# Checks whether the domain has DesktopSSO enabled
# Jun 16th 2020
function HasDesktopSSO
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        (Get-CredentialType -UserName "nn@$domain").EstsProperties.DesktopSsoEnabled -eq "True"
    }
}

# Checks whether the domain has CBA enabled
# Jun 17th 2022
function HasCBA
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$UserName
    )
    Process
    {
        (Get-CredentialType -UserName $UserName).Credentials.HasCertAuth -eq "True"
    }
}



# Checks whether the user exists in Azure AD or not
# Jun 16th 2020
function DoesUserExists
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$User,
        [Parameter(Mandatory=$False)]
        [ValidateSet("Normal","Login","Autologon")]
        [String]$Method="Normal"
    )
    Process
    {
        $exists = $false 

        if($Method -eq "Normal")
        {
            # Get the credential type information
            $credType=Get-CredentialType -UserName $User 

            # Works only if desktop sso (aka. Seamless SSO) is enabled
            # Since August 2021 this seems to work for all tenants!
            #if($credType.EstsProperties.DesktopSsoEnabled -eq "True")
            #{
                # Return empty if throttling
                if($credType.ThrottleStatus -eq 1)
                {
                    Write-Warning "Requests throttled!"
                    Remove-Variable exists
                }
                else
                {
                    $exists = $credType.IfExistsResult -eq 0 -or $credType.IfExistsResult -eq 6
                }
            #}
            #else
            #{
            #    Remove-Variable exists
            #}
        }
        else
        {
            if($Method -eq "Login")
            {
                # Try to log in as the user
                $randomGuid = New-Guid
                $body = @{
                    "resource"=$randomGuid
                    "client_id"=$randomGuid
                    "grant_type"="password"
                    "username"=$User
                    "password"="none"
                    "scope"="openid"
                }

                try
                {
                    $jsonResponse=Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Method POST -Body $body -Headers $headers
                    $exists = $True # May be should change password..?
                }
                catch
                {
                    $errorDetails = ($_.ErrorDetails.Message | convertfrom-json).error_description
                }
            }
            elseif($Method -eq "Autologon")
            {
                $requestId = (New-Guid).ToString()

                $domain = $User.Split("@")[1]
                $password = "none"

                $now = Get-Date
                $created = $now.toUniversalTime().toString("o")
                $expires = $now.addMinutes(10).toUniversalTime().toString("o")

                $url = "https://autologon.microsoftazuread-sso.com/$domain/winauth/trust/2005/usernamemixed?client-request-id=$requestid"
              
                $body=@"
<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>$url</wsa:To>
        <wsa:MessageID>urn:uuid:$((New-Guid).ToString())</wsa:MessageID>
        <wsse:Security s:mustUnderstand="1">
            <wsu:Timestamp wsu:Id="_0">
                <wsu:Created>$created</wsu:Created>
                <wsu:Expires>$expires</wsu:Expires>
            </wsu:Timestamp>
            <wsse:UsernameToken wsu:Id="uuid-$((New-Guid).toString())">
                <wsse:Username>$User</wsse:Username>
                <wsse:Password>$Password</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id='RST0'>
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
                $exists = $false

                try
                {
                    $response = Invoke-RestMethod -UseBasicParsing -Uri $url -Method Post -Body $body -ErrorAction SilentlyContinue
                    $exists = $true # Very bad password
                }
                catch
                {
                    $stream = $_.Exception.Response.GetResponseStream()
                    $responseBytes = New-Object byte[] $stream.Length

                    $stream.Position = 0
                    $stream.Read($responseBytes,0,$stream.Length) | Out-Null
            
                    $responseXml = [xml][text.encoding]::UTF8.GetString($responseBytes)

                    $errorDetails = $responseXml.Envelope.Body.Fault.Detail.error.internalerror.text
                }
            }

            # Parse the error code. Only AADSTS50034 would need to be checked but good to know other errors too.
            if(!$exists -and $errorDetails)
            {
                if($errorDetails.startsWith("AADSTS50053")) # The account is locked, you've tried to sign in too many times with an incorrect user ID or password.
                {
                    $exists = $True
                }
                elseif($errorDetails.StartsWith("AADSTS50126")) # Error validating credentials due to invalid username or password.
                {
                    $exists = $True
                }
                elseif($errorDetails.StartsWith("AADSTS50076")) # Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access '{resource}'
                {
                    $exists = $True
                }
                elseif($errorDetails.StartsWith("AADSTS700016")) # Application with identifier '{appIdentifier}' was not found in the directory '{tenantName}'. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant. You may have sent your authentication request to the wrong tenant.
                {
                    $exists = $True
                }
                elseif($errorDetails.StartsWith("AADSTS50034")) # The user account {identifier} does not exist in the {tenant} directory. To sign into this application, the account must be added to the directory.
                {
                    $exists = $False
                }
                else
                {
                    Remove-Variable exists
                }
            }
        }

        return $exists
    }
}
