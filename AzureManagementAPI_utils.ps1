

# Creates a web session with given cookie header
function Create-WebSession
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$SetCookieHeader,
        [Parameter(Mandatory=$True)]
        [string]$Domain
    )
    Process 
    {
        
        
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

        # login.live.com: MSPRequ=lt=1540361812&co=1&id=N; secure= ;path=/;HTTPOnly=;version=1,uaid=bf4b7f37ec1d4084aa68952b9edebb6b; domain=login.live.com;secure= ;path=/;HTTPOnly= ;version=1,MSPOK=$uuid-f4f5ef25-7343-4de8-84cb-266ea1b47bc2; domain=login.live.com;secure= ;path=/;HTTPOnly= ;version=1
        if($domain -eq "login.live.com")
        {
            $SetCookie = $SetCookieHeader.Split(";,")
            foreach($Cookie in $SetCookie) 
            {
                $name = $Cookie.Split("=")[0].trim()
                $value = $Cookie.Substring($name.Length+1)
                switch($name)
                {
                    "secure" {}
                    "path" {}
                    "HTTPOnly" {}
                    "domain" {}
                    "version" {}
                    default 
                    {
                        $webCookie = New-Object System.Net.Cookie
                        $webCookie.Name = $name
                        $webCookie.Value = $value
                        $webCookie.Domain = $Domain
                        $session.Cookies.Add($webCookie)
                        Write-Verbose "COOKIE [$Domain]: $webCookie"
                    }
                }
            }
            
        }
        elseif($domain.EndsWith(".sharepoint.com")) # Sharepoint
        {
            $SetCookie = $SetCookieHeader.Replace("HttpOnly","|").Split("|")
            foreach($Cookie in $SetCookie) 
            {
                if(![String]::IsNullOrEmpty($Cookie))
                {
                    $Cookie = $Cookie.Split(";")[0].trim()
                    $name = $Cookie.Split("=")[0].trim()
                    $value = $Cookie.Substring($name.Length+1)

                    # Strip the trailing semi colon
                    $value=$value.Split(";")[0]
                
                    $webCookie = New-Object System.Net.Cookie
                    $webCookie.Name = $name
                    $webCookie.Value = $value
                    $webCookie.Domain = $Domain
                    $session.Cookies.Add($webCookie)
                    Write-Verbose "COOKIE [$Domain]: $webCookie"
                }
            }
        }
        else # login.microsoftonline.com: 
        {
            # Split the cookie string
            $SetCookie = $SetCookieHeader.Replace("HttpOnly","|").Split("|")
            foreach($Cookie in $SetCookie) 
            {
                # Split the individual cookie and remove possible trailing comma
                $Cookie=($Cookie.Split(";")[0]).Replace(',','')
                if(![string]::IsNullOrEmpty($Cookie))
                {
                    $webCookie = New-Object System.Net.Cookie
                    $webCookie.Name = $Cookie.Split("=")[0]
                    $webCookie.Value = $Cookie.Substring($webCookie.Name.Length+1)
                    $webCookie.Domain = $Domain
                    $session.Cookies.Add($webCookie)
                    Write-Verbose "COOKIE [$Domain]: $webCookie"
                }
            
            }
        }
        return $session
    }
}

# Creates a web session with given cookie header
function Create-WebSession2
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Security.]$Headers,
        [Parameter(Mandatory=$True)]
        [string]$Domain
    )
    Process
    {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

        # Split the cookie string
        $SetCookie = $SetCookieHeader
        $SetCookie = $SetCookie.Replace("HttpOnly","|").Replace("HTTPOnly","|").Split("|")
        foreach($Cookie in $SetCookie) 
        {
            # Split the individual cookie and remove possible trailing comma
            $Cookie=($Cookie.Split(";")[0]).Replace(',','')
            if(![string]::IsNullOrEmpty($Cookie))
            {
                $webCookie = New-Object System.Net.Cookie
                $webCookie.Name = $Cookie.Split("=")[0]
                $webCookie.Value = $Cookie.Split("=")[1]
                $webCookie.Domain = $Domain
                $session.Cookies.Add($webCookie)
            }
            
        }
        return $session
    }
}

# Gets the access token for Azure Management API
# Uses totally different flow than other access tokens.
# Oct 23rd 2018
# TODO: Add support for form based & SAML authentication
function Get-AccessTokenForAzureMgmtAPI
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Azure Management API

    .DESCRIPTION
    Gets OAuth Access Token for Azure Management API

    .Parameter Credentials
    Credentials of the user.
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForAzureMgmtAPI -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter()]
        [Switch]$SaveToCache
    )
    Process
    {
        $accessToken=""
        $refreshToken=""
        # Check if we got credentials
        if([string]::IsNullOrEmpty($Credentials) -and [string]::IsNullOrEmpty($SAMLToken))
        {
            # No credentials given, so prompt for credentials
            $tokens = Prompt-AzureADCredentials

            $accessToken = $tokens["access_token"]
            $refreshToken = $tokens["refresh_token"]
        }
        else
        {
            $userName = $Credentials.UserName
            $password = $credentials.GetNetworkCredential().Password

            # Step 1: Go to portal.azure.com to get cookies and authentication url
            $headers=@{
                "Sec-Fetch-Dest" = "script"
                "Sec-Fetch-Site" = "same-origin"
                "Sec-Fetch-Mode" = "no-cors"
                "Referer"="https://portal.azure.com"

            }
            $response = Invoke-WebRequest -UseBasicParsing -uri "https://portal.azure.com/signin/idpRedirect.js/?feature.settingsportalinstance=&feature.refreshtokenbinding=true&feature.usemsallogin=true&feature.snivalidation=true&feature.setsamesitecookieattribute=true&feature.argsubscriptions=&feature.showservicehealthalerts=&idpRedirectCount=0" -Headers $headers
            $html=$response.Content
            $s=$html.IndexOf('https://login.microsoftonline.com')
            $e=$html.IndexOf('"',$s)
            $url=$html.Substring($s,$e-$s)
            $azureWebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "portal.azure.com"

            # Step 2: Go to login.microsoftonline.com to get configuration and cookies
            $response = Invoke-WebRequest -UseBasicParsing -uri $url -Headers @{Cookie="x-ms-gateway-slice=004; stsservicecookie=ests; AADSSO=NANoExtension; SSOCOOKIEPULLED=1"}
            $html = $response.Content

            $s=$html.IndexOf('$Config=')
            $e=$html.IndexOf('};',$s+8)
            $config=$html.Substring($s+8,$e-$s-7) | ConvertFrom-Json
            $MSOnlineComwebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "login.microsoftonline.com"

            # Step3: Get user information, including Flow Token
            $userInfo=Get-CredentialType -UserName $userName -FlowToken $config.sFT

            # LOGIN.LIVE.COM
            if($userInfo.EstsProperties.DomainType -eq 2) # =live account
            {
                # Step L1: Go to login.live.com to get configuration and cookies
                $response = Invoke-WebRequest -UseBasicParsing -uri $config.urlGoToAADError
                $html = $response.Content

                $s=$html.IndexOf('ServerData =')
                $e=$html.IndexOf('};',$s+13)
                $config=$html.Substring($s+13,$e-$s-12) 
            
                # ConvertFrom-Json is caseinsensitive so need to use this one
                $config = (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($config)

                $liveWebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "login.live.com"

                $sFTTag= [xml]$config.sFTTag
                $PPFT = $sFTTag.SelectSingleNode("//input[@name='PPFT']").value
            

                # Step L2: Login to login.live.com
                $body=@{
                    "login" = $userName
                    "loginFmt" = $userName
                    "i13"="0"
                    "type"="11"
                    "LoginOptions"="3"
                    "passwd"=$password
                    "ps"="2"
                    "canary"=""
                    "ctx"=""
                    "NewUser"="1"
                    "fspost"="0"
                    "i21"="0"
                    "CookieDisclosure"="1"
                    "IsFidoSupported"="1"
                    "hpgrequestid"=""
                    "PPSX"="Pa"
                    "PPFT"=$PPFT
                    "i18"="__ConvergedLoginPaginatedStrings|1,__OldConvergedLogin_PCore|1,"
                    "i2"="1"
                    }
                $headers=@{
                    "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                    "Upgrade-Insecure-Requests" = "1"

                }

                $response = Invoke-WebRequest -UseBasicParsing -Uri $config.urlPost -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $headers -WebSession $liveWebSession
                $html = $response.Content

                # No well formed xml, so need to do some tricks.. First, find the form start and end tags
                $s=$html.IndexOf("<form")
                $e=$html.IndexOf("</form>")
                $form = $html.Substring($s,$e-$s) # Strip the form end tag
                # End all tags
                $form=$form.replace('">','"/>')
                # Add start and end tags
                $form="<html>$form</html>"

                $html=[xml]$form

                $fmHF = $html.SelectSingleNode("//form[@name='fmHF']").action
                $code = $html.SelectSingleNode("//input[@name='code']").value
                $state = $html.SelectSingleNode("//input[@name='state']").value


                # Step L3: Login to login.microsoftonline.com with code and state
                $body = @{
                    "code" = $code
                    "state" = $state
                }
                $response = Invoke-WebRequest -UseBasicParsing -Uri $fmHF -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $headers -WebSession $MSOnlineComwebSession
                $MSOnlineComwebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "login.microsoftonline.com"
                $html = $response.Content
                $s=$html.IndexOf('$Config=')
                $e=$html.IndexOf('};',$s+8)
                $config=$html.Substring($s+8,$e-$s-7) | ConvertFrom-Json
            

                # Step L4: Get code, id_token, and state information
                $body=@{
                    "LoginOptions"="0"
                    "flowToken"=$config.sFT
                    "canary"=$config.canary
                    "ctx"=$config.sCtx
                    "hpgrequestid"=(New-Guid).ToString()
                }
                $response = Invoke-WebRequest -UseBasicParsing -Uri "https://login.microsoftonline.com/kmsi" -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $headers -WebSession $MSOnlineComwebSession
                $MSOnlineComwebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "login.microsoftonline.com"
                $html = [xml]$response.Content
                $code = $html.SelectSingleNode("//input[@name='code']").value
                $id_token = $html.SelectSingleNode("//input[@name='id_token']").value
                $state = $html.SelectSingleNode("//input[@name='state']").value
                $session_state = $html.SelectSingleNode("//input[@name='session_state']").value

                # Step L5: Sign in to portal.azure.com to get redirect URL
                $body=@{
                    "code"= $code
                    "id_token" = $id_token
                    "state" = $state
                    "session_state" = $session_state
                }
                $response = Invoke-WebRequest -UseBasicParsing -Uri "https://portal.azure.com/signin/index/" -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $headers -WebSession $azureWebSession
                $azureWebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "portal.azure.com"
                $html=$response.Content
                $s=$html.IndexOf('MsPortalImpl.redirectToUri("')
                $e=$html.IndexOf('")',$s)
                $url=$html.Substring($s+28,$e-$s-28) 

                # Step L6: Go to portal.azure.com to get another redirect URL
                $response = Invoke-WebRequest -UseBasicParsing -Uri $url -Method Get -Headers $headers -WebSession $azureWebSession
                $azureWebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "portal.azure.com"
                $html=$response.Content
                $s=$html.IndexOf('https://login.microsoftonline.com')
                $e=$html.IndexOf('"',$s)
                $url=$html.Substring($s,$e-$s)# |ConvertFrom-Json

                # Step L7: Login to login.microsoftonline.com (again) using the received url to get code etc.
                $response = Invoke-WebRequest -UseBasicParsing -Uri $url -Method Get -ContentType "application/x-www-form-urlencoded" -Headers $headers -WebSession $MSOnlineComwebSession
                $MSOnlineComwebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "login.microsoftonline.com"
                $html = [xml]$response.Content
                $code = $html.SelectSingleNode("//input[@name='code']").value
                $id_token = $html.SelectSingleNode("//input[@name='id_token']").value
                $state = $html.SelectSingleNode("//input[@name='state']").value
                $session_state = $html.SelectSingleNode("//input[@name='session_state']").value
                $url = $html.SelectSingleNode("//form[@name='hiddenform']").action

                # Step L8: Sign in to portal.azure.com to get OAuth token
                $body=@{
                    "code"= $code
                    "id_token" = $id_token
                    "state" = $state
                    "session_state" = $session_state
                }
                $response = Invoke-WebRequest -UseBasicParsing -Uri $url -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $headers -WebSession $azureWebSession
                $azureWebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "portal.azure.com"
            
            }
            else # LOGIN.MICROSOFTONLINE.COM
            {

                # Step M1: Login to login.microsoftonline.com
                $body=@{
                    "login" = $userName
                    "loginFmt" = $userName
                    "i13"="0"
                    "type"="11"
                    "LoginOptions"="3"
                    "passwd"=$password
                    "ps"="2"
                    "flowToken"=$userInfo.FlowToken
                    "canary"=$config.canary
                    "ctx"=$config.sCtx
                    "NewUser"="1"
                    "fspost"="0"
                    "i21"="0"
                    "CookieDisclosure"="1"
                    "IsFidoSupported"="1"
                    "hpgrequestid"=(New-Guid).ToString()
                }
                $headers=@{
                    "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                    "Upgrade-Insecure-Requests" = "1"

                }
                $response = Invoke-WebRequest -UseBasicParsing -Uri "https://login.microsoftonline.com/common/login" -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $headers -WebSession $MSOnlineComwebSession
                $MSOnlineComwebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "login.microsoftonline.com"
                $html = $response.Content
                $s=$html.IndexOf('$Config=')
                $e=$html.IndexOf('};',$s+8)
                $config=$html.Substring($s+8,$e-$s-7) | ConvertFrom-Json
                $MSOnlineComwebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "login.microsoftonline.com"

                # Step M2: Get code, id_token, and state information
                $body=@{
                    "LoginOptions"="0"
                    "flowToken"=$config.sFT
                    "canary"=$config.canary
                    "ctx"=$config.sCtx
                    "hpgrequestid"=(New-Guid).ToString()
                }
                $response = Invoke-WebRequest -UseBasicParsing -Uri "https://login.microsoftonline.com/kmsi" -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $headers -WebSession $MSOnlineComwebSession
                $MSOnlineComwebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain "login.microsoftonline.com"
                $html = [xml]$response.Content
                $code = $html.SelectSingleNode("//input[@name='code']").value
                $id_token = $html.SelectSingleNode("//input[@name='id_token']").value
                $state = $html.SelectSingleNode("//input[@name='state']").value
                $session_state = $html.SelectSingleNode("//input[@name='session_state']").value

                # Step M3: Sign in to portal.azure.com
                $body=@{
                    "code"= $code
                    "id_token" = $id_token
                    "state" = $state
                    "session_state" = $session_state
                }
                $response = Invoke-WebRequest -UseBasicParsing -Uri "https://portal.azure.com/signin/index/" -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $headers -WebSession $azureWebSession
            }

            # Get the OAuth token
            $html=$response.Content

            $s=$html.IndexOf('{"oAuthToken":')
            $e=$html.IndexOf('}}',$s)
            $token=$html.Substring($s,$e-$s+2) |ConvertFrom-Json

            # Return
            $accessToken = $token.oAuthToken.authHeader.Split(" ")[1]
            $refreshToken = $token.oAuthToken.refreshToken

        }

        # Save the tokens to cache
        if($SaveToCache)
        {
            Write-Verbose "ACCESS TOKEN: SAVE TO CACHE"
            $Script:tokens["$ClientId-https://graph.windows.net"] =         $accessToken
            $Script:refresh_tokens["$ClientId-https://graph.windows.net"] = $refreshToken
        }
        else # Return
        {
            return $accessToken
        }
    }
}

# Obsolete since Nov 11th 2020
# Gets the access token for Azure AD IAM API
# Oct 24th 2018
# TODO: Add support for form based & SAML authentication
function Get-AccessTokenForAADIAMAPI2
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Azure AD IAM API

    .DESCRIPTION
    Gets OAuth Access Token for Azure AD IAM API

    .Parameter Credentials
    Credentials of the user.
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForAADIAMAPI -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credentials
    )
    Process
    {
        $AADAuth = Get-AccessTokenForAzureMgmtAPI -Credentials $Credentials -ExportTokenObject
        $token = Get-DelegationToken -ExtensionName Microsoft_AAD_IAM -AccessToken $AADAuth
        return $token.authHeader.Split(" ")[1]
    }
}

# Get delegation token for the given extension
function Get-DelegationToken
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet('Microsoft_AAD_IAM')]
        [String]$ExtensionName,
        [Parameter(Mandatory=$False)]
        $ResourceName="self",
        [Parameter(Mandatory=$True)]
        $AccessToken
    )
    Process
    {
        # Check the expiration
        if(Is-AccessTokenExpired($AccessToken.access_token))
        {
            throw "AccessToken has expired"
        }


        $Headers=@{
            "x-ms-client-request-id" = (New-Guid).ToString()
            "x-ms-extension-flags" ='{"feature.advisornotificationdays":"30","feature.advisornotificationpercent":"100","feature.armtenants":"true","feature.artbrowse":"true","feature.azureconsole":"true","feature.checksdkversion":"true","feature.contactinfo":"true","feature.dashboardfilters":"false","feature.enableappinsightsmetricsblade":"true","feature.globalsearch":"true","feature.guidedtour":"true","feature.helpcontentenabled":"true","feature.helpcontentwhatsnewenabled":"true","feature.internalonly":"false","feature.irissurfacename":"AzurePortal_Notifications_PROD","feature.mergecoadmins":"true","feature.metricsv2ga":"true","feature.newsubsapi":"true","feature.npsintervaldays":"90","feature.npspercent":"3.0","feature.npsshowportaluri":"true","feature.sessionvalidity":"true","feature.searchnocache":"true","feature.subscreditcheck":"true","hubsextension_parameterseditor":"true","hubsextension_showpolicyhub":"true","feature.autosettings":"true","feature.azurehealth":"true","feature.blockbladeredirect":"Microsoft_Azure_Resources","feature.browsecuration":"default","feature.collapseblade":"true","feature.dashboardfiltersaddbutton":"false","feature.decouplesubs":"true","feature.disablebladecustomization":"true","feature.disabledextensionredirects":"","feature.enablee2emonitoring":"true","feature.enablemonitoringgroup":"true","feature.enableworkbooks":"true","feature.feedback":"true","feature.feedbackwithsupport":"true","feature.fullwidth":"true","feature.managevminbrowse":"true","feature.mgsubs":"true","feature.newautoscale":"true","feature.newtageditorblade":"true","feature.nps":"true","feature.pinnable_default_off":"true","feature.reservationsinbrowse":"true","feature.reservehozscroll":"true","feature.resourcehealth":"true","feature.seetemplate":"true","feature.showdecoupleinfobox":"true","feature.tokencaching":"true","feature.usealertsv2blade":"true","feature.usemdmforsql":"true","feature.usesimpleavatarmenu":"true","hubsextension_budgets":"true","hubsextension_costalerts":"false","hubsextension_costanalysis":"true","hubsextension_costrecommendations":"true","hubsextension_eventgrid":"true","hubsextension_isinsightsextensionavailable":"true","hubsextension_islogsbladeavailable":"true","hubsextension_isomsextensionavailable":"true","hubsextension_savetotemplatehub":"true","hubsextension_servicenotificationsblade":"true","hubsextension_showservicehealthevents":"true","microsoft_azure_marketplace_itemhidekey":"Citrix_XenDesktop_EssentialsHidden,Citrix_XenApp_EssentialsHidden,AzureProject"}'
            "x-ms-version" = "5.0.302.5601 (production#c19533145d.181011-0133) Signed"
            "X-Requested-With" = "XMLHttpRequest"
            "Referer" = "https://portal.azure.com/"
            "x-ms-client-session-id" = $Script:AADSessionId
            "Origin" = "https://portal.azure.com"
            "x-ms-effective-locale"="en.en-us"
            "Accept-Language" = "en"
            "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            "Cookie" ="browserId=6d84502d-b03c-433c-acec-d87e20449090"
        }

        $Body=@{
            "extensionName" = $ExtensionName
            "portalAuthorization" = $AccessToken.refresh_token
            "resourceName" = $ResourceName
            "tenant" = Get-TenantId -AccessToken $AccessToken.access_token
        }
        # Call the API
        $response = Invoke-RestMethod -Uri "https://portal.azure.com/api/DelegationToken?feature.tokencaching=true" -ContentType "application/json" -Method POST -Body ($Body | ConvertTo-Json) #-Headers $Headers -WebSession $Script:azureWebSession

        # Return
        $response.value
    }
}

# Calls the Azure AD IAM API
function Call-AzureAADIAMAPI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $Body,
        [Parameter(Mandatory=$True)]
        $AccessToken,
        [Parameter(Mandatory=$True)]
        $Command,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Put','Get','Post','Delete')]
        [String]$Method="Get",
        [Parameter(Mandatory=$False)]
        [String]$Version = "2.0"
    )
    Process
    {
        # Check the expiration
        if(Is-AccessTokenExpired($AccessToken))
        {
            throw "AccessToken has expired"
        }

        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "X-Requested-With" = "XMLHttpRequest"
            "x-ms-client-request-id" = (New-Guid).ToString()
        }
        # Call the API
        $response = Invoke-RestMethod -Uri "https://main.iam.ad.ext.azure.com/api/$command`?api-version=$Version" -ContentType "application/json; charset=utf-8" -Headers $headers -Method $Method -Body ($Body | ConvertTo-Json -Depth 5)

        # Return
        if($response.StatusCode -eq $null)
        {
            return $response
        }
    }
}

# Calls the Azure Management API
# Jul 11th 2019
function Call-AzureManagementAPI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $Body,
        [Parameter(Mandatory=$True)]
        $AccessToken,
        [Parameter(Mandatory=$True)]
        $Command
    )
    Process
    {
        # Check the expiration
        if(Is-AccessTokenExpired($AccessToken))
        {
            throw "AccessToken has expired"
        }

        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "X-Requested-With" = "XMLHttpRequest"
            "x-ms-client-request-id" = (New-Guid).ToString()
        }
        # Call the API
        $response=Invoke-RestMethod -Uri "https://portal.azure.com/api/$command" -Method Post -Headers $headers
    
        # Return
        return $response
       
    }
}



# Prompts for credentials and gets the access token
# Supports MFA, federation, etc.
# Jul 11th 2019
function Prompt-AzureADCredentials
{
    [cmdletbinding()]
    Param(
    )
    Process
    {
        # Set variables
        $auth_redirect="https://portal.azure.com/signin/index/"
        $url="https://portal.azure.com/"

        # Create the form
        $form = Create-LoginForm -Url $url -auth_redirect $auth_redirect

        # Show the form and wait for the return value
        if($form.ShowDialog() -ne "OK") {
            # Dispose the control
            $form.Controls[0].Dispose()
            Write-Verbose "Login cancelled"
            return $null
        }

        # Dispose the control
        $form.Controls[0].Dispose()

        # Get the access token from script scope variable
        $accessToken = $script:accessToken
        $script:accessToken = $null

        # Return
        $accessToken
    }
}
