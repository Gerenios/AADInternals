       
# Get's tokens using CBA
# May 24th 2022
function Get-AdminPortalAccessTokenUsingCBA
{
<#
    .SYNOPSIS
    Gets Access Tokens using CBA

    .DESCRIPTION
    Gets Access Tokens using Certificate Based Authentication (CBA). Returns tokens for Portal and Business Store.
    Assumes that CN of the given certificate contains upn with domain name.

    .Parameter PfxFileName
    Name of the certificate file to be used

    .Parameter PfxPassword
    Password of the certificate file to be used

    .Example
    Get-AADIntAccessTokenForAADGraph
    
    .Example
    PS C:\>$tokens = Get-AADIntAdminPortalAccessTokenUsingCBA -PfxFileName .\my_cert.pfx -PfxPassword "my supersecret password"
    Logged in as user@company.com

    PS C:\>Read-AADIntAccesstoken $tokens[0] | Select aud,iss,appid,amr | fl
    
    aud   : https://portal.office.com/
    iss   : https://sts.windows.net/25dc721a-d37f-44ec-b8dc-cc5783e9ec56/
    appid : 00000006-0000-0ff1-ce00-000000000000
    amr   : {rsa, mfa}
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName="File",Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName="File",Mandatory=$False)]
        [string]$PfxPassword,
        [Parameter(ParameterSetName="Certificate",Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    Process
    {
        if($Certificate -eq $null)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }
        $TenantId = Get-TenantID -Domain $certificate.SubjectName.Name.Split("@")[1]

        # Create a web session
        $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $webSession.Cookies.Add((New-Object System.Net.Cookie("x-portal-routekey", "wuk", "/", "admin.microsoft.com")))

        # Invoke the first request to get redirect url
        $response = Invoke-WebRequest2 -Uri "https://admin.microsoft.com/login?ru=%2FAdminportal%2FHome%3F%26source%3Dapplauncher" -Method Get -WebSession $webSession -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $url = $response.Headers.'Location'

        # Get the login parameters and cookies with the certificate
        $loginInfo = Get-LoginParametersUsingCBA -Url $url -TenantId $TenantId -Certificate $certificate -WebSession $webSession

        # Send parameters to redirect_url
        $response2 = Invoke-RestMethod -UseBasicParsing -Uri "https://admin.microsoft.com/landing" -Method Post -Body $loginInfo.parameters -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $webSession

        # Return an array of access tokens
        $retVal = @()
        $retVal += Get-AccessTokenUsingAdminAPI -TokenType PortalAT        -WebSession $webSession
        $retVal += Get-AccessTokenUsingAdminAPI -TokenType BusinessStoreAT -WebSession $webSession
        
        return $retVal
    }
}

# Get's tokens using CBA
# May 24th 2022        
function Get-PortalAccessTokenUsingCBA
{
<#
    .SYNOPSIS
    Gets Access Tokens using CBA

    .DESCRIPTION
    Gets Access Tokens using Certificate Based Authentication (CBA). 
    Returns tokens for Graph, Office search, Substrate, Loki, and Portal
    Assumes that CN of the given certificate contains upn with domain name.

    .Parameter PfxFileName
    Name of the certificate file to be used

    .Parameter PfxPassword
    Password of the certificate file to be used

    .Example
    Get-AADIntAccessTokenForAADGraph
    
    .Example
    PS C:\>$tokens = Get-AADIntPortalAccessTokenUsingCBA -PfxFileName .\my_cert.pfx -PfxPassword "my supersecret password"
    Logged in as user@company.com

    PS C:\>Read-AADIntAccesstoken $tokens[0] | Select aud,iss,appid,amr | fl
    
    aud   : https://graph.microsoft.com
    iss   : https://sts.windows.net/25dc721a-d37f-44ec-b8dc-cc5783e9ec56/
    appid : 4765445b-32c6-49b0-83e6-1d93765276ca
    amr   : {rsa, mfa}
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName="File",Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName="File",Mandatory=$False)]
        [string]$PfxPassword,
        [Parameter(ParameterSetName="Certificate",Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    Process
    {
        if($Certificate -eq $null)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }
        $TenantId = Get-TenantID -Domain $certificate.SubjectName.Name.Split("@")[1]

        # Create a web session
        $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession

        # Invoke the first request to get redirect url
        $response = Invoke-WebRequest2 -Uri "https://www.office.com/login?ru=%2F%3Ffrom%3DPortalHome" -Method Get -WebSession $webSession -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $url = $response.Headers.'Location'

        # Get the login parameters and cookies with the certificate
        $loginInfo = Get-LoginParametersUsingCBA -Url $url -TenantId $TenantId -Certificate $certificate -WebSession $webSession

        # Send parameters to redirect_url
        $response2 = Invoke-RestMethod -UseBasicParsing -Uri "https://www.office.com/landingv2" -Method Post -Body $loginInfo.parameters -MaximumRedirection 1 -ErrorAction SilentlyContinue -WebSession $webSession

        # Parse tokens from the html
        $tokens = (Get-Substring -String $response2 -Start '<div id="primaryTokensInfo" style="display: none;">' -End "</div>").replace('&quot;','"') | ConvertFrom-Json

        # Return an array of access tokens
        $retVal = @()
        foreach($token in ($tokens | Get-Member -MemberType NoteProperty))
        {
            $value = $tokens | Select -ExpandProperty $token.Name
            $retVal += $value.TokenValue
        }

        return $retVal
    }
}

function Get-LoginParametersUsingCBA
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Url,
        [Parameter(Mandatory=$True)]
        [String]$TenantId,
        [Parameter(Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$True)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession
    )
    Process
    {
        function Get-Config
        {
            Param(
                [Parameter(Mandatory=$True)]
                [String]$Content
            )
            Process
            {
                $strConfig = Get-Substring -String $Content -Start '$Config=' -End ";`n"
                if([string]::IsNullOrEmpty($strConfig))
                {
                    Throw "Could not parse config"
                }
                try
                {
                    return $strConfig | ConvertFrom-Json
                }
                catch
                {
                    Throw "Coud not parse config"
                }
            }
        }

        $nonce = (New-Guid).ToString()

        # Make an initial request to login.microsoftonline.com to get required tokens and config
        $response1 = Invoke-WebRequest -UseBasicParsing -Uri $Url -Method Get -WebSession $WebSession -ErrorAction SilentlyContinue


        # Extract the config
        $config = Get-Config -Content $response1.Content
        
        # Make request to https://certauth.login.microsoftonline.com/<tenantid>/certauth
        $body = @{
            "ctx"=$config.sCtx
            "flowToken"=$config.sFT
        }

        $response2 = Invoke-RestMethod -UseBasicParsing -Uri "https://certauth.login.microsoftonline.com/$TenantId/certauth" -Method Post -Body $body -Certificate $Certificate

        # Parse the hidden form fields
        $parameters = @{}
        foreach($e in $response2.html.body.form.input)
        {
            $parameters[$e.name]=$e.value
        }

        # Make the final request to login.microsoftonline.com to get cookies
        $response3 = Invoke-WebRequest -UseBasicParsing -Uri "https://login.microsoftonline.com/common/login" -Method Post -Headers @{"Referer"="https://certauth.login.microsoftonline.com/"} -Body $parameters

        # Parse the config
        $config = Get-Config -Content $response3.content 

        if(-not [string]::IsNullOrEmpty($config.strMainMessage))
        {
            Throw $config.strServiceExceptionMessage
        }

        # Get the cookies
        foreach($cookie in $response3.Headers.'Set-Cookie'.Split(","))
        {
            $parts = $cookie.Split(";")[0].Split("=")
            switch($parts[0])
            {
                "ESTSAUTH"      { $estsauth      = $parts[1] }
                "ESTSAUTHLIGHT" { $estsauthlight = $parts[1] }
            }
        }


        Write-Host "Logged in as $($config.sPOST_Username)" -ForegroundColor Green

        # Make a request to login.microsoftonline.com/kmsi to get code and id_token
        $body = @{
            "LoginOptions" = "3"
            "type" = "28"
            "ctx" = $config.sCtx
            "hpgrequestid" = $config.sessionId
            "flowToken"	= $config.sFT
            "canary" = $config.canary
            "i19" = "2326"
        }
        $response4 = Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/kmsi" -Method Post -WebSession $WebSession -Body $body

        # Parse the hidden form fields
        $parameters = @{}
        foreach($e in $response4.html.body.form.input)
        {
            $parameters[$e.name]=$e.value
        }

        if(-not $parameters.ContainsKey("code"))
        {
            $config = Get-Config -Content $response4
            if(-not [string]::IsNullOrEmpty($config.strMainMessage))
            {
                Throw $config.strServiceExceptionMessage
            }
            Throw "Could not get authorization code!"
        }

        # Return 
        return New-Object psobject -Property @{
            "parameters" = $parameters
            "ESTSAUTH"   = $estsauth
        }
    }
}