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
    Get-AADIntSPOAuthenticationCookie
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
        $response = Invoke-WebRequest -uri $Site -MaximumRedirection 0 -ErrorAction SilentlyContinue
        
        # Step 2: Go to "/_layouts/15/Authenticate.aspx?Source=%2F"
        $url = $response.Headers.'Location'
        $response = Invoke-WebRequest -uri $url -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $siteWebSession = Create-WebSession -SetCookieHeader $response.Headers.'Set-Cookie' -Domain $siteDomain

        # Step 3: Go to "/_forms/default.aspx?ReturnUrl=%2f_layouts%2f15%2fAuthenticate.aspx%3fSource%3d%252F&Source=cookie"
        $html=$response.Content
        $s=$html.IndexOf('href="')+6
        $e=$html.IndexOf('"',$s)
        $url=$html.Substring($s,$e-$s)
        $url="https://$siteDomain/$url"
        $response = Invoke-WebRequest -uri $url -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $siteWebSession

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
        $response = Invoke-WebRequest -Uri $url -Method Post -Body $body -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $siteWebSession

       

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