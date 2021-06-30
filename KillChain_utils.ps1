# Checks whether the domain has MX records pointing to MS cloud
# Jun 16th 2020
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

        return ($results -like "*.mail.protection.outlook.com").Count -gt 0
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



# Checks whether the user exists in Azure AD or not
# Jun 16th 2020
function DoesUserExists
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$User,
        [Parameter(Mandatory=$False)]
        [ValidateSet("Normal","Login")]
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
            if($credType.EstsProperties.DesktopSsoEnabled -eq "True")
            {
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
            }
            else
            {
                Remove-Variable exists
            }
        }
        elseif($Method -eq "Login")
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