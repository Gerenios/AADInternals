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
        [Parameter(ParameterSetName="External", Mandatory=$True)]
        [Parameter(ParameterSetName="Normal", Mandatory=$True)]
        [String]$User,
        [Parameter(ParameterSetName="External", Mandatory=$True)]
        [Switch]$External,
        [Parameter(ParameterSetName="External",Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        # If the user is external, change to correct format
        if($External)
        {
            $User="$($User.Replace("@","_"))#EXT#@$domain"
        }
        $exists = $false 

        # Get the credential type information
        $credType=Get-CredentialType -UserName $User 

        # Works only if desktop sso (aka. Seamless SSO) is enabled
        if($credType.EstsProperties.DesktopSsoEnabled -eq "True")
        {
            $exists = $credType.IfExistsResult -eq 0 -or $credType.IfExistsResult -eq 6
        }

        return $exists
    }
}