# This script contains functions for handling access tokens
# and some utility functions

# VARIABLES

# Unix epoch time (1.1.1970)
$epoch = Get-Date -Day 1 -Month 1 -Year 1970 -Hour 0 -Minute 0 -Second 0 -Millisecond 0

# Well known client ids
<#
    "graph_api"=            "1b730954-1685-4b74-9bfd-dac224a7b894" # MS Graph API
    "aadrm"=                "90f610bf-206d-4950-b61d-37fa6fd1b224" # AADRM
    "exo"=                  "a0c73c16-a7e3-4564-9a95-2bdf47383716" # EXO Remote PowerShell
    "skype"=                "d924a533-3729-4708-b3e8-1d2445af35e3" # Skype
    "www"=                  "00000006-0000-0ff1-ce00-000000000000" # Office portal
    "o365spo"=              "00000003-0000-0ff1-ce00-000000000000" # SharePoint Online
    "o365exo"=              "00000002-0000-0ff1-ce00-000000000000" # Exchange Online
    "dynamicscrm"=          "00000007-0000-0000-c000-000000000000" # Dynamics CRM
    "o365suiteux"=          "4345a7b9-9a63-4910-a426-35363201d503" # O365 Suite UX
    "aadsync"=              "cb1056e2-e479-49de-ae31-7812af012ed8" # Azure AD Sync
    "aadconnectv2"=         "6eb59a73-39b2-4c23-a70f-e2e3ce8965b1" # AAD Connect v2
    "synccli"=              "1651564e-7ce4-4d99-88be-0a65050d8dc3" # Sync client
    "azureadmin" =          "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" # Azure Admin web ui
    "pta" =                 "cb1056e2-e479-49de-ae31-7812af012ed8" # Pass-through authentication
    "patnerdashboard" =     "4990cffe-04e8-4e8b-808a-1175604b879"  # Partner dashboard (missing on letter?)
    "webshellsuite" =       "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7" # Office365 Shell WCSS-Client
    "teams" =               "1fec8e78-bce4-4aaf-ab1b-5451cc387264" # Teams
    "office" =              "d3590ed6-52b3-4102-aeff-aad2292ab01c" # Office, ref. https://docs.microsoft.com/en-us/office/dev/add-ins/develop/register-sso-add-in-aad-v2
    "office_online2" =      "57fb890c-0dab-4253-a5e0-7188c88b2bb4" # SharePoint Online Client
    "office_online" =       "bc59ab01-8403-45c6-8796-ac3ef710b3e3" # Outlook Online Add-in App
    "powerbi_contentpack" = "2a0c3efa-ba54-4e55-bdc0-770f9e39e9ee" # PowerBI content pack
    "aad_account" =         "0000000c-0000-0000-c000-000000000000" # https://account.activedirectory.windowsazure.com
    "sara" =                "d3590ed6-52b3-4102-aeff-aad2292ab01c" # Microsoft Support and Recovery Assistant (SARA)
    "office_mgmt" =         "389b1b32-b5d5-43b2-bddc-84ce938d6737" # Office Management API Editor https://manage.office.com 
    "onedrive" =            "ab9b8c07-8f02-4f72-87fa-80105867a763" # OneDrive Sync Engine
    "adibizaux" =           "74658136-14ec-4630-ad9b-26e160ff0fc6" # Azure portal UI "ADIbizaUX"
    "msmamservice" =        "27922004-5251-4030-b22d-91ecd9a37ea4" # MS MAM Service API
    "teamswebclient" =      "5e3ce6c0-2b1f-4285-8d4b-75ee78787346" # Teams web client
    "azuregraphclientint" = "7492bca1-9461-4d94-8eb8-c17896c61205" # Microsoft Azure Graph Client Library 2.1.9 Internal
    "azure_mgmt" =          "84070985-06ea-473d-82fe-eb82b4011c9d" # Windows Azure Service Management API
    "az" =                  "1950a258-227b-4e31-a9cf-717495945fc2" # AZ PowerShell Module
                            "f8d98a96-0999-43f5-8af3-69971c7bb423" # Apple Internet Accounts
                            "7f59a773-2eaf-429c-a059-50fc5bb28b44" # https://docs.microsoft.com/en-us/rest/api/authorization/globaladministrator/elevateaccess#code-try-0
                            "9bc3ab49-b65d-410a-85ad-de819febfddc" # SPO Management Shell
                            "06c6433f-4fb8-4670-b2cd-408938296b8e" # AAD Pin redemption client
                            "19db86c3-b2b9-44cc-b339-36da233a3be2" # https://mysignins.microsoft.com
                            "00b41c95-dab0-4487-9791-b9d2c32c80f2" # Office 365 Management (mobile app)
                            "29d9ed98-a469-4536-ade2-f981bc1d605e" # Microsoft Authentication Broker (Azure MDM client)
                            "6f7e0f60-9401-4f5b-98e2-cf15bd5fd5e3" # Microsoft.AAD.BrokerPlugin resource:https://cs.dds.microsoft.com
                            "38aa3b87-a06d-4817-b275–7a316988d93b" # Microsoft AAD Cloud AP
                            "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa" # Azure Android App
                            "6c7e8096-f593-4d72-807f-a5f86dcc9c77" # Intune MAM client resource:https://intunemam.microsoftonline.com
                            "4813382a-8fa7-425e-ab75-3b753aab3abb" # Authenticator App resource:ff9ebd75-fe62-434a-a6ce-b3f0a8592eaf
                            "1fec8e78-bce4-4aaf-ab1b-5451cc387264" # Teams client
                            "de0853a1-ab20-47bd-990b-71ad5077ac7b" # Windows Configuration Designer (WCD)
                            "b90d5b8f-5503-4153-b545-b31cecfaece2" # AADJ CSP
                            "fb78d390-0c51-40cd-8e17-fdbfab77341b" # Microsoft Exchange REST API Based Powershell
                            "18ed3507-a475-4ccb-b669-d66bc9f2a36e" # Microsoft_AAD_RegisteredApps
                            "3f1abb3f-12cc-42c3-ad06-5b608dc5fb67" # Microsoft Intune multi-tenant management UX extension
#>


# AccessToken resource strings
<#
$resources=@{
    "aad_graph_api"=         "https://graph.windows.net"
    "ms_graph_api"=          "https://graph.microsoft.com"
    "azure_mgmt_api" =       "https://management.azure.com"
    "windows_net_mgmt_api" = "https://management.core.windows.net/"
    "cloudwebappproxy" =     "https://proxy.cloudwebappproxy.net/registerapp"
    "officeapps" =           "https://officeapps.live.com"
    "outlook" =              "https://outlook.office365.com"
    "webshellsuite" =        "https://webshell.suite.office.com"
    "sara" =                 "https://api.diagnostics.office.com"
    "office_mgmt" =          "https://manage.office.com"
    "msmamservice" =         "https://msmamservice.api.application"
    "spacesapi" =            "https://api.spaces.skype.com"
}
#>

# Stored tokens (access & refresh)
$tokens=@{}
$refresh_tokens=@{}

## UTILITY FUNCTIONS FOR API COMMUNICATIONS

# Return user's login information
function Get-LoginInformation
{
<#
    .SYNOPSIS
    Returns authentication information of the given user or domain

    .DESCRIPTION
    Returns authentication of the given user or domain

    .Example
    Get-AADIntLoginInformation -Domain outlook.com

    Tenant Banner Logo                   : 
    Authentication Url                   : https://login.live.com/login.srf?username=nn%40outlook.com&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=
    Pref Credential                      : 6
    Federation Protocol                  : WSTrust
    Throttle Status                      : 0
    Cloud Instance                       : microsoftonline.com
    Federation Brand Name                : MSA Realms
    Domain Name                          : live.com
    Federation Metadata Url              : https://nexus.passport.com/FederationMetadata/2007-06/FederationMetadata.xml
    Tenant Banner Illustration           : 
    Consumer Domain                      : True
    State                                : 3
    Federation Active Authentication Url : https://login.live.com/rst2.srf
    User State                           : 2
    Account Type                         : Federated
    Tenant Locale                        : 
    Domain Type                          : 2
    Exists                               : 5
    Has Password                         : True
    Cloud Instance audience urn          : urn:federation:MicrosoftOnline
    Federation Global Version            : -1

    .Example
    Get-AADIntLoginInformation -UserName someone@company.com

    Tenant Banner Logo                   : https://secure.aadcdn.microsoftonline-p.com/c1c6b6c8-okmfqodscgr7krbq5-p48zooi4b7m9g2zcpryoikta/logintenantbranding/0/bannerlogo?ts=635912486993671038
    Authentication Url                   : 
    Pref Credential                      : 1
    Federation Protocol                  : 
    Throttle Status                      : 1
    Cloud Instance                       : microsoftonline.com
    Federation Brand Name                : Company Ltd
    Domain Name                          : company.com
    Federation Metadata Url              : 
    Tenant Banner Illustration           : 
    Consumer Domain                      : 
    State                                : 4
    Federation Active Authentication Url : 
    User State                           : 1
    Account Type                         : Managed
    Tenant Locale                        : 0
    Domain Type                          : 3
    Exists                               : 0
    Has Password                         : True
    Cloud Instance audience urn          : urn:federation:MicrosoftOnline
    Desktop Sso Enabled                  : True
    Federation Global Version            : 

   
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Domain',Mandatory=$True)]
        [String]$Domain,

        [Parameter(ParameterSetName='User',Mandatory=$True)]
        [String]$UserName

    )
    Process
    {
        if([string]::IsNullOrEmpty($UserName))
        {
            $isDomain = $true
            $UserName = "nn@$Domain"
        }

        # Gather login information using different APIs
        $realm1=Get-UserRealm -UserName $UserName          # common/userrealm API 1.0
        $realm2=Get-UserRealmExtended -UserName $UserName  # common/userrealm API 2.0
        $realm3=Get-UserRealmV2 -UserName $UserName        # GetUserRealm.srf (used in the old Office 365 login experience)
        $realm4=Get-CredentialType -UserName $UserName     # common/GetCredentialType (used in the "new" Office 365 login experience)

        # Create a return object
        $attributes = @{
            "Account Type" = $realm1.account_type # Managed or federated
            "Domain Name" = $realm1.domain_name
            "Cloud Instance" = $realm1.cloud_instance_name
            "Cloud Instance audience urn" = $realm1.cloud_audience_urn
            "Federation Brand Name" = $realm2.FederationBrandName
            "Tenant Locale" = $realm2.TenantBrandingInfo.Locale
            "Tenant Banner Logo" = $realm2.TenantBrandingInfo.BannerLogo
            "Tenant Banner Illustration" = $realm2.TenantBrandingInfo.Illustration
            "State" = $realm3.State
            "User State" = $realm3.UserState
            "Exists" = $realm4.IfExistsResult
            "Throttle Status" = $realm4.ThrottleStatus
            "Pref Credential" = $realm4.Credentials.PrefCredential
            "Has Password" = $realm4.Credentials.HasPassword
            "Domain Type" = $realm4.EstsProperties.DomainType

            "Federation Protocol" = $realm1.federation_protocol
            "Federation Metadata Url" = $realm1.federation_metadata_url
            "Federation Active Authentication Url" = $realm1.federation_active_auth_url
            "Authentication Url" = $realm2.AuthUrl
            "Consumer Domain" = $realm2.ConsumerDomain
            "Federation Global Version" = $realm3.FederationGlobalVersion
            "Desktop Sso Enabled" = $realm4.EstsProperties.DesktopSsoEnabled
        }
      
        # Return
        return New-Object psobject -Property $attributes
    }
}

# Return user's authentication realm from common/userrealm using API 1.0
function Get-UserRealm
{
<#
    .SYNOPSIS
    Returns authentication realm of the given user

    .DESCRIPTION
    Returns authentication realm of the given user using common/userrealm API 1.0

    .Example 
    Get-AADIntUserRealm -UserName "user@company.com"

    ver                 : 1.0
    account_type        : Managed
    domain_name         : company.com
    cloud_instance_name : microsoftonline.com
    cloud_audience_urn  : urn:federation:MicrosoftOnline

    .Example 
    Get-AADIntUserRealm -UserName "user@company.com"

    ver                        : 1.0
    account_type               : Federated
    domain_name                : company.com
    federation_protocol        : WSTrust
    federation_metadata_url    : https://sts.company.com/adfs/services/trust/mex
    federation_active_auth_url : https://sts.company.com/adfs/services/trust/2005/usernamemixed
    cloud_instance_name        : microsoftonline.com
    cloud_audience_urn         : urn:federation:MicrosoftOnline

    
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$UserName

    )
    Process
    {
      
        # Call the API
        $userRealm=Invoke-RestMethod -UseBasicParsing -Uri ("https://login.microsoftonline.com/common/userrealm/$UserName"+"?api-version=1.0")

        # Verbose
        Write-Verbose "USER REALM $($userRealm | Out-String)"

        # Return
        $userRealm
    }
}

# Return user's authentication realm from common/userrealm using API 2.0
function Get-UserRealmExtended
{
<#
    .SYNOPSIS
    Returns authentication realm of the given user

    .DESCRIPTION
    Returns authentication realm of the given user using common/userrealm API 2.0

    .Example
    Get-AADIntUserRealmExtended -UserName "user@company.com"

    NameSpaceType       : Managed
    Login               : user@company.com
    DomainName          : company.com
    FederationBrandName : Company Ltd
    TenantBrandingInfo  : {@{Locale=0; BannerLogo=https://secure.aadcdn.microsoftonline-p.com/xxx/logintenantbranding/0/bannerlogo?
                          ts=111; TileLogo=https://secure.aadcdn.microsoftonline-p.com/xxx/logintenantbranding/0/til
                          elogo?ts=112; BackgroundColor=#FFFFFF; BoilerPlateText=From here
                          you can sign-in to Company Ltd services; UserIdLabel=firstname.lastname@company.com;
                          KeepMeSignedInDisabled=False}}
    cloud_instance_name : microsoftonline.com

    .Example 
    Get-AADIntUserRealmExtended -UserName "user@company.com"

    NameSpaceType       : Federated
    federation_protocol : WSTrust
    Login               : user@company.com
    AuthURL             : https://sts.company.com/adfs/ls/?username=user%40company.com&wa=wsignin1.
                          0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=
    DomainName          : company.com
    FederationBrandName : Company Ltd
    TenantBrandingInfo  : 
    cloud_instance_name : microsoftonline.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$UserName

    )
    Process
    {
      
        # Call the API
        $userRealm=Invoke-RestMethod -UseBasicParsing -Uri ("https://login.microsoftonline.com/common/userrealm/$UserName"+"?api-version=2.0")

        # Verbose
        Write-Verbose "USER REALM $($userRealm | Out-String)"

        # Return
        $userRealm
    }
}

# Return user's authentication realm from GetUserRealm.srf (used in the old Office 365 login experience)
function Get-UserRealmV2
{
<#
    .SYNOPSIS
    Returns authentication realm of the given user

    .DESCRIPTION
    Returns authentication realm of the given user using GetUserRealm.srf (used in the old Office 365 login experience)

    .Example
    Get-AADIntUserRealmV3 -UserName "user@company.com"

    State               : 4
    UserState           : 1
    Login               : user@company.com
    NameSpaceType       : Managed
    DomainName          : company.com
    FederationBrandName : Company Ltd
    CloudInstanceName   : microsoftonline.com

    .Example 
    Get-AADIntUserRealmV2 -UserName "user@company.com"

    State                   : 3
    UserState               : 2
    Login                   : user@company.com
    NameSpaceType           : Federated
    DomainName              : company.com
    FederationGlobalVersion : -1
    AuthURL                 : https://sts.company.com/adfs/ls/?username=user%40company.com&wa=wsignin1.
                              0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=
    FederationBrandName     : Company Ltd
    CloudInstanceName       : microsoftonline.com
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$UserName

    )
    Process
    {
      
        # Call the API
        $userRealm=Invoke-RestMethod -UseBasicParsing -Uri ("https://login.microsoftonline.com/GetUserRealm.srf?login=$UserName")

        # Verbose
        Write-Verbose "USER REALM: $($userRealm | Out-String)"

        # Return
        $userRealm
    }
}

# Return user's authentication type information from common/GetCredentialType
function Get-CredentialType
{
<#
    .SYNOPSIS
    Returns authentication information of the given user

    .DESCRIPTION
    Returns authentication of the given user using common/GetCredentialType (used in the "new" Office 365 login experience)

    .Example
    Get-AADIntUserRealmExtended -UserName "user@company.com"

    Username       : user@company.com
    Display        : user@company.com
    IfExistsResult : 0
    ThrottleStatus : 1
    Credentials    : @{PrefCredential=1; HasPassword=True; RemoteNgcParams=; FidoParams=; SasParams=}
    EstsProperties : @{UserTenantBranding=System.Object[]; DomainType=3}
    FlowToken      : 
    apiCanary      : AQABAAA..A

    NameSpaceType       : Managed
    Login               : user@company.com
    DomainName          : company.com
    FederationBrandName : Company Ltd
    TenantBrandingInfo  : {@{Locale=0; BannerLogo=https://secure.aadcdn.microsoftonline-p.com/xxx/logintenantbranding/0/bannerlogo?
                          ts=111; TileLogo=https://secure.aadcdn.microsoftonline-p.com/xxx/logintenantbranding/0/til
                          elogo?ts=112; BackgroundColor=#FFFFFF; BoilerPlateText=From here
                          you can sign-in to Company Ltd services; UserIdLabel=firstname.lastname@company.com;
                          KeepMeSignedInDisabled=False}}
    cloud_instance_name : microsoftonline.com

    .Example 
    Get-AADIntUserRealmExtended -UserName "user@company.com"

    Username       : user@company.com
    Display        : user@company.com
    IfExistsResult : 0
    ThrottleStatus : 1
    Credentials    : @{PrefCredential=4; HasPassword=True; RemoteNgcParams=; FidoParams=; SasParams=; FederationRed
                     irectUrl=https://sts.company.com/adfs/ls/?username=user%40company.com&wa=wsignin1.0&wtreal
                     m=urn%3afederation%3aMicrosoftOnline&wctx=}
    EstsProperties : @{UserTenantBranding=; DomainType=4}
    FlowToken      : 
    apiCanary      : AQABAAA..A
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [String]$FlowToken

    )
    Process
    {
        # Create a body for REST API request
        $body = @{
            "username"=$UserName
            "isOtherIdpSupported"="true"
	        "checkPhones"="true"
	        "isRemoteNGCSupported"="false"
	        "isCookieBannerShown"="false"
	        "isFidoSupported"="false"
            "originalRequest"=""
            "flowToken"=$FlowToken
        }
      
        # Call the API
        $userRealm=Invoke-RestMethod -UseBasicParsing -Uri ("https://login.microsoftonline.com/common/GetCredentialType") -ContentType "application/json; charset=UTF-8" -Method POST -Body ($body|ConvertTo-Json)

        # Verbose
        Write-Verbose "CREDENTIAL TYPE: $($userRealm | Out-String)"

        # Return
        $userRealm
    }
}

# Return OpenID configuration for the domain
# Mar 21 2019
function Get-OpenIDConfiguration
{
<#
    .SYNOPSIS
    Returns OpenID configuration of the given domain or user

    .DESCRIPTION
    Returns OpenID configuration of the given domain or user

    .Example
    Get-AADIntOpenIDConfiguration -UserName "user@company.com"

    .Example
    Get-AADIntOpenIDConfiguration -Domain company.com

    authorization_endpoint                : https://login.microsoftonline.com/5b62a25d-60c6-40e6-aace-8a43e8b8ba4a/oauth2/authorize
    token_endpoint                        : https://login.microsoftonline.com/5b62a25d-60c6-40e6-aace-8a43e8b8ba4a/oauth2/token
    token_endpoint_auth_methods_supported : {client_secret_post, private_key_jwt, client_secret_basic}
    jwks_uri                              : https://login.microsoftonline.com/common/discovery/keys
    response_modes_supported              : {query, fragment, form_post}
    subject_types_supported               : {pairwise}
    id_token_signing_alg_values_supported : {RS256}
    http_logout_supported                 : True
    frontchannel_logout_supported         : True
    end_session_endpoint                  : https://login.microsoftonline.com/5b62a25d-60c6-40e6-aace-8a43e8b8ba4a/oauth2/logout
    response_types_supported              : {code, id_token, code id_token, token id_token...}
    scopes_supported                      : {openid}
    issuer                                : https://sts.windows.net/5b62a25d-60c6-40e6-aace-8a43e8b8ba4a/
    claims_supported                      : {sub, iss, cloud_instance_name, cloud_instance_host_name...}
    microsoft_multi_refresh_token         : True
    check_session_iframe                  : https://login.microsoftonline.com/5b62a25d-60c6-40e6-aace-8a43e8b8ba4a/oauth2/checkses
                                            sion
    userinfo_endpoint                     : https://login.microsoftonline.com/5b62a25d-60c6-40e6-aace-8a43e8b8ba4a/openid/userinfo
    tenant_region_scope                   : EU
    cloud_instance_name                   : microsoftonline.com
    cloud_graph_host_name                 : graph.windows.net
    msgraph_host                          : graph.microsoft.com
    rbac_url                              : https://pas.windows.net

    
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Domain',Mandatory=$True)]
        [String]$Domain,

        [Parameter(ParameterSetName='User',Mandatory=$True)]
        [String]$UserName
    )
    Process
    {
        if([String]::IsNullOrEmpty($Domain))
        {
            $Domain = $UserName.Split("@")[1]
        }

      
        # Call the API
        $openIdConfig=Invoke-RestMethod -UseBasicParsing "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"

        # Return
        $openIdConfig
    }
}

# Get the tenant ID for the given user/domain/accesstoken
function Get-TenantID
{
<#
    .SYNOPSIS
    Returns TenantID of the given domain, user, or AccessToken

    .DESCRIPTION
    Returns TenantID of the given domain, user, or AccessToken

    .Example
    Get-AADIntTenantID -UserName "user@company.com"

    .Example
    Get-AADIntTenantID -Domain company.com

    .Example
    Get-AADIntTenantID -AccessToken $at

#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Domain',Mandatory=$True)]
        [String]$Domain,

        [Parameter(ParameterSetName='User',Mandatory=$True)]
        [String]$UserName,

        [Parameter(ParameterSetName='AccessToken', Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        if([String]::IsNullOrEmpty($AccessToken))
        {
            if([String]::IsNullOrEmpty($Domain))
            {
                $Domain = $UserName.Split("@")[1]
            }

            Try
            {
                $OpenIdConfig = Get-OpenIDConfiguration -Domain $domain
            }
            catch
            {
                return $null
            }

            $TenantId = $OpenIdConfig.authorization_endpoint.Split("/")[3]
        }
        else
        {
            $TenantId=(Read-Accesstoken($AccessToken)).tid
        }

        # Return
        $TenantId
    }
}

# Check if the access token has expired
function Is-AccessTokenExpired
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken
        
    )
    Process
    {
        # Read the token
        $token = Read-Accesstoken($AccessToken)
        $now=(Get-Date).ToUniversalTime()

        # Get the expiration time
        $exp=$epoch.Date.AddSeconds($token.exp)

        # Compare and return
        $retVal = $now -ge $exp

        return $retVal
    }
}

# Check if the access token signature is valid
# May 20th 2020
function Is-AccessTokenValid
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        # Token sections
        $sections =  $AccessToken.Split(".")
        $header =    $sections[0]
        $payload =   $sections[1]
        $signature = $sections[2]

        $signatureValid = $false

        # Fill the header with padding for Base 64 decoding
        while ($header.Length % 4)
        {
            $header += "="
        }

        # Convert the token to string and json
        $headerBytes=[System.Convert]::FromBase64String($header)
        $headerArray=[System.Text.Encoding]::ASCII.GetString($headerBytes)
        $headerObj=$headerArray | ConvertFrom-Json

        # Get the signing key
        $KeyId=$headerObj.kid
        Write-Debug "PARSED TOKEN HEADER: $($headerObj | Format-List | Out-String)"

        # The algorithm should be RSA with SHA-256, i.e. RS256
        if($headerObj.alg -eq "RS256")
        {
            # Get the public certificate
            $publicCert = Get-APIKeys -KeyId $KeyId
            Write-Debug "TOKEN SIGNING CERT: $publicCert"
            $certBin=[convert]::FromBase64String($publicCert)

            # Construct the JWT data to be verified
            $dataToVerify="{0}.{1}" -f $header,$payload
            $dataBin = [text.encoding]::UTF8.GetBytes($dataToVerify)

            # Remove the Base64 URL encoding from the signature and add padding
            $signature=$signature.Replace("-","+").Replace("_","/")
            while ($signature.Length % 4)
            {
                $signature += "="
            }
            $signBytes = [convert]::FromBase64String($signature)

            # Extract the modulus and exponent from the certificate
            for($a=0;$a -lt $certBin.Length ; $a++)
            {
                # Read the bytes    
                $byte =  $certBin[$a] 
                $nByte = $certBin[$a+1] 

                # We are only interested in 0x02 tag where our modulus is hidden..
                if($byte -eq 0x02 -and $nByte -band 0x80)
                {
                    $a++
                    if($nbyte -band 0x02)
                    {
                        $byteCount = [System.BitConverter]::ToInt16($certBin[$($a+2)..$($a+1)],0)
                        $a+=3
                    }
                    elseif($nbyte -band 0x01)
                    {
                        $byteCount = $certBin[$($a+1)]
                        $a+=2
                    }

                    # If the first byte is 0x00, skip it
                    if($certBin[$a] -eq 0x00)
                    {
                        $a++
                        $byteCount--
                    }

                    # Now we have the modulus!
                    $modulus = $certBin[$a..$($a+$byteCount-1)]

                    # Next byte value is the exponent
                    $a+=$byteCount
                    if($certBin[$a++] -eq 0x02)
                    {
                        $byteCount = $certBin[$a++]
                        $exponent =  $certBin[$a..$($a+$byteCount-1)]
                        Write-Debug "MODULUS:  $(Convert-ByteArrayToHex -Bytes $modulus)"
                        Write-Debug "EXPONENT: $(Convert-ByteArrayToHex -Bytes $exponent)"
                        break
                    }
                    else
                    {
                        Write-Debug "Error getting modulus and exponent"
                    }
                }
            }

            if($exponent -and $modulus)
            {
                # Create the RSA and other required objects
                $rsa = New-Object -TypeName System.Security.Cryptography.RSACryptoServiceProvider
                $rsaParameters = New-Object -TypeName System.Security.Cryptography.RSAParameters
    
                # Set the verification parameters
                $rsaParameters.Exponent = $exponent
                $rsaparameters.Modulus = $modulus
                $rsa.ImportParameters($rsaParameters)
                
                $signatureValid = $rsa.VerifyData($dataBin, $signBytes,[System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

                $rsa.Dispose() 
                  
            }
                
        }
        else
        {
            Write-Error "Access Token signature algorithm $($headerObj.alg) not supported!"
        }

        return $signatureValid 
    }
}



# Gets OAuth information using SAML token
function Get-OAuthInfoUsingSAML
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(Mandatory=$True)]
        [String]$Resource,
        [Parameter(Mandatory=$False)]
        [String]$ClientId="1b730954-1685-4b74-9bfd-dac224a7b894"
    )
    Begin
    {
        # Create the headers. We like to be seen as Outlook.
        $headers = @{
            "User-Agent" = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; Tablet PC 2.0; Microsoft Outlook 16.0.4266)"
        }
    }
    Process
    {
        $encodedSamlToken= [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($SAMLToken))
        # Debug
        Write-Debug "SAML TOKEN: $samlToken"
        Write-Debug "ENCODED SAML TOKEN: $encodedSamlToken"

        # Create a body for API request
        $body = @{
            "resource"=$Resource
            "client_id"=$ClientId
            "grant_type"="urn:ietf:params:oauth:grant-type:saml1_1-bearer"
            "assertion"=$encodedSamlToken
            "scope"="openid"
        }

        # Debug
        Write-Debug "FED AUTHENTICATION BODY: $($body | Out-String)"

        # Set the content type and call the Microsoft Online authentication API
        $contentType="application/x-www-form-urlencoded"
        try
        {
            $jsonResponse=Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType $contentType -Method POST -Body $body -Headers $headers
        }
        catch
        {
            Throw ($_.ErrorDetails.Message | convertfrom-json).error_description
        }

        return $jsonResponse
    }
}

# Return OAuth information for the given user
function Get-OAuthInfo
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory=$True)]
        [String]$Resource,
        [Parameter(Mandatory=$False)]
        [String]$ClientId="1b730954-1685-4b74-9bfd-dac224a7b894"
    )
    Begin
    {
        # Create the headers. We like to be seen as Outlook.
        $headers = @{
            "User-Agent" = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; Tablet PC 2.0; Microsoft Outlook 16.0.4266)"
        }
    }
    Process
    {
        # Get the user realm
        $userRealm = Get-UserRealm($Credentials.UserName)

        # Check the authentication type
        if($userRealm.account_type -eq "Unknown")
        {
            Write-Error "User type  of $($Credentials.Username) is Unknown!"
            return $null
        }
        elseif($userRealm.account_type -eq "Managed")
        {
            # If authentication type is managed, we authenticate directly against Microsoft Online
            # with user name and password to get access token

            # Create a body for REST API request
            $body = @{
                "resource"=$Resource
                "client_id"=$ClientId
                "grant_type"="password"
                "username"=$Credentials.UserName
                "password"=$Credentials.GetNetworkCredential().Password
                "scope"="openid"
            }

            # Debug
            Write-Debug "AUTHENTICATION BODY: $($body | Out-String)"

            # Set the content type and call the Microsoft Online authentication API
            $contentType="application/x-www-form-urlencoded"
            try
            {
                $jsonResponse=Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType $contentType -Method POST -Body $body -Headers $headers
            }
            catch
            {
                Throw ($_.ErrorDetails.Message | convertfrom-json).error_description
            }
        }
        else
        {
            # If authentication type is Federated, we must first authenticate against the identity provider
            # to fetch SAML token and then get access token from Microsoft Online

            # Get the federation metadata url from user realm
            $federation_metadata_url=$userRealm.federation_metadata_url

            # Call the API to get metadata
            [xml]$response=Invoke-RestMethod -UseBasicParsing -Uri $federation_metadata_url 

            # Get the url of identity provider endpoint.
            # Note! Tested only with AD FS - others may or may not work
            $federation_url=($response.definitions.service.port | where name -eq "UserNameWSTrustBinding_IWSTrustFeb2005Async").address.location

            # login.live.com
            # TODO: Fix
            #$federation_url=$response.EntityDescriptor.RoleDescriptor[1].PassiveRequestorEndpoint.EndpointReference.Address

            # Set credentials and other needed variables
            $username=$Credentials.UserName
            $password=$Credentials.GetNetworkCredential().Password
            $created=(Get-Date).ToUniversalTime().toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
            $expires=(Get-Date).AddMinutes(10).ToUniversalTime().toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
            $message_id=(New-Guid).ToString()
            $user_id=(New-Guid).ToString()

            # Set headers
            $headers = @{
                "SOAPAction"="http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"
                "Host"=$federation_url.Split("/")[2]
                "client-request-id"=(New-Guid).toString()
            }

            # Debug
            Write-Debug "FED AUTHENTICATION HEADERS: $($headers | Out-String)"
            
            # Create the SOAP envelope
            $envelope=@"
                <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>
	                <s:Header>
		                <a:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
		                <a:MessageID>urn:uuid:$message_id</a:MessageID>
		                <a:ReplyTo>
			                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		                </a:ReplyTo>
		                <a:To s:mustUnderstand='1'>$federation_url</a:To>
		                <o:Security s:mustUnderstand='1' xmlns:o='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'>
			                <u:Timestamp u:Id='_0'>
				                <u:Created>$created</u:Created>
				                <u:Expires>$expires</u:Expires>
			                </u:Timestamp>
			                <o:UsernameToken u:Id='uuid-$user_id'>
				                <o:Username>$username</o:Username>
				                <o:Password>$password</o:Password>
			                </o:UsernameToken>
		                </o:Security>
	                </s:Header>
	                <s:Body>
		                <trust:RequestSecurityToken xmlns:trust='http://schemas.xmlsoap.org/ws/2005/02/trust'>
			                <wsp:AppliesTo xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'>
				                <a:EndpointReference>
					                <a:Address>urn:federation:MicrosoftOnline</a:Address>
				                </a:EndpointReference>
			                </wsp:AppliesTo>
			                <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
			                <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>
		                </trust:RequestSecurityToken>
	                </s:Body>
                </s:Envelope>
"@
            # Debug
            Write-Debug "FED AUTHENTICATION: $envelope"

            # Set the content type and call the authentication service            
            $contentType="application/soap+xml"
            [xml]$xmlResponse=Invoke-RestMethod -UseBasicParsing -Uri $federation_url -ContentType $contentType -Method POST -Body $envelope -Headers $headers

            # Get the SAML token from response and encode it with Base64
            $samlToken=$xmlResponse.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.Assertion.OuterXml
            $encodedSamlToken= [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($samlToken))

            $jsonResponse = Get-OAuthInfoUsingSAML -SAMLToken $samlToken -Resource $Resource -ClientId $ClientId
        }
        
        # Debug
        Write-Debug "AUTHENTICATION JSON: $($jsonResponse | Out-String)"

        # Return
        $jsonResponse 
    }
}

# Parse access token and return it as PS object
function Read-Accesstoken
{
<#
    .SYNOPSIS
    Extract details from the given Access Token

    .DESCRIPTION
    Extract details from the given Access Token and returns them as PS Object

    .Parameter AccessToken
    The Access Token.
    
    .Example
    PS C:\>$token=Get-AADIntReadAccessTokenForAADGraph
    PS C:\>Parse-AADIntAccessToken -AccessToken $token

    aud                 : https://graph.windows.net
    iss                 : https://sts.windows.net/f2b2ba53-ed2a-4f4c-a4c3-85c61e548975/
    iat                 : 1589477501
    nbf                 : 1589477501
    exp                 : 1589481401
    acr                 : 1
    aio                 : ASQA2/8PAAAALe232Yyx9l=
    amr                 : {pwd}
    appid               : 1b730954-1685-4b74-9bfd-dac224a7b894
    appidacr            : 0
    family_name         : company
    given_name          : admin
    ipaddr              : 107.210.220.129
    name                : admin company
    oid                 : 1713a7bf-47ba-4826-a2a7-bbda9fabe948
    puid                : 100354
    rh                  : 0QfALA.
    scp                 : user_impersonation
    sub                 : BGwHjKPU
    tenant_region_scope : NA
    tid                 : f2b2ba53-ed2a-4f4c-a4c3-85c61e548975
    unique_name         : admin@company.onmicrosoft.com
    upn                 : admin@company.onmicrosoft.com
    uti                 : -EWK6jMDrEiAesWsiAA
    ver                 : 1.0

    .Example
    PS C:\>Parse-AADIntAccessToken -AccessToken $token -Validate

    Read-Accesstoken : Access Token is expired
    At line:1 char:1
    + Read-Accesstoken -AccessToken $at -Validate -verbose
    + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
        + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Read-Accesstoken

    aud                 : https://graph.windows.net
    iss                 : https://sts.windows.net/f2b2ba53-ed2a-4f4c-a4c3-85c61e548975/
    iat                 : 1589477501
    nbf                 : 1589477501
    exp                 : 1589481401
    acr                 : 1
    aio                 : ASQA2/8PAAAALe232Yyx9l=
    amr                 : {pwd}
    appid               : 1b730954-1685-4b74-9bfd-dac224a7b894
    appidacr            : 0
    family_name         : company
    given_name          : admin
    ipaddr              : 107.210.220.129
    name                : admin company
    oid                 : 1713a7bf-47ba-4826-a2a7-bbda9fabe948
    puid                : 100354
    rh                  : 0QfALA.
    scp                 : user_impersonation
    sub                 : BGwHjKPU
    tenant_region_scope : NA
    tid                 : f2b2ba53-ed2a-4f4c-a4c3-85c61e548975
    unique_name         : admin@company.onmicrosoft.com
    upn                 : admin@company.onmicrosoft.com
    uti                 : -EWK6jMDrEiAesWsiAA
    ver                 : 1.0
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [String]$AccessToken,
        [Parameter()]
        [Switch]$ShowDate,
        [Parameter()]
        [Switch]$Validate

    )
    Process
    {
        # Token sections
        $sections =  $AccessToken.Split(".")
        $header =    $sections[0]
        $payload =   $sections[1]
        $signature = $sections[2]

        # Convert the token to string and json
        $payloadString = Convert-B64ToText -B64 $payload
        $payloadObj=$payloadString | ConvertFrom-Json

        if($ShowDate)
        {
            # Show dates
            $payloadObj.exp=($epoch.Date.AddSeconds($payloadObj.exp)).toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
            $payloadObj.iat=($epoch.Date.AddSeconds($payloadObj.iat)).toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
            $payloadObj.nbf=($epoch.Date.AddSeconds($payloadObj.nbf)).toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
        }

        if($Validate)
        {
            # Check the signature
            if((Is-AccessTokenValid -AccessToken $AccessToken))
            {
                Write-Verbose "Access Token signature successfully verified"
            }
            else
            {
                Write-Error "Access Token signature could not be verified"
            }

            # Check the timestamp
            if((Is-AccessTokenExpired -AccessToken $AccessToken))
            {
                Write-Error "Access Token is expired"
            }
            else
            {
                Write-Verbose "Access Token is not expired"
            }

        }

        # Debug
        Write-Debug "PARSED ACCESS TOKEN: $($payloadObj | Out-String)"
        
        # Return
        $payloadObj
    }
}


# Prompts for credentials and gets the access token
# Supports MFA, federation, etc.
function Prompt-Credentials
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Resource,
        [String]$ClientId="1b730954-1685-4b74-9bfd-dac224a7b894" <# graph_api #>,
        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [bool]$ForceMFA=$false
    )
    Process
    {
        # Check the tenant
        if([String]::IsNullOrEmpty($Tenant))        
        {
            $Tenant = "common"
        }

        # Set variables
        $auth_redirect= Get-AuthRedirectUrl -ClientId $ClientId -Resource $Resource
        $client_id=     $ClientId # Usually should be graph_api
                        
        # Create the url
        $request_id=(New-Guid).ToString()
        $url="https://login.microsoftonline.com/$Tenant/oauth2/authorize?resource=$Resource&client_id=$client_id&response_type=code&haschrome=1&redirect_uri=$auth_redirect&client-request-id=$request_id&prompt=login&scope=openid profile"

        if($ForceMFA)
        {
            $url+="&amr_values=mfa"
        }

        # Azure AD Join
        if($ClientId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" -and $Resource -ne "https://enrollment.manage.microsoft.com/") 
        {
                $auth_redirect="ms-aadj-redir://auth/drs"
        }

        # Create the form
        $form = Create-LoginForm -Url $url -auth_redirect $auth_redirect


        # Show the form and wait for the return value
        if($form.ShowDialog() -ne "OK") {
            # Dispose the control
        $form.Controls[0].Dispose()
            Write-Verbose "Login cancelled"
            return $null
        }

        # Parse the query string
        $response = [Web.HttpUtility]::ParseQueryString($form.Controls[0].Url.Query)

        # Create a body for REST API request
        $body = @{
            client_id=$client_id
            grant_type="authorization_code"
            code=$response["code"]
            redirect_uri=$auth_redirect
        }
        
        # Dispose the control
        $form.Controls[0].Dispose()

        # Debug
        Write-Debug "AUTHENTICATION BODY: $($body | Out-String)"

        # Set the content type and call the Microsoft Online authentication API
        $contentType="application/x-www-form-urlencoded"
        $jsonResponse=Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token" -ContentType $contentType -Method POST -Body $body

        # return 
        $jsonResponse
    }
}



# Logs out the web sessions from LiveId
# Aug 10th 2018
function Clear-LiveIdSession
{

<#
    .SYNOPSIS
    Clear the SharePoint Online login session.

    .DESCRIPTION
    Clear the SharePoint Online login session created by Get-AADIntIdentityTokenByLiveId function.

    .Parameter Tenant
    The tenant name to login in to WITHOUT .sharepoint.com part
    
    .Example
    PS C:\>Clear-AADIntLiveIdSession -Tenant mytenant
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Tenant
    )
    Process
    {
        # Set variables
        $auth_redirect="https://login.microsoftonline.com/login.srf?wa=wsignoutcleanup1.0" # When to close the form
        $url="https://$tenant.sharepoint.com/_layouts/15/SignOut.aspx"

        # Create the form
        $form=Create-LoginForm -Url $url -auth_redirect $auth_redirect

        # Show the form and wait for the return value
        $form.ShowDialog()

        # Clear the webbrowser control
        Clear-WebBrowser
    }
}

# Creates an interactive login form based on given url and auth_redirect.
# Aug 10th 2018
function Create-LoginForm
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Url,
        [Parameter(Mandatory=$True)]
        [String]$auth_redirect,
        [Parameter(Mandatory=$False)]
        [String]$Headers
    )
    Process
    {
        # Check does the registry key exists
        $regPath="HKCU:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION"
        if(!(Test-Path -Path $regPath )){
            Write-Warning "WebBrowser control emulation registry key not found!"
            $answer = Read-Host -Prompt "Would you like to create the registry key? (Y/N)"
            if($answer -eq "Y")
            {
                New-Item -ItemType directory -Path $regPath -Force
            }
        }

        # Check the registry value for WebBrowser control emulation. Should be IE 11
        $reg=Get-ItemProperty -Path $regPath

        if([String]::IsNullOrEmpty($reg.'powershell.exe') -or [String]::IsNullOrEmpty($reg.'powershell_ise.exe'))
        {
            Write-Warning "WebBrowser control emulation not set for PowerShell or PowerShell ISE!"
            $answer = Read-Host -Prompt "Would you like set the emulation to IE 11? Otherwise the login form may not work! (Y/N)"
            if($answer -eq "Y")
            {
                Set-ItemProperty -Path $regPath -Name "powershell_ise.exe" -Value 0x00002af9
                Set-ItemProperty -Path $regPath -Name "powershell.exe" -Value 0x00002af9
                Write-Host "Emulation set. Restart PowerShell/ISE!"
                return
            }
        }

        # Create the form and add a WebBrowser control to it
        $form = New-Object Windows.Forms.Form
        $form.Width = 560
        $form.Height = 680
        $form.FormBorderStyle=[System.Windows.Forms.FormBorderStyle]::FixedDialog
        $form.TopMost = $true

        $web = New-Object Windows.Forms.WebBrowser
        $web.Size = $form.ClientSize
        $web.Anchor = "Left,Top,Right,Bottom"
        $form.Controls.Add($web)

        $field = New-Object Windows.Forms.TextBox
        $field.Visible = $false
        $form.Controls.Add($field)
		$field.Text = $auth_redirect

        # Clear WebBrowser control cache
        Clear-WebBrowser

        # Add an event listener to track down where the browser is
        $web.add_Navigated({
            # If the url matches the redirect url, close with OK.
            $curl=$_.Url.ToString()
			$auth_redirect = $form.Controls[1].Text							   
            Write-Debug "NAVIGATED TO: $($curl)"
            if($curl.StartsWith($auth_redirect)) {

                # Hack for Azure Portal Login. Jul 11th 2019 
                # Check whether the body has the Bearer
                if(![String]::IsNullOrEmpty($form.Controls[0].Document.GetElementsByTagName("script")))
                {
                    $script=$form.Controls[0].Document.GetElementsByTagName("script").outerhtml
                    if($script.Contains('"oAuthToken":')){
                        $s=$script.IndexOf('"oAuthToken":')+13
                        $e=$script.IndexOf('}',$s)+1
                        $oAuthToken=$script.Substring($s,$e-$s) | ConvertFrom-Json
                        $at=$oAuthToken.authHeader.Split(" ")[1]
                        $rt=$oAuthToken.refreshToken
                        $script:AccessToken = @{"access_token"=$at; "refresh_token"=$rt}
                        Write-Debug "ACCESSTOKEN $script:accessToken"
                    }
                    elseif($curl.StartsWith("https://portal.azure.com"))
                    {
                        Write-Debug "WAITING FOR THE TOKEN!"
                        # Do nothing, wait for it..
                        return
                    }
                }
                
                # Add the url to the hidden field
                #$form.Controls[1].Text = $curl

                $form.DialogResult = "OK"
                $form.Close()
                Write-Debug "PROMPT CREDENTIALS URL: $curl"
            } # Automatically logs in -> need to logout first
            elseif($curl.StartsWith($url)) {
                # All others
                Write-Verbose "Returned to the starting url, someone already logged in?"
            }
        })

        
        # Add an event listener to track down where the browser is going
        $web.add_Navigating({
            $curl=$_.Url.ToString()
            Write-Verbose "NAVIGATING TO: $curl"
            # SharePoint login
            if($curl.EndsWith("/_forms/default.aspx"))
            {
                $_.Cancel=$True
                $form.DialogResult = "OK"
                $form.Close()
            }
        })
        
#        $web.ScriptErrorsSuppressed = $True

        # Set the url
        if([String]::IsNullOrEmpty($Headers))
        {
            $web.Navigate($url)
        }
        else
        {
            $web.Navigate($url,"",$null,$Headers)
        }

        # Return
        return $form
    }
}

# Clear the Forms.WebBrowser data
$source=@"
[DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int lpdwBufferLength);

[DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetGetCookieEx(string pchURL, string pchCookieName, System.Text.StringBuilder pchCookieData, ref uint pcchCookieData, int dwFlags, IntPtr lpReserved);
"@
#Create type from source
$WebBrowser = Add-Type -memberDefinition $source -passthru -name WebBrowser -ErrorAction SilentlyContinue
$INTERNET_OPTION_END_BROWSER_SESSION = 42
$INTERNET_OPTION_SUPPRESS_BEHAVIOR   = 81
$INTERNET_COOKIE_HTTPONLY            = 0x00002000
$INTERNET_SUPPRESS_COOKIE_PERSIST    = 3
function Clear-WebBrowser
{
    [cmdletbinding()]
    Param(
    )
    Process
    {
        
        # Clear the cache
        [IntPtr] $optionPointer = [IntPtr]::Zero
        $s =                      [System.Runtime.InteropServices.Marshal]::SizeOf($INTERNET_OPTION_END_BROWSER_SESSION)
        $optionPointer =          [System.Runtime.InteropServices.Marshal]::AllocCoTaskMem($s)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($optionPointer, ([ref]$INTERNET_SUPPRESS_COOKIE_PERSIST).Value)
        $status =                 $WebBrowser::InternetSetOption([IntPtr]::Zero, $INTERNET_OPTION_SUPPRESS_BEHAVIOR, $optionPointer, $s)
        Write-Debug "Clearing Web browser cache. Status:$status"
        [System.Runtime.InteropServices.Marshal]::Release($optionPointer)|out-null

        # Clear the current session
        $status = $WebBrowser::InternetSetOption([IntPtr]::Zero, $INTERNET_OPTION_END_BROWSER_SESSION, [IntPtr]::Zero, 0)
        Write-Debug "Clearing Web browser. Status:$status"
    }
}

function Get-WebBrowserCookies
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Url
    )
    Process
    {
        $dataSize = 1024
        $cookieData = [System.Text.StringBuilder]::new($dataSize)
        $status = $WebBrowser::InternetGetCookieEx($Url,$null,$cookieData, [ref]$dataSize, $INTERNET_COOKIE_HTTPONLY, [IntPtr]::Zero)
        Write-Debug "GETCOOKIEEX Status: $status, length: $($cookieData.Length)"
        if(!$status)
        {
            $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Debug "GETCOOKIEEX ERROR: $LastError"
        }

        if($cookieData.Length -gt 0)
        {
            $cookies = $cookieData.ToString()
            Write-Debug "Cookies for $url`: $cookies"
            Return $cookies
        }
        else
        {
            Write-Warning "Cookies not found for $url"
        }

    }
}


## GENERAL ADMIN API FUNCTIONS

# Gets Office 365 instance names (used when getting ip addresses)
function Get-EndpointInstances
{
<#
    .SYNOPSIS
    Get Office 365 endpoint instances

    .DESCRIPTION
    Get Office 365 endpoint instances
  
    .Example
    PS C:\>Get-AADIntEndpointInstances

    instance     latest    
    --------     ------    
    Worldwide    2018100100
    USGovDoD     2018100100
    USGovGCCHigh 2018100100
    China        2018100100
    Germany      2018100100

#>

    [cmdletbinding()]
    Param()
    Process
    {
        $clientrequestid=(New-Guid).ToString();
        Invoke-RestMethod -UseBasicParsing -Uri "https://endpoints.office.com/version?clientrequestid=$clientrequestid"
    }
}

# Gets Office 365 ip addresses for specific instance
function Get-EndpointIps
{
<#
    .SYNOPSIS
    Get Office 365 endpoint ips and urls

    .DESCRIPTION
    Get Office 365 endpoint ips and urls

    .Parameter Instance
    The instance which ips and urls are returned. Defaults to WorldWide.
  
    .Example
    PS C:\>Get-AADIntEndpointIps

    id                     : 1
    serviceArea            : Exchange
    serviceAreaDisplayName : Exchange Online
    urls                   : {outlook.office.com, outlook.office365.com}
    ips                    : {13.107.6.152/31, 13.107.9.152/31, 13.107.18.10/31, 13.107.19.10/31...}
    tcpPorts               : 80,443
    expressRoute           : True
    category               : Optimize
    required               : True

    id                     : 2
    serviceArea            : Exchange
    serviceAreaDisplayName : Exchange Online
    urls                   : {smtp.office365.com}
    ips                    : {13.107.6.152/31, 13.107.9.152/31, 13.107.18.10/31, 13.107.19.10/31...}
    tcpPorts               : 587
    expressRoute           : True
    category               : Allow
    required               : True

    .Example
    PS C:\>Get-AADIntEndpointIps -Instance Germany

    id                     : 1
    serviceArea            : Exchange
    serviceAreaDisplayName : Exchange Online
    urls                   : {outlook.office.de}
    ips                    : {51.4.64.0/23, 51.5.64.0/23}
    tcpPorts               : 80,443
    expressRoute           : False
    category               : Optimize
    required               : True

    id                     : 2
    serviceArea            : Exchange
    serviceAreaDisplayName : Exchange Online
    urls                   : {r1.res.office365.com}
    tcpPorts               : 80,443
    expressRoute           : False
    category               : Default
    required               : True
#>
    [cmdletbinding()]
    Param(
        [Parameter()]
        [ValidateSet('Worldwide','USGovDoD','USGovGCCHigh','China','Germany')]
        [String]$Instance="Worldwide"
    )
    Process
    {
        $clientrequestid=(New-Guid).ToString();
        Invoke-RestMethod -UseBasicParsing -Uri ("https://endpoints.office.com/endpoints/$Instance"+"?clientrequestid=$clientrequestid")
    }
}

# Gets username from authorization header
# Apr 4th 2019
function Get-UserNameFromAuthHeader
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Auth
    )
    
    Process
        {
        $type = $Auth.Split(" ")[0]
        $data = $Auth.Split(" ")[1]

        if($type -eq "Basic")
        {
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($data))).Split(":")[0]
        }
        else
        {
            (Read-Accesstoken -AccessToken $data).upn
        }
    }
}

# Creates authorization header from Credentials or AccessToken
# Apr 4th 2019
function Create-AuthorizationHeader
{
    Param(
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter()]
        [String]$AccessToken,
        [Parameter()]
        [String]$Resource,
        [Parameter()]
        [String]$ClientId
    )

    Process
    {
    
        if($Credentials -ne $null)
        {
            $userName = $Credentials.UserName
            $password = $Credentials.GetNetworkCredential().Password
            $auth = "Basic $([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($userName):$($password)")))"
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource $Resource -ClientId $ClientId
            $auth = "Bearer $AccessToken"
        }

        return $auth
    }
}


# Gets Microsoft online services' public keys
# May 18th 2020
function Get-APIKeys
{
    [cmdletbinding()]
    Param(
        [Parameter()]
        [String]$KeyId
    )
    Process
    {
        $keys=Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/common/discovery/keys"

        if($KeyId)
        {
            $keys.keys | Where-Object -Property kid -eq $KeyId | Select-Object -ExpandProperty x5c
        }
        else
        {
            $keys.keys
        }
        
    }
}

# Gets the AADInt credentials cache
# Jun 14th 2020
function Get-Cache
{
<#
    .SYNOPSIS
    Dumps AADInternals credentials cache

    .DESCRIPTION
    Dumps AADInternals credentials cache
    
    .EXAMPLE
    Get-AADIntCache | Format-Table

    Name              ClientId                             Audience                             Tenant                               IsExpired HasRefreshToken
    ----              --------                             --------                             ------                               --------- ---------------
    admin@company.com 1b730954-1685-4b74-9bfd-dac224a7b894 https://graph.windows.net            82205ae4-4c4e-4db5-890c-cb5e5a98d7a3     False            True
    admin@company.com 1b730954-1685-4b74-9bfd-dac224a7b894 https://management.core.windows.net/ 82205ae4-4c4e-4db5-890c-cb5e5a98d7a3     False            True
#>
    [cmdletbinding()]
    Param()
    Process
    {
        $cacheKeys = $script:tokens.keys

        # Loop through the cache elements
        foreach($key in $cacheKeys)
        {
            $accessToken=$script:tokens[$key]

            if([string]::IsNullOrEmpty($accessToken))
            {
                Write-Warning "Access token with key ""$key"" not found!"
                return
            }

            $parsedToken = Read-Accesstoken -AccessToken $accessToken

            $attributes = [ordered]@{
                "Name" =            $parsedToken.unique_name
                "ClientId" =        $parsedToken.appid
                "Audience" =        $parsedToken.aud
                "Tenant" =          $parsedToken.tid
                "IsExpired" =       Is-AccessTokenExpired -AccessToken $accessToken
                "HasRefreshToken" = $script:refresh_tokens.Contains($key)
                "AuthMethods" =     $parsedToken.amr
                "Device" =          $parsedToken.deviceid
            }

            New-Object psobject -Property $attributes
        }
        
    }
}

# Clears the AADInt credentials cache
# Jun 14th 2020
function Clear-Cache
{
<#
    .SYNOPSIS
    Clears AADInternals credentials cache

    .DESCRIPTION
    Clears AADInternals credentials cache
    
    .EXAMPLE
    Clear-AADIntCache
#>
    [cmdletbinding()]
    Param()
    Process
    {
        $script:tokens =         @{}
        $script:refresh_tokens = @{}
    }
}

# Gets other domains of the given tenant
# Jun 15th 2020
function Get-TenantDomains
{
<#
    .SYNOPSIS
    Gets other domains from the tenant of the given domain

    .DESCRIPTION
    Uses Exchange Online autodiscover service to retrive other 
    domains from the tenant of the given domain. 

    The given domain SHOULD be Managed, federated domains are not always found for some reason. 
    If nothing is found, try to use <domain>.onmicrosoft.com

    .Example
    Get-AADIntTenantDomains -Domain company.com

    company.com
    company.fi
    company.co.uk
    company.onmicrosoft.com
    company.mail.onmicrosoft.com

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        # Create the body
        $body=@"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<soap:Header>
		<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
		<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
	</soap:Header>
	<soap:Body>
		<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
			<Request>
				<Domain>$Domain</Domain>
			</Request>
		</GetFederationInformationRequestMessage>
	</soap:Body>
</soap:Envelope>
"@
        # Create the headers
        $headers=@{
            "Content-Type" = "text/xml; charset=utf-8"
            "SOAPAction" =   '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"'
            "User-Agent" =   "AutodiscoverClient"
        }
        # Invoke
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -uri "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc" -Body $body -Headers $headers

        # Return
        $response.Envelope.body.GetFederationInformationResponseMessage.response.Domains.Domain | Sort-Object
    }
}

# Gets the auth_redirect url for the given client and resource
# Aug 12th 2021
function Get-AuthRedirectUrl
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$ClientId,
        [Parameter(Mandatory=$True)]
        [String]$Resource
    )
    Process
    {
        # default
        $redirect_uri = "urn:ietf:wg:oauth:2.0:oob"

        if($ClientId -eq "1fec8e78-bce4-4aaf-ab1b-5451cc387264")     # Teams
        {
            $redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
        }
        elseif($ClientId -eq "9bc3ab49-b65d-410a-85ad-de819febfddc") # SPO
        {
            $redirect_uri = "https://oauth.spops.microsoft.com/"
        }
        elseif($ClientId -eq "c44b4083-3bb0-49c1-b47d-974e53cbdf3c") # Azure admin interface
        {
            $redirect_uri = "https://portal.azure.com/signin/index/?feature.prefetchtokens=true&feature.showservicehealthalerts=true&feature.usemsallogin=true"
        }
        elseif($ClientId -eq "0000000c-0000-0000-c000-000000000000") # Azure AD Account
        {
            $redirect_uri = "https://account.activedirectory.windowsazure.com/"
        }
        elseif($ClientId -eq "19db86c3-b2b9-44cc-b339-36da233a3be2") # My sign-ins
        {
            $redirect_uri = "https://mysignins.microsoft.com"
        }
        elseif($ClientId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" -and $Resource -ne "https://enrollment.manage.microsoft.com/") # Azure AD Join
        {
            $redirect_uri = "ms-aadj-redir://auth/drs"
        }
        elseif($ClientId -eq "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa") # Azure Android App
        {
            $redirect_uri = "https://azureapp"
        }
        elseif($ClientId -eq "33be1cef-03fb-444b-8fd3-08ca1b4d803f") # OneDrive Web
        {
            $redirect_uri = "https://admin.onedrive.com/"
        }
        elseif($ClientId -eq "ab9b8c07-8f02-4f72-87fa-80105867a763") # OneDrive native client
        {
            $redirect_uri = "https://login.windows.net/common/oauth2/nativeclient"
        }
        elseif($ClientId -eq "3d5cffa9-04da-4657-8cab-c7f074657cad") # MS Commerce
        {
            $redirect_uri = "http://localhost/m365/commerce"
        }
        elseif($ClientId -eq "4990cffe-04e8-4e8b-808a-1175604b879f") # MS Partner - this flow doesn't work as expected :(
        {
            $redirect_uri = "https://partner.microsoft.com/aad/authPostGateway"
        }
        elseif($ClientId -eq "fb78d390-0c51-40cd-8e17-fdbfab77341b") # Microsoft Exchange REST API Based Powershell
        {
            $redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
        }
		elseif($ClientId -eq "3b511579-5e00-46e1-a89e-a6f0870e2f5a") 
        {
            $redirect_uri = "https://windows365.microsoft.com/signin-oidc"
        }
        

        return $redirect_uri
    }
}
