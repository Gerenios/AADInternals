# This script contains functions for handling access tokens
# and some utility functions

# VARIABLES

# Unix epoch time (1.1.1970)
$epoch = Get-Date -Day 1 -Month 1 -Year 1970 -Hour 0 -Minute 0 -Second 0 -Millisecond 0

# Well known client ids
$client_ids=@{
    "graph_api"=            "1b730954-1685-4b74-9bfd-dac224a7b894" # MS Graph API
    "aadrm"=                "90f610bf-206d-4950-b61d-37fa6fd1b224" 
    "exo"=                  "a0c73c16-a7e3-4564-9a95-2bdf47383716" # EXO Remote PowerShell
    "skype"=                "d924a533-3729-4708-b3e8-1d2445af35e3" 
    "www"=                  "00000006-0000-0ff1-ce00-000000000000"
    "o365spo"=              "00000003-0000-0ff1-ce00-000000000000" # SharePoint Online
    "o365exo"=              "00000002-0000-0ff1-ce00-000000000000" # Exchange Online
    "dynamicscrm"=          "00000007-0000-0000-c000-000000000000" # Dynamics CRM
    "o365suiteux"=          "4345a7b9-9a63-4910-a426-35363201d503" # O365 Suite UX
    "aadsync"=              "cb1056e2-e479-49de-ae31-7812af012ed8" # Azure AD Sync
    "synccli"=              "1651564e-7ce4-4d99-88be-0a65050d8dc3"
    "azureadmin" =          "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" # Azure Admin web ui
    "pta" =                 "cb1056e2-e479-49de-ae31-7812af012ed8" # Pass-through authentication
    "patnerdashboard" =     "4990cffe-04e8-4e8b-808a-1175604b879"  # Partner dashboard (missing on letter?)
    "webshellsuite" =       "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7" 
    "teams" =               "1fec8e78-bce4-4aaf-ab1b-5451cc387264" # Teams
    "office" =              "d3590ed6-52b3-4102-aeff-aad2292ab01c" # Office, ref. https://docs.microsoft.com/en-us/office/dev/add-ins/develop/register-sso-add-in-aad-v2
    "office_online2" =      "57fb890c-0dab-4253-a5e0-7188c88b2bb4" # Office Online
    "office_online" =       "bc59ab01-8403-45c6-8796-ac3ef710b3e3" # Office Online
    "powerbi_contentpack" = "2a0c3efa-ba54-4e55-bdc0-770f9e39e9ee" 
    "aad_account" =         "0000000c-0000-0000-c000-000000000000" # https://account.activedirectory.windowsazure.com
    "sara" =                "d3590ed6-52b3-4102-aeff-aad2292ab01c" # Microsoft Support and Recovery Assistant (SARA)
    "office_mgmt" =         "389b1b32-b5d5-43b2-bddc-84ce938d6737" # Office Management API Editor https://manage.office.com 
    "onedrive" =            "ab9b8c07-8f02-4f72-87fa-80105867a763" # OneDrive Sync Engine
}

# AccessToken resource strings
$resources=@{
    "aad_graph_api"=         "https://graph.windows.net"
    "ms_graph_api"=          "https://graph.microsoft.com"
    "azure_mgmt_api" =       "https://management.azure.com"
    "windows_net_mgmt_api" = "https://management.core.windows.net"
    "cloudwebappproxy" =     "https://proxy.cloudwebappproxy.net/registerapp"
    "officeapps" =           "https://officeapps.live.com"
    "outlook" =              "https://outlook.office365.com"
    "webshellsuite" =        "https://webshell.suite.office.com"
    "sara" =                 "https://api.diagnostics.office.com"
    "office_mgmt" =          "https://manage.office.com"
}

# Stored tokens (access & refresh)
$tokens=@{}
$aad_graph_tokens=$null
$ms_graph_tokens=$null

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
        $userRealm=Invoke-RestMethod -Uri ("https://login.microsoftonline.com/common/userrealm/$UserName"+"?api-version=1.0")

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
        $userRealm=Invoke-RestMethod -Uri ("https://login.microsoftonline.com/common/userrealm/$UserName"+"?api-version=2.0")

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
        $userRealm=Invoke-RestMethod -Uri ("https://login.microsoftonline.com/GetUserRealm.srf?login=$UserName")

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
        $userRealm=Invoke-RestMethod -Uri ("https://login.microsoftonline.com/common/GetCredentialType") -ContentType "application/json; charset=UTF-8" -Method POST -Body ($body|ConvertTo-Json)

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
        $openIdConfig=Invoke-RestMethod "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"

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

# Gets OAuth information using SAML token
function Get-OAuthInfoUsingSAML
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$SAMLToken,
        [ValidateSet('aad_graph_api','ms_graph_api')]
        [String]$Resource="aad_graph_api",
        [ValidateSet('graph_api','aadsync','azureadmin','pta','teams','office','exo','office_mgmt')]
        [String]$ClientId="graph_api"
    )
    Process
    {
        $encodedSamlToken= [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($SAMLToken))
        # Verbose
        Write-Verbose "SAML TOKEN: $samlToken"
        Write-Verbose "ENCODED SAML TOKEN: $encodedSamlToken"

        # Create a body for API request
        $body = @{
            "resource"=$resources[$Resource]
            "client_id"=$client_ids[$ClientId]
            "grant_type"="urn:ietf:params:oauth:grant-type:saml1_1-bearer"
            "assertion"=$encodedSamlToken
            "scope"="openid"
        }

        # Verbose
        Write-Verbose "FED AUTHENTICATION BODY: $($body | Out-String)"

        # Set the content type and call the Microsoft Online authentication API
        $contentType="application/x-www-form-urlencoded"
        try
        {
            $jsonResponse=Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType $contentType -Method POST -Body $body
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
        [ValidateSet('aad_graph_api','ms_graph_api')]
        [String]$Resource="aad_graph_api",
        [ValidateSet('graph_api','aadsync','azureadmin','pta','teams','office','exo','office_mgmt')]
        [String]$ClientId="graph_api"
    )
    Process
    {
        # Get the user realm
        $userRealm = Get-UserRealm($Credentials.UserName)

        # Check the authentication type
        if($userRealm.account_type -eq "Managed")
        {
            # If authentication type is managed, we authenticate directly against Microsoft Online
            # with user name and password to get access token

            # Create a body for REST API request
            $body = @{
                "resource"=$resources[$Resource]
                "client_id"=$client_ids[$ClientId]
                "grant_type"="password"
                "username"=$Credentials.UserName
                "password"=$Credentials.GetNetworkCredential().Password
                "scope"="openid"
            }

            # Verbose
            Write-Verbose "AUTHENTICATION BODY: $($body | Out-String)"

            # Set the content type and call the Microsoft Online authentication API
            $contentType="application/x-www-form-urlencoded"
            try
            {
                $jsonResponse=Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType $contentType -Method POST -Body $body
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
            [xml]$response=Invoke-RestMethod -Uri $federation_metadata_url 

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

            # Verbose
            Write-Verbose "FED AUTHENTICATION HEADERS: $($headers | Out-String)"
            
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
            # Verbose
            Write-Verbose "FED AUTHENTICATION: $envelope"

            # Set the content type and call the authentication service            
            $contentType="application/soap+xml"
            [xml]$xmlResponse=Invoke-RestMethod -Uri $federation_url -ContentType $contentType -Method POST -Body $envelope -Headers $headers

            # Get the SAML token from response and encode it with Base64
            $samlToken=$xmlResponse.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.Assertion.OuterXml
            $encodedSamlToken= [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($samlToken))

            $jsonResponse = Get-OAuthInfoUsingSAML -SAMLToken $samlToken -Resource $Resource -ClientId $ClientId
        }
        
        # Verbose
        Write-Verbose "AUTHENTICATION JSON: $($jsonResponse | Out-String)"

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

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter()]
        [Switch]$ShowDate

    )
    Process
    {
        # Get only the token payload
        $payload = $AccessToken.Split(".")[1]

        # Fill with padding for Base 64 decoding
        while ($payload.Length % 4)
        {
            $payload += "="
        }

        # Convert the token to string and json
        $payloadBytes=[System.Convert]::FromBase64String($payload)
        $payloadArray=[System.Text.Encoding]::ASCII.GetString($payloadBytes)
        $payloadObj=$payloadArray | ConvertFrom-Json

        if($ShowDate)
        {
            # Show dates
            $payloadObj.exp=($epoch.Date.AddSeconds($payloadObj.exp)).toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
            $payloadObj.iat=($epoch.Date.AddSeconds($payloadObj.iat)).toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
            $payloadObj.nbf=($epoch.Date.AddSeconds($payloadObj.nbf)).toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")

        }

        # Verbose
        Write-Verbose "PARSED ACCESS TOKEN: $($payloadObj | Out-String)"
        
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
        [ValidateSet('aad_graph_api','ms_graph_api','azureadmin','outlook','sara')]
        [String]$Resource="aad_graph_api",
        [ValidateSet('graph_api','aadsync','azureadmin','pta','teams','office','exo','sara')]
        [String]$ClientId="graph_api",
        [Parameter(Mandatory=$False)]
        [String]$Tenant
    )
    Process
    {
        # Check the tenant
        if([String]::IsNullOrEmpty($Tenant))        
        {
            $Tenant = "common"
        }

        # Set variables
        $auth_redirect="urn:ietf:wg:oauth:2.0:oob"
        $client_id=$client_ids[$ClientId] # Usually should be graph_api
        
        if($Resource -eq "teams")
        {
            # We are logging in as Teams, so need to use different auth_redirect
            $auth_redirect="https://teams.office.com"
        }
        
        $request_id=(New-Guid).ToString()
        
        $url="https://login.microsoftonline.com/$Tenant/oauth2/authorize?resource=$($Script:resources[$Resource])&client_id=$client_id&response_type=code&haschrome=1&redirect_uri=$auth_redirect&client-request-id=$request_id&prompt=login&scope=openid profile"

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

        # Verbose
        Write-Verbose "AUTHENTICATION BODY: $($body | Out-String)"

        # Set the content type and call the Microsoft Online authentication API
        $contentType="application/x-www-form-urlencoded"
        $jsonResponse=Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token" -ContentType $contentType -Method POST -Body $body

        # return 
        $jsonResponse
    }
}

# Tries to get access token from cache unless provided as parameter
function Get-AccessTokenFromCache
{
    [cmdletbinding()]
    Param(
        [Parameter()]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [ValidateSet('aad_graph_api','ms_graph_api','windows_net_mgmt_api','cloudwebappproxy','officeapps','outlook','azureportal','office_mgmt')]
        [String]$Resource="aad_graph_api"
    )
    Process
    {
        # Check if we got the AccessToken as parameter
        if([string]::IsNullOrEmpty($AccessToken))
        {
            # Check if cache is empty
            if([string]::IsNullOrEmpty($Script:tokens[$Resource]))
            {
                # Empty, so throw the exception
                Throw "No saved tokens. Please call Get-AADIntAccessTokenFor<service>"
            }
            else
            {
                $retVal=$Script:tokens[$Resource].access_token
            }
        }
        else
        {
            # Just return the passed access token
            $retVal=$AccessToken
        }

        # Check the expiration
        if(Is-AccessTokenExpired($retVal))
        {
            throw "AccessToken has expired"
        }

        # Return
        return $retVal
    }
}

# Gets the access token for AAD Graph API
function Get-AccessTokenForAADGraph
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for AAD Graph

    .DESCRIPTION
    Gets OAuth Access Token for AAD Graph, which is used for example in Provisioning API.
    If credentials are not given, prompts for credentials (supports MFA).

    .Parameter Credentials
    Credentials of the user. If not given, credentials are prompted.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos ticket

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Example
    Get-AADIntAccessTokenForAADGraph
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForAADGraph -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(Mandatory=$False)]
        [String]$Tenant
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "aad_graph_api" -ClientId "graph_api" -SAMLToken $SAMLToken -Tenant $Tenant -KerberosTicket $KerberosTicket -Domain $Domain
    }
}

# Gets the access token for MS Graph API
function Get-AccessTokenForMSGraph
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Microsoft Graph

    .DESCRIPTION
    Gets OAuth Access Token for Microsoft Graph, which is used in Graph API.
    If credentials are not given, prompts for credentials (supports MFA).

    .Parameter Credentials
    Credentials of the user. If not given, credentials are prompted.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Example
    Get-AADIntAccessTokenForMSGraph
    
    .Example
    $cred=Get-Credential
    Get-AADIntAccessTokenForMSGraph -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "ms_graph_api" -ClientId "graph_api" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain
    }
}

# Gets the access token for enabling or disabling PTA
function Get-AccessTokenForPTA
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for PTA

    .DESCRIPTION
    Gets OAuth Access Token for PTA, which is used for example to enable or disable PTA.

    .Parameter Credentials
    Credentials of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Example
    Get-AADIntAccessTokenForPTA
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForPTA -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "cloudwebappproxy" -ClientId "pta" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain
    }
}

# Gets the access token for Office Apps
function Get-AccessTokenForOfficeApps
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Office Apps

    .DESCRIPTION
    Gets OAuth Access Token for Office Apps.

    .Parameter Credentials
    Credentials of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Example
    Get-AADIntAccessTokenForOfficeApps
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForOfficeApps -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "officeapps" -ClientId "graph_api" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain
    }
}

# Gets the access token for Exchange Online
function Get-AccessTokenForEXO
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Exchange Online

    .DESCRIPTION
    Gets OAuth Access Token for Exchange Online

    .Parameter Credentials
    Credentials of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 
    
    .Example
    Get-AADIntAccessTokenForEXO
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForEXO -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        # Office app has the required rights to Exchange Online
        Get-AccessToken -Credentials $Credentials -Resource "outlook" -ClientId "office" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -Domain $Domain
    }
}

# Gets the access token for Exchange Online remote PowerShell
function Get-AccessTokenForEXOPS
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for Exchange Online remote PowerShell

    .DESCRIPTION
    Gets OAuth Access Token for Exchange Online remote PowerShell

    .Parameter Credentials
    Credentials of the user.

    .Parameter SAML
    SAML token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token

    .Parameter KerberosTicket
    Kerberos token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token
    
    .Example
    Get-AADIntAccessTokenForEXOPS
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForEXOPS -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        # Office app has the required rights to Exchange Online
        Get-AccessToken -Credentials $Credentials -Resource "outlook" -ClientId "exo" -SAMLToken $SAMLToken -KerberosTicket $KerberosTicket -UserPrincipalName $UserPrincipalName
    }
}

# Gets the access token for SARA
# Jul 8th 2019
function Get-AccessTokenForSARA
{
<#
    .SYNOPSIS
    Gets OAuth Access Token for SARA

    .DESCRIPTION
    Gets OAuth Access Token for Microsoft Support and Recovery Assistant (SARA)

    .Parameter KerberosTicket
    Kerberos token of the user. 

    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos token. 
    
    .Example
    Get-AADIntAccessTokenForSARA
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForSARA -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$KerberosTicket,
        [Parameter(Mandatory=$False)]
        [String]$Domain
    )
    Process
    {
        # Office app has the required rights to Exchange Online
        Get-AccessToken -Resource "sara" -ClientId "sara" -KerberosTicket $KerberosTicket -Domain $Domain
    }
}

# Gets the access token for provisioning API and stores to cache
function Get-AccessToken
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory=$False)]
        [String]$SAMLToken,
        [Parameter()]
        [switch]$UseAdalCache=$false,
        [ValidateSet('aad_graph_api','ms_graph_api','windows_net_mgmt_api','cloudwebappproxy','officeapps','outlook','sara','office_mgmt')]
        [String]$Resource="aad_graph_api",
        [ValidateSet('graph_api','aadsync','pta','teams','office','exo','sara','office_mgmt')]
        [String]$ClientId="graph_api",
        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [String]$KerberosTicket,
        [Parameter(Mandatory=$False)]
        [String]$Domain
    )
    Process
    {
        # Check if we got the kerberos token
        if(![String]::IsNullOrEmpty($KerberosTicket))
        {
            # Get token using the kerberos token
            $access_token = Get-AccessTokenWithKerberosTicket -KerberosTicket $KerberosTicket -Domain $Domain -Resource $Resource -ClientId $ClientId
        }
        # Check if we want to get AccessToken from ADAL cache
        elseif($UseAdalCache)
        {
            # Items from cache for the given resource
            $cache = [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared
            $adalItems = $cache.ReadItems() | where Resource -eq $Script:resources[$Resource]
            
            # Get the first item
            $adalItem=$adalItems[0]

            $token= @{}
            $token.access_token=$adalItem.AccessToken
            $token.id_token=$adalItem.IdToken
            $token.expires_on=(New-TimeSpan –Start $Script:epoch –End $adalItem.ExpiresOn.Date).TotalSeconds
            $token.resource=$Script:resources[$Resource]

            $upn=$adalItem.DisplayableId
            Write-Verbose "ADAL CACHE: Using cached access token of $upn"

            # Save the tokens to cache
            $Script:tokens[$Resource]=$token

            # Set the access token
            $access_token=$token.access_token
        }
        else
        {
            
            # Check if we got credentials
            if([string]::IsNullOrEmpty($Credentials) -and [string]::IsNullOrEmpty($SAMLToken))
            {
                # No credentials given, so prompt for credentials
                if($ClientId -eq "office" -or $ClientId -eq "exo")
                {
                    $OAuthInfo = Prompt-Credentials -Resource "outlook" -ClientId $ClientId
                }
                else
                {
                    $OAuthInfo = Prompt-Credentials -ClientId $ClientId -Tenant $Tenant
                }
                
            }
            else
            {
                # Get OAuth info for user
                if(![string]::IsNullOrEmpty($SAMLToken))
                {
                    $OAuthInfo = Get-OAuthInfoUsingSAML -SAMLToken $SAMLToken -ClientId $ClientId
                }
                else
                {
                    if($ClientId -eq "pta" -or $ClientId -eq "azureadmin" -or $ClientId -eq "teams" -or $ClientId -eq "office" -or $ClientId -eq "exo" -or $ClientId -eq "office_mgmt")
                    {
                        # Requires same clientId
                        $OAuthInfo = Get-OAuthInfo -Credentials $Credentials -ClientId $ClientId
                    }
                    else
                    {
                        # "Normal" flow
                        $OAuthInfo = Get-OAuthInfo -Credentials $Credentials
                    }
                }
            }

            if([String]::IsNullOrEmpty($OAuthInfo))
            {
                throw "Could not get OAuthInfo!"
            }

            if($ClientId -eq "aadsync")
            {
                # Authentication here is simplier, just use the access token from the previous call
                $access_token=$OAuthInfo.access_token
            }
            else
            {
                # We need to get access token using the refresh token from the previous call

                # Save the refresh token and other variables
                $RefreshToken=$OAuthInfo.refresh_token
                $ParsedToken=Read-Accesstoken($OAuthInfo.access_token)
                $tenant_name = $ParsedToken.unique_name.Split("@")[1] # Not used in this script, we can use both name or id in url below
                $tenant_id = $ParsedToken.tid

                # Set the body for API call
                $body = @{
                    "resource"=$resources[$Resource]
                    "client_id"=$client_ids[$ClientId]
                    "grant_type"="refresh_token"
                    "refresh_token"=$RefreshToken
                    "scope"="openid"
                }

                $id_token = 

                # Verbose
                Write-Verbose "ACCESS TOKEN BODY: $($body | Out-String)"
        
                # Set the content type and call the API
                $contentType="application/x-www-form-urlencoded"
                $response=Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenant_id/oauth2/token" -ContentType $contentType -Method POST -Body $body

                # Verbose
                Write-Verbose "ACCESS TOKEN RESPONSE: $response"

                # Save the tokens to cache
                $Script:tokens[$Resource]=$response

                # Get the access token from response
                $access_token=$response.access_token
            }
        }

        # Return
        if([string]::IsNullOrEmpty($access_token))
        {
            Throw "Could not get Access Token!"
        }
        $access_token
    }
}

# Gets the tenant details 
function Get-TenantDetails
{
<#
    .SYNOPSIS
    Extract tenant details using the given Access Token

    .DESCRIPTION
    Extract tenant details using the given Access Token

    .Parameter AccessToken
    The Access Token. If not given, tries to use cached Access Token.
    
    .Example
    PS C:\>$token=Get-AADIntAccessTokenForAADGraph
    PS C:\>Get-AADIntTenantDetails -AccessToken $token

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken

    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache($AccessToken)
        
        # Get tenant id
        $tenant_id=Get-TenantId -AccessToken $AccessToken

        $headers = @{
            "Authorization"="Bearer $AccessToken"
        }

        # Call the API
        $response=Invoke-RestMethod -Uri "$($Script:resources["aad_graph_api"])/$tenant_id/tenantDetails?api-version=1.6" -Headers $headers

        # Verbose
        Write-Verbose "TENANT INFORMATION: $($response.value | Out-String)"

        # Return
        $response.value
    }
}

# Logins to SharePoint Online and returns an IdentityToken
# TODO: Research whether can be used to get access_token to AADGraph
# TODO: Add support for Google?
# FIX: Web control stays logged in - clear cookies somehow?
# Aug 10th 2018
function Get-IdentityTokenByLiveId
{
<#
    .SYNOPSIS
    Gets identity_token for SharePoint Online for External user

    .DESCRIPTION
    Gets identity_token for SharePoint Online for External user using LiveId.

    .Parameter Tenant
    The tenant name to login in to WITHOUT .sharepoint.com part
    
    .Example
    PS C:\>$id_token=Get-AADIntIdentityTokenByLiveId -Tenant mytenant
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Tenant
    )
    Process
    {
        # Set variables
        $auth_redirect="https://login.microsoftonline.com/common/federation/oauth2" # When to close the form
        $url="https://$Tenant.sharepoint.com"

        # Create the form
        $form=Create-LoginForm -Url $url -auth_redirect $auth_redirect

        # Show the form and wait for the return value
        if($form.ShowDialog() -ne "OK") {
            Write-Verbose "Login cancelled"
            return $null
        }

        $web=$form.Controls[0]

        $code=$web.Document.All["code"].GetAttribute("value")
        $id_token=$web.Document.All["id_token"].GetAttribute("value")
        $session_state=$web.Document.All["session_state"].GetAttribute("value")

        return Read-Accesstoken($id_token)
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

        # Clear WebBrowser control cache
        Clear-WebBrowser

        # Add an event listener to track down where the browser is
        $web.add_Navigated({
            # If the url matches the redirect url, close with OK.
            $curl=$_.Url.ToString()
            Write-Verbose "NAVIGATED TO: $($curl)"
            if($curl.StartsWith($auth_redirect)) {

                # Hack for Azure Portal Login. Jul 11th 2019 
                # Check whether the body has the Bearer
                if(![String]::IsNullOrEmpty($form.Controls[0].Document.GetElementsByTagName("script")))
                {
                    $script=$form.Controls[0].Document.GetElementsByTagName("script").outerhtml
                    if($script.Contains("Bearer")){
                        $s=$script.IndexOf('Bearer ')+7
                        $e=$script.IndexOf('"',$s)
                        $script:AccessToken=$script.Substring($s,$e-$s)
                        Write-Verbose "ACCESSTOKEN $script:accessToken"
                    }
                    elseif($curl.StartsWith("https://portal.azure.com"))
                    {
                        Write-Verbose "WAITING FOR THE TOKEN!"
                        # Do nothing, wait for it..
                        return
                    }
                }
                


                $form.DialogResult = "OK"
                $form.Close()
                Write-Verbose "PROMPT CREDENTIALS URL: $url"
            } # Automatically logs in -> need to logout first
            elseif($curl.StartsWith($url)) {
                # All others
                Write-Warning "Returned to the starting url, someone already logged in?"
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
$INTERNET_OPTION_END_BROWSER_SESSION = 42;
$INTERNET_COOKIE_HTTPONLY = 0x00002000;
function Clear-WebBrowser
{
    [cmdletbinding()]
    Param(
    )
    Process
    {
        
        [IntPtr] $optionPointer = [IntPtr]::Zero
        $s=[System.Runtime.InteropServices.Marshal]::SizeOf($INTERNET_OPTION_END_BROWSER_SESSION)
        $optionPointer = [System.Runtime.InteropServices.Marshal]::AllocCoTaskMem($s)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($optionPointer, ([ref]$INTERNET_OPTION_END_BROWSER_SESSION).Value)
        $status = $WebBrowser::InternetSetOption([IntPtr]::Zero, $INTERNET_OPTION_END_BROWSER_SESSION, [IntPtr]::Zero, 0)
        Write-Verbose "Clearing Web browser cache. Status:$status"

        [System.Runtime.InteropServices.Marshal]::Release($optionPointer)|out-null
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
        Write-Verbose "GETCOOKIEEX Status: $status, length: $($cookieData.Length)"
        if(!$status)
        {
            $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "GETCOOKIEEX ERROR: $LastError"
        }

        if($cookieData.Length -gt 0)
        {
            $cookies = $cookieData.ToString()
            Write-Verbose "Cookies for $url`: $cookies"
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
        Invoke-RestMethod -Uri "https://endpoints.office.com/version?clientrequestid=$clientrequestid"
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
        Invoke-RestMethod -Uri ("https://endpoints.office.com/endpoints/$Instance"+"?clientrequestid=$clientrequestid")
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
        [String]$AccessToken
    )

    Process
        {
    
        if([String]::IsNullOrEmpty($AccessToken))
        {
            $userName = $Credentials.UserName
            $password = $Credentials.GetNetworkCredential().Password
            $auth = "Basic $([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($userName):$($password)")))"
        }
        else
        {
            $auth = "Bearer $AccessToken"
        }

        return $auth
    }
}