﻿# This script contains functions for handling access tokens
# and some utility functions

# VARIABLES

# Unix epoch time (1.1.1970)
$epoch = Get-Date -Day 1 -Month 1 -Year 1970 -Hour 0 -Minute 0 -Second 0 -Millisecond 0

# FOCI client ids
# Ref: https://github.com/secureworks/family-of-client-ids-research/blob/main/known-foci-clients.csv

$FOCIs = @{
    "00b41c95-dab0-4487-9791-b9d2c32c80f2" = "Office 365 Management"
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46" = "Microsoft Azure CLI"
    "1950a258-227b-4e31-a9cf-717495945fc2" = "Microsoft Azure PowerShell"
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264" = "Microsoft Teams"
    "26a7ee05-5602-4d76-a7ba-eae8b7b67941" = "Windows Search"
    "27922004-5251-4030-b22d-91ecd9a37ea4" = "Outlook Mobile"
    "4813382a-8fa7-425e-ab75-3b753aab3abb" = "Microsoft Authenticator App"
    "ab9b8c07-8f02-4f72-87fa-80105867a763" = "OneDrive SyncEngine"
    "d3590ed6-52b3-4102-aeff-aad2292ab01c" = "Microsoft Office"
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1" = "Visual Studio"
    "af124e86-4e96-495a-b70a-90f90ab96707" = "OneDrive iOS App"
    "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8" = "Microsoft Bing Search for Microsoft Edge"
    "844cca35-0656-46ce-b636-13f48b0eecbd" = "Microsoft Stream Mobile Native"
    "87749df4-7ccf-48f8-aa87-704bad0e0e16" = "Microsoft Teams - Device Admin Agent"
    "cf36b471-5b44-428c-9ce7-313bf84528de" = "Microsoft Bing Search"
    "0ec893e0-5785-4de6-99da-4ed124e5296c" = "Office UWP PWA"
    "22098786-6e16-43cc-a27d-191a01a1e3b5" = "Microsoft To-Do client"
    "4e291c71-d680-4d0e-9640-0a3358e31177" = "PowerApps"
    "57336123-6e14-4acc-8dcf-287b6088aa28" = "Microsoft Whiteboard Client"
    "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0" = "Microsoft Flow"
    "66375f6b-983f-4c2c-9701-d680650f588f" = "Microsoft Planner"
    "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223" = "Microsoft Intune Company Portal"
    "a40d7d7d-59aa-447e-a655-679a4107e548" = "Accounts Control UI"
    "a569458c-7f2b-45cb-bab9-b7dee514d112" = "Yammer iPhone"
    "b26aadf8-566f-4478-926f-589f601d9c74" = "OneDrive"
    "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12" = "Microsoft Power BI"
    "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0" = "SharePoint"
    "e9c51622-460d-4d3d-952d-966a5b1da34c" = "Microsoft Edge"
    "eb539595-3fe1-474e-9c1d-feb3625d1be5" = "Microsoft Tunnel"
    "ecd6b820-32c2-49b6-98a6-444530e5a77a" = "Microsoft Edge"
    "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d" = "SharePoint Android"
    "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34" = "Microsoft Edge"
    "be1918be-3fe3-4be9-b32b-b542fc27f02e" = "M365 Compliance Drive Client"
    "cab96880-db5b-4e15-90a7-f3f1d62ffe39" = "Microsoft Defender Platform"
    "d7b530a4-7680-4c23-a8bf-c52c121d2e87" = "Microsoft Edge Enterprise New Tab Page"
    "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3" = "Microsoft Defender for Mobile"
    "e9b154d0-7658-433b-bb25-6b8e0a8a7c59" = "Outlook Lite"
}

# Resource ids
$RESIDs = @{
    "00000003-0000-0000-c000-000000000000" = "https://graph.microsoft.com"
}

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

        $subScope = Get-TenantSubscope -Domain $UserName.Split("@")[1]

        # Gather login information using different APIs
        $realm1=Get-UserRealm -UserName $UserName -SubScope $subScope         # common/userrealm API 1.0
        $realm2=Get-UserRealmExtended -UserName $UserName -SubScope $subScope # common/userrealm API 2.0
        $realm3=Get-UserRealmV2 -UserName $UserName -SubScope $subScope       # GetUserRealm.srf (used in the old Office 365 login experience)
        $realm4=Get-CredentialType -UserName $UserName -SubScope $subScope    # common/GetCredentialType (used in the "new" Office 365 login experience)

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
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$webSession,
        [Parameter(Mandatory=$False)]
        [String]$SubScope
    )
    Process
    {
        # Call the API
        $userRealm=Invoke-RestMethod -UseBasicParsing -Uri ("$(Get-TenantLoginUrl -SubScope $SubScope)/common/userrealm/$UserName"+"?api-version=1.0") -WebSession $webSession -Headers @{"User-agent" = Get-UserAgent}

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
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [String]$SubScope
    )
    Process
    {
        # Call the API
        $userRealm=Invoke-RestMethod -UseBasicParsing -Uri ("$(Get-TenantLoginUrl -SubScope $SubScope)/common/userrealm/$UserName"+"?api-version=2.0") -Headers @{"User-agent" = Get-UserAgent}

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
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [String]$SubScope
    )
    Process
    {
       # Call the API
        $userRealm=Invoke-RestMethod -UseBasicParsing -Uri ("$(Get-TenantLoginUrl -SubScope $SubScope)/GetUserRealm.srf?login=$UserName") -Headers @{"User-agent" = Get-UserAgent}

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
        [String]$FlowToken,
        [Parameter(Mandatory=$False)]
        [String]$OriginalRequest,
        [Parameter(Mandatory=$False)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$webSession,
        [Parameter(Mandatory=$False)]
        [String]$SubScope
    )
    Process
    {
        # Create a body for REST API request
        $body = @{
            "username"=$UserName
            "isOtherIdpSupported"   = $true
	        "checkPhones"           = $true
	        "isRemoteNGCSupported"  = $true
	        "isCookieBannerShown"   = $false
	        "isFidoSupported"       = $true
            "isAccessPassSupported" = $true
            "originalRequest"       = $OriginalRequest
            "flowToken"             = $FlowToken
        }

        # TAP support can only be requested if originalRequest is provided. Otherwise we'll get error code 6000.
        if(![string]::IsNullOrEmpty($OriginalRequest))
        {
            $body["isAccessPassSupported"] = $true
        }

        
      
        # Call the API
        $userRealm=Invoke-RestMethod -UseBasicParsing -Uri ("$(Get-TenantLoginUrl -SubScope $SubScope)/common/GetCredentialType") -ContentType "application/json; charset=UTF-8" -Method POST -Body ($body|ConvertTo-Json) -WebSession $webSession -Headers @{"User-agent" = Get-UserAgent}

        # Verbose & Debug
        Write-Verbose "CREDENTIAL TYPE: Exist=$($userRealm.IfExistsResult), Federated=$(![string]::IsNullOrEmpty($userRealm.Credentials.FederationRedirectUrl))"
        Write-Debug "CREDENTIAL TYPE: $($userRealm | Out-String)"

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
        $openIdConfig=Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/$domain/.well-known/openid-configuration" -Headers @{"User-agent" = Get-UserAgent}

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
                $TenantId = (Invoke-RestMethod -UseBasicParsing -Uri "https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain=$domain" -Headers @{"User-agent" = Get-UserAgent}).TenantId
            }
            catch
            {
                return $null
            }

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

            $signBytes = Convert-B64ToByteArray -B64 $signature

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
        [String]$ClientId="1b730954-1685-4b74-9bfd-dac224a7b894",
        [Parameter(Mandatory=$False)]
        [bool]$CAE
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

        # Set Continuous Access Evaluation (CAE) token claims
        if($CAE)
        {
            $body["claims"] = Get-CAEClaims
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

# Prompts for credentials and gets the access token
# Supports MFA.
function Prompt-Credentials
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$Resource,
        [Parameter(Mandatory=$False)]
        [String]$ClientId,
        [Parameter(Mandatory=$True)]
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [bool]$ForceMFA=$false,
        [Parameter(Mandatory=$False)]
        [bool]$ForceNGCMFA=$false,
        [Parameter(Mandatory=$False)]
        [string]$RefreshTokenCredential,
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP,
        [Parameter(Mandatory=$False)]
        [string]$RedirectURI,
        [Parameter(Mandatory=$False)]
        [string]$SubScope,
        [Parameter(Mandatory=$False)]
        [string]$ESTSAUTH,
        [Parameter(Mandatory=$False)]
        [bool]$CAE
    )
    Process
    {
        # Set AMR values as needed
        $amr = $null
        if($ForceMFA)
        {
            $amr = "mfa"
        }
        elseif($ForceNGCMFA)
        {
            $amr = "ngcmfa"
        }

        # If we have credentials, try first using ROPC flow
        $response = $null
        if($Credentials -and [string]::IsNullOrEmpty($amr) -and [string]::IsNullOrEmpty((Get-CredentialType -UserName $Credentials.UserName).Credentials.FederationRedirectUrl))
        {

            Write-Verbose "Domain not federated, credentials provided, and no MFA enforced. Trying ROPC flow."

            # Create a body for REST API request
            $body = @{
                "resource"=$Resource
                "client_id"=$ClientId
                "grant_type"="password"
                "username"=$Credentials.UserName
                "password"=$Credentials.GetNetworkCredential().Password
                "scope"="openid"
            }

            # Set Continuous Access Evaluation (CAE) token claims
            if($CAE)
            {
                $body["claims"] = Get-CAEClaims
            }

            # Debug
            Write-Debug "AUTHENTICATION BODY: $($body | Out-String)"

            # Set the content type and call the Microsoft Online authentication API
			# Headers
			$headers = @{
				"Content-Type" = "application/x-www-form-urlencoded"
				"User-Agent"   = Get-UserAgent
			}
            try
            {
                $response=Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/$tenant/oauth2/token" -Method POST -Body $body -Headers $headers
            }
            catch
            {
                Write-Verbose "ROPC failed, switching to interactive flow: $(($_.ErrorDetails.Message | convertfrom-json).error_description)"
            }
        }

        if($null -eq $response)
        {
            # Check the tenant
            if([string]::IsNullOrEmpty($Tenant))
            {
                $Tenant = "common"
            }

            # Get the authorization code
            $authorizationCode = Get-AuthorizationCode -Resource $Resource -ClientId $ClientId -Tenant $Tenant -AMR $amr -RefreshTokenCredential $RefreshTokenCredential -Credentials $Credentials -OTPSecretKey $OTPSecretKey -TAP $TAP -RedirectURI $RedirectURI -SubScope $SubScope -ESTSAUTH $ESTSAUTH

            if($authorizationCode)
            {

                if([string]::IsNullOrEmpty($RedirectURI))
                {
                    $RedirectURI = Get-AuthRedirectUrl -ClientId $ClientId -Resource $Resource
                }

                # Construct the body for auth code grant
                $body = @{
                    client_id    = $ClientId
                    grant_type   = "authorization_code"
                    code         = $authorizationCode
                    redirect_uri = $RedirectURI
                }

                # Set Continuous Access Evaluation (CAE) token claims
                if($CAE)
                {
                    $body["claims"] = Get-CAEClaims
                }


                # Headers
                $headers = @{
                    "Content-Type" = "application/x-www-form-urlencoded"
                    "User-Agent"   = Get-UserAgent
                }
                
                $response = Invoke-RestMethod -UseBasicParsing -Uri "$(Get-TenantLoginUrl -SubScope $SubScope)/$Tenant/oauth2/token" -Method POST -Body $body -Headers $headers
            }
        }

        # return 
        return $response
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

            if($parsedToken.xms_mirid)
            {
                # Managed identity
                $name = $parsedToken.xms_mirid.Substring($parsedToken.xms_mirid.LastIndexOf("/")+1)
            }
            else
            {
                $name = $parsedToken.unique_name
            }

            $attributes = [ordered]@{
                "Name" =            $name
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

# Adds an access and refresh token to cache
# Aug 30th 2022
function Add-AccessTokenToCache
{
<#
    .SYNOPSIS
    Adds the given access token to AADInternals credentials cache

    .DESCRIPTION
    Adds the given access token to AADInternals credentials cache
    
    .PARAMETER AccessToken
    The access token to add

    .PARAMETER RefreshToken
    The refresh token to add

    .EXAMPLE
    Add-AADIntAccessTokenToCache -AccessToken "eyJ0eXAiOiJKV..." 

    Name              ClientId                             Audience                             Tenant                               IsExpired HasRefreshToken
    ----              --------                             --------                             ------                               --------- ---------------
    admin@company.com 1b730954-1685-4b74-9bfd-dac224a7b894 https://graph.windows.net            82205ae4-4c4e-4db5-890c-cb5e5a98d7a3     False            False

    .EXAMPLE
    Add-AADIntAccessTokenToCache -AccessToken "eyJ0eXAiOiJKV..." -RefreshToken "0.AXkAnZT_xZYmaEueEwVfGe..."

    Name              ClientId                             Audience                             Tenant                               IsExpired HasRefreshToken
    ----              --------                             --------                             ------                               --------- ---------------
    admin@company.com 1b730954-1685-4b74-9bfd-dac224a7b894 https://graph.windows.net            82205ae4-4c4e-4db5-890c-cb5e5a98d7a3     False            True
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$RefreshToken,
        [Parameter(Mandatory=$False)]
        [boolean]$ShowCache = $true
    )
    Process
    {
        # Parse the token
        $parsedToken = Read-Accesstoken -AccessToken $accessToken
        $clientId = $parsedToken.appid
        $resource = $parsedToken.aud.TrimEnd("/")

        # Add to cache
        $Script:tokens["$clientId-$resource"] = $AccessToken
        if(![string]::IsNullOrEmpty($RefreshToken))
        {
            Add-RefreshTokenToCache -ClientId $clientId -Resource $resource -RefreshToken $RefreshToken
        }
        
        # Dump the cache
        if($ShowCache)
        {
            Get-Cache
        }
    }
}

# Adds refresh token to cache
# Apr 25th 2023
function Add-RefreshTokenToCache
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$RefreshToken,
        [Parameter(Mandatory=$True)]
        [String]$ClientId,
        [Parameter(Mandatory=$True)]
        [String]$Resource
    )
    Process
    {
        # Strip the trailing slash
        $Resource = $Resource.TrimEnd("/")
        $Script:refresh_tokens["$ClientId-$Resource"] = $RefreshToken
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
        [String]$Domain,
        [Parameter(Mandatory=$False)]
        [String]$SubScope
    )
    Process
    {
        # Get Tenant Region subscope from Open ID configuration if not provided
        if([string]::IsNullOrEmpty($SubScope))
        {
            $SubScope = Get-TenantSubscope -Domain $Domain
        }

        # Use the correct url
        switch($SubScope)
        {
            "DOD" # DoD
            {
                $uri = "https://autodiscover-s-dod.office365.us/autodiscover/autodiscover.svc"
            }
            "DODCON" # GCC-High
            {
                $uri = "https://autodiscover-s.office365.us/autodiscover/autodiscover.svc"
            }
            default # Commercial/GCC
            {
                $uri = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
            }
        }

        # Create the body
        $body=@"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<soap:Header>
		<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
		<a:To soap:mustUnderstand="1">$uri</a:To>
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
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -uri $uri -Body $body -Headers $headers

        # Return
		$domains = @($response.Envelope.body.GetFederationInformationResponseMessage.response.Domains.Domain)
		if($Domain -notin $domains)
        {
            $domains += $Domain
        }
        $domains | Sort-Object
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
    Begin
    {
        $oobClients = @(
            "d3590ed6-52b3-4102-aeff-aad2292ab01c" # Microsoft Office
            "29d9ed98-a469-4536-ade2-f981bc1d605e" # Microsoft Authentication Broker
            "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223" # Microsoft Intune Company Portal
            )
    }
    Process
    {
        # default
        $redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient"

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
        elseif($ClientId -eq "fb78d390-0c51-40cd-8e17-fdbfab77341b" -or # Microsoft Exchange REST API Based Powershell
               $ClientId -eq "fdd7719f-d61e-4592-b501-793734eb8a0e" -or # SharePoint Migration Tool
               $ClientId -eq "a0c73c16-a7e3-4564-9a95-2bdf47383716")    # EXO PS
        {
            $redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
        }
		elseif($ClientId -eq "3b511579-5e00-46e1-a89e-a6f0870e2f5a") 
        {
            $redirect_uri = "https://windows365.microsoft.com/signin-oidc"
        }
        elseif($ClientId -eq "08e18876-6177-487e-b8b5-cf950c1e598c") # SharePoint Online Web Client Extensibility
        {
            $redirect_uri = "https://*-admin.sharepoint.com/_forms/spfxsinglesignon.aspx"
        }
        elseif($ClientId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" -and $Resource -ne "https://enrollment.manage.microsoft.com/") # AADJoin
        {
                $auth_redirect="ms-aadj-redir://auth/drs"
        }
        elseif($ClientId -eq "dd762716-544d-4aeb-a526-687b73838a22") # WHfB?
        {
            $redirect_uri = "ms-appx-web://microsoft.aad.brokerplugin/dd762716-544d-4aeb-a526-687b73838a22"
        }
        elseif($ClientId -eq "4765445b-32c6-49b0-83e6-1d93765276ca") # Office Web UI
        {
            $redirect_uri = "https://www.office.com/landingv2"
        }
        elseif($oobClients -contains $ClientId)
        {
            $redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
        }

        return $redirect_uri
    }
}

# Gets RST token 
# Mar 3rd 2023
function Get-RSTToken
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='UserNameAndPassword',Mandatory=$True)]
        [String]$UserName,
        [Parameter(ParameterSetName='UserNameAndPassword',Mandatory=$False)]
        [String]$Password,
        [Parameter(Mandatory=$True)]
        [String]$EndpointAddress,
        [Parameter(Mandatory=$True)]
        [String]$Url
    )
    Process
    {
        If([String]::IsNullOrEmpty($UserName))
        {
            $UserName = $Credentials.UserName
            $Password = $Credentials.GetNetworkCredential().password
        }
        $requestId = (New-Guid).ToString()

        $now = Get-Date
        $created = $now.toUniversalTime().toString("o")
        $expires = $now.addMinutes(10).toUniversalTime().toString("o")

        
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
                <wsse:Username>$UserName</wsse:Username>
                <wsse:Password>$Password</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id='RST0'>
                <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                    <wsp:AppliesTo>
                        <wsa:EndpointReference>
                            <wsa:Address>$EndpointAddress</wsa:Address>
                        </wsa:EndpointReference>
                    </wsp:AppliesTo>
                    <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
            </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>
"@
        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Uri $url -Method Post -Body $body -ErrorAction SilentlyContinue
            $tokenResponse = $response.Envelope.Body.RequestSecurityTokenResponse
            if($tokenResponse)
            {
                switch($tokenResponse.TokenType)
                {
                    # DesktopSSOToken when EndpointAddress is:
                    # urn:federation:MicrosoftOnline
                    ("urn:oasis:names:tc:SAML:1.0:assertion")
                    {
                        $token = $tokenResponse.RequestedSecurityToken.Assertion.DesktopSsoToken
                        break
                    }
                    # Passport Compact when EndpointAddress is one of:
                    # officeapps.live.com
                    # sharepoint.com
                    ("urn:passport:compact")
                    {
                        $token = $tokenResponse.RequestedSecurityToken.BinarySecurityToken.'#text'
                        break
                    }
                    # Passport Legacy when EndpointAddress is:
                    # http://Passport.NET/tb
                    ("urn:passport:legacy")
                    {
                        # TODO: Try to figure out how this is encrypted
                        $cipherData = $tokenResponse.RequestedSecurityToken.EncryptedData.CipherData.CipherData
                        $keyName    = $tokenResponse.RequestedSecurityToken.EncryptedData.KeyInfo.KeyName
                        $encAlg     = $tokenResponse.RequestedSecurityToken.EncryptedData.EncryptionMethod.Algorithm

                        Write-Warning "Unable to decrypt legacy passport token, returning encrypted token"
                        $token = $cipherData
                        break
                    }
                }

                return $token
            }
            else
            {
                $errorDetails = $response.Envelope.Body.Fault.Detail.error.internalerror.text
            }
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
        throw $errorDetails
    }
}


# Checks whether the client is a FOCI clientid 
# Apr 25th 2023
function IsFOCI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [guid]$ClientId,
        [Parameter(Mandatory=$False)]
        [int]$FOCI = -1
        )
    Process
    {
        # If FOCI = 1 this is 100% a FOCI client

        # Is this a known FOCI client?
        $isFOCI = $Script:FOCIs.ContainsKey($ClientId.ToString())

        Write-Verbose "FOCI: Known FOCI $isFOCI, FOCI indicator $FOCI"
        
        # Is this a new or deprecated FOCI client?
        if($isFOCI -and $FOCI -eq 0)
        {
            # Found in FOCI list, but no FOCI indicator present
            Write-Warning "Found deprecated FOCI client $ClientId. Please report at https://github.com/secureworks/family-of-client-ids-research"
            $isFOCI = $False
        }
        elseif ($FOCI -eq 1 -and -not $isFOCI)
        {
            # Not found on FOCI list, but FOCI indicator present
            Write-Warning "Found a new FOCI client $ClientId. Please report at https://github.com/secureworks/family-of-client-ids-research"
            $Script:FOCIs[$ClientId] = "UNKNOWN"
            $isFOCI = $True
        }

        return $isFOCI
    }
}

# Lists FOCI clients 
# Apr 26th 2023
function Get-FOCIClientIDs
{
<#
    .SYNOPSIS
    Dumps the list of known FOCI client ids

    .DESCRIPTION
    Dumps the list of Family of known Client IDs (FOCI) client ids

    .Parameter Online
    Get's list online from https://raw.githubusercontent.com/secureworks/family-of-client-ids-research/main/known-foci-clients.csv

    .Example
    PS C:\>Get-AADIntFOCIClientIDs

    client_id                            application_name                        
    ---------                            ----------------                        
    00b41c95-dab0-4487-9791-b9d2c32c80f2 Office 365 Management                   
    04b07795-8ddb-461a-bbee-02f9e1bf7b46 Microsoft Azure CLI                     
    1950a258-227b-4e31-a9cf-717495945fc2 Microsoft Azure PowerShell              
    1fec8e78-bce4-4aaf-ab1b-5451cc387264 Microsoft Teams                         
    26a7ee05-5602-4d76-a7ba-eae8b7b67941 Windows Search                          
    27922004-5251-4030-b22d-91ecd9a37ea4 Outlook Mobile                          
    4813382a-8fa7-425e-ab75-3b753aab3abb Microsoft Authenticator App             
    ab9b8c07-8f02-4f72-87fa-80105867a763 OneDrive SyncEngine                     
    d3590ed6-52b3-4102-aeff-aad2292ab01c Microsoft Office                        
    872cd9fa-d31f-45e0-9eab-6e460a02d1f1 Visual Studio                           
    af124e86-4e96-495a-b70a-90f90ab96707 OneDrive iOS App                        
    2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8 Microsoft Bing Search for Microsoft Edge
    844cca35-0656-46ce-b636-13f48b0eecbd Microsoft Stream Mobile Native          
    87749df4-7ccf-48f8-aa87-704bad0e0e16 Microsoft Teams - Device Admin Agent    
    cf36b471-5b44-428c-9ce7-313bf84528de Microsoft Bing Search                   
    0ec893e0-5785-4de6-99da-4ed124e5296c Office UWP PWA                          
    22098786-6e16-43cc-a27d-191a01a1e3b5 Microsoft To-Do client                  
    4e291c71-d680-4d0e-9640-0a3358e31177 PowerApps                               
    57336123-6e14-4acc-8dcf-287b6088aa28 Microsoft Whiteboard Client             
    57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0 Microsoft Flow                          
    66375f6b-983f-4c2c-9701-d680650f588f Microsoft Planner                       
    9ba1a5c7-f17a-4de9-a1f1-6178c8d51223 Microsoft Intune Company Portal         
    a40d7d7d-59aa-447e-a655-679a4107e548 Accounts Control UI                     
    a569458c-7f2b-45cb-bab9-b7dee514d112 Yammer iPhone                           
    b26aadf8-566f-4478-926f-589f601d9c74 OneDrive                                
    c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12 Microsoft Power BI                      
    d326c1ce-6cc6-4de2-bebc-4591e5e13ef0 SharePoint                              
    e9c51622-460d-4d3d-952d-966a5b1da34c Microsoft Edge                          
    eb539595-3fe1-474e-9c1d-feb3625d1be5 Microsoft Tunnel                        
    ecd6b820-32c2-49b6-98a6-444530e5a77a Microsoft Edge                          
    f05ff7c9-f75a-4acd-a3b5-f4b6a870245d SharePoint Android                      
    f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34 Microsoft Edge

    .Example
    PS C:\>Get-AADIntFOCIClientIDs -Online

    client_id                            application_name                        
    ---------                            ----------------                        
    00b41c95-dab0-4487-9791-b9d2c32c80f2 Office 365 Management                   
    04b07795-8ddb-461a-bbee-02f9e1bf7b46 Microsoft Azure CLI                     
    1950a258-227b-4e31-a9cf-717495945fc2 Microsoft Azure PowerShell              
    1fec8e78-bce4-4aaf-ab1b-5451cc387264 Microsoft Teams                         
    26a7ee05-5602-4d76-a7ba-eae8b7b67941 Windows Search                          
    27922004-5251-4030-b22d-91ecd9a37ea4 Outlook Mobile                          
    4813382a-8fa7-425e-ab75-3b753aab3abb Microsoft Authenticator App             
    ab9b8c07-8f02-4f72-87fa-80105867a763 OneDrive SyncEngine                     
    d3590ed6-52b3-4102-aeff-aad2292ab01c Microsoft Office                        
    872cd9fa-d31f-45e0-9eab-6e460a02d1f1 Visual Studio                           
    af124e86-4e96-495a-b70a-90f90ab96707 OneDrive iOS App                        
    2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8 Microsoft Bing Search for Microsoft Edge
    844cca35-0656-46ce-b636-13f48b0eecbd Microsoft Stream Mobile Native          
    87749df4-7ccf-48f8-aa87-704bad0e0e16 Microsoft Teams - Device Admin Agent    
    cf36b471-5b44-428c-9ce7-313bf84528de Microsoft Bing Search                   
    0ec893e0-5785-4de6-99da-4ed124e5296c Office UWP PWA                          
    22098786-6e16-43cc-a27d-191a01a1e3b5 Microsoft To-Do client                  
    4e291c71-d680-4d0e-9640-0a3358e31177 PowerApps                               
    57336123-6e14-4acc-8dcf-287b6088aa28 Microsoft Whiteboard Client             
    57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0 Microsoft Flow                          
    66375f6b-983f-4c2c-9701-d680650f588f Microsoft Planner                       
    9ba1a5c7-f17a-4de9-a1f1-6178c8d51223 Microsoft Intune Company Portal         
    a40d7d7d-59aa-447e-a655-679a4107e548 Accounts Control UI                     
    a569458c-7f2b-45cb-bab9-b7dee514d112 Yammer iPhone                           
    b26aadf8-566f-4478-926f-589f601d9c74 OneDrive                                
    c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12 Microsoft Power BI                      
    d326c1ce-6cc6-4de2-bebc-4591e5e13ef0 SharePoint                              
    e9c51622-460d-4d3d-952d-966a5b1da34c Microsoft Edge                          
    eb539595-3fe1-474e-9c1d-feb3625d1be5 Microsoft Tunnel                        
    ecd6b820-32c2-49b6-98a6-444530e5a77a Microsoft Edge                          
    f05ff7c9-f75a-4acd-a3b5-f4b6a870245d SharePoint Android                      
    f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34 Microsoft Edge
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$Online
        )
    Process
    {
        if($Online)
        {
            try
            {
                $FOCIClients = Invoke-RestMethod -UseBasicParsing -Uri "https://raw.githubusercontent.com/secureworks/family-of-client-ids-research/main/known-foci-clients.csv"
                ConvertFrom-Csv -Delimiter "," -InputObject $FOCIClients
            }
            catch
            {
                Throw "Unable to get FOCI clients from https://raw.githubusercontent.com/secureworks/family-of-client-ids-research/main/known-foci-clients.csv"
            }
        }
        else
        {
            foreach($key in $Script:FOCIs.Keys)
            {
                [PSCustomObject]@{
                    "client_id" = $key
                    "application_name" = $Script:FOCIs[$key]
                    }
            }
        }
    }
}

# Parses config from login.microsoftonline.com sites
# May 28th 2023
function Parse-LoginMicrosoftOnlineComConfig
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Body
    )
    Process
    {
        # Try to get the $Config=
        $c = Get-StringBetween -String $body -Start '$Config=' -End "//]]>"
        
        try
        {
            # Trim null, carriage return, newline, and ;
            $c = $c.TrimEnd(@(0x00,0x0a,0x0d,0x3B))
            $j = $c | ConvertFrom-Json -ErrorAction SilentlyContinue

            # Some verbose
            if($j.serverDetails)
            {
                $s = $j.serverDetails
                Write-Verbose "SERVER: $($s.dc) $($s.ri) $($s.ver.v -join ".")"
            }
            if($j.correlationId)
            {
                Write-Verbose "Correlation ID: $($j.correlationId)"
            }
            if($j.sessionId)
            {
                Write-Verbose "Session ID: $($j.sessionId)"
            }
        }
        catch
        {}

        return $j
    }
}

# Gets authorization code in interactive mode - Supports MFA
# May 28th 2023
# OAuth 2.0 Auth code grant flow
function Get-AuthorizationCode
{
    [cmdletbinding()]
    Param(
        # Use these default values to get the code as some tenants may have blocked others with Conditional Access.
        # You can then use the refresh_token to get access_token for correct resource and clientid.
        [Parameter(Mandatory=$False)]
        [String]$Resource = "https://graph.windows.net",
        [Parameter(Mandatory=$True)]
        [String]$ClientId = "1b730954-1685-4b74-9bfd-dac224a7b894",

        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [string]$AMR,
        [Parameter(Mandatory=$False)]
        [string]$RefreshTokenCredential,
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$False)]
        [string]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [string]$OTPSecretKey,
        [Parameter(Mandatory=$False)]
        [string]$TAP,
        [Parameter(Mandatory=$False)]
        [string]$RedirectURI,
        [Parameter(Mandatory=$False)]
        [switch]$AppConsent,
        [Parameter(Mandatory=$False)]
        [string]$SubScope,
        [Parameter(Mandatory=$False)]
        [string]$ESTSAUTH,
        [Parameter(Mandatory=$False)]
        [switch]$DumpESTSAUTH,
        [Parameter(Mandatory=$False)]
        [boolean]$KMSI
    )
    Begin
    {
        # Function for processing ADFS authentication
        function Process-ADFSLogin
        {
            [cmdletbinding()]
            Param(
                [Parameter(Mandatory=$False)]
                [System.Management.Automation.PSCredential]$Credentials,
                [Parameter(Mandatory=$False)]
                [String]$UserName,
                [Parameter(Mandatory=$False)]
                [Microsoft.PowerShell.Commands.WebRequestSession]$webSession,
                [Parameter(Mandatory=$True)]
                [String]$FederationRedirectUrl,
                [Parameter(Mandatory=$False)]
                [string]$SubScope
            )
            Process
            {
                # If authentication type is Federated, we must first authenticate against the identity provider
                # to fetch SAML token and then get access token from Microsoft Online
    
                if($Credentials)
                {
                    $UserName = $Credentials.UserName
                }
                
                # Only ADFS is supported
                if(!$FederationRedirectUrl.Contains("/adfs/"))
                {
                    Throw "Only ADFS federation is supported."
                }
    
                # Loop until we get a correct password or get CTRL+C
                $passwordOk = $false
                while(-not $passwordOk)
                {
                    # Set credentials
                    if($Credentials)
                    {
                        $password = $Credentials.GetNetworkCredential().Password
                        # Set Credentials to $null to avoid authentication loop
                        $Credentials = $null
                    }
                    # Prompt for password
                    else
                    {
                        $password = Read-HostPassword -Prompt "Password"
                    }

                    if($password -eq $null)
                    {
                        return $null
                    }

                    # Set the parameters
                    $body = @{
                        "UserName"   = $UserName
                        "Kmsi"	     = ""
                        "AuthMethod" = "FormsAuthentication"
                        "Password"	 = $password
                    }
                    try 
                    {
                        # Authenticate
                        $response = Invoke-WebRequest2 -Uri $FederationRedirectUrl -Method POST -Body $body -Headers $Headers -WebSession $webSession
                        [xml]$xmlResponse = $response.content
                        
                        # Extract WS-Fed parameters
                        $body=@{}
                        foreach($input in $xmlResponse.html.body.form.input)
                        {
                            $body[$input.name] = $input.value
                        }
                        $url = "$(Get-TenantLoginUrl -SubScope $SubScope)/login.srf"

                        return Invoke-WebRequest2 -Uri $url -WebSession $webSession -Method Post -MaximumRedirection 0 -ErrorAction SilentlyContinue -Body $body -Headers @{"User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                    }
                    catch
                    {
                        $_
                        # Failed, probably just wrong password
                    }
                    
                }
            }
        }

        # Function for processing password & TAP
        function Process-Login
        {
            [cmdletbinding()]
            Param(
                [Parameter(Mandatory=$False)]
                [System.Management.Automation.PSCredential]$Credentials,
                [Parameter(Mandatory=$False)]
                [boolean]$isTAP = $false,
                [Parameter(Mandatory=$True)]
                [PSObject]$Config,
                [Parameter(Mandatory=$False)]
                [string]$TAP,
                [Parameter(Mandatory=$False)]
                [string]$SubScope,
                [Parameter(Mandatory=$False)]
                [boolean]$KMSI
            )
            Process
            {
                $loginEndPoint = Get-TenantLoginUrl -SubScope $SubScope

                # Loop until we get a correct password/TAP or get CTRL+C
                while(-not $passwordOk)
                {
                    # Use the provided TAP
                    if($isTAP -and -not [string]::IsNullOrEmpty($TAP))
                    {
                        $password = $TAP
                    }
                    # Use the provided credentials
                    elseif($Credentials)
                    {
                        $password = $Credentials.GetNetworkCredential().Password
                    }
                    # Prompt for password/TAP
                    else
                    {
                        $pwdPrompt = "Password"
                        if($isTAP)
                        {
                            $pwdPrompt = "Temporary Access Pass"
                        }
                        
                        $password = Read-HostPassword -Prompt $pwdPrompt
                    }

                    # Send the password/TAP
                    if($config.urlPost.startsWith("/"))
                    {
                        $url = "$($loginEndPoint)$($config.urlPost)"
                    }
                    else
                    {
                        $url = $config.urlPost
                    }

                    # Create the body
                    $body = @{
                        "login"      = $userName
                        "passwd"     = $password
                        "ctx"        = $config.sCtx
                        "flowToken"  = $config.sFT
                        "canary"     = $config.canary
                        "client_id"  = $ClientId
                    }
                    if($KMSI)
                    {
                        $body["LoginOptions"] = 1
                    }
                    if($isTAP)
                    {
                        $body.Remove("passwd")
                        $body["accesspass"] = $password
                    }
                    
                    $response = Invoke-WebRequest2 -Uri $url -WebSession $LoginSession -Method Post -MaximumRedirection 0 -Headers $Headers -Body $body -ErrorAction SilentlyContinue
                                        
                    $config = Parse-LoginMicrosoftOnlineComConfig -Body $response.Content

                    # Return app consent stuff
                    if($config.pgid -eq "ConvergedConsent")
                    {
                        return [pscustomobject]@{
                            "MFA"      = $MFA
                            "Config"   = $Config
                            "Response" = $response
                        }
                    }

                    # Expired password
                    if($config.pgid -eq "ConvergedChangePassword")
                    {
                        Write-Verbose "ConvergedChangePassword"
                        $newPasswordOk = $false

                        while($newPasswordOk -eq $false)
                        {
                            # Prompt for the password
                            Write-Host "You need to update your password because this is the first time you are signing in, or because your password has expired."
                            $newPassword = Read-HostPassword -Prompt "New password"
                            if([string]::IsNullOrEmpty($newPassword))
                            {
                                return $null
                            }
                            
                            # SSPR BEGIN
                            $body = @{
                                "Ctx"          = $config.sCtx
                                "FlowToken"    = $config.sFT
                                "OldPassword"  = $password
                                "NewPassword"  = $newPassword
                            }
                            $url = "$($loginEndPoint)$($config.urlAsyncSsprBegin)"
                            $ssprResponse = Invoke-RestMethod -UseBasicParsing -Uri $url -WebSession $LoginSession -Method Post -MaximumRedirection 0 -ErrorAction SilentlyContinue -Headers $Headers -Body ($body | ConvertTo-Json) -ContentType "application/json; charset=UTF-8"
                            # SSPR POLL
                            while($ssprResponse.IsJobPending)
                            {
                                $body = @{
                                    "Ctx"               = $ssprResponse.Ctx
                                    "FlowToken"         = $ssprResponse.FlowToken
                                    "CoupledDataCenter" = $ssprResponse.CoupledDataCenter
                                    "CoupledScaleUnit"  = $ssprResponse.CoupledScaleUnit
                                }
                                $url = "$($loginEndPoint)$($config.urlAsyncSsprPoll)"
                                $ssprResponse = Invoke-RestMethod -UseBasicParsing -Uri $url -WebSession $LoginSession -Method Post -MaximumRedirection 0 -ErrorAction SilentlyContinue -Headers $Headers -Body ($body | ConvertTo-Json) -ContentType "application/json; charset=UTF-8"
                            }

                            # Complexity requirements..
                            if($ssprResponse.ErrorMessage)
                            {
                                Write-Host $ssprResponse.ErrorMessage -ForegroundColor Red
                            }
                            else
                            {
                                $newPasswordOk = $true
                            }
                        }
                        # SSPR END
                        $body = @{
                            "ctx"              = $ssprResponse.Ctx
                            "flowToken"        = $ssprResponse.FlowToken
                            "currentpasswd"    = $password
                            "confirmnewpasswd" = $newPassword
                            "canary"           = $config.canary
                        }
                        $url = "$($loginEndPoint)$($config.urlPost)"

                        $response = Invoke-WebRequest2 -Uri $url -WebSession $LoginSession -Method Post -MaximumRedirection 0 -Headers $Headers -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction SilentlyContinue
                        $config = Parse-LoginMicrosoftOnlineComConfig -Body $response.Content
                    }

                    # MFA action required
                    if($config.pgid -eq "ConvergedProofUpRedirect")
                    {
                        Write-Verbose "ConvergedProofUpRedirect"
                        $MFADays = $config.iRemainingDaysToSkipMfaRegistration
                        if($MFADays)
                        {
                            Write-Warning "MFA must be set up in $($MFA) days"
                            # Create the body
                            $body = @{
                                "LoginOptions" = 1
                                "ctx"          = $config.sCtx
                                "flowToken"    = $config.sFT
                                "canary"       = $config.canary
                            }

                            $url = $config.urlSkipMfaRegistration
                            $response = Invoke-WebRequest2 -Uri $url -WebSession $LoginSession -MaximumRedirection 0 -Headers $Headers -ErrorAction SilentlyContinue
                        }
                        else
                        {
                            throw "MFA method must be registered."
                        }
                    }
                    # Keep me signed in prompt
                    elseif($config.pgid -eq "KmsiInterrupt")
                    {
                        Write-Verbose "KMSI"
                        # Create the body
                        $body = @{
                            "LoginOptions" = 1
                            "ctx"          = $config.sCtx
                            "flowToken"    = $config.sFT
                            "canary"       = $config.canary
                        }

                        $url = "$($loginEndPoint)$($config.urlPost)"
                        $response = Invoke-WebRequest2 -Uri $url -WebSession $LoginSession -Method Post -MaximumRedirection 0 -Headers $Headers -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction SilentlyContinue
                    }
                    # Some weird redirect issue with non-edge Chrome browsers 
                    elseif($config.oPostParams)
                    {
                        Throw "Chrome redirect issue. Try using Edge or non-chrome User-Agent."
                    }
                    
                    # Check the response code
                    switch($response.StatusCode)
                    {
                        # We got an error or MFA prompt
                        200
                        {
                            $config = Parse-LoginMicrosoftOnlineComConfig -Body $response.Content

                            # Something severe
                            if($config.strServiceExceptionMessage)
                            {
                                # Wrong redirect URI
                                if($config.strServiceExceptionMessage.StartsWith("AADSTS50011"))
                                {
                                    Write-Verbose "Invalid redirect URI, trying to get correct one"
                                    $newRedirectURI=""
                                    try
                                    {
                                        $url = "$($loginEndPoint)/common/oauth2/authorize?client_id=$ClientID&response_type=code"
                                        $response = Invoke-WebRequest2 -Uri $url -WebSession $LoginSession -Method Get -MaximumRedirection 0 -Headers $Headers -ErrorAction SilentlyContinue

                                        # Parse from the Location header
                                        if($response.StatusCode -eq 302)
                                        {
                                            $newRedirectURI = $response.Headers.Location.Substring(0,$response.Headers.Location.IndexOf("?"))
                                            Write-Verbose "Redirect URI: $newRedirectURI"
                                            Write-Warning "Wrong RedirectURI $RedirectURI for client $ClientID."
                                            Write-Warning "Try again with switch -RedirectURI $newRedirectURI"
                                        }
                                        else
                                        {
                                            Write-Error $config.strServiceExceptionMessage
                                        }

                                        return $null
                                    }
                                    catch
                                    {
                                        throw $config.strServiceExceptionMessage
                                    }
                                }
                                else
                                {
                                    throw $config.strServiceExceptionMessage
                                }
                            }
                            # Wrong password etc
                            elseif($config.sErrorCode -ne $null)
                            {
                                # When using TAP for MFA, the correct error code is not returned
                                if($config.sErrorCode -eq "InvalidAccessPass")
                                {
                                    $AADError = "130503: Your Temporary Access Pass is incorrect. If you don't know your pass, contact your administrator."
                                }
                                # Get error text from Azure AD
                                else
                                {
                                    $AADError = Get-Error -ErrorCode $config.sErrorCode
                                }
                                # We don't want to loop with provided password/TAP so throw the error
                                if(($Credentials) -or ($isTAP -and (-not [string]::IsNullOrEmpty($TAP))))
                                {
                                    Throw $AADError
                                }

                                Write-Host $AADError -ForegroundColor Red
                            }
                            # MFA
                            elseif($config.arrUserProofs -ne $null)
                            {
                                $passwordOk = $true
                                $MFA = $true
                            }
                        }
                        # Ok, we got the code!
                        302
                        {
                            $passwordOk = $true
                        }

                    }
        
                }

                return [pscustomobject]@{
                    "MFA"      = $MFA
                    "Config"   = $Config
                    "Response" = $response
                }
            }
        }
    }
    Process
    {
        # Remove variables
        Remove-Variable -Name "LoginSession" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Config" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Response" -ErrorAction SilentlyContinue

        # Load certificate if provided
        if(!$Certificate -and -not [string]::IsNullOrEmpty($PfxFileName))
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        # Create the url
        $loginEndPoint = Get-TenantLoginUrl -SubScope $SubScope
        $request_id=(New-Guid).ToString()

        # Headers
        $headers = @{
            "User-Agent" = Get-UserAgent
        }

        # Get redirect url
        if([string]::IsNullOrEmpty($RedirectURI))
        {
            $RedirectURI = Get-AuthRedirectUrl -ClientId $ClientId -Resource $Resource
        }

        # If ESTSAUTH cookie provided, use that
        # Ref: https://github.com/rvrsh3ll/TokenTactics/pull/9/commits/1a88fe7f01ea88731de4a23c0b3306d4ed714260 
        if(![string]::IsNullOrEmpty($ESTSAUTH))
        {
            $url="$loginEndPoint/common/oauth2/authorize?resource=$Resource&client_id=$ClientId&response_type=code&redirect_uri=$RedirectURI&scope=openid"
            $LoginSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $cookie = [System.Net.Cookie]::new("ESTSAUTHPERSISTENT", $ESTSAUTH)
            $LoginSession.Cookies.Add("$loginEndPoint/", $cookie)
            $response = Invoke-WebRequest -UseBasicParsing -Uri $url -WebSession $LoginSession -Method get -MaximumRedirection 0 -ErrorAction SilentlyContinue -Headers $Headers
            try
            {
                $config = Parse-LoginMicrosoftOnlineComConfig -Body $response.Content
                if($config.pgid -ne $null)
                {
                    $throwMessage = "Unable to get authorization code with ESTSAUTH cookie. Page ID = $($config.pgid). Error = $($config.strServiceExceptionMessage)"
                }
                else
                {
                    return Parse-CodeFromResponse -Response $response 
                }
            }
            catch
            {
                $throwMessage = "Unable to get authorization code with ESTSAUTH cookie"
            }

            if($throwMessage)
            {
                Throw $throwMessage
            }
        }
        # If getting app consent, use different url
        elseif($AppConsent)
        {
            $url="$loginEndPoint/$Tenant/oauth2/authorize?client_id=$ClientId&response_type=code&sso_reload=True"
        }
        else
        {
            $url="$loginEndPoint/$Tenant/oauth2/authorize?resource=$Resource&client_id=$ClientId&response_type=code&redirect_uri=$RedirectURI&client-request-id=$request_id&prompt=login&scope=openid profile&response_mode=query&sso_reload=True"
        }                       

        # Authentication Method References (AMR), "mfa" or "ngcmfa" will enforce MFA
        # Ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapx/0fc398ca-88d0-4118-ae60-c3033e396e60
        if($AMR)
        {
            $url+="&amr_values=$AMR"
        }

        
        # Set RefreshTokenCredential for device authentication
        if($RefreshTokenCredential)
        {
            $headers["x-ms-RefreshTokenCredential"] = $RefreshTokenCredential
            $parsedToken = Read-AccessToken -AccessToken $RefreshTokenCredential
            if($parsedToken.request_nonce)
            {
                $url += "&sso_nonce=$($parsedToken.request_nonce)"
            }
        }

        # Make the first request to authorization endpoint. Allow one redirect for sso_nonce
        $response = Invoke-WebRequest -UseBasicParsing -Uri $url -SessionVariable "LoginSession" -Method get -MaximumRedirection 1 -ErrorAction SilentlyContinue -Headers $Headers

        $config   = Parse-LoginMicrosoftOnlineComConfig -Body $response.Content
        
        # Prompt for user name if not provided
        if($Credentials)
        {
            $userName = $Credentials.UserName
        }
        else
        {
            Write-Host "Logging in to $($config.sCompanyDisplayName)"
            $userName = Read-Host -Prompt "Enter email, phone, or Skype"
        }

        # Get credential type
        $credType = Get-CredentialType -UserName $userName -FlowToken $config.sFT -OriginalRequest $config.sCtx -webSession $LoginSession

        # Check whether we are throttling
        if($credType.ThrottleStatus -eq 1)
        {
            Write-Warning "Requests throttled. If authentication fails, wait a minute and try again."
        }

        # Does the user exist?
        if($credType.IfExistsResult -ne 0 -and $credType.IfExistsResult -ne 6 -and $credType.IfExistsResult -ne 5)
        {
            Throw "We couldn't find an account with that username." 
        }

        # Check the credential type (managed vs federated)
        $isFederated = ![string]::IsNullOrEmpty($credType.Credentials.FederationRedirectUrl)

        # Do the federated domain authentication
        if($isFederated)
        {
            # Create WS-Fed response
            $response = Process-ADFSLogin -Credentials $Credentials -UserName $userName -webSession $loginSession -FederationRedirectUrl $credType.Credentials.FederationRedirectUrl -SubScope $SubScope
           
            switch($response.StatusCode)
            {
                # We got an error or MFA prompt
                200
                {
                    $config = Parse-LoginMicrosoftOnlineComConfig -Body $response.Content

                    # Something severe
                    if($config.strServiceExceptionMessage)
                    {
                        throw $config.strServiceExceptionMessage
                    }
                    # Wrong password etc
                    elseif($config.sErrorCode -ne $null)
                    {
                        # When using TAP for MFA, the correct error code is not returned
                        if($config.sErrorCode -eq "InvalidAccessPass")
                        {
                            $AADError = "130503: Your Temporary Access Pass is incorrect. If you don't know your pass, contact your administrator."
                        }
                        # Get error text from Azure AD
                        else
                        {
                            $AADError = Get-Error -ErrorCode $config.sErrorCode
                        }
                        # We don't want to loop with provided password/TAP so throw the error
                        if($isTAP -and (-not [string]::IsNullOrEmpty($TAP)))
                        {
                            Throw $AADError
                        }

                        Write-Host $AADError -ForegroundColor Red
                    }
                    # MFA
                    elseif($config.arrUserProofs -ne $null)
                    {
                        $MFA = $true
                    }
                }
                # Ok, we got the code!
                302
                {
                    $passwordOk = $true
                }

            }

            #$config   = $loginResponse.Config
            #$MFA      = $loginResponse.MFA
            #$response = $loginResponse.Response
        }
        # Do the managed domain authentication
        else
        {
            # Ask which account to use (MSA or AAD)
            # MSA not supported at the moment, so skip this
            <#
            $accountType = 0 # AAD
            if($credType.IfExistsResult -eq 6)
            {
                $options = @(
                        New-Object System.Management.Automation.Host.ChoiceDescription "&1 Work or school account"
                        New-Object System.Management.Automation.Host.ChoiceDescription "&2 Personal account"
                    )
                $accountType = $host.UI.PromptForChoice("Choose account","It looks like this email is used with more than one account from Microsoft. Which one do you want to use?",$options,0)
            }
            #>

            # Choose authentication method
            $authOptions = @()
            $nAuthOption = 0
            $pwdOption = -2
            $cbaOption = -2
            $tapOption = -2

            # Password?
            if($credType.Credentials.HasPassword -eq $True)
            {
                Write-Verbose "Password enabled."
                $pwdOption = $nAuthOption
                $nAuthOption++
                $authOptions += New-Object System.Management.Automation.Host.ChoiceDescription "&$nAuthOption Password" 
                
            }

            # Temporary Access Pass (TAP)?
            if($credType.Credentials.HasAccessPass -eq $True)
            {
                Write-Verbose "Temporary Access Pass enabled."
                $tapOption = $nAuthOption
                $nAuthOption++
                $authOptions += New-Object System.Management.Automation.Host.ChoiceDescription "&$nAuthOption Temporary Access Pass"
            }

            # Certificate Based Authentication (CBA)?
            if($credType.Credentials.HasCertAuth -eq $True)
            {
                Write-Verbose "CBA enabled."
                if($Certificate)
                {
                    $cbaOption = $nAuthOption
                    $nAuthOption++
                    $authOptions += New-Object System.Management.Automation.Host.ChoiceDescription "&$nAuthOption Certificate"
                }
                else
                {
                    Write-Verbose "No certificate provided, skipping CBA."
                }
            }

            # No supported authentication options found :(
            if($authOptions.Count -eq 0)
            {
                Throw "No supported authentication options found!"
            }
            # Just one option so use that
            elseif($authOptions.Count -eq 1)
            {
                $authOption = 0
            }
            # If we have TAP and it's available, use that
            elseif($tapOption -ge 0 -and -not [string]::IsNullOrEmpty($TAP))
            {
                $authOption = $tapOption
            }
            # Prompt for options
            else
            {
                $authOption = $host.UI.PromptForChoice("Authentication options","Choose authentication method",[System.Management.Automation.Host.ChoiceDescription[]]$authOptions,0)
            }
            
            switch($authOption)
            {
                $pwdOption
                {
                    $cPWD = $true
                }
                $cbaOption
                {
                    $cCBA = $true
                }
                $tapOption
                {
                    $cTAP = $true
                }
                default
                {
                    return $null
                }
            }

            # PWD & TAP
            if($cPWD -or $cTAP)
            {
                $loginResponse = Process-Login -Credentials $Credentials -Config $config -IsTAP ($cTAP -eq $true) -TAP $TAP -SubScope $SubScope -KMSI $KMSI
                if($loginResponse -eq $null)
                {
                    return $null
                }
                $config   = $loginResponse.Config
                $MFA      = $loginResponse.MFA
                $response = $loginResponse.Response
            }
        }

        if($MFA)
        {
            # Get MFA types from the config
            $MFATypes = [ordered]@{}
            $MFAOptions = @()
            $m = 1
            foreach($mfaType in $config.arrUserProofs)
            {
                # Certificate not currently supported
                if($mfaType.authMethodId -ne "Certificate")
                {
                    $MFATypes[$mfaType.authMethodId] = $mfaType.display
                    $MFAOptions += New-Object System.Management.Automation.Host.ChoiceDescription "&$m $($mfaType.authMethodId) ($($mfaType.display))"
                    $m++

                    # If OTPSecret is provided and whe have PhoneAppOTP option, use that
                    if($mfaType.authMethodId -eq "PhoneAppOTP" -and -not [string]::IsNullOrEmpty($OTPSecretKey))
                    {
                        $mfaMethod = $mfaType.authMethodId
                    }
                }
            }

            if($MFAOptions.Count -eq 0)
            {
                Throw "No supported MFA methods found!"
            }
                        
            # Ask user to choose MFA method if not automatically chosen
            if(-not $mfaMethod)
            {
                # If there's just one method, use that
                if($MFATypes.Count -eq 1)
                {
                    $mfaMethod = [string]$MFATypes.Keys[0]
                }
                else
                {
                    $mfaSelection = $host.UI.PromptForChoice("MFA options","Choose MFA method",$MFAOptions,0)
                    if($mfaSelection -eq -1)
                    {
                        return $null
                    }
                    $p = 0
                    foreach($key in $MFATypes.Keys)
                    {
                        if($p -eq $mfaSelection)
                        {
                            $mfaMethod = $key
                            break
                        }
                        $p++
                    }
                }
            }   

            # Start the MFA loop
            $url = $config.urlBeginAuth
            $body = @{
                "AuthMethodId" = $mfaMethod
                "ctx"          = $config.sCtx
                "flowToken"    = $config.sFT
                "Method"       = "BeginAuth"
            }
            # TAP has unique MFA flow
            if($mfaMethod -eq "AccessPass")
            {
                $body["AuthMethodId"] = "PhoneAppOTP"
            }

            $headers = @{
                "User-Agent"   = Get-UserAgent
                "canary"       = $config.apiCanary
                "Content-Type" = "application/json; charset=utf-8"
            }

            # SAS/BeginAuth if not TAP
            if($mfaMethod -eq "AccessPass")
            {
                $beginAuth = $true
            }
            else
            {
                $response = Invoke-RestMethod -UseBasicParsing -Uri $url -WebSession $LoginSession -Method Post -MaximumRedirection 0 -ErrorAction SilentlyContinue -Headers $Headers -Body ($body|ConvertTo-Json)
                $beginAuth = $response.Success -eq $true
            }
            
            if($beginAuth)
            {
                # Prompt for MFA method
                switch($mfaMethod)
                {
                    "PhoneAppNotification"
                    {
                        Write-Host "Open your Authenticator app, and enter the number shown to sign in:​​"
                        Write-Host $response.Entropy
                        break
                    }
                    "PhoneAppOTP"
                    {
                        # Use provided OTPSecret
                        if($OTPSecretKey)
                        {
                            Write-Host "Using the provided OTP Secret for MFA."
                            # Calculate OTP using the secret key
                            $OTP = New-AADIntOTP -SecretKey $OTPSecretKey
                            # Strip the spaces
                            $additionalAuthData = $OTP.OTP.Replace(" ","")
                            break
                        }
                        else
                        {
                            $additionalAuthData = Read-Host "Please type in the code displayed on your authenticator app from your device"
                            break
                        }
                    }
                    "OneWaySMS"
                    {
                        $additionalAuthData = Read-Host "We texted your phone $($MFATypes[$mfaMethod]). Please enter the code to sign in"
                        break
                    }
                    "TwoWayVoiceMobile"
                    {
                        Write-Host "We're calling your phone $($MFATypes[$mfaMethod]). Please answer it to continue."
                        break
                    }
                    "TwoWayVoiceAlternateMobile"
                    {
                        Write-Host "We're calling your phone $($MFATypes[$mfaMethod]). Please answer it to continue."
                        break
                    }
                    "AccessPass"
                    {
                        # TAP has a unique flow
                        $loginResponse = Process-Login -Config $config -IsTAP $true -TAP $TAP
                        
                        if($loginResponse -eq $null)
                        {
                            return $null
                        }
                        $config   = $loginResponse.Config
                        $MFA      = $loginResponse.MFA
                        $response = $loginResponse.Response
                        
                        break
                    }
                    default
                    {
                        Throw "MFA method $mfaMethod not supported."
                        break
                    }
                }

                # SAS/EndAuth
                if($mfaMethod -ne "AccessPass")
                {
                    for($p = 1;$p -le $config.iMaxPollAttempts ; $p++)
                    {
                        # If OTP or SMS send a single request
                        if(@("PhoneAppOTP","OneWaySMS") -contains $mfaMethod)
                        {
                            $url = $config.urlEndAuth

                            $headers = @{
                                "User-Agent"   = Get-UserAgent
                                "canary"       = $config.apiCanary
                                "Content-Type" = "application/json; charset=utf-8"
                            }

                            $body = @{
                                "AdditionalAuthData" = $additionalAuthData
                                "AuthMethodId"       = $mfaMethod
                                "SessionId"          = $response.SessionId
                                "FlowToken"          = $response.FlowToken
                                "Ctx"                = $response.Ctx
                                "Method"             = "EndAuth"
                            }

                            $response = Invoke-RestMethod -UseBasicParsing -Uri $url -WebSession $LoginSession -Method Post -MaximumRedirection 0 -ErrorAction SilentlyContinue -Headers $Headers -Body ($body | ConvertTo-Json)
                        }
                        # Poll until we get response or timeout
                        else
                        {
                            $url = "$($config.urlEndAuth)?authMethodId=$mfaMethod&pollCount=$p"

                            $headers = @{
                                "User-Agent"     = Get-UserAgent
                                "x-ms-sessionId" = $response.SessionId
                                "x-ms-flowToken" = $response.FlowToken
                                "x-ms-ctx"       = $response.Ctx
                            }

                            $response = Invoke-RestMethod -UseBasicParsing -Uri $url -WebSession $LoginSession -Method Get -MaximumRedirection 0 -ErrorAction SilentlyContinue -Headers $Headers
                        }
                        if($response.Success -eq $true)
                        {
                            # SAS/ProcessAuth
                            $headers = @{
                                "User-Agent"   = Get-UserAgent
                                "Content-Type" = "application/x-www-form-urlencoded"
                            }

                            $url = $config.urlPost

                            $body = @{
                                "request"       = $response.Ctx
                                "mfaAuthMethod" = $mfaMethod
                                "login"         = $userName
                                "flowToken"     = $response.FlowToken
                                "canary"        = $config.canary
                            }

                            $response = Invoke-WebRequest2 -Uri $url -WebSession $LoginSession -Method Post -MaximumRedirection 0 -Headers $Headers -Body $body -ErrorAction SilentlyContinue

                            break
                        }
                        elseif($response.Retry -eq $false)
                        {
                            Throw "$($response.Message) $($response.ResultValue)"
                        }
                        Start-Sleep -Milliseconds $config.iPollingInterval
                    }
                }
            }
        }

        # Dump app consent stuff
        if($AppConsent)
        {
            return $config
        }

        # Some weird redirect again
        if($response.Content.Contains("https://device.login.microsoftonline.com"))
        {
            Write-Warning "Got an error, try using another User-Agent, current is: $(Get-UserAgent)"
            throw "Got unexpected redirect to https://device.login.microsoftonline.com"
        }

        # Check for errors
        $config = Parse-LoginMicrosoftOnlineComConfig -Body $response.Content
        if($config.strServiceExceptionMessage)
        {
            Write-Warning "Got an error, try using another User-Agent, current is: $(Get-UserAgent)"
            throw $config.strServiceExceptionMessage
        }
        elseif($config.sErrorCode -ne $null)
        {
            $AADError = Get-Error -ErrorCode $config.sErrorCode
            throw $AADError
        }

        $authorizationCode = Parse-CodeFromResponse -Response $response
        
        # Try to dump the ESTS cookies
        if($DumpESTSAUTH)
        {
            $cookieName = "ESTSAUTH"
            if($KMSI)
            {
                $cookieName += "PERSISTENT"
            }

            Write-Verbose "Trying to dump $cookieName cookie"

            try
            {
                foreach($cookie in $LoginSession.Cookies.GetCookies((Get-TenantLoginUrl -SubScope $SubScope)))
                {
                    if($cookie.Name -eq $cookieName)
                    {
                        return $cookie.Value
                    }
                }
            }
            catch {}
        }

        return $authorizationCode
    }
}

# May 21st 2024
# Return tenant subscope from Open ID configuration
function Get-TenantSubscope
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Domain',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='Config',Mandatory=$True)]
        [PSObject]$OpenIDConfiguration
    )
    Process
    {
        # Get Tenant Region subscope from Open ID configuration
        if($OpenIDConfiguration -eq $null)
        {
            $OpenIDConfiguration = Get-OpenIDConfiguration -Domain $Domain
        }

        return $OpenIDConfiguration.tenant_region_sub_scope
    }
}

# May 21st 2024
# Return tenant login url based on the subscope
function Get-TenantLoginUrl
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [String]$SubScope
    )
    Process
    {
        # Use the correct url
        switch($SubScope)
        {
            "DOD" # DoD
            {
                return "https://login.microsoftonline.us"
            }
            "DODCON" # GCC-High
            {
                return "https://login.microsoftonline.us"
            }
            default # Commercial/GCC
            {
                return "https://login.microsoftonline.com"
            }
        }
    }
}

# Jan 13th 2025
# Get access token using MSAL
function Get-AccessTokenUsingMSAL
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [String]$TenantId="common",
        [Parameter(Mandatory=$true)]
        [String]$Resource,
        [Parameter(Mandatory=$true)]
        [String]$ClientId,
        [Parameter(Mandatory=$false)]
        [String]$RedirectUri,
        [Parameter(Mandatory=$false)]
        [String]$SubScope,
        [Parameter(Mandatory=$false)]
        [bool]$CAE
    )
    Begin
    {
        # Load MSAL dll
        Add-Type -Path "$PSScriptRoot\Microsoft.Identity.Client.dll"
    }
    Process
    {
        if([string]::IsNullOrEmpty($RedirectUri))
        {
            $RedirectUri = Get-AuthRedirectUrl -ClientId $ClientId -Resource $Resource
        }

        $options = [Microsoft.Identity.Client.PublicClientApplicationOptions]::new()
        $options.ClientId    = $ClientId
        $options.TenantId    = $TenantId
        $options.RedirectUri = $RedirectUri
        $options.AzureCloudInstance = Get-MSALAzureScope -SubScope $SubScope

        if($CAE)
        {
            $options.ClientCapabilities = [string[]]"cp1"
        }

        $builder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::CreateWithApplicationOptions($options)
        $app = $builder.Build()
        $tokenParameters = $app.AcquireTokenInteractive([string[]]"$Resource/.default")
        $result = $tokenParameters.ExecuteAsync()

        return $result.Result
    }
}


# Jan 13th 2025
# Returns MSAL Azure Scope based on subscope
function Get-MSALAzureScope
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [String]$SubScope
    )
    Process
    {
        # Return AzureCloudInstance
        # Ref: https://learn.microsoft.com/en-us/dotnet/api/microsoft.identity.client.azurecloudinstance?view=msal-dotnet-latest
        switch($SubScope)
        {
            "DOD" # DoD
            {
                return 4
            }
            "DODCON" # GCC-High
            {
                return 4
            }
            default # Commercial/GCC
            {
                return 1
            }
        }
    }
}

# Returns CAE claims
# Feb 5th 2024
function Get-CAEClaims
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [String]$SubScope
    )
    Process
    {
        # Claims
        $claims = @{
            "access_token" = @{
                "xms_cc" = @{
                    "values" = @("cp1")
                }
            }
            "id_token" = @{
                "xms_cc" = @{
                    "values" = @("cp1")
                }
            }
        }

        return ConvertTo-Json -InputObject $claims -Depth 10 -Compress
    }
}
