# This script contains functions for handling access tokens
# and some utility functions

# VARIABLES

# Unix epoch time (1.1.1970)
$epoch = Get-Date -Day 1 -Month 1 -Year 1970 -Hour 0 -Minute 0 -Second 0 -Millisecond 0

# Well known client ids
$client_ids=@{
    "graph_api"=   "1b730954-1685-4b74-9bfd-dac224a7b894"
    "aadrm"=       "90f610bf-206d-4950-b61d-37fa6fd1b224"
    "exo"=         "a0c73c16-a7e3-4564-9a95-2bdf47383716"
    "skype"=       "d924a533-3729-4708-b3e8-1d2445af35e3"
    "www"=         "00000006-0000-0ff1-ce00-000000000000"
    "www2"=        "00000003-0000-0ff1-ce00-000000000000"
    "www3"=        "4345a7b9-9a63-4910-a426-35363201d503"
    "aadsync"=     "cb1056e2-e479-49de-ae31-7812af012ed8"
    "synccli"=     "1651564e-7ce4-4d99-88be-0a65050d8dc3"
    "azureadmin" = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
    "pta" =        "cb1056e2-e479-49de-ae31-7812af012ed8"
}

# AccessToken resource strings
$resources=@{
    "aad_graph_api"="https://graph.windows.net"
    "ms_graph_api"= "https://graph.microsoft.com"
    "azure_mgmt_api" = "https://management.azure.com"
    "windows_net_mgmt_api" = "https://management.core.windows.net"
    "cloudwebappproxy" = "https://proxy.cloudwebappproxy.net/registerapp"
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

# Return OAuth information for the given user
function Get-OAuthInfo
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials,
        [ValidateSet('aad_graph_api','ms_graph_api')]
        [String]$Resource="aad_graph_api",
        [ValidateSet('graph_api','aadsync','azureadmin','pta')]
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
            $jsonResponse=Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType $contentType -Method POST -Body $body
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
		                <a:To s:mustUnderstand='1'>https://sts.tampereenseutu.fi/adfs/services/trust/2005/usernamemixed</a:To>
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

            # Verbose
            Write-Verbose "SAML TOKEN: $samlToken"
            Write-Verbose "ENCODED SAML TOKEN: $encodedSamlToken"

            # Create a body for API request
            $body = @{
                "resource"=$resources[$Resource]
                "client_id"=$client_ids["graph_api"]
                "grant_type"="urn:ietf:params:oauth:grant-type:saml1_1-bearer"
                "assertion"=$encodedSamlToken
                "scope"="openid"
            }

            # Verbose
            Write-Verbose "FED AUTHENTICATION BODY: $($body | Out-String)"

            # Set the content type and call the Microsoft Online authentication API
            $contentType="application/x-www-form-urlencoded"
            $jsonResponse=Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType $contentType -Method POST -Body $body
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
        [String]$AccessToken

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

        # Verbose
        Write-Verbose "PARSED ACCESS TOKEN: $($payloadObj | Out-String)"
        
        # Return
        $payloadObj
    }
}

# Gets tenant id from access token
function Get-TenantId
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken

    )
    Process
    {
        # Get the tenant id from token
        $tenant_id=(Read-Accesstoken($AccessToken)).tid

        # Return
        $tenant_id
    }
}


# Prompts for credentials and gets the access token
# Supports MFA, federation, etc.
function Prompt-Credentials
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet('aad_graph_api','ms_graph_api','azureadmin')]
        [String]$Resource="aad_graph_api"
    )
    Process
    {
        

        # Set variables
        $auth_redirect="urn:ietf:wg:oauth:2.0:oob"
        $request_id=(New-Guid).ToString()
        $client_id=$client_ids["graph_api"] # Must always be graph_api
        $url="https://login.microsoftonline.com/common/oauth2/authorize?resource=$($Script:resources[$Resource])&client_id=$client_id&response_type=code&haschrome=1&redirect_uri=$auth_redirect&client-request-id=$request_id&prompt=login"

        # Create the form
        $form = Create-LoginForm -Url $url -auth_redirect $auth_redirect


        # Show the form and wait for the return value
        if($form.ShowDialog() -ne "OK") {
            Write-Verbose "Login cancelled"
            return $null
        }

        # Parse the query string
        $response = [Web.HttpUtility]::ParseQueryString($form.Controls[0].Url.Query)

        # Create a body for REST API request
        $body = @{
            client_id=$client_ids["graph_api"]
            grant_type="authorization_code"
            code=$response["code"]
            redirect_uri=$auth_redirect
        }

        # Verbose
        Write-Verbose "AUTHENTICATION BODY: $($body | Out-String)"

        # Set the content type and call the Microsoft Online authentication API
        $contentType="application/x-www-form-urlencoded"
        $jsonResponse=Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType $contentType -Method POST -Body $body

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
        [ValidateSet('aad_graph_api','ms_graph_api','windows_net_mgmt_api','cloudwebappproxy')]
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
                Throw "No saved tokens. Please call Get-AADIntAccessTokenForAADGraph"
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
    
    .Example
    Get-AADIntAccessTokenForAADGraph
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForAADGraph -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credentials
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "aad_graph_api" -ClientId "graph_api"
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
    
    .Example
    Get-AADIntAccessTokenForMSGraph
    
    .Example
    $cred=Get-Credential
    Get-AADIntAccessTokenForMSGraph -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credentials
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "ms_graph_api" -ClientId "graph_api"
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
    
    .Example
    Get-AADIntAccessTokenForPTA
    
    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>Get-AADIntAccessTokenForPTA -Credentials $cred
#>
    [cmdletbinding()]
    Param(
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credentials
    )
    Process
    {
        Get-AccessToken -Credentials $Credentials -Resource "cloudwebappproxy" -ClientId "pta"
    }
}

# Gets the access token for provisioning API and stores to cache
function Get-AccessToken
{
    [cmdletbinding()]
    Param(
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter()]
        [switch]$UseAdalCache=$false,
        [ValidateSet('aad_graph_api','ms_graph_api','windows_net_mgmt_api','cloudwebappproxy')]
        [String]$Resource="aad_graph_api",
        [ValidateSet('graph_api','aadsync','pta')]
        [String]$ClientId="graph_api"
    )
    Process
    {
        # Check if we want to get AccessToken from ADAL cache
        if($UseAdalCache)
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
            if([string]::IsNullOrEmpty($Credentials))
            {
                # No credentials given, so prompt for credentials
                $OAuthInfo = Prompt-Credentials
            }
            else
            {
                # Get OAuth info for user

                if($ClientId -eq "pta" -or $ClientId -eq "azureadmin" )
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
        $tenant_id=Get-TenantId $AccessToken

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
        if($form.ShowDialog() -ne "OK") {
            Write-Verbose "Login cancelled"
            return $null
        }
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
        [String]$auth_redirect
    )
    Process
    {
    

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

        # Add an event listener to track down where the browser is
        $web.add_Navigated({
            # If the url matches the redirect url, close with OK.
            Write-Verbose "NAVIGATED TO: $($_.Url.ToString())"
            if($_.Url.ToString().StartsWith($auth_redirect)) {
                $form.DialogResult = "OK"
                $form.Close()
                Write-Verbose "PROMPT CREDENTIALS URL: $_.Url"
            } # Automatically logs in -> need to logout first
            elseif($_.Url.ToString().StartsWith($url)) {
                $form.DialogResult = "Cancel"
                $form.Close()
                Write-Error "Please logout first using Clear-AADIntLiveIdSession."
            }
        })

        # Set the url
        $web.Navigate($url)

        # Return
        return $form
    }
}

# Clear the Forms.WebBrowser data
$source=@"
[DllImport("wininet.dll")]

public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int lpdwBufferLength);
"@
#Create type from source
$wininet = Add-Type -memberDefinition $source -passthru -name ClearBrowser -ErrorAction SilentlyContinue
$INTERNET_OPTION_END_BROWSER_SESSION = 42;
function Clear-WebBrowser
{
    [cmdletbinding()]
    Param(
    )
    Process
    {
        $wininet::InternetSetOption([IntPtr]::Zero, $INTERNET_OPTION_END_BROWSER_SESSION, [IntPtr]::Zero, 0)|out-null
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