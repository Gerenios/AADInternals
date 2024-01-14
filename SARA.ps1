# This script contains functions used in Microsoft Support and Recovery Assistant (SARA)



# Sep 23rd 2021
function Get-SARAUserInfo
{
<#
    .SYNOPSIS
    Gets user information using SARA API

    .DESCRIPTION
    Gets user information using Microsoft Support and Recovery Assistant (SARA) API

    .Parameter AccessToken
    Access Token

    .Example
    $at=Get-AADIntAccessTokenForSARA
    PS C:\>Get-AADIntSARAUserInfo -AccessToken $at

    AnalyzerName          : AnalysisRule, Microsoft.Online.CSE.HRC.Analysis.Analyzers.ExchangeCmdlets.GetUserAnalyzer, Microsoft.Online.CSE.HRC.Analysis.Analyzers.ExchangeCmdlets, Version=16.0.3144.0, Culture=
                            neutral, PublicKeyToken=31bf3856ad364e35
    AnalyzerDesc          : Attempting to get information about user "user@company.com".
    StartTime             : 2019-07-08T12:29:40.4911399Z
    Duration              : 00:00:51.1166849
    CoreDuration          : 00:00:51.1166849
    WaitingDuration       : 00:00:00
    TotalChildrenDuration : 00:00:00
    TotalWaitingDuration  : 00:00:00
    ParentId              : 00000000-0000-0000-0000-000000000000
    Value                 : true
    ResultTitle           : Extracting information about Office 365 user is completed.
    ResultTitleId         : Microsoft.Online.CSE.HRC.Analysis.Analyzers.ExchangeCmdlets.StringsGetUserComplete
    UserMessage           : Successfully got the user information for "user@company.com".
    UserMessageId         : Microsoft.Online.CSE.HRC.Analysis.Analyzers.ExchangeCmdlets.StringsGetUserSuccessDesc
    AdminMessage          : 
    SupportMessage        : 
    IsMessageShown        : False
    GenericInfo           : 
    Severity              : 2
    OverridesChildren     : False
    ProblemId             : 00000000-0000-0000-0000-000000000000
    TimeCached            : 0001-01-01T00:00:00
    SaraSymptomId         : 00000000-0000-0000-0000-000000000000
    SaraWorkflowRunId     : 00000000-0000-0000-0000-000000000000
    SaraSymptomRunId      : 00000000-0000-0000-0000-000000000000
    SaraSessionId         : 00000000-0000-0000-0000-000000000000
    Id                    : d5b4c239-7619-4367-9ccb-e9fe2fe01e23

    DisplayName               : Demo USer
    FirstName                 : Demo
    Guid                      : 67a93665-decb-4058-b42a-271d41c47c61
    Id                        : 
    Identity                  : EURP185A001.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/demoo365life4.onmicrosoft.com/AdminO365life
    IsDirSynced               : False
    IsValid                   : True
    LastName                  : User
    MicrosoftOnlineServicesID : user@company.com
    Name                      : DemoUser
    NetID                     : 401320004BA7A415
    RecipientType             : UserMailbox
    RecipientTypeDetails      : UserMailbox
    UserPrincipalName         : user@company.com
    WindowsEmailAddress       : user@company.com
    WindowsLiveID             : user@company.com
    IsHybridTenant            : False
    Forest                    : EURP185.PROD.OUTLOOK.COM
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [ValidateSet('NotSet','HrcCloud','HrcCmd','Sara','MsftSupportModeSara','SaraCloud','QTest')]
        [String]$ExecutionEnvironment='SaraCloud'
    )
    Begin
    {
        
    }
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://api.diagnostics.office.com"
        
        if(!$UserName)
        {
            $userName = (Read-Accesstoken $AccessToken).upn
        }

        $userInformation = [ordered]@{"UserName" = $UserName}

        #
        # TenantUserInfo
        #

        Write-Verbose "TenantUserInfo"

        $body=@{
	        "Symptom"            = "TenantUserInfo"
	        "RequestTimeoutInMs" =  180000
	        "Parameters" = @( 
                @{
			        "Name"                     = "AffectedUser"
			        "Value"                    = $UserName #.Split("@")[1]
			        "ComplianceClassification" = "Identifiable"
		        }
 		        @{
                    "Name"                     = "Symptom"
			        "Value"                    = "TenantUserInfo"
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "ScenarioSymptom"
			        "Value"                    = "TenantUserInfo"
			        "ComplianceClassification" = "Identifiable"

		        }
@{
                    "Name"                     = "UserPuid"
			        "Value"                    = ""
			        "ComplianceClassification" = "Identifiable"

		        }
@{
                    "Name"                     = "CorrelationId"
			        "Value"                    = ""
			        "ComplianceClassification" = "Identifiable"

		        }
                @{
                    "Name"                     = "TargetService"
			        "Value"                    = "Exchange"
			        "ComplianceClassification" = "Identifiable"

		        }
@{
                    "Name"                     = "IsMsaUser"
			        "Value"                    = $False
			        "ComplianceClassification" = "Identifiable"

		        }
@{
                    "Name"                     = "MailboxClient"
			        "Value"                    = "Outlook"
			        "ComplianceClassification" = "Identifiable"

		        }
@{
                    "Name"                     = "TestHook"
			        "Value"                    = ""
			        "ComplianceClassification" = "Identifiable"

		        }

	        )
        }
        
        $response = Call-AnalysisAPI -Body ($body | ConvertTo-Json) -AccessToken $AccessToken -Url "https://api.diagnostics.office.com/v1/cloudcheck"

        if($response.ProcessingStatus -eq "Succeeded")
        {
            $additionalInfo = $response.AdditionalInfo | ConvertFrom-Json

            if($additionalInfo.IsSuccess -eq "true")
            {
                $item = ([xml]$additionalInfo.TenantUserInfo).TenantUserInfo.FirstChild
                while($item)
                {
                    if($item.name -eq "LicenseInformations")
                    {
                        $userInformation[$item.Name] = $item.InnerXml
                    }
                    else
                    {
                        $userInformation[$item.Name] = $item.InnerText
                    }
                    $item = $item.NextSibling
                }
                
            }

            
        }


        #
        # CasMailbox
        #

        Write-Verbose "CasMailBox"

        $body=@{
	        "Symptom"            = "CasMailbox"
	        "RequestTimeoutInMs" =  180000
	        "Parameters" = @( 
                @{
			        "Name"                     = "AffectedUser"
			        "Value"                    = $UserName 
			        "ComplianceClassification" = "Identifiable"
		        }
@{
                    "Name"                     = "MailboxClient"
			        "Value"                    = "Outlook"
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "Symptom"
			        "Value"                    = "CasMailbox"
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "ScenarioSymptom"
			        "Value"                    = "CasMailbox"
			        "ComplianceClassification" = "Identifiable"

		        }
	        )
        }
        
        $response = Call-AnalysisAPI -Body ($body | ConvertTo-Json) -AccessToken $AccessToken -Url "https://api.diagnostics.office.com/v1/cloudcheck"

        if($response.ProcessingStatus -eq "Succeeded")
        {

            $userInformation["CASInfo"] = $response.MessageToUser
        }

        #
        # GetUserDiagnostic
        #

        Write-Verbose "GetUserDiagnostic"

        $body=@{
            "UserUpn"            = $parsedToken.upn
            "UserSMTPEmail"      = $parsedToken.upn
	        "Symptom"            = "GetUserDiagnostic"
	        "RequestTimeoutInMs" = 180000
	        "Parameters" = @( 
                @{
			        "Name"                     = "AffectedUser"
			        "Value"                    = $UserName
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "Symptom"
			        "Value"                    = "GetUserDiagnostic"
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "ScenarioSymptom"
			        "Value"                    = "GetUser"
			        "ComplianceClassification" = "Identifiable"

		        }
	        )
        }
        
        $response = Call-AnalysisAPI -Body ($body | ConvertTo-Json) -AccessToken $AccessToken -Url "https://api.diagnostics.office.com/v1/cloudcheck"

        if($response.ProcessingStatus -eq "Succeeded")
        {
            
            $additionalInfo = $response.AdditionalInfo | ConvertFrom-Json

            if($additionalInfo.IsSuccess -eq "true")
            {
                $userInfo = [xml]$additionalInfo.UserInfo
                $item = $userInfo.UserInfo.FirstChild
                while($item)
                {
                
                    $userInformation[$item.Name] = $item.InnerText
                
                    $item = $item.NextSibling
                }
                
            }
            else
            {
                Write-Warning $additionalInfo.ErrorInfo.Split("`n")[0]
            }

        }

        New-Object psobject -Property $userInformation
    }
}


# Sep 23rd 2021
function Get-SARATenantInfo
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='AccessToken', Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [ValidateSet('ExchangeHybridTenant','DirSyncCheck')]
        [String[]]$Tests=@('ExchangeHybridTenant','DirSyncCheck')
    )
    Begin
    {
        
    }
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://api.diagnostics.office.com"

        $parsedToken = Read-Accesstoken $AccessToken

        if(!$UserName)
        {
            $userName = $parsedToken.upn
        }

        $tenantInfo = [ordered]@{
                "Domain" = $UserName.Split("@")[1]
            }


        # 
        # ExchangeHybridTenant Check
        #

        if($Tests -contains "ExchangeHybridTenant")
        {
            Write-Verbose "ExchangeHybridTenant"

                                                                                                                $body=@{
	        "Symptom"            = "ExchangeHybridTenant"
	        "RequestTimeoutInMs" =  180000
	        "Parameters" = @( 
                @{
			        "Name"                     = "AffectedUser"
			        "Value"                    =  $UserName
			        "ComplianceClassification" = "Identifiable"
		        }
@{
                    "Name"                     = "ExchangeHybridTenantClient"
			        "Value"                    = "OutlookFreeBusy"
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "Symptom"
			        "Value"                    = "ExchangeHybridTenant"
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "ScenarioSymptom"
			        "Value"                    = "ExchangeHybridTenant"
			        "ComplianceClassification" = "Identifiable"

		        }
	        )
        }

            $response = Call-AnalysisAPI -Body ($body | ConvertTo-Json) -AccessToken $AccessToken -Url "https://api.diagnostics.office.com/v1/cloudcheck"
            if($response.AdditionalInfo)
                                                                                                                                                        {
            $additionalInfo = ($response.AdditionalInfo | ConvertFrom-Json)
            
            if($additionalInfo.Category -eq "S")
            {
                $hybridInfoXML = ([xml]($response.AdditionalInfo | ConvertFrom-Json).OrganizationRelationShipInfo).HybridInfo

                $orgRels = @()
                $onPrems = @()

                foreach($rel in $hybridInfoXML.OrganizationRelationShips.OrganizationRelationShip)
                {
                    $orgRels += New-Object psobject -Property @{
                        "FreeBusyAccessLevel" = $rel.FreeBusyAccessLevel
                        "FreeBusyEnabled"     = $rel.FreeBusyEnabled
                        "Identity"            = $rel.Identity
                        "IsValid"             = $rel.IsValid
                    }
                }
                foreach($rel in $hybridInfoXML.OnPremOrganizationRelationShips.OnPremOrganizationRelationShip)
                {
                    $onPrems += New-Object psobject -Property @{
                        "FreeBusyAccessLevel"      = $rel.FreeBusyAccessLevel
                        "OrganizationGuid"         = $rel.OrganizationGuid
                        "OrganizationName"         = $rel.OrganizationName
                        "OrganizationRelationship" = $rel.OrganizationRelationship
                    }
                }
                $tenantInfo["IsHybrid"]                        = $additionalInfo.isHybrid
                $tenantInfo["OrganizationRelationShips"]       = $orgRels
                $tenantInfo["OnPremOrganizationRelationShips"] = $onPrems
                
            }
            else
            {
                Write-Warning "ExchangeHybridTenant error $($additionalInfo.ScenarioResultName)"
            }
        }
        }


        # 
        # DirSyncCheck
        #

        if($Tests -contains "DirSyncCheck")
        {
            Write-Verbose "DirSyncCheck"

                                                                                            $body=@{
	        "Symptom"            = "DirSyncCheck"
	        "RequestTimeoutInMs" =  180000
	        "Parameters" = @( 
                @{
			        "Name"                     = "TenantDomain"
			        "Value"                    = $UserName.Split("@")[1]
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "Symptom"
			        "Value"                    = "DirSyncCheck"
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "ScenarioSymptom"
			        "Value"                    = "DirSyncCheck"
			        "ComplianceClassification" = "Identifiable"

		        }
	        )
        }

            $response = Call-AnalysisAPI -Body ($body | ConvertTo-Json) -AccessToken $AccessToken -Url "https://api.diagnostics.office.com/v1/cloudcheck"

            $tenantInfo["DirSync"] = $response.MessageToAdmin

        }
        # Return
        New-Object psobject -Property $tenantInfo

    }
}

# Sep 23rd 2021
function Get-SARAFreeBusyInformation
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserName,
        [Parameter(Mandatory=$True)]
        [String]$TargetUser
    )
    Begin
    {
        
    }
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://api.diagnostics.office.com"
        
        if(!$UserName)
        {
            $userName = (Read-Accesstoken $AccessToken).upn
        }

        #
        # FreeBusyTenantUserInfo
        #

        Write-Verbose "FreeBusyTenantUserInfo"

        $body=@{
	        "Symptom"            = "FreeBusyTenantUserInfo"
	        "RequestTimeoutInMs" =  180000
	        "Parameters" = @( 
@{
			        "Name"                     = "AffectedUser"
			        "Value"                    = $UserName
			        "ComplianceClassification" = "Identifiable"
		        }
 		        @{
                    "Name"                     = "Symptom"
			        "Value"                    = "FreeBusyTenantUserInfo"
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "ScenarioSymptom"
			        "Value"                    = "FreeBusyTenantUserInfo"
			        "ComplianceClassification" = "Identifiable"

		        }
                @{
                    "Name"                     = "TargetSmtpAddress"
			        "Value"                    = $TargetUser
			        "ComplianceClassification" = "Identifiable"

		        }


	        )
        }
        
        $response = Call-AnalysisAPI -Body ($body | ConvertTo-Json) -AccessToken $AccessToken -Url "https://api.diagnostics.office.com/v1/cloudcheck"

        if($response.ProcessingStatus -eq "Succeeded")
        {
            
            $additionalInfo = $response.AdditionalInfo | ConvertFrom-Json

            if($additionalInfo.IsSuccess -eq "true")
            {
                return $response.MessageToUser
            }
            else
            {
                Write-Error $response.MessageToUser
            }
            
        }


    }
}


# Aug 30th 2023
# Uses SARA to test if provided port is available
function Test-SARAPort
{
<#
    .SYNOPSIS
    Tests whether the given TCP port is open on the given host using SARA API.

    .DESCRIPTION
    Tests whether the given TCP port is open on the given host using SARA API.
    
    .Parameter AccessToken
    Access Token

    .PARAMETER Host
    Hostname or IP address of the target

    .PARAMETER Port
    TCP port number

    
    .Example
    Get-AADIntAccessTokenForSARA -SaveToCache
    PS C:\>Test-AADIntSARAPort -Host www.company.com -Port 443

    Host            Port Open
    ----            ---- ----
    www.company.com  443 True
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Host,
        [Parameter(Mandatory=$True)]
        [String]$Port
    )
    Begin
    {
        
    }
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://api.diagnostics.office.com"
        

        $body=@{
	        "Symptom"            = "PortCheck"
	        "RequestTimeoutInMs" =  180000
	        "Parameters" = @( 
                @{
			        "Name"                     = "HostName"
			        "Value"                    = $Host
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "Symptom"
			        "Value"                    = "PortCheck"
			        "ComplianceClassification" = "Identifiable"
		        }
                @{
                    "Name"                     = "Port"
			        "Value"                    = $Port.ToString()
			        "ComplianceClassification" = "Identifiable"
		        }
@{
                    "Name"                     = "IsReadBanner"
			        "Value"                    = $true
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "ScenarioSymptom"
			        "Value"                    = "Port"
			        "ComplianceClassification" = "Identifiable"

		        }
	        )
	        "UseDiagnosticService"   = $true

        }
        
        $response = Call-AnalysisAPI -Body ($body | ConvertTo-Json) -AccessToken $AccessToken -Url "https://api.diagnostics.office.com/v1/cloudcheck"

        $isOpen = $false
        if($response.ProcessingStatus -eq "Succeeded")
        {
            $additionalInfo = $response.AdditionalInfo | ConvertFrom-Json

            $isOpen = $additionalInfo.IsSuccess -eq "true"
        }

        [pscustomobject][ordered]@{
            "Host" = $Host
            "Port" = $Port
            "Open" = $isOpen
        }
    }
}


# Aug 30th 2023
# Uses SARA to resolve DNS name
function Resolve-SARAHost
{
<#
    .SYNOPSIS
    Tests whether the given hostname can be resolved from DNS using SARA API.

    .DESCRIPTION
    Tests whether the given hostname can be resolved from DNS using SARA API.
    
    .Parameter AccessToken
    Access Token

    .PARAMETER Host
    Hostname of the target

    .Example
    Get-AADIntAccessTokenForSARA -SaveToCache
    PS C:\>Resolve-AADIntSARAHost -Host www.company.com

    Host            Resolved
    ----            --------
    www.company.com     True
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
		[Parameter(Mandatory=$False)]
        [String]$Host

    )
    Begin
    {
        
    }
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://api.diagnostics.office.com"
        

        $body=@{
	        "Symptom"            = "ResolveHostCheck"
	        "RequestTimeoutInMs" =  180000
	        "Parameters" = @( 
                @{
			        "Name"                     = "HostName"
			        "Value"                    = $Host
			        "ComplianceClassification" = "Identifiable"
		        }
		        @{
                    "Name"                     = "Symptom"
			        "Value"                    = "ResolveHostCheck"
			        "ComplianceClassification" = "Identifiable"
		        }
                
	        )
	        "UseDiagnosticService"   = $true
	        
        }
        
        $response = Call-AnalysisAPI -Body ($body | ConvertTo-Json) -AccessToken $AccessToken -Url "https://api.diagnostics.office.com/v1/cloudcheck"

        $isResolved = $false
        if($response.ProcessingStatus -eq "Succeeded")
        {
			$isResolved = $response.MessageTitle.StartsWith("We succeeded")
        }

        [pscustomobject][ordered]@{
            "Host" = $Host
            "Resolved" = $isResolved
        }

    }
}