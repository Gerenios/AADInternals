# This script contains functions used in Microsoft Support and Recovery Assistant (SARA)

# Jul 8th 2019
function Call-AnalysisAPI
{
    [cmdletbinding()]
    Param(
        [ValidateSet('userInfo','tenantInfo','cloudCheck')]
        [String]$Command,
        [Parameter(ParameterSetName='AccessToken', Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        $userName = (Read-Accesstoken $AccessToken).upn

        $uri = "https://api.diagnostics.office.com/v1/analysis"

        switch($Command)
        {
            "userInfo" 
            {
                $body=@"
                {
	                "DiagnosisInfo": {
		                "ARE.ExecutionEnviro": 5,
		                "ARE.LoginUser": {
			                "`$type": "Microsoft.Online.CSE.HRC.Analysis.Analyzers.Common.SaraLoginUser, Microsoft.Online.CSE.HRC.Analysis.Analyzers.Common",
			                "RecipientType": ""
		                },
		                "RemoteAnalyzerType": "Microsoft.Online.CSE.HRC.Analysis.Analyzers.ExchangeCmdlets.GetUserAnalyzer",
		                "AssemblyFile": "Microsoft.Online.CSE.HRC.Analysis.Analyzers.RemoteCmdlets.dll",
		                "Timeout": 120000,
		                "SmtpAddress": "$userName"
	                },
	                "AnalyzerId": "597b1b90-b4a8-4fa0-9ddb-dcd997f0b8c2"
                }
"@
            }
            "tenantInfo"
            {
                $body=@"
                {
	                "DiagnosisInfo": {
		                "SmtpAddress": "$userName",
		                "TenantServicePlan": "MicrosoftOffice",
		                "msauser": false,
		                "Client": "SARAClient",
		                "puid": "",
		                "correlationid": "$(New-Guid)",
		                "ARE.ExecutionEnviro": 5
	                },
	                "AnalyzerId": "64fc98c3-da51-41f0-9051-1fb5921deb95"
                }
"@
            }
            "cloudCheck"
            {
                $encryptedUserName = "" # Base64 encoded encrypted username
                $encryptedPassword = "" # Base64 encoded encrypted password
                $body=@"
                {
	                "UserSMTPEmail": "$userName",
	                "Symptom": "AuthEndpointCheck",
	                "RequestTimeoutInMs": 120000,
	                "Parameters": [{
			                "Name": "UserEnvironment",
			                "Value": "0",
			                "ComplianceClassification": "Identifiable"
		                }, {
			                "Name": "SmtpAddress",
			                "Value": "$userName",
			                "ComplianceClassification": "Identifiable"
		                }, {
			                "Name": "UserAgent",
			                "Value": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.11328; Pro; SaRA)",
			                "ComplianceClassification": "Identifiable"
		                }, {
			                "Name": "Cred",
			                "Value": "{\"UserName\":\"$encryptedUserName\",\"Password\":\"$encryptedPassword\",\"SecurePassword\":{\"Length\":344},\"Domain\":\"\"}",
			                "ComplianceClassification": "Identifiable"
		                }
	                ],
	                "ProductName": "Outlook",
	                "ProductVersion": "16.0.11328.20318",
	                "OperatingSystem": "Windows 10 Enterprise",
	                "OperatingSystemVersion": "10.0.17134.829",
	                "IsAuthenticated": false,
	                "IsInline": null,
	                "IsTest": null
                }
"@
                $uri = "https://api.diagnostics.office.com/v1/cloudcheck"
            }
        }
        
        $headers =@{
                "Content-Type" = "application/json;odata=verbose"
                "Authorization" = $(Create-AuthorizationHeader -AccessToken $AccessToken)
        }
        
        $reply = Invoke-RestMethod -Uri $uri -Method Post -Body $body -Headers $headers
        $sessionId = $reply.SessionId

        while($reply.RequestStatus -ne "Completed")
        {
            Write-Host "Retrieving information.."
            sleep -Seconds "2"
            $reply = Invoke-RestMethod -Uri "$uri/?id=$sessionId" -Method Get -Headers $headers
        }

        # Get the results
        $results = $reply.Result.Results[0]

        # Return
        $results
    }
}

# Jul 8th 2019
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
        [Parameter(ParameterSetName='AccessToken', Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        # Get the results
        $results = Call-AnalysisAPI -Command userInfo -AccessToken $AccessToken
                
        # Extract the user info
        $userInfo = ([xml]$results.SupportMessage).UserInfo
        $results.SupportMessage=""
        
        $results
        $userInfo
        
    }
}


# Jul 8th 2019
function Get-SARATenantInfo
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='AccessToken', Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        # Get the results
        $results = Call-AnalysisAPI -Command tenantInfo -AccessToken $AccessToken
     
        $results
        
    }
}

# Jul 8th 2019
function Get-SARAAuthInfo
{
<#
    .SYNOPSIS
    Gets tenant information using SARA API

    .DESCRIPTION
    Gets tenant information using Microsoft Support and Recovery Assistant (SARA) API

    .Parameter AccessToken
    Access Token

    .Example
    $at=Get-AADIntAccessTokenForSARA
    PS C:\>Get-AADIntSARATenantInfo -AccessToken $at

    AnalyzerName          : AnalysisRule, Microsoft.Online.CSE.HRC.Analysis.Analyzers.TenantInfo.TenantUserInfoAnalyzer, Microsoft.Online.CSE.HRC.Analysis.Analyzers.TenantInfo, Version=16.0.3144.0, Culture=neu
                            tral, PublicKeyToken=31bf3856ad364e35
    AnalyzerDesc          : Checking your tenant and account information.
    StartTime             : 2019-07-08T12:31:06.1602586Z
    Duration              : 00:00:00.6250818
    CoreDuration          : 00:00:00.6250818
    WaitingDuration       : 00:00:00
    TotalChildrenDuration : 00:00:00
    TotalWaitingDuration  : 00:00:00
    ParentId              : 00000000-0000-0000-0000-000000000000
    Value                 : true
    ResultTitle           : The licenses of your tenant and account are all good!
    ResultTitleId         : Microsoft.Online.CSE.HRC.Analysis.Analyzers.TenantInfo.StringsGetTenantInfoSuccess
    UserMessage           : 
    UserMessageId         : 
    AdminMessage          : 
    SupportMessage        : <Setup><ProductId>O365ProPlusRetail</ProductId><ReleaseTrack>False</ReleaseTrack></Setup>
    IsMessageShown        : False
    GenericInfo           : User Puid is not null or empty.OrgIg_User<TenantUserInfo><IsLicensed>True</IsLicensed><ProvisioningStatus>PendingInput</ProvisioningStatus><PreferredLanguage>en</PreferredLanguage/>
                            <ValidationStatus>Healthy</ValidationStatus><ReleaseTrack>Other</ReleaseTrack><LicenseInformations><LicenseInformation><SKUPartNumber>SPE_E5</SKUPartNumber><ServiceStatus><ServiceTy
                            pe>Exchange</ServiceType><ServiceName>INFORMATION_BARRIERS</ServiceName><ProvisioningStatus>PendingProvisioning</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Micro
                            softKaizala</ServiceType><ServiceName>KAIZALA_STANDALONE</ServiceName><ProvisioningStatus>PendingProvisioning</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Bing</S
                            erviceType><ServiceName>MICROSOFT_SEARCH</ServiceName><ProvisioningStatus>PendingProvisioning</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><
                            ServiceName>PREMIUM_ENCRYPTION</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>WhiteboardServices</ServiceType><ServiceName>
                            WHITEBOARD_PLAN3</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>MIP_S_CLP2</ServiceName>
                            <ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>MIP_S_CLP1</ServiceName><ProvisioningStatus>Success</P
                            rovisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>MYANALYTICS_P2</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></Servic
                            eStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>PAM_ENTERPRISE</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><Se
                            rviceType>AzureAdvancedThreatAnalytics</ServiceType><ServiceName>ATA</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>To-Do<
                            /ServiceType><ServiceName>BPOS_S_TODO_3</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>ProcessSimple</ServiceType><ServiceN
                            ame>FLOW_O365_P3</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>PowerAppsService</ServiceType><ServiceName>POWERAPPS_O365_P
                            3</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>OfficeForms</ServiceType><ServiceName>FORMS_PLAN_E5</ServiceName><Provisio
                            ningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Adallom</ServiceType><ServiceName>ADALLOM_S_STANDALONE</ServiceName><ProvisioningStatus>Disabled</
                            ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>MicrosoftStream</ServiceType><ServiceName>STREAM_O365_E5</ServiceName><ProvisioningStatus>Success</ProvisioningStatus>
                            </ServiceStatus><ServiceStatus><ServiceType>Deskless</ServiceType><ServiceName>Deskless</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><
                            ServiceType>Exchange</ServiceType><ServiceName>THREAT_INTELLIGENCE</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Teamspace
                            API</ServiceType><ServiceName>TEAMS1</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>WindowsDefenderATP</ServiceType><Servic
                            eName>WINDEFATP</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Windows</ServiceType><ServiceName>WIN10_PRO_ENT_SUB</Service
                            Name><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>RMSOnline</ServiceType><ServiceName>RMS_S_PREMIUM2</ServiceName><ProvisioningStatus>
                            Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>AADPremiumService</ServiceType><ServiceName>AAD_PREMIUM_P2</ServiceName><ProvisioningStatus>Disabled</Provis
                            ioningStatus></ServiceStatus><ServiceStatus><ServiceType>RMSOnline</ServiceType><ServiceName>RMS_S_PREMIUM</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceSta
                            tus><ServiceStatus><ServiceType>RMSOnline</ServiceType><ServiceName>RMS_S_ENTERPRISE</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><Se
                            rviceType>MultiFactorService</ServiceType><ServiceName>MFA_PREMIUM</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>SCO</Ser
                            viceType><ServiceName>INTUNE_A</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>AADPremiumService</ServiceType><ServiceName>
                            AAD_PREMIUM</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>YammerEnterprise</ServiceType><ServiceName>YAMMER_ENTERPRISE</S
                            erviceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Sway</ServiceType><ServiceName>SWAY</ServiceName><ProvisioningStatus>Success</
                            ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>SharePoint</ServiceType><ServiceName>SHAREPOINTWAC</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></Serv
                            iceStatus><ServiceStatus><ServiceType>SharePoint</ServiceType><ServiceName>SHAREPOINTENTERPRISE</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><Service
                            Status><ServiceType>ProjectWorkManagement</ServiceType><ServiceName>PROJECTWORKMANAGEMENT</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus
                            ><ServiceType>MicrosoftOffice</ServiceType><ServiceName>OFFICESUBSCRIPTION</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>M
                            icrosoftCommunicationsOnline</ServiceType><ServiceName>MCOSTANDARD</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Microsoft
                            CommunicationsOnline</ServiceType><ServiceName>MCOMEETADV</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>MicrosoftCommunica
                            tionsOnline</ServiceType><ServiceName>MCOEV</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceNa
                            me>LOCKBOX_ENTERPRISE</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>SCO</ServiceType><ServiceName>INTUNE_O365</ServiceName
                            ><ProvisioningStatus>PendingActivation</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>EXCHANGE_S_ENTERPRISE</ServiceName><Provisi
                            oningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>EXCHANGE_ANALYTICS</ServiceName><ProvisioningStatus>Success</P
                            rovisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>EQUIVIO_ANALYTICS</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></Ser
                            viceStatus><ServiceStatus><ServiceType>PowerBI</ServiceType><ServiceName>BI_AZURE_P2</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><Ser
                            viceType>Exchange</ServiceType><ServiceName>ATP_ENTERPRISE</ServiceName><ProvisioningStatus>PendingProvisioning</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Adall
                            om</ServiceType><ServiceName>ADALLOM_S_O365</ServiceName><ProvisioningStatus>PendingInput</ProvisioningStatus></ServiceStatus></LicenseInformation><LicenseInformation><SKUPartNumber
                            >EMSPREMIUM</SKUPartNumber><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>EXCHANGE_S_FOUNDATION</ServiceName><ProvisioningStatus>PendingProvisioning</ProvisioningSta
                            tus></ServiceStatus><ServiceStatus><ServiceType>AzureAdvancedThreatAnalytics</ServiceType><ServiceName>ATA</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStat
                            us><ServiceStatus><ServiceType>Adallom</ServiceType><ServiceName>ADALLOM_S_STANDALONE</ServiceName><ProvisioningStatus>PendingInput</ProvisioningStatus></ServiceStatus><ServiceStatu
                            s><ServiceType>RMSOnline</ServiceType><ServiceName>RMS_S_PREMIUM2</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>RMSOnline<
                            /ServiceType><ServiceName>RMS_S_PREMIUM</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>RMSOnline</ServiceType><ServiceName>
                            RMS_S_ENTERPRISE</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>SCO</ServiceType><ServiceName>INTUNE_A</ServiceName><Provis
                            ioningStatus>PendingInput</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>AADPremiumService</ServiceType><ServiceName>AAD_PREMIUM_P2</ServiceName><ProvisioningStatus
                            >Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>MultiFactorService</ServiceType><ServiceName>MFA_PREMIUM</ServiceName><ProvisioningStatus>Success</Provision
                            ingStatus></ServiceStatus><ServiceStatus><ServiceType>AADPremiumService</ServiceType><ServiceName>AAD_PREMIUM</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceS
                            tatus></LicenseInformation></LicenseInformations></TenantUserInfo>
    Severity              : 2
    OverridesChildren     : False
    ProblemId             : 00000000-0000-0000-0000-000000000000
    TimeCached            : 0001-01-01T00:00:00
    SaraSymptomId         : 00000000-0000-0000-0000-000000000000
    SaraWorkflowRunId     : 00000000-0000-0000-0000-000000000000
    SaraSymptomRunId      : 00000000-0000-0000-0000-000000000000
    SaraSessionId         : 00000000-0000-0000-0000-000000000000
    Id                    : 81157ffa-d946-4bf8-8d6e-a391b96e4bf6
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='AccessToken', Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        # Get the results
        $results = Call-AnalysisAPI -Command cloudCheck -AccessToken $AccessToken
                
        # Extract the user info
        #$userInfo = ([xml]$results.SupportMessage).UserInfo
        #$results.SupportMessage=""
        
        $results
        #$userInfo
        
    }
}