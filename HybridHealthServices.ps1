# Creates a new ADHybridHealthService
# Jun 7th 2021
function New-HybridHealthService
{
<#
    .SYNOPSIS
    Creates a new ADHybridHealthService

    .DESCRIPTION
    Creates a new ADHybridHealthService

    .Parameter AccessToken
    The access token used to create ADHybridHealthServices.

    .Parameter Service
    Which kind of service to create. Can be one of: "AdFederationService","AadSyncService"
    Defaults to AdFederationService

    .Parameter DisplayName
    Display name of the service. Usually host name of the AD FS service, like sts.company.com

    .Parameter Signature
    The issuer uri of the AD FS service. Usually same as the display name, like sts.company.com

    .Parameter Disabled
    Whether the service is disabled or not. Defaults to $False

    .Parameter Health
    Health of the service. Can be one of: "Healthy","NotMonitored","Error"
    Defaults to "Healthy"

    .Example
    New-AADIntHybridHealthService -Service AdFederationService -DisplayName sts.company.com -Signature sts.company.com

    activeAlerts                             : 0
    additionalInformation                    : 
    createdDate                              : 2021-05-05T07:13:45.0508805Z
    customNotificationEmails                 : 
    disabled                                 : False
    displayName                              : sts.company.com
    health                                   : Healthy
    lastDisabled                             : 
    lastUpdated                              : 0001-01-01T00:00:00
    monitoringConfigurationsComputed         : 
    monitoringConfigurationsCustomized       : 
    notificationEmailEnabled                 : True
    notificationEmailEnabledForGlobalAdmins  : True
    notificationEmails                       : 
    notificationEmailsEnabledForGlobalAdmins : False
    resolvedAlerts                           : 0
    serviceId                                : 50abc8f3-243a-4ac1-a3fb-712054d7334b
    serviceMembers                           : 
    serviceName                              : AdFederationService-sts.company.com
    signature                                : sts.company.com
    simpleProperties                         : 
    tenantId                                 : 5b53828e-8e7b-42d1-a5f0-9b34bbd1844a
    type                                     : AdFederationService
    originalDisabledState                    : False
    id                                       : /providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts.company.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [ValidateSet("AdFederationService","AadSyncService")]
        [String]$Type = "AdFederationService",
        [Parameter(Mandatory=$True)]
        [String]$DisplayName,
        [Parameter(Mandatory=$True)]
        [String]$Signature
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization"          = "Bearer $AccessToken"
            "x-ms-client-request-id" = (New-Guid).ToString()
        }

        # Create the body
        $body = [ordered]@{
            "ActiveAlerts"                             = 0
            "AdditionalInformation"                    = $null
            "CreatedDate"                              = "0001-01-01T00:00:00"
            "CustomNotificationEmails"                 = $null
            "Disabled"                                 = $False
            "DisplayName"                              = $DisplayName
            "Health"                                   = "Healthy"
            "LastDisabled"                             = $null
            "LastUpdated"                              = "0001-01-01T00:00:00"
            "MonitoringConfigurationsComputed"         = $null
            "MonitoringConfigurationsCustomized"       = $null
            "NotificationEmailEnabled"                 = $null
            "NotificationEmailEnabledForGlobalAdmins"  = $null
            "NotificationEmails"                       = $null
            "NotificationEmailsEnabledForGlobalAdmins" = $false
            "ResolvedAlerts"                           = 0
            "ServiceId"                                = $null
            "ServiceMembers"                           = $null
            "ServiceName"                              = $null
            "Signature"                                = $Signature
            "SimpleProperties"                         = $null
            "TenantId"                                 = $null
            "Type"                                     = $Type
            "OriginalDisabledState"                    = $false
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://management.azure.com/providers/Microsoft.ADHybridHealthService/services?api-version=2014-01-01" -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json; charset=utf-8"

        # Return the service object
        $response
        
    }
}

# Lists ADHybridHealthServices
# May 26th 2021
function Get-HybridHealthServices
{
<#
    .SYNOPSIS
    Gets ADHybridHealthServices

    .DESCRIPTION
    Gets ADHybridHealthServices

    .Parameter AccessToken
    The access token used to get ADHybridHealthServices.

    .Parameter Service
    Which kind of services to return.

    .Example
    Get-AADIntHybridHealthServices -Service AdFederationService

    activeAlerts                             : 3
    additionalInformation                    : 
    createdDate                              : 2021-05-05T07:13:45.0508805Z
    customNotificationEmails                 : 
    disabled                                 : False
    displayName                              : sts.company.com
    health                                   : Error
    lastDisabled                             : 
    lastUpdated                              : 2021-05-06T06:04:20.6537234Z
    monitoringConfigurationsComputed         : 
    monitoringConfigurationsCustomized       : 
    notificationEmailEnabled                 : True
    notificationEmailEnabledForGlobalAdmins  : True
    notificationEmails                       : 
    notificationEmailsEnabledForGlobalAdmins : False
    resolvedAlerts                           : 1
    serviceId                                : 50abc8f3-243a-4ac1-a3fb-712054d7334b
    serviceMembers                           : 
    serviceName                              : AdFederationService-sts.company.com
    signature                                : sts.company.com
    simpleProperties                         : 
    tenantId                                 : 5b53828e-8e7b-42d1-a5f0-9b34bbd1844a
    type                                     : AdFederationService
    originalDisabledState                    : False
    id                                       : /providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts.company.com

    .Example
    PS C:\>Get-AADIntHybridHealthServices -Service AdFederationService | ft serviceName

    serviceName                              
    -----------                              
    AdFederationService-sts.company.com 
    AdFederationService-sts.contoso.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [ValidateSet("AdFederationService","AadSyncService")]
        [String]$Service="AdFederationService"

    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        $url="https://management.azure.com/providers/Microsoft.ADHybridHealthService/services?api-version=2014-01-01"
        if($Service)
        {
            $url += "&serviceType=$Service"
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri $url -Headers $headers

        # Return services
        $response.value
        
    }
}

# Removes the ADHybridHealthService
# Jun 7th 2021
function Remove-HybridHealthService
{
<#
    .SYNOPSIS
    Removes existing ADHybridHealthService

    .DESCRIPTION
    Removes existing ADHybridHealthService

    .Parameter AccessToken
    The access token used to get ADHybridHealthServices.

    .Parameter ServiceName
    Name of the service to be removed

    .Example
    Remove-AADIntHybridHealthService -ServiceName AdFederationService-sts.company.com

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$ServiceName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization"          = "Bearer $AccessToken"
            "x-ms-client-request-id" = (New-Guid).ToString()
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Delete -Uri "https://management.azure.com/providers/Microsoft.ADHybridHealthService/services/$ServiceName`?api-version=2014-01-01" -Headers $headers

        # Return the service object
        $response
        
    }
}

# Get ADHybridHealthService members
# Jun 7th 2021
function Get-HybridHealthServiceMembers
{
<#
    .SYNOPSIS
    Gets ADHybridHealthService members

    .DESCRIPTION
    Gets ADHybridHealthService members

    .Parameter AccessToken
    The access token used to get ADHybridHealthService members.

    .Parameter ServiceName
    Name of the ADHybridHealthService

    .Example
    Get-AADIntHybridHealthServiceMembers -ServiceName "AdFederationService-sts.company.com"

    lastReboot                              : 2021-03-16T08:17:19.0912Z
    lastDisabled                            : 
    lastUpdated                             : 2021-06-07T11:36:34.6667535Z
    activeAlerts                            : 1
    resolvedAlerts                          : 1
    createdDate                             : 0001-01-01T00:00:00
    disabled                                : False
    dimensions                              : 
    additionalInformation                   : 
    tenantId                                : 5b53828e-8e7b-42d1-a5f0-9b34bbd1844a
    serviceId                               : 50abc8f3-243a-4ac1-a3fb-712054d7334b
    serviceMemberId                         : bec07a23-dd4a-4c80-8c92-9b9dc089f75c
    machineId                               : 0cf2774f-a188-4bd3-b4b3-3a690374325d
    machineName                             : SERVER
    role                                    : AdfsServer_2016
    status                                  : Warning
    properties                              : 
    installedQfes                           : 
    recommendedQfes                         : 
    monitoringConfigurationsComputed        : 
    monitoringConfigurationsCustomized      : 
    osVersion                               : 10.0.17763.0
    osName                                  : Microsoft Windows Server 2019 Standard
    disabledReason                          : 0
    serverReportedMonitoringLevel           : 
    lastServerReportedMonitoringLevelChange : 

    lastReboot                              : 0001-01-01T00:00:00
    lastDisabled                            : 
    lastUpdated                             : 0001-01-01T00:00:00
    activeAlerts                            : 0
    resolvedAlerts                          : 0
    createdDate                             : 0001-01-01T00:00:00
    disabled                                : False
    dimensions                              : 
    additionalInformation                   : 
    tenantId                                : 5b53828e-8e7b-42d1-a5f0-9b34bbd1844a
    serviceId                               : 50abc8f3-243a-4ac1-a3fb-712054d7334b
    serviceMemberId                         : e4d72022-a268-4167-a964-1899b8baeaa5
    machineId                               : f5e349d6-67fd-4f11-b489-d98980aa6cab
    machineName                             : PROXY
    role                                    : AdfsProxy_21
    status                                  : Healthy
    properties                              : 
    installedQfes                           : 
    recommendedQfes                         : 
    monitoringConfigurationsComputed        : 
    monitoringConfigurationsCustomized      : 
    osVersion                               : 
    osName                                  : 
    disabledReason                          : 0
    serverReportedMonitoringLevel           : 
    lastServerReportedMonitoringLevelChange : 

    .Example
    Get-AADIntHybridHealthServiceMembers -ServiceName "AdFederationService-sts.company.com" | ft machineName,serviceMemberId

    machineName serviceMemberId                     
    ----------- ---------------                     
    SERVER      bec07a23-dd4a-4c80-8c92-9b9dc089f75c
    PROXY       e4d72022-a268-4167-a964-1899b8baeaa5

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$ServiceName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "x-ms-client-request-id" = (New-Guid).ToString()
        }
        
        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Uri "https://management.azure.com/providers/Microsoft.ADHybridHealthService/services/$ServiceName/servicemembers?api-version=2014-01-01" -Headers $headers -Body ($Body | ConvertTo-Json) -ContentType "application/json; charset=utf-8"

        # Return the service members
        $response.value
    }
}

# Create a new ADHybridHealthService members
# May 26th 2021
function New-HybridHealthServiceMember
{
<#
    .SYNOPSIS
    Adds a new ADHybridHealthService member

    .DESCRIPTION
    Adds a new ADHybridHealthService member

    .Parameter AccessToken
    The access token used to get ADHybridHealthService members.

    .Parameter ServiceName
    Name of the ADHybridHealthService

    .Example
    New-AADIntHybridHealthServiceMember -ServiceName AdFederationService-sts.company.com -MachineName "MyServer"

    lastReboot                              : 0001-01-01T00:00:00Z
    lastDisabled                            : 
    lastUpdated                             : 0001-01-01T00:00:00
    activeAlerts                            : 0
    resolvedAlerts                          : 0
    createdDate                             : 2021-05-06T07:15:50.0087136Z
    disabled                                : False
    dimensions                              : 
    additionalInformation                   : 
    tenantId                                : 5b53828e-8e7b-42d1-a5f0-9b34bbd1844a
    serviceId                               : 50abc8f3-243a-4ac1-a3fb-712054d7334b
    serviceMemberId                         : 0fce7ce0-81a0-4bf7-87fb-fc787dfe13c2
    machineId                               : e9f8357d-8a25-4cef-8c6b-f0b3c916ead5
    machineName                             : MyServer
    role                                    : 
    status                                  : Healthy
    properties                              : 
    installedQfes                           : 
    recommendedQfes                         : 
    monitoringConfigurationsComputed        : 
    monitoringConfigurationsCustomized      : 
    osVersion                               : 
    osName                                  : 
    disabledReason                          : 0
    serverReportedMonitoringLevel           : 
    lastServerReportedMonitoringLevelChange : 
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$ServiceName,
        [Parameter(Mandatory=$False)]
        [guid]$MachineId=(New-Guid),
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [ValidateSet("AdfsServer_2x","AdfsProxy_2x","AdfsServer_21","AdfsProxy_21","AdfsServer_30","AdfsProxy_30","AdfsServer_2016","AdfsProxy_2016")]
        [String]$MachineRole="AdfsServer_2016"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "x-ms-client-request-id" = (New-Guid).ToString()
        }

        # Create the body
        $body= [ordered]@{
            "LastReboot"                             = "0001-01-01T00:00:00"
	        "LastDisabled"                           = "0001-01-01T00:00:00"
	        "LastUpdated"                            = "0001-01-01T00:00:00"
	        "ActiveAlerts"                           = 0
	        "ResolvedAlerts"                         = 0
	        "CreatedDate"                            = "0001-01-01T00:00:00"
	        "Disabled"                               = $False
	        "Dimensions"                             = $null
	        "AdditionalInformation"                  = $null
	        "TenantId"                               = "00000000-0000-0000-0000-000000000000"
	        "ServiceId"                              = "00000000-0000-0000-0000-000000000000"
	        "ServiceMemberId"                        = "00000000-0000-0000-0000-000000000000"
	        "MachineId"                              = $MachineId.ToString()
	        "MachineName"                            = $MachineName
	        "Role"                                   = $MachineRole
	        "Status"                                 = $Status
	        "Properties"                             = $Null
	        "InstalledQfes"                          = $Null
	        "RecommendedQfes"                        = $Null
	        "MonitoringConfigurationsComputed"       = $Null
	        "MonitoringConfigurationsCustomized"     = $Null
	        "OsVersion"                              = $Null
	        "OsName"                                 = $Null
	        "DisabledReason"                         = 0
	        "ServerReportedMonitoringLevel"          = $Null
	        "LastServerReportedMonitoringLevelChange"= "0001-01-01T00:00:00"
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://management.azure.com/providers/Microsoft.ADHybridHealthService/services/$ServiceName/servicemembers?api-version=2014-01-01" -Headers $headers -Body ($Body | ConvertTo-Json) -ContentType "application/json; charset=utf-8"

        # Return the service object
        $response
    }
}

# Remove ADHybridHealthService members
# Jun 14th 2021
function Remove-HybridHealthServiceMember
{
<#
    .SYNOPSIS
    Removes ADHybridHealthService member

    .DESCRIPTION
    Removes ADHybridHealthService member

    .Parameter AccessToken
    The access token used to get ADHybridHealthService members.

    .Parameter ServiceName
    Name of the ADHybridHealthService

    .Parameter ServiceMemberId
    Id of the ADHybridHealthService member to be removed

    .Example
    Remove-AADIntHybridHealthServiceMember -ServiceName AdFederationService-sts.company.com -ServiceMemberId 329485ce-9b5b-4652-ba72-acc41a455e92
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$ServiceName,
        [Parameter(Mandatory=$True)]
        [guid]$ServiceMemberId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "x-ms-client-request-id" = (New-Guid).ToString()
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Delete -Uri "https://management.azure.com/providers/Microsoft.ADHybridHealthService/services/$ServiceName/servicemembers/$ServiceMemberId`?confirm=false&api-version=2014-01-01" -Headers $headers

        # Return the service object
        $response
    }
}

# Gets ADHybridHealthService monitoring policies
# May 29th 2021
function Get-HybridHealthServiceMonitoringPolicies
{
<#
    .SYNOPSIS
    Gets ADHybridHealthService monitoring policies.

    .DESCRIPTION
    Gets ADHybridHealthService monitoring policies.

    .Parameter AccessToken
    The access token used to get ADHybridHealthService monitoring policies

    .Example
    Get-AADIntHybridHealthServiceMonitoringPolicies -AccessToken $at

    serviceType                       : AdFederationService
    serviceId                         : 74b6a260-67a3-43ac-922f-ec7afe19649c
    serviceMemberId                   : 52f7c09f-e6a4-41ff-b328-bb6a182e1aca
    monitoringConfigurations          : {@{key=AadPremium; value=True}, @{key=MonitoringLevel; value=Full}}
    propertiesExtractorClassName      : Microsoft.Identity.Health.Adfs.DataAccess.DataManager, Microsoft.Identity.Health.Adfs.DataAccess
    dimensionTableEntityClassNameList : 
    roleType                          : AdfsServer_2016
    moduleConfigurations              : {@{agentService=ConnectorAgent; moduleName=adfs; properties=}, @{agentService=ConnectorAgent; moduleName=PowerShellCmdletMonitor; properties=}}

    serviceType                       : AadSyncService
    serviceId                         : 4ce7a4dd-0269-4ae1-a92c-88f381f11a33
    serviceMemberId                   : fa657e9b-b609-470c-aa6a-9922d9f37e49
    monitoringConfigurations          : {@{key=MonitoringLevel; value=Off}, @{key=StagingMode; value=False}, @{key=ConfigurationUploadInterval; value=240}, 
                                        @{key=RunProfileResultUploadInterval; value=30}...}
    propertiesExtractorClassName      : Microsoft.Identity.Health.AadSync.DataAccess.DataManager, Microsoft.Identity.Health.AadSync.DataAccess
    dimensionTableEntityClassNameList : 
    roleType                          : AadSync_AadConnectSync_1.0
    moduleConfigurations              : {@{agentService=ConnectorAgent; moduleName=aadsync; properties=}}
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "x-ms-client-request-id" = (New-Guid).ToString()
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://s1.adhybridhealth.azure.com/providers/Microsoft.ADHybridHealthService/monitoringpolicies" -Headers $headers

        # Return upload key
        $response
    }
}

# Send the ADHybridHealthService events to Azure
# May 26th 2021
function Send-HybridHealthServiceEvents
{
<#
    .SYNOPSIS
    Sends the given AD FS audit events to Azure.

    .DESCRIPTION
    Sends the given AD FS audit events to Azure using ADHybridHealthService protocols.

    .Parameter TenantId
    Tenant ID

    .Parameter ServiceID
    ServiceID

    .Parameter MachineId
    Machine ID of the computer running the ADHybridHealthService.

    .Parameter Events
    An array of event objects.

    .Example
    PS C:\>Get-AADIntHybridHealthServiceMembers -ServiceName "AdFederationService-sts.company.com" | ft machineId,serviceId,tenantId

    machineName machineId                            serviceId                            tenantId                            
    ----------- ---------                            ---------                            --------                            
    SERVER      0cf2774f-a188-4bd3-b4b3-3a690374325d a0fae99d-083e-451c-9965-cc7a5851e4a8 b00133a8-b4e1-4c69-91d1-c0945e3e83c4
    PROXY       f5e349d6-67fd-4f11-b489-d98980aa6cab a0fae99d-083e-451c-9965-cc7a5851e4a8 b00133a8-b4e1-4c69-91d1-c0945e3e83c4

    PS C:\>$agentKey = Get-Content "b00133a8-b4e1-4c69-91d1-c0945e3e83c4_f5e349d6-67fd-4f11-b489-d98980aa6cab_SERVER.txt"
    PS C:\>$events = @()
    PS C:\>$events += (New-AADIntHybridHealtServiceEvent -Server "Server" -UPN "user@company.com" -IPAddress "192.168.0.2")

    PS C:\>Send-AADIntHybridHealthServiceEvents -AgentKey $agentKey -TenantId "b00133a8-b4e1-4c69-91d1-c0945e3e83c4" -MachineId "f5e349d6-67fd-4f11-b489-d98980aa6cab" -ServiceId "a0fae99d-083e-451c-9965-cc7a5851e4a8" -Events $events 

    .Example
    PS C:\>$events = @()
    PS C:\>$events += (New-AADIntHybridHealtServiceEvent -Server "Server" -UPN "user@company.com" -IPAddress "192.168.0.2")
    PS C:\>$agentInfo = Get-AADIntHybridHealthServiceAgentInfo
    PS C:\>Send-AADIntHybridHealthServiceEvents -AgentInfo $agentInfo -Events $events 
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Normal'   ,Mandatory=$True)]
        [String]$AgentKey,
        [Parameter(ParameterSetName='Normal'   ,Mandatory=$True)]
        [guid]$MachineId,
        [Parameter(ParameterSetName='Normal'   ,Mandatory=$True)]
        [guid]$TenantId,
        [Parameter(ParameterSetName='Normal'   ,Mandatory=$True)]
        [guid]$ServiceId,
        [Parameter(ParameterSetName='Normal'   ,Mandatory=$True)]
        [Parameter(ParameterSetName='AgentInfo',Mandatory=$True)]
        [System.Array]$Events,
        [Parameter(ParameterSetName='AgentInfo',Mandatory=$True)]
        [psobject]$AgentInfo
    )
    Process
    {
        if($AgentInfo)
        {
            $AgentKey  = $AgentInfo.AgentKey
            $TenantId  = $AgentInfo.TenantId
            $MachineId = $AgentInfo.MachineId
            $ServiceId = $AgentInfo.ServiceId
        }

        # Get the service access token and the needed keys
        $serviceAccessToken = Get-HybridHealthServiceAccessToken          -AgentKey $AgentKey -MachineId $MachineId -TenantId $TenantId
        $BlobKey            = Get-HybridHealthServiceBlobUploadKey        -AccessToken $serviceAccessToken -ServiceId $ServiceId
        $EventPublisherKey  = Get-HybridHealthServiceEventHubPublisherKey -AccessToken $serviceAccessToken -ServiceId $ServiceId

        # Convert the events to json and compress
        $content = ConvertTo-Json -InputObject $Events
        $encContent = Get-CompressedByteArray -byteArray ([text.encoding]::UTF8.GetBytes($content))
        
        # Calculate MD5 for the compressed content
        $md5     = [System.Security.Cryptography.MD5]::Create()
        $bodyMD5 = $md5.ComputeHash($encContent)

        # Construct headers for uploading the blob
        $id      = (New-Guid).ToString()
        $headers = @{
            "User-Agent" =             "Azure-Storage/8.2.0 (.NET CLR 4.0.30319.42000; Win32NT 10.0.17763.0)"
            "x-ms-version" =           "2017-04-17"
            "Content-MD5" =            Convert-ByteArrayToB64 -Bytes $bodyMD5
            "x-ms-blob-type" =         "BlockBlob"
            "x-ms-client-request-id" = $id
        }
        
        # Construct the url
        $BlobUrl  = $BlobKey.Replace("?","/$($id).json?")
        $BlobUrl += "&api-version=2017-04-17"

        # Send the blob to Azure
        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri $BlobUrl -Headers $headers -Body ([byte[]]$encContent) 
        }
        catch
        {
            return
        }

        #
        # Create the HMAC signature for the servicebus message (this is funny)
        #

        # First, an SHA512 hash is calculated from the AgentKey. 
        # Agent key is a B64 string of the binary key, but the hash is calculated from the string.
        # The hash is converted to hex string.
        [System.Security.Cryptography.SHA512] $sha = [System.Security.Cryptography.SHA512]::Create()
        $bKey = Convert-ByteArrayToHex -Bytes $sha.ComputeHash([text.encoding]::ASCII.getBytes($AgentKey))

        # Second, the signing key is derived by calculating HMACSHA512 by converting the hex array to binary by decoding it as B64 ???!?
        $cKey = Convert-B64ToByteArray -B64 $bKey.ToUpper()
        $hmac = [System.Security.Cryptography.HMACSHA512]::new($cKey)

        # Get elements needed for the signature
        $BlobUrl = $BlobUrl.Split("?")[0]
        $signingTime = Get-Date
        $dateString = $signingTime.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)
        
        # Form the string to be signed and calculate the signature.
        $stringToSign="$tenantId,$serviceId,$machineId,Adfs-UsageMetrics,$BlobUrl,$dateString"
        $HMACSignature = Convert-ByteArrayToB64 -Bytes $hmac.ComputeHash([text.encoding]::Unicode.GetBytes($stringToSign))
        
        # Send the signature to Azure via service bus
        Send-ADFSServiceBusMessage -EventHubPublisherKey $EventPublisherKey -BlobAbsoluteUri $BlobUrl -TenantId $TenantId -MachineId $MachineId -ServiceId $ServiceId -SigningTime $signingTime -HMACSignature $HMACSignature
    }
}

# Registers a new HybridHealthServiceAgent
# Jun 7th 2021
function Register-HybridHealthServiceAgent
{
<#
    .SYNOPSIS
    Registers a new ADHybridHealthService agent to the given service.

    .DESCRIPTION
    Registers a new ADHybridHealthService agent to the given service.
    Saves the agent info and client certificates to the current directory. 
    Files are named: <ServiceName>_<TenantId>_<ServiceMemberId>_<MachineName>.xxx where xxx is json for Agent info and pfx for the certificate.

    .Example
    PS C:\>Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

    PS C:\>Get-AADIntHybridHealthServices -Service AdFederationService | ft serviceName

    serviceName                              
    -----------                              
    AdFederationService-sts.company.com 
    AdFederationService-sts.contoso.com

    PS C:\>Register-AADIntHybridHealthServiceAgent -ServiceName "AdFederationService-sts.company.com" -MachineName "SERVER2" -MachineRole AdfsProxy_2016

    Agent info saved to         "AdFederationService-sts.company.com_0a959715-0d39-4409-bcc9-2c6ff5aa7a37_f5e349d6-67fd-4f11-b489-d98980aa6cab_SERVER2.json"
    Client sertificate saved to "AdFederationService-sts.company.com_0a959715-0d39-4409-bcc9-2c6ff5aa7a37_f5e349d6-67fd-4f11-b489-d98980aa6cab_SERVER2.pfx"
#>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$ServiceName,
        [Parameter(Mandatory=$True)]
        [string]$MachineName,
        [Parameter(Mandatory=$False)]
        [ValidateSet("AdfsServer_2x","AdfsProxy_2x","AdfsServer_21","AdfsProxy_21","AdfsServer_30","AdfsProxy_30","AdfsServer_2016","AdfsProxy_2016")]
        [String]$MachineRole="AdfsServer_2016",
        [ValidateSet("Healthy","NotMonitored")]
        [String]$Status = "Healthy"
     )
     Process
     {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Generate machine id
        $MachineId = New-Guid

        # Extract the tenant id from the
        [guid]$TenantId = (Read-Accesstoken -AccessToken $AccessToken).tid

        # Add new service member
        $serviceMember = New-HybridHealthServiceMember -AccessToken $AccessToken -ServiceName $ServiceName -MachineId $MachineId -MachineName $MachineName -MachineRole $MachineRole
        Write-Verbose "Added new service member:"
        Write-Verbose $serviceMember

        # Get the agent credentials
        $agentCredentials  = Get-HybridHealthServiceMemberCredentials -AccessToken $AccessToken -ServiceName $ServiceName -ServiceMemberId $serviceMember.serviceMemberId
        $tenantCertificate = $agentCredentials.'tenant.cert'
        Write-Verbose "Received a new tenant certificate: $($tenantCertificate.Subject)"
        Write-Verbose "AgentKey: $($agentCredentials.AgentKey)"

        # Invoke the request to get the client certificate
        Write-Verbose "Registering the agent using tenant certificate."
        [xml]$response = Invoke-RestMethod -UseBasicParsing -Uri "https://policykeyservice.dc.ad.msft.net/clientregistrationmanager.svc/ClientRegistration/$($TenantId.toString())/$MachineName/$($MachineId.toString())" -Certificate $TenantCertificate

        # Strip CRLF and convert to byte array
        $bCert = Convert-B64ToByteArray -B64 $response.AgentSetupConfiguration.ClientCertificate.Replace("`r`n","")
        $agentCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$bCert)
        Write-Verbose "Received a new agent certificate: $($agentCert.Subject)"
        
        $agentInfo=[ordered]@{
            "AgentKey"        = $agentCredentials.AgentKey
            "TenantId"        = $TenantId 
            "ServiceId"       = $serviceMember.serviceId
            "ServiceMemberId" = $serviceMember.serviceMemberId
            "MachineId"       = $MachineId
            "Server"          = $MachineName
        }

        # Save agent info and certificates to disk
        $fileName = "$($ServiceName)_$($TenantId.toString())_$($MachineId.toString())_$MachineName"
        Set-BinaryContent -Path "$fileName.pfx" -Value $bCert
        $agentInfo | ConvertTo-Json | Set-Content "$fileName.json" -Encoding UTF8
        
        Write-Host "Agent info saved to         ""$fileName.json"""
        Write-Host "Client sertificate saved to ""$fileName.pfx"""
     }
}