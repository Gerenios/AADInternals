## Directory Sync API functions

# NOTE: Azure AD Sync API gets redirected quite often 2-3 times per request. 
# Therefore the functions need to be called recursively and use $Recursion parameter.

# Get synchronization configuration using Provisioning and Azure AD Sync API
# May 6th 2020
function Get-SyncConfiguration
{
<#
    .SYNOPSIS
    Gets tenant's synchronization configuration

    .DESCRIPTION
    Gets tenant's synchronization configuration using Provisioning and Azure AD Sync API.
    If the user doesn't have admin rights, only a subset of information is returned.

    .Parameter AccessToken
    Access Token

    .Example
    Get-AADIntSyncConfiguration

    AllowedFeatures                         : {ObjectWriteback,  , PasswordWriteback}
    AnchorAttribute                         : mS-DS-ConsistencyGuid
    ApplicationVersion                      : 1651564e-7ce4-4d99-88be-0a65050d8dc3
    ClientVersion                           : 1.4.38.0
    DirSyncClientMachine                    : SERVER1
    DirSyncFeatures                         : 41016
    DisplayName                             : Company Ltd
    IsDirSyncing                            : true
    IsPasswordSyncing                       : false
    IsTrackingChanges                       : false
    MaxLinksSupportedAcrossBatchInProvision : 15000
    PreventAccidentalDeletion               : EnabledForCount
    SynchronizationInterval                 : PT30M
    TenantId                                : 57cf9f28-1ad7-40f4-bee8-d3ab9877f0a8
    TotalConnectorSpaceObjects              : 1
    TresholdCount                           : 500
    TresholdPercentage                      : 0
    UnifiedGroupContainer                   : 
    UserContainer                           : 
    DirSyncAnchorAttribute                  : mS-DS-ConsistencyGuid
    DirSyncServiceAccount                   : Sync_SERVER1_xxxxxxxxxxx@company.onmicrosoft.com
    DirectorySynchronizationStatus          : Enabled
    InitialDomain                           : company.onmicrosoft.com
    LastDirSyncTime                         : 2020-03-03T10:23:09Z
    LastPasswordSyncTime                    : 2020-03-04T10:23:43Z

    .Example
    Get-AADIntSyncConfiguration

    ApplicationVersion                      : 1651564e-7ce4-4d99-88be-0a65050d8dc3
    ClientVersion                           : 1.4.38.0
    DirSyncAnchorAttribute                  : mS-DS-ConsistencyGuid
    DirSyncClientMachine                    : SERVER1
    DirSyncServiceAccount                   : Sync_SERVER1_xxxxxxxxxxx@company.onmicrosoft.com
    DirectorySynchronizationStatus          : Enabled
    DisplayName                             : Company Ltd
    InitialDomain                           : company.onmicrosoft.com
    IsDirSyncing                            : true
    LastDirSyncTime                         : 2020-03-03T10:23:09Z
    LastPasswordSyncTime                    : 2020-03-04T10:23:43Z
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

        # First get configuration from Provisioning API (no admin rights needed)
        $config = Get-CompanyInformation -AccessToken $AccessToken

        # Return value
        $attributes=[ordered]@{
            ApplicationVersion =              $config.DirSyncApplicationType                 
            ClientVersion =                   $config.DirSyncClientVersion
            DirSyncAnchorAttribute =          $config.DirSyncAnchorAttribute
            DirSyncClientMachine =            $config.DirSyncClientMachineName                 
            DirSyncServiceAccount =           $config.DirSyncServiceAccount
            DirectorySynchronizationStatus =  $config.DirectorySynchronizationStatus
            DisplayName =                     $config.DisplayName
            InitialDomain =                   $config.InitialDomain
            IsDirSyncing =                    $config.DirectorySynchronizationEnabled
            LastDirSyncTime =                 $config.LastDirSyncTime 
            LastPasswordSyncTime =            $config.LastPasswordSyncTime
        }
        
        # Try to get synchronization information using Azure AD Sync
        try
        {
            $config2=Get-SyncConfiguration2 -AccessToken $AccessToken

            # Merge the configs
            foreach($key in $attributes.Keys)
            {
                $config2[$key] = $attributes[$key]
            }

            return New-Object PSObject -Property $config2
        }
        catch
        {
            return New-Object PSObject -Property $attributes
        }

        

    }
}

# Get synchronization configuration using Sync API
# Oct 11th 2018
function Get-SyncConfiguration2
{
<#
    .SYNOPSIS
    Gets tenant's synchronization configuration

    .DESCRIPTION
    Gets tenant's synchronization configuration using Provisioning and Azure AD Sync API.

    .Parameter AccessToken
    Access Token

    .Example
    Get-AADIntSyncConfiguration

    AllowedFeatures                         : {ObjectWriteback,  , PasswordWriteback}
    AnchorAttribute                         : objectGUID
    ApplicationVersion                      : 1651564e-7ce4-4d99-88be-0a65050d8dc3
    ClientVersion                           : 1.1.819.0
    DirSyncClientMachine                    : AAD-SYNC-01
    DirSyncFeatures                         : 41016
    DisplayName                             : Company Ltd
    IsDirSyncing                            : true
    IsPasswordSyncing                       : false
    IsTrackingChanges                       : false
    MaxLinksSupportedAcrossBatchInProvision : 15000
    PreventAccidentalDeletion               : EnabledForCount
    SynchronizationInterval                 : PT30M
    TenantId                                : 57cf9f28-1ad7-40f4-bee8-d3ab9877f0a8
    TotalConnectorSpaceObjects              : 24
    TresholdCount                           : 500
    TresholdPercentage                      : 0
    UnifiedGroupContainer                   : 
    UserContainer                           : 
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [int]$Recursion=1
    )
    Process
    {
        # Accept only three loops
        if($Recursion -gt 3)
        {
            throw "Too many recursions"
        }

        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

        # Create the body block
        $body=@"
		<GetCompanyConfiguration xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
            <includeLicenseInformation>false</includeLicenseInformation>
        </GetCompanyConfiguration>
"@
        $Message_id=(New-Guid).ToString()
        $Command="GetCompanyConfiguration"

        $serverName=$Script:aadsync_server

        $envelope = Create-SyncEnvelope -AccessToken $AccessToken -Command $Command -Message_id $Message_id -Body $body -Binary -Server $serverName
        
        # Call the API
        $response=Call-ADSyncAPI $envelope -Command "$Command" -Tenant_id (Read-AccessToken($AccessToken)).tid -Message_id $Message_id -Server $serverName

        # Convert binary response to XML
        $xml_doc=BinaryToXml $response

        if(IsRedirectResponse($xml_doc))
        {
            return Get-SyncConfiguration -AccessToken $AccessToken -Recursion ($Recursion+1)
        }
        else
        {
            # Create a return object
            $res=$xml_doc.Envelope.Body.GetCompanyConfigurationResponse.GetCompanyConfigurationResult

            $AllowedFeatures = @()
            foreach($feature in $res.AllowedFeatures.'#text')
            {
                $AllowedFeatures += $feature
            }

            $config=[ordered]@{

                AllowedFeatures =            $AllowedFeatures
                AnchorAttribute =            $res.DirSyncConfiguration.AnchorAttribute
                ApplicationVersion =         $res.DirSyncConfiguration.ApplicationVersion
                ClientVersion =              $res.DirSyncConfiguration.ClientVersion
                DirSyncClientMachine =       $res.DirSyncConfiguration.CurrentExport.DirSyncClientMachineName
                DirSyncFeatures =            $res.DirSyncFeatures
                DisplayName =                $res.DisplayName
                IsDirSyncing =               $res.IsDirSyncing
                IsPasswordSyncing =          $res.IsPasswordSyncing
                IsTrackingChanges =          $res.DirSyncConfiguration.IsTrackingChanges
                MaxLinksSupportedAcrossBatchInProvision = $res.MaxLinksSupportedAcrossBatchInProvision2
                PreventAccidentalDeletion =  $res.DirSyncConfiguration.PreventAccidentalDeletion.DeletionPrevention
                SynchronizationInterval =    $res.SynchronizationInterval
                TenantId =                   $res.TenantId
                TotalConnectorSpaceObjects = $res.DirSyncConfiguration.CurrentExport.TotalConnectorSpaceObjects
                TresholdCount =              $res.DirSyncConfiguration.PreventAccidentalDeletion.ThresholdCount
                TresholdPercentage =         $res.DirSyncConfiguration.PreventAccidentalDeletion.ThresholdPercentage
                UnifiedGroupContainer =      $res.WriteBack.UnifiedGroupContainer
                UserContainer =              $res.WriteBack.UserContainer
            }

            return $config
        }
    }
}

# Enables or disables Password Hash Sync (PHS)
function Set-PasswordHashSyncEnabled
{
<#
    .SYNOPSIS
    Enables or disables password hash sync (PHS)

    .DESCRIPTION
    Enables or disables password hash sync (PHS) using Azure AD Sync API.
    If dirsync is disabled, it's first enabled using Provisioning API.

    Enabling / disabling the PHS usually takes less than 10 seconds. Check the status using Get-AADIntCompanyInformation.

    .Parameter AccessToken
    Access Token

    .Parameter Enabled
    True or False

    .Example
    Set-PasswordHashSyncEnabled -Enabled $true

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [Boolean]$Enabled
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

        # Get the current configuration
        $CompanyConfig = Get-CompanyInformation -AccessToken $AccessToken

        # Check whether the PHS sync is already enabled
        if($Enabled -and $CompanyConfig["PasswordSynchronizationEnabled"].'#text' -eq "true")
        {
            Write-Host "Password Hash Synchronization already enabled"
        }
        else
        {
            # Check whether the dirsync is disabled
            if($CompanyConfig["DirectorySynchronizationEnabled"].'#text' -ne "true")
            {
                # Turn dirsync on
                Set-CompanyDirSyncEnabled -AccessToken $AccessToken -EnableDirSync $true
            }

            # Enable or disable PHS
            if($Enabled)
            {
                Set-SyncFeatures -AccessToken $AccessToken -Features 41017
            }
            else
            {
                Set-SyncFeatures -AccessToken $AccessToken -Features 41016
            }
        }
        
    }
}


# Set dirsync features (i.e. enable or disable password sync).
# May 8th 2019
function Set-SyncFeatures
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [Validateset("41016","41017")] # 41016 = DirSync, 41017 = DirSync + Password Hash Sync
        [String]$Features="41016",
        [Parameter(Mandatory=$False)]
        [int]$Recursion=1
    )
    Process
    {
        # Accept only three loops
        if($Recursion -gt 3)
        {
            throw "Too many recursions"
        }

        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

        # Create the body block
        $body=@"
		<SetCompanyDirsyncFeatures xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
            <dirsyncFeatures>$Features</dirsyncFeatures>
        </SetCompanyDirsyncFeatures>
"@
        $Message_id=(New-Guid).ToString()
        $Command="SetCompanyDirsyncFeatures"

        $serverName=$Script:aadsync_server

        $envelope = Create-SyncEnvelope -AccessToken $AccessToken -Command $Command -Message_id $Message_id -Body $body -Binary -Server $serverName
        
        # Call the API
        $response=Call-ADSyncAPI $envelope -Command "$Command" -Tenant_id (Read-AccessToken($AccessToken)).tid -Message_id $Message_id -Server $serverName

        # Convert binary response to XML
        $xml_doc=BinaryToXml $response

        if(IsRedirectResponse($xml_doc))
        {
            return Set-SyncFeatures -AccessToken $AccessToken -Features $Features -Recursion ($Recursion+1)
        }
        else
        {
            # Create a return object
            $res=$xml_doc.Envelope.Body.GetCompanyConfigurationResponse.GetCompanyConfigurationResult

            
        }
    }
}

# Provision Azure AD Sync Object
function Set-AzureADObject
{
<#
    .SYNOPSIS
    Creates or updates Azure AD object using Azure AD Sync API

    .DESCRIPTION
    Creates or updates Azure AD object using Azure AD Sync API

    .Parameter AccessToken
    Access Token

    .Parameter sourceAnchor
    The source anchor for the Azure AD object. Typically Base 64 encoded GUID of on-prem AD object.

    .Parameter userPrincipalName
    User Principal Name of the Azure AD object

    .Parameter surname
    The last name of the Azure AD object

    .Parameter onPremisesSamAccountName
    The on-prem AD samaccountname of the Azure AD object

    .Parameter onPremisesDistinguishedName
    The on-prem AD DN of the Azure AD object

    .Parameter onPremisesSecurityIdentifier
    The on-prem AD security identifier of the Azure AD object

    .Parameter netBiosName
    The on-prem netbiosname of the Azure AD object

    .Parameter lastPasswordChangeTimeStamp
    Timestamp when the on-prem AD object's password was changed

    .Parameter givenName
    The first name of the Azure AD object

    .Parameter dnsDomainName
    The dns domain name of the Azure AD object

    .Parameter displayName
    The display name of the Azure AD object

    .Parameter countryCode
    The country code of the Azure AD object.

    .Parameter commonName
    The common name of the Azure AD object

    .Parameter accountEnabled
    Is the Azure AD object enabled. Default is $True.

    .Parameter cloudMastered
    Is the Azure AD object editable in Azure AD. Default is $true

    .Parameter usageLocation
    Two letter country code for usage location of Azure AD object.

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$sourceAnchor,
        [Parameter(Mandatory=$False)]
        [String]$userPrincipalName,
        [Parameter(Mandatory=$False)]
        [String]$surname,
        [Parameter(Mandatory=$False)]
        [String]$onPremisesSamAccountName,
        [Parameter(Mandatory=$False)]
        [String]$onPremisesDistinguishedName,
        [Parameter(Mandatory=$False)]
        [String]$onPremiseSecurityIdentifier,
        [Parameter(Mandatory=$False)]
        [String]$netBiosName,
        [Parameter(Mandatory=$False)]
        [String]$lastPasswordChangeTimestamp,
        [Parameter(Mandatory=$False)]
        [String]$givenName,
        [Parameter(Mandatory=$False)]
        [String]$dnsDomainName,
        [Parameter(Mandatory=$False)]
        [String]$displayName,
        [Parameter(Mandatory=$False)]
        [int]$countryCode=0,
        [Parameter(Mandatory=$False)]
        [String]$commonName,
        [Parameter(Mandatory=$False)]
        [String]$CloudAnchor,
        [Parameter(Mandatory=$False)]
        [bool]$accountEnabled=$True,
        [Parameter(Mandatory=$False)]
        [bool]$cloudMastered=$True,
        [Parameter(Mandatory=$False)]
        [ValidateSet('AF','AX','AL','DZ','AS','AD','AO','AI','AQ','AG','AR','AM','AW','AU','AT','AZ','BS','BH','BD','BB','BY','BE','BZ','BJ','BM','BT','BO','BQ','BA','BW','BV','BR','IO','BN','BG','BF','BI','KH','CM','CA','CV','KY','CF','TD','CL','CN','CX','CC','CO','KM','CG','CD','CK','CR','CI','HR','CU','CW','CY','CZ','DK','DJ','DM','DO','EC','EG','SV','GQ','ER','EE','ET','FK','FO','FJ','FI','FR','GF','PF','TF','GA','GM','GE','DE','GH','GI','GR','GL','GD','GP','GU','GT','GG','GN','GW','GY','HT','HM','VA','HN','HK','HU','IS','IN','ID','IQ','IE','IR','IM','IL','IT','JM','JP','JE','JO','KZ','KE','KI','KP','KR','KW','KG','LA','LV','LB','LS','LR','LY','LI','LT','LU','MO','MK','MG','MW','MY','MV','ML','MT','MH','MQ','MR','MU','YT','MX','FM','MD','MC','MN','ME','MS','MA','MZ','MM','NA','NR','NP','NL','NC','NZ','NI','NE','NG','NU','NF','MP','NO','OM','PK','PW','PS','PA','PG','PY','PE','PH','PN','PL','PT','PR','QA','RE','RO','RU','RW','BL','SH','KN','LC','MF','PM','VC','WS','SM','ST','SA','SN','RS','SC','SL','SG','SX','SK','SI','SB','SO','ZA','GS','SS','ES','LK','SD','SR','SJ','SZ','SE','CH','SY','TW','TJ','TZ','TH','TL','TG','TK','TO','TT','TN','TR','TM','TC','TV','UG','UA','AE','GB','US','UM','UY','UZ','VU','VE','VN','VG','VI','WF','EH','YE','ZM','ZW')][String]$usageLocation,
        [Parameter(Mandatory=$False)]
        [ValidateSet('User','Group','Contact')]
        [String]$ObjectType="User",
        [Parameter(Mandatory=$False)]
        [String[]]$proxyAddresses,
        [Parameter(Mandatory=$False)]
        [int]$Recursion=1
    )
    Process
    {
        # Accept only three loops
        if($Recursion -gt 3)
        {
            throw "Too many recursions"
        }
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

        # Create the body block
        $body_start=@"
        <ProvisionAzureADSyncObjects xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
			<syncRequest xmlns:b="http://schemas.microsoft.com/online/aws/change/2014/06" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
				<b:SyncObjects>
					<b:AzureADSyncObject>
						<b:PropertyValues xmlns:c="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
"@
        $body_mid= Add-PropertyValue "SourceAnchor" $sourceAnchor
        $body_mid+=Add-PropertyValue "accountEnabled" $accountEnabled -Type bool
        $body_mid+=Add-PropertyValue "commonName" $commonName
        $body_mid+=Add-PropertyValue "countryCode" $countryCode -Type long
        $body_mid+=Add-PropertyValue "displayName" $displayName
        $body_mid+=Add-PropertyValue "dnsDomainName" $dnsDomainName
        $body_mid+=Add-PropertyValue "givenName" $givenName
        $body_mid+=Add-PropertyValue "lastPasswordChangeTimestamp" $lastPasswordChangeTimestamp
        $body_mid+=Add-PropertyValue "netBiosName" $netBiosName
        $body_mid+=Add-PropertyValue "onPremiseSecurityIdentifier" $onPremiseSecurityIdentifier -Type base64
        $body_mid+=Add-PropertyValue "onPremisesDistinguishedName" $onPremisesDistinguishedName
        $body_mid+=Add-PropertyValue "surname" $surname
        $body_mid+=Add-PropertyValue "userPrincipalName" $userPrincipalName
        $body_mid+=Add-PropertyValue "cloudMastered" $cloudMastered -Type bool
        $body_mid+=Add-PropertyValue "usageLocation" $usageLocation
        $body_mid+=Add-PropertyValue "CloudAnchor" $CloudAnchor
        $body_mid+=Add-PropertyValue "proxyAddresses" $proxyAddresses -Type ArrayOfstring

$body_end=@"
                        </b:PropertyValues>
						<b:SyncObjectType>$ObjectType</b:SyncObjectType>
						<b:SyncOperation>Set</b:SyncOperation>
					</b:AzureADSyncObject>
				</b:SyncObjects>
			</syncRequest>
		</ProvisionAzureADSyncObjects>
"@

        $body=$body_start+$body_mid+$body_end
        $Message_id=(New-Guid).ToString()
        $Command="ProvisionAzureADSyncObjects"

        $serverName=$aadsync_server

        $envelope = Create-SyncEnvelope -AccessToken $AccessToken -Command $Command -Message_id $Message_id -Body $body -Binary -Server $serverName
        
        # Call the API
        $response=Call-ADSyncAPI $envelope -Command "$Command" -Tenant_id (Read-AccessToken($AccessToken)).tid -Message_id $Message_id -Server $serverName
        
        # Convert binary response to XML
        $xml_doc=BinaryToXml $response

        
        if(IsRedirectResponse($xml_doc))
        {
            return Set-AzureADObject -AccessToken $AccessToken -Recursion ($Recursion+1) -sourceAnchor $sourceAnchor -ObjectType $ObjectType -userPrincipalName $userPrincipalName -surname $surname -onPremisesSamAccountName $onPremisesSamAccountName -onPremisesDistinguishedName $onPremisesDistinguishedName -onPremiseSecurityIdentifier $onPremisesDistinguishedName -netBiosName $netBiosName -lastPasswordChangeTimestamp $lastPasswordChangeTimestamp -givenName $givenName -dnsDomainName $dnsDomainName -displayName $displayName -countryCode $countryCode -commonName $commonName -accountEnabled $accountEnabled -cloudMastered $cloudMastered -usageLocation $usageLocation -CloudAnchor $CloudAnchor
        }
        
        # Return
        $xml_doc.Envelope.Body.ProvisionAzureADSyncObjectsResponse.ProvisionAzureADSyncObjectsResult.SyncObjectResults.AzureADSyncObjectResult
    }
}


# Removes the given Azure AD Object
function Remove-AzureADObject
{
<#
    .SYNOPSIS
    Removes Azure AD object using Azure AD Sync API

    .DESCRIPTION
    Removes Azure AD object using Azure AD Sync API

    .Parameter AccessToken
    Access Token

    .Parameter sourceAnchor
    The source anchor for the Azure AD object. Typically Base 64 encoded GUID of on-prem AD object.


#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$sourceAnchor,
        [Parameter(Mandatory=$False)]
        [ValidateSet('User')][String]$ObjectType="User",
        [Parameter(Mandatory=$False)]
        [int]$Recursion=1
    )
    Process
    {
        # Accept only three loops
        if($Recursion -gt 3)
        {
            throw "Too many recursions"
        }
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

        # Create the body block
        $body_start=@"
        <ProvisionAzureADSyncObjects xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
			<syncRequest xmlns:b="http://schemas.microsoft.com/online/aws/change/2014/06" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
				<b:SyncObjects>
					<b:AzureADSyncObject>
						<b:PropertyValues xmlns:c="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
"@
        $body_mid= Add-PropertyValue "SourceAnchor" $sourceAnchor
        

$body_end=@"
                        </b:PropertyValues>
						<b:SyncObjectType>$ObjectType</b:SyncObjectType>
						<b:SyncOperation>Delete</b:SyncOperation>
					</b:AzureADSyncObject>
				</b:SyncObjects>
			</syncRequest>
		</ProvisionAzureADSyncObjects>
"@

        $body=$body_start+$body_mid+$body_end
        $Message_id=(New-Guid).ToString()
        $Command="ProvisionAzureADSyncObjects"

        $serverName=$aadsync_server

        $envelope = Create-SyncEnvelope -AccessToken $AccessToken -Command $Command -Message_id $Message_id -Body $body -Binary -Server $serverName
        
        # Call the API
        $response=Call-ADSyncAPI $envelope -Command "$Command" -Tenant_id (Read-AccessToken($AccessToken)).tid -Message_id $Message_id -Server $serverName
        
        # Convert binary response to XML
        $xml_doc=BinaryToXml $response

        
        if(IsRedirectResponse($xml_doc))
        {
            return Remove-AzureADObject -AccessToken $AccessToken -Recursion ($Recursion+1) -sourceAnchor $sourceAnchor -ObjectType $ObjectType
        }
        
        # Return
        $xml_doc.Envelope.Body.ProvisionAzureADSyncObjectsResponse.ProvisionAzureADSyncObjectsResult.SyncObjectResults.AzureADSyncObjectResult
    }
}


# Finalize Azure AD Sync
function Finalize-Export
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [int]$Count=1,
        [Parameter(Mandatory=$False)]
        [int]$Recursion=1
    )
    Process
    {
        # Accept only three loops
        if($Recursion -gt 3)
        {
            throw "Too many recursions"
        }

        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

        # Create the body block
        

        $body=@"
        <FinalizeExport xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
			<totalExported>$count</totalExported>
			<successfulExportCount>$count</successfulExportCount>
		</FinalizeExport>
"@
        $Message_id=(New-Guid).ToString()
        $Command="FinalizeExport"

        $serverName=$aadsync_server

        $envelope = Create-SyncEnvelope -AccessToken $AccessToken -Command $Command -Message_id $Message_id -Body $body -Binary -Server $serverName
        
        # Call the API
        $response=Call-ADSyncAPI $envelope -Command "$Command" -Tenant_id (Parse-AccessToken($AccessToken)).tid -Message_id $Message_id -Server $serverName

        # Convert binary response to XML
        $xml_doc=BinaryToXml $response
        
        if(IsRedirectResponse($xml_doc))
        {
            return Finalize-Export -Count $Count -AccessToken $AccessToken -Recursion ($Recursion+1)
        }
        else
        {
            return $xml_doc
        }
    }
}

# Get sync objects from Azure AD
function Get-SyncObjects
{
<#
    .SYNOPSIS
    Gets tenant's synchronized objects

    .DESCRIPTION
    Gets tenant's synchronized objects using Azure AD Sync API

    .Parameter AccessToken
    Access Token
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [int]$Recursion=1
    )
    Process
    {
        # Accept only three loops
        if($Recursion -gt 3)
        {
            throw "Too many recursions"
        }

        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

        # Create the body block
        $body=@"
		<ReadBackAzureADSyncObjects xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
            <includeLicenseInformation>true</includeLicenseInformation>
            <inputCookie i:nil="true" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"></inputCookie>
            <isFullSync>true</isFullSync>
        </ReadBackAzureADSyncObjects>
"@
        $Message_id=(New-Guid).ToString()
        $Command="ReadBackAzureADSyncObjects"

        $serverName=$Script:aadsync_server

        $envelope = Create-SyncEnvelope -AccessToken $AccessToken -Command $Command -Message_id $Message_id -Body $body -Binary -Server $serverName
        
        # Call the API
        $response=Call-ADSyncAPI $envelope -Command "$Command" -Tenant_id (Read-AccessToken($AccessToken)).tid -Message_id $Message_id -Server $serverName

        # Convert binary response to XML
        $xml_doc=BinaryToXml $response

        if(IsRedirectResponse($xml_doc))
        {
            return Get-SyncObjects -AccessToken $AccessToken -Recursion ($Recursion+1)
        }
        else
        {
            # Create a return object
            $res=$xml_doc.Envelope.Body.ReadBackAzureADSyncObjectsResponse.ReadBackAzureADSyncObjectsResult

            # Loop through objects
            foreach($obj in $res.ResultObjects.AzureADSyncObject)
            {
                $details=@{}
                $details.SyncObjectType=$obj.SyncObjectType
                $details.SyncOperation=$obj.SyncOperation

                # Loop through all key=value pairs
                foreach($kv in $obj.PropertyValues.KeyValueOfstringanyType)
                {
                    $details[$kv.Key]=$kv.value.'#text'
                }

                # Return
                New-Object -TypeName PSObject -Property $details
            }

        }
    }
}


# Set's user's password
function Set-UserPassword
{
<#
    .SYNOPSIS
    Sets the password of the given user

    .DESCRIPTION
    Sets the password of the given user using Azure AD Sync API. If the Result is 0, the change was successful.
    Requires that Directory Synchronization is enabled for the tenant!

    .Parameter AccessToken
    Access Token

    .Parameter SourceAnchor
    User's source anchor (ImmutableId)

    .Parameter Password
    User's new password

    .Parameter ChangeDate
    Time of the password change. Can be now or in the past.

    .Example
    Set-AADIntUserPassword -SourceAnchor "Vvl6blILG0/Cr/8TWOe9pg==" -Password "MyPassword" -ChangeDate ((Get-Date).AddYears(-1))

    CloudAnchor Result SourceAnchor            
    ----------- ------ ------------            
    CloudAnchor 0      Vvl6blILG0/Cr/8TWOe9pg==
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$SourceAnchor,
        [Parameter(Mandatory=$True)]
        [String]$Password,
        [Parameter(Mandatory=$False)]
        [DateTime]$ChangeDate=(Get-Date),
        [Parameter(Mandatory=$False)]
        [int]$Recursion=1
    )
    Process
    {
        # Accept only three loops
        if($Recursion -gt 3)
        {
            throw "Too many recursions"
        }

        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

        # Create AAD hash
        $CredentialData = Create-AADHash -Password $Password

        # Create the body block
        $body=@"
		<ProvisionCredentials xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
	        <request xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.Online.Coexistence.Schema" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
		        <b:RequestItems>
			        <b:SyncCredentialsChangeItem>
				        <b:ChangeDate>$($ChangeDate.ToUniversalTime().ToString("o"))</b:ChangeDate>
				        <b:CloudAnchor i:nil="true"/>
				        <b:CredentialData>$CredentialData</b:CredentialData>
				        <b:ForcePasswordChangeOnLogon>false</b:ForcePasswordChangeOnLogon>
				        <b:SourceAnchor>$SourceAnchor</b:SourceAnchor>
				        <b:WindowsLegacyCredentials i:nil="true"/>
				        <b:WindowsSupplementalCredentials i:nil="true"/>
			        </b:SyncCredentialsChangeItem>
		        </b:RequestItems>
	        </request>
        </ProvisionCredentials>
"@
        $Message_id=(New-Guid).ToString()
        $Command="ProvisionCredentials"

        $serverName=$Script:aadsync_server

        $envelope = Create-SyncEnvelope -AccessToken $AccessToken -Command $Command -Message_id $Message_id -Body $body -Binary -Server $serverName
        
        # Call the API
        $response=Call-ADSyncAPI $envelope -Command "$Command" -Tenant_id (Read-AccessToken($AccessToken)).tid -Message_id $Message_id -Server $serverName

        # Convert binary response to XML
        $xml_doc=BinaryToXml $response

        if(IsRedirectResponse($xml_doc))
        {
            return Set-UserPassword -AccessToken $AccessToken -Recursion ($Recursion+1) -SourceAnchor $SourceAnchor -Password $Password -ChangeDate $ChangeDate
        }
        else
        {
            # Return

            return $xml_doc.Envelope.Body.ProvisionCredentialsResponse.ProvisionCredentialsResult.Results.SyncCredentialsChangeResult

            

        }
    }
}

# Creates or reset service account
function Reset-ServiceAccount
{
<#
    .SYNOPSIS
    Create or reset Azure AD Connect sync service account.

    .DESCRIPTION
    Creates a new user account for Azure AD Connect sync service OR resets existing user's password. 
    The created user will have DirecotrySynchronizationAccount role.

    .Parameter AccessToken
    Access Token

    .Parameter ServiceAccount
    Name of the service account to be created.

    .Example
    Reset-AADIntServiceAccount -AccessToken $at -ServiceAccount myserviceaccount

    Password         UserName                         
    --------         --------                         
    s@S)uv_?*!IBsu%- myserviceaccount@company.onmicrosoft.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$ServiceAccount,
        [Parameter(Mandatory=$False)]
        [int]$Recursion=1
    )
    Process
    {
        # Accept only three loops
        if($Recursion -gt 3)
        {
            throw "Too many recursions"
        }

        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

       # Create the body block
        $body=@"
	    <GetServiceAccount xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
		    <identifier>$ServiceAccount</identifier>
	    </GetServiceAccount>
"@
        $Message_id=(New-Guid).ToString()
        $Command="GetServiceAccount"

        $serverName=$Script:aadsync_server

        $envelope = Create-SyncEnvelope -AccessToken $AccessToken -Command $Command -Message_id $Message_id -Body $body -Binary -Server $serverName
        
        # Call the API
        $response=Call-ADSyncAPI $envelope -Command "$Command" -Tenant_id (Read-AccessToken($AccessToken)).tid -Message_id $Message_id -Server $serverName

        # Convert binary response to XML
        $xml_doc=BinaryToXml $response

        if(IsRedirectResponse($xml_doc))
        {
            return Get-ServiceAccount -AccessToken $AccessToken -Recursion ($Recursion+1) -ServiceAccount $ServiceAccount
        }
        else
        {
            # Return

            $retval = $xml_doc.Envelope.Body.GetServiceAccountResponse.GetServiceAccountResult
            if($retval -eq $null)
            {
                return $xml_doc.Envelope.Body.Fault.Reason.Text.'#text'
            }
            else
            {
                # Create and return response object
                $Attributes = @{
                    UserName = $retval.UserName
                    Password = $retval.Password
                }
                return New-Object -TypeName psobject -Property $Attributes
            }
        }
    }
}

# Enable or disable pass-through authentication
function Set-PassThroughAuthenticationEnabled
{
<#
    .SYNOPSIS
    Enables or disables passthrough authentication (PTA).

    .DESCRIPTION
    Enables or disables passthrough authentication (PTA) using msapproxy.net api.

    .Parameter AccessToken
    Access Token.

    .Parameter Enabled
    Whether to enable or disable PTA.

    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>$pt=Get-AADIntAccessTokenForPTA -Credentials $cred
    PS C:\>Set-AADIntPassThroughAuthentication -AccessToken $pt -Enable $true

    IsSuccesful Enable Exists
    ----------- ------ ------
    true        true   true
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [bool]$Enable
    )
    Process
    {

       # Create the body block
        $body=@"
	    <PassthroughAuthenticationEnablementRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RegistrationCommons.Registration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	        <AuthenticationToken xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Security.AadSecurity">$AccessToken</AuthenticationToken>
	        <Enable>$($Enable.ToString().ToLower())</Enable>
	        <SkipExoEnablement>false</SkipExoEnablement>
	        <UserAgent>AADConnect/1.1.882.0 PassthroughAuthenticationConnector/1.5.405.0</UserAgent>
        </PassthroughAuthenticationEnablementRequest>
"@
        $tenant_id = Get-TenantId -AccessToken $AccessToken
        
        # Call the api
        $response=Invoke-RestMethod -Uri "https://$tenant_id.registration.msappproxy.net/register/EnablePassthroughAuthentication" -Method Post -ContentType "application/xml; charset=utf-8" -Body $body

        # Create and return the response object
        $attributes=@{
            IsSuccesful = $response.PassthroughAuthenticationRequestResult.IsSuccessful
            Enable = $response.PassthroughAuthenticationRequestResult.Enable
            Exists = $response.PassthroughAuthenticationRequestResult.Exists
        }
        return New-Object -TypeName psobject -Property $Attributes
    }
}

# Aug 21st 2019
function Get-DesktopSSO
{
<#
    .SYNOPSIS
    Returns the status of Seamless SSO status

    .DESCRIPTION
    Returns the status of Seamless SSO status

    .Parameter AccessToken
    Access Token.

    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>$pt=Get-AADIntAccessTokenForPTA -Credentials $cred
    PS C:\>Get-AADIntSeamlessSSO -AccessToken $pt

    Domains      : company.com
    Enable       : True
    ErrorMessage : 
    Exists       : True
    IsSuccessful : True
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        $tenantId = (Read-Accesstoken $AccessToken).tid
        $url="https://$tenantId.registration.msappproxy.net/register/GetDesktopSsoStatus"

        $body=@"
        <TokenAuthenticationRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Security.AadSecurity" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	        <AuthenticationToken>$AccessToken</AuthenticationToken>
        </TokenAuthenticationRequest>
"@
        $results=Invoke-RestMethod -Uri $url -Body $body -Method Post -ContentType "application/xml; charset=utf-8"

        $attributes=@{
            "ErrorMessage" = $results.DesktopSsoStatusResult.ErrorMessage
            "IsSuccessful" = $($results.DesktopSsoStatusResult.IsSuccessful -eq "true")
            "Enabled" = $($results.DesktopSsoStatusResult.Enable -eq "true")
            "Exists" = $($results.DesktopSsoStatusResult.Exists -eq "true")
            "Domains" = $results.DesktopSsoStatusResult.domains.string
        }

        return New-Object -TypeName PSObject -Property $attributes
    }
}

# Aug 21st 2019
function Set-DesktopSSO
{
<#
    .SYNOPSIS
    Enables or disables Seamless SSO for the given domain

    .DESCRIPTION
    Enables or disables Seamless SSO for the given domain

    .Parameter AccessToken
    Access Token.

    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>$pt=Get-AADIntAccessTokenForPTA -Credentials $cred
    PS C:\>Set-AADIntSeamlessSSO -AccessToken $pt -DomainName "company.net" -Password "MySecretPassWord"

    IsSuccessful ErrorMessage
    ------------ ------------
            True             
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$ComputerName="AZUREADSSOACC",
        [Parameter(Mandatory=$True)]
        [String]$DomainName,
        [Parameter(Mandatory=$False)]
        [Bool]$Enable=$True,
        [Parameter(Mandatory=$True)]
        [String]$Password
    )
    Process
    {
        $tenantId = (Read-Accesstoken $AccessToken).tid
        $url="https://$tenantId.registration.msappproxy.net/register/EnableDesktopSso"

        $body=@"
        <DesktopSsoRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RegistrationCommons.Registration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	        <AuthenticationToken xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Security.AadSecurity">$AccessToken</AuthenticationToken>
	        <ComputerName>$ComputerName</ComputerName>
	        <DomainName>$DomainName</DomainName>
	        <Enable>$($Enable.ToString().ToLower())</Enable>
	        <Secret>$([System.Security.SecurityElement]::Escape($Password))</Secret>
        </DesktopSsoRequest>
"@
        $results=Invoke-RestMethod -Uri $url -Body $body -Method Post -ContentType "application/xml; charset=utf-8"


        $attributes=@{
            "ErrorMessage" = $results.DesktopSsoEnablementResult.ErrorMessage
            "IsSuccessful" = $($results.DesktopSsoEnablementResult.IsSuccessful -eq "true")
        }

        $setPwd=Read-Host -Prompt "Would you like to set the password of $ComputerName to `"$Password`"(yes/no)?"
        if($setPwd -eq "yes")
        {
            
            try
            {
                $computer = Get-ADComputer $ComputerName
                Set-ADAccountPassword -Identity $computer.DistinguishedName -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force)

                # TGT ticket can be alive for a week..
                Write-Warning "Password set for $ComputerName. The Kerberos Key Distribution Center should be restarted for the change to take effect."
            }
            catch
            {
                Write-Error "Could not set password for $ComputerName! Set it manually using Set-ADAccountPassword -Identity $($computer.DistinguishedName) -NewPassword (ConvertTo-SecureString -AsPlainText `"$Password`" -Force)"
            }
        }
        else
        {
            # If not set, users won't be able to login..
            Write-Warning "Password NOT set for $ComputerName! Set it manually to `"$Password`" and restart Kerberos Key Distribution Center for the change to take effect."
        }

        return New-Object -TypeName PSObject -Property $attributes
    }
}

# Aug 21st 2019
function Set-DesktopSSOEnabled
{
<#
    .SYNOPSIS
    Enables or disables Seamless SSO 

    .DESCRIPTION
    Enables or disables Seamless SSO 

    .Parameter AccessToken
    Access Token.

    .Example
    PS C:\>$cred=Get-Credential
    PS C:\>$pt=Get-AADIntAccessTokenForPTA -Credentials $cred
    PS C:\>Set-AADIntSeamlessSSOEnabled -AccessToken $pt -Enable $true 

    Domains      : company.com
    Enabled      : True
    ErrorMessage : 
    Exists       : True
    IsSuccessful : True          
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [Bool]$Enable=$True
    )
    Process
    {
        $tenantId = (Read-Accesstoken $AccessToken).tid
        $url="https://$tenantId.registration.msappproxy.net/register/EnableDesktopSsoFlag"

        $body=@"
        <DesktopSsoEnablementRequest  xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RegistrationCommons.Registration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	        <AuthenticationToken xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Security.AadSecurity">$AccessToken</AuthenticationToken>
	        <Enable>$($Enable.ToString().ToLower())</Enable>
        </DesktopSsoEnablementRequest >
"@
        $results=Invoke-RestMethod -Uri $url -Body $body -Method Post -ContentType "application/xml; charset=utf-8"


        $attributes=@{
            "ErrorMessage" = $results.DesktopSsoEnablementResult.ErrorMessage
            "IsSuccessful" = $($results.DesktopSsoEnablementResult.IsSuccessful -eq "true")
        }

        return New-Object -TypeName PSObject -Property $attributes
    }
}