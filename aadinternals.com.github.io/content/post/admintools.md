+++
title = "AADInternals admin and blue team tools"
date = "2021-09-07"
lastmod = "2021-12-22"
categories =["blog"]
tags = ["administration","blue team"]
thumbnail = "/images/posts/admintools.png"
+++

AADInternals toolkit is best known of its offensive or red teams tools. Its origins, however, is in administration - especially for tasks not supported by official tools.

In this blog, I'll introduce recent additions to the admin & blue team tools and also some old goodies!

<!--more-->
# Tenant settings

There are a lot of settings available in the admin portals affecting the security of your tenant. I've selected the following functions to help you to protect your tenant and to easily move to modern authentication.

## Guest Access

As I've demonstrated <a href="/post/quest_for_guest/" target=_blank>earlier</a>, by default, guest users have way too much permissions and can effectively export the users and groups of your tenant. 

To protect your tenant from the guest users, the <a href="https://portal.azure.com/#blade/Microsoft_AAD_IAM/AllowlistPolicyBlade" target="_blank">External collaboration settings</a> should be set to **most restrictive**:

![blaa](/images/posts/quest4guest_4.png)

The status of this setting can easily be checked with AADInternals:

{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Get the tenant guest access
Get-AADIntTenantGuestAccess
{{< /highlight>}}

**Output:**
```
Access Description                                                                        RoleId                              
------ -----------                                                                        ------                              
Normal Guest users have limited access to properties and memberships of directory objects 10dae51f-b6af-4016-8d66-8c2a99b929b3
```

There are three different access levels:

Access level  | Description
---|---
Inclusive     | Guest users have the same access as members
Normal        | Guest users have limited access to properties and memberships of directory objects
Restricted    | Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)

To change the settings using AADInternals (requires Global Administrator role):

{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Get the tenant guest access
Set-AADIntTenantGuestAccess -Level Restricted
{{< /highlight>}}

**Output:**
```
Access Description                                                                                               RoleId                              
------ -----------                                                                                               ------                              
 Guest user access is restricted to properties and memberships of their own directory objects (most restrictive) 2af84b1e-32c8-42b7-82bc-daa82404023b
```

## Azure AD Graph API access

Azure AD is seems to built with the principle than on-premises AD that effectively gives read-only permissions to the whole content of Azure AD, including tenant-level settings.

I've earlier discussed about the ways to <a href="/post/limit-user-access/" target="_blank">restrict users's access</a> to Azure AD data.

The both currently used PowerShell modules (<a href="https://docs.microsoft.com/en-us/powershell/module/msonline" target="_blank">MSOnline</a> and <a href="https://docs.microsoft.com/en-us/powershell/azure/active-directory/overview" target="_blank">AzureAD</a>) are both utilising Azure AD Graph endpoint.
Microsoft <a href="https://techcommunity.microsoft.com/t5/azure-active-directory-identity/update-your-applications-to-use-microsoft-authentication-library/ba-p/1257363" target="_blank">announced</a> in June 2020 that the end-of-support for AAD Graph API will be June 30th 2022.

In the meantime, to disable access to Azure AD Graph using AADInternals:

{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Disable access to AAD Graph API
Disable-AADIntTenantMsolAccess

# Check the settings after 10 seconds or so.
Get-AADIntTenantAuthPolicy | Select block*
{{< /highlight>}}

**Output:**
```
blockMsolPowerShell
-------------------
              True
```



## Self-service purchase products

Self-service purchase products are, as the name suggests, products that tenant users can purchase by themselves. While the products do not generate any billing for the organisation, they can introduce security issues as they may allow access to the organisation data.

I recently read a great <a href="https://office365itpros.com/2021/07/20/block-self-service-purchases-of-windows-365-licenses/" target="_blank">article</a> by **Tony Redmond** (<a href="https://twitter.com/12Knocksinna" target="_blank">@12Knockssinna</a>) on how to block the self-service purchases per product. 
This involved installing <a href="https://www.powershellgallery.com/packages/MSCommerce/1.6" target="_blank">MS Commerce PowerShell module</a> and playing around with product IDs which I felt a bit too complicated.

To block self-service purchase for all products a bit easier with AADInternals:

{{< highlight powershell >}}
# Disable self-service purchase for all products
Get-AADIntSelfServicePurchaseProducts | Set-AADIntSelfServicePurchaseProduct -Enabled $false
{{< /highlight>}}
**Output:**
```
Product                                          Id           Status  
-------                                          --           ------  
Windows 365 Enterprise                           CFQ7TTC0HHS9 Disabled
Windows 365 Business with Windows Hybrid Benefit CFQ7TTC0HX99 Disabled
Windows 365 Business                             CFQ7TTC0J203 Disabled
Power Automate per user                          CFQ7TTC0KP0N Disabled
Power Apps per user                              CFQ7TTC0KP0P Disabled
Power Automate RPA                               CFQ7TTC0KXG6 Disabled
Power BI Premium (standalone)                    CFQ7TTC0KXG7 Disabled
Visio Plan 2                                     CFQ7TTC0KXN8 Disabled
Visio Plan 1                                     CFQ7TTC0KXN9 Disabled
Project Plan 3                                   CFQ7TTC0KXNC Disabled
Project Plan 1                                   CFQ7TTC0KXND Disabled
Power BI Pro                                     CFQ7TTC0L3PB Disabled
```

**Note:** New self-service purchase products are introduced on regular basis, so don't forget to check the products at least once a month!

## Unified Audit log 

The <a href="https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance?view=o365-worldwide" target="_blank">Unified Audit Log</a> contains the following user and admin activity in Microsoft 365 and Azure AD:

* User activity in SharePoint Online and OneDrive for Business
* User activity in Exchange Online (Exchange mailbox audit logging)
* Admin activity in SharePoint Online
* Admin activity in Azure Active Directory (the directory service for Microsoft 365)
* Admin activity in Exchange Online (Exchange admin audit logging)
* eDiscovery activities in the security and compliance center
* User and admin activity in Power BI
* User and admin activity in Microsoft Teams
* User and admin activity in Dynamics 365
* User and admin activity in Yammer
* User and admin activity in Microsoft Power Automate
* User and admin activity in Microsoft Stream
* Analyst and admin activity in Microsoft Workplace Analytics
* User and admin activity in Microsoft Power Apps
* User and admin activity in Microsoft Forms
* User and admin activity for sensitivity labels for sites that use SharePoint Online or Microsoft Teams
* Admin activity in Briefing email and MyAnalytics

As such, the Unified Audit Log is a main source or forensic data for any Incident Response (IR) engagement.

You can turn on the Unified Audit Log with AADInternals:

{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForEXO -SaveToCache

# Disable the unified audit log
Set-AADIntUnifiedAuditLogSettings -Enabled true
{{< /highlight>}}

**Note!** It will take hours for the changes to take effect!

# Logging

As mentioned above, the Unified Audit log contains forensic data for Azure AD and Office/Microsoft 365. There are also other logs containing valuable forensic data.

## Diagnostic settings

> Diagnostic settings are used to configure streaming export of platform logs and metrics for a resource to the destination of your choice. You may create up to five different diagnostic settings to send different logs and metrics to independent destinations.

Diagnostic settings can be set in the Azure Admin Portal but the functionality is also added to AADInternals.

To view the current settings:
{{< highlight powershell >}}
# Get the access token
$at=Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# List diagnostic settings
Get-AADIntAzureDiagnosticSettings
{{< /highlight>}}

**Output:**
```
Name                        : Audit and SignIn to Sentinel
WorkspaceId                 : /subscriptions/a04293e7-46c8-4bf4-bc6d-1bc1f41afae0/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/MySentinel
StorageAccountId            : 
EventHubAuthorizationRuleId : 
EventHubName                : 
ServiceBusRuleId            : 

Name                        : Service Principal to Sentinel
WorkspaceId                 : /subscriptions/a04293e7-46c8-4bf4-bc6d-1bc1f41afae0/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/MySentinel
StorageAccountId            : 
EventHubAuthorizationRuleId : 
EventHubName                : 
ServiceBusRuleId            :
```

To get details of a specific settings:
{{< highlight powershell >}}
# List diagnostic settings for the given workspace
Get-AADAzureIntDiagnosticSettingsDetails -Name "Audit and SignIn to Sentinel"
{{< /highlight>}}

**Output:**
```
Log                          Enabled Retention Enabled Retention Days
---                          ------- ----------------- --------------
ProvisioningLogs               False             False              0
AuditLogs                      False             False              0
SignInLogs                     False             False              0
NonInteractiveUserSignInLogs   False             False              0
ServicePrincipalSignInLogs     False             False              0
ManagedIdentitySignInLogs       True              True            365
```

To change the settings:

{{< highlight powershell >}}
# Set the diagnostic log settings for the given workspace
Set-AADIntDiagnosticSettingsDetails -Name "Audit and SignIn to Sentinel" -Log ManagedIdentitySignInLogs,AuditLogs,SignInLogs -Enabled $true -RetentionEnabled $true -RetentionDays 365
{{< /highlight>}}

**Output:**
```
Log                          Enabled Retention Enabled Retention Days
---                          ------- ----------------- --------------
ProvisioningLogs               False             False              0
AuditLogs                       True              True            365
SignInLogs                      True              True            365
NonInteractiveUserSignInLogs   False             False              0
ServicePrincipalSignInLogs     False             False              0
ManagedIdentitySignInLogs       True              True            365
```

## Sign-ins log

The sign-ins log is the source of (almost) all sign-in events.

To get the entries with AADInternals:

{{< highlight powershell >}}
# Get the Access Token and save to cache
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Show the log
Get-AADIntAzureSignInLog
{{< /highlight>}}

**Output:**
```
createdDateTime              id                                   ipAddress      userPrincipalName             appDisplayName                   
---------------              --                                   ---------      -----------------             --------------                   
2020-05-25T05:54:28.5131075Z b223590e-8ba1-4d54-be54-03071659f900 199.11.103.31  admin@company.onmicrosoft.com Azure Portal                     
2020-05-29T07:56:50.2565658Z f6151a97-98cc-444e-a79f-a80b54490b00 139.93.35.110  user@company.com              Azure Portal                     
2020-05-29T08:02:24.8788565Z ad2cfeff-52f2-442a-b8fc-1e951b480b00 11.146.246.254 user2@company.com             Microsoft Docs                   
2020-05-29T08:56:48.7857468Z e0f8e629-863f-43f5-a956-a4046a100d00 1.239.249.24   admin@company.onmicrosoft.com Azure Active Directory PowerShell
```

To see the details of a specific entry:

{{< highlight powershell >}}
# Show the information for a single entry 
Get-AADIntAzureSignInLog -EntryId b223590e-8ba1-4d54-be54-03071659f900
{{< /highlight>}}

**Output:**
```
id                                : b223590e-8ba1-4d54-be54-03071659f900
createdDateTime                   : 2020-05-25T05:54:28.5131075Z
userDisplayName                   : admin company
userPrincipalName                 : admin@company.onmicrosoft.com
userId                            : 289fcdf8-af4e-40eb-a363-0430bc98d4d1
appId                             : c44b4083-3bb0-49c1-b47d-974e53cbdf3c
appDisplayName                    : Azure Portal
ipAddress                         : 199.11.103.31
clientAppUsed                     : Browser
userAgent                         : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
...
```

## Audit log

The audit log is the source of (almost) all Azure AD related audit events.

To get the audit log with AADInternals:

{{< highlight powershell >}}
# Get the Access Token and save to cache
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Show the log
Get-AADIntAzureAuditLog
{{< /highlight>}}

**Output:**
```
id                                                            activityDateTime             activityDisplayName   operationType result  initiatedBy   
--                                                            ----------------             -------------------   ------------- ------  -----------   
Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545 2020-05-29T07:57:51.4037921Z Add service principal Add           success @{user=; app=}
Directory_f830a9d4-e746-48dc-944c-eb093364c011_1ZJAE_22273050 2020-05-29T07:57:51.6245497Z Add service principal Add           failure @{user=; app=}
Directory_a813bc02-5d7a-4a40-9d37-7d4081d42b42_RKRRS_12877155 2020-06-02T12:49:38.5177891Z Add user              Add           success @{app=; user=}
```

To see the details of a specific entry:
{{< highlight powershell >}}
# Show the information for a single entry 
Get-AADIntAzureAuditLog -EntryId Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545
{{< /highlight>}}

**Output:**
```
id                  : Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545
category            : ApplicationManagement
correlationId       : 9af6aff3-dc09-4ac1-a1d3-143e80977b3e
result              : success
resultReason        : 
activityDisplayName : Add service principal
activityDateTime    : 2020-05-29T07:57:51.4037921Z
loggedByService     : Core Directory
operationType       : Add
initiatedBy         : @{user=; app=}
targetResources     : {@{id=66ce0b00-92ee-4851-8495-7c144b77601f; displayName=Azure Credential Configuration Endpoint Service; type=ServicePrincipal; userPrincipalName=; 
					  groupType=; modifiedProperties=System.Object[]}}
additionalDetails   : {}
```


## Azure Directory Activity Log

I was recently introduced an Azure log I wasn't aware of; **Azure Directory Activity Log**:

![Azure Directory Activity Log](/images/posts/hhealth_17.png)

This log contains events that are not available in other logs. For instance, the log has events for <a href="/post/hybridhealthagent/#registering-fake-agents-with-aadinternals-v0-5-0-and-later" target="_blank">registering</a> fake AD FS healt agents and Global Administrators <a href="/post/azurevms/#getting-access-to-azure" target="_blank">elevating</a> themselves to Azure admins.

The only caveat is that this log is accessed via **Azure subscription**, so at least one subscription is required. As the directory for all subscriptions is the same, also the content of the log is same for all subscriptions. How about organisations without an Azure subscriptions? 
No worries, the log can be accesses as long as "Access management for Azure resources" is switched on:

![Access management for Azure resources](/images/posts/hhealth_18.png)

To change the setting with AADInternals (requires Global Administrator role):
{{< highlight powershell >}}
# Get the Access Token
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Grant Azure User Access Administrator role 
Grant-AADIntAzureUserAccessAdminRole
{{< /highlight>}}

Now we can get the Directory Audit Log events (up to 90 days):

{{< highlight powershell >}}
# Get the access token and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Optional: grant Azure User Access Administrator role 
Grant-AADIntAzureUserAccessAdminRole

# Get the events for the last month
$events = Get-AADIntAzureDirectoryActivityLog -Start (Get-Date).AddDays(-31)

# Select ADHybridHealthService related events and extract relevant information
$events | where {$_.authorization.action -like "Microsoft.ADHybrid*"} | %{New-Object psobject -Property ([ordered]@{"Scope"=$_.authorization.scope;"Operation"=$_.operationName.localizedValue;"Caller"=$_.caller;"TimeStamp"=$_.eventTimeStamp;"IpAddress"=$_.httpRequest.clientIpAddress})} | ft
{{< /highlight>}}

**Output:**
```
Scope                                                                                    Operation          Caller                               TimeStamp IpAddress                  
-----                                                                                    ---------          ------                               --------- ---------         
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:10:59.0148112Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:10:58.3348792Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:10:16.2093169Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:10:15.5693784Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:07:11.3219081Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:07:10.5819036Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:04:18.1500781Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:04:17.7750301Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService                                               Updates a service. admin@company.com 2021-08-25T15:02:33.2797177Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService                                               Updates a service. admin@company.com 2021-08-25T15:02:33.0297112Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts.company.com  Deletes service.   admin@company.com 2021-08-25T15:01:26.9612649Z 152.219.25.6
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts.company.com  Deletes service.   admin@company.com 2021-08-25T15:01:26.7262514Z 152.219.25.6
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts.company.com  Deletes service.   admin@company.com 2021-08-25T15:01:18.4399245Z 152.219.25.6
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts.company.com  Deletes service.   admin@company.com 2021-08-25T15:01:18.2599207Z 152.219.25.6
/providers/Microsoft.ADHybridHealthService                                               Updates a service. admin@company.com 2021-08-25T15:00:00.5760736Z 152.219.25.6
/providers/Microsoft.ADHybridHealthService                                               Updates a service. admin@company.com 2021-08-25T14:59:53.6402357Z 152.219.25.6
```

## Unified Audit log

As mentioned earlier, the Unified Audit Log is the main source of forensic events of Azure AD and Microsoft/Office 365. However, the current tools for searching and exporting the log are slow and difficult to use.
Therefore, I decided to implement the search in AADInternals (technicalyy uses compliance API).

To search the log for the first 150 entries:
{{< highlight powershell >}}
# Get compliance API cookies
$cookies = Get-AADIntComplianceAPICookies

# Dump the first 150 entries from the last 90 days to json file
Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) | Set-Content auditlog.json
{{< /highlight>}}

To search the log for up to 50100 entries and dump them to json file:
{{< highlight powershell >}}
# Dump the whole log (max 50100) from the last 90 days to csv file
Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) -All | Set-Content auditlog.json
{{< /highlight>}}

To search the log for up to 50100 entries and dump them to csv file:
{{< highlight powershell >}}
# Dump the whole log (max 50100) from the last 90 days to csv file
Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) -All | ConvertTo-Csv | Set-Content auditlog.csv
{{< /highlight>}}


# Troubleshooting

## Open-Source Intelligence (OSINT)

OSINT refers to the information publicly available, in this case, about tenants and its domains.

Easies way to quickly check the status of the domains of the tenant with AADInternals is:
{{< highlight powershell >}}
# Show the basic information of the tenant and domains
Invoke-AADIntReconAsOutsider -Domain company.com | Format-Table
{{< /highlight>}}

**Output:**
```
Tenant brand:       Company Ltd
Tenant name:        company
Tenant id:          05aea22e-32f3-4c35-831b-52735704feb3
DesktopSSO enabled: False

Name                           DNS   MX    SPF  DMARC Type      STS
----                           ---   --    ---  ----- ----      ---
company.com                   True  True  True   True Federated sts.company.com
company.mail.onmicrosoft.com  True  True  True  False Managed
company.onmicrosoft.com       True  True  True  False Managed
int.company.com              False False False  False Managed
```

This helps in troubleshooting for instance mailrouting and spam problems, such as, are MX records pointing to the cloud or are SPF & DMARC records configured?

# References
* Microsoft: <a href="https://docs.microsoft.com/en-us/powershell/module/msonline" target="_blank">MSOnline</a> V1 PowerShell module for Azure Active Directory
* Microsoft: <a href="https://docs.microsoft.com/en-us/powershell/azure/active-directory/overview" target="_blank">AzureAD</a> Azure Active Directory V2 PowerShell
* Microsoft: <a href="https://techcommunity.microsoft.com/t5/azure-active-directory-identity/update-your-applications-to-use-microsoft-authentication-library/ba-p/1257363" target="_blank">Update your applications to use Microsoft Authentication Library and Microsoft Graph API</a>
* Tony Redmond: <a href="https://office365itpros.com/2021/07/20/block-self-service-purchases-of-windows-365-licenses/" target="_blank">How to Block Self-Service Purchases of Windows 365 Licenses</a>
* Microsoft: <a href="https://www.powershellgallery.com/packages/MSCommerce/1.6" target="_blank">MS Commerce PowerShell module</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance?view=o365-worldwide" target="_blank">Search the audit log in the compliance center</a> 