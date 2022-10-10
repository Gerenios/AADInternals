+++
title = "Block user access to Azure AD PowerShell and Graph API Explorer"
date = "2018-08-27"
lastmod = "2021-11-09"
categories =["blog"]
tags = ["Azure Active Directory","Security","PowerShell","Graph"]
thumbnail = "/images/posts/limit-user-access.png"
+++

By default, any user of Office 365 or Azure AD tenant can read the content of Azure AD using PowerShell and Graph API Explorer. 
This is a serious security issue because users have undetectable access to other users' personal data, 
which violates for instance GDPR. In this blog, I'll tell how to prevent the access.

<!--more-->

# Azure AD PowerShell access

As I described in my earlier <a href="/post/o365-gdpr/#powershell" target="_blank">blog post</a>, any user of
Office 365 or Azure AD tenant can access Azure AD and, for instance, export the whole directory and see who has admin rights. 

Quite often when I discuss this issue with other administrators, they argue that this is quite similar to the on-premises AD, where users also
have access to the directory. Well, that is true but **what is the real scenario where regular users do need to have access to admin tools?**
I don't know any of such situation. Also, as far as I know, Google doesn't provide such access to their directory..

So, how do we block regular users PowerShell access to Azure AD?

## Method 1: Block the access to others data

Run the following command as Global Admin, and you're done!

{{< highlight powershell >}}
# Connect to Azure AD 
Connect-MsolService

# Disable users' permission to read others data
Set-MsolCompanySettings -UsersPermissionToReadOtherUsersEnabled $false
{{< /highlight>}}

To be more specific, users still do have PowerShell access to Azure AD but they are not able to read other users' information. 
Now, when users are trying to read Azure AD using any of the following commands:
{{< highlight powershell >}}
# Export all AAD users to xml file
Get-MsolUser | Export-Clixml -Path users.xml

# List all Global Administrators
Get-MsolRoleMember -RoleObjectId (Get-MsolRole -RoleName "Company Administrator").ObjectId
{{< /highlight>}}

They will get error similar to this:
```
Get-MsolUser : Access Denied. You do not have permissions to call this cmdlet.
```
</span>

**NOTE:** As pointed out by <a href="https://twitter.com/nestafo" target="_blank">@nestafo</a> and <a href="https://twitter.com/loukkis" target="_blank">@loukkis</a>,
disabling user access to others' information causes problems in <a href="https://docs.microsoft.com/en-us/microsoftteams/known-issues" target="_blank">Teams</a> and Planner:
users will not able to add new members.

## Method 2: Block the access for Msol PowerShell module

Since version 0.4.3, the access for Msol PowerShell module can be blocked for all users.

**Note!** This does not block Azure AD PowerShell module, so.. :man_facepalming:

{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Disable the Msol PowerShell module access
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

Now, when users (including admins) are trying to use any cmdlets of Msol PowerShell module they will get error similar to this:
```
Get-MsolUser : Access Denied. You do not have permissions to call this cmdlet.
```
Also, most of the AADInternals functions utilising AAD Graph API will get the following error:
```
No users are allowed to use Msol PowerShell to access this tenant.
```

# Azure AD Graph Explorers

<a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-graph-api" target="_blank">Azure Active Directory Graph API</a> and <a href="https://developer.microsoft.com/en-us/graph" target="_blank">Microsoft Graph</a> 
are REST APIs for accessing Azure AD. To use them, one must register an app to Azure AD and assign permissions to it. 
To do that, you will need admin rights, such as Global Administrator, to Azure AD. 
In other words, users are not able to access Azure AD using their own apps, unless administrators allow them to do so.

Microsoft has developed API explorers to ease the development of apps using Graph APIs. From technical point-of-view these
explorers are apps, that need to be given access to Azure AD tenant. However, the problem is that **these API explorers are 
already authorised by Microsoft to access all Azure AD tenants!**

## Azure AD Graph Explorer
Azure AD Graph Explorer can be found <a href="https://graphexplorer.azurewebsites.net" target="_blank">here</a>.

To use the API, the user needs to login:
![alt text](/images/posts/adgraph-01.png)

After successful login, the user is asked to grant permissions for the Graph explorer:

![alt text](/images/posts/adgraph-02.png)

To get the list of users, one can use the following url in explorer:
```
https://graph.windows.net/myorganization/users
```

As a result, all users are returned in JSON. 

{{< highlight json >}}
{
    "odata.metadata": "https://graph.windows.net/myorganization/$metadata#directoryObjects/Microsoft.DirectoryServices.User",
    "value": [
        {
            "odata.type": "Microsoft.DirectoryServices.User",
            "objectType": "User",
            "objectId": "584e8bb7-3ed3-45c3-883a-33260951c59a",
            "deletionTimestamp": null,
            "accountEnabled": true,
            "ageGroup": null,
            "assignedLicenses": [],
            "assignedPlans": [],
            "city": null,
            "companyName": null,
            "consentProvidedForMinor": null,
            "country": null,
            "createdDateTime": "2018-06-26T11:04:14Z",
            "creationType": null,
            "department": "Retail",
            "dirSyncEnabled": true,
            "displayName": "Adele Vance",
            "employeeId": null,
            "facsimileTelephoneNumber": null,
            "givenName": "Adele",
            "immutableId": "Ptog2uWbakyjs8UFXuc4yQ==",
            "isCompromised": null,
            "jobTitle": "Retail Manager",
            "lastDirSyncTime": "2018-06-26T11:04:16Z",
            "legalAgeGroupClassification": null,
            "mail": "AdeleV@demo.o365life.com",
            "mailNickname": "AdeleV",
            "mobile": null,
            "onPremisesDistinguishedName": "CN=Adele Vance,OU=Sales and Marketing,OU=DomainUsers,DC=o365life,DC=com",
            "onPremisesSecurityIdentifier": "S-1-5-21-3277080990-2629470435-924441437-1157",
            "otherMails": [],
            "passwordPolicies": "DisablePasswordExpiration",
            "passwordProfile": null,
            "physicalDeliveryOfficeName": "18/2111",
            "postalCode": "98004",
            "preferredLanguage": null,
            "provisionedPlans": [],
            "provisioningErrors": [],
            "proxyAddresses": [
                "smtp:AdeleV@demoO365Life.onmicrosoft.com",
                "SMTP:AdeleV@demo.o365life.com"
            ],
            "refreshTokensValidFromDateTime": "2017-10-03T04:44:44Z",
            "showInAddressList": null,
            "signInNames": [],
            "sipProxyAddress": "AdeleV@demo.o365life.com",
            "state": "WA",
            "streetAddress": "205 108th Ave. NE, Suite 400",
            "surname": "Vance",
            "telephoneNumber": "+1 425 555 0109",
            "thumbnailPhoto@odata.mediaContentType": "image/Jpeg",
            "usageLocation": "FI",
            "userIdentities": [],
            "userPrincipalName": "AdeleV@demo.o365life.com",
            "userState": null,
            "userStateChangedOn": null,
            "userType": "Member"
        }
		]
}
{{< /highlight>}}


## Microsoft Graph Explorer
Microsoft Graph Explorer can be found <a href="https://developer.microsoft.com/en-us/graph/graph-explorer" target="_blank">here</a>.

To use the API, the user needs to login:
![alt text](/images/posts/msgraph-01.png)

After successful login, the user is asked to grant permissions for the Graph explorer:

![alt text](/images/posts/msgraph-02.png)

To get the list of users, one can use the following url in explorer:
```
https://graph.microsoft.com/v1.0/users
```

As a result, all users are returned in JSON. 

{{< highlight json >}}
{
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
    "value": [
        {
            "id": "584e8bb7-3ed3-45c3-883a-33260951c59a",
            "businessPhones": [],
            "displayName": "Adele Vance",
            "givenName": "Adele",
            "jobTitle": null,
            "mail": "AdeleV@demo.o365life.com",
            "mobilePhone": null,
            "officeLocation": null,
            "preferredLanguage": null,
            "surname": "Vance",
            "userPrincipalName": "AdeleV@demo.o365life.com"
        },
        {
            "id": "6e36a8b3-04d9-48f2-bbd5-123c44633dc7",
            "businessPhones": [],
            "displayName": "Alex Wilber",
            "givenName": "Alex",
            "jobTitle": null,
            "mail": "AlexW@demo.o365life.com",
            "mobilePhone": null,
            "officeLocation": null,
            "preferredLanguage": null,
            "surname": "Wilber",
            "userPrincipalName": "AlexW@demo.o365life.com"
        }
		]
}
{{< /highlight>}}

If compared to Azure AD Graph results, there is a lot less information. To get more details, one can use the beta version of the API:

```
https://graph.microsoft.com/beta/users
```

## How to block access to Graph APIs

Actually, you cannot block access to Graph APIs, as it is in the very core of Azure AD. However, there are two ways you can limit the users' access
to Graph API Explorers.

### Block users' access to others information
This is quite easy, as you use the same PowerShell command as earlier:
{{< highlight powershell >}}
# Disable users' permission to read others data
Set-MsolCompanySettings -UsersPermissionToReadOtherUsersEnabled $false
{{< /highlight>}}

This only removes users' access to others' data, so they still can use Graph APIs to query their own data.

### Disable Graph API Explorers
As I mentioned earlier, Microsoft has granted access to all Azure AD tenants for Graph API Explorers. 
Luckily, you can disable them for your tenant.

Start by browsing to <a href="https://portal.azure.com" target="_blank">Azure Portal</a> as Global Administrator.
Then select **Azure Active Directory** and open **Enterprise Applications** blade. Now you should see two explorer apps, 
**Graph explorer** (Microsoft Graph Explorer) and **Graph Explorer** (Azure AD Graph Explorer).

**Note:** Graph explorers will not be shown here unless some user has actually used them.

![alt text](/images/posts/adgraph-03.png)

To disable access, click the first Graph explorer. Open properties and click **No** next to **Enabled for users to sign-in?**
Click save and repeat the steps with the other Graph explorer.

![alt text](/images/posts/adgraph-04.png)

Now, if users are trying to access the Graph explorers, they will have an error like this:

![alt text](/images/posts/adgraph-05.png)