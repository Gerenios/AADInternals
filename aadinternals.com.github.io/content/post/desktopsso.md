+++
title = "Azure AD Seamless SSO allows enumerating tenant users"
date = "2019-10-03"
lastmod = "2021-02-17"
categories =["blog"]
tags = ["Azure Active Directory","Seamless SSO","Desktop SSO","AADInternals","Security"]
thumbnail = "/images/posts/ssso.png"
+++

In 2017, Oliver Morton <a href="https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/" target="_new">introduced</a> a feature he found in Office 365 Active Sync, 
allowing enumerating the existence of the users based on http status codes. (Update: The "feature" was fixed by Microsoft on mid November 2019).
In this blog, I'll introduce my similar findings on using Microsoft API to enumerate users when <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sso" target="_new">Seamless SSO</a> is enabled in Azure AD tenant.

<!--more-->

# What is Seamless Single Sign-on?
Seamless Single Sign-on (SSO) is a feature which allows users on domain-joined computers to automatically sign in to Azure AD (and Office 365). 
Technically, the authentication is using Kerberos tickets, but that is irrelevant to this blog post.

# How does it work?
From the user point-of-view, after entering the username and clicking the next button, the user is automatically signed in.

<img src="/images/posts/sso_login1.png">

However, I noticed that if you give a username of a non-existing user, the following error is given:

<img src="/images/posts/sso_login2.png">

So, I was wondering **how the heck does the login prompt know whether the user exists or not?**

# How to enumerate users?
Under-the-hood, the login prompt is using a **GetCredentialType** API located at https://login.microsoftonline.com/common/GetCredentialType to get details about the given user id.
As an input, the API needs at least the username posted in the request body in JSON format. The output of the API request is similar to the following:
```
Username       : valid.user@company.com
Display        : valid.user@company.com
IfExistsResult : 0
ThrottleStatus : 0
Credentials    : @{PrefCredential=1; HasPassword=True; RemoteNgcParams=; FidoParams=; SasParams=}
EstsProperties : @{DesktopSsoEnabled=True; UserTenantBranding=; CallMetadata=; DomainType=3}
apiCanary      : AQABAAAAAA...iAA
```
As I've previously studied the API, the **IfExistsResult** was always set to 0 (True), regardless of does the user exists or not. The only exception to this is when the user's domain is not registered to any Azure AD tenant.
After a brief study, I discovered that when Seamless SSO is enabled, the **IfExistResult** correctly indicates whether the user exists or not! I.e., if the user does not exist, **IfExistResult** is set to 1 (False).
<br><br>
After studying the **GetCredentialType** with the tenant having Seamless SSO enabled, I discovered that the API could be used to enumerate **any user in tenant** regardless of is the user's domain using Seamless SSO or not.

So, what is the big deal? Using the **GetCredentialType** API, one can find valid user accounts of the tenant and focus password-spray attack on those. Not so surprisingly, as Oliver Morton mentioned in his <a href="https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/" target="_new">blog</a>,
Microsoft does not regard the enumeration to be an issue because the potential attacker still needs to pass the authentication to get in. 
However, my enumeration method has one advantage compared to Morton's method: **It can be used to enumerate external users!** 

External users are users to whom are given some access to tenant. For instance, if a file is shared from OneDrive to someone outside your organization, an external user is added to Azure AD. 
The external users have a special format:
**\<email_address>#EXT#@\<tenant>.onmicrosoft.com** where **email_address** is the external user's email address where the '@' is replaced with '_'

For example, if the external user's email address is **valid.user@gmail.com** the external user in Azure AD would be **valid.user_gmail.com#EXT#@company.onmicrosoft.com**

Again, what is the big deal? Well, if one can find out that some gmail.com or outlook.com user has access to Azure AD tenant we are interested in, one could focus on getting access to that external account. 
This, in turn, could be used to access the actual Azure AD tenant.

Below is a sample script that can be used to enumerate users.

{{< highlight powershell >}}
# Set the user names to a variable (or read from .csv etc)
$users=@("valid.user@company.com","valid.user@company.onmicrosoft.com","invalid.user@company.com","valid.user_gmail.com#EXT#@company.onmicrosoft.com")

# Loop trough all users
foreach($user in $users)
{
    $exists = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/GetCredentialType" -ContentType "application/json" -Method POST -Body (@{"username"="$user"; "isOtherIdpSupported" =  $true}|ConvertTo-Json) | Select -ExpandProperty IfExistsResult
    $properties = [ordered]@{"Username"=$user; "Exists"=$($exists -eq 0 -or $exists -eq 6)}
    New-Object -TypeName PSObject -Property $properties
}
{{< /highlight>}}

**Output:**
```
Username                                          Exists
--------                                          ------
valid.user@company.com                              True
valid.user@company.onmicrosoft.com                  True
invalid.user@company.com            			   False
valid.user_gmail.com#EXT#@company.onmicrosoft.com   True
```
