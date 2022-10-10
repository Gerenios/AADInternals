+++
title = "How to use a non-routable on-premises UPN with Office 365 and Azure AD"
date = "2018-07-24"
lastmod = "2018-07-24"
categories =["blog"]
tags = ["Office 365","ADFS","Federation","Synchronisation"]
thumbnail = "/images/posts/non-routable-upn.png"
+++

I've recently noticed that many organisations moving to Office 365 are struggling with their current on-premises non-routable UPNs. In this blog, I'll show how to use Office 365 without altering on-premises UPNs.

<!--more-->

# Background

## What is a non-routable UPN?

Users are logging into Office 365 using their User Principal Name (UPN). In Office 365 UPN is a combination of username and domain, like **user1@company.com**. For the domain part, only domains registered to Office 365 can be used. To register and verify the domain ownership, one needs to add a certain TXT record to the domains DNS server. This implies that the registered domain must be "a real" domain, i.e., it must be routable on the internet.

## So whats the problem?

At some point, Microsoft instructed organisations to use UPN suffixes such as **company.local** in their on-premises AD. Some organisations are even using flat-domains, such as **domain**. So, when users are signing in to their computers, they use UPNs like **user1@company.local**. These UPN suffixes can't, obviously, be registered as domains to Office 365.

This leads to problems when organisations want to start using Office 365. Azure AD Connect is used to synchronise on-premises AD to Azure AD. Because the UPN suffix used in the on-premises AD is not registered to Office 365, their UPN in Office 365 will be like **user1@company.onmicrosoft.com**. So, users' login names are not the same than in on-premises AD.

The easiest way to cope with this problem is to change the on-premises UPN suffix to a routable, such as **@company.com**. However, this is not always possible. For instance, some (legacy) line-of-business applications may use the UPN attribute for identifying the users, etc.

# Configuration steps
To use a non-routable UPN with Office 365, depending on the authentication method, you need to configure the synchronisation and identity federation.

## Synchronisation (Azure AD Connect)
The Azure AD Connect configuration is the easiest one. What we want to do here is to use users' on-premise AD email address (mail attribute) as UPN in Office 365. This way users can log in using their email address, such as **user1@company.com**. 

**Note!** In this blog, I'll be using the mail attribute, but you can use any attribute you like.

Below is a screenshot from the Azure AD Connect configuration tab, where you need to choose the on-premises attribute used as UPN. After selecting the attribute, you'll also need to check **Continue without any verified domains**, if the **Next** button is greyed. After this, configure the Azure AD Connect normally.

![alt text](/images/posts/non-routable-upn AADConnect.png "Configure Azure AD Connect")

## Federation (AD FS)

If you are using federated identity, you also need to configure AD FS. There are two different configurations to be done. To start, install and configure AD FS normally and convert the domain to federated.

### Claim issuance rules (optional*)
First, you'll need to change claim issuance rules. These rules are used to add claims to security token when the user is logging to Office 365. For short, claims are simply some information about the user. In Office 365, two claims are used: UPN and ImmutableId. The latter is technically a base 64 encoded GUID of user's on-premises AD object.

**\*Note!** As I mentioned in my older <a href="/posts/federation-vulnerability">blog</a>, the UPN is not even used in federated authentication. So, currently, there is no need to do any modifications. However, as I hope Microsoft will fix this in the future, below are instructions how to do it by-the-book.

To backup the current claim issuance rules, run the following PowerShell commands on the primary AD FS server.
{{< highlight powershell >}}
# Backup the current claim issuance rules
Get-AdfsRelyingPartyTrust -Name "Microsoft Office 365 Identity Platform" | Select -ExpandProperty IssuanceTransformRules | Out-File $HOME\o365_rules.bak
{{< /highlight>}}

Open the backup file in Notepad (any text editor will do) and replace **userPrincipalName** by **mail** as below (you can also copy the content below). Save the file as **o365_rules.new**

```
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/claims/UPN", "http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"), query = "samAccountName={0};mail,objectGUID;{1}", param = regexreplace(c.Value, "(?<domain>[^\\]+)\\(?<user>.+)", "${user}"), param = c.Value);

c:[Type == "http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"]
 => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", Value = c.Value, Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
```

Now you can apply the new claim issuance rules
{{< highlight powershell >}}
# Apply the new claim issuance rules
Set-AdfsRelyingPartyTrust -TargetName "Microsoft Office 365 Identity Platform" -IssuanceTransformRulesFile $HOME\o365_rules.new
{{< /highlight>}}

### Alternate login id (optional but recommended)
Now the users can login to Office 365. However, the login experience is following:

1. The user browses to https://portal.office.com, enters username (user1@company.com) and clicks the Next button
2. The user's browser is redirect to on-premises AD FS server.
3. If SSO is configured properly (and the user is in internal network), the user is logged in automatically. If SSO is not configured or the user is outside internal network, user needs to enter the username again (user1@company.local) plus enter the password.

Using two different username formats may confuse users. Therefore it is recommended to configure alternate login id. To allow users to login using their email address, run the following command on primary AD FS server.

{{< highlight powershell >}}
# Set mail attribute as alternate login id for company.local
Set-AdfsClaimsProviderTrust -TargetIdentifier "AD AUTHORITY" -AlternateLoginID mail -LookupForests company.local
{{< /highlight>}}

**Note!** According to Microsoft <a href="https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configuring-alternate-login-id" target="_blank">documentation</a>, if AD FS is configured using Azure AD Connect, the alternate login id is configured automatically.
