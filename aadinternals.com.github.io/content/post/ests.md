+++
title = "Bypassing Azure AD home tenant MFA and CA"
date = "2022-09-12"
lastmod = "2022-09-12"
categories =["blog"]
tags = ["MFA","Conditional Access","Bypass"]
thumbnail = "/images/posts/bypasshometenant.png"
draft = true
+++

Multi-factor Authentication (MFA) and Conditional Access (CA) policies are powerful tools to protect Azure AD users' identities.
For instance, one may allow access only from compliant devices and require MFA from all users.

However, because of Azure AD authentication platform architecture, **users can bypass home tenant MFA and CA policies** when logging in directly to certain resource tenants.

This blog post tries to shed some light to how Azure AD authentication works under-the-hood. The blog is co-authored with <a href="https://twitter.com/SravanAkkaram" target="_blank">@SravanAkkaram</a> and is based on his findings.
<!--more-->

# Introduction
This story, like many others, began after a <a href="https://twitter.com/SravanAkkaram/status/1491902335429214232" target="_blank">tweet</a>:

![Tweet](/images/posts/ests_01.png)

I replied to Sravan and asked him to DM me if he'd like me to have a look on his case. Luckily, he did 😉

# Azure AD 

Azure AD is Microsoft's Identity and Access Management (IAM) service used by Microsoft 365 and Azure, but also by thousands of third party service providers.
An instance of Azure AD is called **tenant**. 

## Home and resource tenants

Users can log in to the tenant using the authentication methods configured by the administrators. Microsoft is calling this to <a href="https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/multi-tenant-user-management-introduction#terminology" target="_blank">home tenant</a>.

Users are also able to log in to other tenants, if they are invited there as **guests**. Microsoft calls these tenants <a href="https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/multi-tenant-user-management-introduction#terminology" target="_blank">resource tenants</a>.

![users and guests](/images/posts/ests_02.png)

After user accepts the invitation, a corresponding user object is created to the resource tenant. 
The two objects are linked to each other. The resource tenant user object has an array of **alternativeSecurityId**s and one of them (of type 5) equals the **PUID**(aka LiveId) attribute of the home tenant user object.

## eSTS

Based on our observations, when logging in to Azure AD tenant, you are actually logging in to **eSTS**. But what is eSTS? 
According to <a href="https://api.servicetrust.microsoft.com/api/v2/downloadDocuments/af762fa7-7b22-4e78-a5ff-0c187acc0bee" target="_blank">Microsoft Azure SOC 3 Report. October 1, 2017 - September 30, 2018</a>:

> **Evolved Security Token Service (eSTS):** eSTS provides a stateless service that accesses multiple principal and key stores.
> eSTS absorbs the roles of multiple STSs, so that users see one Azure AD STS.
> eSTS relies on MSODS to hold information required to complete the authentication. 
> eSTS supports a number of protocols including OAuth 2.0, Open ID Connect, WS-Fed, and Security Assertion Markup Language (SAML) protocol.

> **MSODS:** MSODS is Microsoft Online Directory Services, a feature of Azure Active Directory that also includes Azure Active Directory B2B.

Here is an example of a tenant using username and password. User goes to **login.microsoftonline.com** and provides username and password.
eSTS then checks the provided credentials against home tenant Azure AD.

![eSTS](/images/posts/ests_03.png)

## Multi-factor authentication (MFA) and Conditional Access (CA)

MFA can be applied either <a href="https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates" target="_blank">per user</a>, with <a href="https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults" target="_blank">Security Defaults</a>, or using <a href="https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa" target="_blank">Conditional Access</a> (requires Azure AD Premium).

With <a href="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview" target="_blank">Conditional Access</a> one can 
**grant** or **block** access to services based on the user, device, application, user's location, etc.

Both MFA and CA are applied **post-authentication**, i.e., after logging in to eSTS. 
Moreover, MFA and CA are configured per tenant. 

Here is an example, where user is logging in to home tenant (login.microsoftonline.com):

1. eSTS checks the provided credentials against **home tenant**.
2. **Home tenant** MFA is prompted and CA policies evaluated.

![Home tenant MFA and CA](/images/posts/ests_04.png)

Sravan found out that when logging in to resource tenant, home tenant MFA and CA are not applied.
Here is an example, where user is logging in to resource tenant (login.microsoftonline.com/&lt;resource tenant>):

1. eSTS checks the provided credentials against **home tenant**.
2. **Resource tenant** MFA is prompted and CA policies evaluated.

![Resource tenant MFA and CA](/images/posts/ests_05.png)

# Room for abuse

## Bypassing MFA and CA
Let's see how we can exploit the authentication flow. First, we create a CA rule to block access for Nestor Wilke.
![CA rule to block NestorW](/images/posts/ests_06.png)

When trying to get an access token using AADInternals, we can see that the **sign-in was succesful** but due to CA, **you don't have permission to access this resource**.
![CA blocks](/images/posts/ests_07.png)

However, if we provide a **tenant name** or **tenant id** of a known **resource tenant**, home tenant CA is not evaluated. 

**Note:** Resource tenant MFA and CA are still applied.

![CA bypass](/images/posts/ests_08.png)

The returned access token shows that the **issuer** (iss) claim and **identity provider** (idp) claims are different.
We can also see that there is no MFA included in **authentication methods** (amr) claim.

![access token](/images/posts/ests_09.png)

This means that **home tenant** administrators can't block access to **resource tenants**. 

This is not very intuitive, as one would assume blocking access to home tenant would block access to all tenants.

## Exploiting

So, how would threat actors exploit this? To begin with, you'd need to have user's credentials. 

If you have those, you can log in to any resource tenant the user is member of, and do anything the user has permission to do. 
The most common scenario would be to access Teams.

But what if you don't know any resource tenants user is member of? Another Sravan's finding will help on this.

Sravan noticed that some tenants allows you to log in, even when you're not a guest in that tenant!
![public tenant](/images/posts/ests_12.png)

Now you can use AADInternals to get list of user's tenants. The last tenant is the one we logged in, and doesn't have any other information.
The rest of the tenants are the ones the user can access.
![tenants](/images/posts/ests_13.png)

# Detecting

Log ins to resource tenants are also logged in sign-ins log. Here we can see the events of the examples above:

![sign-ins log](/images/posts/ests_10.png)

Details of the first event shows that this was **B2B collaboration** type of access. We can also see the resource and home tenant ids.

![sign-ins details](/images/posts/ests_11.png)

# Preventing
Unfortunately, there is no way to prevent this.

# Communication with Microsoft

xx

# Summary



# Credits and references
* Sravan Akkaram: Tweet: <a href="https://twitter.com/SravanAkkaram/status/1491902335429214232" target="_blank">Discrepancy in handling the MSRC Case 67233 </a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/multi-tenant-user-management-introduction#terminology" target="_blank">Multi-tenant user management</a>
* Microsoft: <a href="https://api.servicetrust.microsoft.com/api/v2/downloadDocuments/af762fa7-7b22-4e78-a5ff-0c187acc0bee" target="_blank">Microsoft Corporation - Microsoft Azure (Azure & Azure Government). SOC 3 Report. October 1, 2017 - September 30, 2018</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates" target="_blank">Enable per-user Azure AD Multi-Factor Authentication to secure sign-in events</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults" target="_blank">Security defaults in Azure AD</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa" target="_blank">Tutorial: Secure user sign-in events with Azure AD Multi-Factor Authentication</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview" target="_blank">What is Conditional Access?</a>