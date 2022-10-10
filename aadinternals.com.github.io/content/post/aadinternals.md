+++
title = "AADInternals published!"
date = "2018-10-25"
lastmod = "2018-10-26"
categories =["blog"]
tags = ["Azure Active Directory","PowerShell","AADInternals"]
thumbnail = "/images/posts/aadinternals.png"
+++

For the last couple months I've used most of my free time on studying and hacking Azure AD admin APIs. As a result, I'm finally
publishing the first (beta) version of the AADInternals PowerShell module.

<!--more-->

So what is the **<a href="/aadinternals" target="_blank">AADInternals</a>**? For short, it is a PowerShell module, where I've put all my knowledge about hacking and managing Azure AD.
I've studied a lot how Microsoft's admin tools are communicating with Azure AD and found some quite interesting stuff.. 

To start, install the module from PowerShell:
{{< highlight powershell >}}
Install-Module AADInternals
{{< /highlight>}}

And now you're ready to use the module! For instance, you can now easily check where your Office 365 services are really located:
{{< highlight powershell >}}
# Get the access token and save it to cache
Get-AADIntAccessTokenForAADGraph -Credentials (Get-Credential)
# Get service location information of the tenant
Get-AADIntServiceLocations | Format-Table
{{< /highlight>}}

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
As the example above shows services for this tenant are provided from UK, US, Ireland, and the Netherlands. The IR country code actually means Iran, but I suppose guys at Microsoft just had a typo (IE=Ireland) :joy:.
Anyways, especially those who are worried about GDPR compliancy, can see what services are located in EU/ETA countries and which are not. To see all the functions visit **<a href="/aadinternals" target="_blank">AADInternals</a>** page.

I'll post new blogs on how to use the module in due course - so keep visiting my blog! 

![orlando](/images/posts/orlando2018speak.jpg)

For the next month or so, I'll be finalising my sessions for <a href="https://techmentorevents.com/ecg/live360events/events/orlando-2018/techmentor.aspx" target="_blank">Techmentor Orlando</a>. 
For those attending the **Live!360 / Techmentor**, here is a promise: 
**If there are more than 500 dowloads of AADInternals by Nov 25th, I'll be wearing my doctoral robe :point_down: during my <a href="https://live360events.com/Events/Orlando-2018/Sessions/Thursday/TMH11-The-Weakest-Link-of-Office-365-Security.aspx" target="_blank">The Weakest Link of Office 365 Security</a> -session on Dec 6th.**
So spread the word and see you in Orlando!

![doc](/images/posts/aadinternals_hbr.jpg)
