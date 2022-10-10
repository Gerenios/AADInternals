+++
title = "PowerShell"
date = "2017-09-05"
lastmod = "2018-02-09"
menu = "main"
tags = ["Office365", "PowerShell"]
categories = ["article"]
description = "How to connect to Office 365 with PowerShell"
thumbnail = "/images/PowerShell.png"
+++

This article explains how to connect Office 365 using PowerShell and more!
 <!--more-->
<script src="myscripts.js"></script>
 
# How to connect to Office 365

## Before you start

Before you can use any Office 365 PowerShell cmdlets, you need to download and install them following the links below.

1. Install <a href="../post/ps-module" target="_blank">Azure AD PowerShell module</a>
2. Download <a href="http://www.microsoft.com/download/details.aspx?id=35588" target="_blank">SharePoint Online Management Shell</a>
3. Download <a href="http://www.microsoft.com/en-us/download/details.aspx?id=39366" target="_blank">Skype for Business, Windows PowerShell Module</a>

After installing the modules, you're ready to go! 

First we save your credentials and tenant name to variables, so we can use them later. For tenant, use the first part of your tenant name: **yourtenant**.onmicrosoft.com

{{< highlight powershell >}}
$cred=Get-Credential
$tenant="yourtenant"
{{< /highlight>}}

## Office 365

To connect to Office 365, please use the following command:
{{< highlight powershell >}}
Connect-MsolService -credential $credential
{{< /highlight>}}

## SharePoint Online

To connect to SharePoint online, please use the following command:
{{< highlight powershell >}}
Connect-SPOService -Url https://$tenant-admin.sharepoint.com -Credential $cred
{{< /highlight>}}

## Skype for Business

There are two phases to connect to Skype for Business. First you create a remote session and then you import it to your local PowerShell session:
{{< highlight powershell >}}
$s4bses = New-CsOnlineSession -Credential $cred
Import-PSSession $s4bses
{{< /highlight>}}

## Exchange Online

Connecting to Exchange Online is similar to Skype for Business connection. However, you do not need to install any module to connect to Exchange Online.
{{< highlight powershell >}}
$exses = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $cred -Authentication Basic -AllowRedirection
Import-PSSession $exses
{{< /highlight>}}

## The complete connection script

{{< highlight powershell >}}
# Save credentials and tenant for later use
$cred=Get-Credential
$tenant="yourtenant"

# Connect to Office 365 (Azure AD)
Connect-MsolService -credential $cred

# Connect to SharePoint Online
Connect-SPOService -Url https://$tenant-admin.sharepoint.com -Credential $cred

# Connect to Skype for Business
$s4bses = New-CsOnlineSession -Credential $cred
Import-PSSession $s4bses

# Connect to Exchange Online
$exses = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $cred -Authentication Basic -AllowRedirection
Import-PSSession $exses
{{< /highlight>}}


