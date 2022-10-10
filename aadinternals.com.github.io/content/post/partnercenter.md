+++
title = "Partner Center PowerShell module sends telemetry data to Microsoft"
date = "2020-01-19"
lastmod = "2020-01-19"
categories =["blog"]
tags = ["Azure","Partner","Security"]
thumbnail = "/images/posts/partnercenter.png"
+++

Microsoft has published a PowerShell module for their partners to ease and automate operations with their customers.
This module is (quite intuitively) called <a href="https://docs.microsoft.com/en-us/powershell/partnercenter/overview" target="_blank">Partner Center</a>.
While the module does well what it's meant to do, it also tells Microsoft what the partners are doing.

<!--more-->

# PartnerCenter PowerShell module
According to Microsoft:

> Partner Center PowerShell is commonly used by partners to manage their Partner Center resources. It is an open source project maintained by the partner community. Since this module is maintained by the partner community, it is not officially supported by Microsoft. 

This means that the module is actually developed by the partner community, not Microsoft, thus it is not officially supported. However, interestingly, only person who has lately
 <a href="https://github.com/microsoft/Partner-Center-PowerShell/commits" target="_blank">committed</a> anything to its GitHub
is working as a Senior Cloud Technology Strategist for Microsoft.

# How it works
One of my "hobbies" is to see what happens behind the curtains of Microsoft administrative tools. 
The end goal is of course to find new functionality to my <a href="/aadinternals/" target="_blank">AADInternals</a> toolkit.
So, it was time to install the module and fire up my favourite web debugging tool <a href="https://www.telerik.com/fiddler" target="_blank">Fiddler</a>.
At that time, I didn't know that the source code of the module was already available at <a href="https://github.com/microsoft/Partner-Center-PowerShell" target="_blank">GitHub</a>.

The module is using the standard OAuth authentication flow. After getting the AccessToken, an initial request is made to https://api.partnercenter.microsoft.com/v1/profiles/organization. 

(By the way, who is maintaining the rest APIs at api.partnercenter.microsoft.com? I'm quite sure not by the partner community..)

What we got back is a json file with the following information about the partner:

{{< highlight json >}}
{
	"id": "",
	"companyName": "",
	"defaultAddress": {
		"country": "",
		"city": "",
		"addressLine1": "",
		"postalCode": "",
		"firstName": "",
		"lastName": "",
		"phoneNumber": ""
	},
	"tenantId": "",
	"domain": "",
	"email": "",
	"language": "",
	"culture": "",
	"profileType": "OrganizationProfile",
	"links": {
		"self": {
			"uri": "/profiles/organization",
			"method": "GET",
			"headers": []
		}
	},
	"attributes": {
		"etag": "",
		"objectType": "OrganizationProfile"
	}
}
{{< /highlight>}}

However, after a couple of seconds, another request was made to https://dc.services.visualstudio.com/v2/track with the following content:
{{< highlight json >}}
{
	"name": "Microsoft.ApplicationInsights.786d393cbe8e46a8b2b2a3b6d5b417fc.PageView",
	"time": "2020-01-19T08:42:14.7508659Z",
	"iKey": "786d393c-be8e-46a8-b2b2-a3b6d5b417fc",
	"tags": {
		"ai.internal.sdkVersion": "dotnet:2.4.0-32153",
		"ai.device.osVersion": "Microsoft Windows NT 10.0.17763.0",
		"ai.session.id": "046cb320-70f2-4175-9531-8a3363d33d17"
	},
	"data": {
		"baseType": "PageViewData",
		"baseData": {
			"ver": 2,
			"name": "cmdletInvocation",
			"duration": "00:00:42.3047976",
			"properties": {
				"HashMacAddress": "919a73720aea203d2d2b5d2b674f0a931b5897edfecac17e027861cfe42a4101",
				"SessionId": "046cb320-70f2-4175-9531-8a3363d33d17",
				"PowerShellVersion": "5.1.17763.771",
				"ModuleVersion": "3.0.5.0",
				"CommandParameterSetName": "User",
				"Command": "Connect-PartnerCenter",
				"IsSuccess": "True",
				"TenantId": ""
			}
		}
	}
}
{{< /highlight>}}

**This happens every time any cmdlet is used!** 

So, Microsoft knows which PowerShell commands are used against which tenant, the information which should already be available in their API logs. 
However, also the hash of your MAC address is sent to Microsoft with the OS information, so the commands can be tracked down to individual
computer. The hash is by the way a <a href="https://github.com/microsoft/Partner-Center-PowerShell/blob/master/src/PowerShell/Commands/PartnerPSCmdlet.cs" target="_blank">SHA256 hash of the MAC string of your NIC withouth dashes</a>.

# Conclusion
To sum up, the PartnerCenter PowerShell module is sending telemetry data back to Microsoft. Whether this is an issue or not is up to you. As the module is open source, partners can always build their own version of the module
which would not send telemetry data to Microsoft.
