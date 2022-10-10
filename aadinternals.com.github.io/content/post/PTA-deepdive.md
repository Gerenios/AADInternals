+++
title = "Deep-dive to Azure AD Pass-Through Authentication"
date = "2020-03-30"
lastmod = "2020-03-30"
categories =["blog"]
tags = ["Azure Active Directory","PowerShell","AADInternals","Security","PTA","Authentication"]
thumbnail = "/images/posts/pta_deepdive.png"
+++

In my earlier <a href="/post/aad-deepdive/" target="_blank">blog</a>, I explained how Azure AD identity federation works under-the-hood.
In this post, I'll be doing the same with Azure AD pass-through authentication (PTA).

<!--more-->
# What is pass-through authentication?
Azure Active Directory <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-pta" target="_blank">Pass-through Authentication</a> (PTA) is an authentication
method allowing users to sign in to on-premises and Azure AD/Office 365 using the same credentials. Technically it is a service running on a Windows server. The first instance is installed along with Azure AD Connect. 
For high-availability, extra agents can be installed from <a href="https://download.msappproxy.net/Subscription/00000000-0000-0000-0000-000000000000/Connector/ptaDownloadConnectorInstaller" target="_blank">here</a>.

# How it works?
The overall authentication steps are explained in <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-pta-how-it-works" target="_blank">this</a> article by Microsoft.

In more detail, it goes like this:

1. The PTA agent is registered to Azure AD. The certificate used by the agent is signed by the Azure app proxy.
2. When starting the agent, a bootstrap file is fetched from the Azure app proxy.
3. A persistent https connection using WebSocket/wsrelayedamqp is made to each signalling listener endpoints (in total 4 to 8 connections).
4. When user is logging in and gives a password, a request to connect to Azure Service Bus relay is sent to some endpoints.
5. The agent "picking up" the request will send back an "accept message" and connect to the given relay using WebSocket/wsrelayedconnection.
6. The agent notifies the relay and receives a request to connect to app proxy. A WebSocket connection is made to proxy.
7. The agent notifies the proxy and receives an authentication request in JSON format.
8. The agent decrypts the password with the private key of the certificate it is using.
9. The user name and password are sent to Win32 API LogonUserW function
10. The authentication result is sent back to the app proxy with a regular https POST

The technical details are provided below :mag:


## Registering the PTA agent
When the PTA Agent is installed, it is first registered to Azure AD. This is done by sending an XML document containing a CSR (Certificate Signing Request) to "https://< tenant-id >.registration.msappproxy.net/register/registerConnector".

For example, if your Azure AD tenant id is "ae11aea0-4e67-438a-80a8-d877c5d4a885", the following XML file is sent to https://ae11aea0-4e67-438a-80a8-d877c5d4a885.registration.msappproxy.net/register/registerConnector using POST protocol.

{{< highlight xml >}}
<RegistrationRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Registration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	<Base64Csr>MII..</Base64Csr>
	<AuthenticationToken>eyJ..</AuthenticationToken>
	<Base64Pkcs10Csr i:nil="true"/>
	<Feature>ApplicationProxy</Feature>
	<FeatureString>PassthroughAuthentication</FeatureString>
	<RegistrationRequestSettings>
		<SystemSettingsInformation i:type="a:SystemSettings" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RegistrationCommons" xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Utilities.SystemSettings">
			<a:MachineName>DC.company.com</a:MachineName>
			<a:OsLanguage>1033</a:OsLanguage>
			<a:OsLocale>0409</a:OsLocale>
			<a:OsSku>8</a:OsSku>
			<a:OsVersion>10.0.17763</a:OsVersion>
		</SystemSettingsInformation>
		<PSModuleVersion>1.5.643.0</PSModuleVersion>
		<SystemSettings i:type="a:SystemSettings" xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Utilities.SystemSettings">
			<a:MachineName>DC.company.com</a:MachineName>
			<a:OsLanguage>1033</a:OsLanguage>
			<a:OsLocale>0409</a:OsLocale>
			<a:OsSku>8</a:OsSku>
			<a:OsVersion>10.0.17763</a:OsVersion>
		</SystemSettings>
	</RegistrationRequestSettings>
	<TenantId>ae11aea0-4e67-438a-80a8-d877c5d4a885</TenantId>
	<UserAgent>PassthroughAuthenticationConnector/1.5.643.0</UserAgent>
</RegistrationRequest>
{{< /highlight>}}

If everything goes okay, the following response is returned, containing the signed certificate.
{{< highlight xml >}}
<RegistrationResult xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.Registration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	<Certificate>MIIDO..</Certificate>
	<ErrorMessage/>
	<IsSuccessful>true</IsSuccessful>
</RegistrationResult>
{{< /highlight>}}

As it can be seen below, the certificate is issued by **hisconnectorregistrationca.msappproxy.net**, and the subject is the tenant id. The certificate is valid for 180 days.

![Certificate details](/images/posts/pta_dd_1.png)

As can be seen above, the **MachineName** in the CSR is the name of the server where the agent is installed. In the Azure AD Admin center, the status is shown as below. 
When multiple agents are installed, the status of each will be shown in the list.

![Certificate details](/images/posts/pta_dd_2.png)

## Connecting to Azure Ad
After the agent is registered, it can connect to Azure AD.

Technically there are three (or more) different types of connections involved in the authentication process. 

### Bootstrap
When the agent starts, it first requests a bootstrap from "https://< tenant-id >.pta.bootstrap.his.msappproxy.net/ConnectorBootstrap" using the following XML document.
Authentication is performed using the certificate created during the registration process. Moreover, the MachineName is sent to Azure AD as part of the request.
{{< highlight xml >}}
<BootstrapRequest xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	<AgentSdkVersion>1.5.1542.0</AgentSdkVersion>
	<AgentVersion>1.5.1542.0</AgentVersion>
	<BootstrapAddOnRequests i:nil="true"/>
	<BootstrapDataModelVersion>1.5.1542.0</BootstrapDataModelVersion>
	<ConnectorId>0ea97280-4738-498d-b18a-3790e4886e62</ConnectorId>
	<ConnectorVersion i:nil="true"/>
	<ConsecutiveFailures>0</ConsecutiveFailures>
	<CurrentProxyPortResponseMode>Primary</CurrentProxyPortResponseMode>
	<FailedRequestMetrics xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel"/>
	<InitialBootstrap>true</InitialBootstrap>
	<IsProxyPortResponseFallbackDisabledFromRegistry>true</IsProxyPortResponseFallbackDisabledFromRegistry>
	<LatestDotNetVersionInstalled>461814</LatestDotNetVersionInstalled>
	<MachineName>DC.company.com</MachineName>
	<OperatingSystemLanguage>1033</OperatingSystemLanguage>
	<OperatingSystemLocale>040b</OperatingSystemLocale>
	<OperatingSystemSKU>7</OperatingSystemSKU>
	<OperatingSystemVersion>10.0.17763</OperatingSystemVersion>
	<PerformanceMetrics xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel">
		<a:CpuAggregates/>
		<a:CurrentActiveBackendWebSockets>0</a:CurrentActiveBackendWebSockets>
		<a:FaultedServiceBusConnectionCount>0</a:FaultedServiceBusConnectionCount>
		<a:FaultedWebSocketConnectionCount>0</a:FaultedWebSocketConnectionCount>
		<a:LastBootstrapLatency>0</a:LastBootstrapLatency>
		<a:TimeGenerated>2020-03-30T13:49:31.4249204Z</a:TimeGenerated>
	</PerformanceMetrics>
	<ProxyDataModelVersion>1.5.1542.0</ProxyDataModelVersion>
	<RequestId>0c891cd7-afae-49bd-8f40-2f52263c2c0a</RequestId>
	<SubscriptionId>ae11aea0-4e67-438a-80a8-d877c5d4a885</SubscriptionId>
	<SuccessRequestMetrics xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel"/>
	<TriggerErrors/>
	<UpdaterStatus>Stopped</UpdaterStatus>
	<UseServiceBusTcpConnectivityMode>false</UseServiceBusTcpConnectivityMode>
	<UseSpnegoAuthentication>false</UseSpnegoAuthentication>
</BootstrapRequest>
{{< /highlight>}}

Among other information, the bootstrap response has a list of "signalling listener endpoints". Each of the endpoints has a unique Shared Access Key and url. 

{{< highlight xml >}}
<BootstrapResponse xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	<BackendSessionTimeoutMilliseconds>305000</BackendSessionTimeoutMilliseconds>
	<BootstrapAddOnResponses i:nil="true"/>
	<BootstrapClientAddOnSettings i:nil="true" xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel"/>
	<BootstrapEndpointOverride i:nil="true"/>
	<CheckForTrustRenewPeriodInMinutes>360</CheckForTrustRenewPeriodInMinutes>
	<ConfigRequestTimeoutMilliseconds>20000</ConfigRequestTimeoutMilliseconds>
	<ConfigurationEndpointFormat>https://{0}:{1}/subscriber/admin</ConfigurationEndpointFormat>
	<ConnectionLimit>200</ConnectionLimit>
	<ConnectivitySettings>{"ServicePointManagerSettings":{"ConnectionLimit":200,"MaxServicePoints":0,"MaxServicePointIdleTimeMilliseconds":300000,"DnsRefreshTimeoutMilliseconds":1800000,"Expect100Continue":false,"UseNagleAlgorithm":false,"TcpKeepAliveEnabled":true,"TcpKeepAliveTime":60000,"TcpKeepAliveInterval":1000},"SignalingSettings":{"BindingType":"NetTcpRelayBinding","OpenTimeout":"00:01:00","CloseTimeout":"00:01:00","ReceiveTimeout":"10675199.02:48:05.4775807","ReliableSessionEnabled":false,"ReliableSessionInactivityTimeout":"00:10:00","ReliableSessionOrdered":true,"ListenBacklog":10,"MaxReceivedMessageSize":65536,"MaxBufferPoolSize":65536,"MaxBufferSize":65536,"MaxConnections":100,"WebSocketReceiveTimeout":"02:00:00","UseCachedServiceBusSasToken":false,"ServiceBusSasTokenTtl":"23:59:59","UseServiceBusTracingForListenerId":false},"WebSocketSignalingSettings":{"OpenTimeout":"00:00:30","CloseTimeout":"00:00:30","SendTimeout":"00:00:30","ReceiveTimeout":"02:00:00","IdleTimeout":"02:00:00","LeaseTimeout":"06:00:00","KeepAliveInterval":"00:00:10","MaxReceivedMessageSize":65536,"MaxConnections":1,"EnableAutomaticReconnects":true,"RetryableOperationSettings":{"MinimumSuccessfulOperationTimeSpan":"00:01:00","TotalAttempts":5,"InitialDelayMilliseconds":200,"DelayFactor":2}},"DnsCacheSettings":{"DnsCacheEnabled":true,"DnsCacheTtl":"00:30:00","DnsCacheResolutionTimeout":"00:01:00"},"BackendWebSocketSettings":{"MessageBufferSize":16384,"BackendWebSocketIdleTimeout":"05:00:00","BackendWebSocketInactivityCheckPeriod":"00:30:00"}}</ConnectivitySettings>
	<ConnectorState>Ok</ConnectorState>
	<DnsLookupCacheTtl>PT30M</DnsLookupCacheTtl>
	<DnsRefreshTimeoutMilliseconds>1800000</DnsRefreshTimeoutMilliseconds>
	<ErrorEndpointFormat>https://{0}:{1}/subscriber/error</ErrorEndpointFormat>
	<LogicalResponseTimeoutMilliseconds>15000</LogicalResponseTimeoutMilliseconds>
	<MaxBootstrapAddOnRequestsLength>0</MaxBootstrapAddOnRequestsLength>
	<MaxFailedBootstrapRequests>144</MaxFailedBootstrapRequests>
	<MaxServicePointIdleTimeMilliseconds>300000</MaxServicePointIdleTimeMilliseconds>
	<MinutesInTrustLifetimeBeforeRenew>43200</MinutesInTrustLifetimeBeforeRenew>
	<PayloadEndpointFormat>https://{0}:{1}/subscriber/payload</PayloadEndpointFormat>
	<PayloadRequestTimeoutMilliseconds>20000</PayloadRequestTimeoutMilliseconds>
	<PeriodicBootstrapIntervalMilliseconds>600000</PeriodicBootstrapIntervalMilliseconds>
	<ProxyPortResponseFallbackPeriod>P1D</ProxyPortResponseFallbackPeriod>
	<RelayReceiveTimeout>P10675199DT2H48M5.4775807S</RelayReceiveTimeout>
	<ResponseEndpointFormat>https://{0}:{1}/subscriber/connection</ResponseEndpointFormat>
	<ResponseRetryDelayFactor>2</ResponseRetryDelayFactor>
	<ResponseRetryInitialDelayMilliseconds>200</ResponseRetryInitialDelayMilliseconds>
	<ResponseRetryTotalAttempts>5</ResponseRetryTotalAttempts>
	<ResponseSigningEnabled>false</ResponseSigningEnabled>
	<ServiceMessage/>
	<SignalingListenerEndpoints xmlns:a="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel">
		<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
			<a:IsAvailable>true</a:IsAvailable>
			<a:Name>his-eur1-weur1/ae11aea0-4e67-438a-80a8-d877c5d4a885_b9ebb6bb-e7e8-40e6-9bf9-fc258b2c77b8</a:Name>
			<a:Domain>servicebus.windows.net</a:Domain>
			<a:Namespace>his-eur1-weur1</a:Namespace>
			<a:ReliableSessionEnabled>false</a:ReliableSessionEnabled>
			<a:Scheme>sb</a:Scheme>
			<a:ServicePath>ae11aea0-4e67-438a-80a8-d877c5d4a885_b9ebb6bb-e7e8-40e6-9bf9-fc258b2c77b8</a:ServicePath>
			<a:SharedAccessKey>k5..</a:SharedAccessKey>
			<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
		</a:SignalingListenerEndpointSettings>
		<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
			<a:IsAvailable>true</a:IsAvailable>
			<a:Name>his-eur1-neur1/ae11aea0-4e67-438a-80a8-d877c5d4a885_b9ebb6bb-e7e8-40e6-9bf9-fc258b2c77b8</a:Name>
			<a:Domain>servicebus.windows.net</a:Domain>
			<a:Namespace>his-eur1-neur1</a:Namespace>
			<a:ReliableSessionEnabled>false</a:ReliableSessionEnabled>
			<a:Scheme>sb</a:Scheme>
			<a:ServicePath>ae11aea0-4e67-438a-80a8-d877c5d4a885_b9ebb6bb-e7e8-40e6-9bf9-fc258b2c77b8</a:ServicePath>
			<a:SharedAccessKey>jq..</a:SharedAccessKey>
			<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
		</a:SignalingListenerEndpointSettings>
		<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
			<a:IsAvailable>true</a:IsAvailable>
			<a:Name>his-eur1-weur1/ae11aea0-4e67-438a-80a8-d877c5d4a885_b9ebb6bb-e7e8-40e6-9bf9-fc258b2c77b8_reliable</a:Name>
			<a:Domain>servicebus.windows.net</a:Domain>
			<a:Namespace>his-eur1-weur1</a:Namespace>
			<a:ReliableSessionEnabled>true</a:ReliableSessionEnabled>
			<a:Scheme>sb</a:Scheme>
			<a:ServicePath>ae11aea0-4e67-438a-80a8-d877c5d4a885_b9ebb6bb-e7e8-40e6-9bf9-fc258b2c77b8_reliable</a:ServicePath>
			<a:SharedAccessKey>Z+..</a:SharedAccessKey>
			<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
		</a:SignalingListenerEndpointSettings>
		<a:SignalingListenerEndpointSettings i:type="a:ServiceBusSignalingListenerEndpointSettings">
			<a:IsAvailable>true</a:IsAvailable>
			<a:Name>his-eur1-neur1/ae11aea0-4e67-438a-80a8-d877c5d4a885_b9ebb6bb-e7e8-40e6-9bf9-fc258b2c77b8_reliable</a:Name>
			<a:Domain>servicebus.windows.net</a:Domain>
			<a:Namespace>his-eur1-neur1</a:Namespace>
			<a:ReliableSessionEnabled>true</a:ReliableSessionEnabled>
			<a:Scheme>sb</a:Scheme>
			<a:ServicePath>ae11aea0-4e67-438a-80a8-d877c5d4a885_b9ebb6bb-e7e8-40e6-9bf9-fc258b2c77b8_reliable</a:ServicePath>
			<a:SharedAccessKey>gy..</a:SharedAccessKey>
			<a:SharedAccessKeyName>Connector</a:SharedAccessKeyName>
		</a:SignalingListenerEndpointSettings>
	</SignalingListenerEndpoints>
	<Triggers/>
	<TrustRenewEndpoint>https://his-eur1-weur1.renewtrust.msappproxy.net/renewTrust</TrustRenewEndpoint>
</BootstrapResponse>
{{< /highlight>}}

### Service Bus
After retrieving the bootstrap, a connection is made to each endpoint, e.g. "https://his-eur1-neur1.servicebus.windows.net/$servicebus/websocket". Technically, the connection is a persistent https connection (WebSocket/wsrelayedamqp) to Azure Service Bus
with client certificate authentication. Also, a shared access signature (SAS) <a href="https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization" target="_blank">authentication</a> is made
with key information from the bootstrap response. The bus is using **OASIS Advanced Message Queuing Protocol (AMQP)** standard (available <a href="http://docs.oasis-open.org/amqp/core/v1.0/os/amqp-core-complete-v1.0-os.pdf" target="_blank">here</a>) for the messaging.
After the connection is initialised, agents are waiting for a connection request. After receiving an AMQP Transfer message, another message is received with the information of the Service Bus Relay to be connected to.

### Service Bus Relay
After getting the connection information from the signalling listener endpoint, a connection is made to the Service Bus Relay to the url similar to "https://g10-prod-am3-005-sb.servicebus.windows.net/$servicebus/websocket". 
Again, this is an https connection (WebSocket/wsrelayedconnection) with client certificate authentication. The bus is using somekind of binary XML, but I couldn't figure out which one. After sending an "accept relay connection" message, a message with proxy connection instructions is waited for.

### Proxy
After receiving a connection request message from the relay, a connection is made to the url similar to "https://proxyworkerrolein2-his-weur-2.connector.his.msappproxy.net/subscriber/websocketconnect?requestId=ccb1beca-8d25-4ecc-86c1-42f77634aaea".
This connection is also an https connection (WebSocket). After sending an "accept" message, the actual authentication message is received in JSON format.

{{< highlight json >}}
{	"__type": "SignalMessage:#Microsoft.ApplicationProxy.Common.SignalingDataModel",
	"RequestId": "858809ba-30e5-4bcb-af5c-378bcd250300",
	"SessionId": "00000000-0000-0000-0000-000000000000",
	"SubscriptionId": "ae11aea0-4e67-438a-80a8-d877c5d4a885",
	"TransactionId": "ccebc60e-6ead-400d-a718-aeecf5fc972d",
	"OverrideServiceHostEnabled": true,
	"OverridenReturnHost": "ProxyWorkerRoleIN2-his-weur-2.connector.his.msappproxy.net",
	"OverridenReturnPort": 443,
	"ReturnHost": "ProxyWorkerRoleIN2-his-weur-2.connector.his.msappproxy.net",
	"ReturnPort": 10100,
	"TunnelContext": {
		"__type": "TunnelContext",
		"ConfigurationHash": "854346866",
		"CorrelationId": "ccebc60e-6ead-400d-a718-aeecf5fc972d",
		"HasPayload": false,
		"ProtocolContext": {
			"__type": "PasswordValidationContext",
			"TrafficProtocol": 2,
			"Domain": "COMPANY",
			"EncryptedData": [{
					"__type": "EncryptedOnPremValidationData:#Microsoft.ApplicationProxy.Common.SignalingDataModel",
					"Base64EncryptedData": "CFhEmbziFkQwRCI4KzidnvmJjikWx62CsypowLs2PXtPb9suC4b\/ssAyvigsVrjXd2Uq0HLtn+G1OZcvFvzZM8aXVYXY7nno2fOh6gdo2K9NVjl89AnHaTiovs7z7JEkmF\/mzxe3bZNQxZhhd39J4LteadFLzQEfAEaAIifhKSywZfF7aK36RsOgYVFWQ06wcxsZkqSueYkZ3d8ITZYp7w4MUHsXQ8UDN8nUtJRflS7kpGj1LElPINCVBXZ0w1i9vuVKYxaSRkob1y57MEibFH8WnSFbVbt7hjldSQ\/\/sgVpVfiR0NPob6LYZCdrvYTGERPE7T2191qtJ70nwG4TrA==",
					"KeyIdentifer": "7d40765f-5e41-45d8-b3af-16123bc727cb_97C89CBDDA59AE2A619F31D8F6DE02933FFBD6D6"
				}, {
					"__type": "EncryptedOnPremValidationData:#Microsoft.ApplicationProxy.Common.SignalingDataModel",
					"Base64EncryptedData": "yJGy9ghD4I92dYPlAq68EqZZX9DwBucCQE2mWqj8m41M0oGzCqLmn98khaD\/6n2ePiInljB240DqKsUADVExrjsfO4fZeilDsOjoOioZbMtH7QiQYGwsDVn1HuUbZQuZPBCq9iHx4YN7glNkR8\/5JWOLZLf\/VpJ+kTid4agXV\/6MwaQtFIRPhVVKHvMhbvzwxYsTXVUt2XXSTqQU37OeagmUYvdmMHWoED6zlWFuW+B0lGmdWj6w6hCARZQCQSPKTVxRBRYjnpPk+kzcVs4GdEOc9QkBWRvQ5KimgECrINEkzVyVgMjcRdVdnKENiSWlZf\/\/XLWaL55\/PtOXxdzQCg==",
					"KeyIdentifer": "5905551d-8eb1-4f23-a041-5bcf0919a331_FFFE8C5F086B1EA51F76BEE0D183DE9FA38BA86C"
				}
			],
			"Password": "",
			"UserPrincipalName": "user@company.com"
		}
	}
}
{{< /highlight>}}

EncryptedData contains one element for each **registered PTA agent**. Base64EncryptedData contains the password the user entered, encrypted using the public key of the agent's certificate. Key identifier is in the format
"< serial-number >_< thumbprint >" where serial-number and thumbprint identify the correct certificate.

After decrypting the password, the agent calls <a href="https://docs.microsoft.com/en-gb/windows/win32/api/winbase/nf-winbase-logonuserw" target="_blank">Win32 LogonUser API</a> (LogonUserW to be specific) with the given username and password.
If successful, the following Base64-encoded JSON file is sent to the url similar to "https://proxyworkerrolein2-his-weur-2.connector.his.msappproxy.net/subscriber/connection?requestId=5903c353-93d9-47cd-8a40-8c45a0844794" in "x-cwap-backend-response" header in a regular https POST request.
{{< highlight json >}}
[{
		"ClaimType": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/authentication",
		"Resource": true,
		"Right": "http://schemas.xmlsoap.org/ws/2005/05/identity/right/identity"
	}, {
		"ClaimType": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"Resource": "user@company.com",
		"Right": "http://schemas.xmlsoap.org/ws/2005/05/identity/right/identity"
	}
]
{{< /highlight>}}

If the password is incorrect, the following error message is used instead. There are other possible errors too, such as 1328 for logon time restrictions.
{{< highlight json >}}
[{
		"ClaimType": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/authentication",
		"Resource": false,
		"Right": "http://schemas.xmlsoap.org/ws/2005/05/identity/right/identity"
	}, {
		"ClaimType": "http://msappproxy.net/ws/2015/02/identity/claims/validationfailurereasoning",
		"Resource": 1326,
		"Right": "http://schemas.xmlsoap.org/ws/2005/05/identity/right/identity"
	}
]
{{< /highlight>}}

### Conclusion
The PTA authentication process seems a bit complicated with many moving parts. However, as the technologies it is based on (Azure Service Bus) are robust, it seems to work fine.

# Setting up Fiddler to capture PTA flow
As many of you might be keen to see yourself what is going on, here are the instructions on how to set up <a href="https://www.telerik.com/fiddler" target="_blank">Fiddler</a> to work with PTA traffic.

## Install PTA agent
The first step is to install the PTA agent normally from <a href="https://download.msappproxy.net/Subscription/00000000-0000-0000-0000-000000000000/Connector/ptaDownloadConnectorInstaller" target="_blank">here</a>. After the installation completes, turn the "Microsoft Azure AD Connect Authentication Agent" service off.

## Register the PTA Agent
Next step is to register a new PTA Agent. This can be easily done with AADInternals v0.2.8 or newer.

{{< highlight powershell >}}
# Register a PTA Agent
pt=Get-AADIntAccessTokenForPTA
Register-AADIntPTAAgent -AccessToken $pt -MachineName "server1.company.com" -FileName server1.pfx
{{< /highlight>}}
The output should be similar to this:
```
PTA agent registered as server1.company.com
Certificate saved to server1.pfx
```
Open the folder where the certificate is located and double-click the certificate to install it. The certificate must be installed to the Personal store of the Local Machine.

After installing the certificate, open the certification manager (Local Machine). Locate the certificate and export it as "ClientCertificate.cer" to "Documents\Fiddler2". 
This way, Fiddler knows which certificate to use in client certificate authentication.

## Change the PTA Agent certificate
The next step is to change the current PTA Agent configuration to use the newly registered agent information and certificate.

{{< highlight powershell >}}
# Change the PTA certificate
Set-AADIntPTACertificate -PfxFileName server1.pfx
{{< /highlight>}}
The output should be similar to the following:
```
Certification information set, remember to restart the service.
```
**Note!** After a while, Azure AD won't send password requests encrypted using the certificate of the original agent (as it is inactive). That leads to "unable to encrypt" error message. 
If this happens, you need to find out (using SysInterals Procmon or similar tool) which certificate the agent tries to use under "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\", and give
read access to that file for "Network Service".

## Run the Fiddler
The last step is to run Fiddler and change the default proxy to it. When the "Microsoft Azure AD Connect Authentication Agent" is started, you should see how the boostrap is fetched and connections to
signalling listener endpoints are made.

# Credits
This article and the research was inspired by two great articles: Adam Chester's <a href="https://blog.xpnsec.com/azuread-connect-for-redteam/" target="_blank">Azure AD Connect for Red Teamers</a> and
Matt Felton's <a href="https://journeyofthegeek.com/tag/azure-pass-through-authentication/" target="_blank">Azure AD Pass-through Authentication – How does it work? Part 2</a>.
