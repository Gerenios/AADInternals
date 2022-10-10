+++
title = "Deep-dive to Azure AD device join"
date = "2021-03-03"
lastmod = "2021-09-10"
categories =["blog"]
tags = ["Azure Active Directory","Azure","security","MFA","BPRT","PRT","device","join","hybrid join"]
thumbnail = "/images/posts/devices.png"
+++

Devices (endpoints) are a crucial part of Microsoft's Zero Trust concept. Devices can be Registered, Joined, or Hybrid Joined to Azure AD. 
Conditional Access uses the device information as one of the decisions criteria to allow or block access to services.

In this blog, I'll explain what these different registration types are, what happens under-the-hood during the registration, and how to register devices with <a href="/aadinternals/#hack-functions-azure-ad-join-mdm-prt" target="_blank">AADInternals</a> **v0.4.6**.

<!--more-->
# What is a device?

Technically, a device is one of the object types in Azure AD. The device object is sometimes called <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/overview" target="_blank">device identity</a>.

Where users are identified based on their credentials, **devices are identified by certificates**. In other words, a device certificate represents the device registered to Azure AD. 
These certificates are created during the registration process (this will be explained later).

# Join Types

There are three different registration types, which are called **Join Types**. According to <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/overview#getting-devices-in-azure-ad" target="_blank">documentation</a>
these types are:

Join Type     | Purpose 
---           | ---
Registered    | Devices that are Azure AD registered are **typically personally owned or mobile devices** and are **signed in with a personal** Microsoft account or another local account.
Joined        | Devices that are Azure AD joined are **owned by an organization** and are **signed in with an Azure AD account** belonging to that organization. They exist only in the cloud.
Hybrid Joined | Devices that are hybrid Azure AD joined are **owned by an organization** and are **signed in with an Active Directory Domain Services account** belonging to that organization. They exist in the cloud and on-premises.

Next, let's view the documentation to see in detail the differences between these join types!

## Azure AD Registered

According to <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-azure-ad-register" target="_blank">documentation:</a>

> The goal of Azure AD registered devices is to provide your users with support for the Bring Your Own Device (BYOD) or mobile device scenarios. In these scenarios, a user can access your organization’s Azure Active Directory controlled resources using a personal device.

Azure AD Registered    | Description
---                    | ---
Definition             | Registered to Azure AD without requiring organizational account to sign in to the device
Primary audience       | Applicable to all users with the following criteria: <br><ul><li>Bring your own device (BYOD)</li><li>Mobile Devices</li></ul>
Device ownership       | User or Organization
Operating Systems      | Windows 10, iOS, Android, and MacOS
Provisioning           | Windows 10 - Settings <br>iOS/Android - Company Portal or Microsoft Authentication app <br>MacOS - Company Portal
Device sign in options | <ul><li>End-user local credentials</li><li>Password</li><li>Windows Hello</li><li>PIN</li><li>Biometrics or Patter for other devices</li></ul>
Key capabilities       | <ul><li>SSO to cloud resources</li><li>Conditional Access when enrolled into Intune</li><li>Conditional Access via App protection policy</li><li>Enables Phone sign in with Microsoft Authenticator app</li></ul>

## Azure AD Joined

According to <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-azure-ad-join" target="_blank">documentation:</a>

> Azure AD join is intended for organizations that want to be cloud-first or cloud-only. Any organization can deploy Azure AD joined devices no matter the size or industry. Azure AD join works even in a hybrid environment, enabling access to both cloud and on-premises apps and resources.

Azure AD Joined        | Description
---                    | ---
Definition             | Joined only to Azure AD requiring organizational account to sign in to the device
Primary audience       | Suitable for both cloud-only and hybrid organizations.<br>Applicable to all users in an organization
Device ownership       | Organization
Operating Systems      | <ul><li>All Windows 10 devices except Windows 10 Home</li><li>Windows Server 2019 Virtual Machines running in Azure (Server core is not supported)</li></ul>
Provisioning           | <ul><li>Self-service: Windows OOBE or Settings</li><li>Bulk enrollment</li><li>Windows Autopilot</li></ul>
Device sign in options | Organizational accounts using:<br><ul><li>Password</li><li>Windows Hello for Business</li><li>FIDO2.0 security keys</li></ul>
Device management      | <ul><li>Mobile Device Management (example: Microsoft Intune)</li><li>Co-management with Microsoft Intune and Microsoft Endpoint Configuration Manager</li></ul>
Key capabilities       | <ul><li>SSO to both cloud and on-premises resources</li><li>Conditional Access through MDM enrollment and MDM compliance evaluation</li><li>Self-service Password Reset and Windows Hello PIN reset on lock screen</li><li>Enterprise State Roaming across devices</li></ul>

## Azure AD Hybrid Joined

According to <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-azure-ad-join-hybrid" target="_blank">documentation:</a>

>Typically, organizations with an on-premises footprint rely on imaging methods to provision devices, and they often use Configuration Manager or group policy (GP) to manage them.

>If your environment has an on-premises AD footprint and you also want benefit from the capabilities provided by Azure Active Directory, you can implement hybrid Azure AD joined devices. These devices, are devices that are joined to your on-premises Active Directory and registered with your Azure Active Directory.

Azure AD Joined        | Description
---                    | ---
Definition             | Joined to on-premises AD and Azure AD requiring organizational account to sign in to the device
Primary audience       | Suitable for hybrid organizations with existing on-premises AD infrastructure.<br>Applicable to all users in an organization
Device ownership       | Organization
Operating Systems      | <ul><li>Windows 10, 8.1, and 7</li><li>Windows Server 2008/R2, 2012/R2, 2016, and 2019</li></ul>
Provisioning           | Windows 10, Windows Server 2016/2019<br><ul><li>Domain join by IT and autojoin via Azure AD Connect or ADFS config</li><li>Domain join by Windows Autopilot and autojoin via Azure AD Connect or ADFS config</li></ul>Windows 8.1, Windows 7, Windows Server 2012 R2, Windows Server 2012, and Windows Server 2008 R2 - Require MSI
Device sign in options | Organizational accounts using:<br><ul><li>Password</li><li>Windows Hello for Business for Win10</li></ul>
Device management      | <ul><li>Group Policy</li><li>Configuration Manager standalone or co-management with Microsoft Intune</li></ul>
Key capabilities       | <ul><li>SSO to both cloud and on-premises resources</li><li>Conditional Access through Domain join or through Intune if co-managed</li><li>Self-service Password Reset and Windows Hello PIN reset on lock screen</li><li>Enterprise State Roaming across devices</li></ul>

# Technical details

Now that we know the purpose of different join types let's dive into technical details!

## Device Object

Device objects are stored to Azure AD. Based on my research, here are the relevant attributes and their values related to different join types.

**Note!** The attribute names presented here are those exposed by <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-graph-api" target="_blank">Azure Active Directory Graph API</a> with
**api-version=1.61-internal** query parameter.

### objectId
The id of the Azure AD device object.

### deviceId
The device id attribute of the Azure AD device object. For Hybrid Joined devices, equals to equals to **objectGuid** of the on-prem AD device object.

### deviceTrustType
Indicates the join type.

Join Type     | Value
---           | --- 
Registered    | Workplace
Joined        | AzureAd
Hybrid Joined | ServerAd

### dirSyncEnabled
Indicates whether the device is synchronised from the on-prem AD or not. **True** for Hybrid Joined devices.

### isManaged
Indicates whether the device is managed or not. Always **True** for Hybrid Joined devices. For Registered and Joined devices, the attribute needs to be set by device management application
or **AADInternals** <a href="/aadinternals/#set-aadintdevicecompliant-a" target="_blank">Set&#8209;AADIntDeviceCompliant</a> function.

### isCompliant
Indicates whether the device is compliant or not. Attribute needs to be set by device management application
or **AADInternals** <a href="/aadinternals/#set-aadintdevicecompliant-a" target="_blank">Set&#8209;AADIntDeviceCompliant</a> function.

### reserved1
The **userCertificate** attribute of the device from the on-prem AD object for Hybrid Joined devices. Public key with a subject name that equals to **objectGuid** of the on-prem AD device object.

### onPremisesSecurityIdentifier
The security identifier (**SID**) of the on-prem AD device object. Only set for Hybrid Joined devices.

### profileType
Always **RegisteredDevice** for Registered and Joined devices. For Hybrid Joined devices initially empty after synced from on-prem AD, set to registered after the actual join.

### deviceSystemMetadata
Metadata about the device registration.

Key                     | Description
---                     | ---
CreationTime            | Time the device object was created. <br>Example: "2/20/2021 8:52:52 AM"
RegistrationAuthority   | Always set to "ADRS"
RegistrationAuthTime    | For Registered and Joined devices, the epoch timestamp when the user who registered/joined the device was authenticated.  <br>Example: "1613810824" <br>Note: The timestamp comes from user's access token (nbf claim), which is always 5 minutes earlier than the actual login.
RegistrationAuthMethods | For Registered and Joined devices, the list of authentication methods used by the user who registered/joined the device. Can be any combination of "pwd","rsa","otp","fed","wia","mfa","mngcmfa","wiaormfa","none". The PRT token created using this device will inherit this value.<br>Can be changed with **AADInternals** <a href="/aadinternals/#set-aadintdeviceregauthmethods-a" target="_blank">Set&#8209;AADIntDeviceRegAuthMethods</a> function.

## Join process

Now that we know the three different join types let's dive to process how each of these join types are performed.

Devices with different Join Type as seen in Azure AD portal:
![Device join types](/images/posts/devices_4.png)

### Register

Registering devices to Azure AD has five steps:

![Register flow](/images/posts/device_register_flow.png)

1. Generate **Device key** and **Transport key**. <br><br>
The registration software (depends on the device) generates two keysets called **Device key** (dkpub/dkpriv) and **Transport key** (tkpub/tkpriv). The private keys are stored in the device.<br><br>
The **Device key** is used to identify the device, whereas the **Transport key** is used to decrypt the session key when requesting the PRT (see this <a href="/post/prt" target="_blank">blog</a> for details).<br><br>
A certificate signing request (SCR) for "CN=7E980AD9-B86D-4306-9425-9AC066FB014A" (dkpub) is generated with dkpriv.<br><br>
2. Request access token for Azure AD Join<br><br>
The registration software request access token for appid **1b730954-1685-4b74-9bfd-dac224a7b894** with **01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9** audience.<br><br>
3. Return **access token**
4. Enroll device <br><br>
A http POST request is made to "https[:]//enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=1.0" to register the device to Azure AD:
{{< highlight json "linenos=inline,hl_lines=2 3 8" >}}
{
    "TransportKey":  "UlNBMQAIAAADA[redacted]+Ht0sYG4vPqK1B2wQcnkO4cZhJ2Q==",
    "JoinType":  4,
    "DeviceDisplayName":  "Registered Device",
    "OSVersion":  "C64",
    "CertificateRequest":  {
                               "Type":  "pkcs10",
                               "Data":  "MIICdDCCAVwCAQAwLzE[redacted]n/rOiQamubMpzL1eaEhWLH8v9hkxZic="
                           },
    "TargetDomain":  "contoso.com",
    "DeviceType":  "Commodore",
    "Attributes":  {
                       "ReuseDevice":  true,
                       "ReturnClientSid":  true,
                       "SharedDevice":  false
                   }
}
{{< /highlight>}}<br>
The dkpub (row 8) and tkpriv (row 2) are Base64 encoded. The join type (row 3) indicates device registration.

5. Return **device certificate**<br><br>
The return value contains the signed (dkpub) of the **Device key** (row 4) and its thumbprint (row 3). The owner of the device is also returned (row 7).
{{< highlight json "linenos=inline,hl_lines=3 4 7">}}
{
    "Certificate": {
        "Thumbprint": "EA9CE04D0FCFB4AB382E253B7F1BC48CBC60010B",
        "RawBody": "MIID8jCC[redacted]IE34ylUixWmNVJj39HQ5ky4+0cY6JR1JovPLaCQ"
    },
    "User": {
        "Upn": "AllanD@contoso.com"
    },
    "MembershipChanges": [{
            "LocalSID": "S-1-5-32-544",
            "AddSIDs": ["S-1-12-1-4209995732-1115842628-132208791-3473393508", "S-1-12-1-1284395347-1172857899-2838897599-3439875365"]
        }
    ]
}
{{< /highlight>}}

### Join

The process joining devices to Azure AD is identical to registering devices:

![Join flow](/images/posts/device_register_flow.png)

1. Generate **Device key** and **Transport key**.
2. Request access token for Azure AD Join
3. Return **access token**
4. Enroll device <br><br>
Only difference to the Registration is the **JoinType** (row 3):
{{< highlight json "linenos=inline,hl_lines=3" >}}
{
    "TransportKey":  "UlNBMQAIAA[redacted]QkSnl0b8xkWqv5CKfBp8RQ==",
    "JoinType":  0,
    "DeviceDisplayName":  "Joined Device",
    "OSVersion":  "Vic20",
    "CertificateRequest":  {
                               "Type":  "pkcs10",
                               "Data":  "MIICdDCCAVwCAQAwLz[redacted]2003EixNAH3U7ggIXgXBWwtVbs="
                           },
    "TargetDomain":  "contoso.com",
    "DeviceType":  "Commodore",
    "Attributes":  {
                       "ReuseDevice":  true,
                       "ReturnClientSid":  true,
                       "SharedDevice":  false
                   }
}
{{< /highlight>}}
5. Return **device certificate**

### Hybrid Join

As mentioned earlier, hybrid joined devices are joined to both on-prem AD and Azure AD. **Hybrid Joining** is similar to Registering and Joining, but there are some big differences.

First, the device object has to exist in Azure AD before the join can be performed. There are two ways to create the hybrid device object to Azure AD: it can be **synced from on-prem AD 
with Azure AD Connect**, or it can be **generated via identity federation**. With the latter way, the device object is created immediately to Azure AD, whereas the former method creates the object during the next synchronisation cycle.

Second, the device is **joined by the system**, not the user. The authentication method used during the joining depends on how the device object is created to Azure AD:

* For the Azure AD Connect synchronisation, the authentication is performed by signing a part of the enrollment request with the private key of the computer's machine certificate. 
Azure AD can verify the computer's identity by validating the signature with the public key of the machine certificate. The public key is saved in Azure AD in the **reserved1** attribute of the device object.

* For the identity federation, the authentication is performed by requesting a SAML token from AD FS and requesting an access token from Azure AD with that SAML token. The resulting access token is then used for the enrollment request.

Let's start with the **Azure AD Connect synchronisation flow**:

![Hybrid flow 1](/images/posts/device_hybrid_flow1.png)

1. Generate **Machine certificate**
2. Set the value of **userCertificate** attribute of the device's on-prem AD object to match the public key of the **Machine certificate**.
3. Synchronise the device object to Azure AD. <br>The **Device Id** attribute of the device's Azure AD object is set to **ObjectGuid** of the device's on-prem AD object.<br>
4. Generate **Device key** and **Transport key**. 
5. Enroll device <br><br>
The http POST request is a bit different than with Register and Join:
{{< highlight json "linenos=inline,hl_lines=9 11 25" >}}
{
    "ServerAdJoinData":  {
                             "DeviceType":  "Windows",
                             "TransportKey":  "UlNBMQAIAAA[redacted]eXG2wVZ/D6/VtQZCgxrq0uOEdGvJ+Gwwez6GQ==",
                             "TargetDomainId":  "5694aa9c-04e1-4df1-9d37-5d64d0915d42",
                             "OSVersion":  "Vista",
                             "TargetDomain":  "",
                             "ClientIdentity":  {
                                                    "Sid":  "S-1-5-21-181028512-47807049-227815571-9284.2021-02-20 08:57:42Z",
                                                    "Type":  "sha256signed",
                                                    "SignedBlob":  "mt4lVuVcnAsc[redacted]pYAr+d8LJZyfNan6MeXvk+2SU40BGkfdw=="
                                                },
                             "SourceDomainController":  "dc.contoso.com",
                             "DeviceDisplayName":  "Hybrid Joined Device 2"
                         },
    "CertificateRequest":  {
                               "Type":  "pkcs10",
                               "Data":  "MIICdDCCAVwCAQAwL[redacted]ctccQcPO0wwtq0dKUk/+V8aKw4i4TNznHeZ3DY="
                           },
    "Attributes":  {
                       "ReuseDevice":  true,
                       "ReturnClientSid":  true,
                       "SharedDevice":  false
                   },
    "JoinType":  6
}
{{< /highlight>}}
The join type (row 25) indicates Hybrid Join. Also, the SID of the device is sent (row 9), and it must match the **onPremisesSecurityIdentifier** of the device's Azure AD object.<br><br>
The enrollment request is authorised by calculating a SHA256 hash from "&lt;SID>.&lt;timestamp>" (row 9) and signing the hash with the private key of the **Machine certificate**. The signature (row 11) is sent with the enrollment request.
6. Return **device certificate**

**Identity federation flow:**

![Hybrid flow 2](/images/posts/device_hybrid_flow2.png)

1. Generate **Machine certificate**
2. Set the public key of the **Machine certificate** to the **userCertificate** attribute of the device's on-prem AD object.
3. Request SAML token. <br>The computer requests a SAML token from the AD FS server.
4. Return **SAML token**.<br><br>
The token includes the **name** (row 15) and **SID** (row 27) of the device and its on-prem AD GUID in Base64 encoded format (rows 9,18, 24, and 35). The account type is always **DJ** (row 21).
{{< highlight xml "linenos=inline,hl_lines=9 15 18 21 24 27 35" >}}
<saml:Assertion MajorVersion="1" MinorVersion="1" AssertionID="_b2db43d0-2f96-479e-a31f-e8225326fdbb" Issuer="http://e5.myo365.site/adfs/services/trust/" IssueInstant="2021-02-21T15:13:15.505Z" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion">
	<saml:Conditions NotBefore="2021-02-21T15:13:15.505Z" NotOnOrAfter="2021-02-21T16:13:15.505Z">
		<saml:AudienceRestrictionCondition>
			<saml:Audience>urn:federation:MicrosoftOnline</saml:Audience>
		</saml:AudienceRestrictionCondition>
	</saml:Conditions>
	<saml:AttributeStatement>
		<saml:Subject>
			<saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UUEMXKriXkOYeql655jERA==</saml:NameIdentifier>
			<saml:SubjectConfirmation>
				<saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
			</saml:SubjectConfirmation>
		</saml:Subject>
		<saml:Attribute AttributeName="UPN" AttributeNamespace="http://schemas.xmlsoap.org/claims">
			<saml:AttributeValue>DESKTOP-4A5AE8$@company.com</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute AttributeName="ImmutableID" AttributeNamespace="http://schemas.microsoft.com/LiveID/Federation/2008/05">
			<saml:AttributeValue>UUEMXKriXkOYeql655jERA==</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute AttributeName="accounttype" AttributeNamespace="http://schemas.microsoft.com/ws/2012/01">
			<saml:AttributeValue>DJ</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute AttributeName="onpremobjectguid" AttributeNamespace="http://schemas.microsoft.com/identity/claims">
			<saml:AttributeValue>UUEMXKriXkOYeql655jERA==</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute AttributeName="primarysid" AttributeNamespace="http://schemas.microsoft.com/ws/2008/06/identity/claims">
			<saml:AttributeValue>S-1-5-21-126850608-2097551590-1142751551-1260</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute AttributeName="insidecorporatenetwork" AttributeNamespace="http://schemas.microsoft.com/ws/2012/01" a:OriginalIssuer="CLIENT CONTEXT" xmlns:a="http://schemas.xmlsoap.org/ws/2009/09/identity/claims">
			<saml:AttributeValue>true</saml:AttributeValue>
		</saml:Attribute>
	</saml:AttributeStatement>
	<saml:AuthenticationStatement AuthenticationMethod="urn:federation:authentication:windows" AuthenticationInstant="2021-02-21T15:13:15.505Z">
		<saml:Subject>
			<saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UUEMXKriXkOYeql655jERA==</saml:NameIdentifier>
			<saml:SubjectConfirmation>
				<saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
			</saml:SubjectConfirmation>
		</saml:Subject>
		<saml:SubjectLocality IPAddress="" DNSAddress=""/>
	</saml:AuthenticationStatement>
	<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
		<SignedInfo>
			<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
			<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<Reference URI="#_b2db43d0-2f96-479e-a31f-e8225326fdbb">
				<Transforms>
					<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
				</Transforms>
				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
				<DigestValue>tLyWWYmqHM5OqQoULGhxtO0iFiHu2uqg/nmS0orxfG4=</DigestValue>
			</Reference>
		</SignedInfo>
		<SignatureValue>Ook5qUQYD[redacted]/39yd2WVc3ZbN5asVD6a3kU25ZqCY3A==</SignatureValue>
		<KeyInfo>
			<X509Data>
				<X509Certificate>MIIC7jCCA[redacted]SV4JYS3wGstXeMw5qx++5fw==</X509Certificate>
			</X509Data>
		</KeyInfo>
	</Signature>
</saml:Assertion>
{{< /highlight>}}
5. Request access token for Azure AD Join<br>
Requests an access token using the SAML token. 
6. Return **access token** <br>
The returned access token looks like a normal user token, but there are some differences.<br><br>
The token contains **account type** (row 7), which is always "DJ". It also contains the **on-prem AD object id** (row 16) and **SID** (row 17) of the device. <br><br>
The **idp** (row 13) and **unique_name** (row 23) attributes contains what seems to be the issuer uri of the AD FS. However, this is not the case, as the **domain part of the uri is the domain of the device**, not FQDN of the AD FS service.<br><br>
{{< highlight json "linenos=inline,hl_lines=7 13 16 17 23" >}}
{
    "aud": "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",
    "iss": "https://sts.windows.net/8c63b77b-19de-4b04-a8b2-ae8bb19a00fe/",
    "iat": 1613920183,
    "nbf": 1613920183,
    "exp": 1613924083,
    "account_type": "DJ",
    "acr": "1",
    "aio": "AXQAi/8TAAAASTiNcttgcax[redacted]o27/TRsgA==",
    "amr": ["wia"],
    "appid": "1b730954-1685-4b74-9bfd-dac224a7b894",
    "appidacr": "0",
    "idp": "http://company.com/adfs/services/trust/",
    "in_corp": "true",
    "ipaddr": "13.122.32.15",
    "on_prem_id": "5c0c4151-e2aa-435e-987a-a97ae798c444",
    "primary_sid": "S-1-5-21-1768792239-781667213-1105014165-9071",
    "rh": "0.AAAAnKqUVuEE8U2dN11k0JFdQlQJcxuFFnRLm_3awiSnuJR5AIE.",
    "scp": "policy_management",
    "sub": "6vWJbn3QWCXJShfSB3c2MbRKe5YPYZ01e3nLFlWiUFk",
    "tenant_region_scope": "EU",
    "tid": "8c63b77b-19de-4b04-a8b2-ae8bb19a00fe",
    "unique_name": "http://company.com/adfs/services/trust/#",
    "uti": "fjp57QEVuEGDuKTRzjQkAA",
    "ver": "1.0",
    "xms_sptype": "0"
}
{{< /highlight>}}
7. Generate **Device key** and **Transport key**. 
8. Enroll device
9. Return **device certificate**


# Conditional Access

Devices are a crucial part of Microsoft's **Zero Trust** concept: 

![Zero Trust](/images/posts/diagram-zero-trust-security-elements.png)

In practice, implementing Zero Trust requires Azure AD Conditional Access (CA), which is included in Azure AD Premium P1. Among other things, with CA, we can allow or deny access based on the device information. 

According to <a href="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/require-managed-devices#managed-devices" target="_blank">documentation</a>,
we can require the device to be **managed**. Managed devices are devices that are either **Hybrid Joined** or marked as **compliant**. 

The Hybrid Joined devices are assumed to be managed by **Configuration Manager** and/or **GPO**s. 
Other devices can be marked compliant by Mobile Device Management (MDM) system, such as <a href="https://docs.microsoft.com/en-us/mem/intune/fundamentals/what-is-intune" target="_blank">Intune</a>. However, as I described in an earlier <a href="/post/mdm/" target="_blank">blog post</a>, the device compliance can be "faked", depending on the compliance requirements.
The compliance can also be set by **AADInternals** <a href="/aadinternals/#set-aadintdevicecompliant-a" target="_blank">Set&#8209;AADIntDeviceCompliant</a> function.

# Single-Sign-On

As mentioned earlier, devices registered or joined to Azure AD allows single-sign-on (SSO) for Azure AD. The SSO is implemented by <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token" target="_blank">Primary Refresh Tokens</a> (PRTs), 
which can be created with the device and transport certificates.
The process and details of creating PRTs are described in an earlier <a href="/post/prt/" target="_blank">blog post</a>.

One important detail related to PRTs is the authentication method used when the device was registered or joined to Azure AD. If the user was authenticated with MFA, also the access tokens fetched using the PRT will have
the MFA claim set. This will satisfy MFA requirement of CA policies. Administrators can change the methods after the registration with **AADInternals** <a href="/aadinternals/#set-aadintdeviceregauthmethods-a" target="_blank">Set&#8209;AADIntDeviceRegAuthMethods</a> function.

# Joining devices with AADInternals

**AADInternals** can register, join, and hybrid join devices to Azure AD with <a href="/aadinternals/#join-aadintdevicetoazuread-j" target="_blank">Join&#8209;AADIntDeviceToAzureAD</a> function.
Let's see how to do this in action!

## Registering devices

Registering devices to Azure AD is supported in **AADInternals** version **v0.4.6** and later. <br><br>
To register a device, obtain an access token and provide **Register** as **JoinType**:

{{< highlight powershell>}}
# Get access token for Azure AD Join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache

# Register a new device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My Registered Device" -JoinType Register
{{< /highlight>}}
**Output:**
```
Device successfully registered to Azure AD:
  DisplayName:     "My Registered Device"
  DeviceId:        77b7781f-9531-44f0-bae2-ad45b995880a
  Cert thumbprint: 00D8F218928A63D466091BA6847CE5A701A75218
  Cert file name : "77b7781f-9531-44f0-bae2-ad45b995880a.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-4209995732-1115842628-132208791-3473393508
  S-1-12-1-1284395347-1172857899-2838897599-3439875365
```

## Joining devices

The **JoinType** defaults to **Join**, so joining a device is easy:

{{< highlight powershell>}}
# Get access token for Azure AD Join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache

# Register a new device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My Joined Device"
{{< /highlight>}}
**Output:**
```
Device successfully registered to Azure AD:
  DisplayName:     "My Joined Device"
  DeviceId:        bbe84457-2c93-4857-a7e4-0573fdcfd229
  Cert thumbprint: 6AFA62FEF611EBC1DFDA72B0221C986B77CF7597
  Cert file name : "bbe84457-2c93-4857-a7e4-0573fdcfd229.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-4209995732-1115842628-132208791-3473393508
  S-1-12-1-1284395347-1172857899-2838897599-3439875365
  S-1-12-1-1372034668-1267036473-87356082-2200290463
```

## Hybrid joining devices

As explained earlier, hybrid join requires that a device object exists in Azure AD. Moreover, we now know that there are two ways to create those device objects to Azure AD.

### Hybrid joining to synced device - option 1

Let's start by creating a device object to on-prem AD, syncing it to Azure AD, and hybrid joining it.

The following script creates a computer object to on-prem AD (rows 1-5), gets its GUID (rows 6-7), creates a self-signed certificate for it using **AADInternals** (row 8), and finally, sets the public key
of the certificate to the **userCertificate** attribute of the computer object (row 9).

{{< highlight powershell "linenos=inline" >}}
$ComputerName = "DESKTOP-1234"
$ComputerOU =   "OU=Computers,DC=company,DC=com"
$CloudDomain =  "company.com"

New-ADComputer -Name $ComputerName -SAMAccountName $ComputerName -DisplayName $ComputerName -Path $ComputerOU -Enabled $true
$ComputerObject = Get-ADComputer $ComputerName 
$ComputerGuid = $ComputerObject.ObjectGUID
New-AADIntCertificate -SubjectName "CN=$ComputerGuid" -Export
Set-ADObject $ComputerGuid -Add @{"userCertificate" = [byte[]](get-content ".\CN=$ComputerGuid.cer" -Encoding byte)}
{{< /highlight>}}

As the output shows, the generated certificate is also exported to a file:

```
Certificate successfully exported:
  CN=09d302c1-8160-430a-a9b1-a699ae696b31.pfx
  CN=09d302c1-8160-430a-a9b1-a699ae696b31.cer
```

The script created a new computer object to the Active Directory:

![Computer added to AD](/images/posts/devices_1.png)

Next, run the following cmdlet to start the sync:

{{< highlight powershell >}}
Start-ADSyncSyncCycle
{{< /highlight>}}

After the sync, the device appears in Azure AD:

![Computer added to Azure AD](/images/posts/devices_2.png)

Now we can continue the script we started earlier. First, we need to get the tenant id (row 10).
By using the generated certificate and providing the name and SID of the computer, we can hybrid join the device (row 11):

{{< highlight powershell "linenos=inline,linenostart=10">}}
$TenantId = Get-AADIntTenantID -Domain $CloudDomain
Join-AADIntDeviceToAzureAD -PfxFileName ".\CN=$ComputerGuid.pfx" -DeviceName $ComputerObject.Name -SID $ComputerObject.SID -TenantId $TenantId
{{< /highlight>}}

```
Device successfully registered to Azure AD:
  DisplayName:     "DESKTOP-1234"
  DeviceId:        09d302c1-8160-430a-a9b1-a699ae696b31
  Cert thumbprint: 99EE3264242568BDDB3D0800C064F9D369B051E8
  Cert file name : "09d302c1-8160-430a-a9b1-a699ae696b31.pfx"
```

Now the computer is successfully hybrid joined to Azure AD:

![Computer Hybrid Joined to Azure AD](/images/posts/devices_3.png)

### Hybrid joining to synced device - option 2

It is also possible to create device objects directly to Azure AD with **AADInternals** using <a href="/aadinternals/#join-aadintonpremdevicetoazuread-a" target="_blank">Join&#8209;AADIntOnPremDeviceToAzureAD</a> function.
The function uses the same API Azure AD Connect is using, so **Global Admin** or **Directory Synchronization Accounts** role is required.

If SID, DeviceId, or certificate are not provided, the function will generate them.

{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAADGraph -SaveToCache 

# Create a device object to Azure AD
Join-AADIntOnPremDeviceToAzureAD -DeviceName "DESKTOP-5678"
{{< /highlight>}}
```
Device successfully created:
  Device Name:     "DESKTOP-5678"
  Device ID:       663cb1d1-bd4b-412f-a673-14f04ea55622
  Device SID:      S-1-5-21-378725881-735212363-822861820-5928
  Cloud Anchor:    Device_d7bf50e4-9538-43e9-b1ed-d20f8fd60064
  Source Anchor:   0bE8Zku9L0GmcxTwTqVWIg==
  Cert thumbprint: DF40352AD440EF8A4BECC27347A4FA9D35677188
  Cert file name:  "663cb1d1-bd4b-412f-a673-14f04ea55622-user.pfx"
```

We can now use the generated certificate and other information to hybrid join the device:
{{< highlight powershell >}}
# Get the tenant id
$TenantId = Get-AADIntTenantID -Domain company.com
# Hybrid join the device
Join-AADIntDeviceToAzureAD -DeviceName "DESKTOP-5678" -SID "S-1-5-21-378725881-735212363-822861820-5928" -TenantId $TenantId -PfxFileName .\663cb1d1-bd4b-412f-a673-14f04ea55622-user.pfx
{{< /highlight>}}
```
Device successfully registered to Azure AD:
  DisplayName:     "DESKTOP-5678"
  DeviceId:        663cb1d1-bd4b-412f-a673-14f04ea55622
  Cert thumbprint: BCDFF1388B845A2CEF4D0C9F4C08DD68CC130B41
  Cert file name : "663cb1d1-bd4b-412f-a673-14f04ea55622.pfx"
```

### Hybrid joining by federation

To hybrid join a device with federation, a SAML token is needed. To create the SAML token, we need to have the **token signing certificate** and the **issuer uri** of the identity provider.

**Note:** AD FS certificate export functionality was heavily refactored in **v0.4.7**. See the <a href="/post/adfs/" target="_blank">blog</a> for details.

Easies way to get the certificate is to export it from AD FS with **AADInternals**:
{{< highlight powershell >}}
# Export AD FS token signing and encryption certificates
Export-AADIntADFSCertificates
{{< /highlight>}}

To get the issuer uri, run the following cmdlet on AD FS server:
{{< highlight powershell >}}
# Get AD FS issuer uri
$issuer = (Get-AdfsProperties).Identifier.OriginalString
{{< /highlight>}}

To create a SAML token for the device:
{{< highlight powershell >}}
# Create a new SAML token
$saml = New-AADIntSAMLToken -UserName "DESKTOP-9999" -DeviceGUID (New-Guid) -Issuer $issuer -PfxFileName .\ADFS_signing.pfx
{{< /highlight>}}

Now we have all we need to hybrid join the device:
{{< highlight powershell >}}
# Get an access token for the device with the SAML token
Get-AADIntAccessTokenForAADJoin -SAMLToken $saml -Device -SaveToCache

# Hybrid join the device
Join-AADIntDeviceToAzureAD -DeviceName "DESKTOP-9999"
{{< /highlight>}}
```
Device successfully registered to Azure AD:
  DisplayName:     "DESKTOP-9999"
  DeviceId:        0810056c-d2d5-4c1b-bc17-2f2fbedd6ca3
  Cert thumbprint: 3022FF7937C0766CE3DB0AD45C9413FB68A05EE3
  Cert file name : "0810056c-d2d5-4c1b-bc17-2f2fbedd6ca3.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-3240472016-1160587922-3614255014-3410032901
  S-1-12-1-2566832563-1141717763-392342924-578657198
```

# Summary

In this blog post, I explained what happens under-the-hood when devices are joined to Azure AD. Although there are three different join types, all device certificates are technically identical.

Next question would be how to exploit what we've have learned? Well, that is another story soon to be told :wink:

# References
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/overview" target="_blank">What is a device identity?</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-azure-ad-register" target="_blank">Azure AD registered devices</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-azure-ad-join" target="_blank">Azure AD joined devices</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-azure-ad-join-hybrid" target="_blank">Hybrid Azure AD joined devices</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-device-writeback" target="_blank">Azure AD Connect: Enabling device writeback</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview" target="_blank">What is Conditional Access?</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/require-managed-devices#managed-devices" target="_blank">How To: Require managed devices for cloud app access with Conditional Access</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-graph-api" target="_blank">Azure Active Directory Graph API</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/mem/intune/fundamentals/what-is-intune" target="_blank">Microsoft Intune is an MDM and MAM provider for your devices</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token" target="_blank">What is a Primary Refresh Token?</a>
