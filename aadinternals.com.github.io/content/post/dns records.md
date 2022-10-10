+++
title = "Create DNS records for Office 365 using PowerShell"
date = "2017-10-11"
categories =["blog"]
tags = ["PowerShell","DNS"]
thumbnail = "/images/posts/dns.png"
+++

If you are using Microsoft DNS for Office 365 DNS records, you can create the required records easily with PowerShell.

<!--more-->

# Creating DNS records

The script below creates all DNS records required to enable Office 365 services. You should run the script on the DNS server.

**Note!** The script below is only an example, you should always modify it for your purposes. Especially the **MX** and **SPF** records are crucial for mail routing to function properly.

{{< highlight powershell >}}

# Name of the domain 
$domain="mydomain.com"

# Create a new forward zone for the domain
Add-DnsServerPrimaryZone -name $domain -zonefile "$domain.dns"

# Create a Sender Policy Framework (SPF) record:
Add-DnsServerResourceRecord -zonename $domain -descriptivetext "v=spf1 include:spf.protection.outlook.com -all" -txt -name "@" -TimeToLive 3600

# Build a correct mail server name, store it to a variable, and create an MX record:
$mailExchange=$domain.Replace(".","-")+".mail.protection.outlook.com" 
Add-DnsServerResourceRecord -zonename $domain -MX -MailExchange $mailExchange -Name "@" -TimeToLive 3600 -Preference 0

# Create a SRV record for Skype for Business directory 
Add-DnsServerResourceRecord -zonename $domain -name "_sip._tls"  -TimeToLive 3600 -srv -DomainName "sipdir.online.lync.com" -Priority 100 -Weight 1 -port 443

# Create a SRV record for Skype for Business federation
Add-DnsServerResourceRecord -zonename $domain -name "_sipfederationtls._tcp" -TimeToLive 3600 -srv -DomainName "sipfed.online.lync.com" -Priority 100 -Weight 1 -port 5061

# Create a CNAME record for Outlook autodiscover:
Add-DnsServerResourceRecord -ZoneName $domain -TimeToLive 3600 -CName "autodiscover" -HostNameAlias "autodiscover.outlook.com"

# Create a CNAME record for Skype for Business autodiscover:
Add-DnsServerResourceRecord -ZoneName $domain -TimeToLive 3600 -CName "lyncdiscover" -HostNameAlias "webdir.online.lync.com"

# Create a CNAME record for Skype for Business SIP:
Add-DnsServerResourceRecord -ZoneName $domain -TimeToLive 3600 -CName "sip" -HostNameAlias "sipdir.online.lync.com"

# Create a CNAME record for client configuration:
Add-DnsServerResourceRecord -ZoneName $domain -TimeToLive 3600 -CName "msoid" -HostNameAlias "clientconfig.microsoftonline-p.net"

# Create a CNAME record for Mobile Device Managementin (MDM) registration:
Add-DnsServerResourceRecord -ZoneName $domain -TimeToLive 3600 -CName "enterpriseregistration" -HostNameAlias "enterpriseregistration.windows.net"

# create a CNAME record for Mobile Device Managementin (MDM) enrollment:
Add-DnsServerResourceRecord -ZoneName $domain -TimeToLive 3600 -CName "enterpriseenrollment" -HostNameAlias "enterpriseenrollment.manage.microsoft.com"

{{< /highlight>}}
