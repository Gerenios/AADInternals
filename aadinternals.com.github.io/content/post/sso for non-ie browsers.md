+++
title = "How to enable SSO for all browsers"
date = "2017-09-28"
categories =["blog"]
tags = ["SSO", "ADFS","PowerShell","Browser"]
thumbnail = "/images/posts/sso for non-ie browsers.png"
+++

By default, AD FS only supports SSO with Internet Explorer. However, you can easily enable support for Google Chrome, Firefox, and Edge.

<!--more-->

# Configuring single-sign-on

As we know, Office 365 single-sign-on (SSO) between the on-premises and cloud is (typically) implemented using Active Directory Federation Services (AD FS). 
AD FS is a built-in service of Windows Server operating system. 
Typically AD FS is configured so that the extranet login is handled by forms-based authentication and intranet by Windows Integrated Authentication (WIA). 
This means that when a user is logging in from a domain joined computer in intranet, the browser logs in automatically (that's why it is called single-sign-on).
However, if user is logginh in from intranet using a browser which is not supported in AD FS, user will get the login prompt:

![alt text](/images/posts/sso for non-ie browsers contoso.png "login prompt")

By default, AD FS is configured to perform WIA only with Internet Explorer. 
Luckily this can be easily changed to support also Firefox, Chrome, and Edge (Edge is supported by default in AD FS 4.0, i.e. Windows Server 2016). 
Below is the script to configure WIA in AD FS 3.0 (i.e. Windows Server 2012 R2) and AD FS 4.0.

## Server side configuration

**Note:** The script needs to be run on all AD FS servers of AD FS farm.

{{< highlight powershell >}}
# Save the list of currently supported browser user-agents to a variable
$browsers=Get-AdfsProperties | Select -ExpandProperty WIASupportedUseragents

# Add Mozilla/5.0 user-agent to the list
$browsers+="Mozilla/5.0"

# Apply the new list
Set-AdfsProperties -WIASupportedUseragents $browsers

# Restart the AD FS service
Restart-Service adfssrv
{{< /highlight>}}

**Note:** If you have problems with the Firefox SSO, you might need to turn off <a href="https://technet.microsoft.com/en-us/library/hh237448%28v=ws.10%29.aspx" target="_blank">AD FS Extended Protection</a> using the following script.

{{< highlight powershell>}}
# Turn off Extended Protection
Set-ADFSProperties –ExtendedProtectionTokenCheck None

# Restart the AD FS service
Restart-Service adfssrv
{{< /highlight>}}


## Client side configuration

If you are using Chrome or Edge, you don't need to do any client side configuration as it is using same settings than IE. 
In Firefox, you  need to do some client side configuration if you got the following authentication prompt:

![alt text](/images/posts/sso for non-ie browsers wia prompt.png "Windows login prompt")

For Firefox, you need to browse to [about:config](about:config) and add the address of your AD FS server (e.g. sts.contoso.com) to **network.negotiate-auth.trusted-uris**.

![alt text](/images/posts/sso for non-ie browsers firefox.png "Firefox configuration")

And that's it, you are ready to go. Enjoy!