+++
title = "Azure AD PowerShell module installation got easier"
date = "2018-02-09"
lastmod = "2018-05-31"
categories =["blog"]
tags = ["PowerShell"]
thumbnail = "/images/posts/ps module.png"
+++

Azure AD PowerShell module was earlier installed by a standard .msi package. Now you can install it using one PowerShell command. However, installation requires PowerShell 5 or newer.

<!--more-->

# Before you begin
Module installation requires PowerShell 5 or later which is included in Windows 10 & Server 2016. If you have previous version of Windows, you need to install Windows Management Framework 5.1 <a href="https://docs.microsoft.com/en-us/powershell/wmf/5.1/install-configure" target="_blank">here</a>.

# Installing the Azure AD PowerShell module
To install the latest Azure AD PowerShell module, enter the following commands as an administrator.

## Azure AD PowerShell v1 (MsOnline)

{{< highlight powershell >}}

# Install the MsOnline module
Install-Module MSOnline
{{< /highlight>}}

If you haven't used the Install-Module command earlier, you might not have NuGet provider. Just click the Yes to continue.
 
![alt text](/images/posts/ps module_1.png "NuGet prompt")

You might also get the following error message stating that PSGallery is untrusted. This is okay so you may safely click the yes button.

![alt text](/images/posts/ps module_2.png "PSGallery")

Now you are ready to connect to Office 365!

{{< highlight powershell >}}
Connect-MsolService
{{< /highlight>}}

## Azure AD PowerShell v2 (AzureAD)
{{< highlight powershell >}}

# Install the AzureAD module
Install-Module AzureAD
{{< /highlight>}}

Now you are ready to connect to Office 365!

{{< highlight powershell >}}
Connect-AzureAD
{{< /highlight>}}

## Azure AD PowerShell v2 preview (AzureADPreview)

**Note!** AzureAD Preview has same commands than AzureAD, only the module name is different. Therefore, they 
cannot be installed in the same computer together.

{{< highlight powershell >}}

# Install the AzureAD module
Install-Module AzureADPreview
{{< /highlight>}}

Now you are ready to connect to Office 365! 


{{< highlight powershell >}}
Connect-AzureAD
{{< /highlight>}}

