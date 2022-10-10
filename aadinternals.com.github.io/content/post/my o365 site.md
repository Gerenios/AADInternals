+++
title = "Get a free custom domain for Office 365/Azure AD from www.myo365.site!"
date = "2018-02-20"
lastmod = "2020-03-30"
categories =["blog"]
tags = ["Office365","DNS","AzureAD"]
thumbnail = "/images/posts/myo365site.png"
+++

Did you know that you could get a free custom domain for your Office 365 or Azure AD tenant?

<!--more-->

As a Microsoft Certified Trainer (MCT) I’ve trained Office 365 administration to hundreds of people. An extremely important part of the Office 365 administration is the management of custom domains. However, I’ve noticed that the students have always had challenges to get access to DNS to test and evaluate Office 365. Therefore I decided to create a service where you can easily get a free custom domain with all required DNS records!

You'll find the service at <a href="https://www.myo365.site" target="_blank">www.myo365.site</a>. Below I'll tell you how to get and use a free custom domain.

# 1. Claiming a domain

First, you need to browse to <a href="https://www.myo365.site" target="_blank">www.myo365.site</a> and click login.
You will be asked for a consent to access your user information. This is used only for authentication so you can safely accept.

![alt text](/images/posts/Screenshots/02_www.myo365.site_consent.png "Consent")

Next step is to claim a domain. Basically, you can choose any domain from the three second-level domains (myo365.site, myo365.net, and myo365.online).
After you've chosen your domain name, click <b>Claim It!</b>.

![alt text](/images/posts/Screenshots/03 www.myo365.site claim domain.png "Claim the domain")

When you've successfully  claimed your domain, you can manage it (TXT record).

![alt text](/images/posts/Screenshots/03 www.myo365.site domain claimed.png "Manage the domain")

# 2. Adding a custom domain to your tenant
The second step is to add the custom domain to your tenant. You can use either PowerShell or the admin center to do this.

## 2.1. PowerShell

First, we need to add the claimed custom domain to your tenant.
{{< highlight powershell >}}
New-MsolDomain -name Awesome.MyO365.site
{{< /highlight>}}

Next, we need to find out the verification DNS record:
{{< highlight powershell >}}
Get-MsolDomainVerificationDns -DomainName Awesome.MyO365.site -Mode DnsTxtRecord
{{< /highlight>}}

You should see the output such as below. Copy the MS=msXXXXXXXX value to the clipboard.
{{< highlight powershell >}}
Label : Awesome.MyO365.site
Text  : MS=ms71184682
Ttl   : 3600
{{< /highlight>}}

## 2.2. Office 365 Admin Center

First, we need to add the claimed custom domain to your tenant. In Admin Center, browse to <a href="https://portal.office.com/adminportal/home#/Domains" target="_blank">Setup > Domains </a> and click <b>Add domain</b>.

![alt text](/images/posts/Screenshots/04 02 add domain.png "Add the domain")

Enter the name of the domain you claimed and click <b>Next</b>

![alt text](/images/posts/Screenshots/04 021 add domain.png "Enter the domain")

Copy the MX=msXXXXXXXX value to the clipboard.

![alt text](/images/posts/Screenshots/04 03 copy TXT.png "Copy the TXT")

# 3. Verifying the custom domain ownership

First browse back to www.myo365.site and enter the TXT value you copied.

![alt text](/images/posts/Screenshots/04 04 add TXT.png "Enter the TXT")

Click <b>Save</b> and you should see the saved TXT value.

![alt text](/images/posts/Screenshots/04 05 TXT saved.png "TXT saved")

The verification of the custom domain can be done using PowerShell or the admin center.

## 3.1. PowerShell

Enter the following command to verify the ownership:
{{< highlight powershell >}}
Confirm-MsolDomain -DomainName Awesome.MyO365.site
{{< /highlight>}}

You should have the following confirmation:
{{< highlight powershell >}}
        Availability AvailabilityDetails                                       
        ------------ -------------------                                       
AvailableImmediately The domain has been successfully verified for your acco...
{{< /highlight>}}

You can check the status of your domains using the following command.
Enter the following command to verify the ownership:
{{< highlight powershell >}}
Get-MsolDomain
{{< /highlight>}}

And that's it! If you see your domain as verified, your custom domain is ready to use! 

{{< highlight powershell >}}
Name                    Status   Authentication
----                    ------   --------------
Awesome.MyO365.site     Verified Managed
{{< /highlight>}}

**Note!** Your domain is likely to appear as "Setup in progress" in admin center. This is just an indication that the admin center has not checked the DNS records, so everything is still working fine!  If you like to, you can check the DNS records by opening your domain in admin center and by clicking <b>Continue setup</b>.

## 3.2. Office 365 Admin Center

Browse back to Office 365 Admin center and click <b>Verify</b>.

![alt text](/images/posts/Screenshots/04 06 click verify.png "Verify")

And that's it! Your custom domain is ready to use!

![alt text](/images/posts/Screenshots/05 Domain verified.png "Setup complete")
