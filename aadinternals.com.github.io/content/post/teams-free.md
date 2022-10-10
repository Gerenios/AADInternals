+++
title = "Technical deep dive to Microsoft Teams (free)"
date = "2018-07-25"
lastmod = "2018-07-25"
categories =["blog"]
tags = ["Office 365","Teams"]
thumbnail = "/images/posts/teams-free.png"
+++

Microsoft Teams has been available for free since July 2018. In this blog, I'll deep dive to its technical details.

<!--more-->

# Teams

Teams is a collaboration platform competing mainly against Slack. In this blog, I'm not discussing the Teams as such but focus on some technical details.


# Signing up for free Teams

To sign up for Teams free, browse to <a href="https://products.office.com/en-us/microsoft-teams/free" target="_blank">Teams product site.</a>

You need a Microsoft account (Office 365 account won't work), you can use your existing account or create a new one.

![sign up for teams](/images/posts/teams-free-01.png)

Congratulations, now you have a free Teams for up to 300 people.

# Underlying Azure AD

As we know, all Office 365 services are utilising Azure AD. Teams is not an exception to this. If you look at the url, it is something like this:
```
https://teams.microsoft.com/_?tenantId=11111111-4115-4cfb-906f-b157e27c2f82
```
So, if there is an underlying tenant, we only can see the id, not the name.

What if I just browse to https://portal.office.com and see whether I can access the Office 365 portal? No luck, as it prompts for username and password.

![login prompt](/images/posts/teams-free-02.png)

However, browsing to https://portal.azure.com did the trick. Now you can access the underlying Azure AD! If you go to Users, there is only one user similar to one below.

We are interested in Identity and Authentication information.

As we can see, the username is admin, and the tenant name is the company name given when signing up. If someone else has already used the same name, a random number is added to the end. We can also notice that the source for the user is Microsoft Account

![Azure AD](/images/posts/teams-free-03.png)

As the authentication information below shows, the user is logging in as the very same Microsoft Account I used when signing up.
![Azure AD](/images/posts/teams-free-04.png)

# Creating a new admin user

Now that we have access to Azure AD, we can also create new users. So let's start by creating a new user with Global Administrator rights.
Unfortunately, we can't choose the password, so we need to change it during the first login.

![Azure AD](/images/posts/teams-free-05.png)

Now that the new admin is created, you can log out and login again to https://portal.azure.com as the new admin.

# Entering Office 365

After successfully logging in to Azure portal, you can also access the Office 365 at https://portal.office.com

The new admin doesn't have any licenses, so there's not much to see. However, the admin can access the Admin portal.

As we can see below, there is only one subscription named "Microsoft Teams (free)". The subscription is a trial one, with a reasonably long trial period of 833 years. 

**Note!** Licensing information is also available in Azure portal.

![Office 365 Admin Center](/images/posts/teams-free-06.png)

# Office 365 services and admin centers

If we assign the license to our new admin user, we can see that the license includes **Microsoft Teams**,**SharePoint Online Kiosk**, and **Office Web apps**.

![Licenses](/images/posts/teams-free-07.png)

Because we have a SharePoint license, we can also access the **SharePoint admin center**. You can create new sites as with "normal" Office 365. However, space is limited to one terabyte and resources to 600. This does not include users' OneDrive quota, which is two gigabytes. 

We can also access the **Teams & Skype admin center**, which has a limited functionality as Skype for Business is not included in the free Teams license.

# PowerShell access

Because Teams is running on Office 365 tenant, we can access it normally using PowerShell. However, as the license does not include Exchange online, we cannot use Exchange online commands to manipulate Office 365 groups. Luckily, also <a href="https://www.powershellgallery.com/packages/MicrosoftTeams" target="_blank">Teams PowerShell Beta module</a> works fine.

# What else can you do?

* You can register a custom domain (you can get one free from <a href="https://www.myo365.site" target="_blank">here</a>)
* You can synchronize users from your on-prem AD using Azure AD Connect
* You can use AD FS and MFA
* You can purchase additional licenses (and get a trial too)

# Summary

From technical point-of-view, when you get the free Microsoft Teams, you'll also have a full-fledged Office 365/Azure AD environment with Teams licenses. This means that you will get a free SharePoint Online with one terabyte quota and two gigabytes OneDrive for Business for each user. You can also synchronize your on-premises AD to Office 365, so you can log in using the same credentials than in on-premises.
