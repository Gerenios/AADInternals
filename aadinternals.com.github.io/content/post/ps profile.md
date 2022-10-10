+++
title = "Using PowerShell profile to connect to Office 365"
date = "2017-10-10"
categories =["blog"]
tags = ["PowerShell","DNS"]
thumbnail = "/images/posts/ps profile thumb.png"
+++

PowerShell profile makes connecting to Office 365 a lot easier!

<!--more-->

# What is a PowerShell profile?

PowerShell <a href="https://technet.microsoft.com/en-us/library/bb613488(v=vs.85).aspx" target="_blank">profile</a> is simply a PowerShell script that is executed whenever you launch a new PowerShell session.

You can have a profile which applies to all users or just to you. To automate the connection to Office 365 you should use the latter one.

The path of the profile file is stored in **$profile** variable. You can easily find the location by "executing" the variable:
{{< highlight powershell >}}
# Print the location of the PowerShell profile
$profile
{{< /highlight>}}

**Note:** There is a separate profile for both PowerShell and ISE!

You can also check whether the profile file exists. The following command returns **True** if the profile exists:
{{< highlight powershell >}}
# Check if the profile exists
Test-Path $profile
{{< /highlight>}}

# Creating a profile

If the profile does not exist, you first need to create one. Easies way is (naturally) to do it with PowerShell:
{{< highlight powershell >}}
# Create a new profile file with required directory structure
New-Item -Path $profile -ItemType File -Force
{{< /highlight>}}

Make not of the file name and open it in your favorite editor, such as PowerShell ISE. Next we will create a script that connects you to Office 365 services.

Usually you connect to Office 365 by using saved credentials. 
Credentials are first saved to variable using **Get-Credential** command, which shows a login prompt where you enter your username and password. 
To speed up the process, you can give your username as parameter so you only need to enter your password.

Below is an example of a profile which is based to our connection script from the <a href="/powershell/#the-complete-connection-script" target="_blank">PowerShell</a> article.

{{< highlight powershell >}}
# Save credentials and tenant for later use
$cred=Get-Credential -UserName "youradmin@yourdomain.com" -Message "Office 365"
$tenant="yourtenant"

# Check for null before connecting
if($cred -ne $null){
	# Connect to Office 365 (Azure AD)
	Connect-MsolService -credential $cred

	# Connect to SharePoint Online
	Connect-SPOService -Url https://$tenant-admin.sharepoint.com -Credential $cred

	# Connect to Skype for Business
	$s4bses = New-CsOnlineSession -Credential $cred
	Import-PSSession $s4bses

	# Connect to Exchange Online
	$exses = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $cred -Authentication Basic -AllowRedirection
	Import-PSSession $exses
}
{{< /highlight>}}

After saving the file, you will be prompted for the password every time start a new PowerShell session. To skip connecting, simply click cancel or hit the escape button.

![alt text](/images/posts/ps profile.png "profile login prompt")

