Add-Type -AssemblyName System.Web

# Registers Syncgent to the Azure AD
# Apr 2nd 2019
function Register-SyncAgent
{
<#
    .SYNOPSIS
    Registers the Sync agent to Azure AD and creates a client certificate

    .DESCRIPTION
    Registers the Sync agent to Azure AD with given machine name and creates a client certificate

    .Example
    Register-AADIntSyncAgent -MachineName "server1.company.com"

    Sync agent registered as server1.company.com
    Certificate saved to Sync_client_certificate.pfx

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntSyncAgent -AccessToken $pt -MachineName "server1.company.com" -FileName server1.pfx

    Sync agent registered as server1.company.com
    Certificate saved to server1.pfx
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$FileName="Sync_client_certificate.pfx"
    )
    Process
    {
        return Register-Agent -AccessToken $AccessToken -MachineName $MachineName -FileName $FileName -AgentType Sync
    }
}

# Invokes the Sync Agent

function Invoke-SyncAgent
{

<#
    .SYNOPSIS
    Invokes a Sync Agent with given name and certificate.

    .DESCRIPTION
    Invokes a Sync Agent with given name and certificate, and connects to Azure AD. Emulates Azure AD Sync Agent.

    .Example
    Invoke-AADIntSyncAgent -MachineName "server1.company.com"

    Connector 1 connecting to his-eur1-neur1
    Connector 2 connecting to his-eur1-neur1
    Connector 3 connecting to his-eur1-weur1
    Connector 4 connecting to his-eur1-weur1

    Sync Agent started, waiting for logins..

    .Example
    Register-AADIntSyncAgent -MachineName "server1.company.com"

    Sync agent registered as server1.company.com
    Certificate saved to Sync_client_certificate.pfx

    PS C:\>Invoke-AADIntSyncAgent -MachineName "server1.company.com"

    Connector 1 connecting to his-eur1-neur1
    Connector 2 connecting to his-eur1-neur1
    Connector 3 connecting to his-eur1-weur1
    Connector 4 connecting to his-eur1-weur1

    Sync Agent started, waiting for logins..

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntSyncAgent -AccessToken $pt -MachineName "server1.company.com" -FileName server1.pfx

    Sync agent registered as server1.company.com
    Certificate saved to server1.pfx

    PS C:\>Invoke-AADIntSyncAgent -MachineName "server1.company.com" -FileName server1.pfx

    Connector 1 connecting to his-eur1-neur1
    Connector 2 connecting to his-eur1-neur1
    Connector 3 connecting to his-eur1-weur1
    Connector 4 connecting to his-eur1-weur1

    Sync Agent started, waiting for logins..
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$fileName="Sync_client_certificate.pfx"
    )
    Process
    {
        # Clean the old jobs
        Get-Job | Remove-Job -Force

        # Load the certificate
        $fullPath = (Get-Item $fileName).FullName
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile($fullPath)
       
        # Get the bootStraps
        $BootStraps = Get-BootstrapConfiguration -MachineName $MachineName -fileName $fileName
        $max = 10
        
        $connectors = @()
        
        foreach($BootStrap in $bootStraps)
        {
            if($connectors.Length -gt $max)
            {
                break
            }

            $id=($connectors.count+1)

            # The startup script
            $sb={
                param($BootStrap, $cert)
                . "$PSScriptRoot\MSAppProxy_utils.ps1";
                Connect-ToBus -BootStrap $BootStrap -cert $cert
                }
            
            # Create a synchronized hashtable for status etc.
            $status=[hashtable]::Synchronized(@{})

            # Create the runspace etc.
            $rs=[runspacefactory]::CreateRunspace()
            $ps=[powershell]::Create()  
            $ps.Runspace = $rs
            $rs.Open() 
            $rs.SessionStateProxy.SetVariable("status",$status)

            $ps.AddScript($sb)
            $ps.AddArgument($BootStrap)
            $job = $ps.BeginInvoke() 

            $name = "$id-$($BootStrap.Namespace)"

            # Create a connector object
            $connector = New-Object PSObject
            $connector | Add-Member -NotePropertyName "Name" -NotePropertyValue ($name)
            $connector | Add-Member -NotePropertyName "PowerShell" -NotePropertyValue ($ps)
            $connector | Add-Member -NotePropertyName "Runspace" -NotePropertyValue ($rs)
            $connector | Add-Member -NotePropertyName "Job" -NotePropertyValue ($job)
            $connector | Add-Member -NotePropertyName "Status" -NotePropertyValue ($status)

            $connectors+=$connector
        }
        

        
        
        $colors=@("Yellow","White","Cyan","Red")
        while($true)
        {
            $running = $connectors.count
            
            Clear-Host

            foreach($connector in $connectors)
            {
                Write-Host "$($connector.Name) Completed: $($connector.job.IsCompleted) Status: $($connector.status.status)" -ForegroundColor $colors[$((([int]$connector.Name.Substring(0,1))-1)%4)]
                if($connector.job.IsCompleted)
                {
                    $connector.PowerShell.EndInvoke($connector.job)
                    $connector.Runspace.Close()
                    $running--

                }
            }
            
            if($running -eq 0)
            {
                Write-Host "All connectors completed. Exiting.." 
                break
            }
            Start-Sleep -Seconds 3
        }

    }
}





