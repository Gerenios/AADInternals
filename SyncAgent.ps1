Add-Type -AssemblyName System.Web

# Registers Syncgent to the Azure AD
# Apr 2nd 2019
# Sep 7th 2022: Added UpdateTrust
function Register-SyncAgent
{
<#
    .SYNOPSIS
    Registers the Sync agent to Azure AD and creates a client certificate or renews existing certificate.

    .DESCRIPTION
    Registers the Sync agent to Azure AD with given machine name and creates a client certificate or renews existing certificate.

    The filename of the certificate is <server FQDN>_<tenant id>_<agent id>_<cert thumbprint>.pfx

    .Example
    Get-AADIntAccessTokenForPTA -SaveToCache
    Register-AADIntPTAAgent -MachineName "server1.company.com"

    Sync Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
    Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntPTAAgent -AccessToken $pt -MachineName "server1.company.com" 

    Sync Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
    Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx

    .Example
    PS C:\>Register-AADIntPTAAgent -MachineName "server1.company.com" -UpdateTrust -PfxFileName .\server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx

    Sync Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) certificate renewed for server1.company.com
    Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_449D42C1BA32B23A621EBE62329AE460FE68924B.pfx
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$FileName,
        [Parameter(ParameterSetName='normal',Mandatory=$False)]
        [Parameter(ParameterSetName='update',Mandatory=$True)]
        [switch]$UpdateTrust,
        [Parameter(ParameterSetName='update',Mandatory=$True)]
        [String]$PfxFileName,
        [Parameter(ParameterSetName='update',Mandatory=$False)]
        [String]$PfxPassword
    )
    Process
    {
        return Register-ProxyAgent -AccessToken $AccessToken -MachineName $MachineName -FileName $FileName -AgentType Sync -UpdateTrust $UpdateTrust -PfxFileName $PfxFileName -PfxPassword $PfxPassword
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





