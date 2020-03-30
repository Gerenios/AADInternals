# Process utils

# May 20th 2019
function Execute-Process
{
<#
    .SYNOPSIS
    Executes a given executable, batch, etc. in a new process and returns its stdout.

    .DESCRIPTION
    Executes a given executable, batch, etc. in a new process and returns its stdout.

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$FileName,
        [Parameter(Mandatory=$True)]
        [String]$Arguments
    )
    Process
    {
        # Create ProcessStartInfo
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = $FileName
        $info.Arguments = $Arguments
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.UseShellExecute = $false

        # Create a new process and execute it
        $ps = New-Object System.Diagnostics.Process
        $ps.StartInfo = $info
        $ps.Start() | Out-Null
        $ps.WaitForExit()

        # Get the output and return it
        $stdout = $ps.StandardOutput.ReadToEnd()

        return $stdout
    }
}

# May 20th 2019
function Inject-DLL
{
<#
    .SYNOPSIS
    Injects a given DLL to the given process

    .DESCRIPTION
    Injects a given DLL to the given process.

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$ProcessID,
        [Parameter(Mandatory=$True)]
        [String]$FileName
    )
    Process
    {
        $InjectDLL = "$PSScriptRoot\InjectDLL.exe"

        Execute-Process -FileName $InjectDLL -Arguments "$ProcessID `"$Filename`""
    }
}

# May 20th 2019
Function Get-ShortName { 
   
    [cmdletbinding()] 
    Param( 
        [Parameter(Mandatory=$True)] 
        [String]$FileName
    ) 
    Process
    {
        $ScriptingFSO = New-Object -ComObject Scripting.FileSystemObject 
        return $ScriptingFSO.GetFile($($FileName)).ShortPath 
    }
}