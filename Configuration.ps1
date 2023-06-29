# Load the settings from config.json
# May 29th 2023
function Read-Configuration
{
<#
    .SYNOPSIS
    Loads AADInternals settings

    .DESCRIPTION
    Loads AADInternals settings from config.json. All changes made after loading AADInternals module will be lost.

    .Example
    PS C:\>Read-AADIntConfiguration
#>
    [cmdletbinding()]
    param()
    Process
    {
        # Clear the settings
        $Script:config = @{}

        # ConvertFrom-Json -AsHashtable not supported in PowerShell 5.1
        $configObject = Get-Content -Path "$PSScriptRoot\config.json" | ConvertFrom-Json
        foreach($property in $configObject.PSObject.Properties)
        {
            $Script:config[$property.Name] = $property.Value
        }
    }
}

# Save the settings to config.json
# May 29th 2023
function Save-Configuration
{
<#
    .SYNOPSIS
    Saves AADInternals settings

    .DESCRIPTION
    Saves the current AADInternals settings to config.json. Settings will be loaded when AADInternals module is loaded.
    
    .Example
    PS C:\>Save-AADIntConfiguration
#>
    [cmdletbinding()]
    param()
    Process
    {
        $Script:config | ConvertTo-Json | Set-Content -Path "$PSScriptRoot\config.json"

        Write-Host "Settings saved."
    }
}

# Shows the configuration
# May 29th 2023
function Get-Configuration
{
<#
    .SYNOPSIS
    Shows AADInternals settings

    .DESCRIPTION
    Shows AADInternals settings
    
    .Example
    PS C:\>Get-AADIntSettings

    Name                           Value
    ----                           -----
    SecurityProtocol               Tls12
    User-Agent                     AADInternals
#>
    [cmdletbinding()]
    param()
    Process
    {
        $Script:config
    }
}

# Get AADInternals setting
# May 29th 2023
function Get-Setting
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline)]
        [string]$Setting
    )
    Process
    {
        return $Script:config[$Setting]
    }
}

# Sets AADInternals setting value
# May 29th 2023
function Set-Setting
{
    <#
    .SYNOPSIS
    Sets the given setting with given value

    .DESCRIPTION
    Sets the given setting with given value. To persist, use Save-AADIntConfiguration after setting the value.

    .Parameter Setting
    Name of the setting to be set

    .Parameter Value
    Value of the setting
    
    .Example
    PS C:\>Set-AADIntSetting -Setting "User-Agent" -Value "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"

    .Example
    PS C:\>Set-AADIntSetting -Setting "User-Agent" -Value "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
    PS C:\>Save-AADIntConfiguration

    Settings saved.
#>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline, Position=0)]
        [string]$Setting,
        [parameter(Mandatory=$true, ValueFromPipeline, Position=1)]
        [PSObject]$Value
    )
    Process
    {
        $Script:config[$Setting] = $value
    }
}