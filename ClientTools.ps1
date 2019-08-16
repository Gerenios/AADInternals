# This script contains functions for client side

<#
    .SYNOPSIS
    Gets the Office update branch of the local computer

    .DESCRIPTION
    Gets the Office update branch of the local computer from the registry

    .Example
    Get-AADIntOfficeUpdateBranch

    Update branch: Current
    
#>
# Jul 8th 2019
function Get-OfficeUpdateBranch
{
    Param(

            [ValidateSet('16.0')]
            [String]$Version="16.0"
        )
    Process
    {
        $reg=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\office\$Version\common\officeupdate\"

        Write-Host "Update branch: $($reg.updateBranch)"
        #Write-Host "Automatic updates enabled: $($reg.EnableAutomaticUpdates -ne 0)"
    }
}

<#
    .SYNOPSIS
    Sets the Office update branch of the local computer

    .DESCRIPTION
    Sets the Office update branch of the local computer to the registry. Requires administrator rights!

    .Example
    Set-AADIntOfficeUpdateBranch -UpdateBranch InsiderFast

    Update branch: InsiderFast
  
#>
# Jul 8th 2019
function Set-OfficeUpdateBranch
{
    Param(
            [ValidateSet('16.0')]
            [String]$Version="16.0",
            [ValidateSet('InsiderFast','FirstReleaseCurrent','Current','FirstReleaseDeferred','Deferred','DogFood')]
            [String]$UpdateBranch="Current"
        )
    Process
    {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\office\$Version\common\officeupdate\" -Name "updateBranch" -Value $UpdateBranch

        Get-OfficeUpdateBranch -Version $Version
    }
}