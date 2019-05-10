# TODO: Figure out how to decode the settings file

function Export-AADConnectSettings
{
<#
    .SYNOPSIS
    Exports AAD Connect settings

    .Description
    Exports and decrypts Azure Active Directory Connect settings from WID configuration database. Must be run on AADConnect server
    as domain administrator
  
    .Parameter fileName
    Filename of the exported configuration file. Default is "output".

    .Parameter deleteTxt
    If set $true, deletes the exported configuration txt. Default is $true.

    .Example
    Export-AADConnectSettings
    
    .Example
    Export-AADConnectSettings -fileName myconfig -deleteTxt $false
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$fileName="output",
        [Parameter(Mandatory=$False)]
        [bool]$deleteTxt=$true
        
    )
    Process
    {
        # Check that we are on AADConnect server
        if((Get-Service ADSync -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Error "This command needs to be run on a computer with AADConnect"
            return
        }

        # Set the filenames
        $txtFile="$filename.txt"

        # Export the AADConnect configuration to an txt file
        bcp "SELECT encrypted_configuration from mms_management_agent where subtype = 'Windows Azure Active Directory (Microsoft)'" queryout $txtFile -S "(localdb)\.\ADSync" -d ADSync -T -C RAW -w | Out-Null

        # Get the file content
        $encrypted_settings_b64 = Get-Content $txtFile

        # Remove the txt file
        if($deleteXml)
        {
            Remove-Item $txtfile -Force
        }

        # Get the keyset from registry
        $keyset=Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\AD Sync\Shared\1' -Name "(default)"

        # Return
        $encrypted_settings_b64
    }
}

