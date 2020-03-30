# This file contains functions for various Active Directory related operations

# Gets the class name of the given registry key (can't be read with pure PowerShell)
# Mar 25th 2020
function Invoke-RegQueryInfoKey
{

    [CmdletBinding()]

    
    param(
        [Parameter(Mandatory=$true)]
        [Microsoft.Win32.RegistryKey]$RegKey
    )

    Begin
    {
        # Add the C# type
        Add-Type @"
        using System;
        using System.Text;
        using System.Runtime.InteropServices;

        namespace AADInternals {
            public class advapi32 {
                [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                public static extern Int32 RegQueryInfoKey(
                    Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
                    StringBuilder lpClass,
                    [In, Out] ref UInt32 lpcbClass,
                    UInt32 lpReserved,
                    out UInt32 lpcSubKeys,
                    out UInt32 lpcbMaxSubKeyLen,
                    out UInt32 lpcbMaxClassLen,
                    out UInt32 lpcValues,
                    out UInt32 lpcbMaxValueNameLen,
                    out UInt32 lpcbMaxValueLen,
                    out UInt32 lpcbSecurityDescriptor,
                    out Int64 lpftLastWriteTime
                );
            }
        }
"@
    }
    Process
    {
        # Create the StringBuilder and length to retrieve the class name
        $length = 255
        $name = New-Object System.Text.StringBuilder $length

        # LastWrite
        [int64]$lw=0

        $error = [AADInternals.advapi32]::RegQueryInfoKey(
            $RegKey.Handle,
            $name,       # ClassName
            [ref] $length,     # ClassNameLength
            $null,  # Reserved
            [ref] $null, # SubKeyCount
            [ref] $null, # MaxSubKeyNameLength
            [ref] $null, # MaxClassLength
            [ref] $null, # ValueCount
            [ref] $null, # MaxValueNameLength
            [ref] $null, # MaxValueValueLength
            [ref] $null, # SecurityDescriptorSize
            [ref] $lw
        )

        if ($error -ne 0) {
            Throw "Error while invoking RegQueryInfoKey"
        }
        else {
            $hexValue = $name.ToString()
            if([String]::IsNullOrEmpty($hexValue))
            {
                Write-Error "RegQueryInfoKey: ClassName is empty"
            }
            else
            {
                return Convert-HexToByteArray $hexValue
            }
            
        }
    }
}

# Gets the boot key from the registry
# Mar 25th 2020
function Get-Bootkey
{
    Process
    {
        # Get the current controlset 
        $cc = Get-ItemPropertyValue "HKLM:\SYSTEM\Select" -Name "Current"

        # Construct the bootkey
        $lsaKey = "HKLM:\SYSTEM\ControlSet00$cc\Control\Lsa"
        $bootKey =  Invoke-RegQueryInfoKey (Get-Item "$lsaKey\JD")
        $bootKey += Invoke-RegQueryInfoKey (Get-Item "$lsaKey\Skew1")
        $bootKey += Invoke-RegQueryInfoKey (Get-Item "$lsaKey\GBG") 
        $bootKey += Invoke-RegQueryInfoKey (Get-Item "$lsaKey\Data")

        # Return the bootkey with the correct byte order
        return @(
            $bootKey[0x08]
            $bootKey[0x05]
            $bootKey[0x04]
            $bootKey[0x02]
            $bootKey[0x0B]
            $bootKey[0x09]
            $bootKey[0x0E]
            $bootKey[0x03]
            $bootKey[0x00]
            $bootKey[0x06]
            $bootKey[0x01]
            $bootKey[0x0D]
            $bootKey[0x0E]
            $bootKey[0x0A]
            $bootKey[0x0F]
            $bootKey[0x07]
        )

    }
}

# Gets the system key
# Mar 25th 2020
function Get-SystemKey
{
    Process
    {
        # Get the username of the ADSync service
        $runAsUser = (Get-CimInstance -Query "select StartName from win32_service where name = 'ADSync'").StartName

        if([String]::IsNullOrEmpty($runAsUser))
        {
            Throw "Could not get the user name of ADSync service"
        }

        # Get the username part
        $AAD = $runAsUser.split("\")[1]

        # Loop through the credential files
        $credFolder = "C:\Users\$AAD\AppData\Local\Microsoft\Credentials"
        $credFiles = Get-ChildItem $credFolder -Force
        foreach($credFile in $credFiles)
        {
            $data = [IO.File]::ReadAllBytes("$credFolder\$($credFile.Name)")
            $data | format-hex
        }
    }
}

# Gets the machine guid
# Mar 25th 2020
function Get-MachineGuid
{
    Process
    {
        $registryValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid"

        return [guid] $registryValue.MachineGuid

    }
}

