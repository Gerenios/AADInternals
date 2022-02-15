# This file contains utility functions for local AAD Joined devices

# Exports the transport key of the local device
# Dec 17th 2021
function Get-LocalDeviceTransportKeys
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateSet('Joined','Registered')]
        [String]$JoinType,
        [Parameter(Mandatory=$True)]
        [String]$IdpDomain,
        [Parameter(Mandatory=$True)]
        [String]$TenantId,
        [Parameter(Mandatory=$True)]
        [String]$UserEmail
    )
    Begin
    {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
    }
    Process
    {
        # Calculate registry key parts
        $idp    = Convert-ByteArrayToHex -Bytes ($sha256.ComputeHash([text.encoding]::Unicode.GetBytes($IdpDomain)))
        $tenant = Convert-ByteArrayToHex -Bytes ($sha256.ComputeHash([text.encoding]::Unicode.GetBytes($TenantId)))
        $email  = Convert-ByteArrayToHex -Bytes ($sha256.ComputeHash([text.encoding]::Unicode.GetBytes($UserEmail)))
        $sid    = Convert-ByteArrayToHex -Bytes ($sha256.ComputeHash([text.encoding]::Unicode.GetBytes(([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value)))
        

        if($JoinType -eq "Joined")
        {
            $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey\PerDeviceKeyTransportKey\$Idp\$tenant"
        }
        else
        {
            $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey\$sid\$idp\$($tenant)_$($email)"
        }

        if((Test-Path -Path $registryPath) -eq $false)
        {
            Throw "The device seems not to be Azure AD joined or registered. Registry key not found: $registryPath"
        }

        # Get the Transport Key name from registry
        try
        {
            $transPortKeyName = Get-ItemPropertyValue -Path "$registryPath" -Name "SoftwareKeyTransportKeyName"
        }
        catch
        {
            # This machine probably has a TPM, so the value name would be "TpmKeyTransportKeyName"
            Throw "Unable to get SoftwareTransportKeyName from $registryPath"
        }

        Write-Verbose "TransportKey name: $transportKeyName`n"

        # Loop through the system keys 
        $systemKeys = Get-ChildItem -Path "$env:ALLUSERSPROFILE\Microsoft\Crypto\SystemKeys"
        foreach($systemKey in $systemKeys)
        {
            Write-Verbose "Parsing $($systemKey.FullName)"
            $keyBlob = Get-Content $systemKey.FullName -Encoding byte

            # Parse the blob to get the name
            $key = Parse-CngBlob -Data $keyBlob
            if($key.name -eq $transPortKeyName)
            {
                Write-Verbose "Transport Key found! Decrypting.."
                
                # Decrypt the found key
                $transPortKey = Parse-CngBlob -Data $keyBlob -Decrypt -LocalMachine

                return $transPortKey
            }
        }
    }
    End
    {
        $sha256.Dispose()
    }
}

# Parses the oid values of the given certificate
# Dec 23rd 2021
function Parse-CertificateOIDs
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    Process
    {
        function Get-OidRawValue
        {
            Param([byte[]]$RawValue)
            Process
            {
                # Is this DER value?
                if($RawValue.Length -gt 2 -and ($RawValue[2] -eq $RawValue.Length-3 ))
                {
                    return $RawValue[3..($RawValue.Length-1)] 
                }
                else
                {
                    return $RawValue
                }
            }
        }
        $retVal = New-Object psobject
        foreach($ext in $Certificate.Extensions)
        {
            switch($ext.Oid.Value)
            {
               "1.2.840.113556.1.5.284.2" {
                    $retVal | Add-Member -NotePropertyName "DeviceId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                
               } 
               "1.2.840.113556.1.5.284.3" {
                    $retVal | Add-Member -NotePropertyName "ObjectId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                
               } 
               "1.2.840.113556.1.5.284.5" {
                    $retVal | Add-Member -NotePropertyName "TenantId" -NotePropertyValue ([guid][byte[]](Get-OidRawValue -RawValue $ext.RawData))
                
               }  
            }
        }

        return $retVal
    }
}
