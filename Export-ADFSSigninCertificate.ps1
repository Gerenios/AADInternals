# Data SHOULD be encrypted using AES 256 CBC with 128 bit blocksize.
# Hash SHOULD be HMAC256
# FIX: Decryption doesn't work :(


function Export-ADFSSigningCertificate
{
<#
    .SYNOPSIS
    Exports ADFS signing certificate

    .Description
    Exports ADFS signing certificate from WID configuration database. Must be run on ADFS server
    as domain administrator (requires access to DKM container)
  
    .Parameter fileName
    Filename of the exported configuration xml and certificate pfx without extension. Default is "output".

    .Parameter deleteXml
    If set $true, deletes the exported configuration xml. Default is $true.

    .Example
    Export-AADIntADFSSigningCertificate
    
    .Example
    Export-AADIntADFSSigningCertificate -fileName myadfs -deleteXml $false
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$fileName="output",
        [Parameter(Mandatory=$False)]
        [bool]$deleteXml=$true
        
    )
    Process
    {
        # Check that we are on ADFS server
        if((Get-Service ADFSSRV -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Error "This command needs to be run on ADFS server"
            return
        }

        # Set the filenames
        $xmlFile="$filename.xml"
        $pfxFile="$filename.pfx"

        # Export the ADFS configuration to an xml file
        bcp "SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings" queryout $xmlfile -S \\.\pipe\MICROSOFT##WID\tsql\query -d AdfsConfigurationV3 -T -C RAW -w

        # Read the XML, read the encrypted PFX, and save the bytes to a variable
        [xml]$xml=Get-Content $xmlFile 
        $encPfx=$xml.ServiceSettingsData.SecurityTokenService.AdditionalSigningTokens.CertificateReference.EncryptedPfx
        $encPfxBytes=[System.Convert]::FromBase64String($encPfx)

        # Remove the xml file
        if($deleteXml)
        {
            Remove-Item $xmlfile -Force
        }

        # Get DKM container info
        $group=$xml.ServiceSettingsData.PolicyStore.DkmSettings.Group
        $container=$xml.ServiceSettingsData.PolicyStore.DkmSettings.ContainerName
        $parent=$xml.ServiceSettingsData.PolicyStore.DkmSettings.ParentContainerDn
        $base="CN=$group,$container,$parent"

        # Read the encryption/decryption key
        $ke=(get-adobject -filter 'ObjectClass -eq "Contact" -and name -ne "CryptoPolicy"' -SearchBase $base -Properties thumbnailPhoto).thumbnailPhoto

        # Set the parameters
        $macLn=32 #HMAC-256 = 32 bytes
        $ctLn=$encPfxBytes.Count

        $iv=$encPfxBytes[0..15]
        $ct=$encPfxBytes[16..($ctLn-$macLn)]

        # Create a decryptor and decrypt
        $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create("AES")
        $Crypto.Mode="CBC"
        $Crypto.KeySize = 256
        $Crypto.BlockSize = 128
        $Crypto.Padding = "PKCS7" # Default
        #$Crypto.Padding = "None"
        #$Crypto.Padding = "ANSIX923"
        $Crypto.Key = $ke
        $Crypto.IV = $iv

        $decryptor = $Crypto.CreateDecryptor()
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$decryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($ct,0,$ct.Count)
        $cs.Close()

        $pfx = $ms.ToArray()
        $ms.Close()

        $pfx | Set-Content $pfxFile -Encoding Byte
    }
}