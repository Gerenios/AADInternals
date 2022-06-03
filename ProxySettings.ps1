# This file contains functions for setting proxy settings for Windows devices

# Sets proxy settings
# Jan 20th 2022
Function Set-ProxySettings
{
<#
    .SYNOPSIS
    Sets proxy settings of the local Windows machine and trusts Fiddler root certificate.

    .DESCRIPTION
    Sets proxy settings of the local Windows machine for:
    * .NET Framework (both 32 & 64 bit) by editing machine.config
    * LocalSystem using BITSAdmin
    * NetworkService using BITSAdmin
    * winhttp using netsh
    * Local user by modifying registry
    * Machine level by modifying registry
    * Force machine level proxy by modifying registry

    Trusts Fiddler root certificate by importing it to Local Machine truster root certificates

    .Parameter ProxyAddress
    Proxy address with port number.

    .Parameter TrustFiddler
    Trust Fiddler root certificate

    .EXAMPLE
    PS\:>Set-AADIntProxySettings -ProxyAddress 10.0.0.10:8080

    Setting proxies for x86 & x64 .NET Frameworks:
     C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\machine.config
     C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config
    Setting proxy for LocalSystem:

    BITSADMIN version 3.0
    BITS administration utility.
    (C) Copyright Microsoft Corp.

    Internet proxy settings for account LocalSystem were set.
    (connection = default)

    Proxy usage set to       Manual_proxy
    Proxy list set to        http://10.0.0.1:8080
    Proxy bypass list set to <empty>
    Setting proxy for NetworkService:

    BITSADMIN version 3.0
    BITS administration utility.
    (C) Copyright Microsoft Corp.

    Internet proxy settings for account NetworkService were set.
    (connection = default)

    Proxy usage set to       Manual_proxy
    Proxy list set to        http://10.0.0.1:8080
    Proxy bypass list set to <empty>
    Setting winhttp proxy:

    Current WinHTTP proxy settings:

        Proxy Server(s) :  10.0.0.1:8080
        Bypass List     :  (none)

    Setting the proxy of local user Internet Settings:
    VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\C
    urrentVersion\Internet Settings\Connections Property: DefaultConnectionSettings".
    VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\C
    urrentVersion\Internet Settings\Connections Property: SavedLegacySettings".
    Setting the proxy of machine Internet Settings:
    VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\
    CurrentVersion\Internet Settings\Connections Property: DefaultConnectionSettings".
    VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\
    CurrentVersion\Internet Settings\Connections Property: SavedLegacySettings".
    Setting machine level procy policy for Internet Settings:
    VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft
    \Windows\CurrentVersion\Internet Settings Property: ProxySettingsPerUser".

    .EXAMPLE
    PS\:>Set-AADIntProxySettings -ProxyAddress 10.0.0.10:8080 -TrustFiddler

    Setting proxies for x86 & x64 .NET Frameworks:
     C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\machine.config
     C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config
    Setting proxy for LocalSystem:

    BITSADMIN version 3.0
    BITS administration utility.
    (C) Copyright Microsoft Corp.

    Internet proxy settings for account LocalSystem were set.
    (connection = default)

    Proxy usage set to       Manual_proxy
    Proxy list set to        http://10.0.0.1:8080
    Proxy bypass list set to <empty>
    Setting proxy for NetworkService:

    BITSADMIN version 3.0
    BITS administration utility.
    (C) Copyright Microsoft Corp.

    Internet proxy settings for account NetworkService were set.
    (connection = default)

    Proxy usage set to       Manual_proxy
    Proxy list set to        http://10.0.0.1:8080
    Proxy bypass list set to <empty>
    Setting winhttp proxy:

    Current WinHTTP proxy settings:

        Proxy Server(s) :  10.0.0.1:8080
        Bypass List     :  (none)

    Setting the proxy of local user Internet Settings:
    VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\C
    urrentVersion\Internet Settings\Connections Property: DefaultConnectionSettings".
    VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\C
    urrentVersion\Internet Settings\Connections Property: SavedLegacySettings".
    Setting the proxy of machine Internet Settings:
    VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\
    CurrentVersion\Internet Settings\Connections Property: DefaultConnectionSettings".
    VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\
    CurrentVersion\Internet Settings\Connections Property: SavedLegacySettings".
    Setting machine level procy policy for Internet Settings:
    VERBOSE: Performing the operation "Set Property" on target "Item: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft
    \Windows\CurrentVersion\Internet Settings Property: ProxySettingsPerUser".
    Trusting Fiddler root certificate:


       PSParentPath: Microsoft.PowerShell.Security\Certificate::LocalMachine\Root

    Thumbprint                                Subject                                                              
    ----------                                -------                                                              
    33D6FCEE2850DC53EEED517F3E8E72EB944BD467  CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST, OU=Created by http://...

#>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [String]$ProxyAddress,
        [Switch]$TrustFiddler,
        [Switch]$TrustBurp
    )
    Process
    {
        # Split the proxy address
        $proxyHost = $ProxyAddress.Split(":")[0]
        $proxyPort = $ProxyAddress.Split(":")[1]

        # Set .NET proxy in a quick-and-dirty way by just adding at the end
        $configXml = @"
    <!-- Added by AADInternals $((Get-Date).ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)+"Z")-->
    <system.net>
	    <defaultProxy enabled = "true" useDefaultCredentials = "true">
		    <proxy autoDetect="false" bypassonlocal="true" proxyaddress="http://$($ProxyAddress)" usesystemdefault="false" />
	    </defaultProxy>
    </system.net>
</configuration>
"@
        Write-Host "Setting proxies for x32 & x64 .NET Frameworks:" -ForegroundColor Yellow
        $dotNetConfigs = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\machine.config","C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"
        foreach($dotNetConfig in $dotNetConfigs)
        {
            $content = Get-Content $dotNetConfig -Encoding UTF8

            [xml]$xmlContent = $content
            if($xmlContent.configuration.'system.net'.defaultProxy)
            {
                Write-Warning ".NET proxy settings already set, skipping $dotNetConfig"
            }
            else
            {
                $lines = $content.Length
                for($a = $lines ; $a-- ; $a -ge 0)
                {
                    if($content[$a] -like "*</configuration>*")
                    {
                        $content[$a] = $configXml
                        break
                    }
                }

                Write-Host " $dotNetConfig" -ForegroundColor Yellow

                $content | Set-Content $dotNetConfig -Encoding UTF8
            }
        }

        # Add proxy for the LocalSystem and NetworkService using bitsadmin
        Write-Host "Setting proxy for LocalSystem:" -ForegroundColor Yellow
        & 'bitsadmin' '/Util' '/SetIEProxy' 'LocalSystem' 'Manual_proxy' "http://$ProxyAddress" '""'

        Write-Host "Setting proxy for NetworkService:"  -ForegroundColor Yellow
        & 'bitsadmin' '/Util' '/SetIEProxy' 'NetworkService' 'Manual_proxy' "http://$ProxyAddress" '""'

        # Set winhttp proxy
        Write-Host "Setting winhttp proxy:" -ForegroundColor Yellow
        & 'netsh' 'winhttp' 'set' 'proxy' "$ProxyAddress"

        #
        # Set proxy for Internet Settings
        #

        # Generate the settigns blob
        [byte[]]$settingsBlob = New-DefaultConnectionSettings -ProxyAddress $ProxyAddress

        # Set Current User settings
        Write-Host "Setting the proxy of local user Internet Settings:" -ForegroundColor Yellow
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name "DefaultConnectionSettings" -Value $settingsBlob -Force -Verbose
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name "SavedLegacySettings"       -Value $settingsBlob -Force -Verbose
        
        # Set Machine settings
        Write-Host "Setting the proxy of machine Internet Settings:" -ForegroundColor Yellow
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name "DefaultConnectionSettings" -Value $settingsBlob -Force -Verbose
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name "SavedLegacySettings"       -Value $settingsBlob -Force -Verbose

        # Set proxy policy on machine level
        Write-Host "Setting machine level procy policy for Internet Settings:" -ForegroundColor Yellow
        New-Item         -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Force -Verbose
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxySettingsPerUser" -Value 0 -Force -Verbose

        # Trust the Fiddler
        if($TrustFiddler)
        {
            Write-Host "Trusting Fiddler root certificate:" -ForegroundColor Yellow
            $tmpFile = New-TemporaryFile
            Invoke-RestMethod -Uri "http://ipv4.fiddler:$proxyPort/FiddlerRoot.cer" -Proxy "http://$ProxyAddress" -OutFile $tmpFile
            Import-Certificate -FilePath $tmpFile -CertStoreLocation "Cert:\LocalMachine\Root"            Remove-Item $tmpFile -Force
        }

        # Trust Burp Suite
        if($TrustBurp)
        {
            Write-Host "Trusting Burp root certificate:" -ForegroundColor Yellow
            $tmpFile = New-TemporaryFile
            Invoke-RestMethod -Uri "http://$ProxyAddress/cert" -OutFile $tmpFile
            Import-Certificate -FilePath $tmpFile -CertStoreLocation "Cert:\LocalMachine\Root"            Remove-Item $tmpFile -Force
        }

    }
}

# Generates a DefaultConnectionSettings blob
# Jan 20th 2022
Function New-DefaultConnectionSettings
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [String]$ProxyAddress
    )
    Process
    {
        # Ref: http://atyoung.blogspot.com/2012/06/info-regarding-hkeycurrentusersoftwarem.html

        $proxyLen = $ProxyAddress.length
        $blob = new-object byte[] (56 + $proxyLen)
        $p = 0
        
        [Array]::Copy([bitconverter]::GetBytes([UInt32] 0x46 ) , 0, $blob, $p, 4); $p += 4 # Identifier 0x46 or 0x3C
        [Array]::Copy([bitconverter]::GetBytes([UInt32] 0x00 ) , 0, $blob, $p, 4); $p += 4 # Counter
        [Array]::Copy([bitconverter]::GetBytes([UInt32] 0x03 ) , 0, $blob, $p, 4); $p += 4 # Use a proxy server for your lan
                # 09 when only 'Automatically detect settings' is enabled
                # 03 when only 'Use a proxy server for your LAN' is enabled
                # 0B when both are enabled
                # 05 when only 'Use automatic configuration script' is enabled
                # 0D when 'Automatically detect settings' and 'Use automatic configuration script' are enabled
                # 07 when 'Use a proxy server for your LAN' and 'Use automatic configuration script' are enabled
                # 0F when all the three are enabled.
                # 01 when none of them are enabled.
        [Array]::Copy([bitconverter]::GetBytes([UInt32] $proxyLen )  , 0, $blob, $p,         4); $p += 4         # Proxy address length
        [Array]::Copy([Text.Encoding]::ASCII.GetBytes($ProxyAddress) , 0, $blob, $p, $proxyLen); $p += $proxyLen # Proxy address
        
        #[Array]::Copy([bitconverter]::GetBytes([UInt32] 0x00 ) , 0, $blob, $p, 4); $p += 4 # Additional info length
        #[Array]::Copy([bitconverter]::GetBytes([UInt32] 0x00 ) , 0, $blob, $p, 4); $p += 4 # Automatic script address length
        # Rest is just 32 bytes of 0x00

        return $blob
    }
}