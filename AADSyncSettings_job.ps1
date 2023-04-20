# This file will export AAD Connect credentials in a backgroud process
# so that the current PowerShell session is not elevated.
# Called from Get-SyncCredentials if -AsBackgroundProcess equals $true (=default)

# Add AADInternals dll to be able to elevate
Add-Type -path "$PSScriptRoot\Win32Ntv.dll"

# Import required AADInternals PowerShell scripts
. "$PSScriptRoot\CommonUtils.ps1"
. "$PSScriptRoot\AADSyncSettings.ps1"

# Get the credentials as PSObject
$credentials = Get-SyncCredentials -AsBackgroundProcess $false

# Convert to JSON string and return
return $credentials | ConvertTo-Json -Compress