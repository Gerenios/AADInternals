# This file contains functions for Compliance API

# Refactored to use access tokens Dec 13th 2024
# Searches UnifiedAuditLog
function Search-UnifiedAuditLog
{
<#
    .SYNOPSIS
    Searches Unified Audit Log

    .DESCRIPTION
    Searches Unified Audit Log using https://compliance.microsoft.com/api

    .Parameter AccessToken
    AccessToken for Compliance API 

    .Parameter Start
    Start time (date) of the search. Defaults to current date - 1 day.

    .Parameter End
    Start time (date) of the search. Defaults to current date.

    .Parameter All
    If provided, returns all results (max 50100)

    .Parameter IpAddresses
    List of IP addresses to search.

    .Parameter Operations
    List of operations to search. The list of available operations: https://docs.microsoft.com/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance#audited-activities

    .Parameter Target
    The target file, folder, or site. Url or a part of it withouth spaces.

    .Parameter Users
    List of users to search. UPNs and partial UPNs seem to work.

    .Example
    PS C:\>$at = Get-AADIntAccessTokenForCompliance
    PS C:\>Search-AADIntUnifiedAuditLog -AccessToken $at -Verbose -Start (get-date).AddDays(-90) | Set-Content auditlog.json

    .Example
    PS C:\>Get-AADIntAccessTokenForCompliance -SaveToCache
    PS C:\>Search-AADIntUnifiedAuditLog -Verbose -Start (get-date).AddDays(-90) | ConvertTo-Csv | Set-Content auditlog.csv
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$AccessToken,
        [Parameter(Mandatory=$False)]
        [datetime]$Start = (Get-Date).AddDays(-1),
        [Parameter(Mandatory=$False)]
        [datetime]$End = (Get-Date),
        [Parameter(Mandatory=$False)]
        [switch]$All,
        [Parameter(Mandatory=$False)]
        [string[]]$IpAddresses,
        [Parameter(Mandatory=$False)]
        [string]$Target,
        [Parameter(Mandatory=$False)]
        [string[]]$Operations,
        [Parameter(Mandatory=$False)]
        [string[]]$Users
    )
    Process
    {

        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -Resource "80ccca67-54bd-44ab-8625-4b79c4dc7775"

        $body=@{
            "newSession"   = $true
            "optin"        = $true
            "sessionId"    = [uint64]((Get-Date).ToUniversalTime() - $epoch).totalmilliseconds
            "startDate"    = "$($Start.ToString("yyyy-MM-dd")) 00:00:00 +0000"
            "endDate"      = "$(  $End.ToString("yyyy-MM-dd")) 00:00:00 +0000"
            "ipAddresses"  = $IpAddresses -join ","
            "targetObject" = $Target
            "operations"   = $Operations -join ","
            "users"        = $Users -join ","
        }

        do
        {
            # Invoke the request
            $results = Invoke-ComplianceAPIRequest -AccessToken $AccessToken -api "UnifiedAuditLog" -Method POST -Body ($body|ConvertTo-Json)

            # Change the newSession to false to fetch rest of the events 
            $body["newSession"] = $false

            # Verbose
            Write-Verbose "Received: $($results[$results.count-1].ResultIndex)/$($results[$results.count-1].ResultCount)"

            # Return
            $results
        } # If -All switch used, loop until all results received
        while($All -and $results[$results.count-1].ResultIndex -lt $results[$results.count-1].ResultCount)
    }
}