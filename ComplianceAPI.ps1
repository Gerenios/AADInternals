# This file contains functions for Compliance API

# Aug 31st 2021
# Gets cookies used with compliance API functions
function Get-ComplianceAPICookies
{
<#
    .SYNOPSIS
    Gets cookies used with compliance API functions

    .DESCRIPTION
    Gets cookies used with compliance API functions.
    Note: Uses interactive login form so AAD Joined or Registered computers may login automatically. If this happens, start PowerShell as another user and try again.

    .Example
    PS C:\>$cookies = Get-AADIntComplianceAPICookies
    PS C:\>Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) | Set-Content auditlog.json

    .Example
    PS C:\>$cookies = Get-AADIntComplianceAPICookies
    PS C:\>Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) | ConvertTo-Csv | Set-Content auditlog.csv
#>
    [cmdletbinding()]
    Param()
    Process
    {
        Write-Warning "Get-AADIntComplianceAPICookies function doesn't work right with SSO. If credentials are not prompted, start PowerShell as another user and try again."

        $url = "https://compliance.microsoft.com"

        # Get the first set of cookies
        $response = Invoke-WebRequest -Uri $url -SessionVariable "WebSession" -Method get -MaximumRedirection 0
        $url = $response.Headers["location"]
        
        $form = Create-LoginForm -Url $url -auth_redirect "https://login.microsoftonline.com/kmsi"

        # Show the form and wait for the return value
        if($form.ShowDialog() -ne "OK") {
            # Dispose the control
            $form.Dispose()
            Write-Verbose "Login cancelled"
            return $null
        }

        # Parse the hidden form to get the parameters
        $hiddenForm = $form.controls[0].document.DomDocument.forms[0]
        $redirect = $hiddenForm.action
        $body=@{}
        foreach($element in $hiddenForm.elements)
        {
            if($element.Type -eq "hidden")
            {
                $body[$element.Name] = $element.Value
            }
        }
        # Increase the cookie maximum size and get the second set of cookies.
        $websession.Cookies.MaxCookieSize=65536

        $response = Invoke-WebRequest -UseBasicParsing -Uri $redirect -body $body -WebSession $WebSession -Method post -MaximumRedirection 1 -ErrorAction SilentlyContinue 

        # If redirect to MCAS before the previous step, we need to make an extra request
        if($redirect.EndsWith(".mcas.ms/aad_login"))
        {
            Write-Verbose "Handling MCAS response from $redirect"
            $body=@{}

            # Parse the form from the response
            $htmlResponse = $response.Content
            $s = $htmlResponse.IndexOf("<form")
            if($s -lt 0)
            {
                Write-Warning "Error handling MCAS redirect"
            }
            else
            {
                $e = $htmlResponse.IndexOf("</form>",$s)

                [xml]$xmlForm = $response.Content.Substring($s, $e-$s+7)

                foreach($element in $xmlForm.GetElementsByTagName("input"))
                {
                    if($element.Type -eq "hidden")
                    {
                        $body[$element.name] = $element.value
                    }
                }

                $response = Invoke-WebRequest -UseBasicParsing -Uri $xmlForm.form.action -body $body -WebSession $WebSession -Method post -MaximumRedirection 1 -ErrorAction SilentlyContinue 
            }
        }
        


        # Dispose the form
        $form.Dispose()

        # Extract the required cookies (sccauth & XSRF-TOKEN)
        $cookies = $WebSession.cookies.GetCookies("https://compliance.microsoft.com")
        $attributes = [ordered]@{
            "sccauth"    = $cookies["sccauth"   ].value
            "XSRF-TOKEN" = $cookies["XSRF-TOKEN"].value
        }
        
        # Return
        New-Object psobject -Property $attributes
    }
}

# Aug 31st
# Searches UnifiedAuditLog
function Search-UnifiedAuditLog
{
<#
    .SYNOPSIS
    Searches Unified Audit Log

    .DESCRIPTION
    Searches Unified Audit Log using https://compliance.microsoft.com/api

    .Parameter Cookies
    Compliance API cookies. A PSObject with sccauth and XSRF-TOKEN properties.

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
    PS C:\>$cookies = Get-AADIntComplianceAPICookies
    PS C:\>Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) | Set-Content auditlog.json

    .Example
    PS C:\>$cookies = Get-ComplianceAPICookies
    PS C:\>Search-AADIntUnifiedAuditLog -Cookies $cookies -Verbose -Start (get-date).AddDays(-90) | ConvertTo-Csv | Set-Content auditlog.csv
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [psobject]$Cookies,
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
            $results = Invoke-ComplianceAPIRequest -Cookies $Cookies -api "UnifiedAuditLog" -Method POST -Body ($body|ConvertTo-Json)

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