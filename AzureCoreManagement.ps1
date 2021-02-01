# This script contains functions for Azure Core Management API

# Return the classic administrators of the given subscription
# May 30th 2020
function Get-AzureClassicAdministrators
{
<#
    .SYNOPSIS
    Returns classic administrators of the given Azure subscription

    .DESCRIPTION
    Returns classic administrators of the given Azure subscription

    .Example
    Get-AADIntAzureClassicAdministrators

    emailAddress                  role                                     
    ------------                  ----                                     
    admin@company.onmicrosoft.com ServiceAdministrator;AccountAdministrator
    co-admin@comapny.com          CoAdministrator

    .Example
    $at=Get-AADIntAccessTokenFor
    C:\PS>Get-AADIntAccessTokenForAzureCoreManagement
    C:\PS>Get-AADIntAzureClassicAdministrators -AccessToken $at

    emailAddress                  role                                     
    ------------                  ----                                     
    admin@company.onmicrosoft.com ServiceAdministrator;AccountAdministrator
    co-admin@comapny.com          CoAdministrator

   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Subscription
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        # Invoke the command
        $response=Invoke-RestMethod -Method get -Uri "https://management.azure.com/subscriptions/$Subscription/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01" -Headers $headers

        # Return
        $response.value.properties
    }
}

# Elevates the current Global Admin to Azure User Access Administrator
# May 30th 2020
function Grant-AzureUserAccessAdminRole
{
<#
    .SYNOPSIS
    Elevates the current authenticated Global Admin to Azure User Access Administrator

    .DESCRIPTION
    Elevates the current authenticated Global Admin to Azure User Access Administrator.
    This allows the admin for instance to manage all role assignments in all subscriptions of the tenant.

    .Example
    Grant-AADIntAzureUserAccessAdminRole

    .Example
    $at=Get-AADIntAccessTokenForAzureCoreManagement
    C:\PS>Grant-AADIntAzureUserAccessAdminRole -AccessToken $at

   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        # Invoke the command. Returns 200 OK if successfull
        Invoke-RestMethod  -Method Post -Uri "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2015-07-01" -Headers $headers
    }
}


# Lists user's Subscriptions
# Jun 2nd 2020
function Get-AzureSubscriptions
{
<#
    .SYNOPSIS
    Lists the user's Azure subscriptions

    .DESCRIPTION
     Lists the user's Azure subscriptions

    .Example
    $at=Get-AADIntAccessTokenForAzureCoreManagement
    C:\PS>Get-AADIntAzureSubscriptions -AccessToken $at

    subscriptionId                       displayName   state  
    --------------                       -----------   -----  
    867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 MyAzure001    Enabled
    99fccfb9-ed41-4179-aaf5-93cae2151a77 Pay-as-you-go Enabled
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        # Invoke the command. Returns 200 OK if successfull
        $response = Invoke-RestMethod  -Method Get -Uri "https://management.azure.com/subscriptions?api-version=2016-06-01" -Headers $headers

        # Return
        foreach($value in $response.value)
        {
            $value | Select subscriptionId,displayName,state
        }
        
    }
}

# Lists azure subscription resource groups
# Jun 2nd 2020
function Get-AzureResourceGroups
{
<#
    .SYNOPSIS
    Lists Azure subscription ResourceGroups

    .DESCRIPTION
    Lists Azure subscription ResourceGroups

    .Example
    Get-AADIntAzureResourceGroups -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0

    name       location tags
    ----       -------- ----
    Production westus   Production
    Test       eastus   Test

    .Example
    $at=Get-AADIntAccessTokenForAzureCoreManagement
    C:\PS>Get-AADIntAzureSubscriptions -AccessToken $at

    subscriptionId                       displayName state  
    --------------                       ----------- -----  
    867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 MyAzure001  Enabled

    C:\PS>Get-AADIntAzureResourceGroups -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0

    name       location tags
    ----       -------- ----
    Production westus   Production
    Test       eastus   Test
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$SubscriptionId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        # Invoke the command.
        $response = Invoke-RestMethod  -Method Get -Uri "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups?api-version=2019-10-01" -Headers $headers

        # Return
        foreach($value in $response.value)
        {
            $value | Select name,location,tags
        }
        
    }
}


# Lists azure subscription VMs
# Jun 2nd 2020
function Get-AzureVMs
{
<#
    .SYNOPSIS
    Lists Azure subscription VMs

    .DESCRIPTION
    Lists Azure subscription VMs and shows information including server name, VM OS and size, and admin user name.

    .Example
    Get-AADIntAzureVMs -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0

    resourceGroup name     location   id                                   computerName adminUserName vmSize          OS     
    ------------- ----     --------   --                                   ------------ ------------- ------          --     
    PRODUCTION    Client   westus     c210d38b-3346-41d3-a23d-27988315825b Client       AdminUSer     Standard_A2_v2  Windows
    PRODUCTION    DC       westus     9b8f8753-196f-4f24-847a-e5bcb751936d DC           AdminUSer     Standard_DS1_v2 Windows
    PRODUCTION    Exchange westus     a12ffb24-a69e-4ce9-aff3-275f49bba315 Exchange     AdminUSer     Standard_DS2_v2 Windows
    PRODUCTION    Server1  westus     c7d98db7-ccb5-491f-aaeb-e71f0df478b6 Server1      AdminUSer     Standard_DS1_v2 Windows
    TEST          Server2  eastus     ae34dfcc-ad89-4e53-b0b4-20d453bdfcef Server2      AdminUSer     Standard_DS1_v2 Windows
    TEST          Server3  eastus     f8f6a7c5-9927-47f9-a790-84c866f5719c Server3      AzureUser     Standard_B1ms   Linux

    .Example
    $at=Get-AADIntAccessTokenForAzureCoreManagement
    C:\PS>Get-AADIntAzureSubscriptions -AccessToken $at

    subscriptionId                       displayName state  
    --------------                       ----------- -----  
    867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 MyAzure001  Enabled

    C:\PS>Get-AADIntAzureVMs -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0

    resourceGroup name     location   id                                   computerName adminUserName vmSize          OS     
    ------------- ----     --------   --                                   ------------ ------------- ------          --     
    PRODUCTION    Client   westus     c210d38b-3346-41d3-a23d-27988315825b Client       AdminUSer     Standard_A2_v2  Windows
    PRODUCTION    DC       westus     9b8f8753-196f-4f24-847a-e5bcb751936d DC           AdminUSer     Standard_DS1_v2 Windows
    PRODUCTION    Exchange westus     a12ffb24-a69e-4ce9-aff3-275f49bba315 Exchange     AdminUSer     Standard_DS2_v2 Windows
    PRODUCTION    Server1  westus     c7d98db7-ccb5-491f-aaeb-e71f0df478b6 Server1      AdminUSer     Standard_DS1_v2 Windows
    TEST          Server2  eastus     ae34dfcc-ad89-4e53-b0b4-20d453bdfcef Server2      AdminUSer     Standard_DS1_v2 Windows
    TEST          Server3  eastus     f8f6a7c5-9927-47f9-a790-84c866f5719c Server3      AzureUser     Standard_B1ms   Linux

   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$SubscriptionId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }
        
        # Invoke the command
        $response = Invoke-RestMethod  -Method Get -Uri "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Compute/virtualMachines?api-version=2019-12-01" -Headers $headers

        # Return
        foreach($value in $response.value)
        {
            $attributes=[ordered]@{
                ResourceGroup = $value.id.split("/")[4]
                Name =          $value.name
                Location =      $value.location
                Id =            $value.properties.vmId
                #license =       $value.properties.licenseType
                ComputerName=   $value.properties.osProfile.computerName
                AdminUserName=  $value.properties.osProfile.adminUserName
                VMSize =        $value.properties.hardwareProfile.vmSize
                OS = ""
            }
            if($value.properties.osProfile.WindowsConfiguration)
            {
                $attributes["OS"] = "Windows"
            }
            if($value.properties.osProfile.linuxConfiguration)
            {
                $attributes["OS"] = "Linux"
            }
            New-Object psobject -Property $attributes
        }
        
    }
}


# Runs a given script on the given Azure VM
# Jun 2nd 2020
function Invoke-AzureVMScript
{
<#
    .SYNOPSIS
    Runs a given script on the given Azure VM

    .DESCRIPTION
    Runs a given script on the given Azure VM and prints out the response. Note! Returns only ascii, so any non-ascii character is not shown correctly. 
    Multi-line scripts are supported. Use `n as a line separator.

    .Example
    Invoke-AADIntAzureVMScript -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup TEST -Server Server2 -Script "whoami"

    [stdout]
    nt authority\system

    [stderr]

    .Example
    Invoke-AADIntAzureVMScript -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup TEST -Server Server2 -Script "whoami`nGet-Process 123123123"

    [stdout]
    nt authority\system

    [stderr]
    Get-Process : Cannot find a process with the name "123123123". Verify the process name and call the cmdlet again.
    At C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\1.1.5\Downloads\script42.ps1:2 char:1
    + Get-Process 123123123
    + ~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : ObjectNotFound: (123123123:String) [Get-Process], ProcessCommandException
        + FullyQualifiedErrorId : NoProcessFoundForGivenName,Microsoft.PowerShell.Commands.GetProcessCommand

    .Example
    Invoke-AADIntAzureVMScript -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup TEST -Server Server3 -Script "whoami" -VMType Linux

    Enable succeeded: 
    [stdout]
    root

    [stderr]

    .Example
    Invoke-AADIntAzureVMScript -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup PRODUCTION -Server Server2 -Script "Get-Process"

    [stdout]
        727      36    14132      27092       5.94    396   0 svchost                                                      
        936      29    69796      76820       7.91    400   0 svchost                                                      
        664      22    15664      27432      39.39    464   0 svchost                                                      
        839      23     6856      24352       0.91    792   0 svchost                                                      
        785      17     4792      10968       4.75    892   0 svchost                                                      
        282      13     3020       9324       7.41   1052   0 svchost                                                      
       1889      96    38548      72480      24.86   1216   0 svchost                                                      
        642      35     8928      28452       0.50   1236   0 svchost                                                      
        519      24    19480      37620       4.08   1376   0 svchost                                                      
        411      17    15440      18076      29.81   1392   0 svchost                                                      
        833      41    10676      25512       2.02   1424   0 svchost                                                      
        317      11     2000       8840       0.08   1432   0 svchost                                                      
        380      31     7324      16320       0.39   1584   0 svchost                                                      
        211      12     1876       7524       0.22   1808   0 svchost                                                      
        199       9     1596       6916       0.00   1968   0 svchost                                                      
        200      10     2308       8344       0.06   2188   0 svchost                                                      
        146       8     1472       7144       0.06   3000   0 svchost                                                      
        468      21     6516      31128       0.33   3140   2 svchost                                                      
        173       9     4332      12968       0.72   3208   0 svchost                                                      
       2061       0      192        156      11.45      4   0 System                                                       
        340      17     3964      17324       0.13   3416   2 TabTip                                                       
        413      24    13016      34008       0.25   4488   2 TabTip                                                       
        103       7     1264       4756       0.00   3264   2 TabTip32                                                     
        216      22     4864      14260       0.08   1272   2 taskhostw                                                    
        446      24    17080      22096       0.39   2796   0 taskhostw                                                    
        150       9     1664       8984       0.03   1196   0 VSSVC                                                        
        946      45    62896      78976      13.22   2068   0 WaAppAgent                                                   
        119       6     1504       5800       0.02   4152   0 WaSecAgentProv                                               
        646      41    45220      68180      85.78   2088   0 WindowsAzureGuestAgent                                       
        131       9     2252       8344       0.03   3868   0 WindowsAzureNetAgent                                         
        174      11     1548       6916       0.11    552   0 wininit                                                      
        234      11     2588      11160       0.09    612   1 winlogon                                                     
        266      12     2456      10120       0.08   3428   2 winlogon                                                     
        178      10     2776       8368       0.02   4052   0 WmiPrvSE

   [stderr]
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$SubscriptionId,
        [Parameter(Mandatory=$True)]
        [String]$ResourceGroup,
        [Parameter(Mandatory=$True)]
        [String]$Server,
        [Parameter(Mandatory=$True)]
        [String]$Script,
        [ValidateSet("Windows","Linux")]
        [String]$VMType="Windows"

    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "x-ms-command-name" = "Microsoft_Azure_Automation."
        }
        
        # Define the script type
        if($VMType -eq "Windows")
        {
            $scriptType="Power"
        }

        # Create the body
        $body = @{
            "commandId" = "Run$($scriptType)ShellScript"
            "script" = @($Script)
        }

        # Invoke the command
        $response = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$Server/runCommand?api-version=2018-04-01" -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json; charset=utf-8"

        # Get the async operation url
        $async = $response.Headers["Azure-AsyncOperation"]
        Write-Verbose "Azure-AsyncOperation: $async"

        while($status = Invoke-RestMethod -Uri $async -Headers $headers)
        {
            if($status.status -eq "InProgress")
            {
                # Still pending, wait for two seconds
                Start-Sleep -Seconds 5
            }
            else
            {
                if($status.status -eq "Succeeded")
                {
                    # Script was executed successfully - but we don't the actual result
                    $value = $status.properties.output.value

                    # Loop through the output streams
                    foreach($output in $value)
                    {
                        if($output.code.Contains("StdOut"))
                        {
                            Write-Host "[stdout]"
                            Write-Host $output.message
                        }
                        elseif($output.code.Contains("StdErr"))
                        {
                            Write-Host "`n[stderr]"
                            Write-Host $output.message
                        }
                        else
                        {
                            Write-Host $output.message 
                        }
                    }

                }
                else
                {
                    Write-Error "The script failed"
                }
                
                break
            }
        }
        
    }
}



# Runs a given script on the given Azure VM
# Jun 3rd 2020
function Get-AzureVMRdpSettings
{
<#
    .SYNOPSIS
    Gets RDPSettings of the given Azure VM

    .DESCRIPTION
    Gets RDPSettings of the given Azure VM

    .Example
    Get-AADIntAzureVMRdpSettings -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup PRODUCTION -Server Server2

    Not domain joined
    HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\PortNumber: 3389
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections: 
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\KeepAliveEnable: 1
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\KeepAliveInterval: 1
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\KeepAliveTimeout: 1
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableAutoReconnect: 0
    HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\fInheritReconnectSame: 1
    HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\fReconnectSame: 0
    HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\fInheritMaxSessionTime: 1
    HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\fInheritMaxDisconnectionTime: 1
    HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\MaxDisconnectionTime: 0
    HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\MaxConnectionTime: 0
    HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\fInheritMaxIdleTime: 1
    HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\MaxIdleTime: 0
    HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\MaxInstanceCount: 4294967295

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$SubscriptionId,
        [Parameter(Mandatory=$True)]
        [String]$ResourceGroup,
        [Parameter(Mandatory=$True)]
        [String]$Server
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" =  "application/json"
            "x-ms-command-name" = "Microsoft_Azure_Automation."
        }

        # Create the body
        $body="{""commandId"":""RDPSettings""}"

        # Invoke the command
        $response = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$Server/runCommand?api-version=2018-04-01" -Headers $headers -Body $body

        # Get the async operation url
        $async = $response.Headers["Azure-AsyncOperation"]
        Write-Verbose "Azure-AsyncOperation: $async"

        while($status = Invoke-RestMethod -Uri $async -Headers $headers)
        {
            if($status.status -eq "InProgress")
            {
                # Still pending, wait for two seconds
                Start-Sleep -Seconds 5
            }
            else
            {
                if($status.status -eq "Succeeded")
                {
                    # Script was executed successfully - but we don't the actual result
                    $value = $status.properties.output.value

                    # Loop through the output streams
                    foreach($output in $value)
                    {
                        if($output.code.Contains("StdOut"))
                        {
                            Write-Host $output.message
                        }
                        elseif($output.code.Contains("StdErr") -and -not [string]::IsNullOrEmpty($output.message))
                        {
                            Write-Error $output.message
                        }
                    }

                }
                else
                {
                    Write-Error "The script failed"
                }
                
                break
            }
        }
        
    }
}

# Gets Azure Role Assignment ID for the given name
# Jun 3rd 2020
function Get-AzureRoleAssignmentId
{
<#
    .SYNOPSIS
    Gets Azure Role Assignment ID for the given role name

    .DESCRIPTION
    Gets Azure Role Assignment ID for the given role name

    .Example
    Get-AADIntAzureRoleAssignmentId -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -RoleName "Virtual Machine Contributor"

    9980e02c-c2be-4d73-94e8-173b1dc7cf3c
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$SubscriptionId,
        [Parameter(Mandatory=$True)]
        [String]$RoleName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        # Invoke the command
        $response = Invoke-RestMethod -Method Get -Uri "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions?`$filter=roleName eq '$RoleName'&api-version=2018-01-01-preview" -Headers $headers

        # Return the ID
        $response.value[0].name
        
    }
}


# Assigns a role to a given user
# Jun 3rd 2020
function Set-AzureRoleAssignment
{
<#
    .SYNOPSIS
    Assigns a role to a given user

    .DESCRIPTION
    Assigns a role to a given user

    .Example
    Set-AADIntAzureRoleAssignment -AccessToken $at -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -Role Name "Virtual Machine Contributor"

    roleDefinitionId : /subscriptions/867ae413-0ad0-49bf-b4e4-6eb2db1c12a0/providers/Microsoft.Authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c
    principalId      : 90f9ca62-2238-455b-bb15-de695d689c12
    principalType    : User
    scope            : /subscriptions/867ae413-0ad0-49bf-b4e4-6eb2db1c12a0
    createdOn        : 2020-06-03T11:29:58.1683714Z
    updatedOn        : 2020-06-03T11:29:58.1683714Z
    createdBy        : 
    updatedBy        : 90f9ca62-2238-455b-bb15-de695d689c12
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$SubscriptionId,
        [Parameter(Mandatory=$False)]
        [String]$UserName,
        [Parameter(Mandatory=$True)]
        [String]$RoleName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" =  "application/json"
        }

        # Get the role id
        $roleId=Get-AzureRoleAssignmentId -AccessToken $AccessToken -SubscriptionId $SubscriptionId -RoleName $RoleName

        # If user name is not given, use the id from the Access Token
        if([string]::IsNullOrEmpty($UserName))
        {
            $userId = (Read-AccessToken -AccessToken $AccessToken).oid
        }
        else
        {
            # TODO: get the id
            Throw "Not implemented yet. Only current user is supported."
        }

        # Create the body
        $body=@"
        {
          "properties": {
            "roleDefinitionId": "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$roleId",
            "principalId": "$userId",
            "canDelegate": false
          }
        }

"@

        # Invoke the command
        $response = Invoke-RestMethod -Method Put -Uri "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleAssignments/$(New-Guid)?api-version=2018-09-01-preview" -Headers $headers -Body $body

        # Return the results
        $response.properties
    }
}


# Lists azure tenants of the logged in user
# Jun 10th 2020
function Get-AzureTenants
{
<#
    .SYNOPSIS
    Lists all Azure AD tenants the user has access to.

    .DESCRIPTION
    Lists all Azure AD tenants the user has access to.

    .Example
    $at=Get-AADIntAccessTokenForAzureCoreManagement
    PS C:\>Get-AADIntAzureTenants -AccessToken $at

    Id                                   Country Name        Domains                                                                                                  
    --                                   ------- ----        -------                                                                                                  
    221769d7-0747-467c-a5c1-e387a232c58c FI      Firma Oy    {firma.mail.onmicrosoft.com, firma.onmicrosoft.com, firma.fi}              
    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd US      Company Ltd {company.onmicrosoft.com, company.mail.onmicrosoft.com,company.com}

    .Example
    Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

    Tenant                               User Resource                             Client                              
    ------                               ---- --------                             ------                              
    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd      https://management.core.windows.net/ d3590ed6-52b3-4102-aeff-aad2292ab01c

    PS C:\>Get-AADIntAzureTenants

    Id                                   Country Name        Domains                                                                                                  
    --                                   ------- ----        -------                                                                                                  
    221769d7-0747-467c-a5c1-e387a232c58c FI      Firma Oy    {firma.mail.onmicrosoft.com, firma.onmicrosoft.com, firma.fi}              
    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd US      Company Ltd {company.onmicrosoft.com, company.mail.onmicrosoft.com,company.com}
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Content-type" = "application/json"
        }

        $body=@"
        {
            "requests":
            [
                {
                    "httpMethod":"GET",
                    "name":"$((New-Guid).ToString())",
                    "requestHeaderDetails":
                    {
                        "commandName":"fx.Services.Tenants.getTenants"
                    },
                    "url":"/tenants?api-version=2019-03-01&`$includeAllTenantCategories=true"
                }
            ]
        }'
"@

        # Invoke the command.
        $response = Invoke-RestMethod  -Method Post -Uri "https://management.azure.com/batch?api-version=2015-11-01" -Headers $headers -Body $body

        # Return
        foreach($value in $response.responses[0].content.value)
        {
            $attributes=[ordered]@{
                "Id" =      $value.tenantId
                #"Type" =    $value.tenantCategory # All are "Home"
                "Country" = $value.countryCode
                "Name" =    $value.displayName
                "Domains" = $value.domains
            }
            New-Object psobject -Property $attributes
        }
        
    }
}


# Invokes an Azure query
# Jan 22nd 2021
function Invoke-AzureQuery
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Query,
        [Parameter(Mandatory=$True)]
        [GUID]$SubscriptionId
    )
    Process
    {
        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Content-type" = "application/json"
        }

        $body=@"
        {
            "requests": [{
                    "content": {
                        "subscriptions": ["$($SubscriptionId.toString())"],
                        "query": "$Query"
                    },
                    "httpMethod": "POST",
                    "name": "$((New-Guid).toString())",
                    "requestHeaderDetails": {
                        "commandName": "Microsoft_Azure_Security_Insights."
                    },
                    "url": "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2019-04-01"
                }
            ]
        }
"@

        # Invoke the command.
        $response = Invoke-RestMethod  -Method Post -Uri "https://management.azure.com/batch?api-version=2015-11-01" -Headers $headers -Body $body

        return $response
        
    }
}


# Show diagnostic settings
# Jan 22nd 2021
function Get-AzureDiagnosticSettingsDetails
{
<#
    .SYNOPSIS
    Gets log settings of the given Azure workspace.

    .DESCRIPTION
    Gets log settings of the given Azure workspace.

    .Parameter AccessToken
    AccessToken of the user. Must be Global Administrator or Security Administrator.

    .Parameter Name
    Name of the Sentinel workspace.

    .Example
    Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache
    PS C:\>Get-AADIntDiagnosticSettingsDetails -Name "Audit and SignIn to Sentinel"

    Log                          Enabled Retention Enabled Retention Days
    ---                          ------- ----------------- --------------
    ProvisioningLogs               False             False              0
    AuditLogs                       True              True            365
    SignInLogs                      True              True            365
    NonInteractiveUserSignInLogs   False             False              0
    ServicePrincipalSignInLogs     False             False              0
    ManagedIdentitySignInLogs       True              True            365

    .Example
    $at=Get-AADIntAccessTokenForAzureCoreManagement

    PS C:\>Get-AADIntAzureDiagnosticSettings

    Name                        : Audit and SignIn to Sentinel
    WorkspaceId                 : /subscriptions/a04293e7-46c8-4bf4-bc6d-1bc1f41afae0/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/MySentinel
    StorageAccountId            : 
    EventHubAuthorizationRuleId : 
    EventHubName                : 
    ServiceBusRuleId            : 

    Name                        : Service Principal to Sentinel
    WorkspaceId                 : /subscriptions/a04293e7-46c8-4bf4-bc6d-1bc1f41afae0/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/MySentinel
    StorageAccountId            : 
    EventHubAuthorizationRuleId : 
    EventHubName                : 
    ServiceBusRuleId            : 

    PS C:\>Get-AADIntDiagnosticSettingsDetails -Name "Audit and SignIn to Sentinel"

    Log                          Enabled Retention Enabled Retention Days
    ---                          ------- ----------------- --------------
    ProvisioningLogs               False             False              0
    AuditLogs                       True              True            365
    SignInLogs                      True              True            365
    NonInteractiveUserSignInLogs   False             False              0
    ServicePrincipalSignInLogs     False             False              0
    ManagedIdentitySignInLogs       True              True            365

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Name
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Content-type" = "application/json"
        }
        
        # Invoke the command.
        $response = Invoke-RestMethod  -Method Get -Uri "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/$Name`?api-version=2017-04-01" -Headers $headers

        
        # Return
        foreach($value in $response.properties.logs)
        {
            $attributes=[ordered]@{
                "Log" =               $value.category
                "Enabled" =           $value.enabled
                "Retention Enabled" = $value.retentionPolicy.enabled
                "Retention Days" =    $value.retentionPolicy.days
            }
            New-Object psobject -Property $attributes
        }
    }
}


# Set diagnostic settings
# Jan 22nd 2021
function Set-AzureDiagnosticSettingsDetails
{
<#
    .SYNOPSIS
    Sets log settings for the given Sentinel.

    .DESCRIPTION
    Sets log settings for the given Sentinel.

    .Parameter AccessToken
    AccessToken of the user. Must be Global Administrator or Security Administrator.

    .Parameter Name
    Name of the Sentinel workspace.

    .Parameter Logs
    List of logs to be edited, can be one or more of "SignInLogs","AuditLogs","NonInteractiveUserSignInLogs","ServicePrincipalSignInLogs","ManagedIdentitySignInLogs", or "ProvisioningLogs".
    
    .Parameter Enabled
    Is the log enabled.

    .Parameter RetentionEnabled
    Is the log retention enabled.

    .Parameter RetentionDays
    The number of retention days. Must be between 0 and 365 days.

    .Example
    Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

    PS C:\>Set-AADIntDiagnosticSettingsDetails -Name "Audit and SignIn to Sentinel" -Log ManagedIdentitySignInLogs,AuditLogs,SignInLogs -Enabled $true -RetentionEnabled $true -RetentionDays 365

    Log                          Enabled Retention Enabled Retention Days
    ---                          ------- ----------------- --------------
    ProvisioningLogs               False             False              0
    AuditLogs                       True              True            365
    SignInLogs                      True              True            365
    NonInteractiveUserSignInLogs   False             False              0
    ServicePrincipalSignInLogs     False             False              0
    ManagedIdentitySignInLogs       True              True            365

    .Example
    $at=Get-AADIntAccessTokenForAzureCoreManagement

    PS C:\>Get-AADIntAzureDiagnosticSettings

    Name                        : Audit and SignIn to Sentinel
    WorkspaceId                 : /subscriptions/a04293e7-46c8-4bf4-bc6d-1bc1f41afae0/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/MySentinel
    StorageAccountId            : 
    EventHubAuthorizationRuleId : 
    EventHubName                : 
    ServiceBusRuleId            : 

    Name                        : Service Principal to Sentinel
    WorkspaceId                 : /subscriptions/a04293e7-46c8-4bf4-bc6d-1bc1f41afae0/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/MySentinel
    StorageAccountId            : 
    EventHubAuthorizationRuleId : 
    EventHubName                : 
    ServiceBusRuleId            : 

    PS C:\>Set-AADIntDiagnosticSettingsDetails -Name "Audit and SignIn to Sentinel" -Log ManagedIdentitySignInLogs,AuditLogs,SignInLogs -Enabled $true -RetentionEnabled $true -RetentionDays 365

    Log                          Enabled Retention Enabled Retention Days
    ---                          ------- ----------------- --------------
    ProvisioningLogs               False             False              0
    AuditLogs                       True              True            365
    SignInLogs                      True              True            365
    NonInteractiveUserSignInLogs   False             False              0
    ServicePrincipalSignInLogs     False             False              0
    ManagedIdentitySignInLogs       True              True            365

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [ValidateSet("SignInLogs","AuditLogs","NonInteractiveUserSignInLogs","ServicePrincipalSignInLogs","ManagedIdentitySignInLogs","ProvisioningLogs")]
        [String[]]$Logs,
        [Parameter(Mandatory=$True)]
        [String]$Name,
        [Parameter(Mandatory=$True)]
        [bool]$Enabled,
        [Parameter(Mandatory=$True)]
        [bool]$RetentionEnabled,
        [Parameter(Mandatory=$True)]
        [int]$RetentionDays

    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Check the retention days value
        if($RetentionDays -lt 0 -or $RetentionDays -gt 365)
        {
            Write-Error "Retention days must be between 0 and 365 days"
            return
        }

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Content-type" = "application/json"
        }

        # Get the current settings and workspaceid
        $response = Invoke-RestMethod  -Method Get -Uri "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/$Name`?api-version=2017-04-01" -Headers $headers
        $workspaceId = $response.properties.workspaceId

        # Create the array for log settings objects
        $log_array = @()
        foreach($value in $response.properties.logs)
        {
            # Check if this log is to be changed
            if($logs -contains $value.category)
            {
                $log_entry = @{
                    "category" = $value.category
                    "enabled" =  $Enabled
                    "retentionPolicy" = @{
                        "days" =    $RetentionDays
                        "enabled" = $RetentionEnabled
                        }
                    }
                
            }
            else
            {
                $log_entry = @{
                    "category" = $value.category
                    "enabled" =  $value.enabled
                    "retentionPolicy" = @{
                        "days" =    $value.retentionPolicy.days
                        "enabled" = $value.retentionPolicy.enabled
                        }
                    }
            }
            $log_array += $log_entry
        }

        # Create the body
        $body = @{
            "id" =   "/providers/microsoft.aadiam/diagnosticSettings/$Name"
            "name" = $Name
            "properties" = @{
                "logs" =        $log_array
                "metrics" =     @()
                "workspaceId" = $WorkspaceId
                }
        }
        
        # Invoke the command.
        $response = Invoke-RestMethod  -Method Put -Uri "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/$Name`?api-version=2017-04-01" -Headers $headers -Body ($body | ConvertTo-Json -Depth 5)

        
        # Return
        foreach($value in $response.properties.logs)
        {
            $attributes=[ordered]@{
                "Log" =               $value.category
                "Enabled" =           $value.enabled
                "Retention Enabled" = $value.retentionPolicy.enabled
                "Retention Days" =    $value.retentionPolicy.days
            }
            New-Object psobject -Property $attributes
        }


        
    }
}

# List diagnostic settings
# Jan 22nd 2021
function Get-AzureDiagnosticSettings
{
<#
    .SYNOPSIS
    Lists all diagnostic settings.

    .DESCRIPTION
    Lists all diagnostic settings.

    .Parameter AccessToken
    AccessToken of the user. Must be Global Administrator or Security Administrator.

    .Example
    Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache
    PS C:\>Get-AADIntAzureDiagnosticSettings

    Name                        : Audit and SignIn to Sentinel
    WorkspaceId                 : /subscriptions/a04293e7-46c8-4bf4-bc6d-1bc1f41afae0/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/MySentinel
    StorageAccountId            : 
    EventHubAuthorizationRuleId : 
    EventHubName                : 
    ServiceBusRuleId            : 

    Name                        : Service Principal to Sentinel
    WorkspaceId                 : /subscriptions/a04293e7-46c8-4bf4-bc6d-1bc1f41afae0/resourcegroups/sentinel/providers/microsoft.operationalinsights/workspaces/MySentinel
    StorageAccountId            : 
    EventHubAuthorizationRuleId : 
    EventHubName                : 
    ServiceBusRuleId            : 


   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization" =     "Bearer $AccessToken"
            "Content-type" =      "application/json"
            "x-ms-command-name" = "Microsoft_Azure_Monitoring"
            "x-ms-path-query" =   "/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"
        }


        $response = Invoke-RestMethod  -Method Get -Uri "https://management.azure.com/api/invoke" -Headers $headers

        # Return
        foreach($value in $response.value)
        {
            $attributes=[ordered]@{
                "Name" =                        $value.name
                "WorkspaceId" =                 $value.properties.workspaceId
                "StorageAccountId" =            $value.properties.storageAccountId
                "EventHubAuthorizationRuleId" = $value.properties.eventHubAuthorizationRuleId
                "EventHubName" =                $value.properties.eventHubName
                "ServiceBusRuleId" =            $value.properties.serviceBusRuleId
            }
            New-Object psobject -Property $attributes
        }
        
    }
}

# Remove all diagnostic settings
# Ja 23rd 2021
function Remove-AzureDiagnosticSettings
{
<#
    .SYNOPSIS
    Removes all diagnostic settings.

    .DESCRIPTION
    Removes all diagnostic settings by disabling all logs.

    .Parameter AccessToken
    AccessToken of the user. Must be Global Administrator or Security Administrator.

    .Example
    $at=Get-AADIntAccessTokenForAzureCoreManagement
    PS C:\>Remove-AADIntDiagnosticSettings
  
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [Switch]$Force
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Get the list of diagnostic settings
        $diagSettings = Get-AzureDiagnosticSettings -AccessToken $AccessToken

        $count = $diagSettings.count

        if(!$count)
        {
            $count = 1
        }

        if(!$Force)
        {
            $answer = Read-Host -Prompt "About to delete $count diagnostic settings. Are you sure? (Y/N)"
            if($answer -ne "Y")
            {
                return
            }
        }

        foreach($settings in $diagSettings)
        {
            Write-Verbose "Removing diagnostic settings ""$($settings.name)"""
            Set-AzureDiagnosticSettingsDetails -AccessToken $AccessToken -Name $($settings.name) -Logs AuditLogs,SignInLogs,NonInteractiveUserSignInLogs,ServicePrincipalSignInLogs,ManagedIdentitySignInLogs,ProvisioningLogs -Enabled $False -RetentionEnabled $False -RetentionDays 0 | Out-Null
        }
        
    }
}