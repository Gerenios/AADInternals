# This file contains functions for MS Partner operations.

# List partner organizations
# Sep 22nd 2021
function Get-MSPartnerOrganizations
{
<#
    .SYNOPSIS
    Lists partner organisations of the logged in user. Does not require permissions to MS Partner Center.

    .DESCRIPTION
    Lists partner organisations of the logged in user. Does not require permissions to MS Partner Center.

    .Parameter AccessToken
    The access token used to get the list of partner organisations.

    .Example
    PS C:\>Get-AADIntAccessTokenForMSPartner -SaveToCache
    PS C:\>Get-AADIntMSPartnerOrganizations 

    id             : 9a0c7346-f305-4646-b3fb-772853f6b209
    typeName       : Tenant
    legalEntityCid : bc07db21-7a22-4fc9-9f8a-5df27532f09f
    MPNID          : 8559543
    companyName    : Partner Ltd
    address        : @{country=US; city=PARTNERVILLE; state=AT; addressLine1=666 Partner Park; addressLine2=; postalCode=1234567890}
    contact        : @{firstName=Partner; lastName=Manager; email=pmanager@company.com; phoneNumber=+1 234567890}

    id             : 60a0020f-bd16-4f27-a23c-104644918834
    typeName       : PartnerGlobal
    legalEntityCid : bc07db21-7a22-4fc9-9f8a-5df27532f09f
    MPNID          : 8559542
    companyName    : Partner Ltd
    address        : @{country=US; city=PARTNERVILLE; state=AT; addressLine1=666 Partner Park; addressLine2=; postalCode=1234567890}
    contact        : @{firstName=Partner; lastName=Manager; email=pmanager@company.com; phoneNumber=+1 234567890}

    id             : 297588a4-5c2a-430e-ae1e-b16c5d944a7d
    typeName       : PartnerLocation
    name           : Partner Ltd, US, PARTNERVILLE
    legalEntityCid : bc07db21-7a22-4fc9-9f8a-5df27532f09f
    MPNID          : 8559543
    companyName    : Partner Ltd
    address        : @{country=US; city=PARTNERVILLE; state=AT; addressLine1=666 Partner Park; addressLine2=; postalCode=1234567890}
    contact        : @{firstName=Partner; lastName=Manager; email=pmanager@company.com; phoneNumber=+1 234567890}
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Invoke the API call
        #$response = Invoke-MSPartnerAPI -Method Get -AccessToken $AccessToken -Url "accountenrollments/v1/partnerorganizations"
        # /accounts doesn't require partner credentials :)
        $response = Invoke-MSPartnerAPI -Method Get -AccessToken $AccessToken -Url "accountenrollments/v1/accounts"

        if($response.items.Count -gt 0)
        {
            $accounts = $response.items

            $ids = ($accounts | Select-Object -ExpandProperty id) -join ","

            $response = Invoke-MSPartnerAPI -Method Get -AccessToken $AccessToken -Url "accountenrollments/v1/accountexternalresourcekeys?accountIds=$ids&keyType=mpnId"
            $mpnIds = $response.items | Select-Object -Property accountId,keyValue
        
            foreach($account in $accounts)
            {
                # Add MPN ID and remove unneeded properties
                $account | Add-Member -NotePropertyName "MPNID" -NotePropertyValue ($mpnIds | Where-Object accountId -eq $account.id | Select-Object -ExpandProperty keyValue)
                $account.PSObject.Properties.Remove("cid")
                $account.PSObject.Properties.Remove("attributes")
                $account.PSObject.Properties.Remove("status")
                $account.PSObject.Properties.Remove("accountType")

                # Get & add legal entity information
                $response = Invoke-MSPartnerAPI -Method Get -AccessToken $AccessToken -Url "accountenrollments/v1/legalentities/$($account.legalEntityCid)?basicInfoOnly=false"
            
                $account | Add-Member -NotePropertyName "companyName" -NotePropertyValue $response.profiles[0].companyName
                $account | Add-Member -NotePropertyName "address"     -NotePropertyValue $response.profiles[0].address
                $account | Add-Member -NotePropertyName "contact"     -NotePropertyValue $response.profiles[0].primaryContact
            }

            $accounts
        }
    }
}

# List partner publishers
# Sep 22nd 2021
function Get-MSPartnerPublishers
{
<#
    .SYNOPSIS
    Lists partner publishers of the logged in user.

    .DESCRIPTION
    Lists partner publishers of the logged in user.

    .Parameter AccessToken
    The access token used to get the list of partner publishers.

    .Example
    PS C:\>Get-AADIntAccessTokenForMSPartner -SaveToCache
    PS C:\>Get-AADIntMSPartnerPublishers 

    name          mpnId programCodes
    ----          ----- ------------
    Company Ltd 7086220 {1, 99, 223}
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        $body = "{""aadTenantId"":""$((Read-Accesstoken $AccessToken).tid)"",""isBasicAccount"":true,""program"":""Azure""}"

        # Invoke the API call
        $headers=@{
            "Authorization"             = "Bearer $AccessToken"
        }

        # Invoke the command 
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://partner.microsoft.com/en-us/dashboard/account/v3/api/accounts/search" -Headers $headers -Body $body -ContentType "application/json"

        $response
    }
}

# List available offers of the partner organisation
# Sep 22nd 2021
function Get-MSPartnerOffers
{
<#
    .SYNOPSIS
    Lists available offers of the partner organisation.

    .DESCRIPTION
    Lists available offers of the partner organisation.

    .Parameter AccessToken
    The access token used to get the list of partner offers.

    .Parameter Type
    Type of the offers to list. Can be Trial or Purchase.

    .Parameter CountryCode
    Two letter country code. Defaults to "US".

    .Parameter Locale
    Locale. Defaults to "en-US".

    .Example
    PS C:\>Get-AADIntAccessTokenForMSPartner -SaveToCache
    PS C:\>Get-AADIntMSPartnerOffers

    id                : 01824D11-5AD8-447F-8523-666B0848B381
    name              : Azure Active Directory Premium P1 Trial
    productName       : Azure Active Directory Premium P1
    unit              : Licenses
    minimumQuantity   : 25
    maximumQuantity   : 10000000
    term              : 1
    termUnitOfMeasure : Month
    learnMoreLink     : https://aka.ms/office-365/0
    programCode       : 99

    id                : 0A845364-6AA2-4046-8198-6CF6461F7F2B
    name              : Project Plan 3 Trial
    productName       : Project Plan 3
    unit              : Licenses
    minimumQuantity   : 25
    maximumQuantity   : 10000000
    term              : 1
    termUnitOfMeasure : Month
    learnMoreLink     : https://aka.ms/office-365/0
    programCode       : 99

    id                : 0F5B471A-08EF-4E69-ABB0-BB4DA43F0344
    name              : Visio Plan 2 Trial
    productName       : Visio Plan 2
    unit              : Licenses
    minimumQuantity   : 25
    maximumQuantity   : 10000000
    term              : 1
    termUnitOfMeasure : Month
    learnMoreLink     : https://aka.ms/office-365/1268
    programCode       : 99

    .Example
    PS C:\>Get-AADIntAccessTokenForMSPartner -SaveToCache
    PS C:\>Get-AADIntMSPartnerOffers | Format-Table id,name,maximumQuantity

    id                                   name                                                         maximumQuantity
    --                                   ----                                                         ---------------
    01824D11-5AD8-447F-8523-666B0848B381 Azure Active Directory Premium P1 Trial                             10000000
    0A845364-6AA2-4046-8198-6CF6461F7F2B Project Plan 3 Trial                                                10000000
    0F5B471A-08EF-4E69-ABB0-BB4DA43F0344 Visio Plan 2 Trial                                                  10000000
    101BDE18-5FFB-4D79-A47B-F5B2C62525B3 Office 365 E5 Trial                                                 10000000
    10DDC3DA-B394-42B8-BB45-37F7CBA40981 Office 365 F3 Trial                                                 10000000
    121ACBBF-05EE-4C97-98B6-31DC25879186 Exchange Online Protection Trial                                    10000000
    15C64B7B-475C-414C-A711-9C7CC0310F0E Common Area Phone Trial                                             10000000
    204A8E44-C924-4BFB-AA90-DDF42DC0E18A Project Plan 1 Trial                                                10000000
    248D15A4-0B1D-494B-96D2-C93D1D17205E Microsoft 365 F1 Trial                                              10000000
    2A3F5C07-BBB2-4786-857C-054F5DDD3486 Microsoft 365 Apps for enterprise Trial                             10000000
    32F37F52-2F8A-428F-82EA-92B56A44E1A7 Microsoft 365 F3 Trial                                              10000000
    3C9462FF-5045-4A71-A7A6-5A7EC82911CF OneDrive for Business (Plan 2) Trial                                10000000
    467EAB54-127B-42D3-B046-3844B860BEBF Microsoft 365 Business Standard Trial                                    300
    47128319-73FF-4A7B-B96F-A3E8B14728E2 Microsoft 365 Business Premium Trial                                     300
    4F188E46-77E9-4693-A2E2-65433499159B Domain Subscription 1-year Trial                                           1
    503D4D1D-0169-4E1F-AE26-DB041C54C5C4 Microsoft 365 E5 Information Protection and Governance Trial        10000000
    508CDA15-1DEB-4135-9C54-4D691A705353 Exchange Online Archiving for Exchange Server Trial                 10000000
    60265DB3-1D66-40AF-8342-A861655E218A Domain Subscription 1-year Trial                                           1
    62F0E3F1-B224-4D22-B98D-761DB2A43ACD Meeting Room Trial                                                  10000000
    757C4C34-D589-46E4-9579-120BBA5C92ED Microsoft Cloud App Security Trial                                  10000000
    7809E406-FCF6-4C06-8BFD-7C020E77046A Visio Plan 1 Trial                                                  10000000
    7B74C69A-2BFC-41C9-AAF1-23070354622D Microsoft 365 E5 Insider Risk Management Trial                      10000000
    8339CC50-D965-4AD5-BB94-749021A5EBF9 Windows Store for Business Trial                                    10000000
    8368AC6A-5797-4859-B2EC-4D32330277C9 Microsoft 365 Apps for business Trial                                    300
    A43415D3-404C-4DF3-B31B-AAD28118A778 Azure Information Protection Premium P1 Trial                       10000000
    B07A1127-DE83-4A6D-9F85-2C104BDAE8B4 Office 365 E3 Trial                                                 10000000
    BDA7A87A-FFD0-4B20-B4D9-A3B48EBD70B9 OneDrive for Business (Plan 1) Trial                                10000000
    C6CA396F-4467-4761-95F6-B6D9A5386716 Microsoft 365 E5 eDiscovery and Audit Trial                         10000000
    D59682F3-3E3B-4686-9C00-7C7C1C736085 Power BI Pro Trial                                                  10000000
    DDC284E8-D5FA-4EAE-AC29-C8A52C237B7B Project Online Essentials Trial                                     10000000
    E56A8505-FEEA-4B75-BD30-BD2959D77943 Microsoft 365 E3 Trial                                              10000000
    EBE94500-8C76-457C-8D3F-EB40CE524BC0 Microsoft Kaizala Pro Trial                                         10000000
    F6F20264-E785-4749-BD8E-884BAB076DE4 Microsoft 365 E5 Trial                                              10000000
    1760F437-30BF-42F8-950C-B111DDFA4EF8 Dynamics 365 Sales Professional Trial                               10000000
    5CC5F505-815F-4DA6-9203-74B5017F2432 Dynamics 365 Customer Service Enterprise Trial                      10000000
    70274D52-B96A-482A-ACA1-D0066E0F7FEB Dynamics 365 Sales Insights Trial                                   10000000
    B285FC76-2E9C-47D2-95C9-9EAE32578354 Dynamics 365 Customer Insights Trial                                10000000
    BD569279-37F5-4F5C-99D0-425873BB9A4B Dynamics 365 Customer Engagement Plan Trial                         10000000
    E516657E-6146-4866-8F06-2F8B7F494608 Power Virtual Agent Trial                                           10000000
    EAC27224-2BB3-42CF-9D84-0D9A0DC80898 Dynamics 365 Marketing Trial                                              10
    F97F075B-4FB7-4E6D-8168-E28A85C54EE9 Dynamics 365 Customer Service Insights Trial                        10000000
    0D5E0E30-4B24-429F-B826-33B3F021B8BD Microsoft Intune Device Trial                                       10000000
    2E481A78-9C3C-4FDF-ABBF-C7268201397A Microsoft Stream Trial                                              10000000
    33657A0F-4B2B-453B-A58E-99469D6E58A0 Power Automate per user plan Trial                                  10000000
    40BE278A-DFD1-470A-9EF7-9F2596EA7FF9 Microsoft Intune Trial                                              10000000
    83D3609A-14C1-4FC2-A18E-0F5CA7047E46 Power Apps per user plan Trial                                      10000000
    87DD2714-D452-48A0-A809-D2F58C4F68B7 Enterprise Mobility + Security E5 Trial                             10000000
    A0DB242A-96D7-4F99-BD52-05C0D5556257 Azure Advanced Threat Protection for Users Trial                    10000000
    C38088A5-CD04-440E-A46B-85873D58BB26 Power Automate per user with attended RPA plan Trial                10000000
    FAF849AB-BD30-42B2-856C-8F1EDC230CE9 Azure Active Directory Premium P2 Trial                             10000000
    87857ADF-3D82-4AD3-9861-F6E076401ADD Dynamics 365 Guides Trial                                           10000000
    CCA26D6B-360E-44AB-8376-C17F30A8ACF7 Dynamics 365 Remote Assist Trial                                    10000000
    D6B9A50A-E0F7-4366-842A-8C30B6D67CDC Dynamics 365 Remote Assist Attach Trial                             10000000 
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Trial','Purchase')]
        [String]$Type="Trial",
        [Parameter(Mandatory=$False)]
        [String]$CountryCode="US",
        [Parameter(Mandatory=$False)]
        [String]$Locale="en-US"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Invoke the API call
        $response = Invoke-MSPartnerAPI -Method Get -AccessToken $AccessToken -Url "internal/v1/quote/offers?inviteType=$Type&countryCode=$CountryCode&locale=$Locale"

        $response.items
    }
}

# Creates a new trial offer
# Sep 22nd 2021
function New-MSPartnerTrialOffer
{
<#
    .SYNOPSIS
    Creates a new trial offer.

    .DESCRIPTION
    Creates a new trial offer. Allows providing more licenses than in standard trial offers (up to 10 million).
    The working limit seems to be around 10000 licenses.

    .Parameter AccessToken
    The access token used to create an trial offer.

    .Parameter ProductIds
    Ids of products to include in the trial offer

    .Parameter CountryCode
    Two letter country code. Defaults to "US".

    .Parameter Quantity
    Quantity of licenses for the product. Defaults to 25.

    .Parameter PartnerId
    MS Partner id.

    .Parameter IncludeDelegatedAdministrationRequest
    Whether include delegated administration request

    .Example
    PS C:\>Get-AADIntAccessTokenForMSPartner -SaveToCache
    PS C:\>Get-AADIntMSPartnerOffers | Format-Table id,name,maximumQuantity

    id                                   name                                                         maximumQuantity
    --                                   ----                                                         ---------------
    01824D11-5AD8-447F-8523-666B0848B381 Azure Active Directory Premium P1 Trial                             10000000
    0A845364-6AA2-4046-8198-6CF6461F7F2B Project Plan 3 Trial                                                10000000
    0F5B471A-08EF-4E69-ABB0-BB4DA43F0344 Visio Plan 2 Trial                                                  10000000

    PS C:\>New-MSPartnerTrialOffer -PartnerId 7086220 -ProductIds 0F5B471A-08EF-4E69-ABB0-BB4DA43F0344 -Quantity 9999
    Offer saved to a file: Offer_a1041c87-aad3-4653-a93a-0b20aa3e570a.json
    https://portal.office.com/partner/partnersignup.aspx?type=Trial&id=a1041c87-aad3-4653-a93a-0b20aa3e570a&msppid=7086220
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [guid[]]$ProductIds,
        [Parameter(Mandatory=$False)]
        [String]$CountryCode="US",
        [Parameter(Mandatory=$True)]
        [int]$PartnerId,
        [Parameter(Mandatory=$False)]
        [int]$Quantity=25,
        [Parameter(Mandatory=$False)]
        [bool]$IncludeDelegatedAdministrationRequest = $false
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        $items=@()

        $line = 0
        foreach($id in $ProductIds)
        {
            $items += New-Object -TypeName psobject -Property ([ordered]@{
                    "lineItemNumber"   = $line++
                    "offerId"          = $id.ToString().ToUpper() # MUST be in upper case
                    "partnerId"        = $PartnerId
                    "includedQuantity" = $Quantity
                })
        }

        $body = @{
            "items"                                   = $items
            "countryCode"                             = $CountryCode
            "delegatedAdministrationPartnerRequested" = $IncludeDelegatedAdministrationRequest
        }

        # Invoke the API call
        try
        {
            $response = Invoke-MSPartnerAPI -Method Post -AccessToken $AccessToken -Url "internal/v1/advisorquote" -Body ($body | ConvertTo-Json)
        }
        catch
        {
            Write-Error ($_.ErrorDetails.Message | ConvertFrom-Json).description
            return
        }

        # Filename
        $fileName = "Offer_$($response.id).json"

        # Url
        $Url = "https://portal.office.com/partner/partnersignup.aspx?type=Trial&id=$($response.id)&msppid=$PartnerId"

        # Write to file
        $response | ConvertTo-Json | Set-Content $fileName

        Write-Host "Offer saved to a file: $fileName"

        return $Url
    }
}


# Creates a new delegated admin request
# Sep 22nd 2021
function New-MSPartnerDelegatedAdminRequest
{
<#
    .SYNOPSIS
    Creates a new delegated admin request.

    .DESCRIPTION
    Creates a new delegated admin request.

    .Parameter TenantId
    TenantId of the partner organisation.

    .Parameter Domain
    Any registered domain of the partner organisation.

    .Example
    PS C:\>New-AADIntMSPartnerDelegatedAdminRequest -Domain company.com
    
    https://admin.microsoft.com/Adminportal/Home?invType=Administration&partnerId=c7e52a77-e461-4f2e-a652-573305414be9#/BillingAccounts/partner-invitation

    .Example
    PS C:\>New-AADIntMSPartnerDelegatedAdminRequest -TenantId c7e52a77-e461-4f2e-a652-573305414be9
    
    https://admin.microsoft.com/Adminportal/Home?invType=Administration&partnerId=c7e52a77-e461-4f2e-a652-573305414be9#/BillingAccounts/partner-invitation
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='TenantId',Mandatory=$True)]
        [guid]$TenantId,
        [Parameter(ParameterSetName='Domain',Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        if($Domain)
        {
            $TenantId = Get-TenantID -Domain $Domain
        }

        return "https://admin.microsoft.com/Adminportal/Home?invType=Administration&partnerId=$TenantId#/BillingAccounts/partner-invitation"
    }
}

# Get partner roles
# Dec 13th 2021
function Get-MSPartnerRoles
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Invoke the API call
        $response = Invoke-MSPartnerAPI -Method Get -AccessToken $AccessToken -Url "v1/roles"

        if($response.items.Count -gt 0)
        {
            $retVal = @()
            $roles = $response.items
            foreach($role in $roles)
            {
                # Just get the partner roles
                if($role.category -ne "tenant")
                {
                    $retVal += New-Object psobject -Property ([ordered]@{"Id" = $role.id; "Name" = $role.name})
                }
            }

            $retVal
        }
    }
}

# Get partner role member
# Dec 13th 2021
function Get-MSPartnerRoleMembers
{
<#
    .SYNOPSIS
    Lists MS Partner roles and their members

    .DESCRIPTION
    Lists MS Partner roles and their members

    .Parameter AccessToken
    The access token used to get the list of partner organisations.

    .Example
    PS C:\>Get-AADIntAccessTokenForMSPartner -SaveToCache
    PS C:\>Get-AADIntMSPartnerRoleMembers 

    Id                                   Name                            Members                                          
    --                                   ----                            -------                                          
    0e7f236d-a3d8-458a-bd49-eaf200d12cd5 Admin Agent                     {@{displayName=Admin; userPrincipalNa...
    082cc3a5-2eff-4274-8fe1-ad5b4387ef55 Helpdesk Agent                  {@{displayName=User; userPrincipalN...                                                 
    6b07cbb3-16e4-453a-82f4-7a4310c21bc9 MPN Partner Administrator       @{displayName=User 1; userPrincipalN...
    e760e836-1c2d-47d2-9dee-92131ce57878 Report Viewer                                                                    
    9ac2b88b-6fad-416c-b849-433f8090de68 Executive Report Viewer         @{displayName=User 2; userPrincipalN...
    B53FEC78-7449-4A46-A071-C8BEF4A45134 Account Admin                                                                    
    8d3c7e52-447f-4cfd-9b50-1e4dd00495b7 Cosell Solution Admin                                                            
    0a28a37c-ec3a-462a-a87b-c409abbdba68 Incentive Administrator                                                          
    f712b351-0d8f-4051-a374-0abab5a49b5b Incentive User                                                                   
    140c97a7-ab21-4c2f-8f3b-9086898de0d5 Incentive Readonly User                                                          
    3d8005f3-1d34-4191-9969-b6da64b83777 Marketing Content Administrator                                                  
    4b38bcd9-a505-445b-af32-06c05aaeddd7 Referrals Administrator                                                          
    2d9bb971-5414-4bc7-a826-079da1fa0c93 Referrals User   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Get the roles
        $roles = Get-MSPartnerRoles -AccessToken $AccessToken

        # Get the members
        foreach($role in $roles)
        {
            # Invoke the API call
            $response = Invoke-MSPartnerAPI -Method Get -AccessToken $AccessToken -Url "v1/roles/$($role.id)/usermembers"
            
            if($response.items.Count -gt 0)
            {
                $members = $response.items | select displayName,userPrincipalName
                $role | Add-Member -NotePropertyName "Members" -NotePropertyValue $members
            }
        }

        $roles
    }
}

# Finds MS Partners
# Dec 14th 2021
function Find-MSPartners
{
<#
    .SYNOPSIS
    Finds MS Partners using the given criteria.

    .DESCRIPTION
    Finds MS Partners using the given criteria.

    .Parameter MaxResults
    Maximum number of partners to return. Defaults to 100.

    .Parameter Country
    Two letter country code

    .Example
    PS C:\>Find-AADIntMSPartners -Country FI -MaxResults 20 | Sort-Object CompanyName
    
    TenantId                             CompanyName                          Country Address                             
    --------                             -----------                          ------- -------                             
    6f28e5b8-67fe-4207-a048-cc17b8e13499 Addend Analytics LLP                 FI      @{country=FI; region=Europe; city...
    12f4ed76-f694-4b1e-9b57-c3849eea3f6c CANORAMA OY AB                       FI      @{country=FI; region=Europe; city...
    bff3224c-767a-4628-8c53-23a4df13a03c CloudNow IT Oy                       FI      @{country=FI; region=Europe; city...
    719dc930-9d0e-4ea4-b53e-a2c65a625979 Cloudriven Oy                        FI      @{country=FI; region=Europe; city...
    6f1ff46b-bd45-422f-ad28-485c03cd59fc Cubiq Analytics Oy                   FI      @{country=FI; region=Europe; city...
    6fce4bb8-3501-41c9-afcc-db0fb51c7e3d Digia                                FI      @{country=FI; region=Europe; city...
    87fc9aba-de47-425e-b0ac-712471cbb34f Fujitsu Limited                      FI      @{country=FI; region=Europe; city...
    a951d4b8-d93b-4425-a116-6a0b4efbb964 Futurice Oy                          FI      @{country=FI; region=Europe; city...
    4b4e036d-f94b-4209-8f07-6860b3641366 Gofore Oyj                           FI      @{country=FI; region=Europe; city...
    4eee4718-7215-41bf-b130-25ce43c85b33 Henson Group                         FI      @{country=FI; region=Europe; city...
    b6602c2f-7bd6-49d3-a2aa-f0b0359a73ef Henson Group Service Ireland Limited FI      @{country=FI; region=Europe; city...
    7c0c36f5-af83-4c24-8844-9962e0163719 Hexaware Technologies                FI      @{country=FI; region=Europe; city...
    99ebba89-0dd9-4b7b-8f23-95339d2a81e1 IBM                                  FI      @{country=FI; region=Europe; city...
    1c8672ad-d9cc-4f59-b839-90be132d96ab IFI Techsolutions Pvt Ltd            FI      @{country=FI; region=Europe; city...
    1e3ee4c0-94a9-45a4-9151-07e1858e6372 InlineMarket Oy                      FI      @{country=FI; region=Europe; city...
    431fbbea-8544-49f8-9891-e8a4e4756e83 Medha Hosting (OPC) Ltd              FI      @{country=FI; region=Europe; city...
    04207efa-4522-4391-a621-5708a40b634d MPY Yrityspalvelut Oyj               FI      @{country=FI; region=Europe; city...
    8c467c92-8e59-426e-a612-e23d69cb4437 Myriad Technologies                  FI      @{country=FI; region=Europe; city...
    50950a2d-dde4-4887-978d-630468d7f741 Solteq Plc                           FI      @{country=FI; region=Europe; city...
    eab8b88b-cf1a-441a-9ad9-6a8d94dcccbb Solu Digital Oy                      FI      @{country=FI; region=Europe; city...
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [int]$MaxResults=100,
        [Parameter(Mandatory=$False)]
        [string]$Country,
        [Parameter(Mandatory=$False)]
        [ValidateSet("Consulting","Custom solution","Deployment or Migration","Hardware","IP Services(ISV)","Integration","Learning and Certification","Licensing","Managed Services (MSP)","Project management")]
        [string[]]$Services
    )
    Process
    {
        if($Domain)
        {
            $TenantId = Get-TenantID -Domain $Domain
        }
        if($services)
        {
            $servicesParameter = ";services=$([System.Web.HttpUtility]::UrlEncode(($services -join ",")))"
        }

        $totalresults = 0
        $offSet       = 0
        $pageSize     = 20
        
        $first=$true

        # For book keeping, returns many duplicates :(
        $foundTenants = @()

        while($totalResults -lt $MaxResults)
        {
            $url = "https://main.prod.marketplacepartnerdirectory.azure.com/api/partners?filter=pageSize=$pageSize;pageOffset=$offSet;country=$Country;onlyThisCountry=true$servicesParameter"

            # Invoke the API call
            $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri $url

            # Print out the estimated number of results
            if($first)
            {
                Write-Host "Estimated total matches: $($response.estimatedTotalMatchingPartners)"
                $first = $false
            }

            # Adjust the max results as needed
            $MaxResults = [math]::Min($MaxResults,$response.estimatedTotalMatchingPartners)
            

            $items = $response.matchingPartners.items

            # Loop through the items
            foreach($item in $items)
            {
                if($foundTenants -notcontains $item.partnerId)
                {
                    $totalResults++

                    $foundTenants += $item.partnerId
                    $attributes = [ordered]@{
                        "TenantId"    = $item.partnerId
                        "CompanyName" = $item.name
                        "Country"     = $item.location.address.country
                        "Address"     = $item.location.address
                    }
                    New-Object psobject -Property $attributes
                }
            }

            # Continue as needed
            if($items.count -eq $pageSize)
            {
                # More items
                $offSet += $pageSize
            }
            else
            {
                # Got all
                break
            }
        }

    }
}
