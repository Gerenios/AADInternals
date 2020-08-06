# This script contains utility functions for provisioning API at https://provisioning.microsoftonline.com
# Office 365 / Azure AD v1, a.k.a. MSOnline module uses this API

# Azure AD Roles
$AADRoles=@{
"Helpdesk Administrator"=                  "729827e3-9c14-49f7-bb1b-9608f156bbb8"
"Service Support Administrator"=           "f023fd81-a637-4b56-95fd-791ac0226033"
"Billing Administrator"=                   "b0f54661-2d74-4c50-afa3-1ec803f12efe"
"Partner Tier1 Support"=                   "4ba39ca4-527c-499a-b93d-d9b492c50246"
"Partner Tier2 Support"=                   "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"
"Directory Readers"=                       "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
"Exchange Service Administrator"=          "29232cdf-9323-42fd-ade2-1d097af3e4de"
"Lync Service Administrator"=              "75941009-915a-4869-abe7-691bff18279e"
"User Account Administrator"=              "fe930be7-5e62-47db-91af-98c3a49a38b1"
"Directory Writers"=                       "9360feb5-f418-4baa-8175-e2a00bac4301"
"Company Administrator"=                   "62e90394-69f5-4237-9190-012177145e10"
"SharePoint Service Administrator"=        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
"Device Users"=                            "d405c6df-0af8-4e3b-95e4-4d06e542189e"
"Device Administrators"=                   "9f06204d-73c1-4d4c-880a-6edb90606fd8"
"Device Join"=                             "9c094953-4995-41c8-84c8-3ebb9b32c93f"
"Workplace Device Join"=                   "c34f683f-4d5a-4403-affd-6615e00e3a7f"
"Compliance Administrator"=                "17315797-102d-40b4-93e0-432062caca18"
"Directory Synchronization Accounts"=      "d29b2b05-8046-44ba-8758-1e26182fcf32"
"Device Managers"=                         "2b499bcd-da44-4968-8aec-78e1674fa64d"
"Application Administrator"=               "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
"Application Developer"=                   "cf1c38e5-3621-4004-a7cb-879624dced7c"
"Security Reader"=                         "5d6b6bb7-de71-4623-b4af-96380a352509"
"Security Administrator"=                  "194ae4cb-b126-40b2-bd5b-6091b380977d"
"Privileged Role Administrator"=           "e8611ab8-c189-46e8-94e1-60213ab1f814"
"Intune Service Administrator"=            "3a2c62db-5318-420d-8d74-23affee5d9d5"
"Cloud Application Administrator"=         "158c047a-c907-4556-b7ef-446551a6b5f7"
"Customer LockBox Access Approver"=        "5c4f9dcd-47dc-4cf7-8c9a-9e4207cbfc91"
"CRM Service Administrator"=               "44367163-eba1-44c3-98af-f5787879f96a"
"Power BI Service Administrator"=          "a9ea8996-122f-4c74-9520-8edcd192826c"
"Guest Inviter"=                           "95e79109-95c0-4d8e-aee3-d01accf2d47b"
"Conditional Access Administrator"=        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
"Reports Reader"=                          "4a5d8f65-41da-4de4-8968-e035b65339cf"
"Message Center Reader"=                   "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b"
"Information Protection Administrator"=    "7495fdc4-34c4-4d15-a289-98788ce399fd"
"License Administrator"=                   "4d6ac14f-3453-41d0-bef9-a3e0c569773a"
"Cloud Device Administrator"=              "7698a772-787b-4ac8-901f-60d6b08affd2"
"Teams Communications Administrator"=      "baf37b3a-610e-45da-9e62-d9d1e5e8914b"
"Teams Communications Support Engineer"=   "f70938a0-fc10-4177-9e90-2178f8765737"
"Teams Communications Support Specialist"= "fcf91098-03e3-41a9-b5ba-6f0ec8188a12"
"Teams Service Administrator"=             "69091246-20e8-4a56-aa4d-066075b2a7a8"
"Guest User"=                              "10dae51f-b6af-4016-8d66-8c2a99b929b3"
}

# Boolean to string
function b2s
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$Bool
    )
    Process
    {
        $Bool.ToString().ToLower()
    }
}

# Create SOAP envelope
function Create-Envelope
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,

        [Parameter(Mandatory=$True)]
        [String]$Command,

        [Parameter(Mandatory=$True)]
        [String]$RequestElements
    )
    Process
    {
        # Create the envelope
        $message_id=(New-Guid).ToString()
        $envelope=@"
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	        <s:Header>
		        <a:Action s:mustUnderstand="1">http://provisioning.microsoftonline.com/IProvisioningWebService/$Command</a:Action>
		        <a:MessageID>urn:uuid:$message_id</a:MessageID>
		        <a:ReplyTo>
			        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		        </a:ReplyTo>
		        <UserIdentityHeader xmlns="http://provisioning.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
			        <BearerToken xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">Bearer $AccessToken</BearerToken>
			        <LiveToken i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService"/>
		        </UserIdentityHeader>
		        <ClientVersionHeader xmlns="http://provisioning.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
			        <ClientId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">50afce61-c917-435b-8c6d-60aa5a8b8aa7</ClientId>
			        <Version xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">1.2.183.17</Version>
		        </ClientVersionHeader>
		        <ContractVersionHeader xmlns="http://becwebservice.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
			        <BecVersion xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">Version47</BecVersion>
		        </ContractVersionHeader>
		        <a:To s:mustUnderstand="1">https://provisioningapi.microsoftonline.com/provisioningwebservice.svc</a:To>
	        </s:Header>
	        <s:Body>
                <$Command xmlns="http://provisioning.microsoftonline.com/">
			        <request xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
                        <b:BecVersion>Version16</b:BecVersion>
		                <b:TenantId i:nil="true"/>
		                $RequestElements
                    </request>
                </$Command>
	        </s:Body>
        </s:Envelope>
"@
        # Debug
        Write-Debug "ENVELOPE ($Command): $envelope"

        # Return
        return $envelope

    }
}

# Calls the provisioning SOAP API
function Call-ProvisioningAPI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Envelope
    )
    Process
    {
        # Call the API
        Invoke-RestMethod -Uri "https://provisioningapi.microsoftonline.com/provisioningwebservice.svc" -ContentType "application/soap+xml" -Method POST -Body $envelope
    }
}


# Parses the response object(s) from SOAP message
function Parse-SOAPResponse
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $Response
    )
    Process
    {
        # Check if empty
        if(![string]::IsNullOrEmpty($Response))
        {
            # All good, try to parse the response object
            $results=(Select-Xml -Xml $response -XPath "//*[local-name()='$($Command+"Result")']").Node 

            # Check if we got response
            if([string]::IsNullOrEmpty($results))
            {
                # Got error
                throw $Response.Envelope.Body.Fault.Reason.Text.'#text'
            }

            # Sometimes response message is empty
            if($results.ReturnValue -ne $null)
            {
                (Remove-XMLNameSpace $results.ReturnValue).ReturnValue
            }
            else
            {
                return ""
            }
        }
        else
        {
            # Empty, so throw an exception
            throw "Null or empty Response"
        }
    }
}

# Remove namespace from xml doc
function Remove-XMLNameSpace
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $xmlDoc
    )
    Process
    {
        $xml=[System.Xml.Linq.XDocument]::Parse($xmlDoc.OuterXml)

        $remove=@()
        foreach ($XE in $xml.Descendants())
        {
            if($XE.Name.LocalName.Length -eq 1)
            {
                # Remove "c" etc. tags
                $remove+=$XE
            }
            else
            {
                # Strip the namespace and attributes
                $XE.Name = $XE.Name.LocalName
                $XE.RemoveAttributes()
            }
            
        }

        foreach($XE in $remove)
        {
            $XE.Remove()
        }

        return [xml]$xml.ToString()
    }
}

# Parses the given ServiceInformation object from Get-CompanyInformation and returns as hashtable
# Aug 11th 2018
function Parse-ServiceInformation
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Xml.XmlElement]$ServiceInformation
    )
    Process
    {
        # Set the return hastable
        $retVal=@{}

        # Loop through service information elements. There might be even more than these here.

        foreach($service in $ServiceInformation.ServiceInformation)
        {
            $settings=$null
            $instance = $service.ServiceInstance
            $instance_name=$instance.Split("/")[0]

            if($instance_name -ceq "sharepoint")
            {
                $settings=$service.ServiceElements.XElement.XElement.ServiceExtension.ServiceParameters.ServiceParameter
            }
            elseif($instance_name -ceq "SharePoint")
            {
                $settings=$service.ServiceElements.XElement.ServiceExtension.ServiceParameters.ServiceParameter
                #$service.ServiceElements.XElement.ServiceExtension.DNSRecords.DNSRecord
            }
            elseif($instance_name -eq "RMSOnline")
            {
                $settings=$service.ServiceElements.XElement.RmsCompanyServiceInfo.ServiceLocations.ServiceLocation
            }
            elseif($instance_name -eq "SCO")
            {
                $settings=$service.ServiceElements.XElement.WindowsIntuneServiceInfo.ServiceParameters.ServiceParameter
                $name = $service.ServiceElements.XElement.WindowsIntuneServiceInfo.ServiceParameters.ServiceParameter.Name
                $value = $service.ServiceElements.XElement.WindowsIntuneServiceInfo.ServiceParameters.ServiceParameter.Value
                if($name -ne $null)
                {
                    $settings=@{$name = $value}
                }
            }
            elseif($instance_name -ieq "YammerEnterprise")
            {
                $settings=$service.ServiceElements.XElement.ServiceExtension.ServiceParameters.ServiceParameter
            }
            elseif($instance_name -ieq "ProjectWorkManagement")
            {
                $settings=$service.ServiceElements.XElement.Topology
            }
            elseif($instance_name -ieq "Netbreeze")
            {
                $settings=$service.ServiceElements.XElement.ServiceExtension.ServiceParameters.ServiceParameter
            }
            elseif($instance_name -ieq "DynamicsMarketing")
            {
                $settings=$service.ServiceElements.XElement.ServiceExtension.ServiceParameters.ServiceParameter
            }
            elseif($instance_name -ieq "CRM")
            {
                $settings=$service.ServiceElements.XElement.ServiceExtension.ServiceParameters.ServiceParameter
            }
            $retVal[$instance]=$settings
            
    
        }

        $retval
    }
}


# Get Sku and service name from SKU array
# Aug 12th 2018
function Get-SkuAndServiceName
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [psobject[]]$SKUs,
        [Parameter(Mandatory=$True)]
        [string]$ServicePlanId
    )
    Process
    {
        $attributes=@{}
        foreach($sku in $SKUs)
        {
            $attributes["SkuName"]=$sku.SkuPartNumber
            foreach($service in $sku.ServiceStatus)
            {
                if($service.ServicePlanId -eq $ServicePlanId)
                {
                    $attributes["ServiceName"]=$service.ServiceName
                    $attributes["ServiceType"]=$service.ServiceType
                    $attributes["ProvisioningStatus"]=$service.ProvisioningStatus

                    return New-Object psobject -Property $attributes
                }
            }
        }
        # No matching SKU found so return $null
        $null
    }
}


# Creates a <namespace:parameter> -element
function Add-Element
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$NameSpace,
        [Parameter(Mandatory=$True)]
        [String]$Parameter,
        [Parameter(Mandatory=$False)]
        $Value
    )
    Process
    {

        if(![string]::IsNullOrEmpty($NameSpace))
        {
            $Parameter="$NameSpace`:$Parameter"
        }
        if([string]::IsNullOrEmpty($Value))
        {
            $element="<$Parameter i:nil=`"true`"/>"
            
        }
        else
        {
            if($Value -is [Boolean])
            {
                $Value=b2s -Bool $Value
            }
            $element="<$Parameter>$Value</$Parameter>"
        }

        $element
    }
}

# Creates a <b:parameter> -element
function Add-BElement
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Parameter,
        [Parameter(Mandatory=$False)]
        $Value
    )
    Process
    {
        Add-Element -NameSpace "b" -Parameter $Parameter -Value $Value
    }
}

# Creates a <c:parameter> -element
function Add-CElement
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Parameter,
        [Parameter(Mandatory=$False)]
        $Value
    )
    Process
    {
        Add-Element -NameSpace "c" -Parameter $Parameter -Value $Value
    }
}

# Creates a <d:parameter> -element
function Add-DElement
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Parameter,
        [Parameter(Mandatory=$False)]
        $Value
    )
    Process
    {
        Add-Element -NameSpace "d" -Parameter $Parameter -Value $Value
    }
}

# Converts xml to PSObject
function ConvertXmlTo-PSObject
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Xml.XmlLinkedNode]$xml
    )
    Begin
    {
        $XMLProperties=@(
            "InnerText"
            "InnerXml"
            "OuterXml"
            "BaseURI"
            "Prefix"
            "NamespaceURI"
            "Name"
            "LocalName"
            "Value"
            "IsEmpty"
            "HasAttributes"
            "HasChildNodes"
            "IsReadOnly"
            "ChildNodes"
        )
    }
    Process
    {
        $attributes=[ordered]@{}

        foreach($property in $xml.PSObject.Properties)
        {
            if(!$XMLProperties.Contains($property.Name))
            {
                switch($property.TypeNameOfValue)
                {
                    "System.String"
                    {
                        $attributes[$property.Name] = $property.Value
                        break
                    }
                    "System.Boolean"
                    {
                        $attributes[$property.Name] = $property.Value
                        break
                    }
                    "System.Object[]"
                    {
                        $values=@()
                        foreach($value in $property.Value)
                        {
                            $values += $value
                        }
                        $attributes[$property.Name] = $values
                        break
                    }
                    "System.Xml.XmlElement" 
                    {
                        $values = ConvertXmlTo-PSObject -xml $property.Value
                        $attributes[$property.Name] = $values.PSObject.Properties.Value
                        break
                    }
                    "System.Xml.XmlNodeList" 
                    {
                        $attributes[$property.Name] = $property.Value
                        break
                    }
                    
                }
            }
        }

        return New-Object psobject -Property $attributes
    }
}
