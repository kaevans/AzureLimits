#Go to the Agents Management tab in the Log Analytics workspace to retrieve workspace ID and key
#This is the value that would be configured on an individual agent for a VM
$CustomerId = ""  # Log Analytics workspace ID
$SharedKey = "" # Log Analytics shared access key 

$LogType = "AzureLimits" # Name of table to create and use to store limits, it will be converted to AzureLimits_CL


if ([string]::IsNullOrEmpty($(Get-AzContext).Account)) 
{
   $cred = Get-Credential
    Connect-AzAccount -Credential $cred -Subscription $subscription
}

# Null out some values for later use
$limits = @()
$json = ""

#Get all the Azure subscriptions the user has permission to access
$subscriptions = Get-AzSubscription | select subscriptionId

foreach($subscription in $subscriptions)
{
    Set-AzContext -SubscriptionId $subscription

    $resourceGroups = Get-AzResourceGroup

    $rgLocations = $resourceGroups.Location | Sort-Object | Get-Unique # Gets unique locations of deployed resource groups

    $locations = Get-AzLocation # Gets all Azure region locations

    # use $locations.Location for all azure regions or use $rgLocations for only location where resource groups are deployed
    foreach($location in $rgLocations)
    {
        $usage = Get-AzVMUsage -Location $location -ErrorAction SilentlyContinue
        foreach($item in $usage)
        {
            $limit = New-Object -TypeName psobject
            $limit | Add-Member -MemberType NoteProperty -Name Subscription -Value $subscription
            $limit | Add-Member -MemberType NoteProperty -Name ResourceType -Value "Compute"
            $limit | Add-Member -MemberType NoteProperty -Name Location -Value $location
            $limit | Add-Member -MemberType NoteProperty -Name CurrentValue -Value $item.CurrentValue
            $limit | Add-Member -MemberType NoteProperty -Name Limit -Value $item.Limit
            $limit | Add-Member -MemberType NoteProperty -Name Name -Value $item.Name.LocalizedValue
            $limit | Add-Member -MemberType NoteProperty -Name Unit -Value $item.Unit
            try{
            $percent = ($item.CurrentValue/$item.Limit)*100
            $limit | Add-Member -MemberType NoteProperty -Name PercentUsed -Value $percent
            } catch {
            $limit | Add-Member -MemberType NoteProperty -Name PercentUsed -Value 0
            }
            $limits += $limit
        }
        $usage = Get-AzStorageUsage -Location $location -ErrorAction SilentlyContinue
        foreach($item in $usage)
        {
            $limit = New-Object -TypeName psobject
            $limit | Add-Member -MemberType NoteProperty -Name Subscription -Value $subscription
            $limit | Add-Member -MemberType NoteProperty -Name ResourceType -Value "Storage"
            $limit | Add-Member -MemberType NoteProperty -Name Location -Value $location
            $limit | Add-Member -MemberType NoteProperty -Name Limit -Value $item.Limit
            $limit | Add-Member -MemberType NoteProperty -Name CurrentValue -Value $item.CurrentValue
            $limit | Add-Member -MemberType NoteProperty -Name Name -Value $item.LocalizedName
            $limit | Add-Member -MemberType NoteProperty -Name Unit -Value $item.Unit
            try{
            $percent = ($item.CurrentValue/$item.Limit)*100
            $limit | Add-Member -MemberType NoteProperty -Name PercentUsed -Value $percent
            } catch {
            $limit | Add-Member -MemberType NoteProperty -Name PercentUsed -Value 0
            }
            $limits += $limit
        }
        $usage = Get-AzNetworkUsage -Location $location -ErrorAction SilentlyContinue
        foreach($item in $usage)
        {
            $limit = New-Object -TypeName psobject
            $limit | Add-Member -MemberType NoteProperty -Name Subscription -Value $subscription
            $limit | Add-Member -MemberType NoteProperty -Name ResourceType -Value "Network"
            $limit | Add-Member -MemberType NoteProperty -Name Location -Value $location
            $limit | Add-Member -MemberType NoteProperty -Name Limit -Value $item.Limit
            $limit | Add-Member -MemberType NoteProperty -Name CurrentValue -Value $item.CurrentValue
            $limit | Add-Member -MemberType NoteProperty -Name Name -Value $item.ResourceType
            try{
            $percent = ($item.CurrentValue/$item.Limit)*100
            $limit | Add-Member -MemberType NoteProperty -Name PercentUsed -Value $percent
            } catch {
            $limit | Add-Member -MemberType NoteProperty -Name PercentUsed -Value 0
            }
            $limits += $limit
        }
    }
}
$json = $limits | ConvertTo-Json

Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }
    
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

# ToDo: Enable processing of data in chunks if larger then 30MB
if($json.Length/1MB -lt 30)
{
    $TimeStampField = (get-date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffffffZ") # Todo: Set to time data gathered if different from time sent and then add to request, currently not used
    Post-LogAnalyticsData -customerId $CustomerId -sharedKey $SharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $LogType  
}
