<#  
    .NOTES

===========================================================================
Created by:    Andrew Matthews
Organization:  To The Cloud and Beyond
Filename:      Get-DeviceIDs.ps1
Documentation: TBC
Execution Tested on: FunctionApp
Requires:      
Versions:
1.0 - 28 April 2022
 - First version
 - Includes core functionality to request Device IDs and computer names

===========================================================================
.SYNOPSIS

Query Graph API for a list of devices in a particular group

.DESCRIPTION
Section 1 - Script initialisation
Section 2 - Check whether the group exists
Section 3 - Get Group members
Section 4 - Response

.INPUTS
A REST API Request

.OUTPUTS
A list of Device ID's in JSON format

#>

param(
    [Parameter(Mandatory = $true)]$Request,
    $TriggerMetadata
)


################################################
# Declare Constants and other Script Variables
################################################
#Set the master function error state
$ExecutionError = $False

#Create the log cache
$LogCacheArray = New-Object System.Collections.ArrayList
#Array list standard fields
# Source
# Log GUID
# Log Date Time
# Log level
# Log Text


#Log standard text strings
$Log_FunctionApp = "GetDeviceIDs"
$Log_Type = "FunctionAppGetDeviceIDs"
$LogLevel_Error = "Error"
$LogLevel_Warning = "Warning"
$LogLevel_Information = "Information"
$script:OutputEntry = 0

#Instantiate a LOG GUID for the RUN ID
$Log_GUID = New-GUID

#Log to the console - if true will output as write-host
$Log_Console = $True
#Log to Log Analytics - if true will upload to Log Analytics at the end of the script
$Log_LogAnalytics = $True

$GraphBaseURI = "https://graph.microsoft.com"
#$GraphApiVersion = "2019-08-01"
$GraphApiVersion = "2017-09-01"
$GraphQueryVersion = "v1.0"

#The array of group members
$Devices = New-Object System.Collections.ArrayList

$TimeStampField = ""


################################################
# Declare Functions
################################################

<# Create a New log entry #>
Function New-LogEntry {
    param (
        [Parameter(Mandatory=$true)][string]$LogLevel,
        [Parameter(Mandatory=$true)][string]$LogText
    )
    #Incrementing Output Entry Number
    $script:OutputEntry = $Script:OutputEntry + 1
    #Set the log level
    switch ($LogLevel) {
        $LogLevel_Error {  
            $FormattedLogLevel = $LogLevel_Error
        }
        $LogLevel_Warning { 
            $FormattedLogLevel = $LogLevel_Warning
        }
        $LogLevel_Information { 
            $FormattedLogLevel = $LogLevel_Information
        }
        default {
            $FormattedLogLevel = $LogLevel_Information
        }
    }

    #Format the datetime
    [String]$FormattedDateTime = get-date -Format "yyyy-MM-ddTHH:mm:ss:fffZ" -date (get-date).ToUniversalTime()

    $LogCacheEntry = New-Object -TypeName PSObject -Property @{
        'Source' = $Log_FunctionApp
        'RunID' = $Log_GUID
        'LogDate' = $FormattedDateTime
        'LogLevel' = $FormattedLogLevel
        'LogText' = $LogText
        'EntryID' = $Script:OutputEntry
    }

    $LogCacheArray.Add($LogCacheEntry) | Out-Null

    If ($Log_Console -eq $True) {
        write-host "$($FormattedLogLevel): $($LogText)"
    }

}


<# Create the authorization signature for Azure Log Analytics #>
Function New-LogAnalyticsSignature {
    param (
        [Parameter(Mandatory=$true)]$WorkspaceID,
        [Parameter(Mandatory=$true)]$SharedKey,
        [Parameter(Mandatory=$true)]$SignatureDate,
        [Parameter(Mandatory=$true)]$ContentLength,
        [Parameter(Mandatory=$true)]$RESTMethod,
        [Parameter(Mandatory=$true)]$ContentType,
        [Parameter(Mandatory=$true)]$Resource
    )
    
    $xHeaders = "x-ms-date:" + $SignatureDate
    $StringToHash = $RESTMethod + "`n" + $ContentLength + "`n" + $ContentType + "`n" + $xHeaders + "`n" + $Resource
    
    $BytesToHash = [Text.Encoding]::UTF8.GetBytes($StringToHash)
    $KeyBytes = [Convert]::FromBase64String($SharedKey)

    $SHA256 = New-Object System.Security.Cryptography.HMACSHA256
    $SHA256.Key = $KeyBytes

    $CalculatedHash = $SHA256.ComputeHash($BytesToHash)
    $EncodedHash = [Convert]::ToBase64String($CalculatedHash)
    $Authorization = 'SharedKey {0}:{1}' -f $WorkspaceID,$EncodedHash
    return $Authorization
}


<# Post Log data to Log Analytics #>
Function New-LogAnalyticsData{
    param (
        [Parameter(Mandatory=$true)][String]$WorkspaceID,
        [Parameter(Mandatory=$true)][String]$SharedKey,
        [Parameter(Mandatory=$true)]$LogBody,
        [Parameter(Mandatory=$true)][String]$LogType
    )

    #Create the function response
    $FunctionResponse = New-Object -TypeName PSObject -Property @{
        'Status' = $True
        'Error' = ""
    }
    #Create the signature
    $RESTMethod = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $LogBody.Length
    $Signature = New-LogAnalyticsSignature -WorkspaceID $WorkspaceID -SharedKey $SharedKey -SignatureDate $rfc1123date -ContentLength $contentLength -RESTMethod $RESTMethod -ContentType $contentType -Resource $resource

    #Set the URI for the REST operation
    $uri = "https://" + $WorkspaceID + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    #Set the headers
    $headers = @{
        "Authorization" = $Signature;
        "Log-Type" = $LogType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }
    
    try{
        Invoke-RestMethod -Uri $uri -Method $RESTMethod -ContentType $contentType -Headers $headers -Body $LogBody -UseBasicParsing
    } catch {
        $FunctionResponse.Status = $False
        $FunctionResponse.Error = $_.Exception.Message
        Write-Host "Failed to uploaded logs to Log analytics"
        write-Host  $_.Exception.Message
    }
   
    return $FunctionResponse

}

################################################
# Main Routine
################################################

################################################
# Section 1 - Startup
################################################

# Section 1 Step 1: Retrieve Environment Variables
If($ExecutionError -eq $false) {
    New-LogEntry -LogLevel $LogLevel_Information -LogText "Section 1 Step 1: Retrieving Configuration Variables"
}
#Get the Log Analytics WorkSpace ID from the environment variables
If($ExecutionError -eq $false) {
    
    If(!(($Env:LOG_WORKSPACEID).length -eq 0)) {
        $LogAnalyticsWorkspaceID = $Env:LOG_WORKSPACEID
    } else {
        New-LogEntry -LogLevel $LogLevel_Error -LogText "The Log Analytics WorkSpace ID is not set on the app settings"
        $Log_LogAnalytics = $False
        
    }
}

#Get the Log Analytics Shared Key from the environment variables
If($ExecutionError -eq $false) {
    
    If(!(($Env:LOG_SHAREDKEY).length -eq 0)) {
        $LogAnalyticsSharedKey = $Env:LOG_SHAREDKEY
    } else {
        New-LogEntry -LogLevel $LogLevel_Error -LogText "The Log Analytics Shared Key is not set on the app settings"
        $Log_LogAnalytics = $False
        
    }

}

If($ExecutionError -eq $false) {
    If(!(($env:MSI_SECRET).length -eq 0)) {
        $ManagedServiceIdentitySecret = $env:MSI_SECRET
    } else {
        New-LogEntry -LogLevel $LogLevel_Error -LogText "The Managed Service Identity Secret is not valid"
        $ExecutionError = $True
        $ExecutionErrorText = "The Managed Service Identity Secret is not valid"
    }
}
If($ExecutionError -eq $false) {
    If(!(($env:MSI_ENDPOINT).length -eq 0)) {
        $ManagedServiceIdentityEndpoint = $env:MSI_ENDPOINT
    } else {
        New-LogEntry -LogLevel $LogLevel_Error -LogText "The Managed Service Identity Endpoint is not valid"
        $ExecutionError = $True
        $ExecutionErrorText = "The Managed Service Identity Endpoint is not valid"
    }
}


# Section 1 Step 2: Create Managed Service Identity Token
If($ExecutionError -eq $false) {
    New-LogEntry -LogLevel $LogLevel_Information -LogText "Section 1 Step 2: Obtaining Managed Service Identity"
}
#Get an Authorisation token using the Managed Service Identity
If($ExecutionError -eq $false) {
    try {
        $AuthToken = Invoke-RestMethod -Method Get -Headers @{ 'Secret' = $($ManagedServiceIdentitySecret) } -Uri "$($ManagedServiceIdentityEndpoint)?resource=$($GraphBaseURI)&api-version=$($GraphApiVersion)"
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-LogEntry -LogLevel $LogLevel_Error -LogText "Failed to retrieve Authorisation Token"
        New-LogEntry -LogLevel $LogLevel_Error -LogText $ErrorMessage
        $ExecutionError = $True
        $ExecutionErrorText = "Failed to retrieve Authorisation Token"
    }
    
}

#Create an authorisation header from the authorisation token
If($ExecutionError -eq $false) {
    
    If(!($AuthToken.Length -eq 0)) {
        $AuthHeader = @{ Authorization = "Bearer $($AuthToken.access_token)" }
    } else {
        New-LogEntry -LogLevel $LogLevel_Error -LogText "Auth Token was malformed"
        $ExecutionError = $True
        $ExecutionErrorText = "Auth Token was malformed"
    }
 
}

################################################
# Section 2 - Get the request Body values
################################################

# Section 2 Step 1: Check the request Body
If($ExecutionError -eq $false) {
    New-LogEntry -LogLevel $LogLevel_Information -LogText "Section 2 Step 1: Checking Request body"
}
#Get the values from the request body
If($ExecutionError -eq $false) {
    #Check whether the group object exists
    If(!($Request.Body.Group.Length -eq 0)) {
        $GroupName = $Request.Body.group

    } else {
        New-LogEntry -LogLevel $LogLevel_Error -LogText "The group parameter was missing from the request"
        $ExecutionError = $True
        $ExecutionErrorText = "The group parameter was missing from the request"
    }
}

# Section 2 Step 2: Add a log entry for processing a new request
If($ExecutionError -eq $false) {
    New-LogEntry -LogLevel $LogLevel_Information -LogText "New Request for Group: $($GroupName)"
}

################################################
# Section 3 - Get the Group members
################################################
If($ExecutionError -eq $false) {
    New-LogEntry -LogLevel $LogLevel_Information -LogText "Section 3 Step 1: Check the group exists"
}
# Section 3 Step 1: Check the group exists
If($ExecutionError -eq $false) {
    #Get the graph request URI
    $GroupExistsQueryURI = "$($GraphBaseURI)/$($GraphQueryVersion)/groups?`$count=true&`$filter=startswith(displayName,'$($GroupName)')"
    #Query the Graph API for the group name
    try {
        $GroupExistsQueryResult = Invoke-RestMethod –Method Get –Uri $GroupExistsQueryURI -Headers $AuthHeader
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-LogEntry -LogLevel $LogLevel_Error -LogText "Failed to Query Graph for the group name"
        New-LogEntry -LogLevel $LogLevel_Error -LogText $ErrorMessage
        $ExecutionError = $True
        $ExecutionErrorText = "Failed to retrieve Query Graph for the group name"
    }
}

If($ExecutionError -eq $false) {
    #Set the Group ID to a placeholder value
    $GroupID = "None"
    if((!($Null -eq $GroupExistsQueryResult.Value)) -and (!($GroupExistsQueryResult.Value.Length -eq 0))) {
        Foreach ($QueriedGroup in $GroupExistsQueryResult.Value) {
            if($QueriedGroup.displayName -eq $GroupName) {
                if((!($QueriedGroup.ID.length -eq 0)) -and (!($null -eq $QueriedGroup.ID))) {
                    $GroupID = $QueriedGroup.ID
                } else {
                    New-LogEntry -LogLevel $LogLevel_Error -LogText "The Group ID for Group '$($GroupName)' is invalid"
                    $ExecutionError = $True
                    $ExecutionErrorText = "Graph Query for Group '$($GroupName)' returned an invalid result"
                }
            }
        }
    } else {
        New-LogEntry -LogLevel $LogLevel_Error -LogText "The Group '$($GroupName)' does not exist"
        $ExecutionError = $True
        $ExecutionErrorText = "The Group '$($GroupName)' does not exist"
    }
}

If($ExecutionError -eq $false) {
    if($GroupID -eq "None") {
        New-LogEntry -LogLevel $LogLevel_Error -LogText "The Group '$($GroupName)' was not found in the query"
        $ExecutionError = $True
        $ExecutionErrorText = "The Group '$($GroupName)' does not exist or an error occurred in the query"
    } else {
        New-LogEntry -LogLevel $LogLevel_Information -LogText "Querying for Group ID: $($GroupID)"
    }
}
If($ExecutionError -eq $false) {
    New-LogEntry -LogLevel $LogLevel_Information -LogText "Section 3 Step 2: Query Group Membership"
}
# Section 3 Step 2: Get the Group Members
If($ExecutionError -eq $false) {
    #Get the graph request URI
    $GroupMembersQueryURI = "$($GraphBaseURI)/$($GraphQueryVersion)/groups/$($GroupID)/members"
    try{
        $GroupMembersQueryResult = Invoke-RestMethod –Method Get –Uri $GroupMembersQueryURI -Headers $AuthHeader
    } catch {
        $ErrorMessage = $_.Exception.Message
        New-LogEntry -LogLevel $LogLevel_Error -LogText "Failed to Query Graph for the group members"
        New-LogEntry -LogLevel $LogLevel_Error -LogText $ErrorMessage
        $ExecutionError = $True
        $ExecutionErrorText = "Failed to retrieve Query Graph for the group members"
    }
}

If($ExecutionError -eq $false) {
    #Process the result
    if((!($Null -eq $GroupExistsQueryResult.Value)) -and (!($GroupExistsQueryResult.Value.Length -eq 0))) {
        foreach($QueriedGroupMember in $GroupMembersQueryResult.Value){
            if($QueriedGroupMember."@odata.type" -eq "#microsoft.graph.device"){
                $NewDevice = New-Object -TypeName PSObject -Property @{
                    "ID" = $QueriedGroupMember.deviceID
                    "ComputerName" = $QueriedGroupMember.displayName
                    "Ring" = $QueriedGroupMember.enrollmentProfileName
                }
                $Devices.add($NewDevice) | Out-Null
            }
        }
    } else {
        New-LogEntry -LogLevel $LogLevel_Error -LogText "The Group membership '$($GroupName)' is empty"
        $ExecutionError = $True
        $ExecutionErrorText = "No Group members found in the Group '$($GroupName)'"
    }
}



################################################
# Section 4 - Exit
################################################
# Section 4 Step 1: Upload the logs to Azure Log Analytics
If($Log_LogAnalytics -eq $True) {
    New-LogEntry -LogLevel $LogLevel_Information -LogText "Section 4 Step 1: Uploading Data to Log Analytics"

    #Convert the log cache array to JSON
    $LogAnalyticsJSON = $LogCacheArray | Select-Object source, RunID, LogDate, EntryID, LogLevel, LogText | ConvertTo-Json
    #Upload the log data
    New-LogAnalyticsData -WorkspaceID $LogAnalyticsWorkspaceID -SharedKey $LogAnalyticsSharedKey -LogBody ([System.Text.Encoding]::UTF8.GetBytes($LogAnalyticsJSON)) -LogType $Log_Type
}
# Section 4 Step 2: Send the response

#Create the response body
If($ExecutionError -eq $false) {
    $ReturnObject = New-Object -TypeName PSObject -Property @{
        "Status" = "Success"
        "Devices" = $Devices
    }
} else {
    $ReturnObject = New-Object -TypeName PSObject -Property @{
        "Status" = "Failure"
        "Error" = $ExecutionErrorText
    }
}
$ReturnBody = $ReturnObject | ConvertTo-Json -Depth 3
# Return the response
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    Body = $ReturnBody
})



