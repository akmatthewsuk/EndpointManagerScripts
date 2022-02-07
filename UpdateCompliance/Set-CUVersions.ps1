<#
===========================================================================
Created by:    Andrew Matthews
Organization:  To The Cloud and Beyond
Filename:      Set-CUVersions.ps1
Documentation: TBC
Execution Tested on: Windows 10
Requires:      Access to a Log Analytics Workspace
Purpose: Uploads Cumulative Update Metadata to log analytics
Versions:
1.0 - 20 Jan 2022
===========================================================================

    .SYNOPSIS
    Uploads Cumulative Update Metadata to log analytics 

    .DESCRIPTION
    Reads a JSON file with Cumulative Update Metadata and uploads the metadata to log analytics 

    .PARAMETER VersionFile
    Specified the path to the metadata file

    .EXAMPLE
    C:\PS>Set-CUVersions.ps1 -VersionFile CU.json
    
#>
param (
    [Parameter(Mandatory=$true,HelpMessage="cumulative Update Version File")]
    [string]$VersionFile
)

$LogAnalyticsWorkspaceID = "" #Insert the Log Analytics workspace ID here
$LogAnalyticsSharedKey = "" #Insert the Log Analytics workspace shared key here

$Log_Type = "WU_CU_Metadata"
$TimeStampField = ""

#Set the global execution error value
$ExecutionError = $False

################################################
#Declare Functions
################################################

<# Create the authorization signature for Azure Log Analytics #>
Function New-LogAnalyticsSignature {
    param (
        [Parameter(Mandatory=$true)]
        $WorkspaceID,
        [Parameter(Mandatory=$true)]
        $SharedKey,
        [Parameter(Mandatory=$true)]
        $SignatureDate,
        [Parameter(Mandatory=$true)]
        $ContentLength,
        [Parameter(Mandatory=$true)]
        $RESTMethod,
        [Parameter(Mandatory=$true)]
        $ContentType,
        [Parameter(Mandatory=$true)]
        $Resource
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
        [Parameter(Mandatory=$true)]
        [String]$WorkspaceID,
        [Parameter(Mandatory=$true)]
        [String]$SharedKey,
        [Parameter(Mandatory=$true)]
        $LogBody,
        [Parameter(Mandatory=$true)]
        [String]$LogType
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
        $ErrorMessage = $_.Exception.Message
        $FunctionResponse.Status = $False
        $FunctionResponse.Error = $ErrorMessage
        Write-Error "Failed to uploaded logs to Log analytics - $($ErrorMessage)"
    }
   
    return $FunctionResponse

}


##############################################################################
# Step 1: Get the License Types Configuration
##############################################################################
if($ExecutionError -eq $false) {
    #Confirm that the JSON file Exists 
    If(test-path -Path $VersionFile -PathType leaf) {
        Write-host "Reading version configuration from $($VersionFile)" -ForegroundColor Yellow
    } else {
        Write-Host "The JSON File specified ($($VersionFile)) does not exist" -ForegroundColor Red
        $ExecutionError = $True
    }

}
if($ExecutionError -eq $false) {
    #Import the JSON file with the license types
    Try{
    $VersionData = (Get-Content -Path $VersionFile | ConvertFrom-Json).CU
    } catch {
        Write-Host "Failed to import the JSON File" -ForegroundColor Red
        $ExecutionError = $True
    }
}
if($ExecutionError -eq $false) {
    If($VersionData.Count -eq 0) {
        Write-Host "No Windows Versions were imported" -ForegroundColor Red
        $ExecutionError = $True
    } Else {
        Write-Host "Imported $($VersionData.Count) Windows Versions from the Configuration"
    }
}

##############################################################################
# Step 2: Upload the version data
##############################################################################
if ($ExecutionError -eq $false) {
    Write-Host "Uploading version Date to Log Analytics" -ForegroundColor Yellow
    #Convert the log cache array to JSON
    $LogAnalyticsJSON = $VersionData | Select-object Version, Build, NValue, FeatureUpdate, Description | ConvertTo-Json
    #Upload the log data
    $UploadLogAnalyticsData = New-LogAnalyticsData -WorkspaceID $LogAnalyticsWorkspaceID -SharedKey $LogAnalyticsSharedKey -LogBody ([System.Text.Encoding]::UTF8.GetBytes($LogAnalyticsJSON)) -LogType $Log_Type
    if($UploadLogAnalyticsData.Status -eq $false) {
        Write-Output "Error uploading Logs to Log Analytics"
        $ErrorFlag = $True
    } else {
        Write-Host "Upload Successful"
    }
}


