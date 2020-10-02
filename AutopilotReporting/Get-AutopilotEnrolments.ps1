param (
    [Parameter(Mandatory)]
    [Int]$QuerySize,
    [Parameter(Mandatory)]
    [Int]$PageSize
)

#Create a Log file
$Logfile = "AutopilotEnrolment" + "_" + (get-date -Format "ddMMyyyyHHmm") + ".log"
Start-Transcript -Path .\$Logfile -append

##############################################################################
# Set the Data arrays used for enriching data
##############################################################################

#Create the application array
$Applications = New-Object System.Collections.ArrayList
#Add the application ID's to the Application arrays
$Applications += [pscustomobject] @{
    "AppID"= 'GUID'
    "AppName"="Office"
    "AppDetail" = "Office 365 ProPlus - Monthly Channel"
}
$Applications += [pscustomobject] @{
    "AppID"= 'GUID'
    "AppName"="Office"
    "AppDetail" = "Office 365 ProPlus with Visio - Monthly Channel"
}

$Applications += [pscustomobject] @{
    "AppID"= 'GUID'
    "AppName"="Citrix"
    "AppDetail" = "Citrix Receiver"
}


#Create the Device ring assignment array
$DeviceRings= New-Object System.Collections.ArrayList
$DeviceRings+= [pscustomobject] @{
    'AutopilotProfile' = 'Ring Zero'
    'DeviceType' = "Windows 10 vNext"
    'DeploymentRing' = "Ring Zero"
}
$DeviceRings+= [pscustomobject] @{
    'AutopilotProfile' = 'Ring One'
    'DeviceType' = "Windows 10 vNext"
    'DeploymentRing' = "Ring One"
}
$DeviceRings+= [pscustomobject] @{
    'AutopilotProfile' = 'Ring Two'
    'DeviceType' = "Windows 10 vNext"
    'DeploymentRing' = "Ring Two"
}
$DeviceRings+= [pscustomobject] @{
    'AutopilotProfile' = 'Ring Two Shared'
    'DeviceType' = "Windows 10 Shared"
    'DeploymentRing' = "Ring Two Shared"
}
$DeviceRings+= [pscustomobject] @{
    'AutopilotProfile' = 'Ring Three Shared'
    'DeviceType' = "Windows 10 Shared"
    'DeploymentRing' = "Ring Three Shared"
}


##############################################################################
# Query Autopilot Results from Graph
##############################################################################

#Set the Graph Schema to Beta - Required for the Autopilot query
Write-host "Setting MSGraph Schema Version" -ForegroundColor White
Update-MSGraphEnvironment -SchemaVersion beta

#connect to Connect-MSGraph then run script
Write-host "Connecting to MS Graph" -ForegroundColor White
Connect-MSGraph

#Create an array for the output
$EnrolledDevices = New-Object System.Collections.ArrayList

Write-Host "Querying the Autopilot Device Events" -ForegroundColor Yellow
Write-Host "Maximum result set $($QuerySize) with page size of $($PageSize)" -ForegroundColor blue

#Set the results status variables to the start values
$AllResultsRetrieved = $False
$ResultsRetrieved = 0

#Loop through the result set
do {
    If ($ResultsRetrieved -eq 0) {
        #Set the Graph API URL for the first run
        $AutopilotEventInvokeURL = "deviceManagement/AutopilotEvents?top=$PageSize&" + "$" + "count=true"
    }

    #Retrieve the results for Page set - Using a page size makes the query more reliable
    $AutopilotEventResult = Invoke-MSGraphRequest -HttpMethod GET -Url $AutopilotEventInvokeURL

    #Determine the count of the results returned
    $AutopilotEventCount = $AutopilotEventResult."@odata.count"
    Write-Host "Last query returned $($AutopilotEventCount) Events"

    #Process the results and store the results in the output array
    $AutopilotEvents = $AutopilotEventResult.Value
    foreach ($AutopilotEvent in $AutopilotEvents) {
        
        #Add the result to the results array
        $EnrolledDevice = New-Object -TypeName PSObject -Property @{
            'DeviceName' = $AutopilotEvent.managedDeviceName
            'SerialNumber' = $AutopilotEvent.deviceSerialNumber
            'DeviceType' = ""
            'DeploymentRing' = ""
            'EnrolmentState' = $AutopilotEvent.enrollmentState
            'DeploymentState' = $AutopilotEvent.deploymentState
            'AutopilotDeviceID' = $AutopilotEvent.deviceId
            'AutopilotEventDateTime' = $AutopilotEvent.eventDateTime
            'DeviceRegistrationDateTime' = $AutopilotEvent.deviceRegisteredDateTime
            'enrollmentStartDateTime' = $AutopilotEvent.enrollmentStartDateTime
            'deploymentStartDateTime' = $AutopilotEvent.deploymentStartDateTime
            'deploymentEndDateTime' = $AutopilotEvent.deploymentEndDateTime
            'enrollmentType' = $AutopilotEvent.enrollmentType
            'UPNID' = $AutopilotEvent.userPrincipalName
            'UPN' = ""
            'UserDisplayName' = ""
            'AutopilotProfile' = $AutopilotEvent.windowsAutopilotDeploymentProfileDisplayName
            'OSVersion' = $AutopilotEvent.osVersion
            'Office' = ""
            'Citrix' = ""
        }
        $EnrolledDevices.Add($EnrolledDevice) | Out-Null
    }
    
    #Determine whether the query has reached the end of the result set
    $ResultsRetrieved = $ResultsRetrieved + ($AutopilotEventResult.Value).count
    If ($AutopilotEventCount -eq $PageSize) {
        If ($ResultsRetrieved -eq $QuerySize) {
            write-host "Processed all requested device results ($($ResultsRetrieved))" -ForegroundColor Blue
            $AllResultsRetrieved = $True
        } else {
            Write-Host "Processed $($ResultsRetrieved). Retrieving next $($PageSize) results"
            $AutopilotEventInvokeURL = $AutopilotEventResult."@odata.nextLink"
        }
    } else {
        write-host "Processed all requested device results ($($ResultsRetrieved))" -ForegroundColor Blue
        $AllResultsRetrieved = $True
    }

} until ($AllResultsRetrieved -eq $True)

If ($EnrolledDevices.count -eq 0) {
    Write-Host "#################################################"
    Write-Host "Microsoft Graph Query returned zero devices" -ForegroundColor Red
    Write-Host "#################################################"
    Write-Error "Microsoft Graph Query returned zero devices" -ErrorAction Stop
} else {
    Write-host "Query Returned $($EnrolledDevices.count) Autopilot Events" -ForegroundColor blue
}




##############################################################################
# Enrich Data retrieved from Autopilot
##############################################################################

write-host ""
Write-Host "Determining UserNames for the Autopilot Events" -ForegroundColor Yellow
#Add username upn (rather than object ID)
foreach ($EnrolledDevice in $EnrolledDevices){
    Write-Host "Querying UPN for $($EnrolledDevice.DeviceName)"
    $Deviceupn = $EnrolledDevice.UPNID
    $DeviceUser = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/v1.0/users/$Deviceupn"
    $EnrolledDevice.UPN = $DeviceUser.userPrincipalName
    $EnrolledDevice.UserDisplayName = $DeviceUser.displayName
}

write-host ""
Write-Host "Determining the Device Rings for the Autopilot Events" -ForegroundColor Yellow
Foreach ($EnrolledDevice in $EnrolledDevices) {
    Write-Host "Querying Device Ring for $($EnrolledDevice.DeviceName)"
    $DeviceType = $DeviceRings | Where-Object {$_.AutopilotProfile -eq $EnrolledDevice.AutopilotProfile}
    If (!($null -eq $DeviceType)) {
        $EnrolledDevice.DeviceType = $DeviceType.DeviceType
        $EnrolledDevice.DeploymentRing = $DeviceType.DeploymentRing
    } else {
        $EnrolledDevice.DeviceType = "Unknown"
        $EnrolledDevice.DeploymentRing = "Unknown"
    }

}

write-host ""
Write-Host "Getting completed installations for the Autopilot Events" -ForegroundColor Yellow
#Get completed installations
foreach ($Application in $Applications){
    Write-host "Querying Application Status for $($Application.AppDetail)"
    $AppInstallInvokeURL = "deviceAppManagement/mobileApps/" + $Application.AppID + "/deviceStatuses"
    $AppInstallResult = Invoke-MSGraphRequest -HttpMethod GET -Url $AppInstallInvokeURL
    
    $AppInstallState = $AppInstallResult.Value
    
    #Check with recently enrolled devices if device is found in installstate array. installstate is then append to the data array
    foreach ($EnrolledDevice in $EnrolledDevices){
        $location = [array]::indexof($AppInstallState.DeviceName,$EnrolledDevice.DeviceName) #get location of device from appinstallstate (if returned -1 the device is not listed therefore not insalled)
        if ($location -ne '-1'){
            $EnrolledDevice.($Application.AppName) = $AppInstallState[$location].installState
        } elseif ($null -eq $EnrolledDevice.($Application.AppName)) {
            $EnrolledDevice.($Application.AppName) = "not installed"
        }
    }
}

##############################################################################
# Export the data to CSV
##############################################################################


write-host ""
Write-Host "Exporting the Results" -ForegroundColor Yellow
#export to csv
$filename = "EnrollmentandAppStatus" + " " + (get-date -Format "ddMMyyyy HHmm") + ".csv"
$EnrolledDevices | Select-Object DeviceName,SerialNumber,DeviceType,DeploymentRing,AutopilotProfile,EnrolmentState,UPN,UserDisplayName,OSVersion,Office,Citrix,DeploymentState,DeviceRegistrationDateTime,enrollmentStartDateTime,deploymentStartDateTime,deploymentEndDateTime | Sort-Object SerialNumber,enrollmentStartDateTime | Export-Csv .\$filename -NoTypeInformation
Write-Host "Results exported to $($Filename)"

Stop-Transcript
