<#  
    .NOTES

===========================================================================
Created by:    Andrew Matthews
Organization:  To The Cloud and Beyond
Filename:      New-DeviceIDs.ps1
Documentation: TBC
Execution Tested on: Windows Server 2019 with the AD PowerShell Module
Requires:      
Versions:
1.0 - 28 April 2022
 - First version
 - Includes core functionality to query for AADJ Devices and manage AD Objects
1.1 - 3 May 2022
 - add computer objects to AD groups
 - Updated the logic to handle multiple AD group memberships

===========================================================================
.SYNOPSIS

Queries a Function App via a REST API request for a list of current device IDs

.DESCRIPTION
Section 1 - Script initialisation
Section 2 - Request Device IDs
Section 3 - Update Active Directory
Section 4 - Exit

.INPUTS
An XML Config file

.OUTPUTS
A log file in CMTrace format

#>

param(
    [Parameter(Mandatory = $true)]$ConfigFile
)

################################################
#Declare Constants and other Script Variables
################################################

#Log Levels
[string]$LogLevelError = "Log_Error"
[string]$LogLevelWarning = "Log_Warning"
[string]$LogLevelInfo = "Log_Information"

[string]$LogPath = "C:\Temp\NPSDeviceIDLog"
[string]$TxtLogfilePrefix = "NPSDeviceIDManagement" # Log file in cmtrace format

$LogtoScreen = $True

$LogCacheArray = New-Object System.Collections.ArrayList
$MaxLogCachesize = 10
$MaxLogWriteAttempts = 5

$Groups = New-Object System.Collections.ArrayList

$Script:AADJoinedDevices = New-Object System.Collections.ArrayList

$MaxRequests = 5

################################################
#Declare Functions
################################################

<# Create a New log entry in log files #>
Function New-LogEntry {
    param (
        [Parameter(Mandatory=$true)]    
        [string]$LogEntry,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Log_Error","Log_Warning","Log_Information")]
        [string]$LogLevel,
        [Parameter(Mandatory=$false)]
        [Bool]$ImmediateLog,
        [Parameter(Mandatory=$false)]
        [Bool]$FlushLogCache
    )

    #Create the CMTrace Time stamp
    $TxtLogTime = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $TxtLogDate = "$(Get-Date -Format MM-dd-yyyy)"

    #Create the Script line number variable
    $ScriptLineNumber = "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)"
    #Add the log entry to the cache
    switch ($LogLevel) {
        $LogLevelError {  
            New-LogCacheEntry -LogEntry $LogEntry -LogTime $TxtLogTime -LogDate $TxtLogDate -ScriptLineNumber $ScriptLineNumber -LogLevel $LogLevel
        }
        $LogLevelWarning { 
            New-LogCacheEntry -LogEntry $LogEntry -LogTime $TxtLogTime -LogDate $TxtLogDate -ScriptLineNumber $ScriptLineNumber -LogLevel $LogLevel
        }
        $LogLevelInfo { 
            New-LogCacheEntry -LogEntry $LogEntry -LogTime $TxtLogTime -LogDate $TxtLogDate -ScriptLineNumber $ScriptLineNumber -LogLevel $LogLevel
        }
        default {
            New-LogCacheEntry -LogEntry $LogEntry -LogTime $TxtLogTime -LogDate $TxtLogDate -ScriptLineNumber $ScriptLineNumber -LogLevel $LogLevelInfo
        }
    }

    If ($LogtoScreen -eq $true) {
        Write-Host "$($ScriptLineNumber) : $($LogEntry)" 
    }

    #Set the Write log entries to the default state of false
    $WriteLogEntries = $True
    #Determine whether the log needs to be immediately written
    If ($PSBoundParameters.ContainsKey('ImmediateLog')) {
        If($ImmediateLog -eq $false) {
            #Do not invoke the log flush       
        } Else {
            #If the action is immediate log then flush the log entries
            $WriteLogEntries = $True
        }
    } else {
        #If no value specified then for not flush the log cache
        $WriteLogEntries = $false
    }

    If ($PSBoundParameters.ContainsKey('FlushLogCache')) { 
        If($FlushLogCache -eq $false) {
            If($LogCacheArray.count -eq $MaxLogCachesize) {
                #If the max cache size has been hit then flush the log entries
                $WriteLogEntries = $true
            }
        } else { 
            $WriteLogEntries = $true
        }
    } else {
        If($LogCacheArray.count -eq $MaxLogCachesize) {
            #If the max cache size has been hit then flush the log entries
            $WriteLogEntries = $true
        }
    }


    If ($WriteLogEntries -eq $true) {
        #write the log entries
        Write-LogEntries
    }
}

Function Write-LogEntry {
    param (
        [Parameter(Mandatory=$true)]    
        [string]$LogEntry,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Log_Error","Log_Warning","Log_Information")]
        [string]$LogLevel,
        [Parameter(Mandatory=$true)]
        [string]$LogTime,
        [Parameter(Mandatory=$true)]
        [string]$LogDate,
        [Parameter(Mandatory=$true)]
        [string]$ScriptLineNumber
    )
    #Determine the action based on the log level
    switch ($LogLevel) {
        $LogLevelError {  
            #Create the CMTrace Log Line
            $TXTLogLine = '<![LOG[' + $LogEntry + ']LOG]!><time="' + $TxtLogTime + '" date="' + $TxtLogDate + '" component="' + "$($ScriptLineNumber)" + '" context="" type="' + 3 + '" thread="" file="">'
        }
        $LogLevelWarning {
            $TXTLogLine = '<![LOG[' + $LogEntry + ']LOG]!><time="' + $TxtLogTime + '" date="' + $TxtLogDate + '" component="' + "$($ScriptLineNumber)" + '" context="" type="' + 2 + '" thread="" file="">'
        }
        $LogLevelInfo {
            $TXTLogLine = '<![LOG[' + $LogEntry + ']LOG]!><time="' + $TxtLogTime + '" date="' + $TxtLogDate + '" component="' + "$($ScriptLineNumber)" + '" context="" type="' + 1 + '" thread="" file="">'
        }
        default {
            $TXTLogLine = '<![LOG[' + $LogEntry + ']LOG]!><time="' + $TxtLogTime + '" date="' + $TxtLogDate + '" component="' + "$($ScriptLineNumber)" + '" context="" type="' + 1 + '" thread="" file="">'
        }
    }

    #Write the CMTrace Log line
    Add-Content -Value $TXTLogLine -Path $TxtLogFile -force
}

Function Write-LogEntries {
    Write-Host "**** Flushing $($LogCacheArray.count) Log Cache Entries ****"
    $LogTextRaw = ""
    #Rotate through the Log entries and compile a master variable
    ForEach($LogEntry in $LogCacheArray) {
        switch ($LogEntry.LogLevel) {
            $LogLevelError {  
                #Create the CMTrace Log Line
                $TXTLogLine = '<![LOG[' + $LogEntry.LogEntry + ']LOG]!><time="' + $LogEntry.LogTime + '" date="' + $LogEntry.LogDate + '" component="' + "$($LogEntry.LineNumber)" + '" context="" type="' + 3 + '" thread="" file="">'
            }
            $LogLevelWarning {
                $TXTLogLine = '<![LOG[' + $LogEntry.LogEntry + ']LOG]!><time="' + $LogEntry.LogTime + '" date="' + $LogEntry.LogDate + '" component="' + "$($LogEntry.LineNumber)" + '" context="" type="' + 2 + '" thread="" file="">'
            }
            $LogLevelInfo {
                $TXTLogLine = '<![LOG[' + $LogEntry.LogEntry + ']LOG]!><time="' + $LogEntry.LogTime + '" date="' + $LogEntry.LogDate + '" component="' + "$($LogEntry.LineNumber)" + '" context="" type="' + 1 + '" thread="" file="">'
            }
            default {
                $TXTLogLine = '<![LOG[' + $LogEntry.LogEntry + ']LOG]!><time="' + $LogEntry.LogTime + '" date="' + $LogEntry.LogDate + '" component="' + "$($LogEntry.LineNumber)" + '" context="" type="' + 1 + '" thread="" file="">'
            }
        }
        If($LogTextRaw.Length -eq 0) {
            $LogTextRaw = $TXTLogLine
        } else {
            $LogTextRaw = $LogTextRaw + "`r`n" + $TXTLogLine
        }
    }

    #Write the Log entries Log line
    $LogWritten = $false
    $LogWriteAttempts = 0
    do {
        $LogWriteAttempts = $LogWriteAttempts + 1
        $WriteLog = $True
        Try {
            Add-Content -Value $LogTextRaw -Path $TxtLogFile -ErrorAction stop
        }
        Catch {
            $ErrorMessage = $_.Exception.Message
            $WriteLog = $false
            Write-Host "Log entry flush failed"
            Write-Host $ErrorMessage
        }
        If ($WriteLog-eq $false) {
            If ($LogWriteAttempts -eq $MaxLogWriteAttempts) {
                Write-Host "Maximum log write attempts exhausted - saving log entries for the next attempt"
                $LogWritten = $true
            }
            #Wait five seconds before looping again
            Start-Sleep -Seconds 5
        } else {
            $LogWritten = $true
            Write-Host "Wrote $($LogCacheArray.count) cached log entries to the log file"
            $LogCacheArray.Clear()
        }
    } Until ($LogWritten -eq $true) 
        
}

Function New-LogCacheEntry {
    param (
        [Parameter(Mandatory=$true)]    
        [string]$LogEntry,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Log_Error","Log_Warning","Log_Information")]
        [string]$LogLevel,
        [Parameter(Mandatory=$true)]
        [string]$LogTime,
        [Parameter(Mandatory=$true)]
        [string]$LogDate,
        [Parameter(Mandatory=$true)]
        [string]$ScriptLineNumber
    )

    $LogCacheEntry = New-Object -TypeName PSObject -Property @{
        'LogEntry' = $LogEntry
        'LogLevel' = $LogLevel
        'LogTime' = $LogTime
        'LogDate' = $LogDate
        'Linenumber' = $ScriptLineNumber
    }

    $LogCacheArray.Add($LogCacheEntry) | Out-Null

}

<# Create a new log file for a Txt Log #>
Function New-TxtLog {
    param (
        [Parameter(Mandatory=$true)]    
        [string]$NewLogPath,
        [Parameter(Mandatory=$true)]    
        [string]$NewLogPrefix
    )

    #Create the log path if it does not exist
    if (!(Test-Path $NewLogPath))
    {
        New-Item -itemType Directory -Path $NewLogPath
    }

    #Create the new log name using the prefix
    [string]$NewLogName = "$($NewLogPrefix)-$(Get-Date -Format yyyy-MM-dd)-$(Get-Date -Format HH-mm).log"
    #Create the fill path
    [String]$NewLogfile = Join-Path -path $NewLogPath -ChildPath $NewLogName
    #Create the log file
    New-Item -Path $NewLogfile -Type File -force | Out-Null

    #Return the LogfileName
    Return $NewLogfile
}

<# Exit the script#>
Function Exit-Script {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$ExitText
    )
    
    #Write the exit text to the log, flush the log cache and exit
    New-LogEntry -LogEntry $ExitText -FlushLogCache $true
    Exit
}

<# Retrieve Devices from Graph #>
function Get-DevicesfromGraph {
    Param (
        [Parameter(Mandatory=$true)][string]$AADGroupName,
        [Parameter(Mandatory=$true)][string]$GroupID
    )

    $ReturnValue = New-Object -TypeName PSObject -Property @{
        "Status" = $True
        "Devices" = ""
    }

    #Create the group body for the request
    $GroupRequestBody = @"
    {
        "Group": "$AADGroupName",
	}
"@

    #attempt to query the devices
    $RequestAttempts = 0
    $Devices = 0
    $ExitLoop = $False
    Do {
        $RequestAttempts = $RequestAttempts + 1
        $RequestSucceeded = $True
        New-LogEntry -LogEntry "Querying AAD Devices - Attempt $($RequestAttempts)"
        try{
            $GroupMemberQuery = Invoke-RestMethod -Uri $FunctionAppURL -ContentType "application/json" -Method POST -Body $GroupRequestBody
        } catch {
            $ErrorMessage = $_.Exception.Message
            New-LogEntry -LogEntry "Error Querying the function app: $($ErrorMessage)" -LogLevel $LogLevelError 
            $RequestSucceeded = $False
        }
        if ($RequestSucceeded -eq $True) {
            if($GroupMemberQuery.Status -eq "Success") {
                New-LogEntry -LogEntry "Group Member Query succeeded on attempt $($RequestAttempts)"
                $ExitLoop = $True
                foreach($GroupMember in $GroupMemberQuery.devices) {
                    $NewDevice = New-Object -TypeName PSObject -Property @{
                        "Status" = "New"
                        "AADDeviceID" = $GroupMember.ID
                        "ComputerName" = $GroupMember.ComputerName
                        "AADGroup" = $AADGroupName
                        "GroupID" = $GroupID
                        "ADSID" = ""
                        "Ring" = $GroupMember.Ring
                    }
                    $Script:AADJoinedDevices.Add($NewDevice) | Out-Null
                    $Devices = $Devices + 1
                }
            } else {
                New-LogEntry -LogEntry "Group Member Query failed on attempt $($RequestAttempts) - Error: $($GroupMemberQuery.Error)" -LogLevel $LogLevelWarning
                $RequestSucceeded = $False
            }
        }

        if ($RequestSucceeded -eq $False) {
            if($RequestAttempts -eq $MaxRequests) {
                New-LogEntry -LogEntry "Maximum query attempts reached without success" -LogLevel $LogLevelError
                $ExitLoop = $True
                $ReturnValue.Status = $False
            } else {
                New-LogEntry -LogEntry "Pausing before re-attempting the query" -FlushLogCache $True -LogLevel $LogLevelWarning
                Start-sleep -Seconds 30
            }
        }
    } until ($ExitLoop -eq $True)

    if($ReturnValue.Status -eq $True) {
        if($Devices -eq 0) {
            New-LogEntry -LogEntry "Query returned no devices" -LogLevel $LogLevelError
            $ReturnValue.Status = $False
        } else {
            $ReturnValue.Devices = $Devices
        }
    }
    Return $ReturnValue
}

function Add-ADComputerGroupMembership {
    Param (
        [Parameter(Mandatory=$true)][string]$ADGroup,
        [Parameter(Mandatory=$true)][string]$Computer
    )
    $ReturnValue = New-Object -TypeName PSObject -Property @{
        "Status" = $True
        "Outcome" = "None"
        "Error" = ""
    }

    #Check that the group exists
    if($ReturnValue.Status -eq $True) {
        try{
            $ADGroupObject = Get-ADGroup -Filter "Name -eq `"$($ADGroup)`""
        } catch{
            $ErrorMessage = $_.Exception.Message
            $ReturnValue.Error = "Failed to query group $($ADGroup) - Error: $($ErrorMessage)"
            $ReturnValue.Status = $False
        }
    }
    if($ReturnValue.Status -eq $True) {
        if($null -eq $ADGroupObject) {
            $ReturnValue.Error = "Group $($ADGroup) does not exist"
            $ReturnValue.Status = $False
        }
    }

    #Get the AD Computer object
    if($ReturnValue.Status -eq $True) {
        try{
            $ADComputerObject = Get-ADComputer -filter "Name -eq `"$($Computer)`""
        } catch {
            $ErrorMessage = $_.Exception.Message
            $ReturnValue.Error = "Failed to query computer object $($Computer) - Error: $($ErrorMessage)"
            $ReturnValue.Status = $False
        }
    }
    if($ReturnValue.Status -eq $True) {
        if($Null -eq $ADComputerObject) {
            $ReturnValue.Error = "Computer object not found for $($Computer)"
            $ReturnValue.Status = $False
        }
    }
    #Check whether the device is already a member of the group
    if($ReturnValue.Status -eq $True) {
        try{
            $CheckADGroupMembership = Get-ADGroupMember -Identity $ADGroupObject.DistinguishedName | where-object {$_.distinguishedName -eq $ADComputerObject.distinguishedName}
        } catch{
            $ErrorMessage = $_.Exception.Message
            $ReturnValue.Error = "Failed to query group membership for $($ADGroup) - Error: $($ErrorMessage)"
            $ReturnValue.Status = $False
        }
    }

    #If the device is not a member of the group then add the device to the group
    if($ReturnValue.Status -eq $True) {
        if($null -eq $CheckADGroupMembership) {
            #Add the computer to the group
            $ReturnValue.Outcome = "Added"
            try {
                Add-ADGroupMember -Identity $ADGroupObject.DistinguishedName -members $ADComputerObject.distinguishedName
            } catch {
                $ErrorMessage = $_.Exception.Message
                $ReturnValue.Error = "Failed to add $($ComputerName) to $($ADGroup) - Error: $($ErrorMessage)"
                $ReturnValue.Status = $False
            }
        } else {
            $ReturnValue.Outcome = "Exists"
        }
    }


    Return $ReturnValue
}

################################################
# Section 1: Startup
################################################

# Section 1 Step 1: Create a Log file
New-LogEntry -LogEntry "*** Section 1 Step 1: Creating Log file ***"
$TxtLogFile = New-TxtLog -NewlogPath $LogPath -NewLogPrefix $TxtLogfilePrefix


# Section 1 Step 2: Load Config
New-LogEntry -LogEntry "*** Section 1 Step 2: Loading config ***"

#Loading the configuration from the XML file
write-host $ConfigFile
New-LogEntry -LogEntry "Loading configuration from location: $($ConfigFile)"
try {
    [Xml]$config = Get-Content -path $ConfigFile
} catch {
    $ErrorMessage = $_.Exception.Message
    New-LogEntry -LogEntry "Error loading the config XML" -LogLevel $LogLevelError 
    New-LogEntry -LogEntry $ErrorMessage -LogLevel $LogLevelError -FlushLogCache $true
    Exit-Script -ExitText "Unable to load the Config XML - Script exiting"
}

# Section 1 Step 3: Check Config
New-LogEntry -LogEntry "*** Section 1 Step 3: Checking Config ***"

#Load the Functional App value from the Config
if(!($config.config.FunctionAppURL.length -eq 0)) {
    $FunctionAppURL = $config.config.FunctionAppURL
} else {
    New-LogEntry -LogEntry "Function app URL is missing" -LogLevel $LogLevelError 
    Exit-Script -ExitText "Unable to continue because the function app URL is missing - Script exiting"
}

#Load the groups from the Config
foreach($TempGroup in $config.config.Groups.group) {
    $TempAADGroup = "None"
    $TempGroupID = "None"
    if(!($TempGroup.AAD.Length -eq 0)) {
        $TempAADGroup = $TempGroup.AAD
    } else {
        New-LogEntry -LogEntry "Zero length AD Group name found" -LogLevel $LogLevelError 
    }
    if(!($TempGroup.ID.Length -eq 0)) {
        $TempGroupID = $TempGroup.ID
    } else {
        New-LogEntry -LogEntry "Zero length AD Group name found" -LogLevel $LogLevelError 
    }
    if((!($TempAADGroup -eq "None")) -and (!($TempGroupID -eq "None"))) {
        $NewGroupentry = New-Object -TypeName PSObject -Property @{
            "AADGroup" = $TempAADGroup
            "GroupID" = $TempGroupID
        }
        $Groups.Add($NewGroupentry) | Out-Null
    } else {
        New-LogEntry -LogEntry "Invalid group parameter found (AAD: $($TempAADGroup) - AD: $($TempADGroup))"
    } 

}

if(!($Groups.count -eq 0)) {
    New-LogEntry -LogEntry "Processing $($Groups.count) Azure AD Groups"
} else {
    New-LogEntry -LogEntry "No valid groups found in the config" -LogLevel $LogLevelError 
    Exit-Script -ExitText "Unable to continue because no valid groups found in the config - Script exiting"
}

#Check the OU exists - TBC
if(!($Config.config.OU.length -eq 0)) {
    $AADJADOU = $Config.config.OU
    New-LogEntry -LogEntry "Active Directory OU: $($AADJADOU)"
} else {
    New-LogEntry -LogEntry "No valid OU found in the config" -LogLevel $LogLevelError 
    Exit-Script -ExitText "Unable to continue because no valid OU found in the config - Script exiting"
}

# Section 1 Step 2: Load Config
New-LogEntry -LogEntry "*** Section 1 Step 3: Check PowerShell Modules ***"
if((get-module -ListAvailable | where-object {$_.Name -eq "ActiveDirectory"}).count -eq 1) {
    New-LogEntry -LogEntry "Active Directory PowerShell Module is installed"
} else {
    New-LogEntry -LogEntry "Active Directory PowerShell Module is not installed" -LogLevel $LogLevelError 
    Exit-Script -ExitText "Unable to continue because Active Directory PowerShell Module is not installed - Script exiting"
}



################################################
# Section 2: Process AAD Devices
################################################

New-LogEntry -LogEntry "*** Section 2 Step 1: Querying AAD for Devices ***"
Foreach ($Group in $Groups) {
    New-LogEntry -LogEntry "Processing Devices for $(($config.config.Groups.group | where-object {$_.ID -eq $Group.GroupID }).Description)"
    #Query AAD via the function app for devices
    $QueryAAD = Get-DevicesfromGraph -AADGroupName $Group.AADGroup -GroupID $Group.GroupID 
    if($QueryAAD.Status -eq $True) {
        New-LogEntry -LogEntry "Azure AD Query for devices that are members of $($Group.AADGroup) returned $($QueryAAD.Devices) devices"
    } else {
        New-LogEntry -LogEntry "Azure AD Query for devices that are members of $($Group.AADGroup) failed" -LogLevel $LogLevelWarning
    }
}

if(!($Script:AADJoinedDevices.count -eq 0)) {
    New-LogEntry -LogEntry "*** Section 2 Step 2: Querying AD for Matching Devices ***"
    #Process the AAD Devices and confirm whether a matching device object exists in AAD

    $ExitDeviceLoop = $False
    $DeviceIndex = 0
    do{
        $QueryError = $False
        #Check whether a computer object exists with the AAD Device ID
        try {
            $QueryADComputerbyName = Get-ADComputer -filter "Name -eq `"$($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID)`"" -searchbase $AADJADOU -ErrorAction Stop
        } catch {
            $ErrorMessage = $_.Exception.Message
            New-LogEntry -LogEntry "Error querying Active Directory for $($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID): $($ErrorMessage)" -LogLevel $LogLevelError 
            $QueryError = $true
        }
        if($QueryError -eq $False) {
            if(!($null -eq $QueryADComputerbyName)) {
                New-LogEntry -LogEntry "Found Matching computer object with SAMAccountName $($QueryADComputerbyName.SamAccountName) for AAD Device $($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID)"
                $Script:AADJoinedDevices[$DeviceIndex].ADSID = $QueryADComputerbyName.SID
                $Script:AADJoinedDevices[$DeviceIndex].Status = "Exists"
            } else{
                New-LogEntry -LogEntry "No matching computer object for AAD Device $($Script:AADJoinedDevices[$DeviceIndex].ADSID)"
            }
        }
        #Check whether a computer object exists with the SAM AccountName just in case the AAD Device ID has changed
        if($Script:AADJoinedDevices[$DeviceIndex].Status -eq "New") {
            $QueryError = $False
            try { 
                $QueryADComputerbySamAccountName = Get-ADComputer -filter "SamAccountName -eq `"$($Script:AADJoinedDevices[$DeviceIndex].ComputerName)`$`"" -ErrorAction Stop
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-LogEntry -LogEntry "Error querying Active Directory for $($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID): $($ErrorMessage)" -LogLevel $LogLevelError 
                $QueryError = $true
            }
            if($QueryError -eq $False) {
                if(!($null -eq $QueryADComputerbySamAccountName)) {
                    if($QueryADComputerbySamAccountName.Name -eq $Script:AADJoinedDevices[$DeviceIndex].AADDeviceID) {
                        New-LogEntry -LogEntry "Found Matching computer object with SAMAccountName $($QueryADComputerbyName.SamAccountName) for AAD Device $($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID)"
                        $Script:AADJoinedDevices[$DeviceIndex].ADSID = $QueryADComputerbyName.SID
                        $Script:AADJoinedDevices[$DeviceIndex].Status = "Exists"
                    } else {
                        New-LogEntry -LogEntry "Found non-matching computer object with SAMAccountName $($QueryADComputerbySamAccountName.SamAccountName) for AAD Device $($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID)"
                        #Delete the dissimilar object
                        $DeletionError = $False
                        try{ 
                            Remove-ADComputer -Identity $QueryADComputerbySamAccountName.DistinguishedName -confirm:$False -ErrorAction Stop
                        } catch {
                            $ErrorMessage = $_.Exception.Message
                            New-LogEntry -LogEntry "Error deleting duplicate object for $($Script:AADJoinedDevices[$DeviceIndex].ComputerName) - Error: " -LogLevel $LogLevelError 
                            $DeletionError = $True
                        }
                        if($DeletionError -eq $False) {
                            New-LogEntry -LogEntry "Deleted duplicate object for $($Script:AADJoinedDevices[$DeviceIndex].ComputerName)"
                        }
                    }
                } else {
                    New-LogEntry -LogEntry "No duplicate computer objects found with SAMAccountName $($QueryADComputerbyName.SamAccountName) for AAD Device $($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID)"
                }
            }
        }
        $DeviceIndex = $DeviceIndex + 1
        if($DeviceIndex -eq $Script:AADJoinedDevices.count) {
            New-LogEntry -LogEntry "Completed checking $($Script:AADJoinedDevices.count) AAD Joined devices against Active Directory objects"
            $ExitDeviceLoop = $True
        }
    } until ($ExitDeviceLoop -eq $True)
} else {
    New-LogEntry -LogEntry "No Azure AD Joined devices were found" -LogLevel $LogLevelError 
    Exit-Script -ExitText "Unable to continue because no Azure AD Joined devices were found - Script exiting"
}

################################################
# Section 3: AD Object Creation and deletion
################################################


if(!($Script:AADJoinedDevices.count -eq 0)) {
    New-LogEntry -LogEntry "*** Section 3 Step 1: Create new AD objects ***"

    $ExitDeviceLoop = $False
    $DeviceIndex = 0
    $DevicesCreated = 0
    $DevicesFailed = 0
    do{
        if($Script:AADJoinedDevices[$DeviceIndex].Status -eq "New") {
            $DeviceCreationStatus = $True
            #Create the device
            New-LogEntry -LogEntry "Creating computer object for $($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID)"
            try {
                New-ADComputer -Name "$($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID)" -SAMAccountName "$($Script:AADJoinedDevices[$DeviceIndex].ComputerName)`$" -ServicePrincipalNames "HOST/$($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID)" -path $AADJADOU -Description "$($Script:AADJoinedDevices[$DeviceIndex].Ring)"  -ErrorAction Stop 
            } catch {
                $ErrorMessage = $_.Exception.Message
                New-LogEntry -LogEntry "Error creating Computer object for $($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID) - Error $($ErrorMessage)" -LogLevel $LogLevelError 
                $DeviceCreationStatus = $False
            }

            #Add the Alternative Security Identities
            if($DeviceCreationStatus -eq $True) {
                New-LogEntry -LogEntry "Adding alternate security IDs for $($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID)"
                foreach($IssuingCA in $config.config.CertificateAuthorities.ca) {
                    try{
                        Set-ADComputer -Identity "$($Script:AADJoinedDevices[$DeviceIndex].ComputerName)" -Add @{'altSecurityIdentities'="$($IssuingCA)$($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID)"}
                    } catch{
                        $ErrorMessage = $_.Exception.Message
                        New-LogEntry -LogEntry "Error setting altsecurityids for $($Script:AADJoinedDevices[$DeviceIndex].AADDeviceID) - Error $($ErrorMessage)" -LogLevel $LogLevelError 
                        $DeviceCreationStatus = $False
                    }
                }
            }

            if($DeviceCreationStatus -eq $True) {
                $DevicesCreated = $DevicesCreated + 1
                #Mark the device as created
                $Script:AADJoinedDevices[$DeviceIndex].Status = "Created"
            } else {
                $DevicesFailed = $DevicesFailed + 1
                $Script:AADJoinedDevices[$DeviceIndex].Status = "Failed"
            }
        }
        $DeviceIndex = $DeviceIndex + 1
        if($DeviceIndex -eq $Script:AADJoinedDevices.count) {
            New-LogEntry -LogEntry "Created $($DevicesCreated) AAD Joined devices in Active Directory"
            if($DevicesFailed -gt 0) {
                New-LogEntry -LogEntry "Failed to create $($DevicesFailed) AAD Joined devices in Active Directory" -LogLevel $LogLevelWarning
            }
            $ExitDeviceLoop = $True
        }
    } until ($ExitDeviceLoop -eq $True)
}
if(!($Script:AADJoinedDevices.count -eq 0)) {
    New-LogEntry -LogEntry "*** Section 3 Step 2: Delete old AD objects ***"

    #Query theAADJ OU for Computer objects
    New-LogEntry -LogEntry "Querying for Active Directory Objects in the Domain Joined OU"

    try{
        $ADComputerObjects = Get-ADComputer -Filter * -SearchBase $AADJADOU -ErrorAction Stop
    } catch {
        New-LogEntry -LogEntry "AD query failed" -LogLevel $LogLevelError 
        Exit-Script -ExitText "Unable to Query AD for existing devices - Script exiting"
    }
    New-LogEntry -LogEntry "Processing Active Directory Objects in the Domain Joined OU for stale objects"
    foreach($ADComputerObject in $ADComputerObjects) {
        #Determine whether the object exists in the array
        if(($Script:AADJoinedDevices | where-object {$_.AADDeviceID -eq $ADComputerObject.Name}).count -eq 0) {
            #Delete the object if the object is not in the AAD query
            New-LogEntry -LogEntry "Deleting old object $($ADComputerObject.Name)"
            try{
                Remove-ADComputer -Identity $ADComputerObject.Name -Confirm:$False -ErrorAction Stop
            } catch{
                $ErrorMessage = $_.Exception.Message
                New-LogEntry -LogEntry "Error deleting old computer object for $($ADComputerObject.Name) - Error $($ErrorMessage)" -LogLevel $LogLevelError 
            }
        }
    }

}

if(!($Script:AADJoinedDevices.count -eq 0)) {
    New-LogEntry -LogEntry "*** Section 3 Step 3: Update Group Memberships ***"
    $ExitDeviceLoop = $False
    $DeviceIndex = 0
    do {
        if(($Script:AADJoinedDevices[$DeviceIndex].Status -eq "Created") -or ($Script:AADJoinedDevices[$DeviceIndex].Status -eq "Exists")) {
            New-LogEntry -LogEntry "Processing Groups for $($Script:AADJoinedDevices[$DeviceIndex].ComputerName)"
            #Confirm that groups exist for the device.
            If(!(($config.config.Groups.group | where-object {$_.ID -eq $Script:AADJoinedDevices[$DeviceIndex].GroupID}).ad.count -eq 0)) {
                #Loop through the groups for the device
                foreach($ADGroup in ($config.config.Groups.group | where-object {$_.ID -eq $Script:AADJoinedDevices[$DeviceIndex].GroupID}).ad) {
                    $AddGroupMemberStatus = Add-ADComputerGroupMembership -Computer $Script:AADJoinedDevices[$DeviceIndex].AADDeviceID -ADGroup $ADGroup
                    if($AddGroupMemberStatus.Status -eq $True) {
                        switch($AddGroupMemberStatus.Outcome) {
                            "added" {
                                New-LogEntry -LogEntry "$($Script:AADJoinedDevices[$DeviceIndex].ComputerName) successfully added to '$($ADGroup)'"
                            }
                            "exists" {
                                New-LogEntry -LogEntry "$($Script:AADJoinedDevices[$DeviceIndex].ComputerName) is already a member of '$($ADGroup)'"
                            }
                            default {
                                New-LogEntry -LogEntry "Unknown outcome - $($AddGroupMemberStatus.Outcome)"
                            }
                        }
                    } else {
                        New-LogEntry -LogEntry "Failed to add $($Script:AADJoinedDevices[$DeviceIndex].ComputerName) to '$($ADGroup)' - Error: $($AddGroupMemberStatus.Error)"
                    }
                }
            } else {
                New-LogEntry -LogEntry "no AD Groups found for Group ID $($Script:AADJoinedDevices[$DeviceIndex].GroupID)"
            }
        }
        $DeviceIndex = $DeviceIndex + 1
        if($DeviceIndex -eq $Script:AADJoinedDevices.count) {
            $ExitDeviceLoop = $True
        }
    } until ($ExitDeviceLoop -eq $True)

}


################################################
# Section 4: Exit
################################################

Exit-Script -ExitText "script complete"