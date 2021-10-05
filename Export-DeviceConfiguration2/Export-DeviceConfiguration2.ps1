<#
    .NOTES
    ===========================================================================
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
    EITHER EXPRESSED OR IMPLIED,  INCLUDING BUT NOT LIMITED TO THE IMPLIED
    WARRANTIES OF MERCHANTBILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
    ===========================================================================
    Created by:    Andrew Matthews
    Filename:      Export-DeviceConfiguration2.ps1
    Documentation: None
    Execution Tested on: 
    Requires:      Azure AD PowerShell module
    Versions:
    2.0 - 5-Oct-2021 Revisions by Andrew Matthews to allow encrypted values to be exported
    ===========================================================================

    .SYNOPSIS
    Processes Active Directory user accounts to ensure that mailboxes are correctly mail enabled

    .DESCRIPTION
    An update of https://github.com/microsoftgraph/powershell-intune-samples/blob/master/DeviceConfiguration/DeviceConfiguration_Export.ps1 
    to allow secret values to be exported in plain text.

    .PARAMETER ObjectGUID
    Export a single policy using the GUID ID of the policy

    .EXAMPLE
    Export-DeviceConfiguration2.ps1 -ObjectGUID GUIDValue

    .INPUTS
    (Optional) 

    .OUTPUTS
    JSON files with policies

    #COPYRIGHT
    Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
    See LICENSE in the project root for license information.

#>
Param(
	[Parameter(Mandatory=$false)][string]$ObjectGUID
)


####################################################

function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
        if ($AadModule -eq $null) {
    
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        }
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
        }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($AadModule.count -gt 1){
    
                $aadModule = $AadModule | select -Unique
    
                }
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
        else {
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
        try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
    
            return $authHeader
    
            }
    
            else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
            }
    
        }
    
        catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
        }
    
    }
    
    ####################################################
    
    Function Get-DeviceConfigurationPolicy(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicy
    #>
    
    [cmdletbinding()]
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
        
        try {
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }
        
        catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
        }
    
    }
    Function Get-SingleDeviceConfigurationPolicy(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-SingleDeviceConfigurationPolicy
    Returns a single device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicy
    #>
    Param(
	    [Parameter(Mandatory=$true)][string]$GUID
    )
    
    [cmdletbinding()]
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
        
        try {
        
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$GUID"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        
        }
        
        catch {
    
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
    
        }
    
    }
    
    ####################################################
    
    Function Export-JSONData(){
    
    <#
    .SYNOPSIS
    This function is used to export JSON data returned from Graph
    .DESCRIPTION
    This function is used to export JSON data returned from Graph
    .EXAMPLE
    Export-JSONData -JSON $JSON
    Export the JSON inputted on the function
    .NOTES
    NAME: Export-JSONData
    #>
    
    param (
    
    $JSON,
    $ExportPath
    
    )
    
        try {
    
            if($JSON -eq "" -or $JSON -eq $null){
    
                write-host "No JSON specified, please specify valid JSON..." -f Red
    
            }
    
            elseif(!$ExportPath){
    
                write-host "No export path parameter set, please provide a path to export the file" -f Red
    
            }
    
            elseif(!(Test-Path $ExportPath)){
    
                write-host "$ExportPath doesn't exist, can't export JSON Data" -f Red
    
            }
    
            else {

                
    
                $JSON1 = ConvertTo-Json $JSON -Depth 5
    
                $JSON_Convert = $JSON1 | ConvertFrom-Json
    
                $displayName = $JSON_Convert.displayName
    
                # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
                $DisplayName = $DisplayName -replace '\<|\>|:|"|/|\\|\||\?|\*', "_"
    
                $FileName_JSON = "$DisplayName" + "_" + $(get-date -f dd-MM-yyyy-H-mm-ss) + ".json"
    
                write-host "Export Path:" "$ExportPath"
    
                $JSON1 | Set-Content -LiteralPath "$ExportPath\$FileName_JSON"
                write-host "JSON created in $ExportPath\$FileName_JSON..." -f cyan
                
            }
    
        }
    
        catch {
    
        $_.Exception
    
        }
    
    }

    Function Get-SecretValue(){
    
        <#
        .SYNOPSIS
        This function is used to retrieve a secret value
        .DESCRIPTION
        This function is used to retrieve a secret value when a device configuration setting is encrypted
        .EXAMPLE
        Get-SecretValue -GUID $guid -SecretID $SecretID
        .NOTES
        NAME: Get-SecretValue
        #>
        
        param (
        
        [Parameter(Mandatory=$true)]$GUID,
        [Parameter(Mandatory=$true)]$SecretID
        
        )
        $graphApiVersion = "Beta"
        $DCP_resource = "deviceManagement/deviceConfigurations"
        try {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$GUID/getOmaSettingPlainTextValue(secretReferenceValueId='$SecretID')"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        } catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
    
        }


    }
    
    ####################################################
    
    #region Authentication
    
    write-host
    
    # Checking if authToken exists before running authentication
    if($global:authToken){
    
        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()
    
        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
    
            if($TokenExpires -le 0){
    
            write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            write-host
    
                # Defining User Principal Name if not present
    
                if($User -eq $null -or $User -eq ""){
    
                $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                Write-Host
    
                }
    
            $global:authToken = Get-AuthToken -User $User
    
            }
    }
    
    # Authentication doesn't exist, calling Get-AuthToken function
    
    else {
    
        if($User -eq $null -or $User -eq ""){
    
        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host
    
        }
    
    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
    
    }
    
    #endregion

    ####################################################

    #Check whether a single device policy was specified
    if($null -eq $ObjectGUID) {
        $SinglePolicy = $False
    } else {
        if($ObjectGUID.length -eq 0) {
            $SinglePolicy = $False
        } else {
            $SinglePolicy = $true
        }
    }
    
    ####################################################
    
    $ExportPath = Read-Host -Prompt "Please specify a path to export the policy data to e.g. C:\IntuneOutput"
    
        # If the directory path doesn't exist prompt user to create the directory
        $ExportPath = $ExportPath.replace('"','')
    
        if(!(Test-Path "$ExportPath")){
    
        Write-Host
        Write-Host "Path '$ExportPath' doesn't exist, do you want to create this directory? Y or N?" -ForegroundColor Yellow
    
        $Confirm = read-host
    
            if($Confirm -eq "y" -or $Confirm -eq "Y"){
    
            new-item -ItemType Directory -Path "$ExportPath" | Out-Null
            Write-Host
    
            }
    
            else {
    
            Write-Host "Creation of directory path was cancelled..." -ForegroundColor Red
            Write-Host
            break
    
            }
    
        }
    
    ####################################################
    
    Write-Host
    
    If($SinglePolicy -eq $True) {
        Write-Host "Retrieving settings for a single policy"
        $DCPs = Get-SingleDeviceConfigurationPolicy -GUID $ObjectGUID
        write-host $DCPs.GetType()
    } else {
        Write-Host "Retrieving settings for all policies"
        # Filtering out iOS and Windows Software Update Policies
        $DCPs = Get-DeviceConfigurationPolicy | Where-Object { ($_.'@odata.type' -ne "#microsoft.graph.iosUpdateConfiguration") -and ($_.'@odata.type' -ne "#microsoft.graph.windowsUpdateForBusinessConfiguration") }
    }
    foreach($DCP in $DCPs){
        write-host "Device Configuration Policy:"$DCP.displayName -f Yellow
        If($DCP.'@odata.type' -eq "#microsoft.graph.windows10CustomConfiguration") {
            Write-Host "Preparing Device Configuration Policy for Export"
  
            
            Foreach ($OMASetting in $DCP.omaSettings) {
                If($OMASetting.isEncrypted -eq $false) {
                    $OMASetting = $OMASetting | Select-Object '@odata.type',displayName,description,omaUri,value
                } else {
                    #Get the secret value
                    $PlainTextValue = Get-SecretValue -Guid $DCP.ID -SecretID $OMASetting.secretReferenceValueId
                    $OMASetting.Value = $PlainTextValue
                    $OMASetting = $OMASetting | Select-Object '@odata.type',displayName,description,omaUri,value
                }
            }
        }
        


        Write-Host "Exporting Device Configuration Policy"        
        Export-JSONData -JSON $DCP -ExportPath "$ExportPath"
        Write-Host
        
    }
    
    Write-Host