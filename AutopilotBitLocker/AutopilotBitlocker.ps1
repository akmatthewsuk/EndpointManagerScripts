#Set this value to a path in HKLM
$BitLockerFlagPath = "HKLM:\Software\ModernDeploy\BitLocker"
$BitLockerBackupFlag = "BitLockerBackup"
$BitLockerCompleteFlag = "BitLockerComplete"

#Set the delay time before the encryption loop starts
$StartDelay = 60
#Set the wait time for the encryption loop in seconds
$LoopWaitTime = 30

#Create a Log file

$LogPath = "c:\Software\DeployLog"
$Logfile = "Win10BitLocker.log"
$LogFullPath = $LogPath + "\" + $Logfile
if (!(Test-Path $LogPath))
{
	New-Item -itemType Directory -Path $LogPath
	Start-Transcript -Path $LogFullPath -Append
}
else
{
	Start-Transcript -Path $LogFullPath -Append
}

#If the bitLocker flag path does not exist then create it
If (!(Test-Path $BitLockerFlagPath)) {
    New-Item $BitLockerFlagPath -Force | Out-Null
    $ProcessBitLocker = $true
    Write-Host "BitLocker Script not processed yet"
} else {
    #Check whether the BitLocker Complete flag is set
    $BitLockerCompleteFlagStatus = (Get-Item -Path $BitLockerFlagPath).getvalue($BitLockerCompleteFlag)
    if($null -eq $BitLockerCompleteFlagStatus) {
        $ProcessBitLocker = $true
        Write-Host "BitLocker Script not processed yet"
    } Else {
        $ProcessBitLocker = $false
        Write-Host "BitLocker Script already processed"
    }
}


If ($ProcessBitLocker -eq $true) {

    #Sleep to allow other policy activities to take place
    Write-Host "Waiting for $($StartDelay) seconds to ensure other policy items are processed before the script runs"
    Start-Sleep -Seconds $StartDelay

    #Set the loop flags
    $OSEncrypted = $false
    $LoopCount = 0
    $ExitLoop = $false
    Do {
        #Increment the Encryption loop
        $LoopCount = $LoopCount + 1
        Write-host "Encryption Detection Loop $($LoopCount)"
        
        #Get the the status of the System Drive encryption
        $BitlockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive

        If (!($null -eq $BitlockerVolume)) {
            #Continue processing BitLocker Encryption status

            Switch ($BitlockerVolume.VolumeStatus) {
                "FullyEncrypted" {
                    Write-Host "System Drive encryption is complete"
                    $OSEncrypted = $true
                }
                "EncryptionInProgress" {
                    Write-Host "System Drive encryption is in progress"
                    $OSEncrypted = $true
                }
                "FullyDecrypted" {
                    $OSEncrypted = $False
                    Write-Host "Operating System drive is not encrypted"
                    #If the drive is not encrypted then check the key protectors
                    If ($BitlockerVolume.KeyProtector.Count -eq 0) {
                        Write-Host "No Key Protectors found - Adding a key protectors"
                        #No key protectors present - Add Recovery key key protectors
                        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector | Out-Null
                        Write-Host "Enabling Encryption on the system drive"
                        #Enable BitLocker
                        Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest -TpmProtector
                    } else {
                        #Key protectors present - check the key protectors
                        $BitLockerRecoveryKeyProtectorExists = $False
                       
                        foreach ($KeyProtector in $BitlockerVolume.KeyProtector) {
                            If ($KeyProtector.KeyProtectorType -eq "RecoveryPassword") {
                                Write-host "Key Protector $($KeyProtector.KeyProtectorID) is a Recovery Key Protector"
                                $BitLockerRecoveryKeyProtectorExists = $True
                            }
                        }
                        If ($BitLockerRecoveryKeyProtectorExists -eq $false) {
                            Write-Host "No Recovery Key found - Adding a recovery key"
                            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector | Out-Null
                        }
                        Write-Host "Enabling Encryption on the system drive"
                        #Enable BitLocker
                        Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest -TpmProtector
                    }
                }
                default {
                    Write-Host "Encryption Status $($BitlockerVolume.VolumeStatus) is unknown - attempting another loop"
                }
            }
        } else {
            Write-Host "Encryption status returned a null value - attempting another loop"
        }

        #If OS Encryption is set the True then backup the recovery key to AAD
        If ($OSEncrypted -eq $true) {
            $BitLockerBackupFlagStatus = (Get-Item -Path $BitLockerFlagPath).getvalue($BitLockerBackupFlag)
            if($null -eq $BitLockerBackupFlagStatus) {
                Write-Host "Backing up BitLocker Key"
                $BLVOS = Get-BitLockerVolume -MountPoint $env:SystemDrive
                $BLRecoveryProtectorOS = ($BLVOS.KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"})
                BackupToAAD-BitLockerKeyProtector $env:SystemDrive -KeyProtectorId $BLRecoveryProtectorOS.KeyProtectorID
                #Add the registry entry
                New-ItemProperty -Path $BitLockerFlagPath -Name $BitLockerBackupFlag -Value "1" -PropertyType DWORD -Force | Out-Null
            } Else {
                Write-Host "BitLocker Key already Backed up Yet"
            }
        }

        #check the loop exit condition
        If ($OSEncrypted -eq $true) {
            $ExitLoop = $true
            Write-Host "Encryption check succeeded - Exiting the loop"

            #Update the BitLocker Complete flag
            New-ItemProperty -Path $BitLockerFlagPath -Name $BitLockerCompleteFlag -Value "1" -PropertyType DWORD -Force | Out-Null
        } else {
            If($LoopCount -eq 10) {
                $ExitLoop = $true
                Write-Host "Encryption check failed after ten loops - Exiting the loop"
            }
        }
        Start-Sleep -Seconds $LoopWaitTime

     } until ($ExitLoop -eq $true)
}

Stop-Transcript


    
        

        
        
    
 
    

 
 
 

 

 

#Stop the Log file
Stop-Transcript
