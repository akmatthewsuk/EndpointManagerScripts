<h1>NPS Device IDs</h1>
A solution to create Computer Objects in Active Directory to allow Network Policy Server to authenticate Azure AD Joined devices for 802.1x authentication.
<h2>Get-DeviceIDs.ps1</h2>
Function App code to retrieve a list of Azure AD Joined devices from Azure AD
<h2>New-ADDeviceIDs.ps1</h2>
Scheduled Task PowerShell script to create computer objects in Active Directory. Uses a config file (DeviceIDs.xml) to avoid editign the script.
