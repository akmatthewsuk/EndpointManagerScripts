<h1>Autopilot BitLocker</h1>
This script is a quick and dirty script to enable BitLocker on devices that did not start automatic encryption during Autopilot.

Most devices will automatically start encryption during autopilot enrolment except in the following circumstances.
* A hardware component blocks automatic encryption
* Hybrid devices (sometimes)
* The BitLocker did not apply

The script will encrypt the OS drive with XtsAES256 encryption using a TPM + Recovery Key. The Recovery Key will be escrowed to Azure AD for all devices where the script is run. This safeguards some scenarios where the Recovery Key does not get escrowed automatically (Hybrid devices in particular).

At some stage in the future I will improve this script to add detection for the Recovery Key being already escrowed to Azure AD and a few other improvements.
