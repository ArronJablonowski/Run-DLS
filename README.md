# Run-DLS
Run-DLS (Run Data Locator Script) is a Powershell script to help locate files containing sensitive data by analyzing file names and using RegEx to analyze file content. 

Run-DLS can assist in finding files continaing: 
  * Passwords
  * Credit Card Numbers
  * Encrption & VPN Keys
  * Backups and Archives
  * Identifications
  * Source Code 
  * Databases
  * Emails
  * PCAPs
  * SSNs
  * etc.

Example Usage: 
* In Script Documentation, Examples, & Get Help 
```
Get-Help .\Run-DLS.ps1 -Examples
```
* Find Filenames containing Password Key Terms
```
.\Run-DLS.ps1 -Filename_Terms_Passwords
```
```
.\Run-DLS.ps1 -Filename_Terms_Passwords [-SearchPath <C:\Users\>]
```
```
.\Run-DLS.ps1 -Filename_Terms_Passwords [-SearchPath <\\HostName\C$\Users\>]
```
```
.\Run-DLS.ps1 -Filename_Terms_Passwords [-SearchPath <\\ServerName\SMB_Share\Path\">]
```
