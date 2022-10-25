# Run-DLS
Powershell script to help locate files containing sensitive data such as 
  * Passwords
  * Credit Card Numbers
  * Encrption & VPN Keys
  * Backups and Archives
  * Identifications
  * Source Code 
  * Data Bases
  * Emails
  * PCAPs
  * SSNs
  * etc.

Usage: 
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
