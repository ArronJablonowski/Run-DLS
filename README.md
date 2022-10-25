Run-DLS
=======
Run-DLS (Run Data Locator Script) is a Powershell script to help locate files containing sensitive data by analyzing file names and using RegEx to analyze file content. 

Run-DLS can assist in finding: 
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

## Example Usage: 
* In script documentation, examples, & Get Help 
```
Get-Help .\Run-DLS.ps1
```
```
Get-Help .\Run-DLS.ps1 -Examples
```

* Find file names containing Password key terms (by default the script with search your User folder) 
```
.\Run-DLS.ps1 -Filename_Terms_Passwords
```

* Set the SearchPath to search all user directories 
```
.\Run-DLS.ps1 -Filename_Terms_Passwords -SearchPath <C:\Users\>]
```

* Set the SearchPath to a file share path 
```
.\Run-DLS.ps1 -Filename_Terms_Passwords -SearchPath \\HostName\C$\Users\
```
```
.\Run-DLS.ps1 -Filename_Terms_Passwords -SearchPath \\ServerName\SMB_Share\Path\
```
