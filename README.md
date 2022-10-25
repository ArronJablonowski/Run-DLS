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

## Example Usage 
In script documentation, examples, & Get Help:
```Powershell
Get-Help .\Run-DLS.ps1
```
```Powershell
Get-Help .\Run-DLS.ps1 -Examples
```

Find files containing Password key terms (by default the script with search your User folder):
```Powershell
.\Run-DLS.ps1 -Filename_Terms_Passwords -Find_Passwords_in_Files
```

Set the SearchPath to a target directory or share: 
```Powershell
.\Run-DLS.ps1 -Filename_Terms_CardNumbers -Find_Card_Numbers_in_Files -SearchPath C:\Users\
```
```Powershell
.\Run-DLS.ps1 -Filename_Terms_SSNs -Find_SSNs_in_Files -SearchPath \\HostName\C$\Users\
```
```Powershell
.\Run-DLS.ps1 -Filename_Terms_Passwords -Find_Passwords_in_Files -SearchPath \\ServerName\SMB_Share\Path\
```
Hail Mary - Look for it all. 
```Powershell 
.\Run-DLS.ps1 -Filename_Terms_Passwords -Filename_Terms_CardNumbers -Filename_Terms_SSNs -Filename_Terms_IDs -Filename_Terms_VPN_Keys -Filename_Terms_Encryption_Keys -Filename_Terms_Interesting -Filename_Terms_Network_Docs -Filename_Terms_Schematics -File_Extensions_Source_Code -File_Extensions_RDP_Files -File_Extensions_Password_DBs -File_Extensions_Email -File_Extensions_PCAPs -File_Extensions_Backups -File_Extensions_DBs -File_Extensions_Archives -File_Extensions_Logs -File_Extensions_MobleApps -Find_Passwords_in_Files -Find_Card_Numbers_in_Files -Find_SSNs_in_Files -SearchPath \\ServerName\SMB_Share\Path\
```
