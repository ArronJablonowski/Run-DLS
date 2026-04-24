# Run-DLS.ps1
## Locate Files Containing Sensitive Data

**Run-DLS (Run Data Locator Script)** is a powerful PowerShell script designed to help you locate files containing sensitive data by analyzing file names and using regular 
expressions (RegEx) to examine file contents. This tool can assist in identifying various types of sensitive information, including passwords, credit card numbers, encryption 
keys, backups, archives, identification documents, source code, databases, emails, PCAPs, SSNs, and more.

## Key Features

- **Flexible Search Options**: Run-DLS allows you to search for specific terms within file names or content.
- **Targeted File Extensions**: You can specify which file types to include in your search.
- **Extensive Regex Patterns**: The script uses advanced regex patterns to identify sensitive data within files.
- **Detailed Output Reports**: Generated reports provide comprehensive details about the location and content of sensitive data.

## Example Usage

### Finding Files Containing Password Key Terms
By default, the script searches your user folder:
```powershell
.\Run-DLS.ps1 -Filename_Terms_Passwords -Find_Passwords_in_Files
```

### Setting a Custom Search Path
You can specify a target directory or share to narrow down your search:
```powershell
.\Run-DLS.ps1 -Filename_Terms_CardNumbers -Find_Card_Numbers_in_Files -SearchPath C:\Users\
```
```powershell
.\Run-DLS.ps1 -Filename_Terms_SSNs -Find_SSNs_in_Files -SearchPath \\HostName\C$\Users\
```

### Comprehensive Search
To perform a thorough search across multiple categories, you can combine various switches:
```powershell
.\Run-DLS.ps1 -Filename_Terms_Passwords -Filename_Terms_CardNumbers -Filename_Terms_SSNs -Filename_Terms_IDs -Filename_Terms_VPN_Keys -Filename_Terms_Encryption_Keys 
-Filename_Terms_Interesting -Filename_Terms_Network_Docs -Filename_Terms_Schematics -File_Extensions_Source_Code -File_Extensions_RDP_Files -File_Extensions_Password_DBs 
-File_Extensions_Email -File_Extensions_PCAPs -File_Extensions_Backups -File_Extensions_DBs -File_Extensions_Archives -File_Extensions_Logs -File_Extensions_MobleApps 
-Find_Passwords_in_Files -Find_Card_Numbers_in_Files -Find_SSNs_in_Files -SearchPath \\ServerName\SMB_Share\Path\
```

## Output
Run-DLS generates detailed CSV reports for each category of sensitive data found. These reports include the file path, filename, matched expression, and additional metadata 
such as creation and last write times.

## Security Best Practices
- **Review Generated Reports**: Carefully review the output files to identify any sensitive data.
- **Secure Sensitive Data Files**: Remove or secure identified sensitive data files as necessary.
- **Clean Up Output Files**: After reviewing, you can remove the script's output files using the `-Remove_Output_Files` switch.

## Additional Information
For more detailed usage instructions and examples, refer to the script documentation:
```powershell
Get-Help .\Run-DLS.ps1
```
or specifically for examples:
```powershell
Get-Help .\Run-DLS.ps1 -Examples
```
Set the `-SearchPath` to a target directory or share: 
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

![alt text](https://github.com/ArronJablonowski/Run-DLS/blob/main/ScriptOutput.png?raw=true)
