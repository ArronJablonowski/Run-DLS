<#
.SYNOPSIS
    Run-DLS.ps1   

    Run-DataLocatorScript helps locate files that contain sensitive information on Windows Systems and SMB Shares.  
    
    Use Run-DLS.ps1 to recursevely search directories and analyze file names and file content for potential sensitive data. 
    Then review the output of Run-DLS reports, and secure anything sensitive. 

.EXAMPLE
    Find Filenames containing Password Key Terms 
    PS> .\Run-DLS.ps1 -Filename_Terms_Passwords
    PS> .\Run-DLS.ps1 -Filename_Terms_Passwords [-SearchPath <C:\Users\>]
    PS> .\Run-DLS.ps1 -Filename_Terms_Passwords [-SearchPath <\\HostName\C$\Users\>]
    PS> .\Run-DLS.ps1 -Filename_Terms_Passwords [-SearchPath <"\\ServerName\SMB_Share\Path\">]

.EXAMPLE
    Switches for Finding Filename Key Terms:
    PS> .\Run-DLS.ps1 -Filename_Terms_SSNs [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Filename_Terms_Passwords [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Filename_Terms_CardNumbers [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Filename_Terms_Interesting [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Filename_Terms_IDs [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Filename_Terms_VPN_Keys [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Filename_Terms_Encryption_Keys [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Filename_Terms_Network_Docs [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Filename_Terms_Schematics [-SearchPath <Path>]

.EXAMPLE
    Switches for Finding File Extensions:     
    PS> .\Run-DLS.ps1 -File_Extensions_Source_Code [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -File_Extensions_RDP_Files [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -File_Extensions_Password_DBs [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -File_Extensions_Email [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -File_Extensions_PCAPs [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -File_Extensions_Backups [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -File_Extensions_DBs [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -File_Extensions_Archives [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -File_Extensions_Logs [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -File_Extensions_MobleApps [-SearchPath <Path>]

.EXAMPLE    
    Switches for Finding Terms Inside a File's Content:
    PS> .\Run-DLS.ps1 -Find_SSNs_in_Files [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Find_Passwords_in_Files [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Find_Card_Numbers_in_Files [-SearchPath <Path>]
    PS> .\Run-DLS.ps1 -Find_Email_Addresses_in_Files [-SearchPath <Path>]


.EXAMPLE
    Switch to Delete results (.csv) files 
    PS> .\Run-DLS.ps1 -Remove_Output_Files 

.EXAMPLE
    Switch to List Mounted File Systems 
    PS> .\Run-DLS.ps1 -List_Attached_Storage

.LINK 
    Dependencies:
    - 7Zip -- to read inside of XLSX & DOCX files 
        7z.exe & 7z.dll must be in the script's root folder. 
            Home: https://www.7-zip.org/ 
            Downloads Page: https://www.7-zip.org/download.html          [7-Zip Extra: standalone console version, 7z DLL, etc.] 
            Download: https://www.7-zip.org/a/7z1900-extra.7z   
                        (Extract 7z.exe & 7z.dll to this script's root directory)

    - Pdf to Text -- to read inside of PDF files 
        pdftotxt.exe must be in the script's root folder. 
            Home: http://www.xpdfreader.com/index.html
            Downloads Page: http://www.xpdfreader.com/download.html      [Download the Xpdf command line tools for Windows]
            Download: https://dl.xpdfreader.com/xpdf-tools-win-4.03.zip  
                        (Extract pdftotext.exe to this script's root directory)

.NOTES
    Tips: 
        - Open in Excel and sort by filename or hash value to see file proliferation. 
        - Evaluate more than just the matched RegEx. 
            --- Is it logical a user placed something in the file/directory, or is the discovery more likely to be a useless file? 
        - Make UNC Path clickable in Excel for faster investigation/navigation to file location: 
            --- Open the reports in Excel and double click the UNC path. Move your currsor to the end of the path string, then hit ENTER to move the next cell down. 
            --- This should make the path clickable. Opening either the file itself or an Explorer window to that file's location.

#>
    
[CmdletBinding()]
Param (
    ### Find File Name Switches ### 
    [Parameter(Mandatory=$false)]
    [switch]$Filename_Terms_Passwords,               # Password Terms
    [Parameter(Mandatory=$false)]
    [switch]$Filename_Terms_CardNumbers,             # Card Number Terms
    [Parameter(Mandatory=$false)]
    [switch]$Filename_Terms_SSNs,                    # SSN Terms
    [Parameter(Mandatory=$false)]
    [switch]$Filename_Terms_IDs,                     # ID Terms
    [Parameter(Mandatory=$false)]    
    [switch]$Filename_Terms_VPN_Keys,                # VPN Key Terms
    [Parameter(Mandatory=$false)]    
    [switch]$Filename_Terms_Encryption_Keys,         # Encryption Key Terms
    [Parameter(Mandatory=$false)]
    [switch]$Filename_Terms_Interesting,             # Interesting Terms 
    [Parameter(Mandatory=$false)]
    [switch]$Filename_Terms_Network_Docs,            # Networking Documents 
    [Parameter(Mandatory=$false)]
    [switch]$Filename_Terms_Schematics,              # Schematics    
    
    ### Find File Extension Switches ###
    [Parameter(Mandatory=$false)]
    [switch]$File_Extensions_Source_Code,            # Source Code Extensions 
    [Parameter(Mandatory=$false)]
    [switch]$File_Extensions_RDP_Files,              # RDP Extensions 
    [Parameter(Mandatory=$false)]
    [switch]$File_Extensions_Password_DBs,           # Password DB Extensions
    [Parameter(Mandatory=$false)]
    [switch]$File_Extensions_Email,                  # Email file Extensions 
    [Parameter(Mandatory=$false)]
    [switch]$File_Extensions_PCAPs,                  # PCAP Extensions
    [Parameter(Mandatory=$false)]
    [switch]$File_Extensions_Backups,                # Backups Extensions
    [Parameter(Mandatory=$false)]                   
    [switch]$File_Extensions_DBs,                    # DB Extensions
    [Parameter(Mandatory=$false)]
    [switch]$File_Extensions_Archives,               # Archive Extensions
    [Parameter(Mandatory=$false)]
    [switch]$File_Extensions_Logs,                   # Log File Extension 
    [Parameter(Mandatory=$false)]
    [switch]$File_Extensions_MobleApps,              # Mobile App Extensions 

    ### Find Key Terms In File's Content Switches ###
    [Parameter(Mandatory=$false)]
    [switch]$Find_Passwords_in_Files,                # Passwords in Files
    [Parameter(Mandatory=$false)]
    [switch]$Find_Card_Numbers_in_Files,             # Card Numbers in Files 
    [Parameter(Mandatory=$false)]
    [switch]$Find_SSNs_in_Files,                     # SSN in Files 
    [Parameter(Mandatory=$false)]
    [switch]$Find_Email_Addresses_in_Files,          # Find Email Addresses 

    ### SCRIPT OPTIONS ###
    [Parameter(Mandatory=$false)]    
    [string]$search_Path="C:\Users\$env:UserName\",  # if path not specified, audit C:\Users\{CURRENT_USER}\ 
    [Parameter(Mandatory=$false)]
    [switch]$Remove_Output_Files,                    # Remove Old Output Files 
    [Parameter(Mandatory=$false)]    
    [switch]$List_Attached_Storage                   # List Mounted Drives, File Shares, & File Storage Locations 
)

# Limit Output File Size - Change as needed 
$limitOutputFileSize = '30mb'  # attempt to limit file size - IF one file contains a lot of information, the limit will be exceeded. 

# Set Error Action 
$erroractionpref = "SilentlyContinue"

# Controls the ending message to user - If work has been done = 1 / No work done = 0 
$workdone = 0

$outputFile

# Terms to Search for in File Names (uses Where-Object $_.name -match $patternFileNames)
# ======================================================================================
# Passwords 
$patternFileNamesPw = "pass|protected|secure|access|locked|credential|creds|account|usr|user|root|admin|login|logon|ftp|ssh|vnc|scp|rdp|VPN|WiFi|wi-fi|wi_fi|Wireless"
# card numbers 
$patternFileNamesCC = "credit|debit|card|acct|account|cc#|cc #|ccnum|cc num|Mastercard|AMEX|Visa|AmericanExpress|American Express|American-Express|American_Express|Discover"
# SSNs
$patternFileNamesSSNs = "social security|socialsecurity|social_security|social-security|ssn|ss-n|ss_n|ss num|ss #|ss_#|ss-#|ss#"
# IDs
$patternFileNamesIDs = "passport|pass port|pass-port|pass_port|Drivers_License|Drivers-License|Driver License|Drivers License|DriversLicense|DriverLicense|badge|CorpID|CorporateID|Identification"
# Terms of Interest 
#$patternFileNamesOfInterest = "confidential|secret|private|w2|w-2|w_2|w4|w-4|w_4|1099|bank|routing|earnings|profit|loss|income|pay|cash|budget|balance|insurance|insure|cyber|Policy|PCI|OfferLeter|Offer_letter|Offer-letter|Offer Letter|customer|rewards|resume|covid|severance|salary|terminated|reconciliation"
$patternFileNamesOfInterest = "customer|loyalty|reward|email"
# Schematics Key Terms 
$patternFileNamesSchematics = "diagram|schematic|sitemap|site map|data flow|dataflow|backup|layout"
# Network Document Key Terms 
$patternFileNamesNetworkDocs = "network|firewall|fire_wall|fire wall|switch|data center|data_center|datacenter|datalake|data lake|router|switch|wireless|ssid|gateway|IDS|IPS|net flow|netflow|disaster|recovery|backup|fail over|failover|vlan|lan|wan"
# Encryption Key Terms 
$patternFileNamesEncryptionKeys = "rsa|ecdsa|dsa|ed25519|id_|identity|IdentityFile|ssh|ssl|cert"  
# VPN Key Terms 
$patternFileNamesVPNKeys = "OpenVPN|VPN"

# File Extensions to Search for 
# =============================
# Encryption Key File Extensions 
$patternFileExtensionEncryptionKeys = "pub|priv|gpg|pgp|key|sig|asc|pem|crt|cert|p12|panrc|cer|csr"
# VPN Key File Extensions 
$patternFileExtensionVPNKeys = "ovpn|vpn"  
# Remote Desktop Files 
$patternFileExtensionRDP = "rdp"  
# Password DB Extensions 
$patternFileExtensionPasswordDBs = "kdbx|kdb"
# Source Code Extensions 
$patternFileExtensionSourceCode = "cmd|bat|batch|vbs|ps1|ps1m|py|sh"
# Email Extensions 
$patternFileExtensionEmail = "pst|eml"
# Network Capture Files 
$patternFileExtensionPCAP = "pcap|cap"
# Backups 
$patternFileExtensionBackups = "bak|bac|back"
# Data Bases 
$patternFileExtensionDBs = "sql|SQLite|db|mdb|csv|mar|dtsx|accdc|accdb|accdt|ade|adp|awdb|cdb|cma|gdb|mdf|ndf|ov|pdb|pdt|pho|ssd|usr|wd2|zbd"
# log files 
$patternFileExtensionLogs = "log"
# Archives 
$patterFileExtensionArchives = "zip|7z|tar|iso|bz2|gz|lz|rz|xz|zst|dmg|dd|jar|rar|war|wim|zz"
# MObile Applications 
$patternFileExtensionMobileApps = "APK|IPA"


# Terms & Regex to Search for in File's Content (Read/Match Content of File)
# ==========================================================================
# Array of Terms to Search for Accounts & Passwords inside of files 
$patternPasswords = @('password','pass word','passwd','pass:','username','user:','user name','root','admin','login','logon','passphrase','creds','credential','secret','WiFi','Wi-Fi','Wi_Fi','Wireless')

# Array of Card Number Regex 
$patternCardData = @(
    # Generic CC numbers
    '[4|5|3|6][0-9]{15}|[4|5|3|6][0-9]{3}[-| ][0-9]{4}[-| ][0-9]{4}[-| ][0-9]{4}',
    # Visa, Discover, and MasterCard 
    '[456][0-9]{3}[-| ][0-9]{4}[-| ][0-9]{4}[-| ][0-9]{4}',
    # American Express
    '3[47][0-9]{13}","3[47][0-9]{2}[-| ][0-9]{6}[-| ][0-9]{5}',
    '^3[47][0-9]{13}$',
    # Visa
    '^4[0-9]{12}(?:[0-9]{3})?$',
    '([^0-9\.-]|^)(4[0-9]{3}( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9\.-]|$)',
    # MasterCard
    '^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$',
    '([^0-9\.-]|^)((222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[0-1][0-9]|2720|5[1-5][0-9]{2})( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9\.-]|$)',
    # Discover 
    '^6(?:011|5[0-9]{2})[0-9]{12}$',
    '([^0-9\.-]|^)((6011|6[45][0-9]{2})( |-|)[0-9]{4}( |-|)[0-9]{4}( |-|)[0-9]{4})([^0-9\-]|$)'
)

# Array of SSN Regex & Key Words
$patternSSN = @(
    #This pattern searches for SSNs in the "XXX-XX-XXXX" and "XXX XX XXXX" format
    '[0-9]{3}[-| ][0-9]{2}[-| ][0-9]{4}'
    
    #This pattern searches for SSNs without dashes or spaces, i.e. "XXXXXXXXX"
    # '[0-9]{9}',   # !!! WARNING !!! This is very verbose as it is just searching for any 9 digit numbers. Therefore I have it commented out 
   
    # SSN Key Terms - Can be helpful if SSNs are not in above format, but can also be verbose 
    # 'ssn',
    # 'ss#',
    # 'ss #', 
    # 'SS-#',
    # 'SS_#',
    # 'security number',
    # 'security-number',
    # 'security_number',
    # 'security #',
    # 'security-#',
    # 'security_#',
    # 'social security',
    # 'socialsecurity', 
    # 'social-security',
    # 'social_security'
)

$patternEmailAddress = @(
    # Basic regex for standard email addresses (this will ommit emails with special characters and IP addresses) 
    '^([\w-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$',
    '\w+@\w+\.\w+|\w+\.\w+@\w+\.\w+\.\w+',
    # List of email domains to look for: 
    '@gmail.com',
    '@yahoo',
    '@yandex.ru', 
    '@aol.com', 
    '@hotmail.com',
    '@live.com',
    '@outlook.com',
    '@msn.com', 
    '@att.net',
    '@facebook.com',
    '@earthlink.net'
)

# Create Output File Names 
# ========================
# get host name for output file's name 
$hostName = $env:COMPUTERNAME
# Set Output path to current script directory 
$outPutFilePathHost = "$PSScriptRoot\$hostName"
# Password key terms in filename 
$outputFileNameTermPasswords = "$outputFilePathHost`_Filename_Key_Terms_Passwords.csv"
# Card data key terms in filename  
$outputFileNameTermsCardNums = "$outputFilePathHost`_Filename_Key_Terms_CardNumbers.csv"
# SSN key terms in filename  
$outputFileNameTermsSSNs = "$outputFilePathHost`_Filename_Key_Terms_SSNs.csv"
# ID Key terms in filename 
$outputFileNameTermsIDs = "$outputFilePathHost`_Filename_Key_Terms_IDs.csv"
# Encryption Key terms in filename  
$outputFileNameEncryptionKeys = "$outputFilePathHost`_Filename_Key_Terms_Encryption_Keys.csv"
# VPN Key term  
$outputFileNameVPNKeys = "$outputFilePathHost`_Filename_Key_Terms_VPN_Keys.csv"
# Interesting File Names 
$outputFileNameTermInterest = "$outputFilePathHost`_Filename_Key_Terms_Interesting.csv"
# Schematic key terms 
$outputFileNameSchematics = "$outputFilePathHost`_Filename_Key_Terms_Schematic.csv"
# Networking Docs key terms 
$outputFileNameNetworkingDocs = "$outputFilePathHost`_Filename_Key_Terms_NetworkingDocs.csv"

# Email Extensions 
$outputFileNameEmailFiles = "$outputFilePathHost`_File_Extension_Email.csv"
# PCAP Extensions  
$outputFileNamePCAPFiles = "$outputFilePathHost`_File_Extension_PCAPs.csv"
# RDP Extensions 
$outputFileNameRDP = "$outputFilePathHost`_File_Extension_RDP_Files.csv"
# Code extensions 
$outputFileNameSourceCode = "$outputFilePathHost`_File_Extension_Source_Code.csv"
# Password DB Extensions 
$outputFileNamePasswordDBs = "$outputFilePathHost`_File_Extension_Password_DBs.csv"
# Backup Extensions 
$outputFileNameBackupFiles = "$outputFilePathHost`_File_Extension_Backups.csv"
# DB extensions 
$outputFileNameDBs = "$outputFilePathHost`_File_Extension_DBs.csv"
# Archive extensions 
$outputFileNameArchives = "$outputFilePathHost`_File_Extension_Archives.csv"
# Log Files 
$outputFileNameLogs = "$outputFilePathHost`_File_Extension_Log.csv"
# Mobile Apps 
$patternFileExtensionMobileApps = "$outputFilePathHost`_File_Extension_MobileApps.csv"

# Password Files  
$outputPasswordFiles = "$outputFilePathHost`_Potential_Password_Files.csv" 
# Card data in file content 
$outputCardNumberFiles = "$outputFilePathHost`_Potential_CardData_Files.csv"
# SSNs in file content 
$outputSSNFiles = "$outputFilePathHost`_Potential_SSN_Files.csv"
# Email Addresses in file content (multiple output files due to verbosity of reporting)
$outputEmailAddressTxtFiles = "$outputFilePathHost`_Potential_Email_Addr_TxtFiles.csv"
$outputEmailAddressDocXlsFiles = "$outputFilePathHost`_Potential_Email_Addr_DocXlsFiles.csv"
$outputEmailAddressXlsxFiles = "$outputFilePathHost`_Potential_Email_Addr_XlsxFiles.csv"
$outputEmailAddressDocxFiles = "$outputFilePathHost`_Potential_Email_Addr_DocxFiles.csv"
$outputEmailAddressPdfFiles = "$outputFilePathHost`_Potential_Email_Addr_PdfFiles.csv"

# EXCLUDE FILEs - Don't Read these files - Add any additional exclusions to this list. 
# =====================================================================================
$excludeFiles = @(
    # Don't Search Reporting Files 
    "$outputFileNameTermPasswords",
    "$outputFileNameTermsCardNums",
    "$outputFileNameTermsSSNs",
    "$outputFileNameTermsIDs",
    "$outputFileNameEncryptionKeys",
    "$outputFileNameVPNKeys",
    "$outputFileNameTermInterest",
    "$outputFileNameSchematics",
    "$outputFileNameNetworkingDocs",
    "$outputFileNameEmailFiles",
    "$outputFileNamePCAPFiles",
    "$outputFileNameRDP",
    "$outputFileNameSourceCode",
    "$outputFileNamePasswordDBs",
    "$outputFileNameBackupFiles",
    "$outputFileNameDBs",
    "$outputFileNameArchives",
    "$outputFileNameLogs",
    "$patternFileExtensionMobileApps",
    "$outputPasswordFiles",
    "$outputCardNumberFiles",
    "$outputSSNFiles",
    "$outputEmailAddressFiles",
    # Additional Exclusions: 
    '*_SomeFileIDontWantToSee.csv'
)

# Luhn Check for Found CC Numbers - This will cut down on the false positives by verifying if the found number passes the Luhn check. 
function LuhnCheck($number) { 
    If(-not ([string]::IsNullOrEmpty($number))) {
        #Clean up number 
        $number = $number.Trim();       
        $number = $number.replace(' ','');  
        $number = $number.replace('-','');  
        $number = $number.replace('|','');  
        $number = $number -replace '[^0-9]' 
        #Convert String to Character Array 
        $temp = $Number.ToCharArray();
        $numbers = @(0) * $Number.Length;
        $alt = $false;
        for($i = $temp.Length -1; $i -ge 0; $i--) {
        $numbers[$i] = [int]::Parse($temp[$i])
        if($alt){
            $numbers[$i] *= 2
            if($numbers[$i] -gt 9) { 
                $numbers[$i] -= 9 
            }
        }
        $sum += $numbers[$i]
        $alt = !$alt
        }
        return ($sum % 10) -eq 0 # returns true or false 
    }
}

function removeNumberFromEndOfFileName($baseFileName){ 
    # Strip up to 5 #s from end of file name 
    if(($baseFileName.substring($baseFileName.length - 5)) -match "^\d+$"){ # If the last chars are an int (#)
         # Remove the last 5 Chars (#) from the basename 
         $newFileName = $baseFileName.Substring(0,$baseFileName.Length-5)
         return $newFileName
    }elseif(($baseFileName.substring($baseFileName.length - 4)) -match "^\d+$"){ # If the last chars are an int (#)
         # Remove the last 4 Chars (#) from the basename 
         $newFileName = $baseFileName.Substring(0,$baseFileName.Length-4)
         return $newFileName
    }elseif(($baseFileName.substring($baseFileName.length - 3)) -match "^\d+$"){ # If the last chars are an int (#)
         # Remove the last 3 Chars (#) from the basename 
         $newFileName = $baseFileName.Substring(0,$baseFileName.Length-3)
         return $newFileName
    }elseif(($baseFileName.substring($baseFileName.length - 2)) -match "^\d+$"){ # If the last chars are an int (#)
         # Remove the last 2 Chars (#) from the basename 
         $newFileName = $baseFileName.Substring(0,$baseFileName.Length-2)
         return $newFileName
    }elseif(($baseFileName.substring($baseFileName.length - 1)) -match "^\d+$"){ # If the last chars are an int (#)
         # Remove the last Char (#) from the basename 
         $newFileName = $baseFileName.Substring(0,$baseFileName.Length-1)
         return $newFileName
    }else{
        # Else return the file name as is - because no numbers need removing from end of filename  
         return $baseFileName
    }

}

function changeOutputFileName($inputFilePathName) {
    Write-Host "     -- OUTPUT FILE HAS EXCEEDED THE SIZE LIMIT "
    $filesFullPath = Get-ChildItem $inputFilePathName # get the full path of the output file 
    $baseName = $filesFullPath.BaseName # Base name without extension 
    $extension = $filesFullPath.Extension # extension With '.'

    # Send $basename to function to remove any numbers from end of filename 
    $baseName = removeNumberFromEndOfFileName $baseName

    for ($i = 1 ; $i -le 99999 ; $i++){   
        #Append number to filename
        $newFileName = $baseName+"$i"+$extension 
        # Test if file exists in loop. 
        If(!(test-path "$PSScriptRoot\$newFileName")){
            Write-Host "     -- WRITING TO NEW OUTPUT FILE : $newFileName "
           # Write-Host "$PSScriptRoot\$newFileName"
            return "$PSScriptRoot\$newFileName"

        }
    }

}

#========================#
# FUCTIONS TO READ FILES #
#========================#

# TEXT Based files - .txt, .csv 
#==============================
function searchTextFiles($pattern, $search_Path, $outputFile, $Luhn) {
    Get-ChildItem -Recurse -file -path $search_Path -Include *.txt, *.csv -Exclude $excludeFiles -ErrorAction $erroractionpref | 
    ForEach-Object {         
       # Check output file size, and call 'changeOutputFileName' if larget than X ($limitOutputFileSize - file size limit set at top of script)
        If (Test-Path $outputFile) { # If File Output File Exists 
            If ((Get-Item $outputFile).length -gt $limitOutputFileSize) { # If Output lile larger than X 
                # Chnage the outputfile's name - append a # to the name 
                $newOutputFile = changeOutputFileName $outputFile 
                $outputFile = $newOutputFile
            }
        }

        Select-String -pattern $pattern -Path $PSItem.FullName | 
        ForEach-Object { 
                # Build UNC Path 
                $uncpath = "\\"+$PSItem.Path   # File's full path 
                # $uncpath = $uncpath.Replace(':','$')                 # Replace ':' with '$' to format the unc path   
                $uncpath = $uncpath.Replace($PSItem.Filename,'')     # Replace the File's name in the unc path to display the Directory containing the file

                if ($Luhn -eq $true ){
                    if (LuhnCheck($PSItem.Matches).Value -eq $true){  #Only report card numbers that pass the Luhn Check 
                        Select-Object -InputObject $PSItem -Property Path, Filename,   
                        @{Name = 'MatchedExpression';Expression = {("``  "+ $PSItem.Matches)}},
                        @{Name = 'PassedLuhnCheck';Expression = {(LuhnCheck($PSItem.Matches).Value)}},
                        @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $PSItem.Path).BaseName}},
                        @{Name = 'Extension';Expression = {(Get-ChildItem -Path $PSItem.Path).Extension}},
                        @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $PSItem.Path).Length}},
                        @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $PSItem.Path).CreationTime}},
                        @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $PSItem.Path).LastWriteTime}},             
                        @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},
                        @{Name = 'UNCpath';Expression = {$uncpath}} 
                    }
                }
                else {
                    Select-Object -InputObject $PSItem -Property Path, Filename,   
                    @{Name = 'MatchedExpression';Expression = {("``  "+ $PSItem.Matches)}},
                    @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $PSItem.Path).BaseName}},
                    @{Name = 'Extension';Expression = {(Get-ChildItem -Path $PSItem.Path).Extension}},
                    @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $PSItem.Path).Length}},
                    @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $PSItem.Path).CreationTime}},
                    @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $PSItem.Path).LastWriteTime}},             
                    @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},
                    @{Name = 'UNCpath';Expression = {$uncpath}} 
                }    
        } | Export-Csv -Path $outputFile -NoTypeInformation -Append
    }   
}

# Script Files - .ps1, .cmd, .bat, .batch, .vbs, .py, .sh, *.rb
#==============================================================
function searchScriptFiles($pattern, $search_Path, $outputFile, $Luhn) {
    Get-ChildItem -Recurse -file -path $search_Path -Include *.ps1, *.cmd, *.bat, *.batch, *.vbs, *.py, *.sh, *.rb -Exclude $excludeFiles -ErrorAction $erroractionpref | 
    ForEach-Object { 
        # Check output file size, and call 'changeOutputFileName' if larget than X ($limitOutputFileSize - file size limit set at top of script)
        If (Test-Path $outputFile) { # If File Output File Exists 
            If ((Get-Item $outputFile).length -gt $limitOutputFileSize) { # If Output lile larger than X 
                # Chnage the outputfile's name - append a # to the name 
                $newOutputFile = changeOutputFileName $outputFile 
                $outputFile = $newOutputFile
            }
        }
        
        Select-String -pattern $pattern -Path $PSItem.FullName | 
        ForEach-Object {
                # Build UNC Path 
                $uncpath = "\\"+$PSItem.Path   # File's full path 
                # $uncpath = $uncpath.Replace(':','$')                 # Replace ':' with '$' to format the unc path   
                $uncpath = $uncpath.Replace($PSItem.Filename,'')     # Replace the File's name in the unc path to display the Directory containing the file

                if ($Luhn -eq $true ){ 
                    if (LuhnCheck($PSItem.Matches).Value -eq $true){  #Only report card numbers that pass the Luhn Check 
                        Select-Object -InputObject $PSItem -Property Path, Filename,   
                        @{Name = 'MatchedExpression';Expression = {("``  "+ $PSItem.Matches)}},
                        @{Name = 'PassedLuhnCheck';Expression = {(LuhnCheck($PSItem.Matches).Value)}},
                        @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $PSItem.Path).BaseName}},
                        @{Name = 'Extension';Expression = {(Get-ChildItem -Path $PSItem.Path).Extension}},
                        @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $PSItem.Path).Length}},
                        @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $PSItem.Path).CreationTime}},
                        @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $PSItem.Path).LastWriteTime}},             
                        @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},
                        @{Name = 'UNCpath';Expression = {$uncpath}} 
                    }
                }
                else {
                    Select-Object -InputObject $PSItem -Property Path, Filename,   
                    @{Name = 'MatchedExpression';Expression = {("``  "+ $PSItem.Matches)}},
                    @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $PSItem.Path).BaseName}},
                    @{Name = 'Extension';Expression = {(Get-ChildItem -Path $PSItem.Path).Extension}},
                    @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $PSItem.Path).Length}},
                    @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $PSItem.Path).CreationTime}},
                    @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $PSItem.Path).LastWriteTime}},             
                    @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},
                    @{Name = 'UNCpath';Expression = {$uncpath}} 
                }    
        } | Export-Csv -Path $outputFile -NoTypeInformation -Append
    } # | Export-Csv -Path $outputFile -NoTypeInformation -Append  
}

# Script Config Files - .conf, .config, .ini, .xml, .json 
#========================================================
function searchScriptConfigFiles($pattern, $search_Path, $outputFile, $Luhn) {
    Get-ChildItem -Recurse -file -path $search_Path -Include *.conf, *.config, *.ini, *.xml, *.json -Exclude $excludeFiles -ErrorAction $erroractionpref | 
    ForEach-Object {
        # Check output file size, and call 'changeOutputFileName' if larget than X ($limitOutputFileSize - file size limit set at top of script)
        If (Test-Path $outputFile) { # If File Output File Exists 
            If ((Get-Item $outputFile).length -gt $limitOutputFileSize) { # If Output lile larger than X 
                # Chnage the outputfile's name - append a # to the name 
                $newOutputFile = changeOutputFileName $outputFile 
                $outputFile = $newOutputFile
            }
        }
        
        Select-String -pattern $pattern -Path $PSItem.FullName | 
        ForEach-Object { 
                # Build UNC Path 
                $uncpath = "\\"+$PSItem.Path   # File's full path
                # $uncpath = $uncpath.Replace(':','$')                 # Replace ':' with '$' to format the unc path   
                $uncpath = $uncpath.Replace($PSItem.Filename,'')     # Replace the File's name in the unc path to display the Directory containing the file

                if ($Luhn -eq $true ){ 
                    if (LuhnCheck($PSItem.Matches).Value -eq $true){  #Only report card numbers that pass the Luhn Check 
                        Select-Object -InputObject $PSItem -Property Path, Filename,   
                        @{Name = 'MatchedExpression';Expression = {("``  "+ $PSItem.Matches)}},
                        @{Name = 'PassedLuhnCheck';Expression = {(LuhnCheck($PSItem.Matches).Value)}},
                        @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $PSItem.Path).BaseName}},
                        @{Name = 'Extension';Expression = {(Get-ChildItem -Path $PSItem.Path).Extension}},
                        @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $PSItem.Path).Length}},
                        @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $PSItem.Path).CreationTime}},
                        @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $PSItem.Path).LastWriteTime}},             
                        @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},
                        @{Name = 'UNCpath';Expression = {$uncpath}} 
                    }
                }
                else {
                    Select-Object -InputObject $PSItem -Property Path, Filename,   
                    @{Name = 'MatchedExpression';Expression = {("``  "+ $PSItem.Matches)}},
                    @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $PSItem.Path).BaseName}},
                    @{Name = 'Extension';Expression = {(Get-ChildItem -Path $PSItem.Path).Extension}},
                    @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $PSItem.Path).Length}},
                    @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $PSItem.Path).CreationTime}},
                    @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $PSItem.Path).LastWriteTime}},             
                    @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},
                    @{Name = 'UNCpath';Expression = {$uncpath}} 
                }    
        } | Export-Csv -Path $outputFile -NoTypeInformation -Append
    } # | Export-Csv -Path $outputFile -NoTypeInformation -Append  
}

# OLD MS OFFICE Formats - .doc & .xls 
#====================================
function searchDocXlsFiles($pattern, $search_Path, $outputFile, $Luhn) {
    Get-ChildItem -Recurse -file -path $search_Path -Include *.doc, *.xls -Exclude $excludeFiles -ErrorAction $erroractionpref | 
    ForEach-Object { 
        # Check output file size, and call 'changeOutputFileName' if larget than X ($limitOutputFileSize - file size limit set at top of script)
        If (Test-Path $outputFile) { # If File Output File Exists 
            If ((Get-Item $outputFile).length -gt $limitOutputFileSize) { # If Output lile larger than X 
                # Chnage the outputfile's name - append a # to the name 
                $newOutputFile = changeOutputFileName $outputFile 
                $outputFile = $newOutputFile
            }
        }
        
        Select-String -pattern $pattern -Path $PSItem.FullName | 
        ForEach-Object { 
                #Build UNC Path 
                $uncpath = "\\"+$PSItem.Path   # File's full path
                # $uncpath = $uncpath.Replace(':','$')                 # Replace ':' with '$' to format the unc path   
                $uncpath = $uncpath.Replace($PSItem.Filename,'')     # Replace the File's name in the unc path to display the Directory containing the file
                if ($Luhn -eq $true ){ 
                    if (LuhnCheck($PSItem.Matches).Value -eq $true){  #Only report card numbers that pass the Luhn Check 
                        Select-Object -InputObject $PSItem -Property Path, Filename,   
                        @{Name = 'MatchedExpression';Expression = {("``  "+ $PSItem.Matches)}},
                        @{Name = 'PassedLuhnCheck';Expression = {(LuhnCheck($PSItem.Matches).Value)}},
                        @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $PSItem.Path).BaseName}},
                        @{Name = 'Extension';Expression = {(Get-ChildItem -Path $PSItem.Path).Extension}},
                        @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $PSItem.Path).Length}},
                        @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $PSItem.Path).CreationTime}},
                        @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $PSItem.Path).LastWriteTime}},             
                        @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},                    
                        @{Name = 'UNCpath';Expression = {$uncpath}}  
                    }
                } 
                else {
                    Select-Object -InputObject $PSItem -Property Path, Filename,   
                    @{Name = 'MatchedExpression';Expression = {("``  "+ $PSItem.Matches)}},
                    @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $PSItem.Path).BaseName}},
                    @{Name = 'Extension';Expression = {(Get-ChildItem -Path $PSItem.Path).Extension}},
                    @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $PSItem.Path).Length}},
                    @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $PSItem.Path).CreationTime}},
                    @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $PSItem.Path).LastWriteTime}},             
                    @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},                    
                    @{Name = 'UNCpath';Expression = {$uncpath}}  
                }
        }   | Export-Csv -Path $outputFile -NoTypeInformation -Append        
    } # | Export-Csv -Path $outputFile -NoTypeInformation -Append          
}

# WORD - .docx 
#=============
function searchWordFiles($pattern, $search_Path, $outputFile, $Luhn) {
    Get-ChildItem -Recurse -file -Path $search_Path -Include *.docx -Exclude $excludeFiles -ErrorAction $erroractionpref | 
        ForEach-Object {
            # Check output file size, and call 'changeOutputFileName' if larget than X ($limitOutputFileSize - file size limit set at top of script)
            If (Test-Path $outputFile) { # If File Output File Exists 
                If ((Get-Item $outputFile).length -gt $limitOutputFileSize) { # If Output lile larger than X 
                    # Chnage the outputfile's name - append a # to the name 
                    $newOutputFile = changeOutputFileName $outputFile 
                    $outputFile = $newOutputFile
                }
            }

            $fullPath = $_.FullName
            $filename = $_.Name
            $unzippedPath = "$env:temp\unzipped" # Where to expand/extract the Xlsx files into xml files 
            # Build UNC Path      
            $uncpath = "\\"+$_.FullName   # File's full path 
            #$uncpath = $uncpath.Replace(':','$')              # Replace ':' with '$' to format the unc path             
            $uncpath = $uncpath.Replace($filename ,'')        # Replace the File's name in the unc path to display the Directory containing the file
    
            # Create Temp Folder to hold Docx files 
            If(!(Test-Path -Path $unzippedPath)) {New-Item -Path $env:temp -Name "unzipped" -ItemType Directory -Force}
            #Removed any old content from the directory 
            remove-item -Path "$unzippedPath\*" -Recurse -Force
    
            # Unzip the file into it raw XML files 
            Start-Process -FilePath "$PSScriptRoot\7z.exe" -ArgumentList " x ""$fullPath"" -o""$unzippedPath"" -y" -Wait -WindowStyle Hidden
            Start-Sleep -Milliseconds 500    
    
            If (Test-Path -Path "$unzippedPath\word\document.xml") {    
                Select-String -pattern $pattern -Path "$unzippedPath\word\document.xml" |
                ForEach-Object {                     
                    if ($Luhn -eq $true ){ 
                            if (LuhnCheck($PSItem.Matches).Value -eq $true){  #Only report card numbers that pass the Luhn Check 
                                Select-Object -InputObject $_ -Property @{Name = 'Path';Expression = {$fullPath}},
                                @{Name = 'Filename';Expression = {$filename}},
                                @{Name = 'MatchedExpression';Expression = {("`` "+$_.Matches)}},
                                @{Name = 'PassedLuhnCheck';Expression = {(LuhnCheck($PSItem.Matches).Value)}},
                                @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $fullPath).BaseName}},
                                @{Name = 'Extension';Expression = {(Get-ChildItem -Path $fullPath).Extension}},
                                @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $fullPath).Length}},
                                @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $fullPath).CreationTime}},
                                @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $fullPath).LastWriteTime}},
                                @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},                                  
                                @{Name = 'UNCpath';Expression = {$uncpath}} 
                            }
                    }
                    else {
                        Select-Object -InputObject $_ -Property @{Name = 'Path';Expression = {$fullPath}},  
                            @{Name = 'Filename';Expression = {$filename}},
                            @{Name = 'MatchedExpression';Expression = {("`` "+$_.Matches)}},
                            @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $fullPath).BaseName}},
                            @{Name = 'Extension';Expression = {(Get-ChildItem -Path $fullPath).Extension}},
                            @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $fullPath).Length}},
                            @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $fullPath).CreationTime}},
                            @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $fullPath).LastWriteTime}},
                            @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},                              
                            @{Name = 'UNCpath';Expression = {$uncpath}} 
                    }
                } | Export-Csv -Path $outputFile -NoTypeInformation -Append
           }
            #Clean up when done. 
            remove-item -Path "$unzippedPath\*" -Recurse -Force
    } # | Export-Csv -Path $outputFile -NoTypeInformation -Append    
}

# Excel - .xlsx 
#==============
function searchExcelFiles($pattern, $search_Path, $outputFile, $Luhn) {
    Get-ChildItem -Recurse -file -Path $search_Path -Include *.xlsx -Exclude $excludeFiles -ErrorAction $erroractionpref | 
    ForEach-Object {
        # Check output file size, and call 'changeOutputFileName' if larget than X ($limitOutputFileSize - file size limit set at top of script)
        If (Test-Path $outputFile) { # If File Output File Exists 
            If ((Get-Item $outputFile).length -gt $limitOutputFileSize) { # If Output lile larger than X 
                # Chnage the outputfile's name - append a # to the name 
                $newOutputFile = changeOutputFileName $outputFile 
                $outputFile = $newOutputFile
            }
        }

        $fullPath = $_.FullName
        $filename = $_.Name
        $unzippedPath = "$env:temp\unzipped" # Where to expand/extract the Xlsx files into xml files 
        #Build UNC Path 
        $uncpath = "\\"+$_.FullName   # File's full path
        #$uncpath = $uncpath.Replace(':','$')              #Replace ':' with '$' to format the unc path   
        $uncpath = $uncpath.Replace($filename ,'')        #Replace the File's name in the unc path to display the Directory containing the file

        # Make the directory to expand files in, if it does not exist
        If(!(Test-Path -Path $unzippedPath)) {New-Item -Path $env:temp -Name "unzipped" -ItemType Directory -Force}
        # Remove any old files from the directory 
        remove-item -Path "$unzippedPath\*" -Recurse -Force
        # Expand the file into XML files using 7Zip 
        Start-Process -FilePath "$PSScriptRoot\7z.exe" -ArgumentList " x ""$fullPath"" -o""$unzippedPath"" -y" -Wait -WindowStyle Hidden
        Start-Sleep -Milliseconds 500

        If (Test-Path -Path "$unzippedPath\xl\*.xml") {    
            Get-ChildItem -Recurse -file -Path "$unzippedPath\xl\" -Include *.xml | Select-String -pattern $pattern |
            ForEach-Object { 
                if ($Luhn -eq $true ){ 
                    if (LuhnCheck($PSItem.Matches).Value -eq $true){  #Only report card numbers that pass the Luhn Check 
                        Select-Object -InputObject $_ -Property @{Name = 'Path';Expression = {$fullPath}},  
                        @{Name = 'Filename';Expression = {$filename}},
                        @{Name = 'MatchedExpression';Expression = {("``  "+$_.Matches)}},
                        @{Name = 'PassedLuhnCheck';Expression = {(LuhnCheck($PSItem.Matches).Value)}},
                        @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $fullPath).BaseName}},
                        @{Name = 'Extension';Expression = {(Get-ChildItem -Path $fullPath).Extension}},
                        @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $fullPath).Length}},
                        @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $fullPath).CreationTime}},
                        @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $fullPath).LastWriteTime}},
                        @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},  
                        @{Name = 'UNCpath';Expression = {$uncpath}} 
                    }
                }
                else {
                    Select-Object -InputObject $_ -Property @{Name = 'Path';Expression = {$fullPath}},  
                    @{Name = 'Filename';Expression = {$filename}},
                    @{Name = 'MatchedExpression';Expression = {("``  "+$_.Matches)}},
                    @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $fullPath).BaseName}},
                    @{Name = 'Extension';Expression = {(Get-ChildItem -Path $fullPath).Extension}},
                    @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $fullPath).Length}},
                    @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $fullPath).CreationTime}},
                    @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $fullPath).LastWriteTime}},
                    @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},                      
                    @{Name = 'UNCpath';Expression = {$uncpath}}
                }
            } | Export-Csv -Path $outputFile -NoTypeInformation -Append
        }
        remove-item -Path "$unzippedPath\*" -Recurse -Force
    } # | Export-Csv -Path $outputFile -NoTypeInformation -Append
}

# PDF Files - .pdf
#=================
function searchPdfFiles($pattern, $search_Path, $outputFile, $Luhn) {
    Get-ChildItem -Recurse -file -Path $search_Path -Include *.pdf -Exclude $excludeFiles -ErrorAction $erroractionpref | 
    ForEach-Object {
        # Check output file size, and call 'changeOutputFileName' if larget than X ($limitOutputFileSize - file size limit set at top of script)
        If (Test-Path $outputFile) { # If File Output File Exists 
            If ((Get-Item $outputFile).length -gt $limitOutputFileSize) { # If Output lile larger than X 
                # Chnage the outputfile's name - append a # to the name 
                $newOutputFile = changeOutputFileName $outputFile 
                $outputFile = $newOutputFile
            }
        }

        $fullPath = $_.FullName
        $filename = $_.Name
        $unzippedPath = "$env:temp\unzipped"
        $uncpath = "\\"+$_.FullName   # File's full path  
        #$uncpath = $uncpath.Replace(':','$')              #Replace ':' with '$' to format the unc path          
        $uncpath = $uncpath.Replace($filename ,'')        #Replace the File's name in the unc path to return the Directory containing the file

        If(!(Test-Path -Path $unzippedPath)) {New-Item -Path $env:temp -Name "unzipped" -ItemType Directory} # make dir named "unzipped" if it does not exist
        remove-item -Path "$unzippedPath\*" -Recurse -Force #remove any old data

        Start-Process -FilePath "$PSScriptRoot\pdftotext.exe" -ArgumentList " ""$fullPath"" ""$unzippedPath\pdfFile.txt"" " -Wait -WindowStyle Hidden 
        Start-Sleep -Milliseconds 500
        
        If (Test-Path -Path "$unzippedPath\pdfFile.txt") {    
            Get-ChildItem -Recurse -file -Path "$unzippedPath\pdfFile.txt" | Select-String -pattern $pattern |
            ForEach-Object { 
                if ($Luhn -eq $true ){    
                    if (LuhnCheck($PSItem.Matches).Value -eq $true){  #Only report card numbers that pass the Luhn Check 
                        Select-Object -InputObject $_ -Property @{Name = 'Path';Expression = {$fullPath}},   
                        @{Name = 'Filename';Expression = {$filename}},
                        @{Name = 'MatchedExpression';Expression = {("``  "+$_.Matches)}},
                        @{Name = 'PassedLuhnCheck';Expression = {(LuhnCheck($PSItem.Matches).Value)}},
                        @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $fullPath).BaseName}},
                        @{Name = 'Extension';Expression = {(Get-ChildItem -Path $fullPath).Extension}},
                        @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $fullPath).Length}},
                        @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $fullPath).CreationTime}},
                        @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $fullPath).LastWriteTime}},
                        @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},  
                        @{Name = 'UNCpath';Expression = {$uncpath}}
                    }
                }
                else {
                    Select-Object -InputObject $_ -Property @{Name = 'Path';Expression = {$fullPath}}, 
                        @{Name = 'Filename';Expression = {$filename}},
                        @{Name = 'MatchedExpression';Expression = {("``  "+$_.Matches)}},
                        @{Name = 'BaseName';Expression = {(Get-ChildItem -Path $fullPath).BaseName}},
                        @{Name = 'Extension';Expression = {(Get-ChildItem -Path $fullPath).Extension}},
                        @{Name = 'Bytes';Expression = {(Get-ChildItem -Path $fullPath).Length}},
                        @{Name = 'CreationDate';Expression = {(Get-ChildItem -Path $fullPath).CreationTime}},
                        @{Name = 'LastWriteTime';Expression = {(Get-ChildItem -Path $fullPath).LastWriteTime}},
                        @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},  
                        @{Name = 'UNCpath';Expression = {$uncpath}}
                }
            } | Export-Csv -Path $outputFile -NoTypeInformation -Append
        }
        remove-item -Path "$unzippedPath\*" -Recurse -Force
    } 
}

# Search Filenames for Terms
#===========================
function findFileNames($pattern, $search_Path, $includeFiles, $excludeFiles, $outputFile){
    Get-ChildItem -Recurse -path $search_Path -Include $includeFiles -Exclude $excludeFiles -ErrorAction $erroractionpref -Force |  
            Where-Object {$_.Name -match $pattern} |
                Select-Object -Property @{Name = 'Path';Expression = {$_.Fullname}}, 
                @{Name = 'Filename';Expression = {$_.Name}},
                @{Name = 'BaseName';Expression = {$_.BaseName}},
                @{Name = 'Extension';Expression = {$_.Extension}},
                @{Name = 'MD5';Expression = {(Get-FileHash -Algorithm md5 -path $_.Fullname).Hash}},
                @{Name = 'Bytes';Expression = {$_.Length}},
                @{Name = 'CreationDate';Expression = {$_.CreationTime}},
                @{Name = 'LastWriteTime';Expression = {$_.LastWriteTime}},
                @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},            
                @{Name = 'UNCpath';Expression = {(("\\"+($_.FullName).Replace($_.Name, "") ))}} | Export-Csv -Path $outputFile -NoTypeInformation -Append    
                                    
}

# Search File Extensions
#=======================
function findFileExtensions($fileExtensions, $search_Path, $excludeFiles, $outputFile){
    Get-ChildItem -Recurse -path $search_Path -Exclude $excludeFiles -ErrorAction $erroractionpref -Force | 
            Where-Object {$_.Extension -match $fileExtensions} | 
                Select-Object -Property @{Name = 'Path';Expression = {$_.Fullname}}, 
                @{Name = 'Filename';Expression = {$_.Name}},
                @{Name = 'BaseName';Expression = {$_.BaseName}},
                @{Name = 'Extension';Expression = {$_.Extension}},
                @{Name = 'MD5';Expression = {(Get-FileHash -Algorithm md5 -path $_.Fullname).Hash}},
                @{Name = 'Bytes';Expression = {$_.Length}},
                @{Name = 'CreationDate';Expression = {$_.CreationTime}},
                @{Name = 'LastWriteTime';Expression = {$_.LastWriteTime}},
                @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},            
                @{Name = 'UNCpath';Expression = {(("\\"+($_.FullName).Replace($_.Name, "") ))}} | Export-Csv -Path $outputFile -NoTypeInformation -Append    
                                    
}


# Search Files Without Extensions, such as private keys 
#======================================================
function findFileNamesWithoutExtensions($pattern, $search_Path, $excludeFiles, $outputFile){
    Get-ChildItem -Recurse -path $search_Path -Exclude $excludeFiles -ErrorAction $erroractionpref -Force |
            Where-Object {$_.Extension -eq '' -and $_.Name -match $pattern} | # Match on Filenames with no extensions 
                Select-Object -Property @{Name = 'Path';Expression = {$_.Fullname}}, 
                @{Name = 'Filename';Expression = {$_.Name}},
                @{Name = 'BaseName';Expression = {$_.BaseName}},
                @{Name = 'Extension';Expression = {$_.Extension}},
                @{Name = 'MD5';Expression = {(Get-FileHash -Algorithm md5 -path $_.Fullname).Hash}},
                @{Name = 'Bytes';Expression = {$_.Length}},
                @{Name = 'CreationDate';Expression = {$_.CreationTime}},
                @{Name = 'LastWriteTime';Expression = {$_.LastWriteTime}},
                @{Name = 'HostName';Expression = {$env:COMPUTERNAME }},            
                @{Name = 'UNCpath';Expression = {(("\\"+($_.FullName).Replace($_.Name, "") ))}} | Export-Csv -Path $outputFile -NoTypeInformation -Append    
                                    
}

# Function to remove OutputFiles 
function removeOldOutputFiles() {
    If(Test-Path -Path $outputFileNameTermPasswords) { Remove-Item $outputFileNameTermPasswords };
    If(Test-Path -Path $outputFileNameTermsCardNums) { Remove-Item $outputFileNameTermsCardNums };
    If(Test-Path -Path $outputFileNameTermsSSNs) {Remove-Item $outputFileNameTermsSSNs };
    If(Test-Path -Path $outputFileNameTermInterest) {Remove-Item $outputFileNameTermInterest };
    If(Test-Path -Path $outputPasswordFiles) {Remove-Item $outputPasswordFiles };
    If(Test-Path -Path $outputCardNumberFiles) { Remove-Item $outputCardNumberFiles };
    If(Test-Path -Path $outputSSNFiles) {Remove-Item $outputSSNFiles };
    If(Test-Path -Path $outputFileNameTermsIDs) {Remove-Item $outputFileNameTermsIDs };
    If(Test-Path -Path $outputFileNameEncryptionKeys) {Remove-Item $outputFileNameEncryptionKeys };
    If(Test-Path -Path $outputFileNameVPNKeys) {Remove-Item $outputFileNameVPNKeys };
    If(Test-Path -Path $outputFileNameSchematics) {Remove-Item $outputFileNameSchematics };
    If(Test-Path -Path $outputFileNameNetworkingDocs) {Remove-Item $outputFileNameNetworkingDocs };
    If(Test-Path -Path $outputFileNameEmailFiles) {Remove-Item $outputFileNameEmailFiles };
    If(Test-Path -Path $outputFileNamePCAPFiles) {Remove-Item $outputFileNamePCAPFiles };
    If(Test-Path -Path $outputFileNameRDP) {Remove-Item $outputFileNameRDP };
    If(Test-Path -Path $outputFileNameSourceCode) {Remove-Item $outputFileNameSourceCode };
    If(Test-Path -Path $outputFileNamePasswordDBs) {Remove-Item $outputFileNamePasswordDBs };
    If(Test-Path -Path $outputFileNameBackupFiles) {Remove-Item $outputFileNameBackupFiles };
    If(Test-Path -Path $outputFileNameDBs) {Remove-Item $outputFileNameDBs };
    If(Test-Path -Path $outputFileNameArchives) {Remove-Item $outputFileNameArchives };
    If(Test-Path -Path $outputFileNameLogs) {Remove-Item $outputFileNameLogs };
    If(Test-Path -Path $patternFileExtensionMobileApps) {Remove-Item $patternFileExtensionMobileApps };

}

# List All Logical Disks 
function listLocalStorage(){
    Write-Host " "
    Write-Host "============="
    Write-Host "LOCAL STORAGE"
    Write-Host "============="
    # Get the local drives/storage 
    #Get-WmiObject win32_logicalDisk | Select-Object Caption,Description,DriveType,FileSystem,MediatType,Size,FreeSpace,VolumeName,VolumeSerialNumber,DeviceID
    get-psdrive -PSProvider 'FileSystem' | format-table
    
}
# List All Mounted Shares 
function listMountedShares(){
    Write-Host " "
    Write-Host "==================="
    Write-Host "Mounted File Shares"
    Write-Host "==================="
    Write-Host " "
    if(!(test-path -path hku:\ )) {New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null}
    #Array to hold mapped drives 
    $mapped = @()
    # Get user SIDs
    $currUserHives = Get-ChildItem -Path HKU: | Where-Object {$_.name -match 'S-1-5-21' -and ($_.name -notmatch '_Classes')} | Select-Object Name

    $currUserHives.Name | ForEach-Object {
        $UserSID = $_ -split("\\") # Split string and escape '\'
        $UserSID = $UserSID[1] # Get the SID 
        # HKU Paths 
        $patha = "HKU:\"+$UserSID.TrimStart(" ")+"\Volatile Environment"
        $pathb = "HKU:\"+$UserSID.TrimStart(" ")+"\Network"
        $pathc = "HKU:\"+$UserSID.TrimStart(" ")+"\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

        try {$user = Get-ItemProperty -Path $patha -ErrorAction Stop}
        catch {$user = "Volitile Environment Not Found; Unable to ID User"}
        finally {
            $user =  $env:USERDOMAIN+"\"+$user.USERNAME
            $drives = Get-ChildItem -Path $pathb | Get-ItemProperty | Select-Object PSChildName,RemotePath
            $recent = Get-ChildItem -Path $pathc | Get-ItemProperty | Select-Object PSChildName,RemotePath
            Write-host "Recent: $recent"
            $recent = $recent.PSChildName | Where-Object {$_ -match "##[a-zA-Z-_\\0-9$#\s]*"}
            $recent = $recent -replace("#","\")
            $other = $recent | ForEach-Object {
                if($drives.RemotePath -contains("$_") -eq $false) {$_}
                else {}
            }
            $drives | ForEach-Object {
                $computerName = $env:ComputerName
                $drvltr = $_.PSChildName
                $drvpth = $_.RemotePath
                $drv = new-object PSObject -property @{ComputerName=$computerName;DriveLetter=$drvltr;SharePath=$drvpth;User=$user}
                $mapped += $drv
            }
            $other | ForEach-Object {
                $computerName = $env:ComputerName
                $drvltr = ""
                $drvpth = $_
                $drv = new-object PSObject -property @{ComputerName=$computerName;DriveLetter=$drvltr;SharePath=$drvpth;User=$user}
                $mapped += $drv
            }
        }
    }
    $mapped | Format-Table
}


function userOutput($pattern) {
    Write-Host ""
    Write-Host "Searching - $search_Path" 
    Write-Host "Analyzing Filesnames:  " 
    Write-Host "  - FILENAME PATTERN(S) : $pattern "
}

function userOutputComplete() {
    Write-Host "  -- SEARCH COMPLETE -- "
}

# Script's Banner 
function banner() {
    Clear-Host 
    Write-Host ""
    Write-Host " _______________________________________________________ " 
    Write-Host "     ______ _     _ __   _     ______         _______ "
    Write-Host "    |_____/ |     | | \  | ___ |     \ |      |______ "
    Write-Host "    |    \_ |_____| |  \_|     |_____/ |_____ ______| "
    Write-Host " _______________________________________________________ "
    Write-Host "              script by: Arron Jablonowski              "
    
}
banner # Call the Run-DLP banner. 

# =====================================#
# Switches for Key Terms in File Names #
# =====================================#

# passwords
if($Filename_Terms_Passwords){
    #File Types to include
    $include = @('*.txt', '*.doc', '*.docx', '*.xls', '*.xlsx', '*.eml', '*.mdb', '*.odt', '*.ods', '*.pdf', '*.xml', '*.ini', '*.csv', '*.png', '*.jpg', '*.jpeg', '*.HEIC') # HEIC is an iPhone photo format 
    userOutput $patternFileNamesPw # Output to user function 
    findFileNames $patternFileNamesPw $search_Path $include $excludeFiles $outputFileNameTermPasswords 
    userOutputComplete # Output to user function
    $workdone = 1
}

# card numbers
if($Filename_Terms_CardNumbers){    
    #File Types to include
    $include = @('*.txt', '*.doc', '*.docx', '*.xls', '*.xlsx', '*.mdb', '*.odt', '*.ods', '*.pdf', '*.csv')
    userOutput $patternFileNamesCC # Output to user function
    findFileNames $patternFileNamesCC $search_Path $include $excludeFiles $outputFileNameTermsCardNums 
    userOutputComplete # Output to user function
    $workdone = 1
}

# SSNs
if($Filename_Terms_SSNs){
    #File Types to include
    $include = @('*.txt', '*.doc', '*.docx', '*.xls', '*.xlsx', '*.mdb', '*.odt', '*.ods', '*.pdf', '*.csv', '*.png', '*.jpg', '*.jpeg', '*.HEIC') # HEIC is an iPhone photo format 
    userOutput $patternFileNamesSSNs # Output to user function
    findFileNames $patternFileNamesSSNs $search_Path $include $excludeFiles $outputFileNameTermsSSNs
    userOutputComplete # Output to user function
    $workdone = 1
}

# IDs
if($Filename_Terms_IDs){
    #File Types to include
    $include = @('*.txt', '*.doc', '*.docx', '*.xls', '*.xlsx', '*.mdb', '*.odt', '*.ods', '*.pdf', '*.csv', '*.png', '*.jpg', '*.jpeg', '*.HEIC') # HEIC is an iPhone photo format 
    userOutput $patternFileNamesIDs # Output to user function
    findFileNames $patternFileNamesIDs $search_Path $include $excludeFiles $outputFileNameTermsIDs
    userOutputComplete # Output to user function
    $workdone = 1
}

# Interesting Files 
if($Filename_Terms_Interesting){
    # File Types to include
    $include = @('*.txt', '*.doc', '*.docx', '*.xls', '*.xlsx', '*.mdb', '*.odt', '*.ods', '*.pdf', '*.csv', '*.png', '*.jpg', '*.jpeg', '*.HEIC') # HEIC is an iPhone photo format 
    userOutput $patternFileNamesOfInterest # Output to user function
    findFileNames $patternFileNamesOfInterest $search_Path $include $excludeFiles $outputFileNameTermInterest
    userOutputComplete # Output to user function
    $workdone = 1
}

# Possible Networking Docs
if($Filename_Terms_Network_Docs){
    # File Types to include
    $include = @('*') # Include it all. 
    userOutput $patternFileNamesNetworkDocs # Output to user function
    findFileNames $patternFileNamesNetworkDocs $search_Path $include $excludeFiles $outputFileNameNetworkingDocs
    userOutputComplete # Output to user function
    $workdone = 1
}

# Schematic Files 
if($Filename_Terms_Schematics){
    #File Types to include
    $include = @('*') # Include it all. 
    userOutput $patternFileNamesSchematics # Output to user function
    findFileNames $patternFileNamesSchematics $search_Path $include $excludeFiles $outputFileNameSchematics
    userOutputComplete # Output to user function
    $workdone = 1
}

#  Encryption Key Files 
if($Filename_Terms_Encryption_Keys){     
    userOutput $patternFileExtensionEncryptionKeys # Output to user function
    findFileExtensions $patternFileExtensionEncryptionKeys $search_Path $excludeFiles $outputFileNameEncryptionKeys
    userOutput $patternFileNamesEncryptionKeys # Output to user function
    findFileNamesWithoutExtensions $patternFileNamesEncryptionKeys $search_Path $excludeFiles $outputFileNameEncryptionKeys
    userOutputComplete # Output to user function
    $workdone = 1
}

#  VPN Encryption Key Files 
if($Filename_Terms_VPN_Keys){
    userOutput $patternFileExtensionVPNKeys # Output to user function
    findFileExtensions $patternFileExtensionVPNKeys $search_Path $excludeFiles $outputFileNameVPNKeys
    userOutput $patternFileNamesVPNKeys # Output to user function
    findFileNamesWithoutExtensions $patternFileNamesVPNKeys $search_Path $excludeFiles $outputFileNameVPNKeys
    userOutputComplete
    $workdone = 1
}

#======================#
# FIND FILE EXTENSIONS #
#======================# 

# Password DB Files 
if($File_Extensions_Password_DBs){
    userOutput $patternFileExtensionPasswordDBs # Output to user function
    findFileExtensions $patternFileExtensionPasswordDBs $search_Path $excludeFiles $outputFileNamePasswordDBs
    userOutputComplete # Output to user function
    $workdone = 1
}

# RDP Files 
if($File_Extensions_RDP_Files){
    userOutput $patternFileExtensionRDP # Output to user function
    findFileExtensions $patternFileExtensionRDP $search_Path $excludeFiles $outputFileNameRDP
    userOutputComplete # Output to user function
    $workdone = 1
}

# Source Code 
if($File_Extensions_Source_Code){
    userOutput $patternFileExtensionSourceCode # Output to user function
    findFileExtensions $patternFileExtensionSourceCode $search_Path $excludeFiles $outputFileNameSourceCode
    userOutputComplete # Output to user function
    $workdone = 1
}

# Email 
if($File_Extensions_Email){
    userOutput $patternFileExtensionEmail # Output to user function
    findFileExtensions $patternFileExtensionEmail $search_Path $excludeFiles $outputFileNameEmailFiles
    userOutputComplete # Output to user function
    $workdone = 1
}

# PCAPs 
if($File_Extensions_PCAPs){
    userOutput $patternFileExtensionPCAP # Output to user function
    findFileExtensions $patternFileExtensionPCAP $search_Path $excludeFiles $outputFileNamePCAPFiles
    userOutputComplete # Output to user function
    $workdone = 1
}

# Backups 
if($File_Extensions_Backups){
    userOutput $patternFileExtensionBackups # Output to user function
    findFileExtensions $patternFileExtensionBackups $search_Path $excludeFiles $outputFileNameBackupFiles
    userOutputComplete # Output to user function
    $workdone = 1
}

# DBs 
IF($File_Extensions_DBs) {
    userOutput $patternFileExtensionDBs # Output to user function
    findFileExtensions $patternFileExtensionDBs $search_Path $excludeFiles $outputFileNameDBs
    userOutputComplete # Output to user function
    $workdone = 1 
}

# Archives 
IF($File_Extensions_Archives) {
    userOutput $patterFileExtensionArchives # Output to user function
    findFileExtensions $patterFileExtensionArchives $search_Path $excludeFiles $outputFileNameArchives
    userOutputComplete # Output to user function
    $workdone = 1 
}

# log files 
IF($File_Extensions_Logs) {
    userOutput $patternFileExtensionLogs # Output to user function
    findFileExtensions $patternFileExtensionLogs $search_Path $excludeFiles $outputFileNameLogs
    userOutputComplete # Output to user function
    $workdone = 1 
}

# Mobile Applications
IF($File_Extensions_MobileApps) {
    userOutput $patternFileExtensionMobileApps # Output to user function
    findFileExtensions $patternFileExtensionMobileApps $search_Path $excludeFiles $outputFileNameMobileApps
    userOutputComplete # Output to user function
    $workdone = 1 
}


#=========================================#
# Switchs for Key Terms in File's Content #
#=========================================#

# Passwords 
if($Find_Passwords_in_Files){
    Write-Host ""
    Write-Host "Searching - $search_Path"
    Write-Host "Analyzing File Content for Potential Clear Text Credentials. Please wait..."   
    # Luhn Check - for CC #s
    $Luhn = $false # Don't run Luhn check       
    # Search Text files
    Write-Host "  - CREDENTIALS : Text " 
    searchTextFiles $patternPasswords $search_Path $outputPasswordFiles $Luhn
    # Search Old Office Docs 
    Write-Host "  - CREDENTIALS : Doc, Xls "
    searchDocXlsFiles $patternPasswords $search_Path $outputPasswordFiles $Luhn
    # Search docx files 
    Write-Host "  - CREDENTIALS : Docx "
    searchWordFiles $patternPasswords $search_Path $outputPasswordFiles $Luhn
    # Search xlsx files 
    Write-Host "  - CREDENTIALS : Xlsx "
    searchExcelFiles $patternPasswords $search_Path $outputPasswordFiles $Luhn
    # Search pdf files 
    Write-Host "  - CREDENTIALS : Pdf "
    searchPdfFiles $patternPasswords $search_Path $outputPasswordFiles $Luhn
    # Search script files 
    Write-Host "  - CREDENTIALS : Scripts "
    searchScriptFiles $patternPasswords $search_Path $outputPasswordFiles $Luhn
    # Search script config files 
    Write-Host "  - CREDENTIALS : Configs "
    searchScriptConfigFiles $patternPasswords $search_Path $outputPasswordFiles $Luhn
    # Complete 
    Write-Host "  - CREDENTIALS : SEARCH COMPLETE "
    $workdone = 1

}

#Switch for CardNumbers
if($Find_Card_Numbers_in_Files){
    Write-Host ""
    Write-Host "Searching - $search_Path"
    Write-Host "Analyzing File Content for Potential Clear Text Card Data. Please wait..."    
    # Luhn Check - for CC #s
    $Luhn = $true # Use Luhn Check - LuhnCheck Must = $true for Output 
    # Search Text files
    Write-Host "  - CARD DATA : Text " 
    searchTextFiles $patternCardData $search_Path $outputCardNumberFiles $Luhn
    # Search Old Office Docs 
    Write-Host "  - CARD DATA : Doc, Xls "
    searchDocXlsFiles $patternCardData $search_Path $outputCardNumberFiles $Luhn
    # Search docx files 
    Write-Host "  - CARD DATA : Docx "
    searchWordFiles $patternCardData $search_Path $outputCardNumberFiles $Luhn
    # Search xlsx files 
    Write-Host "  - CARD DATA : Xlsx "
    searchExcelFiles $patternCardData $search_Path $outputCardNumberFiles $Luhn
    # Search pdf files 
    Write-Host "  - CARD DATA : Pdf "
    searchPdfFiles $patternCardData $search_Path $outputCardNumberFiles $Luhn
    # Complete 
    Write-Host "  - CARD DATA : SEARCH COMPLETE "
    $workdone = 1

}

# Switch for Social Security Numbers  
if($Find_SSNs_in_Files){
    Write-Host ""
    Write-Host "Searching - $search_Path"
    Write-Host "Analyzing File Content for Potential Clear Text SSNs. Please wait..."    
    # Luhn Check - for CC #s
    $Luhn = $false
    # Search Text files
    Write-Host "  - SOCIAL SECURITY NUMBERS : Text " 
    searchTextFiles $patternSSN $search_Path $outputSSNFiles $Luhn
    # Search Old Office Docs 
    Write-Host "  - SOCIAL SECURITY NUMBERS : Doc, Xls "
    searchDocXlsFiles $patternSSN $search_Path $outputSSNFiles $Luhn
    # Search docx files 
    Write-Host "  - SOCIAL SECURITY NUMBERS : Docx "
    searchWordFiles $patternSSN $search_Path $outputSSNFiles $Luhn
    # Search xlsx files 
    Write-Host "  - SOCIAL SECURITY NUMBERS : Xlsx "
    searchExcelFiles $patternSSN $search_Path $outputSSNFiles $Luhn
    # Search pdf files 
    Write-Host "  - SOCIAL SECURITY NUMBERS : Pdf "
    searchPdfFiles $patternSSN $search_Path $outputSSNFiles $Luhn
    # Complete 
    Write-Host "  - SOCIAL SECURITY NUMBERS : SEARCH COMPLETE "
    $workdone = 1
}

# Switch for Email Addresses   
if($Find_Email_Addresses_in_Files){
    Write-Host ""
    Write-Host "Searching - $search_Path"
    Write-Host "Analyzing File Content for Potential Email Addresses. Please wait..."   
    # Luhn Check - for CC #s
    $Luhn = $false
    # Search Text files
    Write-Host "  - EMAIL ADDRESSES : Text " 
    searchTextFiles $patternEmailAddress $search_Path $outputEmailAddressTxtFiles $Luhn
    # Search Old Office Docs 
    Write-Host "  - EMAIL ADDRESSES : Doc, Xls "
    searchDocXlsFiles $patternEmailAddress $search_Path $outputEmailAddressDocXlsFiles $Luhn
    # Search docx files 
   # Write-Host "  - EMAIL ADDRESSES : Docx "
   # searchWordFiles $patternEmailAddress $search_Path $outputEmailAddressDocxFiles $Luhn
    # Search xlsx files 
    Write-Host "  - EMAIL ADDRESSES : Xlsx "
    searchExcelFiles $patternEmailAddress $search_Path $outputEmailAddressXlsxFiles $Luhn
    # Search pdf files 
   # Write-Host "  - EMAIL ADDRESSES : Pdf "
   # searchPdfFiles $patternEmailAddress $search_Path $outputEmailAddressPdfFiles $Luhn
    # Complete 
    Write-Host "  - EMAIL ADDRESSES : SEARCH COMPLETE "
    $workdone = 1
}

# List out Storage Location in CLI 
if($List_Attached_Storage){
    #List Local Stoage Locations
    listLocalStorage
    #List Shares
    listMountedShares
}

# Remove Old Output Files
if($Remove_Output_Files){
    Write-Host " " 
    Write-Host "Removing Output Files..."
    removeOldOutputFiles # Function to delete Output Files
    Write-Host "Removed Output (.csv) Files from Script's Root Directory."
    Write-Host " "
}

# Message to user once script completes  
if($workdone -eq 1){
    Write-Host " " 
    Write-Host "Next Steps:"
    Write-Host "  - Review Output Files for Sensitive Data."
    Write-Host "  - Remove and/or Secure any Sensitive Data Files. "
    Write-Host "  - Delete this Script's Output Files Post Review: "
    Write-Host "      .\Run-DLS.ps1 -RemoveOutputFiles "
    Write-Host " "
}
