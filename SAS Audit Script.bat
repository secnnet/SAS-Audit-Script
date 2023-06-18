@echo off

REM Setting up work directory
echo "Setting up work directory"
mkdir "%HOMEPATH%\Downloads\%computername%-SAS_Audit\scripts"
powershell "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3"

REM Downloading dependencies
echo "Downloading dependencies"
powershell "Invoke-WebRequest -Uri https://download.sysinternals.com/files/PSTools.zip -OutFile \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\scripts\PSTools.zip\""
powershell "Invoke-WebRequest -Uri https://github.com/silentsignal/wpc/archive/refs/heads/wpc-2.0.zip -OutFile \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\scripts\wpc-2.0.zip\""
powershell "Invoke-WebRequest -Uri https://github.com/pentestmonkey/windows-privesc-check/archive/refs/heads/master.zip -OutFile \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\scripts\windows-privesc-check.zip\""
powershell "Expand-Archive -LiteralPath \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\scripts\PSTools.zip\" -DestinationPath \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\scripts\""
powershell "Expand-Archive -LiteralPath \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\scripts\wpc-2.0.zip\" -DestinationPath \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\scripts\""
powershell "Expand-Archive -LiteralPath \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\scripts\windows-privesc-check.zip\" -DestinationPath \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\scripts\""
echo.

REM Basics
echo "Basic Enumeration of the System"
systeminfo >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_systeminfo.txt"
hostname >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_systeminfo.txt"
echo.

REM Who am I?
echo "Obtaining whoami"
whoami >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_whoami.txt"
echo %username% >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_whoami.txt"
whoami /priv >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_whoami.txt"
whoami /groups >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_whoami.txt"
whoami /all >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_whoami.txt"
echo.

REM What users/localgroups are on the machine?
echo "What users/localgroups are on the machine?"
net user administrator >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_usr-grp.txt"
net user admin >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_usr-grp.txt"
echo.

REM Password Policy Check
echo "Password Policy Check"
net accounts >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_password_policy.txt"
echo.

REM Installed Software Inventory
echo "Installed Software Inventory"
powershell "Get-WmiObject -Class Win32_Product | Select-Object -Property Name, Version, Vendor | Export-Csv -Path \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_installed_software.csv\" -NoTypeInformation"
echo.

REM Open Ports and Network Connections
echo "Open Ports and Network Connections"
netstat -ano >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_network_connections.txt"
echo.

REM Event Log Analysis
echo "Event Log Analysis"
powershell "Get-WinEvent -FilterHashtable @{LogName='System'; Level=2,3,4; StartTime=(Get-Date).AddDays(-7)} | Format-List -Property TimeCreated, Id, LevelDisplayName, Message | Out-File \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_event_log.txt\""
echo.

REM File Integrity Check
echo "File Integrity Check"
certutil -hashfile C:\Windows\System32\kernel32.dll SHA256 >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_file_integrity.txt"
echo.

REM Scheduled Tasks and Services
echo "Scheduled Tasks and Services"
schtasks /query /fo LIST >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_scheduled_tasks.txt"
sc query state=all >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_services.txt"
echo.

REM Registry Analysis
echo "Registry Analysis"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_registry_analysis.txt"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_registry_analysis.txt"
echo.

REM Patch Level and Vulnerability Assessment
echo "Patch Level and Vulnerability Assessment"
powershell "Get-HotFix | Select-Object -Property HotFixID, InstalledBy, InstalledOn | Export-Csv -Path \"%HOMEPATH%\Downloads\%computername%-SAS_Audit\%computername%_patch_level.csv\" -NoTypeInformation"
echo.

REM Additional commands or actions can be added here.

REM End of script
echo "Audit completed."
