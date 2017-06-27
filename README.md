# Host Utilities

## Revision History

### 1.1.0.0
Updated the Start-ProcessWait cmdlet and moved the ESENT cmdlets to their own module, which is now a dependency for this module.

### 1.0.0.17
Updated manifest file.

### 1.0.0.16
Updated the Convert-SecureStringToString cmdlet and added the Invoke-Using cmdlet.

### 1.0.0.15
Allowed paths supplied to Invoke-ForceDelete to be dot sourced or relative.

### 1.0.0.14
Added the Invoke-ForceDelete function.

### 1.0.0.13
Added the Get-DiskFree function.

### 1.0.0.12 
Added the Get-CertificateSAN function. 

### 1.0.0.11 
Changed the name of the Get-Package function to Get-WebPackage in order to deconflict the function name with MS provided functions in Server 2016. 

### 1.0.0.10 
Updated how errors are displayed on Set-FileSecurity. 

### 1.0.0.9 
Changed the path parameter for Set-Owner to a single string instead of an array. Modified Set-FileSecurity to use the SetAccessControl() method instead of Set-Acl. Added the $script:LocalNames value to use with Get-AccountSid and Get-AccountTranslatedNTName. 

### 1.0.0.8 
Fixed a bug in the Extract-ZipFile cmdlet and the NoOverWrite parameter. 

### 1.0.0.7 
Fixed a logic error in Write-Log 

### 1.0.0.6 
Added Functions: 

Extract-ZipFile 
New-RandomPassword 
New-EncryptedPassword 
Get-EncryptedPassword 
Enable-TaskSchedulerHistory 

### 1.0.0.5 
Removed function: 
Add-DomainUserToLocalGroup (renamed to Add-DomainMemberToLocalGroup with additonal parameters) 

Added numerous additional functions: 

Where-NotMatchIn 
Get-AccountSid 
Get-AccountTranslatedNTName 
Convert-SecureStringToString 
Get-LocalGroupMembers 
Add-DomainMemberToLocalGroup 
Get-PSExecutionPolicy 
Test-PendingReboots 
Test-Credentials 
Write-Log 
Set-UAC 
Set-IEESC 
Set-OpenFileSecurityWarning 
Get-LocalFQDNHostname 
Set-Pagefile 
Set-HighPerformancePowerPlan 
Get-NETVersion 
Set-NET461InstallBlock 
Start-ProcessWait 
Get-FileVersion 
Disable-SSLv3 
Test-PackageInstallation 
Get-Package 
Start-PackageInstallation 
Set-RunOnceScript 

Almost all of these functions use the Write-Log function. This function can be set to use a parameter pointing to a path or you can use something like [System.Environment]::SetEnvironmentVariable("LogPath", "c:\log.txt", [System.EnvironmentVariableTarget]::Machine) to enable logging to the path.