#
# Module manifest for module 'HostUtilities'
#
# Generated by: Michael Haken
#
# Generated on: 2/27/2016
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'HostUtilities.psm1'

# Version number of this module.
ModuleVersion = '1.1.2.2'

# ID used to uniquely identify this module
GUID = 'bd4390dc-a8ad-4bce-8d69-f53ccf8e4163'

# Author of this module
Author = 'Michael Haken'

# Company or vendor of this module
CompanyName = 'BAMCIS'

# Copyright statement for this module
Copyright = '(c) 2017 BAMCIS. All rights reserved.'

# Description of the functionality provided by this module
Description = 'A collection of utilities to help automate administration tasks on a local host.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @("ESENT")

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module
FunctionsToExport = @("Reset-WindowsUpdate", "Get-GroupsFromToken", "Update-TokenGroupMembership", "Start-WithImpersonation",
	"Enable-WinRM", "New-EmptyTestFile", "Start-PortScan", "Remove-JavaInstallations", "Get-RegistryKeyEntries", "Enable-TaskSchedulerHistory",
	"Start-KerberosTraceLog", "Stop-KerberosTraceLog", "Test-IsLocalAdmin", "Write-CCMLogFormat", "Get-IPv6ConfigurationOptions", "Get-ProcessToken",
	"Set-ProcessToken", "Reset-ProcessToken", "Get-LsaSecret", "ConvertFrom-Xml", "Get-WebHistory", "Get-UserProfiles", "ConvertTo-HtmlTable",
	"Test-Port", "Set-AutoLogon", "Set-FileSecurity", "Set-Owner", "Test-RegistryKeyProperty", "ForEach-ObjectParallel", "Invoke-CommandInNewRunspace",
	"Get-WindowsActivationInformation", "Set-CertificatePrivateKeyAccess", "New-GptVolume", "Where-NotMatchIn", "Get-AccountSid",
	"Get-AccountTranslatedNTName", "Convert-SecureStringToString", "Get-LocalGroupMembers", "Add-DomainMemberToLocalGroup", "Get-PSExecutionPolicy",
	"Test-PendingReboots", "Test-Credentials", "Write-Log", "Set-UAC", "Set-IEESC", "Set-OpenFileSecurityWarning", "Get-LocalFQDNHostname",
	"Set-Pagefile", "Set-HighPerformancePowerPlan", "Get-NETVersion", "Set-NET461InstallBlock", "Start-ProcessWait", "Get-FileVersion",
	"Disable-SSLv3", "Test-PackageInstallation", "Get-WebPackage", "Start-PackageInstallation", "Set-RunOnceScript", "Extract-ZipFile",
	"New-RandomPassword", "New-EncryptedPassword", "Get-EncryptedPassword", "Get-CertificateSAN", "Get-DiskFree", "Invoke-ForceDelete",
	"Invoke-Using", "Invoke-WmiRepositoryRebuild", "Merge-Hashtables", "ConvertTo-Hashtable", "Get-PropertyValue", "Get-UnboundParameterValue",
	"Import-UnboundParameterCode", "New-DynamicParameter"
)

# Cmdlets to export from this module
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = @()

# Aliases to export from this module
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess
PrivateData = @{
	PSData = @{
		Title = "Host Automation Utilities"

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @("PortScan", "Kerberos", "ACL", "Disk", "DynamicParameters", "Hashtable", "WMI", "DiskFree", "LocalGroup", "Token", "Parallel", "Runspace")

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/bamcisnetworks/HostUtilities/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/bamcisnetworks/HostUtilities'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = '*1.1.2.2
Updated parameter validation for ValidateSet on New-DynamicParameter.

*1.1.2.1
Fixed bugs with the New-DyanmicParameter cmdlet parameters.
		
*1.1.2.0
Added the Get-PropertyValue, Get-UnboundParameterValue, Import-UnboundParameterCode, and New-DynamicParameter cmdlets.

*1.1.1.2
Changed the parameter of ConvertTo-Hashtable from ExcludedKeys to Exclude.
		
*1.1.1.1
Added the ConvertTo-Hashtable cmdlet.
		
*1.1.1.0
Added the Merge-Hashtables cmdlet. Changed Start-TaskSchedulerHistory to Enable-TaskSchedulerHistory (left an alias for Start-). Added alias "using" to Invoke-Using.
		
*1.1.0.2
Updated the progress notification for ForEach-ObjectParallel.

*1.1.0.1
Added the Invoke-WmiRepositoryRebuild cmdlet.
		
*1.1.0.0
Updated the Start-ProcessWait cmdlet and moved the ESENT cmdlets to their own module, which is now a dependency for this module.

*1.0.0.17
Updated manifest file.
		
*1.0.0.16
Updated the Convert-SecureStringToString cmdlet and added the Invoke-Using cmdlet.

*1.0.0.15
Allowed paths supplied to Invoke-ForceDelete to be dot sourced or relative.

*1.0.0.14
Added the Invoke-ForceDelete function.

*1.0.0.13
Added the Get-DiskFree function.

*1.0.0.12 
Added the Get-CertificateSAN function. 

*1.0.0.11 
Changed the name of the Get-Package function to Get-WebPackage in order to deconflict the function name with MS provided functions in Server 2016. 

*1.0.0.10 
Updated how errors are displayed on Set-FileSecurity. 

*1.0.0.9 
Changed the path parameter for Set-Owner to a single string instead of an array. Modified Set-FileSecurity to use the SetAccessControl() method instead of Set-Acl. Added the $script:LocalNames value to use with Get-AccountSid and Get-AccountTranslatedNTName. 

*1.0.0.8 
Fixed a bug in the Extract-ZipFile cmdlet and the NoOverWrite parameter. 

*1.0.0.7 
Fixed a logic error in Write-Log 

*1.0.0.6 
Added Functions: 

Extract-ZipFile 
New-RandomPassword 
New-EncryptedPassword 
Get-EncryptedPassword 
Enable-TaskSchedulerHistory 

*1.0.0.5 
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
'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

