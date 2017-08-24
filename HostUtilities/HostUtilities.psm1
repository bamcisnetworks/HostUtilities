
$script:LocalNames = @(".", "localhost", "127.0.0.1", "", $env:COMPUTERNAME)

Function Reset-WindowsUpdate {
	<#
		.SYNOPSIS	
			The cmdlet resets all of the windows update components and re-registers the dlls.

		.DESCRIPTION
			Several services are stopped, the log files and directories are renamed, several dlls are re-registered, and then the services are restarted.

		.PARAMETER AutomaticReboot
			Specify whether the computer should automatically reboot after completing the reset.

		.INPUTS
			None

		.OUTPUTS
			None

		.EXAMPLE
			Reset-WindwsUpdate

			Resets windows update and does not automatically reboot.

		.EXAMPLE
			Reset-WindowsUpdate -AutomaticReboot

			Resets windows update and automatically reboots the machine.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATED: 11/14/2016

			The command should be run with administrative credentials.
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=0)]
		[switch]$AutomaticReboot = $false
	)

	Begin {
		if(!(Test-IsLocalAdmin)) {
			throw "This cmdlet must be run with admin credentials."
		}
	}

	Process
	{
		try
		{
			Stop-Service -Name BITS -ErrorAction Stop
		}
		catch [Exception]
		{
			Write-Warning -Message "Could not stop the BITS service"
			Exit 1
		}

		try
		{
			Stop-Service -Name wuauserv -ErrorAction Stop
		}
		catch [Exception]
		{
			Write-Warning -Message "Could not stop the wuauserv service"
			Exit 1
		}

		try
		{
			Stop-Service -Name AppIDSvc -ErrorAction Stop
		}
		catch [Exception]
		{
			Write-Warning -Message "Could not stop the AppIDSvc service"
			Exit 1
		}

		try
		{
			Stop-Service -Name CryptSvc -ErrorAction Stop
		}
		catch [Exception]
		{
			Write-Warning -Message "Could not stop the CryptSvc service"
			Exit 1
		}

		try
		{
			Clear-DnsClientCache -ErrorAction Stop
		}
		catch [Exception]
		{
			Write-Warning -Message "Could not clear the dns client cache"
		}

		Remove-Item -Path "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat"

		if (Test-Path -Path "$env:SYSTEMROOT\winsxs\pending.xml.bak")
		{
			Remove-Item -Path "$env:SYSTEMROOT\winsxs\pending.xml.bak" -Recurse -Force
		}

		if (Test-Path -Path "$env:SYSTEMROOT\winsxs\pending.xml")
		{
			Rename-Item -Path "$env:SYSTEMROOT\winsxs\pending.xml" -NewName "$env:SYSTEMROOT\winsxs\pending.xml.bak"
		}

		if (Test-Path -Path "$env:SYSTEMROOT\SoftwareDistribution.bak")
		{
			Remove-Item -Path "$env:SYSTEMROOT\SoftwareDistribution.bak" -Recurse -Force
		}

		if (Test-Path -Path "$env:SYSTEMROOT\SoftwareDistribution") 
		{
			Rename-Item -Path "$env:SYSTEMROOT\SoftwareDistribution" -NewName "$env:SYSTEMROOT\SoftwareDistribution.bak"
		}

		if (Test-Path -Path "$env:SYSTEMROOT\system32\Catroot2.bak") 
		{
			Remove-Item -Path "$env:SYSTEMROOT\system32\Catroot2.bak" -Recurse -Force
		}

		if (Test-Path -Path "$env:SYSTEMROOT\system32\Catroot2") 
		{
			Rename-Item -Path "$env:SYSTEMROOT\system32\Catroot2" -NewName "$env:SYSTEMROOT\system32\Catroot2.bak"
		}

		if (Test-Path -Path "$env:SYSTEMROOT\WindowsUpdate.log.bak")
		{
			Remove-Item -Path "$env:SYSTEMROOT\WindowsUpdate.log.bak" -Recurse -Force
		}

		if (Test-Path -Path "$env:SYSTEMROOT\WindowsUpdate.log")
		{
			Rename-Item -Path "$env:SYSTEMROOT\WindowsUpdate.log" -NewName "$env:SYSTEMROOT\WindowsUpdate.log.bak"
		}

		& "$env:SYSTEMROOT\system32\sc.exe" sdset "BITS" "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" | Out-Null
		& "$env:SYSTEMROOT\system32\sc.exe" sdset "wuauserv" "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" | Out-Null

		regsvr32.exe /s atl.dll 
		regsvr32.exe /s urlmon.dll 
		regsvr32.exe /s mshtml.dll 
		regsvr32.exe /s shdocvw.dll 
		regsvr32.exe /s browseui.dll 
		regsvr32.exe /s jscript.dll 
		regsvr32.exe /s vbscript.dll 
		regsvr32.exe /s scrrun.dll 
		regsvr32.exe /s msxml.dll 
		regsvr32.exe /s msxml3.dll 
		regsvr32.exe /s msxml6.dll 
		regsvr32.exe /s actxprxy.dll 
		regsvr32.exe /s softpub.dll 
		regsvr32.exe /s wintrust.dll 
		regsvr32.exe /s dssenh.dll 
		regsvr32.exe /s rsaenh.dll 
		regsvr32.exe /s gpkcsp.dll 
		regsvr32.exe /s sccbase.dll 
		regsvr32.exe /s slbcsp.dll 
		regsvr32.exe /s cryptdlg.dll 
		regsvr32.exe /s oleaut32.dll 
		regsvr32.exe /s ole32.dll 
		regsvr32.exe /s shell32.dll 
		regsvr32.exe /s initpki.dll 
		regsvr32.exe /s wuapi.dll 
		regsvr32.exe /s wuaueng.dll 
		regsvr32.exe /s wuaueng1.dll 
		regsvr32.exe /s wucltui.dll 
		regsvr32.exe /s wups.dll 
		regsvr32.exe /s wups2.dll 
		regsvr32.exe /s wuweb.dll 
		regsvr32.exe /s qmgr.dll 
		regsvr32.exe /s qmgrprxy.dll 
		regsvr32.exe /s wucltux.dll 
		regsvr32.exe /s muweb.dll 
		regsvr32.exe /s wuwebv.dll
		regsvr32 /s wudriver.dll
		netsh winsock reset | Out-Null
		netsh winsock reset proxy | Out-Null

		Start-Service -Name BITS
		Start-Service -Name wuauserv
		Start-Service -Name AppIDSvc
		Start-Service -Name CryptSvc

		Write-Host "Successfully reset Windows Update" -ForegroundColor Green

		if ($AutomaticReboot) 
		{
			Restart-Computer -Force
		}
		else 
		{
			$Title = "Reboot Now"
			$Message = "A reboot is required to complete the reset, reboot now?"

			$Yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
			"Reboots the computer immediately."

			$No = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
			"Does not reboot the computer."

			$Options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No)

			$Result = $host.ui.PromptForChoice($Title, $Message, $Options, 0) 

			if ($Result -eq 0)
			{
				Restart-Computer -Force
			}
		}
	}

	End {
	}
}

Function Get-GroupsFromToken {
	<#
		.SYNOPSIS
			Enumerates the SIDs that are maintained in a user's access token issued at logon and translates the SIDs to group names.

		.DESCRIPTION
			The function gets the access token for the user that was issued at their logon. It reads the TOKEN_GROUPS from the access token and retrieves their SIDs from unmanaged memory. It then attempts to translate these SIDs to group names. The function includes all group memberships inherited from nested grouping.

			The function is run as a job so it executes in a new user context.

		.INPUTS
			None

		.OUTPUTS
			System.String[]

		.EXAMPLE
			Get-GroupsFromToken

			Returns an array of group names and/or SIDs in the access token for the current user.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATED: 11/14/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {}

	Process
	{
		$Job = Start-Job -ScriptBlock {

			Add-Type -Assembly System.ComponentModel
	
			$Signatures = @"
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool GetTokenInformation( 
												IntPtr TokenHandle,
												int TokenInformationClass,
												IntPtr TokenInformation,
												uint TokenInformationLength,
												out uint ReturnLength
													 );
		[DllImport("advapi32", SetLastError=true, CharSet=CharSet.Auto)]
		public static extern bool ConvertSidToStringSid(
												IntPtr pSID,
												[In,Out,MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid
												);
"@

			$AdvApi32 = Add-Type -MemberDefinition $Signatures -Name "AdvApi32" -Namespace "PsInvoke.NativeMethods" -PassThru -ErrorAction SilentlyContinue

			$TokenClasses = @"
		using System;
		using System.Runtime.InteropServices;

		namespace TokenServices 
		{
			public enum TOKEN_INFORMATION_CLASS
			{
				 TokenUser = 1,
				 TokenGroups,
				 TokenPrivileges,
				 TokenOwner,
				 TokenPrimaryGroup,
				 TokenDefaultDacl,
				 TokenSource,
				 TokenType,
				 TokenImpersonationLevel,
				 TokenStatistics,
				 TokenRestrictedSids,
				 TokenSessionId,
				 TokenGroupsAndPrivileges,
				 TokenSessionReference,
				 TokenSandBoxInert,
				 TokenAuditPolicy,
				 TokenOrigin,
				 TokenElevationType,
				 TokenLinkedToken,
				 TokenElevation,
				 TokenHasRestrictions,
				 TokenAccessInformation,
				 TokenVirtualizationAllowed,
				 TokenVirtualizationEnabled,
				 TokenIntegrityLevel,
				 TokenUiAccess,
				 TokenMandatoryPolicy,
				 TokenLogonSid,
				 MaxTokenInfoClass
			}

			public enum TOKEN_ELEVATION_TYPE
			{
				TokenElevationTypeDefault = 1,
				TokenElevationTypeFull,
				TokenElevationTypeLimited
			}

			public struct TOKEN_USER 
			{ 
				public SID_AND_ATTRIBUTES User; 
			} 
 
			[StructLayout(LayoutKind.Sequential)]
			public struct SID_AND_ATTRIBUTES
			{
				public IntPtr Sid;
				public UInt32 Attributes;    
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct TOKEN_GROUPS
			{
				public UInt32 GroupCount;
				[MarshalAs(UnmanagedType.ByValArray)] 
				public SID_AND_ATTRIBUTES[] Groups;
			}
		}
"@
	
			Add-Type $TokenClasses -ErrorAction SilentlyContinue

			$CloseHandleSignature = @"
		[DllImport( "kernel32.dll", CharSet = CharSet.Auto )]
		public static extern bool CloseHandle( IntPtr handle );
"@

			$Kernel32 = Add-Type -MemberDefinition $CloseHandleSignature -Name "Kernel32" -Namespace "PsInvoke.NativeMethods" -PassThru -ErrorAction SilentlyContinue

			[UInt32]$TokenInformationLength = 0

			$Success = $AdvApi32::GetTokenInformation( [System.Security.Principal.WindowsIdentity]::GetCurrent().Token,
													   [TokenServices.TOKEN_INFORMATION_CLASS]::TokenGroups,
													   [IntPtr]::Zero,
													   $TokenInformationLength, 
													   [Ref]$TokenInformationLength)


			if ($TokenInformationLength -gt 0)
			{
				[IntPtr]$TokenInformation = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenInformationLength)

				$Success = $AdvApi32::GetTokenInformation(  
															[System.Security.Principal.WindowsIdentity]::GetCurrent().Token,
															[TokenServices.TOKEN_INFORMATION_CLASS]::TokenGroups,
															$TokenInformation,
															$TokenInformationLength, 
															[Ref]$TokenInformationLength
														 )

				if ($TokenInformationLength -gt 0) 
				{
					$GroupArray = @()

					try
					{
						[TokenServices.TOKEN_GROUPS]$Groups = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenInformation, [System.Type][TokenServices.TOKEN_GROUPS])
						$SidAndAttrs = New-Object -TypeName TokenServices.SID_AND_ATTRIBUTES
						[int]$SidAndAttrsSize = [System.Runtime.InteropServices.Marshal]::SizeOf($SidAndAttrs)

						for ($i = 0; $i -lt $Groups.GroupCount; $i++) 
						{
							[TokenServices.SID_AND_ATTRIBUTES]$SidAndAttrsGroup = [System.Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]($TokenInformation.ToInt64() + ($i * $SidAndAttrsSize) + [IntPtr]::Size), [System.Type][TokenServices.SID_AND_ATTRIBUTES]);
                        
							[string]$SidString = ""
							$Success = $AdvApi32::ConvertSidToStringSid($SidAndAttrsGroup.Sid, [Ref]$SidString)
							try
							{
								$Group = (New-Object System.Security.Principal.SecurityIdentifier($SidString)).Translate([System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value
								$GroupArray += $Group
							}
							catch [Exception]
							{
								$GroupArray += $SidString
								Write-Warning -Message $_.Exception.Message
							}
						}

						Write-Output -InputObject $GroupArray
					}
					catch [Exception]
					{
						Write-Warning -Message $_.Exception.Message
					}
					finally
					{
						$Kernel32::CloseHandle($TokenInformation) | Out-Null
					}
				}
				else
				{
					$Kernel32::CloseHandle($TokenInformation) | Out-Null
					Write-Warning -Message (New-Object System.ComponentModel.Win32Exception([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())).Message
				}
			}
			else 
			{
				Write-Warning -Message (New-Object System.ComponentModel.Win32Exception([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())).Message
			}
		}

		Wait-Job -Job $Job | Out-Null
		Write-Output -InputObject (Receive-Job $Job)
	}

	End {}
}

Function Update-TokenGroupMembership {
	<#
		.SYNOPSIS
			The command refreshes the user's token and clears their current Kerberos tickets in order to pick up Active Directory group membership changes since their last logon.

		.DESCRIPTION
			The current group membership of the user is recorded. Then, the user's Kerberos tickets are purged. After that, the explorer.exe process is stopped and restarted, which refreshes the logon token for the user. The user will be required to enter a set of credentials and then required to enter their password to restart the explorer.exe process.

		.PARAMETER Credential
			The credentials of the current user. These are used to launch a new powershell process to get the updated token group membership. Without using credentials, the new process won't be started with the new token and won't reflect the updates in group membership.

		.PARAMETER UseSmartcard
			If the user only has a Smartcard and does not know their windows password, utilize this switch to enable prompting for Smartcard credentials when explorer.exe restarts. However, they will need to specify a credential object to start a new process to check the token changes.

		.INPUTS
			None

		.OUTPUTS
			None
			
		.EXAMPLE
			Update-TokenGroupMembership -Credential (Get-Credential)

			Updates the group membership for the current user.

		.EXAMPLE
			Update-TokenGroupMembership -UseSmartcard

			Updates the groups membership for the current user, but prompts for Smartcard credentials to restart explorer.exe. Because the Credential parameter was not specified, the changes in the group membership in the token are not displayed.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATED: 11/14/2016

	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0)]
		[PSCredential]$Credential = [PSCredential]::Empty,
		[Parameter(Position=1)]
		[switch]$UseSmartcard = $false
	)

	Begin {
		if ($Credential -eq $null) {
			$Credential = [System.Management.Automation.PSCredential]::Empty
		}
	}

	Process
	{
		$CurrentGroups = @()
    
		[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups.Translate([System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value | ForEach-Object {
			if ($_ -ne $null -and $_ -ne "") {
				$CurrentGroups += $_
			}
		}	

		#The ampersand signifies to execute the following scriptblock and treat each value as a parameter
		& "$env:SYSTEMROOT\system32\klist.exe" purge | Out-Null
		& "$env:SYSTEMROOT\system32\klist.exe" tgt | Out-Null

		& "$env:SYSTEMROOT\system32\taskkill.exe" "/F" "/IM" "explorer.exe" | Out-Null

		if (!$UseSmartcard)
		{
			& "$env:SYSTEMROOT\system32\runas.exe" "/user:$env:USERDOMAIN\$env:USERNAME" "explorer.exe" 
		}
		else
		{
			& "$env:SYSTEMROOT\system32\runas.exe" "/user:$env:USERDOMAIN\$env:USERNAME" "/smartcard" "explorer.exe" 
		}

		if ($Credential -ne [PSCredential]::Empty) {

			$Command = @"
		`$Groups = whoami /groups /FO CSV | ConvertFrom-Csv | Select-Object -ExpandProperty "Group Name"
		`$Groups2 = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups.Translate([System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value
		`$Groups += `$Groups2
		`$Groups | Select-Object -Unique
"@

			#Encode the command because it does not like the Open and Close parentheses
	
			$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
			$EncodedCommand = [Convert]::ToBase64String($Bytes)

			#Because Start-Process does not capture the standard out as part of the object, it can only be redirected to a file
			#Use the .NET object in order to capture the standard out without writing to file

			$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
			$ProcessInfo.FileName = "$env:SYSTEMROOT\System32\windowspowershell\v1.0\powershell.exe"
			$ProcessInfo.CreateNoWindow = $true
			$ProcessInfo.Verb = "runas"
			$ProcessInfo.RedirectStandardError = $true
			$ProcessInfo.RedirectStandardOutput = $true
			$ProcessInfo.UseShellExecute = $false
			$ProcessInfo.LoadUserProfile = $false
			$ProcessInfo.Domain = $Credential.UserName.Substring(0, $Credential.UserName.IndexOf("\"))
			$ProcessInfo.UserName = $Credential.UserName.Substring($Credential.UserName.IndexOf("\") + 1)
			$ProcessInfo.Password = $Credential.Password
			$ProcessInfo.Arguments = "-EncodedCommand $EncodedCommand"
			$Process = New-Object -TypeName System.Diagnostics.Process
			$Process.StartInfo = $ProcessInfo
			$Process.Start() | Out-Null
			$Process.WaitForExit()

			if ($Process.ExitCode -eq 0)
			{
				$NewGroups = @()
				$Process.StandardOutput.ReadToEnd().Split("`r`n") | ForEach-Object {
					if ($_ -ne $null -and $_ -ne [System.String]::Empty) {
						$NewGroups += $_
					}
				}

				Write-Host ""

				foreach ($OldGroup in $CurrentGroups) {
					if (!$NewGroups.Contains($OldGroup) -and $OldGroup -ne "CONSOLE LOGON") {
						Write-Host "REMOVED : $OldGroup" -ForegroundColor Red
					}
				}

				Write-Host ""

				foreach ($NewGroup in $NewGroups) {
					if (!($CurrentGroups.Contains($NewGroup)) -and !$NewGroup.StartsWith("Mandatory Label\")) {
						Write-Host "ADDED : $NewGroup" -ForegroundColor Green
					}
				}
			}
			else
			{
				throw $Process.StandardError.ReadToEnd()
			}
		}
	}

	End {}
}

Function Start-WithImpersonation {
	<#
		.SYNOPSIS
			Runs a scriptblock while impersonating another user.

		.DESCRIPTION
			The user enters credentials and a scriptblock to execute. The scriptblock is executed while impersonating the entered credentials.

		.PARAMETER Credential			
			The credentials that will be impersonated.

		.PARAMETER Scriptblock		
			The scriptblock that will be executed with the impersonated credentials

		.PARAMETER LogonType
			The type of logon that will be used for impersonation. This parameter defaults to "INTERACTIVE"

		.INPUTS
			System.Management.Automation.Scriptblock, System.String, System.Management.Automation.PSCredential

		.OUTPUTS
			System.Management.Automation.PSObject
	
				The object returned is whatever the scriptblock from the input returns.		

		.EXAMPLE
			Start-WithImpersonation -Credential (Get-Credential) -Scriptblock {Get-Service} -LogonType INTERACTIVE

			Runs the get-service command using the impersonated credentials received from the Credential parameter.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATED: 2/27/2016
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=1,Mandatory=$true)]
		[PSCredential]$Credential,
		[Parameter(Position=0,Mandatory=$true)]
		[Scriptblock]$Scriptblock,
		[Parameter(Position=2)]
		[ValidateSet("INTERACTIVE","NETWORK","NETWORK_CLEARTEXT","NEW_CREDENTIALS","SERVICE","BATCH","UNLOCK")]
		[string]$LogonType = "INTERACTIVE"
	)

	Begin {}

	Process
	{
	
		$Job = Start-Job -ArgumentList @($Credential, $Scriptblock) -ScriptBlock {
			Add-Type -AssemblyName System.ComponentModel

			[PSCredential]$Credential = $args[0]
			[Scriptblock]$Scriptblock = [Scriptblock]::Create($args[1])

			$Signatures = @"
		[DllImport( "advapi32.dll" )]
		public static extern bool LogonUser( String lpszUserName,
											 String lpszDomain,
											 String lpszPassword,
											 int dwLogonType,
											 int dwLogonProvider,
											 ref IntPtr phToken );
"@

			$AdvApi32 = Add-Type -MemberDefinition $Signatures -Name "AdvApi32" -Namespace "PsInvoke.NativeMethods" -PassThru

			$CloseHandleSignature = @"
		[DllImport( "kernel32.dll", CharSet = CharSet.Auto )]
		public static extern bool CloseHandle( IntPtr handle );
"@

			$Kernel32 = Add-Type -MemberDefinition $CloseHandleSignature -Name "Kernel32" -Namespace "PsInvoke.NativeMethods" -PassThru

			try
			{
				#Logon Types
				[int]$LOGON32_LOGON_INTERACTIVE = 2
				[int]$LOGON32_LOGON_NETWORK = 3
				[int]$LOGON32_LOGON_BATCH = 4
				[int]$LOGON32_LOGON_SERVICE = 5
				[int]$LOGON32_LOGON_UNLOCK = 7
				[int]$LOGON32_LOGON_NETWORK_CLEARTEXT = 8 #Win2K or higher
				[int]$LOGON32_LOGON_NEW_CREDENTIALS = 9 #Win2K or higher

				#Logon Providers
				[int]$LOGON32_PROVIDER_DEFAULT = 0
				[int]$LOGON32_PROVIDER_WINNT35 = 1
				[int]$LOGON32_PROVIDER_WINNT40 = 2
				[int]$LOGON32_PROVIDER_WINNT50 = 3

				[int]$Logon 
				[int]$Provider = $LOGON32_PROVIDER_DEFAULT

				switch ($LogonType)
				{
					"INTERACTIVE" {
						$Logon = $LOGON32_LOGON_INTERACTIVE
						break
					}
					"NETWORK" {
						$Logon = $LOGON32_LOGON_NETWORK
						break
					}
					"NETWORK_CLEARTEXT" {
						$Logon = $LOGON32_LOGON_NETWORK_CLEARTEXT
						break
					}
					"NEW_CREDENTIALS" {
						$Logon = $LOGON32_LOGON_NEW_CREDENTIALS
						$Provider = $LOGON32_PROVIDER_WINNT50
						break
					}
					"SERVICE" {
						$Logon = $LOGON32_LOGON_SERVICE
						break
					}
					"BATCH" {
						$Logon = $LOGON32_LOGON_BATCH
						break
					}
					"UNLOCK" {
						$Logon = $LOGON32_LOGON_UNLOCK
						break
					}
					default {
						$Logon = $LOGON32_LOGON_INTERACTIVE
						break
					}
				}

				$TokenHandle = [IntPtr]::Zero

				if ($Credential.UserName.Contains("\"))
				{
					$UserName = $Credential.UserName.Substring($Credential.UserName.IndexOf("\") + 1)
					$Domain = $Credential.UserName.Substring(0, $Credential.UserName.IndexOf("\"))
				}
				else
				{
					$UserName = $Credential.UserName
					$Domain = $env:COMPUTERNAME
				}

				$Success = $AdvApi32::LogonUser($UserName, $Domain, $Credential.Password, $Logon, $Provider, [Ref]$TokenHandle)
    
				if (!$Success)
				{
					$ReturnValue = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
					$Message = (New-Object -TypeName System.ComponentModel.Win32Exception($ReturnValue)).Message
					Write-Warning -Message "LogonUser was unsuccessful. Error code: $ReturnValue - $Message"
					return
				}

				$NewIdentity = New-Object System.Security.Principal.WindowsIdentity($TokenHandle)

				$IdentityName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
				Write-Host "Current Identity: $IdentityName"
    
				$Context = $NewIdentity.Impersonate()

				$IdentityName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
				Write-Host "Impersonating: $IdentityName"

				Write-Host "Executing custom script"
				$Result = & $Scriptblock
				return $Result
			}
			catch [System.Exception]
			{
				Write-Warning -Message $_.Exception.ToString()
			}
			finally
			{
				if ($Context -ne $null)
				{
					$Context.Undo()
				}

				if ($TokenHandle -ne [System.IntPtr]::Zero)
				{
					$Kernel32::CloseHandle($TokenHandle) | Out-Null
				}
			}
		}

		Wait-Job -Job $Job | Out-Null
		Write-Output -InputObject (Receive-Job -Job $Job)
	}

	End
	{		
	}
}

Function Enable-WinRM {
	<#
		.SYNOPSIS
			Enables WinRM on a host.

		.DESCRIPTION
			The function enables PowerShell remoting, sets WinRM to automatically start, adds the provided to trusted hosts (which defaults to all hosts), and creates the firewall rule to allow inbound WinRM.

		.PARAMETER TrustedHosts
			The hosts that are trusted for remote mamangement. This can be an IP range, a subnet, or a wildcard. This defaults to all hosts: "*".

		.INPUTS
			System.String

				The value can be piped to Enable-WinRM.

		.OUTPUTS
			None

		.EXAMPLE
			Enable-WinRM -TrustedHosts "192.168.100.0-192.168.100.255"

		.NOTES
			This command should be run with administrative credentials

			AUTHOR: Michael Haken
			LAST UPDATED: 2/27/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string]$TrustedHosts = "*"
	)

	Begin {
		if (!(Test-IsLocalAdmin)) {
			throw "This cmdlet must be run with admin credentials."
		}
	}

	Process
	{
		Set-NetConnectionProfile -NetworkCategory Private
		Enable-PSRemoting -Force 
		Set-Service -Name WinRM -StartupType Automatic
		Start-Service -Name WinRM
		Set-Item WSMan:\localhost\Client\TrustedHosts -Value $TrustedHosts -Force
		Restart-Service -Name WinRM
		New-NetFirewallRule -Name "Allow_WinRM" -DisplayName "Windows Remote Management (WinRM)" -Description "Allows WinRM ports 5985-5986 inbound." -Protocol TCP -LocalPort 5985,5986 -Enabled True -Action Allow -Profile Any
		Write-Host "WinRM Enabled" -ForegroundColor Green
	}
	
	End {}
}

Function New-EmptyTestFile {
	<#
		.SYNOPSIS
			Creates an empty file of the specified size.

		.DESCRIPTION
			Creates a file of the provided size in the provided location to test against.

		.PARAMETER FilePath
			The location the file should be created. This defaults to the user's desktop with a filename of Test.txt.

		.PARAMETER Size
			The size of the file to be created. Can be specified in bytes or with units, such as 64GB or 32MB.

		.INPUTS
			None

		.OUTPUTS
			None

		.EXAMPLE
			New-EmptyTestFile -FilePath "c:\test.cab" -Size 15MB

			Creates an empty 15MB cab file at c:\test.cab.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATED: 11/14/2016

		.FUNCTIONALITY
			This cmdlet is used to create empty test files to perform tests on.
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=1)]
		[string]$FilePath = "$env:USERPROFILE\Desktop\Test.txt",
		[Parameter(Position=0,Mandatory=$true)]
		[UInt64]$Size
	)

	Begin {}

	Process
	{
		$Writer = [System.IO.File]::Create($FilePath)

		$Bytes = New-Object Byte[] ($Size)
		$Writer.Write($Bytes, 0, $Bytes.Length)

		$Writer.Close()

		Write-Host "$Size file created at $FilePath"
	}

	End {}
}

Function Start-PortScan {
	<#
		.SYNOPSIS
			Conducts a port scan on the selected computer.

		.DESCRIPTION
			Tries to connect to common ports on a targetted system and reports back the port status of each. Each connection is scheduled as a job; the function waits for all jobs to exit the running status before returning scan information.

		.PARAMETER ComputerName
			The name of the computer to scan. The parameter defaults to "localhost"

		.INPUTS
			System.String

				The input can be piped to Start-PortScan

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]

				Each custom object has a property of Service, Port, and Status. Status is either Open or Closed.

		.EXAMPLE
			Start-PortScan -ComputerName remotecomputer.net

			Returns an array of open and closed ports on remotecomputer.net

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016

		.FUNCTIONALITY
			The intended use of this cmdlet is to conduct a security scan of ports on a computer.

	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string]$ComputerName = "localhost"
	)
	
	Begin
	{
		$Ports = $script:Ports | Sort-Object -Property Port
	}

	Process
	{
		$Jobs = @()

		$i = 1

		foreach ($Item in $Ports)    
		{
			Write-Progress -Activity "Running Port Scan" -Status "Scanning Port $($Item.Port) $($Item.Service)" -PercentComplete (($i++ / $Ports.Count) * 100)
		
			$Jobs += Start-Job -ArgumentList @($ComputerName,$Item) -ScriptBlock {
				$ComputerName = $args[0]
				$Service = $args[1].Service
				$Port = $args[1].Port

				$Socket = New-Object Net.Sockets.TcpClient
				$ErrorActionPreference = 'SilentlyContinue'
				$Socket.Connect($ComputerName, $Port)
				$ErrorActionPreference = 'Continue' 
		
				if ($Socket.Connected) 
				{
					$Socket.Close()
					return [PSCustomObject]@{"Service"="$Service";"Port"=$Port;"Status"="Open"}
				}
				else 
				{
					return [PSCustomObject]@{"Service"="$Service";"Port"=$Port;"Status"="Closed"}
				}
			}
		}

		Write-Progress -Completed -Activity "Running Port Scan"

		Write-Host "Waiting for jobs to complete..."

		$RunningJobs = @()

		$RunningJobs = Get-Job | Where-Object {$_.Id -in ($Jobs | Select-Object -ExpandProperty Id)}

		while (($RunningJobs | Where {$_.State -eq "Running"}).Length -gt 0) {
			$Completed = ($RunningJobs | Where {$_.State -eq "Completed"}).Length

			Write-Progress -Activity "Completing Jobs" -Status ("Waiting for connections to complete: " + (($Completed / $RunningJobs.Length) * 100) + "% Complete") -PercentComplete (($Completed / $RunningJobs.Length) * 100)
			Start-Sleep -Milliseconds 500
		}

		Wait-Job -Job $Jobs | Out-Null
		$Data = @()
		Receive-Job -Job $Jobs | ForEach-Object {
			$Data += $_
		}

		Remove-Job -Job $Jobs

		Write-Output -InputObject ($Data | Select-Object -Property * -ExcludeProperty RunspaceId)
	}

	End
	{	
	}
}

Function Remove-JavaInstallations {
	<#
		.SYNOPSIS
			Removes old versions of Java JRE or does a complete removal.

		.DESCRIPTION
			The function identifies well-known directories, registry keys, and registry key entries. Then based on the type of cleanup and architecture targetted, it removes those files, directories, registry keys, and registry key entries. During a cleanup, the current version of Java is specified so that it is not removed. 

		.PARAMETER MajorVersion
			The current major version of Java, for example 7 or 8.

		.PARAMETER MinorVersion
			The current minor version of Java, this is almost always 0.

		.PARAMETER ReleaseVersion
			The current release version of Java, this is the update number, for example 15, 45, or 73.

		.PARAMETER PluginVersion
			The major version of the Java web plugin, for example 10 or 11.
	
		.PARAMETER Architecture
			The architecture to target, either x86, x64, or All. This defaults to All.

		.PARAMETER FullRemoval
			Specifies that a full removal of Java should be conducted.

		.INPUTS
			None

		.OUTPUTS
			None

		.EXAMPLE
			Remove-JavaInstallations -MajorVersion 8 -ReleaseVersion 15 -PluginVersion 11 -Architecture All

			Removes all versions previous to JRE 8u15.

		.EXAMPLE
			Remove-JavaInstallations -MajorVersion 8 -ReleaseVersion 15 -PluginVersion 11 -Architecture x64

			Removes all versions previous to JRE 8u15 that are x64 installations.

		.EXAMPLE
			Remove-JavaInstallations -FullRemoval

			Removes all versions of JRE from the system.

		.NOTES
			AUTHOR: Michael Haken	
			LAST UPDATE: 11/14/2016

		.FUNCTIONALITY
			The intended use of this cmdlet is to conduct complete removals of the Java JRE software.
	#>

	[CmdletBinding(DefaultParameterSetName="Cleanup")]
	Param(
		[Parameter(Position=0,ParameterSetName="Cleanup",Mandatory=$true)]
		[int]$MajorVersion,
		[Parameter(ParameterSetName="Cleanup")]
		[int]$MinorVersion = 0,
		[Parameter(Position=1,ParameterSetName="Cleanup",Mandatory=$true)]
		[int]$ReleaseVersion,
		[Parameter(Position=2,ParameterSetName="Cleanup",Mandatory=$true)]
		[int]$PluginVersion,
		[Parameter(ParameterSetname="Cleanup")]
		[ValidateSet("x86","x64","All")]
		[string]$Architecture = "All",
		[Parameter(ParameterSetName="Removal",Mandatory=$true)]
		[switch]$FullRemoval	
	)

	Begin
	{
		if ((Get-PSDrive | Where-Object {$_.Root -eq "HKEY_CLASSES_ROOT"}))
		{
			Get-PSDrive | Where-Object {$_.Root -eq "HKEY_CLASSES_ROOT"} | Remove-PSDrive
		}

		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null

		#These keys are used to cleanup HKLM:\\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL
		$64BIT_REGISTRY_KEY = "*26A24AE4-039D-4CA4-87B4-2F8641*FF*" # 26A24AE4-039D-4CA4-87B4-2F46417015FF - Java 7u15 x64 
		$32BIT_REGISTRY_KEY = "*26A24AE4-039D-4CA4-87B4-2F8321*FF*"
		$GENERIC_REGISTRY_KEY = "*26A24AE4-039D-4CA4-87B4-2F8*1*FF*"

		#These keys are used to cleanup HKCR:\\Installer\Products
		$64BIT_HKCR_INSTALLER_PRODUCTS_KEY = "*4EA42A62D9304AC4784BF23812*FF*" # 4EA42A62D9304AC4784BF238120683FF - Java 6u38 x86
		$32BIT_HKCR_INSTALLER_PRODUCTS_KEY = "*4EA42A62D9304AC4784BF26814*FF*"
		$GENERIC_HKCR_INSTALLER_PRODUCTS_KEY = "*4EA42A62D9304AC4784BF2*81*FF*"

		#Java AutoUpdate
		$HKCR_JAVA_AUTOUPDATER = "F60730A4A66673047777F5728467D401"
		$HKLM_JAVA_AUTOUPDATER = "F60730A4A66673047777F5728467D401"

		#Build the software version 
		[string]$LONG_PUNCTUATED_VERSION = ""
		[string]$NON_PUNCTUATED_VERSION = ""
		[string]$SHORT_VERSION = "1." + $MajorVersion # 1.7
		[string]$BASE_VERSION = "1." + $MajorVersion + "." + $MinorVersion + ".0" # 1.7.0
		[string]$FULL_VERSION = ""
		[string]$PLUGIN_VERSION = $PluginVersion.ToString()		
	}

	Process
	{
		$Temp = $ReleaseVersion.ToString().ToCharArray()
		[System.Array]::Reverse($Temp)
		[string]$REVERSE_RELEASE = $Temp.ToString()

		$Temp = ($MajorVersion.ToString() + $MinorVersion.ToString()).ToCharArray()
		[System.Array]::Reverse($Temp)
		[string]$REVERSE_VERSION = $Temp.ToString()

		#Make the current release string two characters long
		if ($ReleaseVersion.ToString().Length -eq 1) 
		{
			$ReleaseVersion = "0" + $ReleaseVersion.ToString()
		}

		switch ($ReleaseVersion) 
		{
			"00" {
				$FULL_VERSION = "1." + $MajorVersion + (& if($MinorVersion -gt 0) {"." + $MinorVersion } else {""}) # 1.7 or 1.7.1
				$NON_PUNCTUATED_VERSION = "1" + $MajorVersion + $MinorVersion # 170
				$LONG_PUNCTUATED_VERSION = "1." + $MajorVersion + "." + $MinorVersion # 1.7.0
				break
			}
			default {
				$FULL_VERSION = "1." + $MajorVersion + "." + $MinorVersion + "_" + $ReleaseVersion # 1.7.0_15
				$NON_PUNCTUATED_VERSION = "1" + $MajorVersion + $MinorVersion + "_" + $ReleaseVersion # 170_15
				$LONG_PUNCTUATED_VERSION = $FULL_VERSION # 1.7.0_15
				break
			}
		}

		$REVERSE_VERSION_REGISTRY_KEY = $REVERSE_VERSION + $REVERSE_RELEASE + "FF*"
		$NON_PUNCTUATED_REGISTRY_KEY = $MajorVersion.ToString() + $MinorVersion.ToString() + $ReleaseVersion.ToString() + "FF*"
		
		#Create the registry strings to match Java in HKCR and HKLM
		$UNINSTALL_REGISTRY_KEY = ""
		$HKCR_REGISTRY_KEY = ""

		switch ($Architecture)
		{
			# HKLM:\SOFTWARE\Wow6432Node\
			"x86" {
				$UNINSTALL_REGISTRY_KEY = "*26A24AE4-039D-4CA4-87B4-2F8321" + $NON_PUNCTUATED_REGISTRY_KEY # 3217000 or 3217015
				$HKCR_REGISTRY_KEY = "*4EA42A62D9304AC4784BF23812" + $REVERSE_VERSION_REGISTRY_KEY + "*" #38120751
				break
			}
			# HKLM:\SOFTWARE\
			"x64" {
				$UNINSTALL_REGISTRY_KEY = "*26A24AE4-039D-4CA4-87B4-2F8641" + $NON_PUNCTUATED_REGISTRY_KEY # 6417000 or 6417015
				$HKCR_REGISTRY_KEY = "*4EA42A62D9304AC4784BF26814" + $REVERSE_VERSION_REGISTRY_KEY +"*" #68140751
				break
			}
			"All" {
				$UNINSTALL_REGISTRY_KEY = "*26A24AE4-039D-4CA4-87B4-2F8*1" + $NON_PUNCTUATED_REGISTRY_KEY # *17000 or *17015
				$HKCR_REGISTRY_KEY = "*4EA42A62D9304AC4784BF2*81*" + $REVERSE_VERSION_REGISTRY_KEY + "*" #*81*0751
				break
			}
		}

		$FilePaths = @()
		$UserProfiles = Get-ChildItem -Path "$env:SystemDrive\Users"

		Write-Verbose -Message "[INFO] Getting All User Profiles"

		foreach ($Profile in $UserProfiles)
		{
			$FilePaths += "$env:SystemDrive\Users\" + $Profile.Name + "\AppData\LocalLow\Sun"
			$FilePaths += "$env:SystemDrive\Users\" + $Profile.Name + "\AppData\Local\Temp\java_install_reg.log"
			$FilePaths += "$env:SystemDrive\Users\" + $Profile.Name + "\AppData\Local\Temp\java_install.log"  
		}

		Write-Verbose -Message "[INFO] Adding file paths"

		$FilePaths += "$env:SYSTEMROOT\Temp\java_install.log"
		$FilePaths += "$env:SYSTEMROOT\Temp\java_install_reg.log"

		if ($PSCmdlet.ParameterSetName -eq "Removal")
		{
			$FilePaths += "$env:ALLUSERSPROFILE\Sun"

			if ($Architecture -eq "x86" -or $Architecture -eq "All")
			{
				$FilePaths += "$env:SystemDrive\Program Files (x86)\Java"
				$FilePaths += "$env:SYSTEMROOT\System32\java.exe"
				$FilePaths += "$env:SYSTEMROOT\System32\javaw.exe"
				$FilePaths += "$env:SYSTEMROOT\System32\javaws.exe"
			}
			if ($Architecture -eq "x64" -or $Architecture -eq "All")
			{
				$FilePaths += "$env:SystemDrive\Program Files\Java"
				$FilePaths += "$env:SYSTEMROOT\SysWow64\java.exe"
				$FilePaths += "$env:SYSTEMROOT\SysWow64\javaw.exe"
				$FilePaths += "$env:SYSTEMROOT\SysWow64\javaws.exe"
			}
		}

		if ($PSCmdlet.ParameterSetName -eq "Cleanup")
		{
			if ($Architecture -eq "x86" -or $Architecture -eq "All")
			{
				$FilePaths += @(Get-ChildItem "$env:SystemDrive\program files (x86)\Java" | Where-Object {$_.name -notlike "jre" + $MajorVersion})
			}
			if ($Architecture -eq "x64" -or $Architecture -eq "All")
			{
				$FilePaths += @(Get-ChildItem "$env:SystemDrive\program files\Java" | Where-Object {$_.name -notlike "jre" + $MajorVersion})
			}
		}
		
		Write-Verbose -Message "[INFO] Getting Registry Keys"
        $ErrorActionPreference = "SilentlyContinue"
		$RegistryKeys = @()

		$RegistryKeys += 'HKCU:\Software\AppDataLow\Software\Javasoft'
		$RegistryKeys += 'HKCU:\Software\Javasoft\Java Update'
		$RegistryKeys += 'HKCU:\Software\Microsoft\Protected Storage System Provider\S-1-5-21-1292428093-1275210071-839522115-1003\Data'
		$RegistryKeys += 'HKLM:\SOFTWARE\MozillaPlugins\@java.com'
		$RegistryKeys += 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\0357E4991DA5FF14F9615B3312070F06'
		$RegistryKeys += 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\0357E4991DA5FF14F9615B3512070F06'
		$RegistryKeys += 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\4EA42A62D9304AC4784BF238120652FF'
		$RegistryKeys += 'HKLM:\SOFTWARE\Classes\JavaSoft.JavaBeansBridge'
		$RegistryKeys += 'HKLM:\SOFTWARE\Classes\JavaSoft.JavaBeansBridge.1'
		$RegistryKeys += 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\0357E4991DA5FF14F9615B3312070F07'
		$RegistryKeys += 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\0357E4991DA5FF14F9615B3312070F08'
		$RegistryKeys += 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\0357E4991DA5FF14F9615B3312070F09'
		$RegistryKeys += 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\4EA42A62D9304AC4784BF2381206220F'

		if ($PSCmdlet.ParameterSetName -eq "Cleanup")
		{
			$RegistryKeys += @((Get-ChildItem -Path "HKCR:\" | Where-Object {($_.Name -like "*JavaPlugin*") -and ($_.Name -notlike "*JavaPlugin." + $NON_PUNCTUATED_VERSION + "*")}).PSPath)
			$RegistryKeys += @((Get-ChildItem -Path "HKCR:\" | Where-Object {($_.name -like "*JavaWebStart.isInstalled.*") -and ($_.Name -notlike "*JavaWebStart.isInstalled." + $BASE_VERSION +"*")}).PSPath)
			$RegistryKeys += @((Get-ChildItem -Path "HKCR:\Installer\Products" | Where-Object {($_.Name -like $GENERIC_HKCR_INSTALLER_PRODUCTS_KEY) -and ($_.Name -notlike $HKCR_REGISTRY_KEY)}).PSPath)
			$RegistryKeys += @((Get-ChildItem -Path "HKCU:\Software\JavaSoft\Java Runtime Environment" | Where-Object {($_.Name -notlike "*" + $FULL_VERSION +"*") -and ($_.name -notlike "*" + $LONG_PUNCTUATED_VERSION +"*")}).PSPath)
			$RegistryKeys += @((Get-ChildItem -Path "HKCU:\Software\JavaSoft\Java2D" | Where-Object {($_.Name -notlike  "*" + $LONG_PUNCTUATED_VERSION + "*")}).PSPath) 
			$RegistryKeys += @((Get-ChildItem -Path "HKCU:\Software\Classes" | Where-Object {($_.Name -like "*JavaPlugin*") -and ($_.Name -notlike "*JavaPlugin." + $NON_PUNCTUATED_VERSION + "*")}).PSPath)
			$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\Installer\Products" | Where-Object {($_.Name -like $GENERIC_HKCR_INSTALLER_PRODUCTS_KEY) -and  ($_.Name -notlike $HKCR_REGISTRY_KEY) }).PSPath)

			if ($Architecture -eq "x86" -or $Architecture -eq "All")
			{
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\Installer\Features\" | Where-Object {$_.Name -like $32BIT_REGISTRY_KEY}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\" | Where-Object {($_.Name -like $32BIT_REGISTRY_KEY) -and ($_.Name -notlike $UNINSTALL_REGISTRY_KEY)}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes" | Where-Object {($_.Name -notlike "*JavaPlugin." + $NON_PUNCTUATED_VERSION + "*") -and ($_.Name -like "*JavaPlugin*")}).PSPath) 
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes" | Where-Object {($_.Name -notlike "*JavaWebStart.isInstalled." + $BASE_VERSION + "*") -and ($_.Name -like "*JavaWebStart.isInstalled.*")}).PSPath) 
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Runtime Environemt" | Where-Object {($_.Name -notlike  "*" + $FULL_VERSION + "*") -and ($_.Name -notlike  "*" + $SHORT_VERSION + "*")}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Plug-in" | Where-Object {($_.Name -notlike  "*" + $PLUGIN_VERSION + "*")}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Web Start" | Where-Object {($_.Name -notlike "*" + $FULL_VERSION +"*") -and ($_.name -notlike "*" + $SHORT_VERSION +"*")}).PSPath)			
			}

			if ($Architecture -eq "x64" -or $Architecture -eq "All")
			{
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\Installer\Features\" | Where-Object {$_.Name -like $64BIT_REGISTRY_KEY}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" | Where-Object {($_.Name -like $64BIT_REGISTRY_KEY) -and ($_.Name -notlike $UNINSTALL_REGISTRY_KEY)}).PSPath) 
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes" | Where-Object {($_.Name -notlike "*JavaWebStart.isInstalled." + $BASE_VERSION + "*") -and ($_.Name -like "*JavaWebStart.isInstalled.*")}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes" | Where-Object {($_.Name -notlike "*JavaPlugin." + $NON_PUNCTUATED_VERSION + "*") -and ($_.Name -like "*JavaPlugin*")}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\JavaSoft\Java Runtime Environemt" | Where-Object {($_.Name -notlike  "*" + $FULL_VERSION + "*") -and ($_.Name -notlike  "*" + $SHORT_VERSION + "*")}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\JavaSoft\Java Plug-in" | Where-Object {($_.Name -notlike  "*" + $PLUGIN_VERSION + "*")}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\JavaSoft\Java Web Start" | Where-Object {($_.Name -notlike "*" + $FULL_VERSION +"*") -and ($_.name -notlike "*" + $SHORT_VERSION +"*")}).PSPath)	
			}
		}

		if ($PSCmdlet.ParameterSetName -eq "Removal")
		{			
			$RegistryKeys += "HKLM:\SOFTWARE\Classes\jarfile"
			$RegistryKeys += @((Get-ChildItem -Path "HKCR:\" | Where-Object {($_.Name -like "*JavaPlugin*")}).PSPath)
			$RegistryKeys += @((Get-ChildItem -Path "HKCR:\" | Where-Object {($_.Name -like "*JavaScript*")}).PSPath)
			$RegistryKeys += @((Get-ChildItem -Path "HKCR:\" | Where-Object {($_.Name -like "*JavaWebStart*")}).PSPath)
			$RegistryKeys += @((Get-ChildItem -Path "HKCR:\Installer\Products" | Where-Object {($_.Name -like $GENERIC_HKCR_INSTALLER_PRODUCTS_KEY)}).PSPath)
			$RegistryKeys += "HKCU:\Software\JavaSoft\Java Runtime Environment"
			$RegistryKeys += "HKCU:\Software\JavaSoft\Java2D"
			$RegistryKeys += "HKCR:\Installer\Products\$HKCR_JAVA_AUTOUPDATER"

			if ($Architecture -eq "x86" -or $Architecture -eq "All")
			{
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\Installer\Features\" | Where-Object {$_.Name -like $32BIT_REGISTRY_KEY -or $_.Name -like $HKLM_JAVA_AUTOUPDATER}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\" | Where-Object {$_.Name -like $32BIT_REGISTRY_KEY}).PSPath) 
				$RegistryKeys += "HKLM:\SOFTWARE\Wow6432Node\JavaSoft"
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes" | Where-Object {$_.Name -like "*JavaWebStart*"}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes" | Where-Object {$_.Name -like "*JavaPlugin*"}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\Installer\Products" | Where-Object {$_.Name -like $32BIT_HKCR_INSTALLER_PRODUCTS_KEY}).PSPath)
				$RegistryKeys += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\javaws.exe"
			}

			if ($Architecture -eq "x64" -or $Architecture -eq "All")
			{
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\Installer\Features\" | Where-Object {$_.Name -like $64BIT_REGISTRY_KEY -or $_.Name -like $HKLM_JAVA_AUTOUPDATER}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" | Where-Object {$_.Name -like $64BIT_REGISTRY_KEY -or $_.Name -like $HKLM_JAVA_AUTOUPDATER}).PSPath) 
				$RegistryKeys += "HKLM:\SOFTWARE\JavaSoft"
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes" | Where-Object {$_.Name -like "*JavaWebStart*"}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\Software\Classes" | Where-Object {$_.Name -like "*JavaPlugin*"}).PSPath)
				$RegistryKeys += @((Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\Installer\Products" | Where-Object {$_.Name -like $64BIT_HKCR_INSTALLER_PRODUCTS_KEY}).PSPath)
				$RegistryKeys += "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\javaws.exe"
			}
		}

		Write-Verbose -Message "[INFO] Getting Registry Key Properties"

		$RegistryKeyProperties = @()

		$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders") 
		$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\System\ControlSet001\Control\Session Manager\Environment")
		$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\System\ControlSet002\Control\Session Manager\Environment")
		$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\System\ControlSet003\Control\Session Manager\Environment")
		$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Environment")
		$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\SOFTWARE\Classes\jarfile\shell\open\command")

		$EntriesToKeep = @()

		if ($PSCmdlet.ParameterSetName -eq "Cleanup")
		{
			switch ($Architecture)
			{
				"x86" {
					$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\javaws.exe")
					$NOT_LIKE_1 = "$env:SystemDrive\program files (x86)\*\jre" + $majorbuild + "\*"
					$NOT_LIKE_2 = "$env:SystemDrive\program files (x86)\*\jre" + $shortversion + "\*"
					$LIKE = "$env:SystemDrive\program files (x86)\*\jre*"
					break
				}
				"x64" {
					$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\javaws.exe")
					$NOT_LIKE_1 = "$env:SystemDrive\program files\*\jre" + $majorbuild + "\*"
					$NOT_LIKE_2 = "$env:SystemDrive\program files\*\jre" + $shortversion + "\*"
					$LIKE = "$env:SystemDrive\program files\*\jre*"
					break
				}
				"All" {
					$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\javaws.exe")
					$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\javaws.exe")
					$NOT_LIKE_1 = "$env:SystemDrive\program files*\*\jre" + $majorbuild + "\*"
					$NOT_LIKE_2 = "$env:SystemDrive\program files*\*\jre" + $shortversion + "\*"
					$LIKE = "$env:SystemDrive\program files*\*\jre*"
					break
				}
			}

			foreach ($Property in $RegistryKeyProperties)
			{
				if ((($Property.Property -like $LIKE) -and ($Property.Property -notlike $NOT_LIKE_1) -and ($Property.Property -notlike $NOT_LIKE_2)) -or
					(($Property.Value -like $LIKE) -and ($Property.Value -notlike $NOT_LIKE_1) -and ($Property.Value -notlike $NOT_LIKE_2)))
				{
					$EntriesToKeep += $Property
				}
			}
		}

		if ($PSCmdlet.ParameterSetName -eq "Removal")
		{
			switch ($Architecture)
			{
				"x86" {
					$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\javaws.exe")
					$LIKE = "$env:SystemDrive\program files (x86)\*\jre*"
					break
				}
				"x64" {
					$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\javaws.exe")
					$LIKE = "$env:SystemDrive\program files\*\jre*"
					break
				}
				"All" {
					$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\javaws.exe")
					$RegistryKeyProperties += @(Get-RegistryKeyEntries -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\javaws.exe")
					$LIKE = "$env:SystemDrive\program files*\*\jre*"
					break
				}
			}

			foreach ($Property in $RegistryKeyProperties)
			{
				if (($Property.Property -like $LIKE) -or ($Property.Value -like $LIKE))
				{
					$EntriesToKepp += $Property
				}
			}
		}

		$RegistryKeyProperties = $EntriesToKeep

        $ErrorActionPreference = "Continue"

		[int]$DirectoryCount = 0
		[int]$RegistryKeyCount = 0
		[int]$RegistryEntryCount = 0

		Write-Verbose -Message "[INFO] Removing Directories and Files"

		foreach ($Item in $FilePaths)
		{
			if (Test-Path -Path $Item)
			{
				$DirectoryCount++
				Remove-Item -Path $Item -Force -Recurse
			}
		}

		Write-Verbose -Message "[INFO] Removing Registry Keys"

		foreach ($Item in $RegistryKeys)
		{
			if (Test-Path -Path $Item)
			{
				$RegistryKeyCount++
				Remove-Item -Path $Item -Force -Recurse
			}
		}

		Write-Verbose -Message "[INFO] Removing Registry Key Entries"

		foreach ($Item in $RegistryKeyProperties)
		{
			if (Test-Path -Path $Item.Path)
			{
				$RegistryEntryCount++
				Remove-ItemProperty -Path $Item.Path -Name $Item.Property -Force
			}
		}

		Write-Host "[INFO] Java cleanup removed $DirectoryCount directories, $RegistryKeyCount registry keys, and $RegistryEntryCount registry key entries."
	}

	End
	{		
	}
}

Function Get-RegistryKeyEntries {
	<#
		.SYNOPSIS
			Gets all of the properties and their values associated with a registry key.

		.DESCRIPTION
			The Get-RegistryKeyEntries cmdlet gets each entry and its value for a specified registry key.

		.PARAMETER Path
			The registry key path in the format that PowerShell can process, such as HKLM:\Software\Microsoft or Registry::HKEY_LOCAL_MACHINE\Software\Microsoft

		.INPUTS
			System.String

				You can pipe a registry path to Get-RegistryKeyEntries.

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]

		.EXAMPLE
			Get-RegistryEntries -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall

			Gets all of the entries associated with the registry key. It does not get any information about subkeys.

		.NOTES
			AUTHOR: Michael Haken	
			LAST UPDATE: 2/27/2016

		.FUNCTIONALITY
			The intended use of this cmdlet is to supplement the Get-ItemProperty cmdlet to get the values for every entry in a registry key.
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[string]$Path
	)

	Begin {}

	Process
	{
		Get-Item -Path $Path | Select-Object -ExpandProperty Property | ForEach-Object {
			Write-Output -InputObject ([PSCustomObject]@{"Path"=$Path;"Property"="$_";"Value"=(Get-ItemProperty -Path $Path -Name $_ | Select-Object -ExpandProperty $_)})
		}
	}

	End {}
}

Function Enable-TaskSchedulerHistory {
	<#
		.SYNOPSIS
			Enables the Task Scheduler log history.

		.DESCRIPTION
			The Enable-TaskSchedulerHistory cmdlet enables the windows event logs for the Task Scheduler. The command should be used to correct the issue of Scheduled Tasks' history showing as "Disabled" in Task Scheduler.

		.INPUTS
			None

		.OUTPUTS
			None

		.EXAMPLE
			Enable-TaskSchedulerHistory
			This command starts the collection of scheduled task events.

		.NOTES
			AUTHOR: Michael Haken	
			LAST UPDATE: 2/27/2016

		.FUNCTIONALITY
			The intended use of this cmdlet is to turn on history for Scheduled Tasks.
	#>
	[Alias("Start-TaskSchedulerHistory")]
	[CmdletBinding()]
	Param ()

	Begin {}

	Process {
		$LogName = 'Microsoft-Windows-TaskScheduler/Operational'
		$EventLog = New-Object -TypeName System.Diagnostics.Eventing.Reader.EventLogConfiguration($LogName)
		$EventLog.IsEnabled = $true
		$EventLog.SaveChanges()
	}

	End{}
 }

Function Start-KerberosTraceLog {
	<#
		.SYNOPSIS
			Starts a trace to troubleshoot Kerberos authentication issues.

		.DESCRIPTION
			The Start-KerberosTraceLog cmdlet starts a trace of logs and netsh to capture all Kerberos, NTLM, SSL, and Negotiation traffic.

		.PARAMETER Path
			Specify the directory to store the log files during the trace. This defaults to the module root. The directory is created if it does not already exist.

		.INPUTS
			System.String

				You can pipe a directory path string to Start-KerberosTraceLog.

		.OUTPUTS
			None

		.EXAMPLE
			Start-KerberosTraceLog

			This command starts the trace log and logs to $PSScriptRoot\Logs.

		.EXAMPLE
			Start-KerberosTraceLog -Path C:\Logs

			This command starts the trace log and logs to C:\Logs. The directory is created if it doesn't already exist.

		.NOTES
			This command must be run with local administrator credentials.

			The output from the individual logman.exe, nltest.exe, and netsh.exe commands are written to $PSScriptRoot\StartOutput\.
	
			AUTHOR: Michael Haken	
			LAST UPDATE: 11/14/2016

		.FUNCTIONALITY
			The intended use of this cmdlet is to assist in troubleshooting Kerberos authentication issues.
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[Alias("DirectoryPath","LogDirectory")]
		[string]$Path = "$PSScriptRoot\Logs"
	)

	Begin {
		if (!(Test-IsLocalAdmin)) {
			throw "This cmdlet must be run with admin credentials."
		}

		$KerberosbDebugFlags = "0x40243"
		$NtlmDebugFlags = "0x15003"
		$NegoExtsDebugFlags = "0xFFFF"
		$Pku2uDebugFlags = "0xFFFF"
		$SslDebugFlags= "0x0000FDFF"

		$OutputPath = "$PSScriptRoot\StartOutput"

		if (!(Test-Path -Path $OutputPath)) {
			 New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
		}
	}

	Process {
		if (!(Test-Path -Path $Path)) {
			 New-Item -Path $Path -ItemType Directory | Out-Null
		}

		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\logman.exe" -ArgumentList @("start","kerb","-p {6B510852-3583-4e2d-AFFE-A67F9F223438}",$KerberosbDebugFlags,"-o `"$Path\kerb.etl`"","-ets") -NoNewWindow -RedirectStandardOutput "$OutputPath\kerb.txt" -RedirectStandardError "$OutputPath\kerb_error.txt"
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\logman.exe" -ArgumentList @("start","ntlm","-p {5BBB6C18-AA45-49b1-A15F-085F7ED0AA90}",$NtlmDebugFlags,"-o `"$Path\ntlm.etl`"","-ets")-NoNewWindow -RedirectStandardOutput "$OutputPath\ntlm.txt" -RedirectStandardError "$OutputPath\ntlm_error.txt"
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\logman.exe" -ArgumentList @("start","negoexts","-p {5AF52B0D-E633-4ead-828A-4B85B8DAAC2B}",$NegoExtsDebugFlags,"-o `"$Path\negoexts.etl`"","-ets") -NoNewWindow -RedirectStandardOutput "$OutputPath\negoexts.txt" -RedirectStandardError "$OutputPath\negoexts_error.txt"

		$NegoExtender = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters"
		if (!(Test-Path -Path $NegoExtender )) {
			New-Item -Path $NegoExtender -Force | Out-Null

			$Counter = 0
			while (!(Test-Path -Path $NegoExtender)) {
				Start-Sleep -Seconds 1
				$Counter++

				if ($Counter -gt 30) {
					throw "Timeout waiting for registry key $NegoExtender to be created."
				}
			}
		}

		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters" -Name InfoLevel -Value ([System.Convert]::ToInt32($NegoExtsDebugFlags, 16)) -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Force | Out-Null
		
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\logman.exe" -ArgumentList @("start","pku2u","-p {2A6FAF47-5449-4805-89A3-A504F3E221A6}",$Pku2uDebugFlags,"-o `"$Path\pku2u.etl`"","-ets") -NoNewWindow -RedirectStandardOutput "$OutputPath\pku2u.txt" -RedirectStandardError "$OutputPath\pku2u_error.txt"
		
		$Pku2u = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters"

		if (!(Test-Path -Path $Pku2u)) {
			New-Item -Path $Pku2u -Force | Out-Null

			$Counter = 0
			while (!(Test-Path -Path $Pku2u)) {
				Start-Sleep -Seconds 1
				$Counter++

				if ($Counter -gt 30) {
					throw "Timeout waiting for registry key $Pku2u to be created."
				}
			}
		}

		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters" -Name InfoLevel -Value ([System.Convert]::ToInt32($Pku2uDebugFlags, 16)) -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Force | Out-Null

		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\logman.exe" -ArgumentList @("start","ssl","-p {37D2C3CD-C5D4-4587-8531-4696C44244C8}",$SslDebugFlags,"-o `"$Path\ssl.etl`"","-ets") -NoNewWindow -RedirectStandardOutput "$OutputPath\ssl.txt" -RedirectStandardError "$OutputPath\ssl_error.txt"

		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name SPMInfoLevel -Value ([System.Convert]::ToInt32("0x101F", 16)) -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Force | Out-Null
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LogToFile -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Force | Out-Null
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name NegEventMask -Value ([System.Convert]::ToInt32("0xF", 16)) -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Force | Out-Null

		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\nltest.exe" -ArgumentList @("/dbflag:0x2080FFFF") -NoNewWindow -RedirectStandardOutput "$OutputPath\nltest.txt" -RedirectStandardError "$OutputPath\nltest_error.txt"		
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\netsh.exe" -ArgumentList @("trace","stop") -NoNewWindow -RedirectStandardOutput "$OutputPath\netshstop.txt" -RedirectStandardError "$OutputPath\netshstop_error.txt"
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\netsh.exe" -ArgumentList @("trace","start","scenario=NetConnection","capture=yes","persistent=no","traceFile=`"$Path\Tracefile.ETL`"","overwrite=yes") -NoNewWindow -RedirectStandardOutput "$OutputPath\netsh.txt" -RedirectStandardError "$OutputPath\netsh_error.txt"

		Write-Host "Kerberos trace log started. Stdout logged to $OutputPath and logs written to $Path" -ForegroundColor Green
	}

	End {		
	}
}

Function Stop-KerberosTraceLog {
	<#
		.SYNOPSIS
			Stops a trace that was started to troubleshoot Kerberos authentication issues.

		.DESCRIPTION
			The Stop-KerberosTraceLog cmdlet stops the trace of logs and netsh to capture all Kerberos, NTLM, SSL, and Negotiation traffic. The required remaining logs are copied to the specified directory and then compressed into a zip file.

		.PARAMETER Path
			Specify the directory that was used during the Start-KerberosTraceLog to collect logs. This defaults to the module root.

		.INPUTS
			System.String

				You can pipe a directory path string to Stop-KerberosTraceLog.

		.OUTPUTS
			None

		.EXAMPLE
			Stop-KerberosTraceLog

			This command stops the trace log.

		.EXAMPLE
			Stop-KerberosTraceLog -Path C:\Logs

			This command stops the trace log and and copies additional required information to C:\Logs. Then, a zip file is written to C:\Logs containing the logs files.

		.NOTES
			This command must be run with local administrator credentials.

			The output from the individual logman.exe, nltest.exe, and netsh.exe commands are written to $PSScriptRoot\StopOutput\.
	
			AUTHOR: Michael Haken	
			LAST UPDATE: 2/27/2016

		.FUNCTIONALITY
			The intended use of this cmdlet is to assist in troubleshooting Kerberos authentication issues.
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[string]$Path = "$PSScriptRoot\Logs"
	)

	Begin {
		if (!(Test-IsLocalAdmin)) {
			throw "This cmdlet must be run with admin credentials."
		}

		$OutputPath = "$PSScriptRoot\StopOutput"

		if (!(Test-Path -Path $OutputPath)) {
			New-Item -Path $OutputPath -ItemType Directory | Out-Null
		}

		Add-Type -AssemblyName System.IO.Compression.FileSystem
	}

	Process {
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\logman.exe" -ArgumentList @("stop","kerb","-ets") -NoNewWindow -RedirectStandardOutput "$OutputPath\kerb.txt" -RedirectStandardError "$OutputPath\kerb_error.txt"
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\logman.exe" -ArgumentList @("stop","ntlm","-ets") -NoNewWindow -RedirectStandardOutput "$OutputPath\ntlm.txt" -RedirectStandardError "$OutputPath\ntlm_error.txt"
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\logman.exe" -ArgumentList @("stop","negoexts","-ets") -NoNewWindow -RedirectStandardOutput "$OutputPath\negoexts.txt" -RedirectStandardError "$OutputPath\negoexts_error.txt"

		Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters" -Name "InfoLevel" -Force | Out-Null
		 
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\logman.exe" -ArgumentList @("stop","pku2u","-ets") -NoNewWindow -RedirectStandardOutput "$OutputPath\pku2u.txt" -RedirectStandardError "$OutputPath\pku2u_error.txt"

		Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters" -Name "InfoLevel" -Force | Out-Null

		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\logman.exe" -ArgumentList @("stop","ssl","-ets") -NoNewWindow -RedirectStandardOutput "$OutputPath\ssl.txt" -RedirectStandardError "$OutputPath\ssl_error.txt"

		Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SPMInfoLevel" -Force | Out-Null
		Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LogToFile" -Force | Out-Null
		Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NegEventMask" -Force | Out-Null

		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\nltest.exe" -ArgumentList @("/dbflag:0x0") -NoNewWindow -RedirectStandardOutput "$OutputPath\nltest.txt" -RedirectStandardError "$OutputPath\nltest_error.txt"
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\netsh.exe" -ArgumentList @("wfp","capture","stop") -NoNewWindow -RedirectStandardOutput "$OutputPath\netsh_wfp.txt" -RedirectStandardError "$OutputPath\netsh_wfp_error.txt"
		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\netsh.exe" -ArgumentList @("trace","stop") -NoNewWindow -RedirectStandardOutput "$OutputPath\netsh_tracestop.txt" -RedirectStandardError "$OutputPath\netsh_tracestop_error.txt"

		if (Test-Path -Path "$env:SYSTEMROOT\debug\netlogon.log") {
			try {
				Copy-Item -Path "$env:SYSTEMROOT\debug\netlogon.log" -Destination $Path -Force | Out-Null
			}
			catch [Exception] {
				Write-Warning -Message $_.Exception.Message
			}
		}
		
		if (Test-Path -Path "$env:SYSTEMROOT\system32\lsass.log") {
			try {
				Copy-Item -Path "$env:SYSTEMROOT\system32\lsass.log" -Destination $Path -Force | Out-Null
			}
			catch [Exception] {
				Write-Warning -Message $_.Exception.Message
			}
		}

		Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "BuildLabEx" | Select-Object -ExpandProperty BuildLabEx | Out-File -FilePath "$Path\build.txt"

		Add-Type -AssemblyName System.IO.Compression.FileSystem

		$CompressionLevel = [System.IO.Compression.CompressionLevel]::Optimal

		try {
			$FileName = ("$Path\Logs_" + (Get-Date).ToString("yyyy-MM-dd-HH-mm") + ".zip")
			[System.IO.Compression.ZipFile]::CreateFromDirectory($Path,$FileName,$CompressionLevel,$false)
			$Path = $FileName
		}
		catch [Exception] {
			Write-Warning -Message "Possible error creating zip file at $FileName : $($_.Exception.Message) The zip file may still have been created."
		}

		Write-Host "Kerberos trace logs collected at $Path. Please share these for analysis." -ForegroundColor Green
	}

	End {		
	}
}

Function Test-IsLocalAdmin {
	<#
		.SYNOPSIS
			Tests is the current user has local administrator privileges.

		.DESCRIPTION
			The Test-IsLocalAdmin cmdlet tests the user's current Windows Identity for inclusion in the BUILTIN\Administrators role.

		.INPUTS
			None

		.OUTPUTS
			None

		.EXAMPLE
			Test-IsLocalAdmin

			This command returns true if the current is running the session with local admin credentials and false if not.

		.NOTES
			AUTHOR: Michael Haken	
			LAST UPDATE: 2/27/2016

		.FUNCTIONALITY
			The intended use of this cmdlet is to test for administrative credentials before running other commands that require them.
	#>
	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		Write-Output -InputObject ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
	}

	End {}
 }

Function Write-CCMLogFormat {
	<#
		.SYNOPSIS
			Writes a log file formatted to be read by the CMTrace tool.

		.DESCRIPTION
			The Write-CCMLogFormat cmdlet takes a message and writes it to a file in the format that can be read by CMTrace.

		.PARAMETER Message
			The message to be written to the file.

		.PARAMETER FilePath
			The path of the file to write the log information.

		.PARAMETER LogLevel
			The log level of the message. 1 is Informational, 2 is Warning, and 3 is Error. This defaults to Informational.

		.PARAMETER Component
			The component generating the log file.

		.PARAMETER Thread
			The thread ID of the process running the task. This defaults to the current managed thread ID.

		.EXAMPLE
			Write-CCMLogFormat -Message "Test Warning Message" -FilePath "c:\logpath.log" -LogLevel 2 -Component "PowerShell"

			This command writes "Test Warning Message" to c:\logpath.log and sets it as a Warning message in the CMTrace log viewer tool.

		.INPUTS
			System.String, System.String, System.Int32, System.String, System.Int32

		.OUTPUTS
			None
		
		.NOTES
			AUTHOR: Michael Haken	
			LAST UPDATE: 11/14/2016

		.FUNCTIONALITY
			The intended use of this cmdlet is to write CMTrace formatted log files to be used with the viewer tool.
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
		[string]$Message,
		[Parameter(Position=1,Mandatory=$true)]
		[string]$FilePath,
		[Parameter(Position=2)]
		[ValidateSet(1,2,3)]
		[Int32]$LogLevel = 1,
		[Parameter(Position=3)]
		[string]$Component = [System.String]::Empty,
		[Parameter(Position=4)]
		[Int32]$Thread = 0
	)

	Begin {		
	}

	Process {
		if ($Thread -eq 0) {
			$Thread = [System.Threading.Thread]::CurrentThread.ManagedThreadId
		}

		$Date = Get-Date
		$Time = ($Date.ToString("HH:mm:ss.fff") + "+" + ([System.TimeZone]::CurrentTimeZone.GetUtcOffset((Get-Date)).TotalMinutes * -1))
		$Day = $Date.ToString("MM-dd-yyyy")

		$File = $FilePath.Substring($FilePath.LastIndexOf("\") + 1)
		[string]$Log = "<![LOG[" + $Message + "]LOG]!><time=`"$Time`" date=`"$Day`" component=`"$Component`" context=`"`" type=`"$LogLevel`" thread=`"$Thread`" file=`"$File`">`r`n"
		Add-Content -Path $FilePath -Value $Log -Force
	}

	End {		
	}
}

Function Get-IPv6ConfigurationOptions {
	<#
		.SYNOPSIS
			Writes the HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters DisabledComponents key property possible options.

		.DESCRIPTION
			The Get-IPv6ConfigurationOptions cmdlet writes the HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters DisabledComponents key property possible options. This registry key entry determines which components of IPv6 are enabled or disabled.

			The cmdlet writes the possible values to enter in this key entry.

		.EXAMPLE
			Get-IPv6ConfigurationOptions

			This command returns the possible registry key settings as an array of PSCustomObjects.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]
		
		.NOTES
			AUTHOR: Michael Haken	
			LAST UPDATE: 2/28/2016
	#>
	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		Write-Output -InputObject $script:IPv6Configs
	}

	End {}
}

Function Get-ProcessToken {
	<#
		.SYNOPSIS
			Gets the token handle for a specified process.

		.DESCRIPTION
			The Get-ProcessToken cmdlet gets a token handle pointer for a specified process.
			
            The CmdLet must be run with elevated permissions.

		.PARAMETER ProcessName
			The name of the process to get a token handle for.

		.PARAMETER ProcessId
			The Id of the process to get a token handle for.

		.PARAMETER CloseHandle
			Specifies if the handle to the token should be closed. Do not close the handle if you want to duplicate the token in another process.		

		.EXAMPLE
			Get-ProcessToken -ProcessName lsass

			Gets the token handle for the lsass process.

		.INPUTS
			System.String, System.Int32

		.OUTPUTS
            System.IntPtr

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 3/25/2016
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=1)]
		[switch]$CloseHandle
	)

	DynamicParam {
		# Create the dictionary 
        $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		#region Name
        # Create the collection of attributes
        $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object -TypeName System.Management.Automation.PARAMETERAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 0
		$ParameterAttribute.ParameterSetName ="Name"

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

		# Generate and set the ValidateSet 
        $Set = Get-Process | Select-Object -ExpandProperty Name 
        $ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($Set)
		$AttributeCollection.Add($ValidateSetAttribute)

		#Add Alias
		$AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute("Name")
		$AttributeCollection.Add($AliasAttribute)

		# Create and return the dynamic parameter
		$RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("ProcessName", [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add("ProcessName", $RuntimeParameter)
        
		#endregion

		#region Id

		# Create the collection of attributes
        $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object -TypeName System.Management.Automation.PARAMETERAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 0
		$ParameterAttribute.ParameterSetName ="Id"
		
        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

		# Generate and set the ValidateSet 
        $Set = Get-Process | Select-Object -ExpandProperty Id 
        $ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($Set)
		$AttributeCollection.Add($ValidateSetAttribute)

		#Add Alias
		$AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute("Id")
		$AttributeCollection.Add($AliasAttribute)

		# Create and return the dynamic parameter
		$RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("ProcessId", [Int32], $AttributeCollection)
        $RuntimeParameterDictionary.Add("ProcessId", $RuntimeParameter)

		#endregion
		
		return $RuntimeParameterDictionary
	}

	Begin {

		if (!([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
			throw "Run the cmdlet with elevated credentials."
		}
	}

	Process {

        [IntPtr]$DulicateTokenHandle = [IntPtr]::Zero
        [IntPtr]$ProcessTokenHandle = [IntPtr]::Zero
        
		if (!([System.Management.Automation.PSTypeName]"AdjPriv").Type) {
			Add-Type -MemberDefinition $script:TokenSignature -Name AdjPriv -Namespace AdjPriv
		}

        $AdjPriv = [AdjPriv.AdjPriv]

        try {
			switch ($PSCmdlet.ParameterSetName) {
				"Name" {
					$Process = Get-Process -Name $PSBoundParameters["ProcessName"]
					break
				}
				"Id" {
					$Process = Get-Process -Id $PSBoundParameters["ProcessId"]
					break
				}
				default {
					throw "Cannot determine parameter set."
				}
			}

		    $ReturnValue = $AdjPriv::OpenProcessToken($Process.Handle, ([AdjPriv.AdjPriv]::TOKEN_IMPERSONATE -BOR [AdjPriv.AdjPriv]::TOKEN_DUPLICATE), [ref]$ProcessTokenHandle)
		    $ReturnValue = $AdjPriv::DuplicateToken($ProcessTokenHandle, [AdjPriv.AdjPriv+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation, [ref]$DulicateTokenHandle)
		
		    if($ReturnValue -eq $null -or $ReturnValue -eq $false) {
			    throw (New-Object -TypeName System.Exception([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.marshal]::GetLastWin32Error()))
		    }
        }
        finally {
            $AdjPriv::CloseHandle($ProcessTokenHandle) | Out-Null

			if ($CloseHandle) {
				$AdjPriv::CloseHandle($DulicateTokenHandle) | Out-Null
			}
        }

		Write-Output -InputObject $DulicateTokenHandle
	}

	End {		
	}
}

Function Set-ProcessToken {
	<#
		.SYNOPSIS
			Replaces the process token for the current process thread with a token from another process.

		.DESCRIPTION
			The Set-ProcessToken cmdlet takes a token handle from another process and then sets the process thread to use that token. Then it closes the token handle. 

			The passed token handle must not be closed before it is passed.
			
            The CmdLet must be run with elevated permissions.

		.PARAMETER TokenHandle
			The Token Handle pointer that will replace the current process thread token.

		.PARAMETER ElevatePrivileges
			Adds the SeDebugPrivilege to the current process thread, which may be needed to replace the current process thread token.	

		.EXAMPLE
			Get-ProcessToken -ProcessName lsass | Set-ProcessToken 

			Gets the token handle for the lsass process and replaces the current process thread token.

		.INPUTS
			System.IntPtr

		.OUTPUTS
            None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 3/25/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[IntPtr]$TokenHandle,
		[Parameter(Position=1)]
		[switch]$ElevatePrivileges
	)

	Begin {
		if (!([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
			throw "Run the cmdlet with elevated credentials."
		}
	}

	Process {
		if (!([System.Management.Automation.PSTypeName]"AdjPriv").Type) {
			Add-Type -MemberDefinition $script:TokenSignature -Name AdjPriv -Namespace AdjPriv
		}

        $AdjPriv = [AdjPriv.AdjPriv]

		if ($ElevatePrivileges) {

			$TokenPrivilege1Luid = New-Object AdjPriv.AdjPriv+TokPriv1Luid
		    $TokenPrivilege1Luid.Count = 1
		    $TokenPrivilege1Luid.Luid = 0
		    $TokenPrivilege1Luid.Attr = [AdjPriv.AdjPriv]::SE_PRIVILEGE_ENABLED

			[System.IntPtr]$TempToken = [System.IntPtr]::Zero

		    $ReturnValue = $AdjPriv::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$TokenPrivilege1Luid.Luid)
		    $ReturnValue = $AdjPriv::OpenProcessToken($AdjPriv::GetCurrentProcess(), [AdjPriv.AdjPriv]::TOKEN_ALL_ACCESS, [ref]$TempToken)
  
		    $TokenPrivileges = New-Object -TypeName AdjPriv.AdjPriv+TOKEN_PRIVILEGES
        
            $DisableAllPrivileges = $false
            $BufferLength = 12
		    $ReturnValue = $AdjPriv::AdjustTokenPrivileges($TempToken, $DisableAllPrivileges, [ref]$TokenPrivilege1Luid, $BufferLength, [IntPtr]::Zero, [IntPtr]::Zero)

		    if($ReturnValue -eq $null -or $ReturnValue -eq $false) {
			    throw (New-Object -TypeName System.Exception([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marrshal]::GetLastWin32Error()))
		    }
		}

		try {
			$ReturnValue = $AdjPriv::SetThreadToken([IntPtr]::Zero, $TokenHandle)

			if($ReturnValue -eq $null -or $ReturnValue -eq $false) {
			    throw (New-Object -TypeName System.Exception([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))
		    }
		}
		finally {
			$AdjPriv::CloseHandle($TokenHandle) | Out-Null
		}

		Write-Host "Successfully duplicated token to current process thread." -ForegroundColor Green
	}

	End {		
	}
}

Function Reset-ProcessToken {
	<#
		.SYNOPSIS
			Reverts to the process thread token to the current user.

		.DESCRIPTION
			The Reset-ProcessToken cmdlet needs to be called to end any process impersonation called through DdeImpersonateClient, ImpersonateDdeClientWindow, ImpersonateLoggedOnUser, ImpersonateNamedPipeClient, ImpersonateSelf, ImpersonateAnonymousToken or SetThreadToken.
			
			Underlying the cmdlet is a P/Invoke call to RevertToSelf() in AdvApi32.dll.

            The CmdLet must be run with elevated permissions.

		.EXAMPLE
			Reset-ProcessToken

			Reverts the process thread to use the token of the current user.

		.INPUTS
			None

		.OUTPUTS
            None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 3/25/2016
	#>

	[CmdletBinding()]
	Param()

	Begin {
		if (!([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
			throw "Run the cmdlet with elevated credentials."
		}
	}

	Process {
		if (!([System.Management.Automation.PSTypeName]"AdjPriv").Type) {
			Add-Type -MemberDefinition $script:TokenSignature -Name AdjPriv -Namespace AdjPriv
		}

        $AdjPriv = [AdjPriv.AdjPriv]

		#RevertToSelf is equivalent to SetThreadToken([System.IntPtr]::Zero, [System.IntPtr]::Zero)
		$ReturnValue = $AdjPriv::RevertToSelf()

		if($ReturnValue -eq $null -or $ReturnValue -eq $false) {
			throw (New-Object -TypeName System.Exception([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))
		}

		Write-Host "Successfully executed RevertToSelf() and reset the process thread token."
	}

	End {		
	}
}

Function Get-LsaSecret {
	<#
		.SYNOPSIS
			Enumerates the content of the LSA Secrets registry hive.

		.DESCRIPTION
			The cmdlet first duplicates the lsass process token and sets it to the current process thread. Then it copies each secret stored in HKLM:\SECURITY\Policy\Secrets to a temporary location.
			After the content is copied over, Lsa functions from AdvApi32.dll are called to decrypt the content. When the cmdlet finishes, it leaves the registry area unchanged and reverts the process thread token.

            The CmdLet must be run with elevated permissions.

		.EXAMPLE
			Get-LsaSecret

			Retrieves all of the stored secrets in the registry using HKLM:\SECURITY\Policy\Secrets\<Generated GUID> to store the temporary information.

		.INPUTS
			None

		.OUTPUTS
            None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 3/27/2016
	#>

	[CmdletBinding()]
	Param()

	Begin {
		if (!([System.Management.Automation.PSTypeName]"Bamcis.Lsa.LSAUtil").Type) {
			Add-Type -TypeDefinition $script:LsaSignature
		}
	}

	Process {
		Get-ProcessToken -ProcessName lsass | Set-ProcessToken	

		$TempKey = [System.Guid]::NewGuid().ToString()

		#Set up a temporary location to copy the registry keys over so that we can enumerate them, we have to be the owner to get the unencrypted values
		$Destination = "HKLM:\SECURITY\Policy\Secrets\$TempKey"

		if ((Get-Item -Path $Destination -ErrorAction SilentlyContinue) -ne $null) {
			Remove-Item -Path $Destination -Recurse -Force | Out-Null
		}

		New-Item -Path $Destination | Out-Null
		$Secrets = @()

		#Get all sub keys in secrets, these are the accounts
		Get-ChildItem -Path "HKLM:\SECURITY\Policy\Secrets" | Where-Object  {$_.Name -notmatch $TempKey -and $_.Property -ne $null} | ForEach-Object {
			$AccountName = $_.PSChildName
			
			#Get all the sub keys of the accounts, these are keys like CurrVal, OldVal, CupdTime, etc			
			Get-ChildItem -Path $_.PSPath | ForEach-Object {
				$ItemName = $_.PSChildName

				#If the sub key exists at the temp destination, delete it
				if ((Test-Path -Path "$Destination\$ItemName")) {
					Remove-Item -Path "$Destination\$ItemName" -Recurse -Force | Out-Null
				}

				#Copy the value over to the new registry location
				[System.Byte[]]$Property = Get-ItemProperty -Path $_.PSPath | Select-Object -ExpandProperty "(Default)"
				New-Item -Path "$Destination\$ItemName" | Out-Null
				Set-ItemProperty -Path "$Destination\$ItemName" -Name '(Default)' -Value $Property
			}

			$LsaUtil = New-Object -TypeName Bamcis.Lsa.LSAUtil -ArgumentList @($TempKey)

			try {
				$Value = $LsaUtil.GetSecret()
			}
			catch [Exception] {
				$Value = [System.String]::Empty
			}

			if ($AccountName -match "^_SC_") {
				# Get Service Account
				$Service = $AccountName -Replace "^_SC_"
				Try {
					# Get Service Account
					$Service = Get-WmiObject -Query "SELECT StartName FROM Win32_Service WHERE Name = '$Service'" -ErrorAction Stop
					$Account = $Service.StartName
				}
				catch [Exception] {
					$Account = [System.String]::Empty
				}
			} else {
				$Account = [System.String]::Empty
			}

			$Hex = [System.Text.Encoding]::Unicode.GetBytes($Value) | ForEach-Object {
				Write-Output -InputObject $_.ToString("X2")
			}

			$EncryptedBinary = [System.Byte[]](Get-ItemProperty -Path "$Destination\CurrVal" -Name "(Default)" | Select-Object -ExpandProperty "(Default)")

			$Temp = Set-ItemProperty -Path "$Destination\CurrVal" -Name "(Default)" -Value (Get-ItemProperty -Path "$Destination\OldVal" -Name "(Default)" | Select-Object -ExpandProperty "(Default)") -PassThru

			try {
				$OldSecret = $LsaUtil.GetSecret()
			}
			catch [Exception] {
				$OldSecret = [System.String]::Empty
			}

			$Secrets += (New-Object -TypeName PSObject -Property @{Name = $AccountName; Secret = $Value; OldSecret = $OldSecret; SecretHex = ($Hex -join " "); Account = $Account; EncryptedBinary = $EncryptedBinary})  
		}

		Remove-Item -Path "$Destination" -Force -Recurse
		Reset-ProcessToken
		Write-Output -InputObject $Secrets
	}

	End {		
	}
}

Function ConvertFrom-Xml {
	<#
		.SYNOPSIS
			Converts an Xml object to as PSObject.

		.DESCRIPTION
			The ConvertFrom-Xml recursively goes through an Xml object and enumerates the properties of each inputted element. Those properties are accessed and added to the returned object.

			An XmlElement that has attributes and XmlText will end up with the XmlText value represented as a "#name" property in the resulting object.

		.EXAMPLE
			ConvertFrom-Xml -InputObject $XmlObj

			Returns an PSObject constructed from the $XmlObj variable

		.PARAMETER InputObject
			The InputObject is an Xml type in the System.Xml namespace. It could be an XmlDocument, XmlElement, or XmlNode for example. It cannot be a collection of Xml objects.

		.INPUTS
			System.Xml

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 3/31/2015
	#>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
        [ValidateScript({$_.GetType().Namespace -eq "System.Xml"})]
        $InputObject
    )

    Begin {       
    }

    Process {
		$private:Hash = @{}
        
        Get-Member -InputObject $InputObject -MemberType Property | Where-Object {$_.Name -ne "xml" -and (![System.String]::IsNullOrEmpty($_.Name))} | ForEach-Object {
            $PropertyName = $_.Name
            $InputItem = $InputObject.($PropertyName)

            #There are multiple items with the same tag name
            if ($InputItem.GetType() -eq [System.Object[]]) {
                
                #Make the tag name an array
                $private:Hash.($PropertyName) = @()

                #Go through each item in the array
                $InputItem | Where-Object {$_ -ne $null} | ForEach-Object {
                    
                    #Item is an object in the array
                    $Item = $_
                    [System.Type]$Type = $Item.GetType()

                    if ($Type.IsPrimitive -or $Type -eq [System.String]) {                   
                        $private:Hash.($PropertyName) = $Item
                    }
                    else {
						#Create a temp variable to hold the new object that will be added to the array
						$Temp = @{}  
                                
						#Make attributes properties of the object 
						$Item.Attributes | ForEach-Object {
							$Temp.($_.Name) = $_.Value
						}

						#As an XmlElement, the element will have at least 1 childnode, it's value
						$Item.ChildNodes | Where-Object {$_ -ne $null -and ![System.String]::IsNullOrEmpty($_.Name)} | ForEach-Object {
							$ChildNode = $_
   
							if ($ChildNode.HasChildNodes) {
								#If the item has 1 childnode and the childnode is XmlText, then the child is this type of element,
								#<Name>ValueText</Name>, so its child is just the value
								if ($ChildNode.ChildNodes.Count -eq 1 -and $ChildNode.ChildNodes[0].GetType() -eq [System.Xml.XmlText] -and !($ChildNode.HasAttributes)) {
									$Temp.($ChildNode.ToString()) = $ChildNode.ChildNodes[0].Value
								}
								else {
									$Temp.($ChildNode.ToString()) = ConvertFrom-Xml -InputObject $ChildNode
								}
							}
							else {
								$Temp.($ChildNode.ToString()) = $ChildNode.Value
							}
						}
					
						$private:Hash.($PropertyName) += $Temp
					}
                }
            }
            else {
                if ($InputItem -ne $null) {
                    $Item = $InputItem
                    [System.Type]$Type = $InputItem.GetType()
                    
                    if ($Type.IsPrimitive -or $Type -eq [System.String]) {                   
                        $private:Hash.($PropertyName) = $Item
                    }
                    else {

                        $private:Hash.($PropertyName) = @{}  
                                
                        $Item.Attributes | ForEach-Object {
                            $private:Hash.($PropertyName).($_.Name) = $_.Value
                        }

                        $Item.ChildNodes | Where-Object {$_ -ne $null -and ![System.String]::IsNullOrEmpty($_.Name)} | ForEach-Object {
                            $ChildNode = $_
                            
                            if ($ChildNode.HasChildNodes) {
                                if ($ChildNode.ChildNodes.Count -eq 1 -and $ChildNode.ChildNodes[0].GetType() -eq [System.Xml.XmlText] -and !($ChildNode.HasAttributes)) {      
                                    $private:Hash.($PropertyName).($ChildNode.ToString()) = $ChildNode.ChildNodes[0].Value
                                }
                                else {
                                    $private:Hash.($PropertyName).($ChildNode.ToString()) = ConvertFrom-Xml -InputObject $ChildNode
                                }
                            }
                            else {
                                $private:Hash.($PropertyName).($ChildNode.ToString()) = $ChildNode.Value
                            }
                        }
                    }
                }
            }                  
        }

		 Write-Output -InputObject (New-Object -TypeName System.Management.Automation.PSObject -Property $private:Hash)
    }

    End {      
    }
}

Function Get-WebHistory {
	<#
		.SYNOPSIS
			Reads the Internet Explorer web history of a user from the WebCacheV01.dat file.

		.DESCRIPTION
			The Get-WebHistory cmdlet is a forensic tools that reads the actual web history of a given user. It uses the ESE database functions to read the WebCacheV01.dat file. This works in IE10+.

			It is recommended that you use a copy of the database and logs so that the original database is not modified.

		.EXAMPLE
			Get-WebHistory

			Gets the web history of all users on the local computer.

		.PARAMETER UserName
			The user name to get the web history for. This defaults to all users.

		.INPUTS
			System.String

		.OUTPUTS
			System.Management.Automation.PSObject[]

			The array of objects contain Url, AccessedTime, and UserName information

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/25/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)]
		$UserName = [System.String]::Empty
	)

	Begin {
		$Verbose = $PSBoundParameters.ContainsKey("Verbose").IsPresent
	}

	Process {
		$Data = @()

		$Profiles = Get-UserProfiles
		if (![System.String]::IsNullOrEmpty($UserName)) {
			$Profiles = $Profiles | Where-Object {$_ -like "*$UserName*"}
		}

		foreach ($Profile in $Profiles) {			
			$Parts = $Profile.Split("\")
			$CurrentUser = $Parts[$Parts.Length - 1]
			$Path = Join-Path -Path $Profile -ChildPath "AppData\Local\Microsoft\Windows\WebCache"
			$Destination = "$env:USERPROFILE\AppData\Local\Temp"

			Write-Verbose -Message "Processing user $CurrentUser at path $Path"

			if ((Test-Path -Path $Path) -and (Test-Path -Path "$Path\WebCacheV01.dat")) {
				Stop-Process -Name dllhost -Force -ErrorAction SilentlyContinue
				Stop-Process -Name taskhostw -Force -ErrorAction SilentlyContinue
				Write-Verbose -Message "Copying WebCache folder."
				Copy-Item -Path $Path -Destination $Destination -Recurse -Force
				Write-Verbose -Message "Finished copy."
				$DB = $null
				$DB = Get-ESEDatabase -Path "$Destination\WebCache\WebCacheV01.dat" -LogPrefix "V01" -ProcessesToStop @("dllhost","taskhostw") -Recovery $false -CircularLogging $true -Force
				Remove-Item -Path "$Destination\WebCache" -Force -Recurse
				foreach ($Table in $DB) {
					if ($Table.Rows.Count -gt 0 -and (Get-Member -InputObject $Table.Rows[0] -Name "Url" -MemberType Properties) -ne $null) {
						$Data += ($Table.Rows | Select-Object -Property AccessedTime,Url,@{Name="UserName";Expression = {$CurrentUser}})
					}
				}
			}
		}

		Write-Output -InputObject $Data
	}

	End {
	}
}

Function Get-UserProfiles {
	<#
		.SYNOPSIS
			Gets all of the user profiles on the system.

		.DESCRIPTION
			The Get-UserProfiles cmdlet uses the Win32_UserProfile WMI class to get user profile paths. It ignores special profiles like the local system.

		.EXAMPLE
			Get-UserProfiles

			Gets all of the user profiles on the system as an array of path strings.

		.INPUTS
			None

		.OUTPUTS
			System.String[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/25/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {}

	Process {
		Write-Output -InputObject (Get-WmiObject -Class Win32_UserProfile | Where-Object {$_.Special -eq $false} | Select-Object -ExpandProperty LocalPath)
	}

	End {		
	}
}

Function ConvertTo-HtmlTable {
	<#
		.SYNOPSIS
			Converts an object to an HTML table.

		.DESCRIPTION
			The ConvertTo-HtmlTable cmdlet takes an input object and converts it to an HTML document containing a table. The html
			document is either written out to stdout or written to file if a destination is specified.

		.EXAMPLE
			ConvertTo-HtmlTable -CsvPath c:\test.csv -Title "Test Import File" -Destination c:\test.html

			Converts the csv file to an html file and saves the html to the specified destination.

		.PARAMETER CsvPath
			The path to the CSV file that will be converted to HTML. Currently, this is the only supported input format.

		.PARAMETER Title
			An optional title to display on the HTML.

		.PARAMETER Destination
			An optional parameter to save the HTML content to a file. If this parameter is not specified or is Null or Empty, the HTML will be written to the pipeline.

		.PARAMETER IgnoreHeaders
			An array of any headers in the CSV file to ignore when creating the HTML table. Data in these columns will not be added to the table.

		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/15/2017
	#>
	[CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName= "Csv", Position = 0)]
		[ValidateScript({Test-Path -Path $_})]
        [System.String]$CsvPath,

        [Parameter()]
        [System.String]$Title = [System.String]::Empty,

        [Parameter(Position = 1)]
        [System.String]$Destination = [System.String]::Empty,

        [Parameter(ParameterSetName="Csv")]
        [System.String[]]$IgnoreHeaders = @()
    )

    Begin {
    }

    Process {
		switch ($PSCmdlet.ParameterSetName) {
            "Csv" {
                $Data = Import-Csv -Path $CsvPath
				if ($Data.Count -gt 0) {
					$Headers = Get-Member -InputObject $Data[0] -MemberType NoteProperty | Select-Object -ExpandProperty Name | Where-Object {$_.ToString().ToLower() -notin $IgnoreHeaders.ToLower()}
				}
				else {
					$Headers = @()
					Write-Verbose -Message "No content in the CSV."
				}
            }
            default {
                throw "Could not determine parameter set."
            }
        }

        $Html = @"
<!DOCTYPE html>
<html>
	<head>
		<meta name="viewport" content="width=device-width" />
		<title>$Title</title>
	</head>
    <style>
        .logtable {
            width:100%;
            table-layout:fixed;
            border:1px solid black;
        }
        
        .logtable td {
            word-break:break-all;
            word-wrap:break-word;
            vertical-align:top;
			text-align:left;
        }

        .logtable th {
            text-align:center;
        }
    </style>
	<body style=`"width:1200px;margin-left:auto;margin-right:auto;`">
        <H1 style=`"text-align:center;`">$Title</H1>
        <div>
			 <table class=`"logtable`">
				<thead>

"@

		foreach ($Header in $Headers) {
			$Html += "<th>$Header</th>"
		}

		$Html += "</thead><tbody>"

		foreach ($Obj in $Data) {
			$Html += "<tr>"

			$Props = Get-Member -InputObject $Obj -MemberType NoteProperty | Select-Object -ExpandProperty Name | Where-Object {$_.ToString().ToLower() -notin $IgnoreHeaders.ToLower()}

			foreach ($Prop in $Props) {
				$Html += "<td>" + $Obj.$Prop + "</td>"
			}

			$Html += "</tr>"
		}

		$Html += "</tbody></table></div></body></html>"

		if (![System.String]::IsNullOrEmpty($Destination)) {
			Set-Content -Path $Destination -Value $Html -Force
		}
		else {
			Write-Output -InputObject $Html
		}
    }

    End {
    }
}

Function Test-Port {
	<#
		.SYNOPSIS
			Tests if a TCP or UDP is listening on a computer.

		.DESCRIPTION
			The Test-Port cmdlet tests for the availability of a TCP or UDP port on a local or remote server.

		.EXAMPLE
			Test-Port -Port 443 -ComputerName RemoteServer.test.local -TCP

			Tests for the availability of port 443 via TCP on RemoteServer.test.local

		.PARAMETER Port
			The port number to test. This must be between 1 and 65535.

		.PARAMETER ComputerName
			The IP or DNS name of the computer to test. This defaults to "localhost".

		.PARAMETER ReceiveTimeout
			The timeout in milliseconds to wait for a response. This defaults to 1000.

		.PARAMETER Tcp
			Indicates that TCP should be used. This is the default

		.PARAMETER Udp
			Indicates that UDP should be used.

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/10/2017
	#>
    [CmdletBinding(DefaultParameterSetName = "tcp")]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
		[ValidateRange(1, 65535)]
        [System.Int32]$Port,

        [Parameter(Position = 1)]
        [System.String]$ComputerName = "localhost",

        [Parameter(Position = 2)]
        [System.Int32]$ReceiveTimeout = 1000,

        [Parameter(ParameterSetName="tcp")]
        [Switch]$Tcp,

        [Parameter(ParameterSetName="udp")]
        [Switch]$Udp
    )

    Begin {     
    }

    Process {
		$Success = $false

        if ($PSCmdlet.ParameterSetName -eq "tcp") 
		{
            [System.Net.Sockets.TcpClient]$TcpObj = New-Object -TypeName System.Net.Sockets.TcpClient
            Write-Verbose -Message "Beginning tcp connection to $ComputerName."

			try
			{
				$Connection = $TcpObj.BeginConnect($ComputerName, $Port, $null, $null)
				$Wait = $Connection.AsyncWaitHandle.WaitOne($ReceiveTimeout, $false)

				if ($Wait -ne $null) 
				{
					$Error.Clear()
					Write-Verbose -Message "Ending connection."

					try
					{
						$TcpObj.EndConnect($Connection) | Out-Null

						if ($Error[0] -ne $null) 
						{
							Write-Verbose -Message ($Error[0].Exception.Message)
						}
						else 
						{
							Write-Verbose -Message "Connection successful."
							$Success = $true
						}
					}
					catch [Exception]
					{
						Write-Verbose -Message $_.Exception.Message
					}
				}
				else 
				{
					Write-Verbose -Message "Connection timeout."
				}
			}
			finally
			{
				Write-Verbose -Message "Closing TCP connection."
				$TcpObj.Close()
			}
        }		
		else 
		{
            [System.Net.Sockets.UdpClient]$UdpObj = New-Object -TypeName System.Net.Sockets.UdpClient
            $UdpObj.Client.ReceiveTimeout = $ReceiveTimeout
            Write-Verbose -Message "Connected to $ComputerName."

            $UdpObj.Connect($ComputerName, $Port)
            $TestData = New-Object System.Text.ASCIIEncoding
            $Bytes = $TestData.GetBytes("$(Get-Date)")
            Write-Verbose -Message "Sending data."

            [void]$UdpObj.Send($Bytes, $Bytes.Length)
            Write-Verbose -Message "Creating remote endpoint."
            $RemoteEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

            try 
			{
                Write-Verbose -Message "Waiting for message return"
                $ReceivedBytes = $UdpObj.Receive([ref]$RemoteEndpoint)
                [string]$ReturnData = $TestData.GetString($ReceivedBytes)

                if (![System.String]::IsNullOrEmpty($ReturnData)) 
				{
                    Write-Verbose -Message "Connection successful"
                    $Success = $true
                }
            }
            catch [Exception] 
			{
                if ($_.Exception.Message -match "\brespond after a period of time\b") 
				{
                    Write-Verbose -Message "Testing ICMP connection for false positive."
                    if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) 
					{
                        Write-Verbose -Message "Connection successful."
                        $Success = $true
                    }        
                }
                else 
				{
                    Write-Verbose -Message $_.Exception.Message
                }
            }
            finally 
			{
                $UdpObj.Close()
            } 
        }
		
		Write-Output -InputObject $Success                
    }

    End {
    }
}

Function Set-AutoLogon {
	<#
		.SYNOPSIS
			Enables or disables automatic logon for a user.

		.DESCRIPTION
			The cmdlet enables automatic logon for a specified user.

		.EXAMPLE
			Set-AutoLogon -Enable -Username "contoso\john.smith" -Password "MySecureP@$$W0rd"

			Creates an automatic logon for john.smith. The next time the server boots, this user will be automatically logged on.

		.EXAMPLE
			Set-AutoLogon -Disable

		.PARAMETER Enable
			Specifies that auto logon should be enabled. This is the default.

		.PARAMETER Username
			The user that should be automatically logged in.

		.PARAMETER Password
			The password for the user. The password is stored in plain text in the registry.

		.PARAMETER Disable
			Disables auto logon and clears any stored password.

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 11/14/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true, ParameterSetName="Enable")]
		[switch]$Enable,
		[Parameter(Mandatory=$true, ParameterSetName="Enable")]
		[System.String]$UserName,
		[Parameter(Mandatory=$true, ParameterSetName="Enable")]
		[System.String]$Password,
		[Parameter(Mandatory=$true, ParameterSetName="Disable")]
		[switch]$Disable	
	)

	Begin {}

	Process {
		if ($Enable) {
			Write-Log "Enabling automatic logon." -Level VERBOSE
			New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1 -ErrorAction SilentlyContinue | Out-Null
			New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value $UserName -ErrorAction SilentlyContinue | Out-Null
			New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $Password -ErrorAction SilentlyContinue | Out-Null
		}
		elseif ($Disable) {
			Write-Log "Disabling automatic logon." -Level VERBOSE
			Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0 -ErrorAction SilentlyContinue | Out-Null
			Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "" -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue | Out-Null
		}
	}

	End {}
}

Function Set-FileSecurity {
	<#
		.SYNOPSIS
			Sets permissions on a file or directory.

		.DESCRIPTION
			Will add or replace the supplied rules to the specified file or directory. The default behavior is that the rules are just added to the current ACL of the object.

		.PARAMETER Path
			The path to the file to set permissions on.

		.PARAMETER Rules
			An array of File Access Rules to apply to the path.

		.PARAMETER ReplaceAllRules
			Indictates if all permissions on the path should be replaced with these.

		.PARAMETER ReplaceNonInherited
			Replaces all existing rules that are not inherited from a parent directory.

		.PARAMETER ReplaceRulesForUser
			Indicates if the supplied rules should replace existing rules for matching users. For example, if the Rules parameter has a Full Control rule for System and a Read rules for 
			Administrators, existing rules for System and Administrators would be removed and replaced with the new rules.

		.PARAMETER AddIfNotPresent
			Add the rules if they do not already exist on the path. The rules are matched based on all properties including FileSystemRights, PropagationFlags, InheritanceFlags, etc.

		.PARAMETER ForceChildInheritance
			Indicates if all permissions of child items should have their permissions replaced with the parent if the target is a directory.

		.PARAMETER EnableChildInheritance
			Indicates that child items should have inheritance enabled, but will still preserve existing permissions. This parameter is ignored if ForceChildInheritance is specified.

		.PARAMETER ResetInheritance
			Indicates that all explicitly set permissions will be removed from the path and inheritance from its parent will be forced.

        .EXAMPLE
			PS C:\>Set-Permissions -Path "c:\test.txt" -Rules $Rules

			Creates the rule set on the test.txt file.

		.EXAMPLE
			PS C:\>Set-Permissions -Path "c:\test" -ResetInheritance

			Resets inherited permissions on the c:\test directory.

		.EXAMPLE
			PS C:\>Set-Permissions -Path "c:\test" -Rules $Rules -ReplaceAllRules -ForceChildInheritance

			Replaces all existing rules on the c:\test directory with the newly supplied rules and forces child objects to inherit those permissions. This removes existing explicit permissions on child objects.

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2017
	#>

	[CmdletBinding(DefaultParameterSetName = "Add")]
	[Alias("Set-FilePermissions")]
    Param 
    (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$Path,

		[Parameter(ParameterSetName="ReplaceAll")]
		[Parameter(ParameterSetName="Replace")]
		[Parameter(ParameterSetName="Add")]
		[Parameter(ParameterSetName="AddIfNotPresent")]
		[Parameter(ParameterSetName="ReplaceNonInherited")]
		[Parameter(ParameterSetName="AddIfNotPresentAndReplace")]
		[Alias("Rules")]
		[ValidateNotNull()]
        [System.Security.AccessControl.FileSystemAccessRule[]]$AccessRules,

		[Parameter(ParameterSetName = "ReplaceAll")]
		[Parameter(ParameterSetName = "Replace")]
		[Parameter(ParameterSetName = "Add")]
		[Parameter(ParameterSetName = "AddIfNotPresent")]
		[Parameter(ParameterSetName = "ReplaceNonInherited")]
		[Parameter(ParameterSetName = "AddIfNotPresentAndReplace")]
		[ValidateNotNull()]
		[System.Security.AccessControl.FileSystemAuditRule[]]$AuditRules,

		[Parameter(ParameterSetName="ReplaceAll")]
		[switch]$ReplaceAllRules,

		[Parameter(ParameterSetName="ReplaceNonInherited")]
		[switch]$ReplaceNonInheritedRules,

		[Parameter(ParameterSetName="Replace")]
		[switch]$ReplaceRulesForUser,

		[Parameter(ParameterSetName="AddIfNotPresent")]
		[switch]$AddIfNotPresent,

		[Parameter(ParameterSetName="AddIfNotPresentAndReplace")]
		[switch]$AddIfNotPresentAndReplace,

		[Parameter()]
		[switch]$ForceChildInheritance,

		[Parameter()]
		[switch]$EnableChildInheritance,

		[Parameter(ParameterSetName="Reset")]
		[switch]$ResetInheritance
    )

    Begin 
	{       	
		Function Convert-FileSystemRights {
			Param(
				[Parameter(Mandatory = $true, Position = 0)]
				[System.Security.AccessControl.FileSystemRights]$Rights
			)

			Begin {
			}

			Process {
				[System.Security.AccessControl.FileSystemRights]$ExistingFileSystemRights = $Rights
				[System.Int32]$Temp = $Rights

				switch ($Temp)
				{
					#268435456
					0x10000000 {
						$ExistingFileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
						break
					}
					#-1610612736
					0xA0000000 {
						$ExistingFileSystemRights = @([System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.FileSystemRights]::Synchronize)
						break
					}
					#-536805376
					0xE0010000 {
						$ExistingFileSystemRights = @([System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.FileSystemRights]::Synchronize)
						break
					}
					default {
						$ExistingFileSystemRights = $Rights
						break
					}
				}

				Write-Output -InputObject $ExistingFileSystemRights
			}

			End {
			}
		}

		Function Get-AuthorizationRuleComparison {
			Param(
				[Parameter(Mandatory = $true, Position = 0)]
				[System.Security.AccessControl.AuthorizationRule]$Rule1,

				[Parameter(Mandatory = $true, Position = 1)]
				[System.Security.AccessControl.AuthorizationRule]$Rule2
			)

			Begin {
			}

			Process {
				$Equal = $false

				try
				{
					[System.Security.AccessControl.FileSystemRights]$ExistingFileSystemRights1  = Convert-FileSystemRights -Rights $Rule1.FileSystemRights
					[System.Security.AccessControl.FileSystemRights]$ExistingFileSystemRights2  = Convert-FileSystemRights -Rights $Rule2.FileSystemRights

					if ($ExistingFileSystemRights1 -eq $ExistingFileSystemRights2 -and `
						$Rule1.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $Rule2.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -and `
						$Rule1.AccessControlType -eq $Rule2.AccessControlType -and `
						$Rule1.InheritanceFlags -eq $Rule2.InheritanceFlags -and `
						$Rule1.PropagationFlags -eq $Rule2.PropagationFlags)
					{
						$Equal = $true
					}
				}
				catch [Exception]
				{
					Write-Verbose -Message "[ERROR] Error evaluating access rule $($_.Exception.Message) : `nExisting $($Rule1 | FL | Out-String) `nNew $($Rule2 | FL | Out-String)"
				}

				Write-Output -InputObject $Equal
			}

			End {
			}
		}
	}

    Process
    {
		if ($PSCmdlet.ParameterSetName -eq "Add" -and $AccessRules.Length -eq 0 -and $AuditRules.Length -eq 0)
		{
			throw "Either a set of access rules or audit rules must be provided to add to the path."
		}

		Write-Verbose -Message "Setting access and audit rules on $Path"
		Push-Location -Path $env:SystemDrive

		[System.Boolean]$IsProtectedFromInheritance = $false

		#This is ignored if IsProtectedFromInheritance is false
		[System.Boolean]$PreserveInheritedRules = $false

		try
        {
			#$Acl = Get-Acl -Path $Path
			$Item = Get-Item -Path $Path
			[System.Security.AccessControl.FileSystemSecurity]$Acl = $Item.GetAccessControl(@([System.Security.AccessControl.AccessControlSections]::Access, [System.Security.AccessControl.AccessControlSections]::Audit))

            if ($Acl -ne $null)
            {
				switch ($PSCmdlet.ParameterSetName) {
					"ReplaceAll" {

						if ($AccessRules.Length -gt 0)
						{
							Write-Verbose -Message "Disabling access rule inheritance on $Path"
							$Acl.SetAccessRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)

							[System.Security.AccessControl.AuthorizationRuleCollection]$OldAcls = $Acl.Access

							foreach ($Rule in $OldAcls)
							{
								try 
								{
									$Acl.RemoveAccessRule($Rule) | Out-Null
								}
								catch [Exception] 
								{
									Write-Verbose -Message "[ERROR] Error removing access rule $($_.Exception.Message) : $($Rule | FL | Out-String)"
								}
							}
						}

						if ($AuditRules.Length -gt 0)
						{
							Write-Verbose -Message "Disabling audit rule inheritance on $Path"
							$Acl.SetAuditRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)

							Write-Verbose -Message "Getting audit rules"
							[System.Security.AccessControl.AuthorizationRuleCollection]$OldAuditRules = $Acl.GetAuditRules($script:EXPLICIT_TRUE,  $script:INHERITED_FALSE, [System.Security.Principal.NTAccount])

							foreach ($Rule in $OldAuditRules)
							{
								try
								{
									$Acl.RemoveAuditRule($Rule) | Out-Null
								}
								catch [Exception]
								{
									Write-Verbose -Message "[ERROR] Error removing audit rule $($_.Exception.Message) : $($Rule | FL | Out-String)"
								}
							}
						}

						break
					}
					"ReplaceNonInherited" {

						if ($AccessRules.Length -gt 0)
						{
							[System.Security.AccessControl.AuthorizationRuleCollection]$OldAcls = $Acl.Access

							foreach ($Rule in ($OldAcls | Where-Object {$_.IsInherited -eq $false}))
							{
								try 
								{
									$Acl.RemoveAccessRule($Rule) | Out-Null
								}
								catch [Exception] 
								{
									Write-Verbose -Message "[ERROR] Error removing access rule $($_.Exception.Message) : $($Rule | FL | Out-String)"
								}
							}
						}

						if ($AuditRules.Length -gt 0)
						{
							Write-Verbose -Message "Disabling audit rule inheritance on $Path"

							Write-Verbose -Message "Getting non inherited audit rules"
							[System.Security.AccessControl.AuthorizationRuleCollection]$OldAuditRules = $Acl.GetAuditRules($script:EXPLICIT_TRUE,  $script:INHERITED_FALSE, [System.Security.Principal.NTAccount])

							foreach ($Rule in $OldAuditRules)
							{
								try
								{
									$Acl.RemoveAuditRule($Rule) | Out-Null
								}
								catch [Exception]
								{
									Write-Verbose -Message "[ERROR] Error removing audit rule $($_.Exception.Message) : $($Rule | FL | Out-String)"
								}
							}
						}

						break
					}
					"Replace" {
						
						[System.Security.Principal.SecurityIdentifier[]]$Identities = $AccessRules | Select-Object -Property @{Name = "ID"; Expression = { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) } } | Select-Object -ExpandProperty ID
						foreach ($Sid in $Identities)
						{
							$Acl.PurgeAccessRules($Sid)
							$Acl.PurgeAuditRules($Sid)
						}
						
						break
					}
					"Add" {
						#Do Nothing
						break
					}
					"Reset" {
						[System.Security.AccessControl.AuthorizationRuleCollection]$OldAcls = $Acl.Access

						foreach ($Rule in $OldAcls)
						{
							$Acl.RemoveAccessRule($Rule) | Out-Null
						}
				
						$Acl.SetAccessRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)			

						[System.Security.AccessControl.AuthorizationRuleCollection]$OldAuditRules = $Acl.GetAuditRules($script:EXPLICIT_TRUE,  $script:INHERITED_FALSE, [System.Security.Principal.NTAccount])

						foreach ($Rule in $OldAuditRules)
						{
							$Acl.RemoveAuditRule($Rule) | Out-Null
						}

						$Acl.SetAuditRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)
						
						#Call set ACL since no additional rules are provided
						$Item.SetAccessControl($Acl)
					}
					"AddIfNotPresent" {
						if ($AccessRules.Length -gt 0)
						{
							foreach ($Rule in $AccessRules)
							{
								[System.Boolean]$Found = $false

								foreach ($ExistingRule in $Acl.Access)
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule
									if ($Found -eq $true)
									{
										Write-Verbose -Message "Found matching access rule, no need to add this one"
										break
									}
								}

								if ($Found -eq $false)
								{
									try
									{
										$Acl.AddAccessRule($Rule)
									}
									catch [Exception]
									{
										Write-Verbose -Message "[ERROR] Error adding access rule $($_.Exception.Message) : $($Rule | FL | Out-String)"
									}
								}
							}

							#Call set access control since we've already added the rules
							$Item.SetAccessControl($Acl)
						}	

						if ($AuditRules.Length -gt 0)
						{
							foreach ($Rule in $AuditRules)
							{
								[System.Boolean]$Found = $false

								foreach ($ExistingRule in $Acl.GetAuditRules($script:EXPLICIT_TRUE, $script:INHERITED_FALSE, [System.Security.Principal.NTAccount]))
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule

									if ($Found -eq $true)
									{
										break
									}
								}

								if ($Found -eq $false)
								{
									try
									{
										$Acl.AddAuditRule($Rule)
									}
									catch [Exception]
									{
										Write-Verbose -Message "[ERROR] Error adding audit rule $($_.Exception.Message) : $($Rule | FL | Out-String)"
									}
								}
							}
							#Call set access control since we've already added the rules
							$Item.SetAccessControl($Acl)
						}
						break
					}
					"AddIfNotPresentAndReplace" {
						if ($AccessRules.Length -gt 0)
						{
							foreach ($ExistingRule in ($Acl.Access | Where-Object {$_.IsInherited -eq $false }))
							{
								[System.Boolean]$Found = $false

								foreach ($Rule in $AccessRules)
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule

									#The existing rule did match a new rule
									if ($Found -eq $true)
									{
										break
									}
								}

								#The existing rule did not match a new rule, remove it
								if ($Found -eq $false)
								{
									try
									{
										Write-Verbose -Message "Removing rule $($Rule | FL | Out-String)"
										$Acl.RemoveAccessRule($ExistingRule)
									}
									catch [Exception]
									{
										Write-Verbose -Message "[ERROR] Error removing access rule $($_.Exception.Message) : $($Rule | FL | Out-String)"
									}
								}
							}


							foreach ($Rule in $AccessRules)
							{
								[System.Boolean]$Found = $false

								foreach ($ExistingRule in $Acl.Access)
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule

									if ($Found -eq $true)
									{
										break
									}
								}

								#Did not find a matching, existing rule
								if ($Found -eq $false)
								{
									try
									{
										Write-Verbose -Message "Adding rule $($Rule | FL | Out-String)"
										$Acl.AddAccessRule($Rule)
									}
									catch [Exception]
									{
										Write-Verbose -Message "[ERROR] Error adding access rule $($_.Exception.Message) : $($Rule | FL | Out-String)"
									}
								}
							}

							#Call set access control since we've already added the rules
							$Item.SetAccessControl($Acl)
						}	

						if ($AuditRules.Length -gt 0)
						{
							foreach ($ExistingRule in $Acl.GetAuditRules($script:EXPLICIT_TRUE, $script:INHERITED_FALSE, [System.Security.Principal.NTAccount]))
							{
								[System.Boolean]$Found = $false

								foreach ($Rule in $AccessRules)
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule

									#The existing rule did match a new rule
									if ($Found -eq $true)
									{
										break
									}
								}

								#The existing rule did not match a new rule, remove it
								if ($Found -eq $false)
								{
									try
									{
										Write-Verbose -Message "Removing rule $($Rule | FL | Out-String)"
										$Acl.RemoveAuditRule($ExistingRule)
									}
									catch [Exception]
									{
										Write-Verbose -Message "[ERROR] Error removing audit rule $($_.Exception.Message) : $($Rule | FL | Out-String)"
									}
								}
							}

							foreach ($Rule in $AuditRules)
							{
								[System.Boolean]$Found = $false

								foreach ($ExistingRule in ($Acl.GetAuditRules($script:EXPLICIT_TRUE, $true, [System.Security.Principal.NTAccount]) | Where-Object {$_.IsInherited -eq $false }))
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule

									if ($Found -eq $true)
									{
										break
									}
								}

								#Did not find a matching, existing rule
								if ($Found -eq $false)
								{
									try
									{
										Write-Verbose -Message "Adding audit rule $($Rule | FL | Out-String)"
										$Acl.AddAuditRule($Rule)
									}
									catch [Exception]
									{
										Write-Verbose -Message "[ERROR] Error adding audit rule $($_.Exception.Message) : $($Rule | FL | Out-String)"
									}
								}
							}

							#Call set access control since we've already added the rules
							$Item.SetAccessControl($Acl)
						}

						break
					}
					default {
						throw "Could not determine parameter set name"
					}
				}
				
				if ($PSCmdlet.ParameterSetName -like "Replace*" -or $PSCmdlet.ParameterSetName -eq "Add")
				{
					#Add new access rules
					if($AccessRules.Length -gt 0)
					{
						foreach ($Rule in $AccessRules) 
						{
							$Acl.AddAccessRule($Rule)
						}

						$Item.SetAccessControl($Acl)
					}

					#Add new audit rules
					if ($AuditRules.Length -gt 0)
					{
						foreach ($Rule in $AuditRules)
						{
							$Acl.AddAuditRule($Rule)
						}

						$Item.SetAccessControl($Acl)
					}	
				}

				#If child permissions should be forced to inherit
				if (($ForceChildInheritance -or $EnableChildInheritance) -and [System.IO.Directory]::Exists($Path))
				{
					Write-Verbose -Message "Evaluating child items"
					Get-ChildItem -Path $Path -Recurse -Force | ForEach-Object {

						$ChildItem = Get-Item -Path $_.FullName
						[System.Security.AccessControl.FileSystemSecurity]$ChildAcl = $ChildItem.GetAccessControl(@([System.Security.AccessControl.AccessControlSections]::Access, [System.Security.AccessControl.AccessControlSections]::Audit))

						if ($AccessRules.Length -gt 0 -or $PSCmdlet.ParameterSetName -eq "Reset")
						{
							if ($ForceChildInheritance)
							{
								Write-Verbose -Message "Forcing access rule inheritance on $($ChildItem.FullName)"

								foreach ($ChildRule in ($ChildAcl.Access | Where-Object {$_.IsInherited -eq $false }))
								{
									try
									{
										$ChildAcl.RemoveAccessRule($ChildRule) | Out-Null
									}
									catch [Exception]
									{
										Write-Warning -Message "Error removing ACL from $($ChildItem.FullName)`: $($_.Exception.Message) $($ChildRule | FL | Out-String)"
									}
								}
							}

							try
							{
								$ChildAcl.SetAccessRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)
								$ChildItem.SetAccessControl($ChildAcl)
							}
							catch [Exception]
							{
								Write-Verbose -Message "[ERROR] Could not set ACL on path $ChildPath : $($_.Exception.Message)."
							}
						}

						if ($AuditRules.Length -gt 0 -or $PSCmdlet.ParameterSetName -eq "Reset")
						{
							Write-Verbose -Message "Forcing audit rule inheritance on $($ChildItem.FullName)"

							[System.Security.AccessControl.AuthorizationRuleCollection]$OldChildAuditRules = $ChildAcl.GetAuditRules($script:EXPLICIT_TRUE, $script:INHERITED_FALSE, [System.Security.Principal.NTAccount])

							if ($ForceChildInheritance)
							{
								foreach ($ChildAudit in $OldChildAuditRules)
								{
									try
									{
										$ChildAcl.RemoveAuditRule($ChildAudit) | Out-Null
									}
									catch [Exception]
									{
										Write-Warning -Message "Error removing audit from $($ChildItem.FullName)`: $($_.Exception.Message) $($ChildAudit | FL | Out-String)"
									}
								}
							}

							try
							{
								$ChildAcl.SetAccessRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)
								$ChildItem.SetAccessControl($ChildAcl)
							}
							catch [Exception]
							{
								Write-Verbose -Message "[ERROR] Could not set ACL on path $ChildPath : $($_.Exception.Message)."
							}
						}
					}
				}                   
            }
            else
            {
                Write-Warning -Message "Could not retrieve the ACL for $Path"
            }
        }
        catch [System.Exception]
        {
            Write-Warning -Message $_.Exception.Message
        }

		Pop-Location
    }
    
    End {}
}

Function Set-Owner {
    <#
        .SYNOPSIS
            Changes owner of a file or folder to another user or group.

        .DESCRIPTION
            Changes owner of a file or folder to another user or group.

        .PARAMETER Path
            The folder or file that will have the owner changed.

        .PARAMETER Account
            Optional parameter to change owner of a file or folder to specified account.

            Default value is 'Builtin\Administrators'

        .PARAMETER Recurse
            Recursively set ownership on subfolders and files beneath given folder.

		.EXAMPLE
            PS C:\>Set-Owner -Path C:\temp\test.txt

            Changes the owner of test.txt to Builtin\Administrators

        .EXAMPLE
            PS C:\>Set-Owner -Path C:\temp\test.txt -Account 'Domain\bprox

            Changes the owner of test.txt to Domain\bprox

        .EXAMPLE
            PS C:\>Set-Owner -Path C:\temp -Recurse 

            Changes the owner of all files and folders under C:\Temp to Builtin\Administrators

        .EXAMPLE
            PS C:\>Get-ChildItem C:\Temp | Set-Owner -Recurse -Account 'Domain\Administrator'

            Changes the owner of all files and folders under C:\Temp to Domain\Administrator

        .NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/28/2016
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param (
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [Alias("FullName")]
		[System.String]$Path,

        [Parameter(Position=1)]
        [System.String]$Account = 'BUILTIN\Administrators',

        [Parameter()]
        [switch]$Recurse
    )

    Begin {
        #Prevent Confirmation on each Write-Debug command when using -Debug
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        try {
            [void][TokenAdjuster]
        } catch {
            $AdjustTokenPrivileges = @"
            using System;
            using System.Runtime.InteropServices;

             public class TokenAdjuster
             {
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
              ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
              [DllImport("kernel32.dll", ExactSpelling = true)]
              internal static extern IntPtr GetCurrentProcess();
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
              phtok);
              [DllImport("advapi32.dll", SetLastError = true)]
              internal static extern bool LookupPrivilegeValue(string host, string name,
              ref long pluid);
              [StructLayout(LayoutKind.Sequential, Pack = 1)]
              internal struct TokPriv1Luid
              {
               public int Count;
               public long Luid;
               public int Attr;
              }
              internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
              internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
              internal const int TOKEN_QUERY = 0x00000008;
              internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
              public static bool AddPrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
              public static bool RemovePrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_DISABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
             }
"@
            Add-Type $AdjustTokenPrivileges
        }

        #Activate necessary admin privileges to make changes without NTFS perms
        [void][TokenAdjuster]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
        [void][TokenAdjuster]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
        [void][TokenAdjuster]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions
    }

    Process {
		Write-Verbose -Message "FullName: $Path"
		$Account = Get-AccountTranslatedNTName -UserName $Account
		Write-Verbose -Message "Account Name: $Account"
       
		#The ACL objects do not like being used more than once, so re-create them on the Process block
        $DirOwner = New-Object System.Security.AccessControl.DirectorySecurity
        $DirOwner.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount($Account)))
        
		$FileOwner = New-Object System.Security.AccessControl.FileSecurity
        $FileOwner.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount($Account)))
        
		$DirAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
        $FileAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
        
		[System.Security.Principal.SecurityIdentifier]$Administrators = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

		$AdminACL = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($Administrators.Translate([System.Security.Principal.NTAccount]),
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::InheritOnly,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        
		$FileAdminAcl.AddAccessRule($AdminACL)
        $DirAdminAcl.AddAccessRule($AdminACL)
        
		try {
			$Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop

            if (-not $Item.PSIsContainer) {
                    
				if ($PSCmdlet.ShouldProcess($Item, 'Set File Owner')) {
					try 
					{
						$Item.SetAccessControl($FileOwner)
						Write-Verbose -Message "Set ownership to $Account on $($Item.FullName)"
					} 
					catch [Exception] 
					{
						Write-Warning -Message "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Directory.FullName)"
						$Item.Directory.SetAccessControl($FileAdminAcl)
						$Item.SetAccessControl($FileOwner)
					}
				}
			} 
			else 
			{
				if ($PSCmdlet.ShouldProcess($Item, 'Set Directory Owner')) {                        
					try 
					{
						$Item.SetAccessControl($DirOwner)
						Write-Verbose -Message "Set ownership to $Account on $($Item.FullName)"
					} 
					catch [Exception] 
					{
						Write-Warning -Message "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Parent.FullName)"
						$Item.Parent.SetAccessControl($DirAdminAcl) 
						$Item.SetAccessControl($DirOwner)
					}
				}

				if ($Recurse) 
				{
					[void]$PSBoundParameters.Remove('Path')
					Get-ChildItem $Item -Force -Recurse | ForEach-Object {
						Set-Owner -Path $_.FullName -Account $Account
					}
				}
			}
		} 
		catch [Exception] 
		{
			Write-Warning -Message "$($Item): $($_.Exception.Message)"
        }
    }

    End {  
        #Remove priviledges that had been granted
        [void][TokenAdjuster]::RemovePrivilege("SeRestorePrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeBackupPrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeTakeOwnershipPrivilege")     
    }
}

Function Test-RegistryKeyProperty {
	<#
		.SYNOPSIS
			Tests the existence of a registry value 

		.DESCRIPTION
			The Test-RegistryKeyProperty cmdlet test the extistence of a registry value (property of a key).

		.PARAMETER Key
			The registry key to test for containing the property.

		.PARAMETER PropertyName
			The property name to test for.

        .EXAMPLE
			Test-RegistryKeyProperty -Key "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing" -PropertyName PendingFileRenameOperations 
	        
			Returns true or false depending on the existence of the property

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/28/2016
	#>

	Param (
		[Parameter(Position=0, Mandatory=$true)]
		[string]$Key,
		[Parameter(Position=1, Mandatory=$true)]
		[string]$PropertyName
	)

	Begin {
	}

	Process {
		Get-ItemProperty -Path $Key -Name $PropertyName -ErrorAction SilentlyContinue | Out-Null
		Write-Output -InputObject $?
	}

	End {
	}
}

Function ForEach-ObjectParallel {
	<#
		.SYNOPSIS
			Runs a script in a multi-threaded foreach.

		.DESCRIPTION
			The ForEach-ObjectParallel cmdlet runs through each input value and executes the script in a new thread.

		.PARAMETER ScriptBlock
			The script to execute on each input object.

		.PARAMETER InputObject
			The array of items to provide as input to the foreach.

		.PARAMETER Parameters
			A hashtable of additional parameters to provide to the script. For example @{Name = "MyService", Priority = 1} could be used by a scriptblock that looked like

			{
				Param(
					$Name,
					$Priority
				)

				Write-Host $Name
				Write-Host $Priority
			}

		.PARAMETER InputParamName
			If the input object needs to be associated with a parameter in the script, define its parameter name with this parameter. For example, consider the following Windows services:

			@("Winmgmt", "WinRM") | ForEach-ObjectParallel {
				Param(
					$Type
					$Name
				)
				Get-Service $Name
			} -InputParamName "Name"

			This will ensure that Winmgmt and WinRM are provided to the $Name parameter and not $Type

		.PARAMETER MinimumThreads
			The minimum number of threads to use, this defaults to 1.

		.PARAMETER MaximumThreads
			The maximum number of threads to use, this defaults to 4. This must be greater than or equal to the minimum threads.

		.PARAMETER WaitTime
			The amount of time, in milliseconds, the function waits in between checking the status of each task. For long running tasks
			you can increase this time to utilize less resources during execution.

        .EXAMPLE
			@("Winmgmt", "WinRM") | ForEach-ObjectParallel {
				Param(
					$Name
				)
				Get-Service $Name
			}

			This will return the service objects for the Winmgmt and WinRM services.

		.EXAMPLE
			$Results = ForEach-ObjectParallel -InputObject ("Hello", "Goodbye") -ScriptBlock {
				Param(
					$Greeting,
					$FirstName,
					$LastName
				)

				Write-Output -InputObject ($Greeting $FirstName $LastName)

			} -Parameters @{FirstName = "John", LastName = "Smith"}

			The example would execute two tasks, one outputing "Hello John Smith" and the other outputing "Goodbye John Smith", but not 
			necessarily in that order. The InputObject items are mapped against the parameter in the first position of the script, $Greeting, 
			while the additional parameters are mapped by matching their name.

		.INPUTS
			System.Object[]

		.OUTPUTS
			System.Object[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/26/2016
	#>
	[CmdletBinding()]
	Param(	       
		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "ScriptBlock")]
		[System.Management.Automation.ScriptBlock]$ScriptBlock,

		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Cmdlet")]
		[ValidateScript({
			Get-Command -Name $_
		})]
		[System.String]$Cmdlet,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
		[System.Object[]]$InputObject,

		[Parameter()]
		[System.Collections.Hashtable]$Parameters,

        [Parameter()]
        $InputParamName = [System.String]::Empty,

		[Parameter()]
		[System.UInt32]$MinimumThreads = 1,

		[Parameter()]
		[ValidateScript({
            $_ -ge $MinimumThreads
		})]
		[System.UInt32]$MaximumThreads = 4,

        [Parameter()]
        [System.UInt32]$WaitTime = 100
	)

	Begin {
	}

	Process {
		$Jobs = New-Object -TypeName System.Collections.ArrayList
		$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
		$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($MinimumThreads, $MaximumThreads, $SessionState, $Host)
		$RunspacePool.Open()

		foreach ($Item in $InputObject) {
			$Pipeline = [System.Management.Automation.PowerShell]::Create()


			if ($PSCmdlet.ParameterSetName -eq "ScriptBlock")
			{
				$Pipeline.AddScript($ScriptBlock) | Out-Null
			}
			elseif ($PSCmdlet.ParameterSetName -eq "Cmdlet")
			{
				$Pipeline.AddCommand($Cmdlet) | Out-Null
			}
			else
			{
				throw New-Object -TypeName System.ArgumentException("The parameter set name could not be determined from the given parameters.")
			}

			if ($Parameters.Length -gt 0)
			{
				$Pipeline.AddParameters($Parameters) | Out-Null
			}

            if (![System.String]::IsNullOrEmpty($InputParamName))
            {
                $Pipeline.AddParameter($InputParamName, $Item) | Out-Null
            }
            else
            {
                $Pipeline.AddArgument($Item) | Out-Null
            }

			$Pipeline.RunspacePool = $RunspacePool
			$AsyncHandle = $Pipeline.BeginInvoke()

			$Jobs.Add(@{Handle = $AsyncHandle; Pipeline = $Pipeline}) | Out-Null
		}

		$Results = @()
        $TotalJobs = $Jobs.Count

		while ($Jobs.Count -gt 0)
		{
			Write-Progress -Activity "Waiting for async tasks" `
						-PercentComplete ((($TotalJobs - $Jobs.Count) / $TotalJobs) * 100) `
						-Status ( ($TotalJobs - $Jobs.Count).ToString() + " of $TotalJobs completed, $($Jobs.Count) remaining")

			foreach($Job in ($Jobs | Where-Object {$_.Handle.IsCompleted -eq $true}))
			{
				$Results += $Job.Pipeline.EndInvoke($Job.Handle)
				$Job.Pipeline.Dispose() | Out-Null
                $Jobs.Remove($Job)
			}

			Start-Sleep -Milliseconds $WaitTime
		}

		Write-Progress -Activity "Waiting for async tasks" -Completed

		$RunspacePool.Close() | Out-Null
		$RunspacePool.Dispose() | Out-Null

		Write-Output -InputObject $Results
	}

	End {
	}
}

Function Invoke-CommandInNewRunspace {
	<#
		.SYNOPSIS
			Runs a scriptblock in a new powershell runspace.

		.DESCRIPTION
			The Invoke-CommandInNewRunspace cmdlet uses a clean PowerShell runspace to execute the provided script block.

		.PARAMETER ScriptBlock
			The script to execute on each input object.

		.PARAMETER Parameters
			A hashtable of additional parameters to provide to the script. For example @{Name = "MyService", Priority = 1} could be used by a scriptblock that looked like

			{
				Param(
					$Name,
					$Priority
				)

				Write-Host $Name
				Write-Host $Priority
			}

        .EXAMPLE
			Invoke-CommandInNewRunspace -ScriptBlock {Get-Service}
	        
			Invokes the Get-Service cmdlet in a new runspace.

		.EXAMPLE
			Invoke-CommandInNewRunspace -ScriptBlock {
				Param(
					$Name
				)	
			
				Get-Process $Name
			} -Parameters @{Name = "winlogon"}

			Performs a Get-Process for the winlogon process in a new runspace

		.INPUTS
			None

		.OUTPUTS
			System.Object

			This depends on what is returned from the ScriptBlock

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/26/2016
	#>
	[CmdletBinding()]
	Param(
		
		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "ScriptBlock")]
		[System.Management.Automation.ScriptBlock]$ScriptBlock,

		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Cmdlet")]
		[ValidateScript({
			Get-Command -Name $_
		})]
		[System.String]$Cmdlet,

		[Parameter(Position = 1)]
		[System.Collections.Hashtable]$Parameters
	)

	Begin {
	}

	Process {
		$Results = $null
		$Runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()

		#Create a new PowerShell instance
		$Pipeline = [System.Management.Automation.PowerShell]::Create()

		try {
			#Assign the PowerShell instance to the new RunspacePool we created
			$Pipeline.Runspace = $Runspace

			#Open the runspace
			$Runspace.Open()

			#If the cmdlet was run using a script block, add it
			if ($PSCmdlet.ParameterSetName -eq "ScriptBlock")
			{
				$Pipeline.AddScript($ScriptBlock) | Out-Null
			}
			elseif ($PSCmdlet.ParameterSetName -eq "Cmdlet")
			{
				$Pipeline.AddCommand($Cmdlet) | Out-Null
			}
			else
			{
				throw New-Object -TypeName System.ArgumentException("The parameter set name could not be determined from the given parameters.")
			}

			#Add parameters if they are defined
			if ($Parameters.Length -gt 0)
			{
				$Pipeline.AddParameters($Parameters) | Out-Null
			}

			#Invoke the command synchronously
			$Results = $Pipeline.Invoke()
		}
		finally {
			#Dispose the powershell instance
			$Pipeline.Dispose() | Out-Null
		
			#Terminate the runspace
			$Runspace.Close() | Out-Null
			$Runspace.Dispose() | Out-Null
		}

		Write-Output -InputObject $Results
	}

	End {
		
	}
}

Function Get-WindowsActivationInformation {
	<#
		.SYNOPSIS
			Gets information about the Windows Activation.

		.DESCRIPTION
			The cmdlet gets the Product Key, Product Id, the OEM Product Key stored in the BIOS, and OS version.

		.EXAMPLE
			Get-WindowsActivationInformation

			Gets the activation information from the local computer.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 11/14/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {
		$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
		$Namespace = "root\cimv2"
		$SWService = "SoftwareLicensingService"
		$OEMProdKey = "OA3xOriginalProductKey"
		$RegKey = "DigitalProductId"
		$ByteArrayStart = 52
		$ArrayLength = 15
		$ProductKey = ""

		#These are the valid chars for a product key
		$CharArray = @("B", "C", "D", "F", "G", "H", "J", "K", "M", 
			"P", "Q", "R", "T", "V", "W", "X", "Y", "2", "3", "4", "6", "7", "8", "9")
	}

	Process {
		$OS = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Version
		$Major = [System.Int32]::Parse($OS.Split(".")[0])

		#Product Id is also part of they DigitalProductId byte array from position 8 to 30, it can be converted back using
		#[System.Text.Encoding]::ASCII.GetString($Bytes) by converting the bytes to ASCII or Unicode
		$ProductId = Get-ItemProperty -Path $RegPath -Name "ProductId" | Select-Object -ExpandProperty "ProductId"

		#If the OS is Server 2008 or later, the registry key is DigitalProductId4
		if ($Major -gt 5) {
			$RegKey += "4"
		}
	
		$Bytes = Get-ItemProperty -Path $RegPath -Name $RegKey | Select-Object -ExpandProperty $RegKey

		for ($i = 24; $i -ge 0; $i--) 
		{
			$k = 0
        
			for ($j = $ByteArrayStart + $ArrayLength - 1; $j -ge $ByteArrayStart; $j--) 
			{
				$k = $k * 256 -bxor $Bytes[$j]
				$Bytes[$j] = [math]::truncate($k / 24)
				$k = $k % 24
			}
	
			$ProductKey = $CharArray[$k] + $ProductKey

			if (($i % 5 -eq 0) -and ($i -ne 0)) 
			{
				$ProductKey = "-" + $ProductKey
			}
		}

		$BiosOEMKey = Get-CimInstance -Namespace $Namespace -ClassName $SWService | Select-Object -ExpandProperty $OEMProdKey

		Write-Output -InputObject (New-Object -TypeName System.Management.Automation.PSObject -Property @{
			"BIOSOEMKey" = $BiosOEMKey
			"ProductKey" = $ProductKey
			"ProductId" = $ProductId
			"OSVersion" = $OS
			"ComputerName" = $env:COMPUTERNAME
		})
	}

	End {		
	}
}

Function Set-CertificatePrivateKeyAccess {
	<#
		.SYNOPSIS
			Provides access to certificates for a specific user.

		.DESCRIPTION
			The cmdlet grants access to certificates stored in $env:ProgramData\Microsoft\Crypto\RSA\MachineKeys. The cmdlet can grant
			Read, Read/Write, and Full control to either a specific certificate or the entire directory. The credentials used to run the cmdlet
			must have the ability to set permissions on the files or directory.

		.EXAMPLE
			Set-CertificatePrivateKeyAccess -User "contoso\john.smith" -All

			Grants john.smith full control access to all certificates.

		.EXAMPLE
			Set-CertificatePrivateKeyAccess -User "contoso\john.smith" -Thumbprint 00E811CCE0444D23A9A055F0FB6CEA576F880B89 -AccessLevel READ_WRITE

			Grants john.smith read/write access to the certificate specified by the thumbprint.

		.EXAMPLE
			Set-CertificatePrivateKeyAccess -User "contoso\john.smith" -Subject CN=f366ac78-22c8-427e-9a4e-f5ffab31725e -AccessLevel READ

			Grants john.smith read access to the certificate specified by the subject.

		.PARAMETER User
			The username that should have access.

		.PARAMETER All
			Specifies that the user should be granted access to all of the machine keys stored on the computer.

		.PARAMETER Replace
			Specifies that existing permissions for the user on the machine keys should be replaced with only the specified permissions.

		.PARAMETER AccessLevel
			The level of access the user should receive. This is either FULL_CONTROL, READ_WRITE, or READ.

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 11/14/2016
	#>
	[CmdletBinding(DefaultParameterSetName="Thumbprint")]
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$User,
        [Parameter(ParameterSetName="All",Mandatory=$true)]
        [switch]$All,
        [Parameter(ParameterSetName="All")]
        [switch]$Replace,
		[Parameter()]
		[ValidateSet("FULL_CONTROL", "READ", "READ_WRITE")]
		[System.String]$AccessLevel = "FULL_CONTROL"
    )

    DynamicParam {
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

        [System.Management.Automation.ParameterAttribute]$Attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
        $Attributes.ParameterSetName = "Thumbprint"
		$Attributes.ValueFromPipeline = $true
        $Attributes.Mandatory = $true

        $Prints = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.HasPrivateKey -eq $true } | Select-Object -ExpandProperty Thumbprint

        [System.Management.Automation.ValidateSetAttribute]$ValidateSet = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($Prints)
        
        $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
        $AttributeCollection.Add($Attributes)
        $AttributeCollection.Add($ValidateSet)

        [System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("Thumbprint", [System.String], $AttributeCollection)
        $ParamDictionary.Add("Thumbprint", $DynParam)

        [System.Management.Automation.ParameterAttribute]$Attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
        $Attributes.ParameterSetName = "Subject"
		$Attributes.ValueFromPipeline = $true
        $Attributes.Mandatory = $true

        $Subjects = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.HasPrivateKey -eq $true } | Select-Object -ExpandProperty Subject

        [System.Management.Automation.ValidateSetAttribute]$ValidateSet = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($Subjects)
        
          
        $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
        $AttributeCollection.Add($Attributes)
        $AttributeCollection.Add($ValidateSet)

        [System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("Subject", [System.String], $AttributeCollection)
        $ParamDictionary.Add("Subject", $DynParam)

        Write-Output -InputObject $ParamDictionary
    }

    Begin {
    }

    Process {

        $Account = New-Object -TypeName System.Security.Principal.NTAccount($User)

		switch ($AccessLevel) {
			"FULL_CONTROL" {
				[System.Security.AccessControl.FileSystemRights]$Level = [System.Security.AccessControl.FileSystemRights]::FullControl
			}
			"READ_WRITE" {
				[System.Security.AccessControl.FileSystemRights]$Level = ([System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Write )
			}
			"READ" {
				[System.Security.AccessControl.FileSystemRights]$Level = [System.Security.AccessControl.FileSystemRights]::Read
			}
			default {
				throw "Invalid access level specified."
			}
		}

        switch ($PSCmdlet.ParameterSetName) {
            "Thumbprint" {
                [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert = Get-Item -Path "Cert:\LocalMachine\My\$($PSBoundParameters["Thumbprint"])"

				if ($Cert.HasPrivateKey()) {
					$Path = "$($env:ProgramData)\Microsoft\Crypto\RSA\MachineKeys\$($Cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)"
					[System.Security.AccessControl.InheritanceFlags[]]$Inheritance = @([System.Security.AccessControl.InheritanceFlags]::None)
				}
				else {
					throw "A certificate without a private key was selected."
				}
                break
            }
            "Subject" {
                [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Subject -eq $PSBoundParameters["Subject"]} | Select-Object -First 1
				if ($Cert.HasPrivateKey()) {
					$Path = "$($env:ProgramData)\Microsoft\Crypto\RSA\MachineKeys\$($Cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)"
					[System.Security.AccessControl.InheritanceFlags[]]$Inheritance = @([System.Security.AccessControl.InheritanceFlags]::None)
				}
				else {
					throw "A certificate without a private key was selected."
				}
                break
            }
            "All" {
                $Path = "$($env:ProgramData)\Microsoft\Crypto\RSA\MachineKeys"
                [System.Security.AccessControl.InheritanceFlags[]]$Inheritance = @([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
                break
            }
            default {
                throw "Could not determine parameter set name"
            }
        }

        #Provide access to Subfolders and files
        [System.Security.AccessControl.FileSystemAccessRule]$AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule(
            $Account.Translate([System.Security.Principal.SecurityIdentifier]),
            $Level,
            $Inheritance,
            [System.Security.AccessControl.PropagationFlags]::InheritOnly,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

		Set-FileSecurity -AccessRules @($AccessRule) -Path $Path -ReplaceRulesForUser:$Replace -ForceChildInheritance:$All
    }
    
    End {
    }
}

Function New-GptVolume {
	<#
		.SYNOPSIS
			Creates a formatted GPT partition and volume on the specified disk.

		.DESCRIPTION
			The cmdlet cleans, initializes to GPT, partitions using all available disk space, and creates an NTFS volume on the partition.

			It is essentially a shortcut/convenience cmdlet for the common task that used to be performed with DIKSPART.

		.EXAMPLE
			Get-Disk -Number 1 | New-GptVolume

			Creates a GPT NTFS formatted volume on Disk 1 and auto assigns it a drive letter.

		.EXAMPLE
			New-GptVolume -DiskNumber 2 -DriveLetter G -Confirm

			Creates a new GPT NTFS formatted volume on Disk 2 and assigns it a drive letter of G.

		.PARAMETER DiskNumber
			The disk number of the disk to partition and format.

		.PARAMETER InputObject
			The MSFT_Disk CIM object to partition and format.

		.PARAMETER DriveLetter
			The letter to assign to the new volume. If this is not specified, a letter is auto assigned.

		.PARAMETER Confirm
			Prompts you for confirmation before running the cmdlet.

		.INPUTS
			[Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/Storage/MSFT_Disk]

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/4/2017
	#>
	[CmdletBinding(DefaultParameterSetName = "Number", ConfirmImpact = "High", SupportsShouldProcess = $true)]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Number", ValueFromPipeline = $true)]
		[System.Int32]$DiskNumber,

		[Parameter(Mandatory = $true, ParameterSetName = "Input", ValueFromPipeline = $true)]
		[Microsoft.Management.Infrastructure.CimInstance]
        [PSTypeName("Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/Storage/MSFT_Disk")]
		$InputObject,

		[Parameter()]
		[ValidatePattern("[d-zD-Z]")]
		[System.Char]$DriveLetter,
        
        [Parameter()]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
	)

	Begin {
	}

	Process {
        if ($CimSession -eq $null)
        {
            $CimSession = New-CimSession
        }

		if ($PSCmdlet.ParameterSetName -eq "Number")
		{
			[Microsoft.Management.Infrastructure.CimInstance]$Disk = Get-Disk -Number $DiskNumber -CimSession $CimSession
		}
		else 
		{
			[Microsoft.Management.Infrastructure.CimInstance]$Disk = $InputObject
		}

        if ($PSCmdlet.ShouldProcess($Disk.UniqueId, "Clean, initialize, and format"))
		{
		    Set-Disk -Number $Disk.Number -IsOffline $false -CimSession $CimSession
		    Set-Disk -Number $Disk.Number -IsReadOnly $false -CimSession $CimSession

		    if ($Disk.PartitionStyle -ne "RAW")
		    {
			    Clear-Disk -InputObject $Disk -RemoveData -CimSession $CimSession -Confirm:$false
		    }
		
		    Initialize-Disk -InputObject $Disk -PartitionStyle GPT -CimSession $CimSession -Confirm:$false
            Stop-Service -Name ShellHWDetection -Force -Confirm:$false

		    if ($PSBoundParameters.ContainsKey("DriveLetter") -and $DriveLetter -ne $null -and $DriveLetter -ne '')
		    {
			    New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter $DriveLetter -CimSession $CimSession | Format-Volume -FileSystem NTFS -CimSession $CimSession
		    }
		    else
		    {
			    New-Partition -DiskNumber $Disk.Number -UseMaximumSize -AssignDriveLetter -CimSession $CimSession | Format-Volume -FileSystem NTFS -CimSession $CimSession
		    }

            Start-Service -Name ShellHWDetection -Confirm:$false
        }
	}

	End {

	}
}

Function Where-NotMatchIn {
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        $Input,

        [Parameter(Position=1)]
        [string[]]$Matches,

        [Parameter()]
        [string]$Property = [System.String]::Empty
    )

    Begin {
    }

    Process {
		

        foreach($Item in $Input) {
            $Match = $false

            if ($Property -eq [System.String]::Empty) {
                $Value = $Item
            }
            else {
                $Value = $Item.$Property
            }

            foreach ($Matcher in $Matches) {
				
                if ($Value -like $Matcher) {
                    $Match = $true
                    break
                }
            }

            if (!$Match) {
                Write-Output -InputObject $Item
            }
        }
    }

    End {       
    }
}

Function Get-AccountSid {
	<#
		.SYNOPSIS
			Gets the SID of a given username.

		.DESCRIPTION
			The cmdlet gets the SID of a username, which could a service account, local account, or domain account. The cmdlet returns null if the username could not be translated.

		.PARAMETER UserName
			The name of the user or service account to get the SID of.

		.PARAMETER ComputerName
			If the account is local to another machine, such as an NT SERVICE account or a true local account, specify the computer name the account is on.

		.PARAMETER Credential
			The credentials used to connect to the remote machine.
			
		.INPUTS
			None

		.OUTPUTS
			System.Security.Principal.SecurityIdentifier

        .EXAMPLE
			Get-AccountSid -UserName "Administrator"

			Gets the SID for the Administrator account.

		.EXAMPLE
			Get-AccountSid -UserName "NT AUTHORITY\Authenticated Users"

			Gets the SID for the Authenticated Users group.

		.EXAMPLE
			Get-AccountSid -UserName "NT AUTHORITY\System"

			Gets the SID for the SYSTEM account. The user name could also just be "System".

		.EXAMPLE
			Get-AccountSid -UserName "NT SERVICE\MSSQLSERVER" -ComputerName SqlServer

			Gets the SID for the virtual MSSQLSERVER service principal.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/23/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$UserName,

		[Parameter(Position=1)]
		[ValidateNotNull()]
		[System.String]$ComputerName = [System.String]::Empty,

		[Parameter()] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

	Begin {	
	}

	Process{
		Write-Verbose "Getting SID for $UserName."

		[System.String]$Domain = [System.String]::Empty
		[System.String]$Name = [System.String]::Empty

		if ($UserName.IndexOf("\") -ne -1) 
		{
			[System.String[]]$Parts = $UserName.Split("\")
			$Domain = $Parts[0]

			#If the UserName is something like .\john.doe, change the computer name
			if ($Domain -iin $script:LocalNames)
			{
				#Use an empty string for the domain name on the local computer
				$Domain = [System.String]::Empty
			}

			$Name = $Parts[1]			
		}
		elseif ($UserName.IndexOf("@") -ne -1) 
		{
			[System.String[]]$Parts = $UserName.Split("@")
			$Domain = $Parts[1]
			$Name = $Parts[0]
		}
		else 
		{
			try 
			{
				$Domain = Get-ADDomain -Current LocalComputer -ErrorAction Stop | Select-Object -ExpandProperty Name
			}
			catch [Exception] 
			{
				#Use an empty string for the domain name on the local computer
				$Domain = [System.String]::Empty
			}

			$Name = $UserName
		}

		if ([System.String]::IsNullOrEmpty($ComputerName) -or $ComputerName -iin $script:LocalNames) 
		{
			try 
			{
				$User = New-Object -TypeName System.Security.Principal.NTAccount($Domain, $Name)
				$UserSid = $User.Translate([System.Security.Principal.SecurityIdentifier])
			}
			catch [Exception]
			{
				Write-Verbose -Message "Exception translating $Domain\$Name`: $($_.Exception.Message)"
				$UserSid = $null
			}
		}
		else 
		{
			$Session = New-PSSession -ComputerName $ComputerName -Credential $Credential
				
			$UserSid = Invoke-Command -Session $Session -ScriptBlock { 
				try
				{
					$User = New-Object -TypeName System.Security.Principal.NTAccount($args[0], $args[1])
					Write-Output -InputObject $User.Translate([System.Security.Principal.SecurityIdentifier])
				}
				catch [Exception]
				{
					Write-Verbose -Message "Exception translating $($args[0])\$($args[1]): $($_.Exception.Message)"
					Write-Output -InputObject $null

				}
			} -ArgumentList @($Domain, $Name)

			Remove-PSSession -Session $Session
		}
		
		Write-Output -InputObject $UserSid
	}

	End {		
	}
}

Function Get-AccountTranslatedNTName {
	<#
		.SYNOPSIS
			Gets the full NT Account name of a given username.

		.DESCRIPTION
			The cmdlet gets the SID of a username, which could a service account, local account, or domain account and then translates that to an NTAccount. The cmdlet returns null if the username
			could not be translated.

		.PARAMETER UserName
			The name of the user or service account to get the SID of.

		.PARAMETER ComputerName
			If the account is local to another machine, such as an NT SERVICE account or a true local account, specify the computer name the account is on.

		.PARAMETER Credential
			The credentials used to connect to the remote machine.
			
		.INPUTS
			None

		.OUTPUTS
			System.Security.Principal.SecurityIdentifier

        .EXAMPLE
			Get-AccountTranslatedNTName -UserName "Administrator"

			Gets the NT account name for the Administrator account, which is BUILTIN\Administrator.

		.EXAMPLE
			Get-AccountTranslatedNTName -UserName "Authenticated Users"

			Gets the NT account name for the Authenticated Users group, which is NT AUTHORITY\Authenticated Users.

		.EXAMPLE
			Get-AccountTranslatedNTName -UserName "System"

			Gets the NT account name for the SYSTEM account, which is NT AUTHORITY\System

		.EXAMPLE
			Get-AccountSid -UserName "MSSQLSERVER" -ComputerName SqlServer

			Gets the NT account name for the virtual MSSQLSERVER service principal, which is NT SERVICE\MSSQLSERVER.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/23/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$UserName,

		[Parameter(Position=1)]
		[ValidateNotNull()]
		[System.String]$ComputerName = [System.String]::Empty,

		[Parameter()] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

	Begin {	
	}

	Process{
		Write-Verbose "Getting NT Account for $UserName."

		[System.Security.Principal.SecurityIdentifier]$UserSid = Get-AccountSid -UserName $UserName.Trim() -ComputerName $ComputerName -Credential $Credential

		[System.String]$NTName = [System.String]::Empty

		if ($UserSid -ne $null)
		{
			if ([System.String]::IsNullOrEmpty($ComputerName) -or $ComputerName -iin $script:LocalNames) 
			{
				try
				{
					[System.Security.Principal.NTAccount]$NTAccount = $UserSid.Translate([System.Security.Principal.NTAccount])
					$NTName = $NTAccount.Value.Trim()
				}
				catch [Exception]
				{
					Write-Verbose -Message "Exception translating SID $($UserSid.Value) for $UserName to NTAccount: $($_.Exception.Message)"
					$NTName = $null
				}
			}
			else 
			{
				$Session = New-PSSession -ComputerName $ComputerName -Credential $Credential
				
				$NTName = Invoke-Command -Session $Session -ScriptBlock { 
					try
					{
						[System.Security.Principal.NTAccount]$NTAccount = ([System.Security.Principal.SecurityIdentifier]$args[0]).Translate([System.Security.Principal.NTAccount])
						Write-Output -InputObject $NTAccount.Value.Trim()
					}
					catch [Exception]
					{
						Write-Verbose -Message "Exception translating SID $($args[0].Value) to NTAccount: $($_.Exception.Message)"
						Write-Output -InputObject $null
					}
				} -ArgumentList @($UserSid)

				Remove-PSSession -Session $Session
			}
		}
		else
		{
			$NTName = $null
		}

		Write-Output -InputObject $NTName
	}

	End {		
	}
}

Function Convert-SecureStringToString {
	<#
		.SYNOPSIS
			The cmdlet converts a secure string to standard string.

		.DESCRIPTION
			The cmdlet converts a secure string to standard string.

		.PARAMETER SecureString
			The secure string to convert to a standard string

		.INPUTS
			System.Security.SecureString
		
		.OUTPUTS
			System.String

		.EXAMPLE 
			Convert-SecureStringToString -SecureString (ConvertTo-SecureString -String "test" -AsPlainText -Force)

			Converts the secure string created from the text "test" back to plain text.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 6/21/2017
	#>
	[CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )

    Begin {}

    Process { 
        [System.String]$PlainText = [System.String]::Empty
        [System.IntPtr]$IntPtr = [System.IntPtr]::Zero

        try 
        {     
            $IntPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)     
            $PlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($IntPtr)   
        }   
        finally 
        {     
            if ($IntPtr -ne $null -and $IntPtr -ne [System.IntPtr]::Zero) 
			{       
                [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($IntPtr)     
            }   
        }

		Write-Output -InputObject $PlainText
    }

    End {      
    }
}

Function Get-LocalGroupMembers {
	<#
		.SYNOPSIS
			Gets the members of a local group

		.DESCRIPTION
			This cmdlet gets the members of a local group on the local or a remote system. The values are returned as DirectoryEntry values in the format WinNT://Domain/Name.

		.PARAMETER LocalGroup
			The local group on the computer to enumerate.

		.PARAMETER ComputerName
			The name of the computer to query. This defaults to the local computer.

		.INPUTS
			None

		.OUTPUTS
			System.String[]

        .EXAMPLE
			Get-LocalGroupMembers -LocalGroup Administrators 

			Gets the membership of the local administrators group on the local machine.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/25/2016
	#>  
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true, Position=0)]
		[System.String]$LocalGroup,		

		[Parameter(Position=1)]
		[System.String]$ComputerName = $env:COMPUTERNAME
	)

	Begin {
	}

	Process {
		if ([System.String]::IsNullOrEmpty($ComputerName))
		{
			$ComputerName = $env:COMPUTERNAME
		}

		$Group = [ADSI]"WinNT://$ComputerName/$LocalGroup,group"	
									
		$Members = $Group.Invoke("Members", $null) | Select-Object @{Name = "Name"; Expression = {$_[0].GetType().InvokeMember("ADSPath", "GetProperty", $null, $_, $null)}} | Select-Object -ExpandProperty Name				

		Write-Output -InputObject $Members
	}

	End {		
	}
}

Function Add-DomainMemberToLocalGroup {
	<#
		.SYNOPSIS
			Adds a domain user or group to a local group.

		.DESCRIPTION
			This cmdlet adds a domain user or group to a local group on a specified computer. The cmdlet returns true if the member is added or is already a member of the group.

			The cmdlet uses the current computer domain to identify the domain member.

		.PARAMETER LocalGroup
			The local group on the computer that will have a member added.

		.PARAMETER Member
			The domain user or group to add.

		.PARAMETER MemberType
			The type of the domain member, User or Group. This defaults to User.

		.PARAMETER ComputerName
			The name of the computer on which to add the local group member. This defaults to the local computer.

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

        .EXAMPLE
			Add-DomainMemberToLocalGroup -LocalGroup Administrators -Member "Exchange Trusted Subsystem" -MemberType Group

			Adds the domain group to the local administrators group on the local machine.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/25/2016
	#>  
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[System.String]$LocalGroup,

		[Parameter(Mandatory=$true,Position=1)]
		[System.String]$Member,

		[Parameter(Position=2)]
		[ValidateSet("Group", "User")]
		[System.String]$MemberType = "User",

		[Parameter(Position=3)]
		[System.String]$ComputerName = $env:COMPUTERNAME
	)

	Begin {
	}

	Process {
		$Success = $false

		if ([System.String]::IsNullOrEmpty($ComputerName))
		{
			$ComputerName = $env:COMPUTERNAME
		}

		$Domain = Get-CimInstance -ClassName Win32_ComputerSystem -Property Domain | Select-Object -ExpandProperty Domain
		$Domain = $Domain.Substring(0, $Domain.IndexOf("."))

		$Group = [ADSI]"WinNT://$ComputerName/$LocalGroup,group"	
		
		if ($Group.Path -ne $null)	
		{					
			$Members = $Group.Invoke("Members", $null) | Select-Object @{Name = "Name"; Expression = {$_[0].GetType().InvokeMember("ADSPath", "GetProperty", $null, $_, $null)}} | Select-Object -ExpandProperty Name		
			$NewMember = [ADSI]"WinNT://$Domain/$Member,$MemberType"
							
			$Path = $NewMember.Path.Remove($NewMember.Path.LastIndexOf(","))
			
			if ($Members -inotcontains $Path)
			{
				try {
					$Group.Add($NewMember.Path)
					Write-Verbose -Message "Successfully added $Member to $($Group.Name)"
					$Success = $true
				}
				catch [Exception] {
					Write-Error -Message $_.Exception.Message
				}
			}
			else
			{
				Write-Verbose -Message "$($NewMember.Name) already a member of $($Group.Name)."
				$Success = $true
			}
		}
		else
		{
			Write-Verbose -Message "$LocalGroup local group could not be found."
		}

		Write-Output -InputObject $Success
	}

	End {
		
	}
}

Function Get-PSExecutionPolicy {
	<#
		.SYNOPSIS
			Gets the current PowerShell script execution policy for the computer.

		.DESCRIPTION
			Retrieves the execution policy from HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell.

		.INPUTS
			None

		.OUTPUTS
			System.String

        .EXAMPLE
			Get-PSExecutionPolicy

			This might return "Unrestricted" or "Bypass".

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {}

	Process 
	{       
		$PSPolicy= Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name ExecutionPolicy -ErrorAction SilentlyContinue

        if (![System.String]::IsNullOrEmpty($PSPolicy)) 
		{
            Write-Log -Message "PowerShell Execution Policy is set to $($PSPolicy.ExecutionPolicy) through GPO" -Level WARNING
        }
        else 
		{
            Write-Log -Message "PowerShell Execution Policy not configured through GPO" -Level VERBOSE
        }

		Write-Output -InputObject $PSPolicy
	}

	End {		
	}
}

Function Test-PendingReboots {
	<#
		.SYNOPSIS
			Determines if there are any pending reboot operations.

		.DESCRIPTION
			This cmdlet checks pending reboots from Windows Update, File Rename Operations, Computer Renaming, SCCM, and Component Based Servicing.

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

        .EXAMPLE
			Test-PendingReboots

			Returns true if there are pending reboots or false otherwise.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {		
	}

	Process {
		$CbsReboot = $false
		$SccmReboot = $false

		$OSBuild = Get-CimInstance -Class Win32_OperatingSystem -Property BuildNumber -ErrorAction SilentlyContinue | Select-Object -ExpandProperty BuildNumber
		
		$WindowsUpdateReboot = Test-Path -Path "HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

		#if OS is Vista/2008 or greater
		if ([System.Int32]$OSBuild -ge 6001)
		{
			$CbsReboot = (Get-ChildItem -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing" | Select-Object -ExpandProperty Name | Where-Object {$_ -contains "RebootPending"}) -ne $null
		}

		$FileRename = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue

		$FileNameReboot = ($FileName -ne $null)

		$ComputerRenameReboot = (Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName" -Name ComputerName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ComputerName) -ne 
			(Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName" -Name ComputerName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ComputerName)

		try
		{
			$SccmClientSDK = Invoke-CimMethod -ClassName CCM_ClientUtilities -MethodName "DetermineIfRebootPending" -Namespace "ROOT\\ccm\\ClientSDK" -ErrorAction Stop
			$SccmReboot = ($SccmClientSDK.IsHardRebootPending -or $SccmClientSDK.RebootPending)
		}
		catch [Exception] {}

		$Reboots = @{"Component Based Servicing" = $CbsReboot; "File Rename" = $FileNameReboot; "Computer Rename" = $ComputerRenameReboot; "Windows Update" = $WindowsUpdateReboot; "SCCM" = $SccmReboot}

		$Reboots.GetEnumerator() | Where-Object {$_.Value -eq $true} | ForEach-Object {
			Write-Log -Message "Pending reboot for $($_.Name)." -Level "VERBOSE"
		}

		Write-Output ($Reboots.ContainsValue($true))
	}

	End {		
	}
}

Function Test-Credentials {
	<#
		.SYNOPSIS
			Validates a set of credentials.

		.DESCRIPTION
			This cmdlet takes a set of credentials and validates them against Active Directory.

		.PARAMETER EncryptedPassword
			An encrypted string representing the password. This string should be encrypted using the ConvertFrom-SecureString cmdlet under the current user's context.

		.PARAMETER UserName
			The name of the user account. This can be specified as either DOMAIN\UserName or just as UserName and the domain will default to the current user domain.

		.PARAMETER Password
			An unencrypted string.

		.PARAMETER Credential
			A PSCredential object of the credentials to validate.

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

        .EXAMPLE
			Test-Credentials -UserName administrator -Password MyP@$$w0rD

			Validates the provided credentials using the current user domain.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding(DefaultParameterSetName="Encrypted")]
	Param(
		[Parameter(Mandatory=$true, ParameterSetName="Encrypted")]
		[System.String]$EncryptedPassword,

		[Parameter(Mandatory=$true, ParameterSetName="Secure")]
		[System.Security.SecureString]$Password,

		[Parameter(Mandatory=$true, ParameterSetName="Encrypted")]
		[Parameter(Mandatory=$true, ParameterSetName="Secure")]
		[System.String]$UserName,

		[Parameter(Mandatory=$true, ParameterSetName="Credential")]
		[PSCredential]$Credential
	)

	Begin {		
	}

	Process {
		$Result = $false

		switch ($PSCmdlet.ParameterSetName) {
			"Encrypted" {
				$PlainTextPassword = Convert-SecureStringToString -SecureString (ConvertTo-SecureString -String $EncryptedPassword)
				break
			}
			"Secure" {
				$PlainTextPassword = Convert-SecureStringToString -SecureString $Password
				break
			}
			"Credential" {
				$UserName = $Credential.UserName
				$PlainTextPassword = Convert-SecureStringToString -SecureString $Credential.Password
				break
			}		
		}

		if($UserName.Contains("\")) {
            $Parts= $UserName.Split("\")
            $Domain = $Parts[0]
            $UserName= $Parts[1]
        }
        else {
            $Domain = $env:USERDOMAIN
        }

		Write-Log -Message "Testing credentials for user $UserName in domain $Domain." -Level VERBOSE
		[System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.AccountManagement") | Out-Null

		[System.DirectoryServices.AccountManagement.PrincipalContext]$Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain)

		try 
		{			
			$Result = $Context.ValidateCredentials($UserName, $PlainTextPassword)			
			Write-Log -Message "Provided credentials are valid : $Result" -Level VERBOSE
		}
		catch [Exception] 
		{
			Write-Log -Message "Error checking credentials."-Level WARNING
			Write-Log -ErrorRecord $_ -Level WARNING
		}
		finally 
		{
			$Context.Dispose()
		}

		Write-Output -InputObject $Result
    }

	End {
		
	}
}

Function Write-Log {
	<#
		.SYNOPSIS
			Writes to a log file and echoes the message to the console.

		.DESCRIPTION
			The cmdlet writes text or a PowerShell ErrorRecord to a log file and displays the log message to the console at the specified logging level.

		.PARAMETER Message
			The message to write to the log file.

		.PARAMETER ErrorRecord
			Optionally specify a PowerShell ErrorRecord object to include with the message.

		.PARAMETER Level
			The level of the log message, this is either INFO, WARNING, ERROR, DEBUG, or VERBOSE. This defaults to INFO.

		.PARAMETER Path
			The path to the log file. If this is not specified, the message is only echoed out.

		.PARAMETER NoInfo
			Specify to not add the timestamp and log level to the message being written.

		.INPUTS
			System.String

				The log message can be piped to Write-Log

		.OUTPUTS
			None

        .EXAMPLE
			try {
				$Err = 10 / 0
			}
			catch [Exception]
			{
				Write-Log -Message $_.Exception.Message -ErrorRecord $_ -Level ERROR
			}

			Writes an ERROR log about dividing by 0 to the default log path.

		.EXAMPLE
			Write-Log -Message "The script is starting"

			Writes an INFO log to the default log path.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position = 2)]
		[ValidateSet("INFO", "WARNING", "ERROR", "DEBUG", "VERBOSE")]
		[System.String]$Level = "INFO",

		[Parameter(Mandatory=$true, Position = 0, ValueFromPipeline = $true)]
		[System.String]$Message,

		[Parameter(Position = 1)]
		[System.Management.Automation.ErrorRecord]$ErrorRecord,

		[Parameter()]
		[System.String]$Path,

		[Parameter()]
		[switch]$NoInfo
	)

	Begin {		
	}

	Process {
		if ($ErrorRecord -ne $null) {
			$Message += "`r`n"
			$Message += ("Exception: `n" + ($ErrorRecord.Exception | Select-Object -Property * | Format-List | Out-String) + "`n")
			$Message += ("Category: " + ($ErrorRecord.CategoryInfo.Category.ToString()) + "`n")
			$Message += ("Stack Trace: `n" + ($ErrorRecord.ScriptStackTrace | Format-List | Out-String) + "`n")
			$Message += ("Invocation Info: `n" + ($ErrorRecord.InvocationInfo | Format-List | Out-String))
		}
		
		if ($NoInfo) {
			$Content = $Message
		}
		else {
			$Content = "$(Get-Date) : [$Level] $Message"
		}

		if ([System.String]::IsNullOrEmpty($Path))
		{
			$Path = [System.Environment]::GetEnvironmentVariable("LogPath", [System.EnvironmentVariableTarget]::Machine)
		}

		if (-not [System.String]::IsNullOrEmpty($Path)) 
		{
			try
			{
				Add-Content -Path $Path -Value $Content
			}
			catch [Exception]
			{
				Write-Warning -Message "Could not write to log file : $($_.Exception.Message)`n$Content"
			}
		}

		switch ($Level) {
			"INFO" {
				Write-Host $Content
				break
			}
			"WARNING" {
				Write-Warning -Message $Content
				break
			}
			"ERROR" {
				Write-Error -Message $Content
				break
			}
			"DEBUG" {
				Write-Debug -Message $Content
				break
			}
			"VERBOSE" {
				Write-Verbose -Message $Content
				break
			}
			default {
				Write-Warning -Message "Could not determine log level to write."
				Write-Host $Content
				break
			}
		}
	}

	End {
	}
}

Function Set-UAC {
	<#
		.SYNOPSIS
			Sets the User Account Control to enabled or disabled.

		.DESCRIPTION
			This cmdlet sets the User Account Control to enabled or disabled.

		.PARAMETER Enabled
			Specify whether UAC should be enabled or disabled.

		.INPUTS
			Systyem.Boolean

		.OUTPUTS
			None

        .EXAMPLE
			Set-UAC -Enabled $false

			Disables UAC.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true, ValueFromPipeline = $true, Position = 0)]
		[System.Boolean]$Enabled
	)
    
	Begin {		
	}

	Process {
		Write-Log -Message "Setting User Account Control to Enabled = $Enabled." -Level VERBOSE
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value ([Int32]$Enabled) -ErrorAction SilentlyContinue| out-null
	}

	End {}
}

Function Set-IEESC {
	<#
		.SYNOPSIS
			Sets Internet Explorer Enhanced Security Configuration to enabled or disabled.

		.DESCRIPTION
			This cmdlet sets Internet Explorer Enhanced Security Configuration to enabled or disabled.

		.PARAMETER Enabled
			Specify whether IEESC should be enabled or disabled.

		.INPUTS
			Systyem.Boolean

		.OUTPUTS
			None

        .EXAMPLE
			Set-IEESC -Enabled $false

			Disables IEESC.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[System.Boolean]$Enabled
	)

	Begin {}

	Process {
        Write-Log "Setting IE Enhanced Security Configuration to Enabled = $Enabled." -Level VERBOSE

        $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
        $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"

        Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value ([Int32]$Enabled)
        Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value ([Int32]$Enabled)
	}

	End {}
}

Function Set-OpenFileSecurityWarning {
	<#
		.SYNOPSIS
			Enables or disables file security warnings from items downloaded from the internet.

		.DESCRIPTION
			This cmdlet enables or disables file security warnings from items downloaded from the internet.

		.PARAMETER Enable
			Specify to enable the security warnings.

		.PARAMETER Disable
			Specify to disable the security warnings.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Set-OpenFileSecurityWarning -Disable

			Disables the security warning when opening files from the internet.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true, ParameterSetName="Enable")]
		[switch]$Enable,

		[Parameter(Mandatory=$true, ParameterSetName="Disable")]
		[switch]$Disable	
	)

	Begin {}

	Process {
		if ($Enable) {
			Write-Log -Message "Enabling File Security Warning dialog." -Level VERBOSE

			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "LowRiskFileTypes" -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "LowRiskFileTypes" -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
		}
		elseif ($Disable) {
			Write-Log -Message "Disabling File Security Warning dialog." -Level VERBOSE

			New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -ErrorAction SilentlyContinue | Out-Null
			New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "LowRiskFileTypes" -Value ".exe;.msp;.msu;.msi" -ErrorAction SilentlyContinue | Out-Null
			New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ErrorAction SilentlyContinue | Out-Null
			New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1 -ErrorAction SilentlyContinue | Out-Null
			Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "LowRiskFileTypes" -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
		}
	}

	End {}
}

Function Get-LocalFQDNHostname {
	<#
		.SYNOPSIS
			Gets the FQDN of the local host.

		.DESCRIPTION
			This cmdlet get the FQDN of the local host from DNS.

		.INPUTS
			None

		.OUTPUTS
			System.String

        .EXAMPLE
			Get-LocalFQDNHostname

			Returns the local computer's FQDN.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {}

	Process {
		Write-Output -InputObject ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME)).HostName
	}

	End {}
}

Function Set-Pagefile {
	<#
		.SYNOPSIS
			Configures the size of the page file.

		.DESCRIPTION
			This cmdlet sets the page file to the specified size or a default, optimal size.

		.PARAMETER InitialSize
			The initial size of the page file. This defaults to the maximum size.

		.PARAMETER MaximumSize
			The maximum size of the page file. This defaults to the computer system's RAM plus 10MB up to a size of 32GB + 10MB as both the initial and maximum size.

		.INPUTS 
			System.Int32

		.OUTPUTS
			None

        .EXAMPLE
			Set-Pagefile

			Sets the page file size manually.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position = 1)]
		[System.Int32]$InitialSize = -1,

		[Parameter(Position = 0, ValueFromPipeline = $true)]
		[System.Int32]$MaximumSize = -1
	)

	Begin {}

	Process {
		[System.Int32]$ProductType = Get-CimInstance -ClassName Win32_OperatingSystem -Property ProductType | Select-Object -ExpandProperty ProductType

		if ($ProductType -ne 1)
		{
			Write-Log -Message "Checking Pagefile Configuration" -Level VERBOSE
			$CS = Get-CimInstance -ClassName Win32_ComputerSystem

			if ($CS.AutomaticManagedPagefile -eq $true) {
				Write-Log -Message "System configured to use Automatic Managed Pagefile, reconfiguring"

				try {
					$CS.AutomaticManagedPagefile = $false
				
					if ($MaximumSize -le 0)
					{
						# RAM + 10 MB, with maximum of 32GB + 10MB
						$InstalledMem = $CS.TotalPhysicalMemory
						$MaximumSize = (($InstalledMem + 10MB), (32GB+10MB) | Measure-Object -Minimum).Minimum / 1MB
					}

					if ($InitialSize -gt $MaximumSize -or $InitialSize -le 0)
					{
						$InitialSize = $MaximumSize
					}

					$CPF = Get-CimInstance -ClassName Win32_PageFileSetting
					$CPF.InitialSize= $InitialSize
					$CPF.MaximumSize= $MaximumSize
					$CPF.Put() | Out-Null
				}
				catch [Exception] {
					Write-Log -Message "Problem reconfiguring pagefile." -ErrorRecord $_ -Level WARNING
				}

				$CPF= Get-CimInstance -ClassName Win32_PageFileSetting
				Write-Log -Message "Pagefile set to manual, initial/maximum size: $($CPF.InitialSize)MB / $($CPF.MaximumSize)MB." -Level VERBOSE
			}
			else {
				Write-Log -Message "Manually configured page file, skipping configuration" -Level VERBOSE
			}
		}
		else
		{
			Write-Log -Message "Page file settings are only available on the Server operating system." -Level WARNING
		}
	}
	
	End {
	}
}

Function Set-HighPerformancePowerPlan {
	<#
		.SYNOPSIS
			Enables the high performance power plan on the computer.

		.DESCRIPTION
			This cmdlet sets the active power plan to the High Performance setting.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Set-HighPerformancePowerPlan

			Sets the High Performance plan to active.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[switch]$PassThru
	)

	Begin {}

	Process {
        Write-Log -Message "Configuring Power Plan" -Level VERBOSE

        $PowerPlan = Get-CimInstance -Name root\cimv2\power -ClassName Win32_PowerPlan -Filter "ElementName = 'High Performance'"          
        $Temp = Invoke-CimMethod -InputObject $PowerPlan -MethodName Activate        
        $CurrentPlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan | Where-Object { $_.IsActive }

        Write-Log -Message "Power Plan active: $($CurrentPlan.ElementName)" -Level VERBOSE

		if ($PassThru)
		{
			Write-Output -InputObject $CurrentPlan
		}
	}

	End {}
}

Function Get-NETVersion {
	<#
		.SYNOPSIS
			Gets the current version of .NET version 4 installed.

		.DESCRIPTION
			This cmdlet gets the current version of .NET version 4 installed from the registry at HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full.

		.INPUTS
			None

		.OUTPUTS
			System.Int

        .EXAMPLE
			Get-NETVersion

			Retrieves the .NET version 4 specific version.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
    [CmdletBinding()]
	Param(
	)

	Begin {}

	Process {
        $NetVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Release
        Write-Log -Message ".NET version installed is $NetVersion." -Level VERBOSE
		Write-Output ([System.Int32]$NetVersion)
    }

	End {		
	}
}

Function Set-NET461InstallBlock {
	<#
		.SYNOPSIS
			Sets a temporary installation block for .NET version 4.6.1 (KB3133990) or disables the block.

		.DESCRIPTION
			This cmdlet sets a temporary installation block for .NET 4.6.1 which is sometimes needed is a program is not compatible with this version and you don't want it to be accidentally installed
			through automatic updates. The cmdlet can also disable the block.

		.PARAMETER Disable
			This disables the block. If the parameter is not specified, the block is enabled.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Set-NET461InstallBlock

			Blocks the installation of .NET 4.6.1

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[switch]$Disable
	)

	Begin {}

	Process {
        Write-Log -Message "Set temporary installation block for .NET Framework 4.6.1 (KB3133990)." -Level VERBOSE
        $RegKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\WU"
        $RegName= "BlockNetFramework461"

		if (-not $Disable)
		{
			if (!(Test-Path -Path $RegKey)) {
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Name "WU" | Out-Null
			}

			if ((Get-ItemProperty -Path $RegKey -Name $RegName -ErrorAction SilentlyContinue) -eq $null) {
				New-ItemProperty -Path $RegKey -Name $RegName -Value 1 -PropertyType DWORD  | Out-Null
			}
			else {
				Set-ItemProperty -Path $RegKey -Name $RegName -Value 1 | Out-Null
			}

			if ((Get-ItemProperty -Path $RegKey -Name $RegName -ErrorAction SilentlyContinue) -eq $null) {
				Write-Log -Message "Unable to set registry key $RegKey\$RegName." -Level WARNING 
			}
		}
		else
		{
			if (Test-Path -Path $RegKey) {				
				if ((Get-ItemProperty -Path $RegKey -Name $RegName -ErrorAction SilentlyContinue) -eq $null) {
					Remove-ItemProperty -Path $RegKey -Name $RegName | Out-Null
				}

				if ((Get-ItemProperty -Path $RegKey -Name $RegName -ErrorAction SilentlyContinue) -eq $null) {
					Write-Log -Message "Unable to set registry key $RegKey\$RegName." -Level WARNING 
				}
			}
		}
    }

	End {}
}

Function Start-ProcessWait {
	<#
		.SYNOPSIS
			Starts a new process and waits for it to complete.

		.DESCRIPTION
			This cmdlet starts a new process using .NET System.Diagnostics.Process and waits for it to complete. It optionally writes the standard out of the process to the log file.

		.PARAMETER FilePath
			The path to the executable, script, msi, msu, etc to be executed.

		.PARAMETER ArgumentList
			An array of arguments to run with the file being executed. This defaults to an empty array.

		.PARAMTER EnableLogging
			Specify to write standard output or standard errors to the log file.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Start-ProcessWait -FilePath "c:\installer.msi" -EnableLogging -ArgumentList @("/qn")

			Launches a quiet installation from installer.msi with a no restart option. Logging is also enabled.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[System.String]$FilePath,

		[Parameter()]
		[ValidateNotNull()]
		[System.String[]]$ArgumentList = @(),

		[Parameter()]
		[switch]$EnableLogging
	)

	Begin {
	}

	Process {
		if (Test-Path -Path $FilePath) {
			[System.IO.FileInfo]$FileInfo = New-Object -TypeName System.IO.FileInfo($FilePath)

			[System.Diagnostics.Process]$Process = New-Object -TypeName System.Diagnostics.Process
			$Process.StartInfo.RedirectStandardOutput = $true
			$Process.StartInfo.UseShellExecute = $false
			$Process.StartInfo.CreateNoWindow = $true
			$Process.StartInfo.RedirectStandardError = $true

            switch($FileInfo.Extension.ToUpper()) {
                ".MSU" {
					$ArgumentList += "$FilePath"
					$Process.StartInfo.Filename = "$env:SystemRoot\System32\WUSA.EXE"
					$Process.StartInfo.Arguments = ($ArgumentList -join " ")
					break
                }
                ".MSP" {
                    $ArgumentList += "$FilePath"
					$ArgumentList += "/update"
					$Process.StartInfo.Filename = "MSIEXEC.EXE"
					$Process.StartInfo.Arguments = ($ArgumentList -join " ")
					break
                }
				".MSI" {
                    $ArgumentList += "$FilePath"
					$Process.StartInfo.Filename = "MSIEXEC.EXE"
					$Process.StartInfo.Arguments = ($ArgumentList -join " ")
					break
                }
                default {
					$Process.StartInfo.Filename = "$FilePath"
					$Process.StartInfo.Arguments = ($ArgumentList -join " ")
					break
                }
            }

            Write-Log -Message "Executing $FilePath $($ArgumentList -Join " ")" -Level VERBOSE

			$Process.Start() | Out-Null
			
			if ($EnableLogging) {
				while (!$Process.HasExited) {
					 while (![System.String]::IsNullOrEmpty(($Line = $Process.StandardOutput.ReadLine()))) {
						Write-Log -Message $Line -NoInfo
					}

					Start-Sleep -Milliseconds 100
				}

				if ($Process.ExitCode -ne 0) {
					$Line = $Process.StandardError.ReadToEnd()
					if (![System.String]::IsNullOrEmpty($Line)) {
						Write-Log -Message $Line -Level ERROR -NoInfo
					}
				}
				else {
					$Line = $Process.StandardOutput.ReadToEnd()
					if (![System.String]::IsNullOrEmpty($Line)) {
						Write-Log -Message $Line -NoInfo
					}
				}
			}
			else {
				$Process.WaitForExit()
			}
        }
        else {
            Write-Log -Message "$FilePath not found." -Level WARNING
        }
	}

	End {}
}

Function Get-FileVersion {
	<#
		.SYNOPSIS
			Gets the version of a specific file or file running a Windows service from its metadata.

		.DESCRIPTION
			This cmdlet gets the FileVersion data from a specified file or file running a service. If no version is included in the FileInfo, the cmdlet returns "0".

		.PARAMETER Path
			The path to the file.

		.PARAMETER Service
			The name of the service.

		.INPUTS
			None

		.OUTPUTS
			System.String

        .EXAMPLE
			Get-FileVersion -Path "c:\installer.exe"

			Gets the file version of installer.exe.

		.EXAMPLE
			Get-FileVersion -Service lmhosts

			Gets the file version of the svchost.exe running the lmhosts service.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,ParameterSetName="File",ValueFromPipeline = $true, Position = 0)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$Path
	)

	DynamicParam
    {
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		$Services = Get-Service | Select-Object -ExpandProperty Name

		$ValidateSet = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($Services)

		[System.Management.Automation.ParameterAttribute]$Attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
		$Attributes.ParameterSetName = "Service"
		$Attributes.Mandatory = $true
		$Attributes.ValueFromPipeline = $true
		$Attributes.Position = 0
            
		$AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
		$AttributeCollection.Add($Attributes)
		$AttributeCollection.Add($ValidateSet)

        [System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("ServiceName", [System.String], $AttributeCollection)
        $ParamDictionary.Add("ServiceName", $DynParam)

		return $ParamDictionary
	}

	Begin {}

	Process {
		switch ($PSCmdlet.ParameterSetName) {
			"File" {
				break
			}
			"Service" {
				$Path = (Get-WmiObject -Class Win32_Service -Filter "Name = `"$($PSBoundParameters.ServiceName)`"" | Select-Object -ExpandProperty PathName).Trim("`"")
				break
			}
			default {
				throw "Could not determine parameter set name from given parameters."
			}
		}

		$Version = New-Object -TypeName System.IO.FileInfo($Path) | Select-Object -ExpandProperty VersionInfo | Select-Object -ExpandProperty FileVersion

		if ([System.String]::IsNullOrEmpty($Version))
		{
			$Version = "0"
		}

		Write-Output -InputObject $Version
	}

	End {	
	}
}

Function Disable-SSLv3 {
	<#
		.SYNOPSIS
			Completely disables the use of SSLv3.

		.DESCRIPTION
			This cmdlet disables SSLv3 by use of both the client and server components.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Disable-SSLv3

			Disables SSLv3 on the system.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {
		#Disable SSLv3 to protect against POODLE scan
		$ServerRegKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
		$ClientRegKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
        $ServerRegName = "Enabled"
		$ClientRegName = "DisabledByDefault"
	}

	Process {
		Write-Log -Message "Disabling SSLv3 protocol."

		if (!(Test-Path -Path $ServerRegKey)) {
			New-Item -Path $ServerRegKey | Out-Null
		}

		New-ItemProperty -Path $ServerRegKey -Name $ServerRegName -Value 0 -PropertyType DWORD | Out-Null

		if (!(Test-Path -Path $ClientRegKey)) {
			New-Item -Path $ClientRegKey | Out-Null
		}

		New-ItemProperty -Path $ClientRegKey -Name $ServerRegName -Value 0 -PropertyType DWORD | Out-Null
		New-ItemProperty -Path $ClientRegKey -Name $ClientRegName -Value 1 -PropertyType DWORD | Out-Null

		Write-Log -Message "Successfully disabled SSLv3."
	}

	End {		
	}        
}

Function Test-PackageInstallation {
	<#
		.SYNOPSIS
			Tests for the installation of the specified software or update.

		.DESCRIPTION
			This cmdlet evaluates Win32_QuickFixEngineering, HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall, and
			HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products for a matching product.

		.PARAMETER PackageId
			The Id of the installed package, software, or update.

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

        .EXAMPLE
			Test-PackageInstallation -PackageId KB2803757

			Tests for the installation of KB2803757.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[System.String]$PackageId
	)

	Begin {}

	Process {
        $PresenceKey = $null
        $PresenceKey = Get-CimInstance -Class Win32_quickfixengineering -ErrorAction SilentlyContinue | Where-Object { $_.HotFixID -eq $PackageId } | Select-Object -ExpandProperty HotFixID
        
		if ([System.String]::IsNullOrEmpty($PresenceKey)) {
			$Result = Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$PackageId"
            
			if ($Result -eq $false) {
				# Alternative (seen KB2803754, 2802063 register here)
                $Result = Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$PackageId"
                
                if ($Result -eq $false) {
                    # Alternative (Office2010FilterPack SP1)
					$Result = Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$PackageId"
                }
            }
        }
		else {
			$Result = $true
		}

		Write-Output -InputObject $Result
	}

	End {		
	}
}

Function Get-WebPackage {
	<#
		.SYNOPSIS
			Retrieves a specified package from the internet.

		.DESCRIPTION
			This cmdlet tests for the presence of the desired package name, and if it is not present at the provided destination folder, downloads it from the given Url.

			Hotfixes that download with a _zip in the filename, but have a .exe extension, will be automatically expanded to a true zip file.

		.PARAMETER PackageName
			The name of the package.

		.PARAMETER Destination
			The path where the package should be downloaded to, this should be the resulting file name of the downloaded item.

		.PARAMETER Url
			The source to download the package from.

		.INPUTS
			None

		.OUTPUTS
			System.String[]

        .EXAMPLE
			Get-WebPackage -PackageName "Test App" -Url "http://contoso.com/testapp.zip" -Destination "c:\testapp.zip"

			Gets the zip file from the Url and returns the list of its contents.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[System.String]$PackageName,

		[Parameter(Mandatory = $true, Position = 0)]
		[System.String]$Url,

		[Parameter(Mandatory = $true, Position = 1)]
		[System.String]$Destination
	)

	Begin {		
	}

	Process {
		$Result = @()

		if (![System.String]::IsNullOrEmpty($PackageName)) 
		{
			Write-Log -Message "Processing package $PackageName."
		}

		if (!(Test-Path -Path $Destination)) 
		{
			Write-Log "$Destination not present, downloading from $Url." -Level VERBOSE

			try {
				$WebClient = New-Object -TypeName System.Net.WebClient
				$WebClient.DownloadFile($Url, $Destination)

				$FileInfo = New-Object -TypeName System.IO.FileInfo($Destination)

				if ($FileInfo.Name.Contains("_zip")) 
				{
					try {
						Write-Log -Message "Expanding Hotfix $($FileInfo.Name)." -Level VERBOSE

						if (!$Destination.EndsWith(".zip")) 
						{
							$Destination = Rename-Item -Path $Destination -NewName "$Destination.zip" -PassThru | Select-Object -ExpandProperty FullName
						}

						[System.IO.Compression.ZipArchive]$Zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
						$Contents = $Zip.Entries | Select-Object -Property @{Name = "Path"; Expression = {"$($FileInfo.DirectoryName)\$($_.FullName)"}} | Select-Object -ExpandProperty Path
						$Zip.Dispose()
						[System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $FileInfo.DirectoryName)

						Write-Log -Message "Successfully expanded files $($Contents -join `",`")" -Level VERBOSE

						$Result = $Contents
					}
					catch [Exception] {
						Write-Log -Message "Error expanding zip file $Destination." -Level WARNING -ErrorRecord $_
					}
				}
				else {
					$Result = @($Destination)
				}
			}
			catch [Exception] {
				Write-Log -Message "Problem downloading file from $Url." -Level WARNING -ErrorRecord $_
			}
		}
		else 
		{
			Write-Log -Message "$Destination is present, no need to download." -Level VERBOSE
			$Result = @($Destination)
		}

		Write-Output -InputObject $Result
	}

	End {		
	}
}

Function Start-PackageInstallation {
	<#
		.SYNOPSIS
			Installs the specified package.

		.DESCRIPTION
			This cmdlet launches the installation of a specified package.

		.PARAMETER PackageId
			The PackageId of the package to test if the package is already installed.

		.PARAMETER PackageName
			The name of the package to install, can be any text you want to identify the package in the logs.

		.PARAMETER Destination
			The location to download the installation files to.

		.PARAMETER Url
			The source path to download the installation files from.

		.PARAMETER Arguments
			The arguments to be used with the installation file.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Start-PackageInstallation -PackageId "KB123456" -PackageName "Another update" -Destination "c:\kb123456.msu" -Url "http://contoso.com/kb123456.msu" -ArgumentList @("\qn")

			Installs the specified KB.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[System.String]$PackageId,

		[Parameter(Mandatory=$true)]
		[System.String]$PackageName,

		[Parameter(Mandatory=$true)]
		[System.String]$Destination,

		[Parameter(Mandatory=$true)]
		[System.String]$Url,

		[Parameter()]
		[ValidateNotNull()]
		[System.String[]]$Arguments = @()
	)

	Begin {}

	Process {
        Write-Log -Message "Processing $PackageName ($PackageId)"

        if (!(Test-PackageInstallation -PackageId $PackageId)) {

			Write-Log -Message "Package not detected, installing."

			$Contents = @()

            if (!(Test-Path -Path $Destination)) {
				# Download & Extract
				$Contents = Get-WebPackage -Package $PackageName -Url $Url -Destination $Destination

                if ($Contents.Count -eq 0) {
					Write-Log -Message "Problem downloading/accessing $PackageName" -Level ERROR
					throw "Problem downloading/accessing $PackageName"
                }
            }
			else {
				$Contents += $Destination
			}
               
			Write-Log -Message "Installing $PackageName"

			foreach ($Item in $Contents) {
				$Lower = $Item.ToLower()
				if ($Lower.EndsWith(".exe") -or $Lower.EndsWith(".msi") -or $Lower.EndsWith(".msu") -or $Lower.EndsWith(".msp")) {
					Start-ProcessWait -FilePath $Item -ArgumentList $Arguments -EnableLogging
				}
			}

			if (!(Test-PackageInstallation -PackageId $PackageId)) {
                Write-Log -Message "Problem installing $PackageName after the install steps were run, did not find the package Id $PackageId." -Level ERROR
				throw "Problem installing $PackageName after the install steps were run, did not find the package Id $PackageId."
            }
			else {
				Write-Log -Message "$PackageName successfully installed."
			}
        }
        else {
            Write-Log -Message "$PackageName already installed" -Level VERBOSE
        }  
	}
	
	End {}  
}

Function Set-RunOnceScript {
	<#
		.SYNOPSIS
			Adds a RunOnce script that launches a PowerShell script at user logon.

		.DESCRIPTION
			This cmdlet adds a RunOnce script that launches on user logon. If the specified Name already exists as a RunOnce entry, it is removed first.

		.PARAMETER Command
			The command to run. This can be the path to a script file, or native PowerShell commands.

		.PARAMETER StoreAsPlainText
			Stores the commands as plain text instead of Base64.

		.PARAMTER RunFile
			Specifies that the command parameter was the path to a script file and not native PowerShell commands.

		.PARAMETER Name
			The name of the RunOnce entry in the registry.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Set-RunOnceScript -Command "c:\test.ps1" -RunFile

			Configures the RunOnce setting to run the c:\test.ps1 file when a user logs on.

		.EXAMPLE 
			Set-RunOnceScript -Command "Get-Service" -Name "ListServices"

			Configures the RunOnce setting to run the Get-Service cmdlet when a user logs on.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/26/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[System.String]$Command,

		[Parameter(ParameterSetName="Text")]
		[switch]$StoreAsPlainText,

		[Parameter(ParameterSetName="File")]
		[switch]$RunFile,

		[Parameter(Mandatory = $true)]
		[System.String]$Name
	)

	Begin {

	}

	Process {
		$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        
		if ([System.String]::IsNullOrEmpty($Name))
		{
			$Name = $script:RunOnceTaskName
		}

        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue

		$RunOnce = "$PSHome\PowerShell.exe -NoProfile -NoLogo -NoExit -ExecutionPolicy Unrestricted"

		if ($StoreAsPlainText) {		
			$Command = $Command.Replace("`"", "\`"").Replace("`n","").Replace("`r","").Replace("`t","")
			#$RunOnce += " -Command `"& {$Command}`""
            $RunOnce += " -Command `"$Command`""
		}
		elseif ($RunFile) {
            $RunOnce += " -File `"$Command`""
        }
		else {
			$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
			$EncodedCommand = [System.Convert]::ToBase64String($Bytes)
			$RunOnce += " -EncodedCommand $EncodedCommand"
		}

		if (!(Test-Path -Path $Path)) {
			New-Item -Path $Path | Out-Null
		}
		
		Write-Log -Message "Setting RunOnce: $RunOnce" -Level VERBOSE
		New-ItemProperty -Path $Path -Name $Name -Value "$RunOnce" -PropertyType String | Out-Null
		Write-Log -Message "Successfully set RunOnce." -Level VERBOSE
	}

	End {
	}
}

Function Extract-ZipFile {
	<#
		.SYNOPSIS
			The cmdlet extracts the contents of a zip file to a specified destination.

		.DESCRIPTION
			The cmdlet extracts the contents of a zip file to a specified destination and optionally preserves the contents in the destination if they already exist.

		.PARAMETER Source
			The path to the zip file.

		.PARAMETER Destination
			The folder where the zip file should be extracted. The destination is created if it does not already exist.

		.PARAMETER NoOverwrite
			Specify if the contents in the destination should be preserved if they already exist.

		.INPUTS
			None
		
		.OUTPUTS
			None

		.EXAMPLE 
			Extract-ZipFile -Source "c:\test.zip" -Destination "c:\test"

			Extracts the contents of test.zip to c:\test.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0, Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$Source,

		[Parameter(Position=1, Mandatory=$true)]
		[System.String]$Destination,

		[Parameter()]
		[switch]$NoOverwrite
	)

	Begin {
		Add-Type -AssemblyName System.IO.Compression.FileSystem
	}

	Process {
		if (!(Test-Path -Path $Source)) {
			throw [System.IO.FileNotFoundException]("Source zip file not found.")
		}

		if (!(Test-Path -Path $Destination)) {

			Write-Log "Zip extract destination $Destination does not exist, creating it."

			try {
				New-Item -Path $Destination -ItemType Directory | Out-Null

				$Counter = 0

				while (!(Test-Path -Path $Destination)) {
					Start-Sleep -Seconds 1
					$Counter++

					if ($Counter -gt 60) {
						throw "Timeout error waiting for the zip extraction destination $Destination to be created."
					}
				}
			}
			catch [Exception] {
				Write-Log -ErrorRecord $_
				throw $_.Exception
			}
		}
		else {
			if (![System.IO.Directory]::Exists($Destination)) {
				throw [System.IO.DirectoryNotFoundException]("The destination is a file, not a directory.")
			}
		}

		if (-not $NoOverwrite) {
			Write-Log -Message "Extracting zip without overwriting existing content."
			[System.IO.Compression.ZipArchive]$ZipArchive = [System.IO.Compression.ZipFile]::OpenRead($Source)

			try
			{
				foreach ($ZipArchiveEntry in $ZipArchive.Entries) {
					$FullPath = [System.IO.Path]::Combine($Destination, $ZipArchiveEntry.FullName)

					#Test to see if the archive entry is a directory
					#Directories' name attribute is empty, 
					if ([System.String]::IsNullOrEmpty($ZipArchiveEntry.Name) -or $ZipArchiveEntry.FullName.Contains("/")) {
						$Temp = [System.IO.Path]::Combine($Destination, $ZipArchiveEntry.FullName.Substring(0, $ZipArchiveEntry.FullName.LastIndexOf("/")))
						$Temp = $Temp.Replace("/","\")
						if (![System.IO.Directory]::Exists($Temp)) {
							try {
								New-Item -Path $Temp -ItemType Directory | Out-Null

								$Counter = 0
								while (!(Test-Path -Path $Temp)) {
									Start-Sleep -Seconds 1
									$Counter++

									if ($Counter -gt 60) {
										throw "Timeout waiting for directory creation $Temp"
									}
								}
							}
							catch [Exception] {
								Write-Log -ErrorRecord $_
							}
						}
					}

					if (![System.String]::IsNullOrEmpty($ZipArchiveEntry.Name)) {
						try
						{
							$FullPath = $FullPath.Replace("/","\")

							[System.IO.Compression.ZipFileExtensions]::ExtractToFile($ZipArchiveEntry, $FullPath, $true)

							$Counter = 0
							
							while(!(Test-Path -Path $FullPath)) {
								Start-Sleep -Seconds 1
								$Counter++

								if ($Counter -gt 60) {
									Write-Log "Timeout waiting for zip extraction of $FullPath"
									break
								}
							}
						}
						catch [Exception] {
							Write-Log -ErrorRecord $_
						}
					}
				}
			}
			finally {
				$ZipArchive.Dispose()
			}
		}
		else {
			Write-Log -Message "Extracting zip with overwrite."
			[System.IO.Compression.ZipFile]::ExtractToDirectory($Source, $Destination)
		}
	}

	End {		
	}
}

Function New-RandomPassword {
	<#
		.SYNOPSIS
			The cmdlet generates a random string.

		.DESCRIPTION
			The cmdlet generates a random string with a specific length and complexity settings.

		.PARAMETER Length
			The length of the returned string, this defaults to 14.

		.PARAMETER SourceData
			The range of characters that can be used to generate the string. This defaults to 

			for ($a=33; $a -le 126; $a++) {
				$SourceData += ,[char][byte]$a 
			}  

			which contains upper, lower, number, and special characters.

		.PARAMETER EnforceComplexity
			Specify to ensure the produced string has at least 2 upper, 2 lower, 2 number, and 2 special characters.

		.PARAMETER AsSecureString
			Specify to return the result as a secure string instead of a standard string.

		.INPUTS
			System.Int32
		
		.OUTPUTS
			System.String

			System.Security.SecureString

		.EXAMPLE 
			$Pass = New-RandomPassword

			Generates a new random password.

		.NOTES
			None
	#>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [System.Int32]$Length=14,

        [Parameter(Position=1)]
        $SourceData = $null,

        [Parameter()]
        [switch]$EnforceComplexity,

		[Parameter()]
		[switch]$AsSecureString
    )

	Begin {		
	}

    Process {
		$Password = [System.String]::Empty

		if ($SourceData -eq $null) {        
			for ($a=33; $a -le 126; $a++) {
				$SourceData += ,[char][byte]$a 
			}          
		}

		if ($EnforceComplexity) {
			if ($Length -lt 14) {
				$Length = 14
			}
		}

		if ($EnforceComplexity) {
			$Upper = 0
			$Lower = 0
			$Special = 0
			$Number = 0

			while ($Upper -lt 2 -or $Lower -lt 2 -or $Special -lt 2 -or $Number -lt 2) {
				$Upper = 0
				$Lower = 0
				$Special = 0
				$Number = 0

				$Password = ""

				for ($i=1; $i –le $Length; $i++) {
					$Password += ($SourceData | Get-Random)
				}

				for ($i = 0; $i -lt $Password.Length; $i++) {
					if ([System.Char]::IsUpper($Password[$i])) {
						$Upper++
					}
					if ([System.Char]::IsLower($Password[$i])) {
						$Lower++
					}
					if ([System.Char]::IsSymbol($Password[$i])) {
						$Special++
					}
					if ([System.Char]::IsNumber($Password[$i])) {
						$Number++
					}
				}
			}
		}
		else {
			for ($i=1; $i –le $Length; $i++) {
				$Password += ($SourceData | Get-Random)
			}
		}

		if ($AsSecureString) {
			Write-Output -InputObject (ConvertTo-SecureString -String $Password -AsPlainText -Force)
		}
		else {
			Write-Output -InputObject $Password
		}
	}

	End {		  		
	}
}

Function New-EncryptedPassword {
	<#
		.SYNOPSIS
			The cmdlet creates a password encrypted with the calling user's credentials.

		.DESCRIPTION
			The cmdlet creates a password encrypted with the calling user's credentials via the Windows Data Protection API (DPAPI).

		.PARAMETER Password
			The plain text password to encrypt.

		.PARAMETER SecurePassword
			The secure string password to encrypt.

		.INPUTS
			System.String

			System.Security.SecureString
		
		.OUTPUTS
			System.String

		.EXAMPLE 
			New-EncryptedPassword -Password "MySecurePassword"

			Encrypts the password with the calling user's credentials.

		.NOTES
			None
	#>
    [CmdletBinding(DefaultParameterSetName="SecureString")]
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true,ParameterSetName="PlainText")]
        [System.String]$Password,

        [Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true,ParameterSetName="SecureString")]
        [SecureString]$SecurePassword
    )

    Begin {        
    }

    Process {
		switch ($PSCmdlet.ParameterSetName) {
            "PlainText" {
                [SecureString]$SecurePass = ConvertTo-SecureString -String $Password -AsPlainText -Force
                break
            }
            "SecureString" {
                [SecureString]$SecurePass = $SecurePassword
				break
            }
            default {
                throw "Could not determine parameter set for Save-EncryptedPassword."
            }
        }

        Write-Output -InputObject (ConvertFrom-SecureString -SecureString $SecurePass)
    }

    End {}
}

Function Get-EncryptedPassword {
	<#
		.SYNOPSIS
			The cmdlet unencrypts an encrypted string stored in a file.

		.DESCRIPTION
			The cmdlet unencrypts a string stored in a file using the calling user's credentials via the Windows Data Protection API (DPAPI).

		.PARAMETER FilePath
			The path to the file with the encrypted password.

		.INPUTS
			System.String
		
		.OUTPUTS
			System.Security.SecureString

		.EXAMPLE 
			Get-EncryptedPassword -FilePath "c:\password.txt"

			Unencrypts the password stored in the file with the calling user's credentials.

		.NOTES
			None
	#>
	[CmdletBinding()]
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
        [System.String]$FilePath
    )

    Begin {        
    }

    Process {
        [SecureString]$Password = Get-Content -Path $FilePath | ConvertTo-SecureString

		Write-Output -InputObject $Password
    }

    End {       
    }
}

Function Get-CertificateSAN {
	<#
		.SYNOPSIS
			The cmdlet gets the Subject Alternative Name (SAN) values from a certificate.

		.DESCRIPTION
			The cmdlet reviews a provided certificate and extracts the SAN values from the certificate
			as an array of strings. If no SAN values exist, it returns an empty array.
		
		.PARAMETER CertificateHash
			The certificate hash string or thumbprint value for the certificate to get SAN values for. This certificate
			should be in the LocalMacine\My certificate store.

		.PARAMETER Certificate
			The X509Certificate2 object to get SAN values for.

		.INPUTS
			System.String, System.Security.Cryptography.X509Certificates.X509Certificate2
		
		.OUTPUTS
			System.String[]

		.EXAMPLE 
			Get-CertificateSAN -CertificateHash 53A7B7B8F3EC7AC94E59EDAC82029F4D6AAB4E47

			Gets the SAN values, if any, for the certificate with thumprint 53A7B7B8F3EC7AC94E59EDAC82029F4D6AAB4E47.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 3/31/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(ParameterSetName = "Hash", Mandatory = $true, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$CertificateHash,

		[Parameter(ParameterSetName = "Certificate", Mandatory = $true, ValueFromPipeline = $true)]
		[ValidateNotNull()]
		[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
	)

	Begin{
	}

	Process {
        switch ($PSCmdlet.ParameterSetName)
        {
            "Hash" {
                $Certificate = Get-Item -Path "Cert:\LocalMachine\My\$CertificateHash"
                break
            }
            "Certificate" {
                # Do nothing
                break
            }
            default {
                throw "Could not determine parameterset name"
                break
            }
        }

		if($Certificate -ne $null)
		{
			$Result = $Certificate.Extensions | Where-Object {$_.Oid.FriendlyName -match "subject alternative name"}
			if ($Result -ne $null)
			{
				#Indicates if the return string should contain carriage returns
				[System.Boolean]$MultiLine = $false
				Write-Output -InputObject ($Result.Format($MultiLine).Split(",") | ForEach-Object {
                    Write-Output -InputObject $_.Trim()
                })
			}
			else
			{
				Write-Output -InputObject @()
			}
		}
		else
		{
			throw "Certificate not found."
		}
	}

	End {
	}
}

Function Get-DiskFree {
	<#
		.SYNOPSIS
			The cmdlet implements many of the features of the *nix command "df" and retrieves information about logical drives.

		.DESCRIPTION
			The cmdlet gets disk information on a local or remote computer using the CIM interface. It can display the information as
			a number of a specified block size, which defaults to 1K blocks, or in a more human readable format.
		
		.PARAMETER ComputerName
			The name of the computer to get the information from. This defaults to the local computer.

		.PARAMETER HumanReadable
			Provides the data in a human readable format in terms of MB, GB, TB, etc.

		.PARAMETER BlockSize
			Specifies how the size, available, and used space are reported. This defaults to 1024 (1K) blocks. So, on a system that had 4KB of storage, the
			Size parameter would report 4 for 1K blocks.

		.PARAMETER Type
			Specify the type of file system to report on. Only logical drives with this file system will be included. This cannot be specified if the
			ExcludeType parameter is specified.

		.PARAMETER ExcludeType
			Specify the type of file system to not include in the results. Logical drives with this file system will not be included. This cannot be specified
			if the Type parameter is specified.

		.PARAMETER Credential
			The credentials used to connect to the remote machine.

		.INPUTS
			System.String
		
		.OUTPUTS
			System.Management.Automation.PSCustomObject

		.EXAMPLE 
			Get-DiskFree

			Gets information about the logical drives on the local machine in terms of 1K blocks.

		.EXAMPLE
			Get-DiskFree -BlockSize 2048
			
			Gets information about the logical drives on the local machine in terms of 2K blocks.

		.EXAMPLE
			Get-DiskFree -HumanReadable
			
			Gets information about the logical drives on the local machine and presents the storage quantities in a human readable form.

			This command could also have been run as df -h

		.EXAMPLE
			Get-DiskFree -Type NTFS
	
			Gets information about logical drives on the local machine that are formatted with NTFS and presents them in terms of 1K blocks.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/20/2017
	#>
    [Alias("df")]
    [CmdletBinding(DefaultParameterSetName = "blocks")]
    Param(
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [System.String]$ComputerName,

        [Parameter(ParameterSetName="human")]
        [Alias("h")]
        [switch]$HumanReadable,

        [Parameter(ParameterSetName="blocks")]
        [ValidateScript({
            $_ % 1024 -eq 0
        })]
        [System.UInt32]$BlockSize = 1024,

        [Parameter()]
        [ValidateSet("FAT16", "FAT32", "NTFS", "CDFS", "ReFS", "ext3", "ext4", "HDFS")]
        [ValidateScript({
            -not $PSBoundParameters.ContainsKey("ExcludeType")
        })]
        [System.String]$Type,

        [Parameter()]
        [ValidateSet("FAT16", "FAT32", "NTFS", "CDFS", "ReFS", "ext3", "ext4", "HDFS")]
        [ValidateScript({
            -not $PSBoundParameters.ContainsKey("Type")
        })]
        [System.String]$ExcludeType,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty

    )

    Begin {
        Function Format-FileSize {
            Param (
                [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
                [System.Int64]$Size
            )

            Begin {
            }

            Process {
                [System.String]$private:Result = [System.String]::Empty

                switch ($Size)
                {
                    {$_ -ge 1PB} {
                        $private:Result = [System.String]::Format("{0:0.00}PB", $Size / 1PB)
                        break
                    }
                    {$_ -ge 1TB} {
                        $private:Result = [System.String]::Format("{0:0.00}TB", $Size / 1TB)
                        break
                    }
                    {$_ -ge 1GB} {
                        $private:Result = [System.String]::Format("{0:0.00}GB", $Size / 1GB)
                        break
                    }
                    {$_ -ge 1MB} {
                        $private:Result = [System.String]::Format("{0:0.00}MB", $Size / 1MB)
                        break
                    }
                    {$_ -ge 1KB} {
                        $private:Result = [System.String]::Format("{0:0.00}KB", $Size / 1KB)
                        break
                    }
                    default {
                        $private:Result = [System.String]::Format("{0:0.00}B", $Size)
                        break
                    }
                }

                Write-Output -InputObject $private:Result
                
            }

            End {
            }
        }
    }
    
    Process {
        $Splat = @{}

        if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
        {
            $Splat.Credential = $Credential
        }

        #Make sure the computer specified isn't the local machine
        if (-not [System.String]::IsNullOrEmpty($ComputerName) -and $ComputerName.ToLower() -notin ("127.0.0.1", ".", "localhost", $env:COMPUTERNAME.ToLower()))
        {
            $Splat.ComputerName = $ComputerName
        }

        <#
            https://msdn.microsoft.com/en-us/library/aa394173(v=vs.85).aspx
            Drive Types

            Unknown (0)
            No Root Directory (1)
            Removable Disk (2)
            Local Disk (3)
            Network Drive (4)
            Compact Disc (5)
            RAM Disk (6)

            Only want to look at disks from 2 on that have a reported size
            
            The Windows Configuration Manager error code reports 0 when the device is working properly
        #>
        [Microsoft.Management.Infrastructure.CimInstance]$Result = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "Size != Null AND DriveType >= 2 AND (ConfigManagerErrorCode = Null OR ConfigManagerErrorCode = 0)" @Splat

        $FormatSplat = @{}

        if ($PSBoundParameters.ContainsKey("BlockSize"))
        {
            $FormatSplat.BlockSize = $BlockSize
        }

        $Disks = $Result | Select-Object @{Name = "ComputerName"; Expression = {$_.SystemName}},
                @{Name = "Vol"; Expression = {$_.DeviceID}},
                @{Name = if ($HumanReadable) { "Size" } else { "$($BlockSize / 1KB)K-blocks" }; Expression = { if ($HumanReadable) { Format-FileSize -Size $_.Size } else {$_.Size / $BlockSize } }},
                @{Name = "Used"; Expression = { if ($HumanReadable) { Format-FileSize -Size ($_.Size - $_.FreeSpace) } else { ($_.Size - $_.FreeSpace) / $BlockSize } }},
                @{Name = "Avail"; Expression = { if ($HumanReadable) { Format-FileSize -Size ($_.FreeSpace) } else { $_.FreeSpace / $BlockSize } }},
                @{Name = "Use%"; Expression = {[System.Math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100)}},
                @{Name = "FS"; Expression = {$_.FileSystem}},
                @{Name = "Type"; Expression = {$_.Description}}
                    
        if ($PSBoundParameters.ContainsKey("Type"))
        {
            $Disks = $Disks | Where-Object {$_.FS -ieq $Type}
        }

        if ($PSBoundParameters.ContainsKey("ExcludeType"))
        {
            $Disks = $Disks | Where-Object {$_.FS -ine $ExcludeType}
        }

        Write-Output -InputObject $Disks
    }
}

Function Invoke-ForceDelete {
		<#
		.SYNOPSIS
			The cmdlet forces the deletion of a file or folder and all of its content.

		.DESCRIPTION
			The cmdlet takes ownership of the file or content in a directory and grants the current user
			full control permissions to the item. Then it deletes the item and performs this recursively
			through the directory structure specified.
		
		.PARAMETER Path
			The path to the file or folder to forcefully delete.

		.PARAMETER Force
			Ignores the confirmation to delete each item.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			Invoke-ForceDelete -Path c:\windows.old

			Forcefully deletes the c:\windows.old directory and all of its content.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/24/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ 
            try {
                Write-Output -InputObject (Test-Path -Path $Path -ErrorAction Stop)
            }
            catch [System.UnauthorizedAccessException] {
                Write-Output $true
            } 
        })]
		[System.String]$Path,

		[Parameter()]
		[switch]$Force
	)

	Begin {
	}

	Process {	
		#Fix any paths that were fed in dot sourced
		$Path = Resolve-Path -Path $Path

        Write-Verbose -Message "Cmdlet called with path $Path"

        #Take ownership of the provided path
        & takeown.exe /F "$Path" | Out-Null

		#Get current user
        [System.Security.Principal.WindowsIdentity]$Current = [System.Security.Principal.WindowsIdentity]::GetCurrent()

		#Give full control to the user
		& icacls.exe "$Path" /grant "*$($Current.User.Value):(F)" | Out-Null

		#If it's a directory, remove all of the child content
		if ([System.IO.Directory]::Exists($Path))
		{
            Write-Verbose -Message "The current path $Path is a directory."

			Get-ChildItem -Path $Path -Force | ForEach-Object { 		
                Invoke-ForceDelete -Path $_.FullName
			}
		}
        
        #Remove the specified path whether it is a folder or file
		try
        {	
			if ($PSCmdlet.ShouldProcess($Path, "Delete") -or $Force)
			{
				Write-Host "Deleting $Path" 
				Remove-Item -Path $Path -Confirm:$false -Force -Recurse

				$Counter = 0

				do 
				{
					try {
						$Found = Test-Path -Path $Path -ErrorAction Stop
					}
					catch [System.UnauthorizedAccessException] {
						$Found = $true
					}

					Start-Sleep -Milliseconds 100
                
				} while (($Found -eq $true) -and $Counter++ -lt 50)

				if ($Counter -eq 50)
				{
					Write-Warning -Message "Timeout waiting for $Path to delete"
				}
			}
        }
        catch [Exception]
        {
            Write-Warning -Message $_.Exception.Message
        }      
	}

	End {
	}
}

Function Invoke-Using {
    <#
        .SYNOPSIS
            Provides a C#-like using() block to automatically handle disposing IDisposable objects.

        .DESCRIPTION
            The cmdlet takes an InputObject that should be an IDisposable, executes the ScriptBlock, then disposes the object.

        .PARAMETER InputObject
            The object that needs to be disposed of after running the scriptblock.

        .PARAMETER ScriptBlock
            The scriptblock to execute with the "using" variable.

        .EXAMPLE
            Invoke-Using ([System.IO.StreamWriter]$Writer = New-Object -TypeName System.IO.StreamWriter([System.Console]::OpenStandardOutput())) {
                $Writer.AutoFlush = $true
                [System.Console]::SetOut($Writer)
                $Writer.Write("This is a test.")
            }

            The StreamWriter is automatically disposed of after the script block is executed. Future calls to $Writer would fail. Please notice
            that the open "{" bracket needs to be on the same line as the cmdlet.

        .INPUTS
            System.Management.Automation.ScriptBlock

        .OUTPUTS
            None

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 6/21/2017

    #>
	[Alias("using")]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [AllowNull()]
        [System.Object]$InputObject,
 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Management.Automation.ScriptBlock]$ScriptBlock
    )
    
    Begin {
    }
    
    Process 
    {       
        try
        {
            & $ScriptBlock
        }
        finally
        {
            if ($InputObject -ne $null -and $InputObject -is [System.IDisposable])
            {
                $InputObject.Dispose()
            }
        }
    }

    End {
    }
}

Function Invoke-WmiRepositoryRebuild {
	<#
        .SYNOPSIS
            Rebuilds the WMI repository.

        .DESCRIPTION
            The cmdlet rebuilds the WMI repository by calling mofcomp.exe on all non uninstall mof files in c:\system32\wbem
      
        .EXAMPLE
            Invoke-WmiRepositoryRebuild

			Rebuilds the WMI repository.

        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/21/2017
    #>
	[CmdletBinding()]
	Param()

	Begin {
	}

	Process {
		Get-ChildItem -Path "$env:SystemRoot\System32\wbem\*" -Include @("*.mof") -Exclude @("*uninstall*") | ForEach-Object {
			$Result = & $env:SystemRoot\System32\wbem\mofcomp.exe $_.FullName

			[System.String]$Message = ([System.String]::Join("`r`n", $Result))

			if ($Message -ilike "*An error occurred*") {
                Write-Error -Message $Message -Category FromStdErr -TargetObject $_.FullName
            }
			else {
				Write-Verbose -Message ([System.String]::Join("`r`n", $Result))
			}
		}
	}

	End {
	}
}

Function Merge-Hashtables {
	<#
		.SYNOPSIS 
			Merges two hashtables.

		.DESCRIPTION
			The cmdlet merges a second hashtable with a source one. The second hashtable will add or overwrite its values to a copy of the first. Neither of the two input hashtables are modified.

		.PARAMETER Source
			The source hashtable that will be added to or overwritten. The original hashtable is not modified.

		.PARAMETER Update
			The hashtable that will be merged into the source. This hashtable is not modified.

		.EXAMPLE
			Merge-Hashtables -Source @{"Key" = "Test"} -Data @{"Key" = "Test2"; "Key2" = "Test3"}

			This cmdlet results in a hashtable that looks like as follows: @{"Key" = "Test2"; "Key2" = "Test3"}

		.INPUTS
            None

        .OUTPUTS
            System.Collections.Hashtable

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/21/2017	
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Source,

		[Parameter(Mandatory = $true)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Update
	)

	Begin {
	}

	Process {
		# Make a copy of the source so it is not modified
		[System.Collections.Hashtable]$Output = $Source.Clone()

		# Check each key in the update to see if the output already has it
		foreach ($Key in $Update.Keys)
		{
			# If it does, update the value
			if ($Output.ContainsKey($Key))
			{
				$Output[$Key] = $Update[$Key]
			}
			else 
			{
				# If not, add the key/value
				$Output.Add($Key, $Update[$Key])
			}
		}

		Write-Output -InputObject $Output
	}

	End {
	}
}

Function ConvertTo-Hashtable {
	<#
		.SYNOPSIS 
			Converts a PSCustomObject to a Hashtable.

		.DESCRIPTION
			The cmdlet takes a PSCustomObject and converts all of its property key/values to a Hashtable. You can specify keys from the PSCustomObject to exclude or specify that empty values not be added to the Hashtable.

		.PARAMETER InputObject
			The PSCustomObject to convert.

		.PARAMETER Exclude
			The key values from the PSCustomObject not to include in the Hashtable.

		.PARAMETER NoEmpty
			Specify to not include keys with empty or null values from the PSCustomObject in the Hashtable.

		.EXAMPLE
			ConvertTo-Hashtable -InputObject ([PSCustomObject]@{"Name" = "Smith"})

			Converts the inputted PSCustomObject to a hashtable.

		.EXAMPLE 
			ConvertTo-Hashtable -InputObject ([PSCustomObject]@{"LastName" = "Smith", "Middle" = "", "FirstName" = "John"}) -NoEmpty -Exclude @("FirstName")

			Converts the inputted PSCustomObject to a hashtable. The empty property, Middle is excluded, and the property FirstName is excluded explicitly. This results
			in a hashtable @{"LastName" = "Smith"}

		.INPUTS
            System.Management.Automation.PSCustomObject

        .OUTPUTS
            System.Collections.Hashtable

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/21/2017	
	#>
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[PSCustomObject]$InputObject,

		[Parameter()]
		[System.String[]]$Exclude = @(),

		[Parameter()]
		[Switch]$NoEmpty
	)

	Begin {
	}
	
	Process {
		[System.Collections.Hashtable]$Result = @{}

		$InputObject | Get-Member -MemberType "*Property" | Select-Object -ExpandProperty Name | ForEach-Object {
			if ($Exclude -inotcontains $_) {
				if ($NoEmpty -and -not ($InputObject.$_ -eq $null -or $InputObject.$_ -eq ""))
				{
					Write-Verbose -Message "Property $_ has an empty/null value."
				}
				else 
				{
					$Result.Add($_, $InputObject.$_)
				}
			}
			else {
				Write-Verbose -Message "Property $_ excluded."
			}
		}

		Write-Output -InputObject $Result
	}

	End {
	}
}

Function Get-PropertyValue {
	<#
		.SYNOPSIS
			Attempts to get the value of a property on an object.

		.DESCRIPTION
			The cmdlet uses reflection to get the value of a property on the provided object. If the property does not exist, the cmdlet returns null.

		.PARAMETER InputObject
			The object instance to get the property value of.

		.PARAMETER Name
			The name of the object property or field to retrieve the value of.
		
		.EXAMPLE
			Get-PropertyValue -InputObject (New-Object -TypeName System.IO.FileInfo("c:\pagefile.sys")) -FieldName FullName

			This cmdlet returns the value "c:\pagefile.sys"

		.INPUTS
			System.Object

		.OUTPUTS
			System.Object
		
		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/22/2017

	#>
    [CmdletBinding()]
	[OutputType([System.Object])]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [System.Object]$InputObject,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.String]$Name
    )

    Begin {
        [System.Reflection.BindingFlags]$BindingFlags = @([System.Reflection.BindingFlags]::Instance, [System.Reflection.BindingFlags]::NonPublic, [System.Reflection.BindingFlags]::Public)
    }

    Process {
        if ($InputObject -eq $null -or [System.String]::IsNullOrEmpty($Name))
        {
            Write-Output -InputObject $null
        }

        [System.Reflection.PropertyInfo]$PropertyInfo = $InputObject.GetType().GetProperty($Name, $BindingFlags)
    
        if ($PropertyInfo -ne $null)
        {
            try {
				Write-Output -InputObject $PropertyInfo.GetValue($InputObject, $null)
            }
            catch [Exception] {
				Write-Verbose -Message $_.Exception.Message
                Write-Output -InputObject $null
            }
        }
		# Maybe the property is a field
        else
        {
            [System.Reflection.FieldInfo]$FieldInfo = $InputObject.GetType().GetField($Name, $BindingFlags)

            if ($FieldInfo -ne $null)
            {
                try {
                    Write-Output -InputObject $FieldInfo.GetValue($InputObject, $null)
                }
                catch [Exception] {
					Write-Verbose -Message $_.Exception.Message
                    Write-Output -InputObject $null
                }
            }
            else {
				# The name wasn't a property or field
                Write-Output -InputObject $null
            }
        }
    }

    End {
    }
}

Function Get-UnboundParameterValue {
	<#
		.SYNOPSIS
			Gets the value of an unbound dynamic parameter from an array of unbound parameters.

		.DESCRIPTION
			This cmdlet gets the value of a specified dynamic parameter name or positional parameter from the enumerated unbound dynamic parameters of a PowerShell cmdlet.

		.PARAMETER UnboundArgs
			The unbound arguments from a PowerShell cmdlet.

		.PARAMETER ParameterName
			The name of the parameter to get the value of.

		.PARAMETER Type
			The type of the parameter value.

		.PARAMETER Position 
			The position of the parameter to get the value of. Use this if the syntax 'New-Cmdlet -Parameter "Value"' was NOT used and instead 'New-Cmdlet "Value"' was used instead.

		.EXAMPLE
			DynamicParam {
				...
			
				[System.Reflection.BindingFlags]$BindingFlags = @([System.Reflection.BindingFlags]::Instance, [System.Reflection.BindingFlags]::NonPublic, [System.Reflection.BindingFlags]::Public)
				$Context = Get-PropertyValue -InputObject $PSCmdlet -Name "Context"
			
				# Can't use Get-PropertyValue fpr CurrentCommandProcessor because it returns itself as the current command processor
				$CurrentCommandProcessor = $Context.GetType().GetProperty("CurrentCommandProcessor", $BindingFlags).GetValue($Context)
				$ParameterBinder = Get-PropertyValue -InputObject $CurrentCommandProcessor -Name "CmdletParameterBinderController"
				$UnboundArgs = Get-PropertyValue -InputObject $ParameterBinder -Name "UnboundArguments"

				[System.String]$Target = (Get-UnboundParameterValue -UnboundArgs $UnboundArgs -ParameterName "Target" -Type ([System.String])) -as [System.String]

				...
			}

			This example enumerates the unbound arguments inside the dynamic parameter section of a PowerShell cmdlets. It supplies those arguments to the Get-UnboundParameterValue cmdlet looking
			for the value of the "Target" parameter. If the target parameter has been defined at the command line, the $Target variable will receive its value, otherwise null is returned.

		.INPUTS
			System.Object[]

		.OUTPUTS
			System.Object

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/23/2017
	#>
	[CmdletBinding()]
	[OutputType([System.Object])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[System.Object[]]$UnboundArgs,

		[Parameter(Mandatory = $true, ParameterSetName = "Name")]
        [System.String]$ParameterName,

        [Parameter(Mandatory = $true)]
        [System.Type]$Type,

        [Parameter(ParameterSetName = "Position", Mandatory = $true)]
        [System.Int32]$Position = -1
	)

	Begin {
	}

	Process {

		if ($UnboundArgs -ne $null)
        {
            [System.Boolean]$IsSwitch = [System.Management.Automation.SwitchParameter] -eq $Type

            [System.Int32]$i = 0

            foreach ($Item in $UnboundArgs | Where-Object {$_ -ne $null})
            {
				# Is the unbound argument associated with a parameter name
                $IsParameterName = Get-PropertyValue $Item -Name "ParameterNameSpecified"

				# The parameter name for the argument was specified
                if ($IsParameterName -ne $null -and $true.Equals($IsParameterName))
                {
                    [System.String]$CurrentParameterName = Get-PropertyValue $Item -Name "ParameterName"

					# If it's a switch parameter that was requested, there won't be a value following it, so just return a present switch
                    if ($IsSwitch -and [System.String]::Equals($CurrentParameterName, $ParameterName, [System.StringComparison]::OrdinalIgnoreCase))
                    {
						# Use return to stop execution
                        return (New-Object -TypeName System.Management.Automation.SwitchParameter($true))
                    }

					# Since we have a current parameter name, the next value in UnboundArgs should be the value supplied to the argument
					# so continue will start the next iteration in the foreach and skip the below code
                    continue
                }
                
				# We assume the previous iteration identified a parameter name, so this must be its value
                $ParamValue = Get-PropertyValue $Item -Name "ArgumentValue"

				if ($Type -eq [System.String])
				{
					$ParamValue = $ParamValue.Trim("`"").Trim("'")
				}

				# If the value we have grabbed had a parameter name specified, 
				# let's check to see if it's the desired parameter
                if (-not [System.String]::IsNullOrEmpty($CurrentParameterName))
                {
					# If the parameter name currently being assessed is equal to the provided param name, then return the value of the param
                    if ($CurrentParameterName.Equals($ParameterName, [System.StringComparison]::OrdinalIgnoreCase))
                    {
                        return $ParamValue 
                    }
                    else
                    {
						# Since this wasn't the parameter name we were looking for, clear it out
                        $CurrentParameterName = [System.String]::Empty
                    }
                }
				# Otherwise there wasn't a parameter name, so the argument must have been supplied positionally,
				# check if the current index is the position whose value we want.
				# Since positional parameters have to be specified frst, this will be evaluated and increment until
				# we run out of parameters or find a parameter with a name/value
                elseif ($i++ -eq $Position) {
                    return $ParamValue
                }
            }
        }
        else
        {
            return $null
        }
	}

	End {
	}
}

Function Import-UnboundParameterCode {
	<#
		.SYNOPSIS
			Imports the .NET code to inspect unbound dynamic parameters in a PowerShell cmdlet DynamicParam section.

		.DESCRIPTION
			The cmdlet performs and Add-Type to import the code. It can also pass through the type you need to then invoke the unbound parameter checking.

		.PARAMETER PassThru
			Passes the static type to the pipeline.

		.EXAMPLE
			DynamicParam {
			...

				$Type = Import-UnboundParameterCode -PassThru
				$Type.GetMethod("GetUnboundParameterValue").MakeGenericMethod([System.String]).Invoke($Type, @($PSCmdlet, "Target", -1))

			...
			}
			
			This example imports the .NET code inside the DyanmicParam section of a PowerShell cmdlet. Then it uses the passed static class to call the 
			generic GetUnboundParameterValue method looking for the "Target" parameter. That parameter is a dynamic parameter added earlier in the DynamicParam section.

		.INPUTS
			None

		.OUTPUTS
			None or System.Type

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/23/2017
			
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[Switch]$PassThru
	)

	Begin {
	}

	Process {
		if (-not ([System.Management.Automation.PSTypeName]"BAMCIS.ExtensionMethods").Type) {
            Add-Type -TypeDefinition $script:UnboundExtensionMethod
			Write-Verbose -Message "Type successfully added."
        }
		else {
			Write-Verbose -Message "Type already added."
		}

		if ($PassThru) {
			Write-Output -InputObject ([BAMCIS.ExtensionMethods])
		}
	}

	End {
	}
}

Function New-DynamicParameter {
	<#
		.SYNOPSIS
			Expedites creating PowerShell cmdlet dynamic parameters.

		.DESCRIPTION
			This cmdlet facilitates the easy creation of dynamic parameters.

		.PARAMETER Name
			The name of the parameter.

		.PARAMETER Type
			The type of the parameter, this defaults to System.String.

		.PARAMETER Mandatory
			Indicates whether the parameter is required when the cmdlet or function is run.

		.PARAMETER ParameterSets
			The name of the parameter sets to which this parameter belongs. This defaults to __AllParameterSets.

		.PARAMETER Position
			The position of the parameter in the command-line string.

		.PARAMETER ValueFromPipeline
			Indicates whether the parameter can take values from incoming pipeline objects.

		.PARAMETER ValueFromPipelineByPropertyName
			Indicates that the parameter can take values from a property of the incoming pipeline object that has the same name as this parameter. For example, if the name of the cmdlet or function parameter is userName, the parameter can take values from the userName property of incoming objects.

		.PARAMETER ValueFromRemainingArguments
			Indicates whether the cmdlet parameter accepts all the remaining command-line arguments that are associated with this parameter.

		.PARAMETER HelpMessage
			A short description of the parameter.

		.PARAMETER DontShow
			Indicates that this parameter should not be shown to the user in this like intellisense. This is primarily to be used in functions that are implementing the logic for dynamic keywords.

		.PARAMETER Alias
			Declares a alternative namea for the parameter.

		.PARAMETER ValidateNotNull
			Validates that the argument of an optional parameter is not null.

		.PARAMETER ValidateNotNullOrEmpty
			Validates that the argument of an optional parameter is not null, an empty string, or an empty collection.

		.PARAMETER AllowEmptyString

		.PARAMETER AllowNull

		.PARAMETER AllowEmptyCollection

		.PARAMETER ValidateScript
			Defines an attribute that uses a script to validate a parameter of any Windows PowerShell function.

		.PARAMETER ValidateSet
			Defines an attribute that uses a set of values to validate a cmdlet parameter argument.

		.PARAMETER ValidateRange
			Defines an attribute that uses minimum and maximum values to validate a cmdlet parameter argument.

		.PARAMETER ValidateCount
			Defines an attribute that uses maximum and minimum limits to validate the number of arguments that a cmdlet parameter accepts.

		.PARAMETER ValidateLength
			Defines an attribute that uses minimum and maximum limits to validate the number of characters in a cmdlet parameter argument.

		.PARAMETER ValidatePattern
			Defines an attribute that uses a regular expression to validate the character pattern of a cmdlet parameter argument.

		.PARAMETER RuntimeParameterDictionary
			The dictionary to add the new parameter to. If one is not provided, a new dictionary is created and returned to the pipeline.
		
		.EXAMPLE
			DynamicParam {
				...

				$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

				New-DynamicParameter -Name "Numbers" -ValidateSet @(1, 2, 3) -Type [System.Int32] -Mandatory -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

				...

				return $RuntimeParameterDictionary

			}

			A new parameter named "Numbers" is added to the cmdlet. The parameter is mandatory and must be 1, 2, or 3. The dictionary sent in is modified and does not need to be received. 

		.EXAMPLE
			DynamicParam {
				...

				$Params = @(
					@{
						"Name" = "Numbers";
						"ValidateSet" = @(1, 2, 3);
						"Type" = [System.Int32]
					},
					@{
						"Name" = "FirstName";
						"Type" = [System.String];
						"Mandatory" = $true;
						"ParameterSets" = @("Names")
					}
				)

				$Params | ForEach-Object {
					New-Object PSObject -Property $_ 
				} | New-DynamicParameter
			}

			The example creates an array of two hashtables. These hashtables are converted into PSObjects so they can match the parameters by property name, then new dynamic parameters are created. All of the 
			parameters are fed to New-DynamicParameter which returns a single new RuntimeParameterDictionary to the pipeline, which is returned from the DynamicParam section.

		.INPUTS
			System.Management.Automation.PSObject

		.OUTPUTS
			System.Management.Automation.RuntimeDefinedParameterDictionary

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/23/2017	
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Name,

		# These parameters are part of the standard ParameterAttribute

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNull()]
		[System.Type]$Type = [System.String],

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Switch]$Mandatory,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateCount(1, [System.Int32]::MaxValue)]
		[System.String[]]$ParameterSets = @("__AllParameterSets"),

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[System.Int32]$Position = [System.Int32]::MinValue,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Switch]$ValueFromPipeline,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Switch]$ValueFromPipelineByPropertyName,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Switch]$ValueFromRemainingArguments,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$HelpMessage,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Switch]$DontShow,

		# These parameters are each their own attribute

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[System.String[]]$Alias = @(),

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Switch]$ValidateNotNull,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Switch]$ValidateNotNullOrEmpty,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Switch]$AllowEmptyString,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Switch]$AllowNull,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Switch]$AllowEmptyCollection,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.ScriptBlock]$ValidateScript,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String[]]$ValidateSet = @(),

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidateCount(2,2)]
		[System.Int32[]]$ValidateRange = $null,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidateCount(2,2)]
		[System.Int32[]]$ValidateCount = $null,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidateCount(2,2)]
		[System.Int32[]]$ValidateLength = $null,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ValidatePattern = $null,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNull()]
		[System.Management.Automation.RuntimeDefinedParameterDictionary]$RuntimeParameterDictionary = $null
	)

	Begin {
		if ($RuntimeParameterDictionary -eq $null) {
			$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
		}
	}

	Process {
		
		# Create the collection of attributes
		$AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

		if ($ParameterSets.Length -le 0)
		{
			$ParameterSets += "__AllParameterSets"
		}
			
		foreach ($Set in $ParameterSets)
		{
			# Create and set the parameter's attributes
			$ParameterAttribute = New-Object -TypeName System.Management.Automation.PARAMETERAttribute

			$ParameterAttribute.ParameterSetName = $Set

			if ($Position -ne $null)
			{
				$ParameterAttribute.Position = $Position
			}

			if ($Mandatory)
			{
				$ParameterAttribute.Mandatory = $true
			}

			if ($ValueFromPipeline)
			{
				$ParameterAttribute.ValueFromPipeline = $true
			}

			if ($ValueFromPipelineByPropertyName)
			{
				$ParameterAttribute.ValueFromPipelineByPropertyName = $true
			}

			if ($ValueFromRemainingArguments)
			{
				$ParameterAttribute.ValueFromRemainingArguments = $true
			}

			if (-not [System.String]::IsNullOrEmpty($HelpMessage))
			{
				$ParameterAttribute.HelpMessage = $HelpMessage
			}

			if ($DontShow)
			{
				$ParameterAttribute.DontShow = $true
			}

			$AttributeCollection.Add($ParameterAttribute)
		}

		if ($Alias.Length -gt 0)
		{
			$AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute($Alias)
			$AttributeCollection.Add($AliasAttribute)
		}

		if ($ValidateSet.Length -gt 0)
		{
			$ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($ValidateSet)
			$AttributeCollection.Add($ValidateSetAttribute)
		}

		if ($ValidateScript -ne $null) 
		{
			$ValidateScriptAttribute = New-Object -TypeName System.Management.Automation.ValidateScriptAttribute($ValidateScript)
			$AttributeCollection.Add($ValidateScriptAttribute)
		}

		if ($ValidateCount -ne $null -and $ValidateCount.Length -eq 2)
		{
			$ValidateCountAttribute = New-Object -TypeName System.Management.Automation.ValidateCountAttribute($ValidateCount[0], $ValidateCount[1])
			$AttributeCollection.Add($ValidateCountAttribute)
		}

		if ($ValidateLength -ne $null -and $ValidateLength -eq 2)
		{
			$ValidateLengthAttribute = New-Object -TypeName System.Management.Automation.ValidateLengthAttribute($ValidateLength[0], $ValidateLength[1])
			$AttributeCollection.Add($ValidateLengthAttribute)
		}

		if (-not [System.String]::IsNullOrEmpty($ValidatePattern))
		{
			$ValidatePatternAttribute = New-Object -TypeName System.Management.Automation.ValidatePatternAttribute($ValidatePattern)
			$AttributeCollection.Add($ValidatePatternAttribute)
		}

		if ($ValidateRange -ne $null -and $ValidateRange.Length -eq 2)
		{
			$ValidateRangeAttribute = New-Object -TypeName System.Management.Automation.ValidateRangeAttribute($ValidateRange)
			$AttributeCollection.Add($ValidateRangeAttribute)
		}

		if ($NotNull)
		{
			$NotNullAttribute = New-Object -TypeName System.Management.Automation.NotNullAttribute
			$AttributeCollection.Add($NotNullAttribute)
		}

		if ($NotNullOrEmpty)
		{
			$NotNullOrEmptyAttribute = New-Object -TypeName System.Management.Automation.NotNullOrEmptyAttribute
			$AttributeCollection.Add($NotNullOrEmptyAttribute)
		}

		if ($AllowEmptyString)
		{
			$AllowEmptyStringAttribute = New-Object -TypeName System.Management.Automation.AllowEmptyStringAttribute
			$AttributeCollection.Add($AllowEmptyStringAttribute)
		}

		if ($AllowEmptyCollection)
		{
			$AllowEmptyCollectionAttribute = New-Object -TypeName System.Management.Automation.AllowEmptyCollectionAttribute
			$AttributeCollection.Add($AllowEmptyCollectionAttribute)
		}

		if (-not $RuntimeParameterDictionary.ContainsKey($Name))
		{
			$RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($Name, $Type, $AttributeCollection)
			$RuntimeParameterDictionary.Add($Name, $RuntimeParameter)
		}
		else
		{
			foreach ($Attr in $AttributeCollection.GetEnumerator())
            {
                if (-not $RuntimeParameterDictionary.$Name.Attributes.Contains($Attr))
                {
                    $RuntimeParameterDictionary.$Name.Attributes.Add($Attr)
                }
            }
		}

		
	}

	End {
		Write-Output -InputObject $RuntimeParameterDictionary
	}
}

$script:IPv6Configs = @(
	[PSCustomObject]@{Name="IPv6 Disabled On All Interfaces";Value="0xFFFFFFFF"},
	[PSCustomObject]@{Name="IPv6 Enabled only on tunnel interfaces";Value="0xFFFFFFFE"}, 
	[PSCustomObject]@{Name="IPv6 Disabled On Tunnel Interfaces, Enabled On All Others";Value="0xFFFFFFEF"},
	[PSCustomObject]@{Name="IPv6 Disabled On Loopback Interface, Enabled On All Others";Value="0xFFFFFFEE"},
	[PSCustomObject]@{Name="IPv6 Disabled, Prefer IPv6 over IPv4";Value="0xFFFFFFDF"},
	[PSCustomObject]@{Name="IPv6 Enabled Only On Tunnel Interfaces, Prefer IPv6 of IPv4";Value="0xFFFFFFDE"},
	[PSCustomObject]@{Name="IPv6 Enabled On All Non Tunnel Interfaces, Prefer IPv6 over IPv4";Value="0xFFFFFFCF"},
	[PSCustomObject]@{Name="IPv6 Disabled On Loopback Interface, Prefer IPv6 over IPv4";Value="0xFFFFFFCE"},
	[PSCustomObject]@{Name="IPv6 Disabled On All Interfaces";Value="0x000000FF"},
	[PSCustomObject]@{Name="IPv6 Prefer IPv4 over IPv6 by changing entries in prefix policy table";Value="0x00000020"},
	[PSCustomObject]@{Name="IPv6 Disabled on LAN and PPP interfaces ";Value="0x00000010"},
	[PSCustomObject]@{Name="Disable Teredo";Value="0x00000008"},
	[PSCustomObject]@{Name="Disable ISATAP";Value="0x00000004"},
	[PSCustomObject]@{Name="Disable 6to4";Value="0x00000002"},
	[PSCustomObject]@{Name="IPv6 Disabled on Tunnel Interfaces including ISATAP, 6to4 and Teredo";Value="0x00000001"}
)

$script:Ports = @(
	[PSCustomObject]@{"Service"="FTP Data";"Port"=20},
	[PSCustomObject]@{"Service"="FTP Command";"Port"=21},
	[PSCustomObject]@{"Service"="SSH";"Port"=22},
	[PSCustomObject]@{"Service"="TelNet";"Port"=23},
	[PSCustomObject]@{"Service"="SMTP";"Port"=25},
	[PSCustomObject]@{"Service"="WINS";"Port"=42},
	[PSCustomObject]@{"Service"="DNS";"Port"=53},
	[PSCustomObject]@{"Service"="DHCP Server";"Port"=67},
	[PSCustomObject]@{"Service"="DHCP Client";"Port"=68},
	[PSCustomObject]@{"Service"="TFTP";"Port"=69},
	[PSCustomObject]@{"Service"="HTTP";"Port"=80},
	[PSCustomObject]@{"Service"="Kerberos";"Port"=88},
	[PSCustomObject]@{"Service"="POP3";"Port"=110},
	[PSCustomObject]@{"Service"="SFTP";"Port"=115},
	[PSCustomObject]@{"Service"="NetBIOS Name Service";"Port"=137},
	[PSCustomObject]@{"Service"="NetBIOS Datagram Service";"Port"=138},
	[PSCustomObject]@{"Service"="NetBIOS Session Service";"Port"=139},
	[PSCustomObject]@{"Service"="SNMP";"Port"=161},
	[PSCustomObject]@{"Service"="LDAP";"Port"=389},
	[PSCustomObject]@{"Service"="SSL";"Port"=443},
	[PSCustomObject]@{"Service"="SMB";"Port"=445},
	[PSCustomObject]@{"Service"="Syslog";"Port"=514},
	[PSCustomObject]@{"Service"="RPC";"Port"=135},
	[PSCustomObject]@{"Service"="LDAPS";"Port"=636},
	[PSCustomObject]@{"Service"="SOCKS";"Port"=1080},
	[PSCustomObject]@{"Service"="MSSQL";"Port"=1433},
	[PSCustomObject]@{"Service"="SQL Browser";"Port"=1434},
	[PSCustomObject]@{"Service"="Oracle DB";"Port"=1521},
	[PSCustomObject]@{"Service"="NFS";"Port"=2049},
	[PSCustomObject]@{"Service"="RDP";"Port"=3389},
	[PSCustomObject]@{"Service"="XMPP";"Port"=5222},
	[PSCustomObject]@{"Service"="HTTP Proxy";"Port"=8080},
	[PSCustomObject]@{"Service"="Global Catalog";"Port"=3268},
	[PSCustomObject]@{"Service"="Global Catalog/SSL";"Port"=3269},
	[PSCustomObject]@{"Service"="POP3/SSL";"Port"=995},
	[PSCustomObject]@{"Service"="IMAP/SSL";"Port"=993},
	[PSCustomObject]@{"Service"="IMAP";"Port"=143}
)

$script:TokenSignature = @"
public enum SECURITY_IMPERSONATION_LEVEL
{
    SecurityAnonymous = 0,
    SecurityIdentification = 1,
    SecurityImpersonation = 2,
    SecurityDelegation = 3
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct TokPriv1Luid
{
	public int Count;
	public long Luid;
	public int Attr;
}

public const int SE_PRIVILEGE_ENABLED = 0x00000002;
public const int TOKEN_QUERY = 0x00000008;
public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;

public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
public const UInt32 TOKEN_DUPLICATE = 0x0002;
public const UInt32 TOKEN_IMPERSONATE = 0x0004;
public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
	TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
    TOKEN_ADJUST_SESSIONID);

public const string SE_TIME_ZONE_NAMETEXT = "SeTimeZonePrivilege";
public const int ANYSIZE_ARRAY = 1;

[StructLayout(LayoutKind.Sequential)]
public struct LUID
{
	public UInt32 LowPart;
	public UInt32 HighPart;
}

[StructLayout(LayoutKind.Sequential)]
public struct LUID_AND_ATTRIBUTES {
	public LUID Luid;
	public UInt32 Attributes;
}

public struct TOKEN_PRIVILEGES {
	public UInt32 PrivilegeCount;
	[MarshalAs(UnmanagedType.ByValArray, SizeConst=ANYSIZE_ARRAY)]
	public LUID_AND_ATTRIBUTES [] Privileges;
}

[DllImport("advapi32.dll", SetLastError=true)]
public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool SetThreadToken(
	IntPtr PHThread,
	IntPtr Token
);

[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

[DllImport("kernel32.dll", ExactSpelling = true)]
public static extern IntPtr GetCurrentProcess();

[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

[DllImport( "kernel32.dll", CharSet = CharSet.Auto )]
public static extern bool CloseHandle( IntPtr handle );

[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool RevertToSelf();
"@

$script:LsaSignature = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace Bamcis.Lsa
{
    public class LSAUtil
    {

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        private enum LSA_AccessPolicy : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaRetrievePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            out IntPtr PrivateData
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaStorePrivateData(
             IntPtr policyHandle,
             ref LSA_UNICODE_STRING KeyName,
             ref LSA_UNICODE_STRING PrivateData
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaNtStatusToWinError(
            uint status
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaClose(
            IntPtr policyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaFreeMemory(
            IntPtr buffer
        );

        private LSA_OBJECT_ATTRIBUTES ObjectAttributes;
        private LSA_UNICODE_STRING LocalSystem;
        private LSA_UNICODE_STRING SecretName;

        public LSAUtil(string Key)
        {
            if (Key.Length == 0)
            {
                throw new ArgumentException("Key length zero");
            }

            this.ObjectAttributes = new LSA_OBJECT_ATTRIBUTES();
            this.ObjectAttributes.Length = 0;
            this.ObjectAttributes.RootDirectory = IntPtr.Zero;
            this.ObjectAttributes.Attributes = 0;
            this.ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            this.ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;

            this.LocalSystem = new LSA_UNICODE_STRING();
            this.LocalSystem.Buffer = IntPtr.Zero;
            this.LocalSystem.Length = 0;
            this.LocalSystem.MaximumLength = 0;

            this.SecretName = new LSA_UNICODE_STRING();
            this.SecretName.Buffer = Marshal.StringToHGlobalUni(Key);
            this.SecretName.Length = (UInt16)(Key.Length * UnicodeEncoding.CharSize);
            this.SecretName.MaximumLength = (UInt16)((Key.Length + 1) * UnicodeEncoding.CharSize);
        }

        private IntPtr GetLsaPolicy(LSA_AccessPolicy Access)
        {
            IntPtr LsaPolicyHandle;

            uint NtsResult = LsaOpenPolicy(ref this.LocalSystem, ref this.ObjectAttributes, (uint)Access, out LsaPolicyHandle);

            uint WinErrorCode = LsaNtStatusToWinError(NtsResult);
            if (WinErrorCode != 0)
            {
                throw new Win32Exception(Convert.ToInt32(WinErrorCode));
            }

            return LsaPolicyHandle;
        }

        private static void ReleaseLsaPolicy(IntPtr LsaPolicyHandle)
        {
            uint NtsResult = LsaClose(LsaPolicyHandle);
            uint WinErrorCode = LsaNtStatusToWinError(NtsResult);

            if (WinErrorCode != 0)
            {
                throw new Win32Exception(Convert.ToInt32(WinErrorCode));
            }
        }

        private static void FreeMemory(IntPtr Buffer)
        {
            uint NtsResult = LsaFreeMemory(Buffer);
            uint WinErrorCode = LsaNtStatusToWinError(NtsResult);
            if (WinErrorCode != 0)
            {
                throw new Win32Exception(Convert.ToInt32(WinErrorCode));
            }
        }

        public void SetSecret(string Value)
        {
            LSA_UNICODE_STRING LusSecretData = new LSA_UNICODE_STRING();

            if (Value.Length > 0)
            {
                //Create data and key
                LusSecretData.Buffer = Marshal.StringToHGlobalUni(Value);
                LusSecretData.Length = (UInt16)(Value.Length * UnicodeEncoding.CharSize);
                LusSecretData.MaximumLength = (UInt16)((Value.Length + 1) * UnicodeEncoding.CharSize);
            }
            else
            {
                //Delete data and key
                LusSecretData.Buffer = IntPtr.Zero;
                LusSecretData.Length = 0;
                LusSecretData.MaximumLength = 0;
            }

            IntPtr LsaPolicyHandle = GetLsaPolicy(LSA_AccessPolicy.POLICY_CREATE_SECRET);
            uint Result = LsaStorePrivateData(LsaPolicyHandle, ref this.SecretName, ref LusSecretData);
            LSAUtil.ReleaseLsaPolicy(LsaPolicyHandle);

            uint WinErrorCode = LsaNtStatusToWinError(Result);
            if (WinErrorCode != 0)
            {
                throw new Win32Exception(Convert.ToInt32(WinErrorCode));
            }
        }

        public string GetSecret()
        {
            IntPtr PrivateData = IntPtr.Zero;

            IntPtr LsaPolicyHandle = GetLsaPolicy(LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION);
            uint NtsResult = LsaRetrievePrivateData(LsaPolicyHandle, ref this.SecretName, out PrivateData);
            LSAUtil.ReleaseLsaPolicy(LsaPolicyHandle);

            uint WinErrorCode = LsaNtStatusToWinError(NtsResult);

            if (WinErrorCode != 0)
            {
                throw new Win32Exception(Convert.ToInt32(WinErrorCode));
            }

            LSA_UNICODE_STRING LusSecretData = (LSA_UNICODE_STRING)Marshal.PtrToStructure(PrivateData, typeof(LSA_UNICODE_STRING));
            string Value = Marshal.PtrToStringAuto(LusSecretData.Buffer).Substring(0, LusSecretData.Length / 2);

            LSAUtil.FreeMemory(PrivateData);

            return Value;
        }
    }
}
"@

$script:UnboundExtensionMethod = @"
using System;
using System.Collections;
using System.Management.Automation;
using System.Reflection;

namespace BAMCIS
{
    public static class ExtensionMethods 
    {
        private static readonly BindingFlags Flags = BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public;

        public static T GetUnboundParameterValue<T>(this PSCmdlet cmdlet, string paramName, int unnamedPosition = -1)
        {
            if (cmdlet != null)
            {
                // If paramName isn't found, value at unnamedPosition will be returned instead
                object Context = GetPropertyValue(cmdlet, "Context");
                object Processor = GetPropertyValue(Context, "CurrentCommandProcessor");
                object ParameterBinder = GetPropertyValue(Processor, "CmdletParameterBinderController");
                IEnumerable Args = GetPropertyValue(ParameterBinder, "UnboundArguments") as System.Collections.IEnumerable;

                if (Args != null)
                {
                    bool IsSwitch = typeof(SwitchParameter) == typeof(T);
                    string CurrentParameterName = String.Empty;
                    int i = 0;

                    foreach (object Arg in Args)
                    {

                        //Is the unbound argument associated with a parameter name
                        object IsParameterName = GetPropertyValue(Arg, "ParameterNameSpecified");

                        //The parameter name for the argument was specified
                        if (IsParameterName != null && true.Equals(IsParameterName))
                        {
                            string ParameterName = GetPropertyValue(Arg, "ParameterName") as string;
                            CurrentParameterName = ParameterName;

                            //If it's a switch parameter, there won't be a value following it, so just return a present switch
                            if (IsSwitch && String.Equals(CurrentParameterName, paramName, StringComparison.OrdinalIgnoreCase))
                            {
                                return (T)(object)new SwitchParameter(true);
                            }

                            //Since we have a current parameter name, the next value in Args should be the value supplied
                            //to the argument, so we can head on to the next iteration, this skips the remaining code below
                            //and starts the next item in the foreach loop
                            continue;
                        }

                        //We assume the previous iteration identified a parameter name, so this must be its
                        //value
                        object ParameterValue = GetPropertyValue(Arg, "ArgumentValue");

                        //If the value we have grabbed had a parameter name specified,
                        //let's check to see if it's the desired parameter
                        if (CurrentParameterName != String.Empty)
                        {
                            //If the parameter name currently being assessed is equal to the provided param
                            //name, then return the value of the param
                            if (CurrentParameterName.Equals(paramName, StringComparison.OrdinalIgnoreCase))
                            {
                                return ConvertParameter<T>(ParameterValue);
                            }
                            else
                            {
                                //Since this wasn't the parameter name we were looking for, clear it out
                                CurrentParameterName = String.Empty;
                            }
                        }
                        //Otherwise there wasn't a parameter name, so the argument must have been supplied positionally,
                        //check if the current index is the position whose value we want
                        //Since positional parameters have to be specified first, this will be evaluated and increment until
                        //we run out of parameters or find a parameter with a name/value
                        else if (i++ == unnamedPosition)
                        {
                            //Just return the parameter value if the position matches what was specified
                            return ConvertParameter<T>(ParameterValue);
                        }
                    }
                }

                return default(T);
            }
            else
            {
                throw new ArgumentNullException("cmdlet", "The PSCmdlet cannot be null.");
            }
        }

        private static object GetPropertyValue(object instance, string fieldName)
        {
            // any access of a null object returns null. 
            if (instance == null || String.IsNullOrEmpty(fieldName))
            {
                return null;
            }

            try
            {
                PropertyInfo PropInfo = instance.GetType().GetProperty(fieldName, Flags);
            
                if (PropInfo != null)
                {
                    try
                    {
                        return PropInfo.GetValue(instance, null);
                    }
                    catch (Exception) { }
                }

                // maybe it's a field
                FieldInfo FInfo = instance.GetType().GetField(fieldName, Flags);

                if (FInfo != null)
                {
                    try
                    {
                        return FInfo.GetValue(instance);
                    }
                    catch { }
                }
            }
            catch (Exception) { }

            // no match, return null.
            return null;
        }
    
        private static T ConvertParameter<T>(this object value)
        {
            if (value == null || object.Equals(value, default(T)))
            {
                return default(T);
            }

            PSObject PSObj = value as PSObject;

            if (PSObj != null)
            {
                return PSObj.BaseObject.ConvertParameter<T>();
            }

            if (value is T)
            {
                if (typeof(T) == typeof(string))
                {
                    //Remove quotes from string values taken from the command line
                    // value = value.ToString().Trim('"').Trim('\'');
                }
                return (T)value;
            }

            var constructorInfo = typeof(T).GetConstructor(new[] { value.GetType() });

            if (constructorInfo != null)
            {
                return (T)constructorInfo.Invoke(new[] { value });
            }

            try
            {
                return (T)Convert.ChangeType(value, typeof(T));
            }
            catch (Exception)
            {
                return default(T);
            }
        }    
    }
}
"@