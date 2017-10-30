$script:LocalNames = @(".", "localhost", "127.0.0.1", "", $env:COMPUTERNAME)

#region Token Manipulation

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
	[OutputType([System.Management.Automation.PSObject])]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(Position = 0, Mandatory = $true)]
		[ValidateNotNull()]
		[System.Management.Automation.ScriptBlock]$ScriptBlock,

		[Parameter(Position = 1)]
		[ValidateSet("INTERACTIVE","NETWORK","NETWORK_CLEARTEXT","NEW_CREDENTIALS","SERVICE","BATCH","UNLOCK")]
		[System.String]$LogonType = "INTERACTIVE"
	)

	Begin {}

	Process
	{
	
		$Job = Start-Job -ArgumentList @($Credential, $ScriptBlock) -ScriptBlock {
			Add-Type -AssemblyName System.ComponentModel

			[System.Management.Automation.PSCredential]$Credential = $args[0]
			[System.Management.Automation.ScriptBlock]$ScriptBlock = [System.Management.Automation.ScriptBlock]::Create($args[1])

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
					Write-Log -Message "LogonUser was unsuccessful. Error code: $ReturnValue - $Message" -Level WARNING
					return
				}

				$NewIdentity = New-Object System.Security.Principal.WindowsIdentity($TokenHandle)

				$IdentityName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
				Write-Log -Mesage "Current Identity: $IdentityName" -Level VERBOSE
    
				$Context = $NewIdentity.Impersonate()

				$IdentityName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
				Write-Log -Message "Impersonating: $IdentityName" -Level VERBOSE

				Write-Log -Message "Executing custom script" -Level VERBOSE
				$Result = & $ScriptBlock
				Write-Output -InputObject $Result
			}
			catch [System.Exception]
			{
				Write-Log -ErrorRecord $_ -Level WARNING
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

	End {		
	}
}

#endregion


#region Logging

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
	[OutputType()]
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
	[OutputType()]
	Param(
		[Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias("DirectoryPath","LogDirectory")]
		[System.String]$Path = "$PSScriptRoot\Logs"
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

		Write-Log -Message "Kerberos trace log started. Stdout logged to $OutputPath and logs written to $Path."
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
	[OutputType()]
	Param(
		[Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$Path = "$PSScriptRoot\Logs"
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
				Write-Log -ErrorRecord $_ -Level WARNING
			}
		}
		
		if (Test-Path -Path "$env:SYSTEMROOT\system32\lsass.log") {
			try {
				Copy-Item -Path "$env:SYSTEMROOT\system32\lsass.log" -Destination $Path -Force | Out-Null
			}
			catch [Exception] {
				Write-Log -ErrorRecord $_ -Level WARNING
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
			Write-Log -Message "Possible error creating zip file at $FileName, the zip file may still have been created." -ErrorRecord $_ -Level WARNING
		}

		Write-Log -Message "Kerberos trace logs collected at $Path. Please share these for analysis."
	}

	End {		
	}
}

#endregion


#region Security / Forensics

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
	[OutputType([System.Boolean])]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Encrypted")]
		[ValidateNotNullOrEmpty()]
		[System.String]$EncryptedPassword,

		[Parameter(Mandatory = $true, ParameterSetName = "Secure")]
		[ValidateNotNull()]
		[System.Security.SecureString]$Password,

		[Parameter(Mandatory = $true, ParameterSetName = "Encrypted")]
		[Parameter(Mandatory = $true, ParameterSetName = "Secure")]
		[ValidateNotNullOrEmpty()]
		[System.String]$UserName,

		[Parameter(Mandatory = $true, ParameterSetName = "Credential")]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
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
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[System.Boolean]$Enabled
	)
    
	Begin {		
	}

	Process {
		Write-Log -Message "Setting User Account Control to Enabled = $Enabled." -Level VERBOSE
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value ([Int32]$Enabled) -ErrorAction SilentlyContinue | Out-Null
	}

	End {
	}
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
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true)]
		[System.Boolean]$Enabled
	)

	Begin {
	}

	Process {
        Write-Log "Setting IE Enhanced Security Configuration to Enabled = $Enabled." -Level VERBOSE

        $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
        $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"

        Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value ([System.Int32]$Enabled)
        Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value ([System.Int32]$Enabled)
	}

	End {
	}
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
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Enable")]
		[Switch]$Enable,

		[Parameter(Mandatory = $true, ParameterSetName = "Disable")]
		[Switch]$Disable	
	)

	Begin {
	}

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
			AUTHOR: Michael Haken
			LAST UPDATE: 10/25/2017
	#>
    [CmdletBinding()]
	[OutputType([System.String], [System.Security.SecureString])]
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
		[ValidateRange(1, [System.Int32]::MaxValue)]
        [System.Int32]$Length=14,

        [Parameter(Position = 1)]
		[ValidateNotNull()]
        $SourceData = $null,

        [Parameter()]
        [Switch]$EnforceComplexity,

		[Parameter()]
		[Switch]$AsSecureString
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
			AUTHOR: Michael Haken
			LAST UPDATE: 10/25/2017
	#>
    [CmdletBinding(DefaultParameterSetName = "SecureString")]
	[OutputType([System.String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true, ParameterSetName = "PlainText")]
		[ValidateNotNullOrEmpty()]
        [System.String]$Password,

        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true, ParameterSetName = "SecureString")]
		[ValidateNotNull()]
        [System.Security.SecureString]$SecurePassword
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
			AUTHOR: Michael Haken
			LAST UPDATE: 10/25/2017
	#>
	[CmdletBinding()]
	[OutputType([System.Security.SecureString])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
		[ValidateScript({
			Test-Path -Path $_
		})]
        [System.String]$FilePath
    )

    Begin {        
    }

    Process {
        [System.Security.SecureString]$Password = Get-Content -Path $FilePath | ConvertTo-SecureString

		Write-Output -InputObject $Password
    }

    End {       
    }
}

Function New-Credential {
	<#
		.SYNOPSIS
			Creates an new PSCredential object.

		.DESCRIPTION
			The cmdlet takes a username and password and creates a credential object. If no password is supplied, the user is prompted to enter a password.

		.PARAMETER UserName
			The username for the credential.

		.PARAMETER Password
			The plain text password for the credential.

		.PARAMETER SecurePassword
			The password as a SecureString.

		.EXAMPLE
			New-Credential -UserName "contoso\john.smith" -Password "@$3scureP@$$w0rd"

			This creates a new PSCredential object with the supplied parameters.

		.EXAMPLE
			New-Credential -UserName "contoso\john.smith"

			This example will prompt the user to enter a password at the command line and creates a new PSCredential object.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSCredential

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/25/2017
	#>
	[CmdletBinding(DefaultParameterSetName = "Secure")]
	[OutputType([System.Management.Automation.PSCredential])]
	Param(
		[Parameter(Mandatory = $true, Position = 0)]
		[ValidateNotNullOrEmpty()]
		[System.String]$UserName,

		[Parameter(Mandatory = $true, ParameterSetName = "Plain", Position = 1)]
		[ValidateNotNull()]
		[System.String]$Password,

		[Parameter(Mandatory = $true, ParameterSetName = "Secure", Position = 1)]
		[ValidateNotNull()]
		[System.Security.SecureString]$SecurePassword
	)

	Begin {
	}

	Process {
		if ($PSCmdlet.ParameterSetName -eq "Secure" -and $SecurePassword -eq $null)
		{
			while ($SecurePassword -eq $null)
			{
				$SecurePassword = Read-Host -Prompt "Enter password" -AsSecureString
			}
		}

		if ($PSCmdlet.ParameterSetName -eq "Plain")
		{
			$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
		}

		Write-Output -InputObject (New-Object -TypeName System.Management.Automation.PSCredential($UserName, $SecurePassword))
	}

	End {
	}
}

#endregion


#region Utility Functions

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
			LAST UPDATED: 10/23/2017

		.FUNCTIONALITY
			This cmdlet is used to create empty test files to perform tests on.
	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.UInt64]$Size,

		[Parameter(Position = 1)]
		[ValidateNotNullOrEmpty()]
		[System.String]$FilePath = "$env:USERPROFILE\Desktop\Test.txt"
	)

	Begin {}

	Process
	{
		$Writer = [System.IO.File]::Create($FilePath)

		$Bytes = New-Object Byte[] ($Size)
		$Writer.Write($Bytes, 0, $Bytes.Length)

		$Writer.Close()

		Write-Log -Message "$Size file created at $FilePath" -Level VERBOSE
	}

	End {}
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
	[OutputType([System.Boolean])]
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

		Write-Output -InputObject ($Reboots.ContainsValue($true))
	}

	End {		
	}
}

#endregion


#region Certificates

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
	[OutputType()]
    Param(
        [Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
        [System.String]$User,

        [Parameter(ParameterSetName = "All", Mandatory = $true)]
        [Switch]$All,

        [Parameter(ParameterSetName = "All")]
        [Switch]$Replace,

		[Parameter()]
		[ValidateSet("FULL_CONTROL", "READ", "READ_WRITE")]
		[System.String]$AccessLevel = "FULL_CONTROL"
    )

    DynamicParam {
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		$Prints = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.HasPrivateKey -eq $true } | Select-Object -ExpandProperty Thumbprint
		New-DynamicParameter -Name "Thumbprint" -ParameterSets "Thumbprint" -Type ([System.String]) -Mandatory -ValueFromPipeline -ValidateSet $Prints -RuntimeParameterDictionary $ParamDictionary | Out-Null

		$Subjects = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.HasPrivateKey -eq $true } | Select-Object -ExpandProperty Subject
		New-DynamicParameter -Name "Subject" -ParameterSets "Subject" -Type ([System.String]) -Mandatory -ValueFromPipeline -ValidateSet $Subjects -RuntimeParameterDictionary $ParamDictionary | Out-Null

        return $ParamDictionary
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
	[OutputType([System.String[]])]
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

#endregion


#region Disk

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
		[ValidateNotNull()]
        [PSTypeName("Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/Storage/MSFT_Disk")]
		[Microsoft.Management.Infrastructure.CimInstance]$InputObject,

		[Parameter()]
		[ValidatePattern("[d-zD-Z]")]
		[System.Char]$DriveLetter,
        
        [Parameter()]
		[ValidateNotNull()]
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
	[OutputType([System.Management.Automation.PSCustomObject])]
    Param(
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [System.String]$ComputerName,

        [Parameter(ParameterSetName="human")]
        [Alias("h")]
        [Switch]$HumanReadable,

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

#endregion


#region User Accounts / Groups

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
	[OutputType([System.String[]])]
	Param(
	)

	Begin {}

	Process {
		Write-Output -InputObject (Get-WmiObject -Class Win32_UserProfile | Where-Object {$_.Special -eq $false} | Select-Object -ExpandProperty LocalPath)
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
	[OutputType([System.Security.Principal.SecurityIdentifier])]
	Param(
		[Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$UserName,

		[Parameter(Position = 1)]
		[ValidateNotNull()]
		[System.String]$ComputerName = [System.String]::Empty,

		[Parameter()] 
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

	Begin {	
	}

	Process{
		Write-Log -Message "Getting SID for $UserName." -Level VERBOSE

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
				Write-Log -Message "Exception translating $Domain\$Name." -ErrorRecord $_ -Level VERBOSEERROR
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
					Write-Log -Message "Exception translating $($args[0])\$($args[1])" -ErrorRecord $_ -Level VERBOSEERROR
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
			System.String

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
	[OutputType([System.String])]
	Param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$UserName,

		[Parameter(Position=1)]
		[ValidateNotNull()]
		[System.String]$ComputerName = [System.String]::Empty,

		[Parameter()] 
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

	Begin {	
	}

	Process{
		Write-Log -Message "Getting NT Account for $UserName." -Level VERBOSE

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
					Write-Log -Message "Exception translating SID $($UserSid.Value) for $UserName to NTAccount." -ErrorRecord $_ -Level VERBOSEERROR
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
						Write-Log -Message "Exception translating SID $($args[0].Value) to NTAccount." -ErrorRecord $_ -Level VERBOSEERROR
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
			System.String

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
	[OutputType([System.String[]])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$LocalGroup,		

		[Parameter(Position = 1)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ComputerName = $env:COMPUTERNAME
	)

	Begin {
	}

	Process {
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
	[OutputType([System.Boolean])]
	Param(
		[Parameter(Mandatory = $true, Position = 0)]
		[ValidateNotNullOrEmpty()]
		[System.String]$LocalGroup,

		[Parameter(Mandatory = $true, Position = 1)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Member,

		[Parameter(Position = 2)]
		[ValidateSet("Group", "User")]
		[System.String]$MemberType = "User",

		[Parameter(Position = 3)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ComputerName = $env:COMPUTERNAME
	)

	Begin {
	}

	Process {
		$Success = $false

		$Domain = Get-ComputerDomain
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
					Write-Log -Message "Successfully added $Member to $($Group.Name)" -Level VERBOSE
					$Success = $true
				}
				catch [Exception] {
					Write-Log -ErrorRecord $_ -Level ERROR
				}
			}
			else
			{
				Write-Log -Message "$($NewMember.Name) already a member of $($Group.Name)." -Level VERBOSE
				$Success = $true
			}
		}
		else
		{
			Write-Log -Message "$LocalGroup local group could not be found." -Level VERBOSE
		}

		Write-Output -InputObject $Success
	}

	End {
		
	}
}

Function Set-LocalAdminPassword {
	<#
		.SYNOPSIS
			Sets the local administrator password.

		.DESCRIPTION
			Sets the local administrator password and optionally enables the account if it is disabled.

			If the password is not specified, the user will be prompted to enter the password when the cmdlet is run. The admin account is
			identified by matching its SID to *-500, which should be unique for the local machine.

		.PARAMETER Password
			The new password for the local administrator account.

		.PARAMETER EnableAccount
			Specify to enable the local administrator account if it is disabled.

		.INPUTS
			System.Security.SecureString
		
		.OUTPUTS
			None

		.EXAMPLE 
			Set-LocalAdminPassword -EnableAccount

			The cmdlet will prompt the user to enter the new password.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/23/2017
	#>
	[CmdletBinding()]
	[OutputType()]
    Param (
        [Parameter(Position=0 , ValueFromPipeline=$true)]
		[ValidateNotNull()]
        [System.Security.SecureString]$Password,

		[Parameter()]
		[Switch]$EnableAccount
    )
    Begin {       
    }
    
    Process {
		$HostName = $env:COMPUTERNAME 
        $Computer = [ADSI]"WinNT://$HostName,Computer" 

		while ($Password -eq $null) 
		{
			$Password = Read-Host -AsSecureString -Prompt "Enter the new administrator password"
		}

		$Name = Get-LocalUser| Where-Object {$_.SID.Value -match "S-1-5-21-.*-500"} | Select-Object -ExpandProperty Name -First 1

		Write-Log -Message "The local admin account is $Name" -Level VERBOSE
        $User = [ADSI]"WinNT://$HostName/$Name,User"
        $PlainTextPass = Convert-SecureStringToString -SecureString $Password
                
		Write-Log -Message "Setting password." -Level VERBOSE
        $User.SetPassword($PlainTextPass)
                
		if ($EnableAccount) 
		{
			#The 0x0002 flag specifies that the account is disabled
			#The binary AND operator will test the value to see if the bit is set, if it is, the account is disabled.
			#Doing a binary OR would add the value to the flags, since it would not be present, the OR would add it
			if ($User.UserFlags.Value -band "0x0002") 
			{
				Write-Log -Message "The account is current disabled with user flags $($User.UserFlags.Value)" -Level VERBOSE
				#The binary XOR will remove the flag, which enables the account, the XOR means that if both values have the bit set, the result does not
				#If only 1 value has the bit set, then it will remain set, so we need to ensure that the bit is actually set with the -band above for the XOR to actually
				#remove the disabled value
				$User.UserFlags = $User.UserFlags -bxor "0x0002"
				$User.SetInfo()
			}
		}
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
			System.Boolean

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
	[OutputType([System.Boolean])]
	Param()

	Begin {}

	Process {
		Write-Output -InputObject ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
	}

	End {}
 }

#endregion


#region Host Configuration

Function Get-ComputerDomain {
	<#
		.SYNOPSIS
			Retrieves the domain the computer is joined to.

		.DESCRIPTION
			This cmdlet retrieves the Active Directory domain the computer is joined to. If the computer is not domain joined, the computer name will be returned.

		.PARAMETER ComputerName
			The name of the computer to connect to and retrieve the domain information. If this parameter is omitted, information from the local computer is used.

		.PARAMETER Credential
			The credential to use to connect to the remote computer.

		.PARAMETER CimSession
			An existing CimSession to use to connect to a remote machine.

		.INPUTS
			System.String
		
		.OUTPUTS
			System.String

		.EXAMPLE 
			Get-ComputerDomain

			Gets the AD domain of the local computer.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/23/2017
	#>
	[CmdletBinding(DefaultParameterSetName = "Computer")]
	[OutputType([System.String])]
	Param(
		[Parameter(ParameterSetName = "Computer", ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ComputerName = [System.String]::Empty,

		[Parameter(ParameterSetName = "Computer")]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(ParameterSetName = "Session")]
		[ValidateNotNull()]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null
	)

	Begin {

	}

	Process {
		[System.Collections.Hashtable]$Splat = @{}
		[System.Boolean]$EndSession = $false

		switch ($PSCmdlet.ParameterSetName)
		{
			"Computer" {

				if ($Credential -eq [System.Management.Automation.PSCredential]::Empty)
				{
					if (-not [System.String]::IsNullOrEmpty($ComputerName) -and $script:LocalNames -inotcontains $ComputerName)
					{
						$Splat.Add("ComputerName", $ComputerName)
					}
				}
				else
				{
					if ([System.String]::IsNullOrEmpty($ComputerName))
					{
						$ComputerName = $env:COMPUTERNAME
					}

					$CimSession = New-CimSession -Credential $Credential -ComputerName $ComputerName
					$Splat.Add("CimSession", $CimSession)
					$EndSession = $true
				}

				break
			}
			"Session" {
				$Splat.Add("CimSession", $CimSession)
				break
			}
		}

		Write-Output -InputObject (Get-CimInstance -ClassName Win32_ComputerSystem @Splat | Select-Object -ExpandProperty Domain)

		if ($EndSession)
		{
			Remove-CimSession -CimSession $CimSession
		}
	}

	End {

	}
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
	[OutputType([System.String])]
	Param(
	)

	Begin {}

	Process {
		Write-Output -InputObject ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME)).HostName
	}

	End {}
}

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

	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType()]
	Param(
		[Parameter()]
		[Switch]$AutomaticReboot = $false,

		[Parameter()]
		[Switch]$Force
	)

	Begin {
		if(!(Test-IsLocalAdmin)) {
			throw "This cmdlet must be run with admin credentials."
		}
	}

	Process
	{
		$ConfirmMessage = "You are about to reset Windows Update."
		$WhatIfDescription = "Windows Update reset."
		$ConfirmCaption = "Reset Windows Update"

		if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
		{
			try
			{
				Stop-Service -Name BITS -Force -ErrorAction Stop
			}
			catch [Exception]
			{
				Write-Log -Message "Could not stop the BITS service" -ErrorRecord $_ -Level WARNING
				Exit 1
			}

			try
			{
				Stop-Service -Name wuauserv -Force -ErrorAction Stop
			}
			catch [Exception]
			{
				Write-Log -Message "Could not stop the wuauserv service" -ErrorRecord $_ -Level WARNING
				Exit 1
			}

			try
			{
				Stop-Service -Name AppIDSvc -Force -ErrorAction Stop
			}
			catch [Exception]
			{
				Write-Log -Message "Could not stop the AppIDSvc service" -ErrorRecord $_ -Level WARNING
				Exit 1
			}

			try
			{
				Stop-Service -Name CryptSvc -Force -ErrorAction Stop
			}
			catch [Exception]
			{
				Write-Log -Message "Could not stop the CryptSvc service" -ErrorRecord $_ -Level WARNING
				Exit 1
			}

			try
			{
				Clear-DnsClientCache -ErrorAction Stop
			}
			catch [Exception]
			{
				Write-Log -Message "Could not clear the dns client cache" -ErrorRecord $_ -Level WARNING
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
			regsvr32.exe /s wudriver.dll
			netsh winsock reset | Out-Null
			netsh winsock reset proxy | Out-Null

			Start-Service -Name BITS
			Start-Service -Name wuauserv
			Start-Service -Name AppIDSvc
			Start-Service -Name CryptSvc

			Write-Log -Message "Successfully reset Windows Update" -Level VERBOSE

			if ($AutomaticReboot) 
			{
				Restart-Computer -Force
			}
			else 
			{
				$Title = "Reboot Now"
				$Message = "A reboot is required to complete the reset, reboot now?"

				$Yes = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription "&Yes", `
				"Reboots the computer immediately."

				$No = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription "&No", `
				"Does not reboot the computer."

				$Options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No)

				$Result = $host.ui.PromptForChoice($Title, $Message, $Options, 0) 

				if ($Result -eq 0)
				{
					Restart-Computer -Force
				}
			}
		}
	}

	End {
	}
}

Function Get-WindowsUpdate {
	<#
		.SYNOPSIS
			Gets a list of windows updates.

		.DESCRIPTION
			The cmdlet retrieves either installed, available, or recommended windows updates for the local computer.

		.PARAMETER Status
			The status of windows updates to query, either INSTALLED, AVAILABLE, RECOMMENDED, or OPTIONAL.

        PARAMETER Category
            The root category to filter the updates by. The defaults to "All". If 1 category is selected that is not "All", the filtering is done pre-query. If multiple
            categories are selected, the filtering is done post-query.

        .PARAMETER Type
            The type of updates to query for. This defaults to Software. The other type is Driver.

        .PARAMETER IncludeHidden
            If this is specified, hidden updates are also included in the results.

		.PARAMETER Proxy
			If a proxy is required to connect to WSUS, specify the address.

		.PARAMETER Convert
			Converts the Microsoft.Update.Update ComObjects to PSCustomObjects

		.EXAMPLE
			Get-WindowsUpdate -Status INSTALLED

			Returns a list of installed windows updates.

		.INPUTS
			System.String

		.OUTPUTS
			Microsoft.Update.UpdateColl or System.Management.Automation.PSCustomObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATED: 11/14/2016
	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateSet("INSTALLED", "AVAILABLE", "RECOMMENDED", "OPTIONAL")]
		[System.String]$Status,

        [Parameter()]
        [ValidateSet("All", "Application", "Connectors", "CriticalUpdates", "DefinitionUpdates", "DeveloperKits", "FeaturePacks", "Guidance", "SecurityUpdates", "ServicePacks", "Tools", "UpdateRollups", "Updates")]
        [System.String[]]$Category = @("All"),

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa387284(v=vs.85).aspx
        [Parameter()]
        [ValidateSet("Software", "Driver", "All")]
        [System.String]$Type = "Software",

        [Parameter()]
        [Switch]$IncludeHidden,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$Proxy,

		[Parameter()]
		[Switch]$Convert
	)

	Begin {
	}

	Process {
		$Session = New-Object -ComObject Microsoft.Update.Session

		if (-not [System.String]::IsNullOrEmpty($Proxy))
		{ 
			Write-Verbose -Message "Setting Proxy to $Proxy." 
			$Proxy = New-Object -ComObject Microsoft.Update.WebProxy
			$Session.WebProxy.Address = $Proxy 
			$Session.WebProxy.AutoDetect = $false 
			$Session.WebProxy.BypassProxyOnLocal = $true 
		} 

		$Searcher = $Session.CreateUpdateSearcher()

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa386526(v=vs.85).aspx
        # Search options

        $QueryString = @()

        $QueryString += "IsInstalled = $(if ($Status -eq "INSTALLED") { 1 } else { 0 })"
        $QueryString += "IsHidden = $(if ($IncludeHidden) { 1 } else { 0 })"
        
        if ($Status -eq "OPTIONAL")
        {
            $QueryString += "BrowseOnly = 1"
        }

        if ($Status -eq "RECOMMENDED")
        {
            $QueryString += "AutoSelectOnWebsites = 1"
        }

        if ($Category -notcontains "All" -and $Category.Length -eq 1)
        {
            if ($script:UpdateClassifications.ContainsKey($Category[0]))
            {
                [System.Guid]$Id = $script:UpdateClassifications[$Category[0]]
                $QueryString += "CategoryIDs contains '$Id'"
            }
        }
		
        $Updates = New-Object -ComObject Microsoft.Update.UpdateColl
        $Results = @()
        $Types = @()

        if ($Type -eq "All")
        {
            $Types = @("Software", "Driver")
        }
        else
        {
            $Types = @($Type)
        }

        foreach ($Item in $Types)
        {
            $Str ="Type = '$Item' and $([System.String]::Join(" and ", $QueryString))"
            
            Write-Verbose -Message "Querying: $Str"
            
            $Temp = $Searcher.Search($Str)


            if ($Category.Length -le 1 -or $Category -contains "All")
            {
                Write-Verbose -Message "$($Temp.Updates.Count) updates found."

                $Results += $Temp.Updates
            }
            else
            {

                $Ids = @()
                    
                foreach ($Item in $Category)
                {
                    Write-Verbose -Message "Adding filter for $Item."

                    if ($script:UpdateClassifications.ContainsKey($Item))
                    {
                        $Ids += $script:UpdateClassifications[$Item]
                    }
                }

                $Temp.RootCategories | Where-Object {$_.CategoryID -in $Ids } | ForEach-Object {
                    $Results += $_.Updates
                }

                Write-Verbose -Message "$($Results.Length) updates found after filtering."
            }
        }
        
		[PSCustomObject[]]$ConvertedResults = @()

        foreach ($Item in $Results)
        {
            if ($Convert)
			{
                [System.Collections.Hashtable]$Temp = @{}

                # Have to use this because the base com object won't serialize to json
                $Item | Get-Member -MemberType *Property | ForEach-Object {
                    [Microsoft.PowerShell.Commands.MemberDefinition]$Member = $_
                    $Temp.Add($Member.Name, $Item."$($Member.Name)")
                }

                # Use this to serialize the com object properties that are other com objects
                [System.String]$Str = ConvertTo-Json -InputObject $Temp
				$ConvertedResults += (ConvertFrom-Json -InputObject $Str)
			}
			else
			{
				$Updates.Add($Item) | Out-Null
			}
        }

		if ($Convert)
		{
			Write-Output -InputObject $ConvertedResults
		}
		else
		{
			Write-Output -InputObject $Updates
		}
	}

	End {
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
	[OutputType()]
	Param(
		[Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNull()]
		[System.String]$TrustedHosts = "*"
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
		Write-Log -Message "WinRM Enabled" -Level VERBOSE
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
	[OutputType()]
	Param(
		[Parameter(Mandatory=$true, ParameterSetName="Enable")]
		[Switch]$Enable,

		[Parameter(Mandatory=$true, ParameterSetName="Enable")]
		[ValidateNotNullOrEmpty()]
		[System.String]$UserName,

		[Parameter(Mandatory=$true, ParameterSetName="Enable")]
		[ValidateNotNull()]
		[System.String]$Password,

		[Parameter(Mandatory=$true, ParameterSetName="Disable")]
		[Switch]$Disable	
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
	[OutputType()]
	Param(
		[Parameter(Position = 0, ValueFromPipeline = $true)]
		[System.Int32]$MaximumSize = -1,

		[Parameter(Position = 1)]
		[System.Int32]$InitialSize = -1
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

				$CPF = Get-CimInstance -ClassName Win32_PageFileSetting
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
	[OutputType()]
	Param(
		[Parameter()]
		[Switch]$PassThru
	)

	Begin {
	}

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
	[OutputType()]
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
		Write-Log -Message "Disabling SSLv3 protocol." -Level VERBOSE

		if (!(Test-Path -Path $ServerRegKey)) {
			New-Item -Path $ServerRegKey | Out-Null
		}

		New-ItemProperty -Path $ServerRegKey -Name $ServerRegName -Value 0 -PropertyType DWORD | Out-Null

		if (!(Test-Path -Path $ClientRegKey)) {
			New-Item -Path $ClientRegKey | Out-Null
		}

		New-ItemProperty -Path $ClientRegKey -Name $ServerRegName -Value 0 -PropertyType DWORD | Out-Null
		New-ItemProperty -Path $ClientRegKey -Name $ClientRegName -Value 1 -PropertyType DWORD | Out-Null

		Write-Log -Message "Successfully disabled SSLv3." -Level VERBOSE
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
	[OutputType()]
	Param(
		[Parameter()]
		[Switch]$Disable
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
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Command,

		[Parameter(ParameterSetName = "Text")]
		[Switch]$StoreAsPlainText,

		[Parameter(ParameterSetName =" File")]
		[Switch]$RunFile,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
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
	[OutputType()]
	Param()

	Begin {
	}

	Process {
		Get-ChildItem -Path "$env:SystemRoot\System32\wbem\*" -Include @("*.mof") -Exclude @("*uninstall*") | ForEach-Object {
			$Result = & $env:SystemRoot\System32\wbem\mofcomp.exe $_.FullName

			[System.String]$Message = ([System.String]::Join("`r`n", $Result))

			if ($Message -ilike "*An error occurred*") {
                Write-Log -Message $Message -Level ERROR
            }
			else {
				Write-Log -Message ([System.String]::Join("`r`n", $Result)) -Level VERBOSE
			}
		}
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
	[OutputType([System.Management.Automation.PSObject])]
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
	[OutputType([System.String])]
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

Function Get-NETVersion {
	<#
		.SYNOPSIS
			Gets the current version of .NET version 4 installed.

		.DESCRIPTION
			This cmdlet gets the current version of .NET version 4 installed from the registry at HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full.

		.INPUTS
			None

		.OUTPUTS
			System.Int32

        .EXAMPLE
			Get-NETVersion

			Retrieves the .NET version 4 specific version.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
    [CmdletBinding()]
	[OutputType([System.Int32])]
	Param(
	)

	Begin {}

	Process {
        $NetVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Release
        Write-Log -Message ".NET version installed is $NetVersion." -Level VERBOSE
		Write-Output -InputObject ([System.Int32]$NetVersion)
    }

	End {		
	}
}

#endregion


#region Software

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

	[CmdletBinding(DefaultParameterSetName = "Cleanup")]
	[OutputType()]
	Param(
		[Parameter(Position = 0, ParameterSetName = "Cleanup", Mandatory = $true)]
		[System.Int32]$MajorVersion,

		[Parameter(ParameterSetName = "Cleanup")]
		[System.Int32]$MinorVersion = 0,

		[Parameter(Position = 1, ParameterSetName = "Cleanup", Mandatory = $true)]
		[System.Int32]$ReleaseVersion,

		[Parameter(Position = 2, ParameterSetName = "Cleanup", Mandatory=$true)]
		[System.Int32]$PluginVersion,

		[Parameter(ParameterSetname = "Cleanup")]
		[ValidateSet("x86", "x64", "All")]
		[System.String]$Architecture = "All",

		[Parameter(ParameterSetName = "Removal", Mandatory = $true)]
		[Switch]$FullRemoval	
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

		Write-Log -Message "[INFO] Getting All User Profiles" -Level VERBOSE

		foreach ($Profile in $UserProfiles)
		{
			$FilePaths += "$env:SystemDrive\Users\" + $Profile.Name + "\AppData\LocalLow\Sun"
			$FilePaths += "$env:SystemDrive\Users\" + $Profile.Name + "\AppData\Local\Temp\java_install_reg.log"
			$FilePaths += "$env:SystemDrive\Users\" + $Profile.Name + "\AppData\Local\Temp\java_install.log"  
		}

		Write-Log -Message "[INFO] Adding file paths" -Level VERBOSE

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
		
		Write-Log -Message "[INFO] Getting Registry Keys" -Level VERBOSE
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

		Write-Log -Message "[INFO] Getting Registry Key Properties" -Level VERBOSE

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

		Write-Log -Message "Removing Directories and Files" -Level VERBOSE

		foreach ($Item in $FilePaths)
		{
			if (Test-Path -Path $Item)
			{
				$DirectoryCount++
				Remove-Item -Path $Item -Force -Recurse
			}
		}

		Write-Log -Message "Removing Registry Keys" -Level VERBOSE

		foreach ($Item in $RegistryKeys)
		{
			if (Test-Path -Path $Item)
			{
				$RegistryKeyCount++
				Remove-Item -Path $Item -Force -Recurse
			}
		}

		Write-Log -Message "Removing Registry Key Entries" -Level VERBOSE

		foreach ($Item in $RegistryKeyProperties)
		{
			if (Test-Path -Path $Item.Path)
			{
				$RegistryEntryCount++
				Remove-ItemProperty -Path $Item.Path -Name $Item.Property -Force
			}
		}

		Write-Log -Message "Java cleanup removed $DirectoryCount directories, $RegistryKeyCount registry keys, and $RegistryEntryCount registry key entries." -Level INFO
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
			System.String

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
	[OutputType([System.Boolean])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNullOrEmpty()]
		[System.String]$PackageId
	)

	Begin {
	}

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
	[OutputType([System.String[]])]
	Param(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$PackageName,

		[Parameter(Mandatory = $true, Position = 0)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Url,

		[Parameter(Mandatory = $true, Position = 1)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Destination
	)

	Begin {		
	}

	Process {
		$Result = @()

		if (![System.String]::IsNullOrEmpty($PackageName)) 
		{
			Write-Log -Message "Processing package $PackageName." -Level VERBOSE
		}

		if (!(Test-Path -Path $Destination)) 
		{
			Write-Log -Message "$Destination not present, downloading from $Url." -Level VERBOSE

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
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$PackageId,

		[Parameter(Mandatory  =$true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$PackageName,

		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Destination,

		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Url,

		[Parameter()]
		[ValidateNotNull()]
		[System.String[]]$Arguments = @()
	)

	Begin {}

	Process {
        Write-Log -Message "Processing $PackageName ($PackageId)" -Level VERBOSE

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
	
	End {
	}  
}

#endregion


# https://msdn.microsoft.com/en-us/library/windows/desktop/ff357803(v=vs.85).aspx
$script:UpdateClassifications = @{
    "Application" = [System.Guid]"5C9376AB-8CE6-464A-B136-22113DD69801";
    "Connectors" = [System.Guid]"434DE588-ED14-48F5-8EED-A15E09A991F6";
    "CriticalUpdates" = [System.Guid]"E6CF1350-C01B-414D-A61F-263D14D133B4";       # A broadly released fix for a specific problem addressing a critical, non-security related bug.
    "DefinitionUpdates" = [System.Guid]"E0789628-CE08-4437-BE74-2495B842F43B";     # A broadly-released and frequent software update containing additions to a product's definition database. Definition databases are often used to detect objects with specific attributes, such as malicious code, phishing Web sites, or junk e-mail.
    "DeveloperKits" = [System.Guid]"E140075D-8433-45C3-AD87-E72345B36078";
    "Drivers" = [System.Guid]"ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0";               # A software component necessary to control or regulate another device.
    "FeaturePacks" = [System.Guid]"B54E7D24-7ADD-428F-8B75-90A396FA584F";          # New product functionality that is first distributed outside the context of a product release, and usually included in the next full product release.
    "Guidance" = [System.Guid]"9511D615-35B2-47BB-927F-F73D8E9260BB";
    "Microsoft" = [System.Guid]"720a9943-9b85-4957-82a8-f344c2ed7423";
    "SecurityUpdates" = [System.Guid]"0FA1201D-4330-4FA8-8AE9-B877473B6441";       # A broadly released fix for a product-specific security-related vulnerability. Security vulnerabilities are rated based on their severity which is indicated in the Microsoft® security bulletin as critical, important, moderate, or low.
    "ServicePacks" = [System.Guid]"68C5B0A3-D1A6-4553-AE49-01D3A7827828";          # A tested, cumulative set of all hotfixes, security updates, critical updates and updates, as well as additional fixes for problems found internally since the release of the product. Service packs may also contain a limited number of customer-requested design changes or features.
    "Tools" = [System.Guid]"B4832BD8-E735-4761-8DAF-37F882276DAB";                 # A utility or feature that aids in accomplishing a task or set of tasks.
    "UpdateRollups" = [System.Guid]"B4832BD8-E735-4761-8DAF-37F882276DAB";         # A tested, cumulative set of hotfixes, security updates, critical updates, and updates packaged together for easy deployment. A rollup generally targets a specific area, such as security, or a component of a product, such as Internet Information Services "IIS".
    "Updates" = [System.Guid]"CD5FFD1E-E932-4E3A-BF74-18BF0B1BBD83";               # A broadly released fix for a specific problem addressing a noncritical, non-security-related bug. 
    "Upgrades" = [System.Guid]"3689bdc8-b205-4af4-8d4a-a63924c5e9d5";              # A new product release bringing a device to the next version, containing bug fixes, design changes and new features.
}