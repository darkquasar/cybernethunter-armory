<# 

.SYNOPSIS
   	Provisioning Script for W2012R2 VM - Packer. 
	By running this script to acknowledge that it's not provided with any guarantees and 
	that you understand the regulations pertaining the software licenses that may be required 
	by any of the softwares referenced by the script. 
	
	Diego Perez - THL - 2017
#>

function Configure-Generics-Start {
	<#
	
	.SYNOPSIS
	   Makes a few general configurations before starting with package deployment and other resource-consuming tasks
	   
	#>
	
	# Creating Tools folder for CyberSec tools (non FLAREvm ones)
	Write-Host "Creating Cybersecurity Tools Folder for custom tools" -ForegroundColor Green
	New-Item $env:cybersec_tools_folder -Type directory
	
	# Downloading & Installing 7zip
	Write-Host "Installing 7zip" -ForegroundColor Green
	(New-Object System.Net.WebClient).DownloadFile('http://www.7-zip.org/a/7z920-x64.msi', 'C:\Windows\Temp\7z920-x64.msi')
	Start-Process -FilePath "$env:comspec" -ArgumentList "/c msiexec /qb /i C:\Windows\Temp\7z920-x64.msi" -NoNewWindow -Wait
	
	# Checking if packer variable was passed to the build instance, otherwise exit
	if ($env:install_vmware_tools -eq $false) {return}
	
	# Downloading & Installing VMWare Tools
	Write-Host "Downloading & Installing VMWare Tools..." -ForegroundColor Green
	
	Start-Job -Name DonwloadVmWareTools -ScriptBlock { (New-Object System.Net.WebClient).DownloadFile('http://softwareupdate.vmware.com/cds/vmw-desktop/ws/12.5.7/5813279/windows/packages/tools-windows.tar', 'C:\Windows\Temp\vmware-tools.tar') } | Wait-Job
	
	Write-Host "Downloaded VMWare Tools" -ForegroundColor Green
	Start-Process -FilePath "$env:comspec" -ArgumentList "/c ""C:\Program Files\7-Zip\7z.exe"" x C:\Windows\Temp\vmware-tools.tar -oC:\Windows\Temp" -Wait
	
	Write-Host "Locating & Renaming Installer" -ForegroundColor Green
	Start-Job -Name Rename -ScriptBlock { Get-ChildItem "C:\Windows\Temp" -File -Filter "vm*iso" | Rename-Item -NewName "vmWareTools.iso" } | Wait-Job
	if(Test-Path "C:\Program Files (x86)\VMWare") {Get-Item "C:\Windows\Temp\vmWareTools.iso" | Remove-Item -Recurse -Force} 
    
	Write-Host "Uncompressing VMWareTools Image" -ForegroundColor Green
    Start-Process -FilePath "$env:comspec" -ArgumentList "cmd /c ""C:\Program Files\7-Zip\7z.exe"" x C:\Windows\Temp\vmWareTools.iso -oC:\Windows\Temp\VMWare" | Out-Null
	Start-Sleep 2
	
	Write-Host "Installing VMWare Tools" -ForegroundColor Green
	Start-Process -FilePath "$env:comspec" -ArgumentList "/c C:\Windows\Temp\VMWare\setup64.exe /S/v ""/qn REBOOT=R""" -NoNewWindow -Wait

	# Enable RDP
	Write-Host "Enabling RDP..." -ForegroundColor Green
	Start-Process -FilePath "$env:comspec" -ArgumentList "/c netsh advfirewall firewall add rule name=""Open Port 3389"" dir=in action=allow protocol=TCP localport=3389" -NoNewWindow -Wait
	Start-Process -FilePath "$env:comspec" -ArgumentList "/c reg add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"" /v fDenyTSConnections /t REG_DWORD /d 0 /f" -NoNewWindow -Wait

	return

}

function Disable-WindowsUpdates {
	<#
	.SYNOPSIS
	   Disables automatic windows updates
	.DESCRIPTION
	   Disables checking for and applying Windows Updates (does not prevent updates from being applied manually or being pushed down)
	   Run on the machine that updates need disabling on.
	#>

	$RunningAsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
	if ($RunningAsAdmin)
	{

		$Updates = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings

		if ($Updates.ReadOnly -eq $True) { Write-Error "Cannot update Windows Update settings due to GPO restrictions." }

		else {
			$Updates.NotificationLevel = 1 #Disabled
			$Updates.Save()
			$Updates.Refresh()
			Write-Output "Automatic Windows Updates disabled."
		}
	}

	else 
	{	Write-Warning "Must be executed in Administrator level shell."
		Write-Warning "Script Cancelled!" } 
	
	return
}

function Install-Chocolatey {
	Write-Host "Installing Chocolatey..." -ForegroundColor Green
	
	$chocoExePath = 'C:\ProgramData\Chocolatey\bin'
	
	# Use Windows native compression library rather than 7zip or other
	$env:chocolateyUseWindowsCompression = 'true'

	if ($($env:Path).ToLower().Contains($($chocoExePath).ToLower())) { echo "Chocolatey found in PATH, skipping install..." ; Exit }

	# Add to system PATH
	$systemPath = [Environment]::GetEnvironmentVariable('Path',[System.EnvironmentVariableTarget]::Machine)
	$systemPath += ';' + $chocoExePath
	[Environment]::SetEnvironmentVariable("PATH", $systemPath, [System.EnvironmentVariableTarget]::Machine)

	# Update local process' path
	$userPath = [Environment]::GetEnvironmentVariable('Path',[System.EnvironmentVariableTarget]::User)
	if($userPath) { $env:Path = $systemPath + ";" + $userPath } 
	else { $env:Path = $systemPath }

	# Run the Chocolatey installer
	iex ((New-Object Net.Webclient).DownloadString('https://chocolatey.org/install.ps1'))
	
	return
}

function Install-ChocoPackages {
	Write-Host "Installing Selected Chocolatey Packages..." -ForegroundColor Green
	Write-Host "Debugging status of environment variables" 
	
	# for debug, remove later
	$env:cybersec_tools_folder | Out-File C:\Users\vagrant\debugVar.txt -Append
	$env:install_putty | Out-File C:\Users\vagrant\debugVar.txt -Append
	"boxstarter follows" | Out-File C:\Users\vagrant\debugVar.txt -Append
	$env:install_boxstarter | Out-File C:\Users\vagrant\debugVar.txt -Append
	$env:install_chrome | Out-File C:\Users\vagrant\debugVar.txt -Append
		
	# Update PowerShell to v5
	if ($PSVersionTable.PSVersion.Major -le 5)
		{
		  Write-Host "Installing Newer Version of PowerShell"
		  Start-Process -FilePath "$env:comspec" -ArgumentList "/c choco install powershell -y" -NoNewWindow -Wait
		}
	else
		{ Write-Host "Not installing PowerShell as it is 5+" }
			 
	# Installing BoxStarter for FlareVM deployment
	if ($env:install_boxstarter -eq $true) 
		{
		Start-Process -FilePath "$env:comspec" -ArgumentList "/c choco install boxstarter -y" -Wait
		}
	
	# Install Notepad++
	if ($env:install_notepadpp -eq $true) 
		{
		Start-Process -FilePath "$env:comspec" -ArgumentList "/c choco install notepadplusplus -y" -NoNewWindow -Wait
		
		# pinning to taskbar
		(New-Object -ComObject Shell.Application).Namespace('C:\Program Files\Notepad++').ParseName('notepad++.exe').InvokeVerb('TaskbarPin')
		}
		
	# Install Putty
	if ($env:install_putty -eq $true) 
		{
		Start-Process -FilePath "$env:comspec" -ArgumentList "/c choco install putty -y" -NoNewWindow -Wait
		}
	
	# Install OpenSSH
	if ($env:install_openssh -eq $true) 
		{
		Start-Process -FilePath "$env:comspec" -ArgumentList "/c choco install mls-software-openssh -y" -NoNewWindow -Wait
		}
	
	# Install Chrome
	if ($env:install_chrome -eq $true) 
		{
		Start-Process -FilePath "$env:comspec" -ArgumentList "/c choco install googlechrome -y" -NoNewWindow -Wait
		#(New-Object -ComObject Shell.Application).Namespace('C:\Program Files (x86)\Google\Chrome\Application\').ParseName('chrome.exe').InvokeVerb('TaskbarPin')
		}
		
	# Install TOR Browser
	if ($env:install_torbrowser -eq $true) 
		{
		Start-Process -FilePath "$env:comspec" -ArgumentList "/c choco install tor-browser -y" -NoNewWindow -Wait
		}

	# Install Firefox
	if ($env:install_firefox -eq $true) 
		{
		Start-Process -FilePath "$env:comspec" -ArgumentList "/c choco install firefox -y" -NoNewWindow -Wait
		#(New-Object -ComObject Shell.Application).Namespace('C:\Program Files (x86)\Mozilla Firefox\').ParseName('firefox.exe').InvokeVerb('TaskbarPin')
		}

	# Install Sysinternals
	if ($env:install_sysinternals -eq $true) 
		{
		Start-Process -FilePath "$env:comspec" -ArgumentList "/c choco install sysinternals --params ""/InstallDir:$env:cybersec_tools_folder\Sysinternals"" -y" -NoNewWindow -Wait
		}		
		
	# Pinning useful Apps to the TaskBar
	(New-Object -ComObject Shell.Application).Namespace('C:\Windows\System32\WindowsPowershell\v1.0\').ParseName('powershell.exe').InvokeVerb('TaskbarPin')
	(New-Object -ComObject Shell.Application).Namespace('C:\Windows\System32\').ParseName('cmd.exe').InvokeVerb('TaskbarPin')
	
	
	

	return
}

function Install-FlareVM {
	
	# Checking if packer variable was passed to the build instance, otherwise exit
	if ($env:install_flarevm -eq $false) {return}
	
	Write-Host "Installing FlareVM Applications via BoxStarter..." -ForegroundColor Green
	
	Write-Host "Importing the Install-BoxstarterPackage Module..." -ForegroundColor Green
	Import-Module "C:\ProgramData\Boxstarter\Boxstarter.Chocolatey\Install-BoxstarterPackage.ps1"
	Start-Sleep 3
	
	$UserName = "vagrant"
	$Password = ConvertTo-SecureString "vagrant" -AsPlainText -Force
	$Credentials = New-Object System.Management.Automation.PSCredential ($Username, $Password)
	$FlareVMPS1url = "https://raw.githubusercontent.com/fireeye/flare-vm/master/flarevm_malware.ps1"
	
	Install-BoxstarterPackage -PackageName $FlareVMPS1url -Credential $Credentials

}

function Configure-Generics-End {
	<#
	.SYNOPSIS
	   Cleanup and other post-deployment tasks. 
	#>
	
	Write-Host "Cleanup Script Starting" -ForegroundColor Green
	
	# Disabling Autologon for Administrator (was activated by BoxStarter)
	Start-Process -FilePath "$env:comspec" -ArgumentList "/c reg add ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"" /v AutoAdminLogon /d 0 /f" -NoNewWindow -Wait
	
	# Removing Files in C:\Windows\Temp
	Get-ChildItem "C:\Windows\Temp" | where {$_.Mode -match "d-"} | Remove-Item -Recurse -Force
	if(Test-Path "C:\Windows\Temp\vmWareTools.iso") {Get-Item "C:\Windows\Temp\vmWareTools.iso" | Remove-Item -Force}
}
