<# 

.SYNOPSIS
    Provisioning Script for Windows 7, 10, Server 2012 and Server 2016 VM - Packer. 
    By running this script you acknowledge that it's not provided with any guarantees and 
    that you understand the regulations pertaining the software licenses that may be required 
    by any of the softwares referenced by the script. 
    
    Diego Perez - THL - 2017
#>

function Start-DummyFunction {
    Write-Host "This is a Dummy Function" -ForegroundColor Green
}

function Start-ConfigureGenerics {
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
    if ($env:install_vmware_tools -eq $true) {
    
        # Downloading & Installing VMWare Tools
        Write-Host "Downloading & Installing VMWare Tools..." -ForegroundColor Green
        
        Start-Job -Name DonwloadVmWareTools -ScriptBlock { (New-Object System.Net.WebClient).DownloadFile('https://softwareupdate.vmware.com/cds/vmw-desktop/ws/15.5.0/14665864/windows/packages/tools-windows.tar', 'C:\Windows\Temp\vmware-tools.tar') } | Wait-Job
        
        if (Test-Path 'C:\Windows\Temp\vmware-tools.tar') {
            Write-Host "Downloaded VMWare Tools" -ForegroundColor Green
        }
        else {
            Write-Host "Could not download VMWare Tools" -ForegroundColor Green
        }
        
        Start-Process -FilePath "$env:comspec" -ArgumentList "/c ""C:\Program Files\7-Zip\7z.exe"" x C:\Windows\Temp\vmware-tools.tar -oC:\Windows\Temp -y" -Wait
        
        Write-Host "Locating & Renaming Installer" -ForegroundColor Green
        Start-Job -Name Rename -ScriptBlock { Get-ChildItem "C:\Windows\Temp" -File -Filter "vm*iso" | Rename-Item -NewName "vmWareTools.iso" } | Wait-Job
        if(Test-Path "C:\Program Files (x86)\VMWare") {
            Write-Host "VMWare Tools already installed, deleting ISO" -ForegroundColor Green
            Get-Item "C:\Windows\Temp\vmWareTools.iso" | Remove-Item -Recurse -Force
        } 
        
        Write-Host "Uncompressing VMWareTools Image" -ForegroundColor Green
        Start-Process -FilePath "$env:comspec" -ArgumentList "cmd /c ""C:\Program Files\7-Zip\7z.exe"" x C:\Windows\Temp\vmWareTools.iso -oC:\Windows\Temp\VMWare" | Out-Null
        Start-Sleep 2
        
        Write-Host "Installing VMWare Tools" -ForegroundColor Green
        Start-Process -FilePath "$env:comspec" -ArgumentList "/c C:\Windows\Temp\VMWare\setup64.exe /S/v ""/qn REBOOT=R""" -NoNewWindow -Wait
    }

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
    if ($RunningAsAdmin) {

        $Updates = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings

        if ($Updates.ReadOnly -eq $True) { Write-Error "Cannot update Windows Update settings due to GPO restrictions." }

        else {
            $Updates.NotificationLevel = 1 #Disabled
            $Updates.Save()
            $Updates.Refresh()
            Write-Output "Automatic Windows Updates disabled."
        }
    }

    else {
        Write-Warning "Please execute this script as Administrator. Script cancelled."
    } 
    
    return
}

function Install-Chocolatey {

    Write-Host "Installing Chocolatey..." -ForegroundColor Green
    
    $chocoExePath = 'C:\ProgramData\Chocolatey\bin'
    
    # Use Windows native compression library rather than 7zip or other
    $env:chocolateyUseWindowsCompression = 'true'

    if ($($env:Path).ToLower().Contains($($chocoExePath).ToLower())) { 
        Write-Host "Chocolatey found in PATH, skipping install..."
        return 
    }

    # Add to system PATH
    $systemPath = [Environment]::GetEnvironmentVariable('Path',[System.EnvironmentVariableTarget]::Machine)
    $systemPath += ';' + $chocoExePath
    [Environment]::SetEnvironmentVariable("PATH", $systemPath, [System.EnvironmentVariableTarget]::Machine)

    # Update local user path
    $userPath = [Environment]::GetEnvironmentVariable('Path',[System.EnvironmentVariableTarget]::User)
    if($userPath) { $env:Path = $systemPath + ";" + $userPath } 
    else { $env:Path = $systemPath }

    # Run the Chocolatey installer
    try {
        Invoke-Expression ((New-Object Net.Webclient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    catch {
        Write-Host "Could not install Chocolatey with current Certificate Checking configuration. Trying to relax Cert checking..." -ForegroundColor Green

        try {
            Invoke-RelaxProxy
            Invoke-Expression ((New-Object Net.Webclient).DownloadString('https://chocolatey.org/install.ps1'))
        }
        catch {
            Write-Host "Could not install Chocolatey" -ForegroundColor Green
        }
    }
        
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

function Start-Cleanup {

    <#
        .SYNOPSIS
        Cleanup and other post-deployment tasks. 
    #>
    
    Write-Host "Cleanup Script Starting" -ForegroundColor Green
    
    # Disabling Autologon for Administrator (was activated by BoxStarter)
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c reg add ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"" /v AutoAdminLogon /d 0 /f" -NoNewWindow -Wait
    
    # Removing Files in C:\Windows\Temp
    Get-ChildItem "C:\Windows\Temp" | Where-Object {$_.Mode -match "d-"} | Remove-Item -Recurse -Force
    if(Test-Path "C:\Windows\Temp\vmWareTools.iso") {Get-Item "C:\Windows\Temp\vmWareTools.iso" | Remove-Item -Force}
}

function Invoke-RelaxProxy {


    # Proxies are too uptight and create problems with Powershell and trusted certs :)
    # Allow current PowerShell session to trust all certificates. Ref: https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
    try {

        Add-Type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
            }
        }
"@
    } 
    catch {
        Write-Host "Could not configure System.Security.Cryptography.X509Certificates"
    }

    try {
        # Trust all certificates
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
    catch {
        Write-Host "Failed to Trust All Certs" -ForegroundColor Green
    }
}