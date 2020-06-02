<# 

.SYNOPSIS
    CYBERANALYSTVM CONFIGURATION SCRIPT
    Module: Download Provisioner script
    Author: Diego Perez (@darkquassar)
    Version: 1.0.0
    Description: This script will help you download 
#>

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

function Start-DownloadCyberAnalystVMProvisioner {


    # Attempt to download the Provisioning script, if it fails, resort to trusting all X509 Certificates
    try {

        $ProvisionerScript = (New-Object Net.Webclient).DownloadString("https://raw.githubusercontent.com/darkquasar/cyber-tools/master/packer/scripts/provisioning/THL-Provisioner-03.ps1")
        return $ProvisionerScript
    }
    catch {
        Write-Host "Failed to download CyberAnalystVM Provisioner. Trying another method..." -ForegroundColor Green
    }

    try {

        Write-Host "Relaxing Certificate checking..." -ForegroundColor Green
        Invoke-RelaxProxy

        # Download Provisioning script
        $ProvisionerScript = (New-Object Net.Webclient).DownloadString("https://raw.githubusercontent.com/darkquasar/cyber-tools/master/packer/scripts/provisioning/THL-Provisioner-03.ps1")
        
        return $ProvisionerScript
    }
    catch {
        Write-Host "Failed to download CyberAnalystVM Provisioner" -ForegroundColor Green
        return $false
    }
}