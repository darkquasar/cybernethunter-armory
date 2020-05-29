
function Start-BuildPackerTemplate {

    <# 

    .SYNOPSIS
        Automation Script to select the appropriate template and combination of variables for packer builds. 
        Diego Perez - @darkquassar - 2017
        
    .DESCRIPTION
        This function will abstract another layer of the whole build process by choosing a packer template based on the options specified when calling it.
        Use the parameters to alter the template pathway, for example by choosing a "vmware" platform for a "linux" ostype from an "iso" source. When overloading a particular variable, from the ones found inside "variables.json", make sure to include the "-var" switch plus the variable(s) inside quotations marks like so: "-var install_windowsupdates=True -var install_sysinternals=False".
        
        NOTE: By default, the "variables.json" file points to empty values for "iso_url", "iso_checksum" and "iso_checksum_type". These are overloaded by the current script when selecting a particular platform
    
    .EXAMPLE 1
        Build a Windows 2012 R2 from an ISO for VMWare, using the defaults (ISO file will be downloaded from the internet) and other variables coded in "variables.json"
        
        Build-Template -Platform vmware -OSType windows -OSName Win2012R2 -VMSource iso
        
    .EXAMPLE 2
        Build a Windows 7 VM from an ISO for VMWare specifying the location of the ISO and associated paramaters.

        Build-Template -Platform vmware -OSType windows -OSName Win7 -VMSource iso -Variables '-var iso_url=C:/D13g0/VirtualMachines/ISO/7600.16385.090713-1255_x64fre_enterprise_en-us_EVAL_Eval_Enterprise-GRMCENXEVAL_EN_DVD.iso -var iso_checksum_type=sha256 -var iso_checksum=B202E27008FD2553F226C0F3DE4DD042E4BB7AE93CFC5B255BB23DC228A1B88E -var output_directory=P:/vmware-win7-test -var install_windowsupdates=True -var install_openssh=False -var install_firefox=False -var install_chrome=False'
    
    .EXAMPLE 3
        Build a Windows 2012 R2 from a VMWare VMX (existing VM machine) and install Windows Updates plus FLAREVM tools but no openssh. Specify a different output folder (output_directory) and explicitly select the source folder (source_path).

        Build-Template -Platform vmware -OSType windows -OSName Win2012R2 -VMSource vmx -Variables '-var source_path=./output-vmware-iso/packer-vmware-iso.vmx -var output_directory=P:/vmware-vmx-test -var install_windowsupdates=True -var install_flarevm=True -var install_openssh=False'
        
    .EXAMPLE
        asdf
        
        
    #>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateSet("vbox", "vmware", "vagrant")]
        [string]$Platform,
        [Parameter(Mandatory=$false,Position=1)]
        [ValidateSet("linux", "windows")]
        [string]$OSType = "windows",
        [Parameter(Mandatory=$true,Position=2)]
        [ValidateSet("Win2012R2", "Win2016StdCore", "Win10", "Win7", "UbuntuXenial")]
        [string]$OSName,
        [Parameter(Mandatory=$true,Position=3)]
        [ValidateSet("iso", "vmx")]
        [string]$VMSource,
        [Parameter(Mandatory=$false,Position=4)]
        [string]$Variables,
        [Parameter(Mandatory=$false,Position=5)]
        [string]$TemplatePath = ".\"
    )

    switch ($OSName)
    {
        'Win2012R2' {
            $osData = @{
                os_name = 'win2012r2'
                guest_os_type = @{vbox = 'Windows2012_64' ; vmware = 'windows8srv-64'}
                full_os_name = 'Windows2012R2'
                iso_checksum = '849734f37346385dac2c101e4aacba4626bb141c'
                iso_checksum_type = 'md5'
                iso_url = 'http://care.dlservice.microsoft.com/dl/download/6/2/A/62A76ABB-9990-4EFC-A4FE-C7D698DAEB96/9600.17050.WINBLUE_REFRESH.140317-1640_X64FRE_SERVER_EVAL_EN-US-IR3_SSS_X64FREE_EN-US_DV9.ISO'
                autounattend = './scripts/answer_file_win2012/autounattend.xml'
            }
        }

        'Win2016StdCore' {
            $osData = @{
                os_name = 'win2016stdcore'
                guest_os_type = @{vbox = 'Windows2012_64' ; vmware = 'windows9srv-64'}
                full_os_name = 'Windows2016StdCore'
                iso_checksum = '18a4f00a675b0338f3c7c93c4f131beb'
                iso_checksum_type = 'md5'
                iso_url = 'http://care.dlservice.microsoft.com/dl/download/1/6/F/16FA20E6-4662-482A-920B-1A45CF5AAE3C/14393.0.160715-1616.RS1_RELEASE_SERVER_EVAL_X64FRE_EN-US.ISO'
                autounattend = './scripts/answer_file_win2012/autounattend.xml'
            }
        }
        
        'Win10' {
            $osData = @{
                os_name = 'win2012r2'
                guest_os_type = @{vbox = 'Windows10_64' ; vmware = 'windows9-64'}
                full_os_name = 'Windows10'
                iso_checksum = '6c60f91bf0ad7b20f469ab8f80863035c517f34f'
                iso_checksum_type = 'md5'
                iso_url = 'http://care.dlservice.microsoft.com/dl/download/B/8/B/B8B452EC-DD2D-4A8F-A88C-D2180C177624/15063.0.170317-1834.RS2_RELEASE_CLIENTENTERPRISEEVAL_OEMRET_X64FRE_EN-US.ISO'
                autounattend = './scripts/answer_file_win2012/autounattend.xml'
            }
        }
        
        'Win7' {
            $osData = @{
                os_name = 'win7ent'
                guest_os_type = @{vbox = 'windows7-64' ; vmware = 'windows7-64'}
                full_os_name = 'Windows7'
                iso_checksum = '1D0D239A252CB53E466D39E752B17C28'
                iso_checksum_type = 'md5'
                iso_url = 'http://care.dlservice.microsoft.com/dl/download/evalx/win7/x64/EN/7600.16385.090713-1255_x64fre_enterprise_en-us_EVAL_Eval_Enterprise-GRMCENXEVAL_EN_DVD.iso'
                autounattend = './scripts/answer_file_win7/Autounattend.xml'
            }
        }
    }

    switch ($OSType)
    {
    
        'linux'         {$ostypex = 'Linux'}
        'windows'       {$ostypex = 'Windows'}
    
    }
    
    switch ($Platform)
    {
    
        'vbox'          {$vmplatform = $ostypex + '-vbox'}
        'vmware'        {$vmplatform = $ostypex + '-vmware'}
        'vagrant'       {$vmplatform = $ostypex + '-vagrant'}
    
    }
    
    switch ($VMSource)
    {
    
        'iso'           {$vmsourcex = $vmplatform + '-iso.json'}
        'vmx'           {$vmsourcex = $vmplatform + '-vmx.json'}
    
    }


    # Run some basic checks to make sure everything is in place before deployment
    if(!(Test-Path $TemplatePath\$vmsourcex)) {
        Write-LogFile -Message "Template $($vmsourcex) is missing, please make sure you copy it to the right folder" -MessageType Info -WriteLogToStdOut
    }

    # TODO: 
    # Read template.json
    # buiild provisioners as blocks, place blocks in a template-blocks.json file
    # read variables from pack-variables to understand which things to run in the script phase. each phase separated by a restart: initial, choco packages, cleanup
    # generate dynamic template this way, then execute, forget about packer variable shit
    
    # Build template with packer based on chosen options
    # if the user chose to overload any variables provided in variables.json, they will be inserted in the commandline with $(if($Variables){$Variables})
    
    Start-Process -FilePath 'packer.exe' -ArgumentList "build  -var-file=variables.json -var `"os_name=$($osData.os_name)`" -var `"iso_checksum=$($osData.iso_checksum)`" -var `"iso_checksum_type=$($osData.iso_checksum_type)`" -var `"iso_url=$($osData.iso_url)`" -var `"guest_os_type=$($osData.guest_os_type.platform)`" $(if($Variables){$Variables}) .\$($vmsourcex)" -Wait -NoNewWindow

}

Function ConvertFrom-JsonV2 {

    <#

    .SYNOPSIS
    Simple helper function to convert to JSON compatible with Powershell V2.0

    #>

    Param ( 
        [Parameter(Mandatory=$True)]
        [Object]$Item
    )

    Add-Type -Assembly System.Web.Extensions
    $ps_js = New-Object System.Web.Script.Serialization.JavascriptSerializer

    #The comma operator is the array construction operator in PowerShell
    Return ,$ps_js.DeserializeObject($item)
}

Function ConvertTo-JsonV2 {

    <#

    .SYNOPSIS
    Simple helper function to convert to JSON compatible with Powershell V2.0

    #>

    Param ( 
        [Parameter(Mandatory=$True)]
        [Object]$Item
    )



    try {
        Add-Type -Assembly System.Web.Extensions
        $ps_js = New-Object System.Web.Script.Serialization.JavascriptSerializer
        $SerializedJSON = $ps_js.Serialize($Item)
    }

    catch [System.Management.Automation.RuntimeException] {
        $SerializedJSON = [LitJson.JsonMapper]::ToJson($Item)
    }
    catch [System.IO.FileNotFoundException] {
        $SerializedJSON = [LitJson.JsonMapper]::ToJson($Item)
    }

    Return $SerializedJSON
}

Function Write-LogFile {

    <#

    .SYNOPSIS
        Function to write message logs from this script in JSON format to a log file. When "LogAsField" is passed it will expect a hashtable of items that will be added to the log as key/value pairs passed as value to the parameter "Dictonary".

    .PARAMETER Message
        The text to be written

    .PARAMETER OutputDir
        The directory where the scan results are stored

    .PARAMETER InitializeLogFile
        When passed, the function will initiate an empty file by opening a handle to it with [System.IO.StreamWriter]

    .PARAMETER LogAsField
        It allows you to pass a dictionary (hashtable) where your keys and values will be converted to a json line. Nested keys are not supported.

    .PARAMETER LogAsIs
        It will log the line as received, without converting it to json.

    .EXAMPLE
        Todo

    #>

    Param (
        [Parameter(Mandatory=$False)]
        [string]$OutputDir,

        [Parameter(Mandatory=$False, Position=0)]
        [string]$Message,

        [Parameter(Mandatory=$False)]
        [Hashtable]$Dictionary,

        [Parameter(Mandatory=$False)]
        [ValidateSet('Memory','Disk')]
        [String[]]$InitializeLogFile = "",

        [Parameter(Mandatory=$False)]
        [ValidateSet('Error','Low','Info','Special','RemoteLog','Rare')]
        [string]$MessageType = "Info",

        [Parameter(Mandatory=$False)]
        [string]$CallingModule = $(if(Get-PSCallStack){$(Get-PSCallStack)[1].FunctionName}else{"NA"}),    
        
        [Parameter(Mandatory=$False)]
        [switch]$CreateRandomName,

        [Parameter(Mandatory=$False)]
        [switch]$LogAsField,

        [Parameter(Mandatory=$False)]
        [switch]$LogAsIs,

        [Parameter(Mandatory=$False)]
        [switch]$WriteLogToStdOut
        
    )

    # We will only proceed if this flag has not been setup somewhere in the script.
    if (!$Global:NoWriteLogFile) {

        if ($InitializeLogFile) {

            if ($CreateRandomName) {
                $Global:strLogFile = [string]([Guid]::newGuid())
            }
            else {
                $strTimeNow = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss")
                $strScanCount = (Get-ItemProperty "HKLM:\SOFTWARE\Hydro\PrinterSchedulerBAP" -Name "ScanCount").ScanCount
                If(!$strScanCount){$strScanCount = 0}

                $RandomSuffix = Get-Random
                $Global:strLogFile = "$OutputDir\$($env:computername)_hydro-bap-script-$strTimeNow-$strScanCount-$RandomSuffix.log"
            }
        }
        
        if ($InitializeLogFile -eq 'Disk') {
            # Initializing the File by opening a File StreamWriter handle to it
            # We need to do this so that the contents of the file are written to memory and only flushed to disk when 
            # we close the handle to the file. The reason is that, otherwise, the Splunk UF service blocks the file while reading it
            # and any other Powershell commands to write to file throw errors. It becomes increasingly harder to maintain if we don't
            # use the StreamWriter .NET handle. At the end of the call to Start-YaraScan the handle is closed and disposed of.
            
            $Global:objDiskFileStream = New-Object -TypeName System.IO.StreamWriter -ArgumentList $strLogFile
            
            Return
        }

        elseif ($InitializeLogFile -eq 'Memory') {
            # Initializing a Memory Stream Writter that will write each line to a memory buffer only flushing to disk at the end
            $Global:MemStream = New-Object -TypeName System.IO.MemoryStream
            $Global:StreamWritter = New-Object -TypeName System.IO.StreamWriter -ArgumentList $MemStream
            $Global:StreamWritter.AutoFlush = 1
            #$Global:objMemoryFileStream = [System.IO.FileStream]::new($Global:strLogFile, [System.IO.FileMode]::OpenOrCreate)

            Return

        }

        # Grabing Time in UTC
        $strTimeNow = (Get-Date).ToUniversalTime().ToString("yy-MM-ddTHH:mm:ssZ")
        $strScanCount = (Get-ItemProperty "HKLM:\SOFTWARE\Hydro\PrinterSchedulerBAP" -Name "ScanCount" -ErrorAction SilentlyContinue).ScanCount

        if ($LogAsField) {

            if (!$Dictionary) {
                Write-LogFile -Message "Cannot log requested Key/Value since no Dictionary parameter was provided"
                Break
                }
            
            # To keep compatibility with Powershell V2 we can't use the [ordered] accelerator
            $strLogLine = New-Object System.Collections.Specialized.OrderedDictionary
            $strLogLine.Add("timestamp", $strTimeNow)
            $strLogLine.Add("module", $CallingModule)
            $strLogLine.Add("hostname", $($env:COMPUTERNAME))
            $strLogLine.Add("scancount", $strScanCount)
            
            ForEach ($key in $Dictionary.Keys){

                $strLogLine.Add($key, $Dictionary.Item($key))
            }
        }

        else {

            if ($LogAsIs) {
                $strLogLine = $Message
            }
            else {

                # To keep compatibility with Powershell V2 we can't use the [order] accelerator
                $strLogLine = New-Object System.Collections.Specialized.OrderedDictionary
                $strLogLine.Add("timestamp", $strTimeNow)
                $strLogLine.Add("module", $CallingModule)
                $strLogLine.Add("hostname", $($env:COMPUTERNAME))
                $strLogLine.Add("scancount", $strScanCount)
                $strLogLine.Add("message", $Message)
            }
        }

        # Converting log line to JSON

        if (!$LogAsIs) {
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                $strLogLine = ConvertTo-JsonV2($strLogLine) -ErrorAction SilentlyContinue
            }
            else {
                $strLogLine = $strLogLine | ConvertTo-Json -Compress
            }
        }



        # Choosing the right StdOut Colors in case we need them
        Switch ($MessageType) {

            "Error" {
                $MessageColor = "Gray"
                $BackgroundColor = "Black"
            }
            "Info" {
                $MessageColor = "Yellow"
                $BackgroundColor = "Black"
            }
            "Low" {
                $MessageColor = "Green"
                $BackgroundColor = "DarkCyan"
            }
            "Special" {
                $MessageColor = "White"
                $BackgroundColor = "Red"
            }
            "RemoteLog" {
                $MessageColor = "DarkGreen"
                $BackgroundColor = "Green"
            }
            "Rare" {
                $MessageColor = "Black"
                $BackgroundColor = "White"
            }
        }

        # Only Log when the writer has been initialized. Otherwise do no nothing. 
        # We implement this check so that we can run modules independently without running into the issue
        # that the LofFile Writter hasn't been initialized
        if ($Global:objDiskFileStream -or $Global:MemStream) {
            # Let's write to Log File on Disk or Memory
            if ($Global:objDiskFileStream) {
                $Global:objDiskFileStream.WriteLine($strLogLine)
            }
            else {
                $Global:StreamWritter.WriteLine($strLogLine)
            }
        }

        # Checking whether we should write to the console too
        # NOTE: In PS 7 Runspaces the concept of a "HOST" doesn't exist, we should avoid using Write-Host
        if ($Host.UI.RawUI -eq "System.Management.Automation.Internal.Host.InternalHostRawUserInterface") {

            if ($Global:LogfileWriteConsole -or $WriteLogToStdOut) {
                Write-Output $strLogLine
            }
        }
        # Running from a .NET PS console v3 to v5
        else {
            if ($Global:LogfileWriteConsole -or $WriteLogToStdOut) {
                Write-Host $strLogLine -ForegroundColor $MessageColor -BackgroundColor $BackgroundColor
            }
        }
    }
}