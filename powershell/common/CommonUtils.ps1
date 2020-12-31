<#
    CYBRHUNTER SECURITY OPERATIONS :)
    Author: Diego Perez (@darkquassar)
    Version: 1.0.7
    Module: Get-SOCHelperScripts
    Description: This module contains a variety of functions to help with common tasks like creating new folders, zipping files, searching Active Directory without the RSAT module (leveraging plain .NET or ADSI), and managing Scheduled Tasks.
    Ref.: This script was adapted from code in CybrHunter (https://github.com/darkquasar/cybrhunter-armory/blob/master/powershell/Get-InteractiveMenu.ps1).
#>

# *** Getting a handle to the running script path so that we can refer to it *** #
if ($MyInvocation.MyCommand.Name) { 
    $Global:ScriptPath = New-Object -TypeName System.IO.DirectoryInfo -ArgumentList $(Split-Path -Parent $MyInvocation.MyCommand.Definition)
} 
else {
    $Global:ScriptPath = New-Object -TypeName System.IO.DirectoryInfo -ArgumentList $(Get-Location)
}

## ***** BEGIN ADD NATIVE ASSEMBLIES ***** ##

<# Some C# code to allow us to run a process in the background without blocking the main application. We can achieve the same with many other Powershell commandlets but I wanted to test doing it with .NET <-->

To use it
    (1) Get a handle to a Process object
    $objProcess = Start-SharpProcess -ExecutablePath $BinaryFullPath -Arguments $ProcArgs -EnableRaisingEvents $True -UseShellExecute $False -CreateNoWindow $True -RedirectStandardOutput $False -RedirectStandardError $False -ExecutableWorkingDir $BinaryPath

    (2) We now need to start this process using a .NET Task handler so that it doesn't block the main script's thread
    The object stored here is of type System.Threading.Tasks.TaskCompletionSource
    [System.Threading.Tasks.TaskCompletionSource[int]]$ProcessTask = [CybrHunter.BackgroundProcess]::RunProcessAsyncP($objProcess)
#>

if ($PSVersionTable.PSVersion.Major -ne 2) {

$Sharp01 = @'
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

namespace CybrHunter {

    public class BackgroundProcess {

        public static System.Threading.Tasks.TaskCompletionSource<int> RunProcessAsyncP(Process process)
        {
            var tcs = new TaskCompletionSource<int>();

            process.Exited += (s, ea) => tcs.SetResult(process.ExitCode);

            bool started = process.Start();
            if (!started)
            {
                throw new InvalidOperationException("Failed to start process: " + process);
            }

            return tcs;
        }
    }
}
'@

    Add-Type -TypeDefinition $Sharp01
}


## ***** END ADD NATIVE ASSEMBLIES ***** ##

# ***** SETUP SOME GLOBAL VARS ***** ##

Function ConvertTo-GZipCompressedByteArray {

    <#

    .SYNOPSIS
        Function to convert a file or string to a compressed byte array.

    .DESCRIPTION
        Function to convert a file or string to a compressed byte array. It will return a byte array representing the compressed object.

    .PARAMETER StringToCompress
        A string that you would like to compress using GZip

    .PARAMETER ByteArrayToCompress
        The DN of the base directory to search from.

    .PARAMETER ObjectToCompress
        The object that requires compression: a string, a byte array or a file. In any case all non-byte array objects are converted to byte arrays.

    .EXAMPLE
        Todo

    #>

    Param (
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [String]$StringToCompress,

        [Parameter(Mandatory=$False)]
        [byte[]]$ByteArrayToCompress,

        [Parameter(Mandatory=$False)]
        [String]$FilePath,

        [Parameter(Mandatory=$True)]
        [ValidateSet("string", "file", "bytearray")]
        [String]$ObjectToCompress

    )
    
    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    ### Configure GZip Stream
    [System.IO.MemoryStream]$CompressedMemStream = [System.IO.MemoryStream]::new()
    $GZipCompressionStream = [System.IO.Compression.GZipStream]::new($CompressedMemStream, ([System.IO.Compression.CompressionMode]::Compress))

    switch ($ObjectToCompress) {

        string { 
            [System.Text.Encoding] $StringEncoder = [System.Text.Encoding]::UTF8
            [byte[]] $EncodedString = $StringEncoder.GetBytes( $StringToCompress )

            ### COMPRESS
            $GZipCompressionStream.Write($EncodedString, 0, $EncodedString.Length)
            $GZipCompressionStream.Close()
            $CompressedMemStream.Close()
            
            return $CompressedMemStream.ToArray()
         }

        file { 
            $FileBytes = [IO.File]::ReadAllBytes($FilePath)

            ### COMPRESS
            $GZipCompressionStream.Write($FileBytes, 0, $FileBytes.Length)
            $GZipCompressionStream.Close()
            $CompressedMemStream.Close()
            
            return $CompressedMemStream.ToArray()
        }

        bytearray {
            ### COMPRESS
            $GZipCompressionStream.Write($ByteArrayToCompress, 0, $ByteArrayToCompress.Length)
            $GZipCompressionStream.Close()
            $CompressedMemStream.Close()
            
            return $CompressedMemStream.ToArray()
        }

    }

}

Function ConvertFrom-GZipCompressedByteArray {

    <#

    .SYNOPSIS
        Function to convert a file or string back to its original byte representation from a compressed byte array.

    .DESCRIPTION
        Function to convert a file or string back to its original byte representation from a compressed byte array. It will return a byte array representing the decompressed object.

    .PARAMETER CompressedByteArray
        A string that you would like to compress using GZip

    .EXAMPLE
        Todo

    #>

    Param (
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [String]$StringToCompress,

        [Parameter(Mandatory=$False)]
        [byte[]]$ByteArrayToCompress,

        [Parameter(Mandatory=$False)]
        [String]$FilePath,

        [Parameter(Mandatory=$False)]
        [ValidateSet("string", "file", "bytearray")]
        [String]$ObjectToCompress

    )
    
    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    ### Configure GZip Stream
    [System.IO.MemoryStream]$CompressedMemStream = [System.IO.MemoryStream]::new()
    $GZipCompressionStream = [System.IO.Compression.GZipStream]::new($CompressedMemStream, ([System.IO.Compression.CompressionMode]::Compress))

    ### DECOMPRESS
    $Input = New-Object System.IO.MemoryStream( , $CompressedMemStream.ToArray() )
    $DecompressedMemStream = [System.IO.MemoryStream]::new()
    #$DecompressedMemStream = [System.IO.File]::Create("mierda3.txt")
    $GZipDecompressionStream = [System.IO.Compression.GZipStream]::new($Input, [System.IO.Compression.CompressionMode]::Decompress)
    $GZipDecompressionStream.CopyTo($DecompressedMemStream)
    Write-Output "Decompressed Stream:", $DecompressedMemStream

    switch ($ObjectToCompress) {

        string { 
            [System.Text.Encoding] $StringEncoder = [System.Text.Encoding]::UTF8
            [byte[]] $EncodedString = $StringEncoder.GetBytes($StringToCompress)

            ### COMPRESS
            $GZipCompressionStream.Write($EncodedString, 0, $EncodedString.Length)
            $GZipCompressionStream.Close()
            $CompressedMemStream.Close()
            
            return $CompressedMemStream.ToArray()
         }

        file { 
            $FileBytes = [IO.File]::ReadAllBytes($FilePath)

            ### COMPRESS
            $GZipCompressionStream.Write($FileBytes, 0, $FileBytes.Length)
            $GZipCompressionStream.Close()
            $CompressedMemStream.Close()
            
            return $CompressedMemStream.ToArray()
        }

        bytearray {
            ### COMPRESS
            $GZipCompressionStream.Write($ByteArrayToCompress, 0, $ByteArrayToCompress.Length)
            $GZipCompressionStream.Close()
            $CompressedMemStream.Close()
            
            return $CompressedMemStream.ToArray()
        }

    }

}

Function Convert-ByteArrayToString {

    <#

    .SYNOPSIS
        Function to convert a byte array to its string representation.


    .PARAMETER ByteArray
        The byte array you wish to convert

    .EXAMPLE
        Todo

    #>

    Param (
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [byte[]]$ByteArray

    )
    
    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    [System.Text.Encoding] $StringEncoder = [System.Text.Encoding]::UTF8
    $StringEncoder.GetString( $ByteArray ) | Out-String

}


<#
Example Importing PoshSSH From Memory

$poshsshdll = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Downloads\PoshSSH.dll"))
$rencisshdll = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Downloads\Renci.SshNet.dll"))

$ByteArrayPoshSSHDLL = [System.Convert]::FromBase64String($poshsshdll)
$PoshSSHInMemoryAssembly = [System.Reflection.Assembly]::Load($ByteArrayPoshSSHDLL)

$ByteArrayRenciSSHDLL = [System.Convert]::FromBase64String($rencisshdll)
$RenciSSHInMemoryAssembly = [System.Reflection.Assembly]::Load($ByteArrayRenciSSHDLL)

Import-Module -Assembly $ByteArrayPoshSSHDLL
Import-Module -Assembly $RenciSSHInMemoryAssembly

#>

function Convert-LDAPProperty {
    <#
    .SYNOPSIS

    Helper that converts specific LDAP property result fields and outputs
    a custom psobject.

    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: None

    .DESCRIPTION

    Converts a set of raw LDAP properties results from ADSI/LDAP searches
    into a proper PSObject. Used by several of the Get-Net* function.

    .PARAMETER Properties

    Properties object to extract out LDAP fields for display.

    .OUTPUTS

    System.Management.Automation.PSCustomObject

    A custom PSObject with LDAP hashtable properties translated.
    #>

    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        #Write-Host $_
        if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0], 0)).Value
        }
        elseif ($_ -eq 'objectguid') {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif ($_ -eq 'ntsecuritydescriptor') {
            $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
        }
        elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                # otherwise just a string
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
            # try to convert misc com objects
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {

                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif ($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}
Function Get-HostChecks {

    <#
 
     .SYNOPSIS
         Function that performs different types of checks on target workstations (existence of files, paths, registry keys, etc.)
 
     .PARAMETER Hostname
         The target machine to query

     .PARAMETER UseWinRM
         For some commands, this parameter will first attempt to perform the check over a WinRM connection rather than using other methods (like WMI or SMB)
 
     #>
 
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Hostname,

        [Parameter(Mandatory=$True)]
        [ValidateSet('CheckFullPath','CheckTargetOSVersion','CheckTargetProcessorArchitecture', 'CheckScheduledTask')]
        [string]$CheckType,

        [Parameter(Mandatory=$False)]
        [string]$TargetPathOrFile,

        [Parameter(Mandatory=$False)]
        [string]$ScheduledTaskName,

        [Parameter(Mandatory=$False)]
        [Switch]$UseWinRM,

        [Parameter(Mandatory=$False)]
        [int]$MaxAttempts = 3,

        [Parameter(Mandatory=$False)]
        [int]$RetryIntervalSeconds = 15

    )

    $AttemptCount = 0
    While ($AttemptCount -ne $MaxAttempts) {

        Switch ($CheckType) {

            "CheckFullPath" {

                Try {

                    # *** Check whether required arguments have been passed *** #
                    # ********************************************************* #
                    If(!$TargetPathOrFile) {
                        Write-LogFile -Message "TargetPathOrFile Parameter Required. Exiting." -MessageType Info
                        Break
                    }

                    # Splitting path and root drive
                    $RootDrive = $TargetPathOrFile.Split("\")[0]
                    $SMBRootDrive = $RootDrive.Replace(":", "$")
                    $RelativePath = $TargetPathOrFile.Replace($RootDrive, "").TrimStart("\")

                    # Run check over WinRM (preferred)
                    If($UseWinRM) {
                        
                        Write-LogFile -Message "Checking whether $TargetPathOrFile is present on $Hostname over WinRM..." -MessageType Info
                        $FullPathTestResult = Invoke-Command -ScriptBlock { Test-Path $using:TargetPathOrFile } -ComputerName $Hostname

                        If($FullPathTestResult) {
                            Write-LogFile -Message "$TargetPathOrFile present on $Hostname" -MessageType Info
                            Return @($True)
                        }
                        Else {
                            Write-LogFile -Message "$TargetPathOrFile missing on $Hostname" -MessageType Info
                            Return @($False, "NA")
                        }
                    }

                    # Run check over other methods (non-WinRM)
                    Else {

                        Write-LogFile -Message "Checking whether $TargetPathOrFile is present on $Hostname using SMB..." -MessageType Info
                        $FullPathTestResult = Get-Item "\\$Hostname\$SMBRootDrive\$RelativePath"

                        If($FullPathTestResult) {
                            Write-LogFile -Message "$TargetPathOrFile present on $Hostname" -MessageType Info
                            Return @($True)
                        }
                        Else {
                            Write-LogFile -Message "$TargetPathOrFile missing on $Hostname" -MessageType Info
                            Return @($False)
                        }
                    }

                }

                Catch [System.Management.Automation.ItemNotFoundException] { 
                    Write-LogFile -Message "SMB Check Failed to test $TargetPathOrFile App on $Hostname. Path is possibly missing" -MessageType Error
                    Return @("FailedQuery", [System.Management.Automation.ItemNotFoundException])
                }

                Catch [System.Management.Automation.Remoting.PSRemotingTransportException] { 
                    Write-LogFile -Message "WinRM cannot process the request. Powershell Remoting issue." -MessageType Error
                    Return @("UnknownWinRMError", [System.Management.Automation.Remoting.PSRemotingTransportException])
                }

                # Catch All
                Catch {
                    Write-LogFile -LogError $_ -Message "Weird Black Magic is protecting target host..." -MessageType Error
                    Return @("FailedQuery", $ErrorNameSpace)
                }
            }

            "CheckTargetOSVersion" {

                Try {

                    # Run check over WinRM
                    If($UseWinRM) {
                        $OSVersion = Invoke-Command -ScriptBlock { Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object Caption } -ComputerName $Hostname
                    }

                    # Run check over WMI (preferred, it's faster)
                    Else {
                        $OSVersion = Get-CimInstance -Computer $Hostname -Query "SELECT * FROM Win32_OperatingSystem" -ErrorAction SilentlyContinue | Select-Object Caption
                    }

                    If(!$OSVersion) {
                        Throw "UnableToGetInfo on $Hostname"
                    }

                    $OSVersion = $OSVersion.Caption
                    $OSVersion =  [regex]::Match($OSVersion, "2003|2008|7|10|2012|2016|2019").Value
                    Write-LogFile -Message "$Hostname OS Version: $OSVersion" -MessageType Low
                    Return $OSVersion

                }

                Catch [System.Runtime.InteropServices.COMException] { 
                    Write-LogFile -Message "COMException, cannot connect via WMI" -MessageType Error
                    Return @("FailedQuery", [System.Runtime.InteropServices.COMException])
                }

                Catch [System.Management.Automation.Remoting.PSRemotingTransportException] { 
                    Write-LogFile -Message "WinRM cannot process the request. Powershell Remoting issue." -MessageType Error
                    Return @("UnknownWinRMError", [System.Management.Automation.Remoting.PSRemotingTransportException])
                }

                # Catch All
                Catch {

                    If ($Error[0].Exception -eq "UnableToGetInfo") {
                        Write-LogFile -Message "Unable to get Information" -MessageType Error
                    }

                    Write-LogFile -LogError $_ -Message "Weird Black Magic is protecting target host..." -MessageType Error
                    Return @("FailedQuery", $ErrorNameSpace)
                }
            }

            "CheckTargetProcessorArchitecture" {
                Try {

                    # Run check over WinRM (preferred)
                    If($UseWinRM) {
                        $ProcessArch = Invoke-Command -ScriptBlock { Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue | Select-Object AddressWidth } -ComputerName $Hostname   
                    }

                    Else {
                        $ProcessArch = Get-CimInstance -Computer $Hostname -Query "SELECT * FROM Win32_Processor" -ErrorAction SilentlyContinue | Select-Object AddressWidth
                    }

                    If(!$ProcessArch) {
                        Throw "UnableToGetInfo"
                    }

                    $ProcessArch = $ProcessArch[0].AddressWidth
                    Write-LogFile -Message "$Hostname Process Architecture: x$ProcessArch"
                    Return $ProcessArch
                }

                Catch [System.Runtime.InteropServices.COMException] {
                    Write-LogFile -Message "COMException, cannot connect via WMI" -MessageType Error
                    Return @("FailedQuery", [System.Runtime.InteropServices.COMException])
                }

                Catch [System.Management.Automation.Remoting.PSRemotingTransportException] { 
                    Write-LogFile -Message "WinRM cannot process the request. Powershell Remoting issue." -MessageType Error
                    Return @("UnknownWinRMError", [System.Management.Automation.Remoting.PSRemotingTransportException])
                }

                # Catch All
                Catch {

                    If ($Error[0].Exception -eq "UnableToGetInfo") {
                        Write-LogFile -LogError $_ -Message "Weird Black Magic is protecting target host..." -MessageType Error
                    }

                    Write-LogFile -LogError $_ -Message "Weird Black Magic is protecting target host..." -MessageType Error
                    Return @("FailedQuery", "NA")
                }
            }

            "CheckScheduledTask" {

                Try {

                    # *** Check whether required arguments have been passed *** #
                    # ********************************************************* #
                    If(!$ScheduledTaskName) {
                        Write-LogFile -Message "ScheduledTaskName Parameter Required. Exiting." -MessageType Info
                        Break
                    }

                    Write-LogFile -Message "Checking whether Task $ScheduledTaskName is installed on $Hostname..." -MessageType Info
                    
                    # Listing tasks in %SystemRoot%\System32\Tasks
                    If($UseWinRM) {

                        $ScheduledTaskList = (Invoke-Command { Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\*" } -ComputerName $Hostname).path

                    }

                    Else {

                        $RegHandle = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $Hostname)
                        $TaskSubKeys = ($RegHandle.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks')).GetSubKeyNames()
                        [System.Collections.ArrayList]$ScheduledTaskList = @()

                        ForEach($Subkey in $TaskSubKeys) {
                            $RegKey = $RegHandle.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\$Subkey")
                            $ScheduledTaskList.Add($RegKey.GetValue("path")) | Out-Null
                        }

                    }

                    If(($ScheduledTaskList).Count -ne 0) {

                        ForEach($Task in $ScheduledTaskList) {

                            $ScheduledTaskPresent = $Task | Select-String $ScheduledTaskName
                            
                            If ($ScheduledTaskPresent) {
                                Write-LogFile -Message "Task $ScheduledTaskName installed on $Hostname" -MessageType Info
                                Return $True
                            }
                            
                        }

                        If (!$ScheduledTaskPresent) {
                            Write-LogFile -Message "Task $ScheduledTaskName NOT installed on $Hostname" -MessageType Info
                            Return $False
                        }
                    }

                }

                Catch [System.Management.Automation.MethodInvocationException] { 
                    Write-LogFile -Message -LogError $_ "Could not connect over WinRM or RPC to $Hostname for Scheduled Task Checks" -MessageType Error
                    Return @("FailedQuery", [System.Management.Automation.MethodInvocationException])

                }

                Catch [System.Management.Automation.RemoteException] {
                    Write-LogFile -Message -LogError $_ "Failed Scheduled Tasks check for $Hostname." -MessageType Error
                    Return @("FailedQuery", [System.Management.Automation.RemoteException])
                }

                Catch [System.Management.Automation.Remoting.PSRemotingTransportException] { 
                    Write-LogFile -Message -LogError $_ "WinRM cannot process the request. Powershell Remoting issue." -MessageType Error
                    Return @("UnknownWinRMError", [System.Management.Automation.Remoting.PSRemotingTransportException])
                }

                # Catch All
                Catch {
                    Write-LogFile -LogError $_ -Message "Weird Black Magic is protecting target host..." -MessageType Error
                    Return @("FailedQuery", $ErrorNameSpace)
                }
            }

        }

        # Incrementing counter & sleeping before next attempt
        $AttemptCount++
        Start-Sleep $RetryIntervalSeconds

    }
}

Function Start-SharpProcess {

    <#

    .DESCRIPTION
        This function will start a process in the background using native .NET assemblies. 

    #>

    Param ( 

      [Parameter(Mandatory=$True)]
      [string]$ExecutablePath,

      [Parameter(Mandatory=$True)]
      [string]$ExecutableWorkingDir,

      [Parameter(Mandatory=$True)]
      [string]$Arguments,

      [Parameter(Mandatory=$False)]
      [Bool]$EnableRaisingEvents,

      [Parameter(Mandatory=$False)]
      [Bool]$UseShellExecute,

      [Parameter(Mandatory=$False)]
      [Bool]$CreateNoWindow,

      [Parameter(Mandatory=$False)]
      [Bool]$RedirectStandardOutput,

      [Parameter(Mandatory=$False)]
      [Bool]$RedirectStandardError

    )

    # Let's instantiate a new ProcessStartInfo object to hold all the properties of our new process
    [System.Diagnostics.ProcessStartInfo]$ProceStartInfo = ""
    $ProceStartInfo.FileName = $ExecutablePath
    $ProceStartInfo.WorkingDirectory = $ExecutableWorkingDir
    $ProceStartInfo.Arguments = $Arguments
    $ProceStartInfo.UseShellExecute = $UseShellExecute
    $ProceStartInfo.CreateNoWindow = $CreateNoWindow
    $ProceStartInfo.RedirectStandardOutput = $RedirectStandardOutput
    $ProceStartInfo.RedirectStandardError = $RedirectStandardError

    # Let's now create a new Process object and assign it our ProcessStartInfo configuration
    $objProcess = New-Object System.Diagnostics.Process
    $objProcess.StartInfo = $ProceStartInfo
    $objProcess.EnableRaisingEvents = $EnableRaisingEvents

    # Returning a handle to the process object
    Return $objProcess
}

Function Get-FileHashV2 {

    <#
    .SYNOPSIS
        Get-Hash is a PowerShell Version 2 port of Get-FileHash that supports hashing files, as well as, strings.

    .PARAMETER InputObject
        This is the actual item used to calculate the hash. This value will support [Byte[]] or [System.IO.Stream] objects.

    .PARAMETER FilePath
        Specifies the path to a file to hash. Wildcard characters are permitted.

    .PARAMETER Text
        A string to calculate a cryptographic hash for.

    .PARAMETER Encoding
        Specified the character encoding to use for the string passed to the Text parameter. The default encoding type is Unicode. The acceptable values for this parameter are:
        - ASCII
        - BigEndianUnicode
        - Default
        - Unicode
        - UTF32
        - UTF7
        - UTF8

    .PARAMETER Algorithm
        Specifies the cryptographic hash function to use for computing the hash value of the contents of the specified file. A cryptographic hash function includes the property that it is not possible to find two distinct inputs that generate the same hash values. Hash functions are commonly used with digital signatures and for data integrity. The acceptable values for this parameter are:
        
        - SHA1
        - SHA256
        - SHA384
        - SHA512
        - MACTripleDES
        - MD5
        - RIPEMD160
        
        If no value is specified, or if the parameter is omitted, the default value is SHA256.
        For security reasons, MD5 and SHA1, which are no longer considered secure, should only be used for simple change validation, and should not be used to generate hash values for files that require protection from attack or tampering.

    .NOTES
    
        This function was adapted from https://p0w3rsh3ll.wordpress.com/2015/02/05/backporting-the-get-filehash-function/
        Author: Jared Atkinson (@jaredcatkinson)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .EXAMPLE
        Get-Hash -Text 'This is a string'

    .EXAMPLE
        Get-Hash -FilePath C:\This\is\a\filepath.exe
    #>

    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        [ValidateNotNullOrEmpty()]
        $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
        [string]
        [ValidateNotNullOrEmpty()]
        $Text,

        [Parameter(ParameterSetName = 'Text')]
        [string]
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Default', 'Unicode', 'UTF32', 'UTF7', 'UTF8')]
        $Encoding = 'Unicode',

        [Parameter()]
        [string]
        [ValidateSet("MACTripleDES", "MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512")]
        $Algorithm = "SHA256"
    )

    switch($PSCmdlet.ParameterSetName)
    {
        File
        {
            try
            {
                $FullPath = Resolve-Path -Path $FilePath -ErrorAction Stop
                $InputObject = [System.IO.File]::OpenRead($FilePath)
                Get-FileHashV2 -InputObject $InputObject -Algorithm $Algorithm
            }
            catch
            {
                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $null
                }
            }
        }
        Text
        {
            $InputObject = [System.Text.Encoding]::$Encoding.GetBytes($Text)
            Get-FileHashV2 -InputObject $InputObject -Algorithm $Algorithm
        }
        Object
        {
            if($InputObject.GetType() -eq [Byte[]] -or $InputObject.GetType().BaseType -eq [System.IO.Stream])
            {
                # Construct the strongly-typed crypto object
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)

                # Compute file-hash using the crypto object
                [Byte[]] $computedHash = $Hasher.ComputeHash($InputObject)
                [string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''

                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                }

                $retVal
            }
        }
    }
}

Function New-Folder {

    <#

    .DESCRIPTION
        This helper function will create/delete folders.

    .EXAMPLE
        New-Folder -Dir C:\dfir_tools\kape\memory
        New-Folder -Dir C:\dfir_tools\kape\memory -Delete

    #>

    Param ( 

      [Parameter(Mandatory=$True)]
      [string]$Dir,

      [Parameter(Mandatory=$False)]
      [Switch]$Delete=$False

    )

    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    if (!(Get-Item $Dir -ErrorAction SilentlyContinue) -eq 1) {

        
        New-Item -ItemType Directory -Path $Dir -Force
        Write-LogFile -Message "Created new folder $Dir" -MessageType Low
        
    }
    
    # Folder already exists
    else {

        if ($Delete) {
            Remove-Item -Path "$Dir" -Recurse -Force
            Write-LogFile -Message "Deleted folder $Dir" -MessageType Low
        }
    }

    $Path = New-Object -TypeName System.IO.DirectoryInfo -ArgumentList $Dir
    Return $Path

    if ($([System.Uri]$Dir).IsUnc -eq $True) {
      #Write-LogFile -Message "Output Directory is a UNC path"
    }
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

Function ConvertTo-HashTable {
    # Ref: https://4sysops.com/archives/convert-json-to-a-powershell-hash-table/

    [CmdletBinding()]
    [OutputType('hashtable')]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        $InputObject
    )

    Process {
        ## Return null if the input is null. This can happen when calling the function
        ## recursively and a property is null
        if ($null -eq $InputObject) {
            Return $null
        }

        ## Check if the input is an array or collection. If so, we also need to convert
        ## those types into hash tables as well. This function will convert all child
        ## objects into hash tables (if applicable)
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $collection = @(
                foreach ($object in $InputObject) {
                    ConvertTo-Hashtable -InputObject $object
                }
            )

            ## Return the array but don't enumerate it because the object may be pretty complex
            Write-Output -NoEnumerate $collection
        } elseif ($InputObject -is [psobject]) { ## If the object has properties that need enumeration
            ## Convert it to its own hash table and return it
            $hash = @{}
            foreach ($property in $InputObject.PSObject.Properties) {
                $hash[$property.Name] = ConvertTo-Hashtable -InputObject $property.Value
            }
            $hash
        } else {
            ## If the object isn't an array, collection, or other object, it's already a hash table
            ## So just return it.
            $InputObject
        }
    }
}

Function Start-IonicZipDir {

    <#
 
     .SYNOPSIS
         Function that uses DotNetZip Library (Ionic.Zip) to compress/extract directories. You must provide a path to the dll.
 
     .PARAMETER TargetDirectory
         The target directory to compress

     .PARAMETER Action
         The type of action to be peformed: zip or unzip.

     .PARAMETER ZippedFile
         The zipped file to extract.

     .PARAMETER DestinationPath
         Depending on the action chosen, the parameter will either specify the relative/full path for the output .zip file ("zip") or the relative/full path of the directory where a compressed file will be extracted (unzip).

     .PARAMETER ExcludeFiles
         Remove files from the zipped file. Useful when you want to zip a whole directory and exclude some files from it. You can use simple patterns like "*.sqlite" or "*template*".
 
     #>
 
    Param (

        [Parameter(Mandatory=$True)]
        [string]$PathToIonicZIP,

        [Parameter(Mandatory=$True)]
        [string]$TargetDirectory,

        [Parameter(Mandatory=$True)]
        [ValidateSet('zip','unzip')]
        [string]$Action,

        [Parameter(Mandatory=$False)]
        [string]$ZippedFile,

        [Parameter(Mandatory=$False)]
        [string]$DestinationPath,

        [Parameter(Mandatory=$False)]
        [array]$ExcludeFiles

    )

    try {
        # // NOTE: Current version of DotNetZip can be found in: https://github.com/haf/DotNetZip.Semverd
        Add-Type -Path $PathToIonicZIP
    }
    catch {
        Write-Host "Could not load Ionic.Zip dll"
        return
    }

    If($Action -eq "zip") {

        $zip = New-Object -TypeName Ionic.Zip.ZipFile
        $zip.AddDirectory($TargetDirectory)

        if ($ExcludeFiles) {
            foreach ($FileName in $ExcludeFiles) {
                $zip.RemoveSelectedEntries($FileName)
            }
        }
        
        $zip.Save($DestinationPath)

    }

    Elseif($Action -eq "unzip") {
        $zipfile = [Ionic.Zip.ZipFile]::Read($ZippedFile)
        $zipfile.ExtractAll($DestinationPath, [Ionic.Zip.ExtractExistingFileAction]::OverwriteSilently)
    }
    
}

Function Get-NetworkConnectivityStatus {

    <#

    .DESCRIPTION
        This helper function will check whether the host has connectivity to a network and if so, whether there is connectivity to the corporate domain.

    .PARAMETER DomainControllersList
        The list of domain controllers to use as monitoring endpoint to check domain connectivity

    #>

    Param (

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [array]$DomainControllersList

    )

    if (!$DomainControllersList) {
        # Obtain the list of DCs using LDAP and .NET
        $CurrentDomain = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://rootDSE").Get("ldapServiceName")
        $CurrentDomain = $CurrentDomain.split(":")[0]
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList ('Domain', $CurrentDomain)
        $objDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)

        # Check if Powershell v2 is running to determine whether we should create an Array insted of 
        # letting Posh infer it
        $OldOSSystem = $PSVersionTable.CLRVersion.Major -le 2
        if ($OldOSSystem -eq $True) {
            $DomainControllersList = $objDomain.DomainControllers | foreach-object { $_.Name }
        }
        else {
            $DomainControllersList = $objDomain.DomainControllers.Name
        }
    }

    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    # If there is at least one interface connected to the Domain we will catch it with this WMI query
    Write-LogFile -Message "Checking for Domain connectivity" -MessageType Low

    # We don't need all DCs here, if a client is able to reach at least one of them it should be enough

    ForEach ($DC in $DomainControllersList) {

        Try {

            $boolDCTest = Test-ComputerSecureChannel -Server $DC -ErrorAction SilentlyContinue
            # If we have connectivity with at least one of these DCs, then we don't need to know more
            if ($boolDCTest -eq $True) {Break}
        }

        # Catch [System.InvalidOperationException], [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException]
        Catch [System.OutOfMemoryException] {
            # This error might happen on old systems or hosts that haven't been rebooted in a long time.
            Write-LogFile -Message "The current system ran out of memory to perform this check"
        }

        Catch {
            Write-LogFile -LogError $_ -Message "[Get-NetworkConnectivityStatus] - Hostname might not exist" -MessageType Error -Verbose
            Continue 
        }
    }


    if ($boolDCTest) {
        # There is domain connectivity, let's set the appropriate registry key
        Write-LogFile -Message "Domain connectivity is healthy" -MessageType Low
        Return $True
    }

    else {
        # If we get to this clause it means there is no active connection to the Domain.
        # We need to signal the script that the status of connectivity is "False" (NOTE: If a scanning process is actively running: do nothing and let the scan run but set a registry flag indicating connection has been lost)
        Write-LogFile -Message "Domain connectivity lost" -MessageType Error
        Return $False
    }

}

Function Invoke-DBAttributeChange {

    <#

    .DESCRIPTION
        This helper function will get or set properties in the registry or a SQLite DB.

    .PARAMETER ActionType
        The type of action that will be performed on the backend attribute: get or set.

    #>

    [cmdletbinding(DefaultParameterSetName='Get')]

    Param (

        [Parameter(Mandatory=$True, ParameterSetName="Get")]
        [Parameter(Mandatory=$True, ParameterSetName="Set")]
        [ValidateSet('Get', 'Set')]
        [string]$ActionType,

        [Parameter(Mandatory=$False, ParameterSetName="Get")]
        [Parameter(Mandatory=$False, ParameterSetName="Set")]
        [ValidateSet('Registry', 'SQLiteDB')]
        [string]$BackEndDB="Registry",

        [Parameter(Mandatory=$False, ParameterSetName="Get")]
        [Parameter(Mandatory=$False, ParameterSetName="Set")]
        [string]$RegistryKeyBase="",

        [Parameter(Mandatory=$True, ParameterSetName="Get")]
        [Parameter(Mandatory=$True, ParameterSetName="Set")]        
        [Parameter(Mandatory=$True)]
        [string]$Attribute,

        [Parameter(Mandatory=$True, ParameterSetName="Set")]
        [AllowEmptyString()]
        [string]$AttributeValue

    )

    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    switch($BackEndDB) {

        Registry {
            if (!$RegistryKeyBase) {
                Write-LogFile -Message "Cannot proceed without a Registry Key Base, ex: HKLM:\SOFTWARE\Something"
                break
            }
            $DBBaseKey = $RegistryKeyBase
            $DBAttribute = $Attribute
        }

        SQLiteDB {
            Write-Host "TBD"
        }

    }

    try {

        switch($ActionType) {

            Get {

                $Results = (Get-ItemProperty $DBBaseKey -Name $DBAttribute -ErrorAction SilentlyContinue).$DBAttribute

                if($null -ne $Results) {
                    if ($Results.Length -ne 0) {
                        Return $Results
                    }
                    else {
                        # if attempting to get the value of a key without value
                        # preemptively fill it with a zero
                        Set-ItemProperty $DBBaseKey -Name $DBAttribute -Value 0
                        $Results = (Get-ItemProperty $DBBaseKey -Name $DBAttribute -ErrorAction SilentlyContinue).$DBAttribute
                        Return $Results
                    }
                    
                }
                else {
                    Return $False
                }
                
            }

            Set {
                if($AttributeValue -eq "") {
                    $AttributeValue = $null
                }
                Set-ItemProperty $DBBaseKey -Name $DBAttribute -Value $AttributeValue
            }
        }
    }
    catch {
        Write-LogFile -LogError $_ -Message "Could not get or set backend database key" -MessageType Error
    }
}

Function Find-ADGroupMembership {

    <#

    .SYNOPSIS
        Function to determine whether a host account is part of a particular AD Group. It RETURNS the [System.DirectoryServices.DirectoryEntry] Group instance the object belongs to.

    .DESCRIPTION
        This function searches a specific AD Group to determine whether a particular host account is a member of an AD Security Group.
        We use it to define whether a scan should be run on a host or not based on membership to an AD control group.
        The root DN that the script will begin its search from is limited to the scope of the OU where the actual security group resides. We do this in order to improve query performance.

    .PARAMETER AccountName
        The name of the account whose membership we want to determine.

    .PARAMETER ADGroup
        The name of the group whose members will be iterated through.

    .PARAMETER SearchGroupsAccountIsMemberOf
        When selected, this option will use the ADSI LDAP_MATCHING_RULE_IN_CHAIN property to traverse the object's ancestry and return all matches for a particular account. When no base AD Group object is specified with the parameter "BaseADGroupMembershipFQDN" then the root domain will be considered as the base.

    .PARAMETER BaseADGroupMembershipFQDN
        When specified, this option will only apply the recursive search selected by SearchGroupsAccountIsMemberOf to test for the membership of the account to the particular AD Group passed as argument. Only the SamAccountName of the AD Group is expected, not it's DN.

    .PARAMETER StringFilter
        A simple string filter that will be matched against each returned LDAP path. If the string matches the LDAP path, then the entry will be added to the results.

    .EXAMPLE
        Todo

    #>
    
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    Param (

        [Parameter(Mandatory=$False)]
        [string]$BaseDomain = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://rootDSE").Get("defaultNamingContext"),

        [Parameter(Mandatory=$True)]
        [string]$AccountName,

        [Parameter(Mandatory=$True)]
        [ValidateSet('Computer', 'User', 'Group')]
        [string]$AccountType,

        [Parameter(Mandatory=$False)]
        [string]$ADGroup,

        [Parameter(Mandatory=$False)]
        [Switch]$SearchGroupsAccountIsMemberOf,

        [Parameter(Mandatory=$False)]
        [string]$BaseADGroupMembershipFQDN,

        [Parameter(Mandatory=$False)]
        [string]$StringFilter=""

    )

    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    # ***** PARAMETER VALIDATION *****
    # First lets make sure we are passing the right machine account string
    if ((!$AccountName.EndsWith("$")) -AND ($AccountType -eq "Computer")){ $AccountName = $AccountName + "$" }

    # Now let's make sure we have a Full DistinguisedName (DN) for the BaseADGroupMembershipFQDN parameter
    # Otherwise, attempt to resolve
    if ($BaseADGroupMembershipFQDN) {
        if($BaseADGroupMembershipFQDN -notlike "CN=*") {
            $BaseADGroupMembershipDN = Find-ADAccount -ADAccount $BaseADGroupMembershipFQDN -ADAccountType Group -ADBaseDir $BaseDomain

            # Check to fix PSv2 issues with returning a hashtable with "0" (operation successful) and the actual object
            if ($BaseADGroupMembershipDN.GetType().BaseType -eq [System.Array]) {
                $strBaseADGroupMembershipDN = $BaseADGroupMembershipDN[1].distinguishedName
                $ldappathBaseADGroupMembershipDN = $BaseADGroupMembershipDN[1].path
            }
            else {
                $strBaseADGroupMembershipDN = $BaseADGroupMembershipDN.distinguishedName
                $ldappathBaseADGroupMembershipDN = $BaseADGroupMembershipDN.path
            }
        }
        else {
			$strBaseADGroupMembershipDN = $BaseADGroupMembershipFQDN
		}
    }

    if ($AccountName -notlike "CN=*") {
        $objADAccountEntry = Find-ADAccount -ADAccount $AccountName -ADAccountType $AccountType -ADBaseDir $BaseDomain
        # Check to fix PSv2 issues with returning a hashtable with "0" (operation successful) and the actual object
        if (!$objADAccountEntry) {
            Return "ObjectNotFoundInAD"
        }
        elseif ($objADAccountEntry.GetType().BaseType -eq [System.Array]) {
            $strADSIDN = $objADAccountEntry[1].distinguishedName
        }
        else {
            $strADSIDN = $objADAccountEntry.distinguishedName
        }
    }

    if ($SearchGroupsAccountIsMemberOf) {

        Write-LogFile -Message "Recursively checking which groups $AccountType $AccountName is a member of" -MessageType Debug

        # Initializing DirectorySearcher Object
        $strDomainDN = "LDAP://$BaseDomain"
        $objDomain = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $strDomainDN
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.PageSize = 10
        $objSearcher.SearchScope = "Subtree"
        
        if ($BaseADGroupMembershipFQDN) {
            $strDomainDN = "LDAP://$strADSIDN"
            $objDomain = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $strDomainDN
            $objSearcher.SearchScope = "Base"
            $strFilter = "(memberof:1.2.840.113556.1.4.1941:=$($strBaseADGroupMembershipDN))"
        }
        else {

            $strFilter = "(member:1.2.840.113556.1.4.1941:=$($strADSIDN))"
        }

        $objSearcher.SearchRoot = $objDomain
        $objSearcher.Filter = $strFilter
        $objADSearchResult = $objSearcher.FindAll()

        # Creating a list out of the StringFilter keywords
        if ($StringFilter) {
            $KeywordList = $StringFilter.Split(",").Trim()
        }

        if($objADSearchResult) {

            [System.Collections.ArrayList]$objGroupList = @()

            # If no value was passed to BaseADGroupMembership then it will return ALL the groups this account belongs to
            # As such, we need to return an array of System.DirectoryServices.DirectoryEntry objects

            if (($objADSearchResult.Count -ge 1) -AND ($objADSearchResult.Path -ne "")) {

                foreach ($entry in $objADSearchResult){
                    if ($StringFilter) {
                        foreach ($Keyword in $KeywordList) {
                            $objGroupEntry = New-Object System.DirectoryServices.DirectoryEntry($entry.Path)
                            $StringFilter = "*" + $Keyword + "*"
                            if($objGroupEntry.Path -like $StringFilter) {
                                $objGroupList.Add($objGroupEntry.distinguishedName) | Out-Null
                            }
                        }
                    }
                    else {
						$objGroupEntry = New-Object System.DirectoryServices.DirectoryEntry($entry.Path)
						$objGroupList.Add($objGroupEntry.distinguishedName) | Out-Null
					}
                }

                if ($objGroupList.Count -eq 1) {
                    # Single object returned
                    Write-LogFile -Message "Found single membership match for $AccountName in $strBaseADGroupMembershipDN" -MessageType Debug
                }
                else {
                    Write-LogFile -Message "Found multiple membership matches for $AccountName in $BaseDomain" -MessageType Debug
                }

                Return $objGroupList
            }

            else {
                Write-LogFile -Message "Could not find membership match for $AccountName in $strBaseADGroupMembershipDN" -MessageType Debug
                Return $null
            }
        }
    }

    else {

        # We use .NET here to connect to the Domain via LDAP and check whether an account is member of the group
        Write-LogFile -Message "Simple Non-Recursive group membership check for $AccountName running..." -MessageType Debug

        # Check whether a FQDN was passed in, in which case we need to trim it down to the account name only
        if ($ADGroup -like "CN=*") {
            $ADGroup = $ADGroup.TrimStart("C", "N", "=", 1).split(",")[0]
        }

        $strFilter = "(&(objectCategory=Group)(name=$ADGroup))"
        $strDomainDN = "LDAP://$BaseDomain"
        $objDomain = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $strDomainDN
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = $objDomain
        $objSearcher.PageSize = 10
        $objSearcher.Filter = $strFilter
        $objSearcher.SearchScope = "Subtree"
        $objADSearchResult = $objSearcher.FindOne()
        $objGroup = New-Object System.DirectoryServices.DirectoryEntry($objADSearchResult.Path)
    }

    Write-LogFile -Message "Looking for host $AccountName in group $ADGroup" -MessageType Debug

    ForEach ($objAccount in $objGroup.member) {

        $strAccountName = $objAccount.TrimStart("C", "N", "=", 1).split(",")[0]

        if ($strAccountName -eq $AccountName.TrimEnd("$")) {

          Write-LogFile -Message "Match found for host $AccountName in group $ADGroup" -MessageType Debug
          # We return a pointer to the System.ComponentModel.Component.Entry object
          # that will be used later by Set-ADGroup -ActionType removeself
          Return $objGroup

        }
    }
    # If function gets here it means it didn't return before and a match was not found
    Write-LogFile -Message "Match not found for host $AccountName in group $ADGroup" -MessageType Debug
}

Function Find-ADAccount {

    <#

    .SYNOPSIS
        Function to find a user/machine account in Active Directory using .NET. Returns a System.DirectoryServices.DirectoryEntry object.

    .DESCRIPTION
        This function searches a specific AD base directory searching for an account and returns a handle to the object

    .PARAMETER ADAccount
        The name of the account we are attempting to find.

    .PARAMETER ADAccountType
        The type of account we are searching for (Machine or User)

    .PARAMETER ADBaseDir
        The DN of the base directory to search from.

    .PARAMETER ReturnHashTable
        The DN of the base directory to search from.

    .EXAMPLE
        Todo

    #>

    [OutputType([System.DirectoryServices.DirectoryEntry])]
    Param (

        [Parameter(Mandatory=$True)]
        [string]$ADAccount,

        [Parameter(Mandatory=$False)]
        [string]$ADBaseDir = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://rootDSE").Get("defaultNamingContext"),

        [Parameter(Mandatory=$True)]
        [ValidateSet('User','Computer','Group')]
        [string]$ADAccountType,

        [Parameter(Mandatory=$False)]
        [System.Array]$ADProperties,

        [Parameter(Mandatory=$False)]
        [switch]$ReturnHashTable

    )

    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    Write-LogFile -Message "Looking for $ADAccount..." -MessageType Debug

    # First lets make sure we are passing the right machine account string
    if(($ADAccountType -eq "Computer") -and (!$ADAccount.EndsWith("$"))){$ADAccount = $ADAccount + "$"}

    # We use .NET here to connect to the Domain via LDAP and check whether an account is member of the group

    $strFilter = "(&(objectCategory=$ADAccountType)(samaccountname=$ADAccount))"
    $strDomainDN = "LDAP://$ADBaseDir"
    $objDomain = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $strDomainDN
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.SearchRoot = $objDomain
    $objSearcher.PageSize = 10
    $objSearcher.Filter = $strFilter
    $objSearcher.SearchScope = "Subtree"

    ForEach ($prop in $ADProperties) {$objSearcher.PropertiesToLoad.Add($prop)}

    $objADSearchResult = $objSearcher.FindOne()
    $objADAccountEntry = New-Object System.DirectoryServices.DirectoryEntry($objADSearchResult.Path)

    if ($objADSearchResult) {
        Write-LogFile -Message "Found Account $ADAccount" -MessageType Debug
        if ($ReturnHashTable) {
            # Instantiate a new ordered dictionary
            $PropDict = New-Object System.Collections.Specialized.OrderedDictionary
            # The DirectoryEntry is a collection of System.Data.PropertyCollection
            # We need to add each key/value pairs to a dict
            #$objADAccountEntry.Properties.Keys | ForEach-Object { $PropDict.Add($_, $objADAccountEntry.$_) }
            $ConvertedLDAPProperties = $objADAccountEntry.Properties | Convert-LDAPProperty -ErrorAction SilentlyContinue
            $ConvertedLDAPProperties.PSObject.Properties.Name | Sort-Object | ForEach-Object { $LDAPPropName = $_ ; $PropDict.Add($LDAPPropName, $ConvertedLDAPProperties.$LDAPPropName) }
            return $PropDict
        }
        else {
            $ConvertedLDAPProperties = $objADAccountEntry.Properties | Convert-LDAPProperty -ErrorAction SilentlyContinue | Sort-Object Name
            return $objADAccountEntry
        }
        
    }

    else {
        Write-LogFile -Message "Account $ADAccount not found" -MessageType Debug
    }
   
}

Function Set-ADGroup {

    <#

        .SYNOPSIS
            Function that will remove/add a machine account from an AD Group. The only condition is for the AD Group to have the "remove self from group" permission enabled for the account this script is running under (SYSTEM for example if it runs from a scheduled task with SYSTEM privileges)

        .PARAMETER ADGroup
            An object representing the System.DirectoryServices.DirectoryEntry AD group

        .PARAMETER ADAccount
            A string representing the AD account to be searched for

        .PARAMETER ActionType
            A switch that represents which action should be taken on the target ADGroup. When selectin "removeself" it only applies to computer objects, particularly the computer the script is run under.

    #>

    Param (

        [Parameter(Mandatory=$False)]
        [System.DirectoryServices.DirectoryEntry]$ADGroup,

        [Parameter(Mandatory=$False)]
        [string]$ADAccount,

        [Parameter(Mandatory=$False)]
        [ValidateSet('Computer', 'User', 'Group')]
        [string]$ADAccountType = 'Computer',

        [Parameter(Mandatory=$True)]
        [ValidateSet('addaccount', 'removeaccount', 'removeself')]
        [string]$ActionType = 'addaccount'
    )

    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    Try {

        If ($ActionType -eq "removeself") {
            $strComputerName = $env:COMPUTERNAME + "$"

            $objADAccount = Find-ADAccount -ADAccount $strComputerName -ADAccountType $ADAccountType
        }
        Else {
            $objADAccount = Find-ADAccount -ADAccount $ADAccount -ADAccountType $ADAccountType
        }

        # Check to fix PSv2 issues with returning a hashtable with "0" (operation successful) and the actual object
        if ($objADAccount.GetType().BaseType -eq [System.Array]) {
            $ADAccountStr = [string]$objADAccount[1].distinguishedName
        }
        else {
            $ADAccountStr = [string]$objADAccount.distinguishedName
        }

        # For logging purposes:
        $ADAccountPlainCN = $ADAccountStr.Substring(0, $ADAccountStr.IndexOf(',OU=')).TrimStart("CN=")

        Switch ($ActionType) {

            {($_ -eq "removeself") -or ($_ -eq "removeaccount")} {

                Write-LogFile -Message "Removing $ADAccountStr from $($ADGroup.Name)" -MessageType Low
                $ADGroup.member.Remove($ADAccountStr)
                $ADGroup.CommitChanges()
                $ADGroup.Close()
                $ADGroup.Dispose()
            
            }

            "addaccount" {

                Write-LogFile -Message "Checking whether $ADAccountPlainCN is already a member of $($ADGroup.Name)" -MessageType Low
                $AccountAlreadyMember =  Find-ADGroupMembership -AccountName $ADAccountPlainCN -ADGroup $ADGroup.cn.ToString() -AccountType $ADAccountType
                If($AccountAlreadyMember) {
                    Write-LogFile -Message "Cannot Add $ADAccountPlainCN to $($ADGroup.Name) because it is already present. Proceeding with the rest of the workflow" -MessageType Low
                    Break
                }

                Write-LogFile -Message "Adding $ADAccountPlainCN to $($ADGroup.Name) & sleeping for 3 seconds" -MessageType Low
                $ADGroup.member.Add($ADAccountStr)
                $ADGroup.CommitChanges()
                $ADGroup.Close()
                $ADGroup.Dispose()
                Start-Sleep 3

            }

        }
    }

    Catch [System.Management.Automation.MethodInvocationException] {
        Write-LogFile -LogError $_ -Message "Could not add/remove $ADAccountStr from $($ADGroup.Name) group. Possible cause: the account is not a member of the group" -MessageType Error
    }

    Catch {

        Write-LogFile -LogError $_ -Message "NonDescript Error" -MessageType Error

        $DomainConnectivity = Invoke-AnalyzerControlStatus -ActionType "Get" -Attribute "DomainConnectivity"
        if ($DomainConnectivity -eq "False") {
            Write-LogFile -Message "Could not add/remove $ADAccountStr from $($ADGroup.Name) group. Domain Connectivity Lost" -MessageType Low
        }
        else {
            Write-LogFile -Message "Could not add/remove $ADAccountStr from $($ADGroup.Name) group. Possible cause: the account was a member of a nested group. We cannot remove accounts from nested groups since that would be constitute a scope violation" -MessageType Error
        }

        Return 1
    }
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

    [cmdletbinding(DefaultParameterSetName='Standard')]

    Param (
        [Parameter(Mandatory=$False, ParameterSetName="Standard")]
        [string]$OutputDir,

        [Parameter(Mandatory=$False, Position=0, ParameterSetName="Standard")]
        [string]$Message,

        [Parameter(Mandatory=$False, ParameterSetName="Standard")]
        [Hashtable]$Dictionary,

        [Parameter(Mandatory=$False, ParameterSetName="Standard")]
        [ValidateSet('Memory','Disk')]
        [String[]]$InitializeLogFile = "",

        [Parameter(Mandatory=$False, ParameterSetName="Standard")]
        [ValidateSet('Error','Low','Info','Special','RemoteLog','Rare','Debug')]
        [string]$MessageType = "Info",

        [Parameter(Mandatory=$False, ParameterSetName="Standard")]
        [string]$CallingModule = $( if($(Get-PSCallStack)[1]){ $(Get-PSCallStack)[1].FunctionName } else {"Script"} ),    
        
        [Parameter(Mandatory=$False, ParameterSetName="Standard")]
        [switch]$CreateRandomName,

        [Parameter(Mandatory=$False, ParameterSetName="Standard")]
        [switch]$LogAsField,

        [Parameter(Mandatory=$False, ParameterSetName="Standard")]
        [switch]$LogAsIs,

        [Parameter(Mandatory=$False, ParameterSetName="Standard")]
        [System.Management.Automation.ErrorRecord]$LogError,

        [Parameter(Mandatory=$False, ParameterSetName="Standard")]
        [switch]$WriteLogToStdOut,

        [Parameter(Mandatory=$False, ParameterSetName="CloseLogging")]
        [switch]$FlushAndCloseLogFile,
  
        [Parameter(Mandatory=$False, ParameterSetName="CloseLogging")]
        [switch]$NoWriteToLogFile
        
    )

    # We will only proceed if this flag has not been setup somewhere in the script.
    if (!$Global:NoWriteLogFile) {

        if ($InitializeLogFile) {

            if ($CreateRandomName) {
                $Global:strLogFile = [string]([Guid]::newGuid())
            }
            else {
                $strTimeNow = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss")
                $RandomSuffix = Get-Random
                $Global:strLogFile = "$OutputDir\$($env:COMPUTERNAME)-soc-script-$strTimeNow-$RandomSuffix.json"
            }

            if ($InitializeLogFile -eq 'Disk') {
                # Initializing the File by opening a File StreamWriter handle to it
                $Global:objDiskFileStream = New-Object -TypeName System.IO.StreamWriter -ArgumentList $strLogFile
                $Global:objDiskFileStream.AutoFlush = $True
    
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

        }

        # If we are not supposed to log Debug messages and they are debug messages, then return
        # TODO: fix this function adding proper "LOG LEVEL" logging
        if (($Global:ShowDebugLogs -eq $False) -and ($MessageType -eq "Debug")) {
            return
        }

        # Grabing Time in UTC
        $strTimeNow = (Get-Date).ToUniversalTime().ToString("yy-MM-ddTHH:mm:ssZ")        

        if ($LogAsField) {

            if (!$Dictionary) {
                Write-LogFile -Message "Cannot log requested Key/Value since no Dictionary parameter was provided" -MessageType Error
                Break
                }

            # To keep compatibility with Powershell V2 we can't use the [ordered] accelerator
            $strLogLine = New-Object System.Collections.Specialized.OrderedDictionary
            $strLogLine.Add("timestamp", $strTimeNow)
            $strLogLine.Add("module", $CallingModule)
            $strLogLine.Add("hostname", $($env:COMPUTERNAME))

            ForEach ($key in $Dictionary.Keys){
                $strLogLine.Add($key, $Dictionary.Item($key))
            }
        }

        elseif ($LogError) {

            # Grab latest error namespace
            $ErrorNameSpace = $Error[0].Exception.GetType().FullName

            # To keep compatibility with Powershell V2 we can't use the [ordered] accelerator
            $strLogLine = New-Object System.Collections.Specialized.OrderedDictionary
            $strLogLine.Add("timestamp", $strTimeNow)
            $strLogLine.Add("module", $CallingModule)
            $strLogLine.Add("hostname", $($env:COMPUTERNAME))
            $strLogLine.Add("message", $Message)
            $strLogLine.Add("error_name_space", $ErrorNameSpace)
            $strLogLine.Add("error_script_line", $LogError.InvocationInfo.ScriptLineNumber)
            $strLogLine.Add("error_script_line_offset", $LogError.InvocationInfo.OffsetInLine)
            $strLogLine.Add("error_full_line", $($LogError.InvocationInfo.Line -replace '[^\p{L}\p{Nd}/(/)/{/}/_/[/]/./\s]', ''))
            $strLogLine.Add("error_message", $($LogError.Exception.Message -replace '[^\p{L}\p{Nd}/(/)/{/}/_/[/]/./\s]', ''))
            $strLogLine.Add("error_id", $LogError.FullyQualifiedErrorId)

        }

        else {

            if ($LogAsIs) {
                $strLogLine = $Message
            }
            else {

                # To keep compatibility with Powershell V2 we can't use the [ordered] accelerator
                $strLogLine = New-Object System.Collections.Specialized.OrderedDictionary
                $strLogLine.Add("timestamp", $strTimeNow)
                $strLogLine.Add("module", $CallingModule)
                $strLogLine.Add("hostname", $($env:COMPUTERNAME))
                $strLogLine.Add("message", $Message)
            }
        }

        # Converting Line to readable string in case output to stdout is selected
        if (($Global:LogfileWriteConsole -eq $True) -or $WriteLogToStdOut -or !$Global:objDiskFileStream -or !$Global:MemStream) {
            $strLogLineStdOut = ""
            foreach($key in $strLogLine.Keys) {
                $strLogLineStdOut += "$($strLogLine.$key) | "
            }
            $strLogLineStdOut = $strLogLineStdOut.TrimEnd("| ")
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
            "Debug" {
                $MessageColor = "Green"
                $BackgroundColor = "Black"
            }
            # Added this for Powershell v2, it has issues assigning the default value...
            "" {
                $MessageColor = "Yellow"
                $BackgroundColor = "Black"
            }
        }

        # Log when a stream writer has been initialized. If no initialization has occured, 
        # then simply log to stdout. 
        # We implement this check so that we can run modules independently without running into the issue
        # that the Log File Writter hasn't been initialized
        if ($Global:objDiskFileStream -or $Global:MemStream) {
            # Let's write to Log File on Disk or Memory
            if ($Global:objDiskFileStream) {
                $Global:objDiskFileStream.WriteLine($strLogLine)
            }
            else {
                $Global:StreamWritter.WriteLine($strLogLine)
            }
        }
        else {
            $WriteLogToStdOut = [System.Management.Automation.SwitchParameter]::new(1)
        }

        # Checking whether we should write to the console too
        # NOTE: In PS 7 Runspaces the concept of a "HOST" doesn't exist, we should avoid using Write-Host
        if ($Host.UI.RawUI -eq "System.Management.Automation.Internal.Host.InternalHostRawUserInterface") {

            if (($Global:LogfileWriteConsole -eq $True) -or $WriteLogToStdOut) {
                if ($MessageType -eq "Debug") {
                    if ($Global:ShowDebugLogs -eq $True) {
                        Write-Output $strLogLineStdOut
                    }
                    
                }
                else {
                    Write-Output $strLogLineStdOut
                }
            }
        }
        # Running from a .NET PS console v3 to v5
        else {
            if (($Global:LogfileWriteConsole -eq $True) -or $WriteLogToStdOut) {
                if ($MessageType -eq "Debug") {
                    if ($Global:ShowDebugLogs -eq $True) {
                        Write-Host $strLogLineStdOut -ForegroundColor $MessageColor -BackgroundColor $BackgroundColor
                    }
                    
                }
                else {
                    Write-Host $strLogLineStdOut -ForegroundColor $MessageColor -BackgroundColor $BackgroundColor
                }
            }
        }
    }

    # Routines for tearing down logging streams

    if ($FlushAndCloseLogFile) {
        # Must: 
        # (1) close handles to files and manage other stopping processes

        # (1)
        if ($Global:objDiskFileStream) {
            # If there are any opened Log File handles, let's close them
            $Global:objStream.Close()
            $Global:objStream.Dispose()
            [System.GC]::Collect()
            Return
        }

        # (1)
        elseif ($Global:MemStream) {
            # We opened a memory-based stream writter
            # Must (1) create a new file to write to (via filestream), (2) flush and write to file in disk

            $Global:objMemoryFileStream = New-Object -TypeName System.IO.FileStream -ArgumentList @($Global:strLogFile, [System.IO.FileMode]::OpenOrCreate)
            $Global:MemStream.Position = 0
            $Global:StreamWritter.Flush()
            $Global:MemStream.WriteTo($Global:objMemoryFileStream)
            $Global:objMemoryFileStream.Close()
            $Global:objMemoryFileStream.Dispose()
            $Global:StreamWritter.Close()
            $Global:StreamWritter.Dispose()
            $Global:MemStream.Close()
            $Global:MemStream.Dispose()
            [System.GC]::Collect()

        }
    }

}

Function Invoke-TaskScheduler {

    <#

    .SYNOPSIS
        Function that wraps around Microsoft.Win32.TaskScheduler.dll allowing us to register and unregister a task using a predefined XML file. It requires you to provide a path to the dll.

    .PARAMETER SourceTaskXMLFile
        The task XML file that we want to import

    .PARAMETER NewTaskName
        The name of the scheduled task once imported on the target system

    .PARAMETER ActionType
        Defines whether there is an existing task that should be deleted or a new task that should be imported

    #>

    Param (

        [Parameter(Mandatory=$False)]
        [string]$SourceTaskXMLFile,

        [Parameter(Mandatory=$True)]
        [string]$TaskSchedulerDllPath,

        [Parameter(Mandatory=$True)]
        [string]$TaskName,

        [Parameter(Mandatory=$True)]
        [ValidateSet('ImportTask', 'DeleteTask', 'RunTask', 'GetTask')]
        [string]$ActionType

    )

    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    # Load assembly
    
    try {
        Add-Type -Path $SourceTaskXMLFile
    }
    catch {
        Write-LogFile -Message "Could not load Microsoft.Win32.TaskScheduler.dll, breaking..."
        return
    }

    # Instantiate the TaskScheduler class
    $ts = New-Object Microsoft.Win32.TaskScheduler.TaskService

    # Let's test whether the task already exists
    $MyTask = $ts.GetTask($TaskName)

    Switch ($ActionType) {

        "ImportTask" {

            Try {

                If($MyTask.State -eq "Running") {
                    Write-LogFile -Message "Task $TaskName is already running on the remote host. Cannot proceed" -MessageType Error
                    $ts.Dispose()
                    Return
                }

                Write-LogFile -Message "Importing Task $TaskName to the root folder" -MessageType Info
                $NewTask = $ts.RootFolder.ImportTask($TaskName, $SourceTaskXMLFile)
                Write-LogFile -Message "Imported Task $TaskName to the root folder" -MessageType Low

                Return $NewTask

            }

            # Catch All - We need to improve this block to refine the catch :)
            Catch {
                Write-LogFile -LogError $_ -Message "The task could not be imported" -MessageType Error
                $ts.Dispose()

            }
        }

        "DeleteTask" {

            Try {

                Write-LogFile -Message "Checking whether Task $TaskName exists in root folder" -MessageType Info
                
                If(!$MyTask) {
                    Write-LogFile -Message "Task $TaskName does not exist" -MessageType Error
                    $ts.Dispose()
                    Return "TaskDoesNotExist"
                }

                Else {
                    Write-LogFile -Message "Deleting Task $TaskName from root folder" -MessageType Info
                    $ts.RootFolder.DeleteTask($TaskName, $True)
                    $ts.Dispose()
                    Return "DeletedTask"
                }
            }

            # Catch All - We need to improve this block to refine the catch :)
            Catch {
                Write-LogFile -LogError $_ -Message "The task could not be deleted" -MessageType Error
                $ts.Dispose()

            }
        }

        "RunTask" {

            Try {

                Write-LogFile -Message "Checking whether Task $TaskName exists in root folder" -MessageType Info
                
                If(!$MyTask) {
                    Write-LogFile -Message "Task $TaskName does not exist" -MessageType Error
                    $ts.Dispose()
                    Return "TaskDoesNotExist"
                }

                Else {

                    If($MyTask.State -eq "Running") {
                        Write-LogFile -Message "Task $TaskName is already running on the remote host" -MessageType Low
                        $ts.Dispose()
                        Return
                    }
                    Else {
                        Write-LogFile -Message "Running Task $TaskName from root folder" -MessageType Info
                        $MyTask.Run()
                        $ts.Dispose()
                    }
                }
            }

            # Catch All - We need to improve this block to refine the catch :)
            Catch {
                Write-LogFile -LogError $_ -Message "The task could not be deleted" -MessageType Error
                $ts.Dispose()

            }
        }

        "GetTask" {

            Try {

                Write-LogFile -Message "Checking whether Task $TaskName exists in root folder" -MessageType Info
                
                If(!$MyTask) {
                    Write-LogFile -Message "Task $TaskName does not exist" -MessageType Error
                    $ts.Dispose()
                    Return "TaskDoesNotExist"
                }

                Else {
                    Return $MyTask
                }
            }

            # Catch All - We need to improve this block to refine the catch :)
            Catch {
                Write-LogFile -LogError $_ -Message "The task could not be deleted" -MessageType Error
                $ts.Dispose()

            }
        }

    }
}