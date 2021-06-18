
class ListDirectories {

    # Public Properties
    [String] $Path # Directory Path
    [String] $SubFolder # Subfolder
    [String] $H1Header
    [String] $RequestURL
    [String] $Root # Root Folder
    [String] $HTTPText
    [String] $HTTPTables = ""

    [ListDirectories] SetPath([String] $Path) {
        $this.Path = $Path
        return $this
    }

    [ListDirectories] SetSubFolder([String] $Path) {
        $this.SubFolder = $Path
        return $this
    }

    [ListDirectories] SetH1Header([String] $H1Header) {
        $this.H1Header = $H1Header
        return $this
    }

    [ListDirectories] SetURL([String] $RequestURL) {
        $this.RequestURL = $RequestURL
        return $this
    }

    [ListDirectories] SetRoot([String] $Root) {
        $this.Root = $Root
        return $this
    }

    [void] GenerateFileList() {

        $FileList = Get-ChildItem $this.Path
        foreach ($File in $FileList)
        {
            $FileURL = ($File.FullName -replace [regex]::Escape($this.Root), "" ) -replace "\\","/"
            if (!$File.Length) { $FileLength = "[dir]" } else { $FileLength = $File.Length }
            
$this.HTTPTables = $this.HTTPTables + "`n" + @"
<tr>
<td align="right">$($File.LastWriteTime)</td>
<td align="right">$($FileLength)</td>
<td align="left"><a href="$($FileURL)">$($File.Name)</a></td>
</tr>
"@
        }

    }

    # Default Constructor
    GenerateHTTPText() {
        $this.HTTPText = @"
<html>
<head>
<title>$($this.H1Header)</title>
</head>
<body>
<h1>$($this.H1Header) | $($this.SubFolder)</h1>
<hr>
<a href="./../">[To Parent Directory]</a><br><br>
<table cellpadding="5">
    $($this.HTTPTables)
</table>
<hr>
</body>
</html>
"@
    }

}


class Logger {

    <#

    .SYNOPSIS
        Function to write message logs from this script in JSON format to a log file. When "LogAsField" is passed it will expect a hashtable of items that will be added to the log as key/value pairs passed as value to the parameter "Dictonary".

    .PARAMETER Message
        The text to be written

    .PARAMETER OutputDir
        The directory where the scan results are stored

    .PARAMETER Dictionary
        It allows you to pass a dictionary (hashtable) where your keys and values will be converted to a json line. Nested keys are not supported.

    #>

    [Hashtable] $Dictionary
    [ValidateSet('DEBUG','ERROR','LOW','INFO','SPECIAL','REMOTELOG')]
    [string] $MessageType
    [string] $CallingModule = $( if(Get-PSCallStack){ $(Get-PSCallStack)[1].FunctionName } else {"NA"} )
    [string] $ScriptPath
    [string] $LogFileJSON
    [string] $LogFileTXT
    [string] $MessageColor
    [string] $BackgroundColor
    $Message
    [string] $LogRecordStdOut
    [string] $strTimeNow

    Logger () {

        # *** Getting a handle to the running script path so that we can refer to it *** #
        if ($MyInvocation.MyCommand.Name) { 
            $this.ScriptPath = [System.IO.DirectoryInfo]::new($(Split-Path -Parent $MyInvocation.MyCommand.Definition))
            Write-Host $MyInvocation
            Write-Host $MyInvocation.MyCommand.Name
        } 
        else {
            $this.ScriptPath = [System.IO.DirectoryInfo]::new($pwd)
        }

        $this.strTimeNow = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss")
        $this.LogFileJSON = "$($this.ScriptPath)\$($env:COMPUTERNAME)-azurehunter-$($this.strTimeNow).json"
        $this.LogFileTXT = "$($this.ScriptPath)\$($env:COMPUTERNAME)-azurehunter-$($this.strTimeNow).txt"
    }

    LogMessage([string]$Message, [string]$MessageType, [Hashtable]$Dictionary, [System.Management.Automation.ErrorRecord]$LogErrorMessage) {
        
        # Capture LogType
        $this.MessageType = $MessageType.ToUpper()
        
        # Generate Data Dict
        $TimeNow = (Get-Date).ToUniversalTime().ToString("yy-MM-ddTHH:mm:ssZ")
        $LogRecord = [Ordered]@{
            "severity"      = $MessageType
            "timestamp"     = $TimeNow
            "hostname"      = $($env:COMPUTERNAME)
            "message"       = "NA"
        }

        # Let's log the dict as key-value pairs if it was passed
        if($null -ne $Dictionary) {
            ForEach ($key in $Dictionary.Keys){
                $LogRecord.Add($key, $Dictionary.Item($key))
            }
        }
        else {
            $LogRecord.message = $Message
        }

        # Should we log an Error?
        if ($null -ne $LogErrorMessage) {
            # Grab latest error namespace
            $ErrorNameSpace = $Error[0].Exception.GetType().FullName
            # Add Error specific fields
            $LogRecord.Add("error_name_space", $ErrorNameSpace)
            $LogRecord.Add("error_script_line", $LogErrorMessage.InvocationInfo.ScriptLineNumber)
            $LogRecord.Add("error_script_line_offset", $LogErrorMessage.InvocationInfo.OffsetInLine)
            $LogRecord.Add("error_full_line", $($LogErrorMessage.InvocationInfo.Line -replace '[^\p{L}\p{Nd}/(/)/{/}/_/[/]/./\s]', ''))
            $LogRecord.Add("error_message", $($LogErrorMessage.Exception.Message -replace '[^\p{L}\p{Nd}/(/)/{/}/_/[/]/./\s]', ''))
            $LogRecord.Add("error_id", $LogErrorMessage.FullyQualifiedErrorId)
        }

        $this.Message = $LogRecord

        # Convert log line to a readable line
        $this.LogRecordStdOut = ""
        foreach($key in $LogRecord.Keys) {
            $this.LogRecordStdOut += "$($LogRecord.$key) | "
        }
        $this.LogRecordStdOut = $this.LogRecordStdOut.TrimEnd("| ")

        # Converting log line to JSON
        $LogRecord = $LogRecord | ConvertTo-Json -Compress

        # Choosing the right StdOut Colors in case we need them
        Switch ($this.MessageType) {

            "Error" {
                $this.MessageColor = "Red"
                $this.BackgroundColor = "Black"
            }
            "Info" {
                $this.MessageColor = "Yellow"
                $this.BackgroundColor = "Black"
            }
            "Low" {
                $this.MessageColor = "Green"
                $this.BackgroundColor = "Black"
            }
            "Special" {
                $this.MessageColor = "White"
                $this.BackgroundColor = "DarkRed"
            }
            "RemoteLog" {
                $this.MessageColor = "DarkGreen"
                $this.BackgroundColor = "Green"
            }
            "Debug" {
                $this.MessageColor = "Green"
                $this.BackgroundColor = "DarkCyan"
            }

        }

        # Finally emit the logs
        $LogRecord | Out-File $this.LogFileJSON -Append ascii
        $this.LogRecordStdOut | Out-File $this.LogFileTXT -Append ascii
        Write-Host $this.LogRecordStdOut -ForegroundColor $this.MessageColor -BackgroundColor $this.BackgroundColor
    }
}
    
function Start-DirtyWebServer {

    <#
    .SYNOPSIS
        A PowerShell function to search the Azure Audit Log
    
    .DESCRIPTION
        This function will perform....
    
    .PARAMETER InputFile
        XXXXXX

    .PARAMETER InputString
        XXXXX

    .PARAMETER InputByteArray
        XXXXX
    
    .EXAMPLE
        XXXX
    
    .EXAMPLE
        XXX

    .EXAMPLE
        XXXX
    
    .NOTES
        Please use this with care and for legitimate purposes. The author does not take responsibility on any damage performed as a result of employing this script.
    #>

    [CmdletBinding(
        SupportsShouldProcess=$False
    )]
    Param (
        [Parameter( 
            Mandatory=$False,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False,
            Position=0,
            HelpMessage='Listener Address, default: http://+:8080'
        )]
        [ValidatePattern("http://.*/")]
        [ValidateNotNullOrEmpty()]
        [string]$ListenerAddress="http://+:8080/",

        [Parameter( 
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            Position=1,
            HelpMessage='Type of HTTP authentication if required'
        )]
        [ValidateSet("Anonymous","Basic","IntegratedWindowsAuthentication","Ntlm","None")]
        [ValidateNotNullOrEmpty()]
        [string]$AuthenticationType="None"
    )

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web")

    $HTTPListener = New-Object System.Net.HttpListener
    $HTTPListener.Prefixes.Add($ListenerAddress)
    #$HTTPListener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::$AuthenticationType
    $HTTPListener.Start()

    # Initialize Logger
    $Logger = [Logger]::New()
    $Logger.LogMessage("Initializing Logger", "INFO", $null, $null)
    $Logger.LogMessage("Server Listening on $ListenerAddress", "INFO", $null, $null)

    # Initialize HTTP Generator
    $HTTPGenerator = [ListDirectories]::new()

    # Create PSDrive and go to Drive
    $DriveName = Get-Random
    New-PSDrive -Name $DriveName -PSProvider FileSystem -Root $PWD.Path
    $Root = $PWD.Path
    Set-Location "$($DriveName):\"

    while ($HTTPListener.IsListening) {

        $Context = $HTTPListener.GetContext()
        $RequestUrl = $Context.Request.Url
        $Response = $Context.Response
        $LocalPath = $RequestUrl.LocalPath

        # Impersonate user if IntegratedWindowsAuthentication used
        if ($AuthenticationType -eq "IntegratedWindowsAuthentication") {
            $Context.User.Identity.Impersonate()
        }
        

        $Logger.LogMessage("Request URL: $RequestUrl", "INFO", $null, $null)
        $Content = ""

        

        try {

            $RequestedItem = Get-Item -LiteralPath "$($DriveName):\$LocalPath" -Force -ErrorAction Stop
            $FullPath = $RequestedItem.FullName

            if($RequestedItem.Attributes -match "Directory") {

                $HTTPGenerator.SetPath($FullPath).SetSubFolder($LocalPath).SetH1Header("Powershell HTTP File Server").SetRoot($Root).GenerateFileList().GenerateHTTPText()

                $Encoding = [system.Text.Encoding]::UTF8
                $Content = $Encoding.GetBytes($HTTPGenerator.HTTPText)
                $Response.ContentType = "text/html"
            } else {
                $Content = [System.IO.File]::ReadAllBytes($FullPath)
                $Response.ContentType = [System.Web.MimeMapping]::GetMimeMapping($FullPath)
            }

        } catch [System.UnauthorizedAccessException] {

            $RequestedFile = "$($DriveName):\$localPath"
            $Logger.LogMessage("Access Denied | User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) | Requested File: $RequestedFile", "ERROR", $null, $_)

            $Response.StatusCode = 404
            $Content = [System.Text.Encoding]::UTF8.GetBytes("<h1>404 - Page not found</h1>")

        } catch [System.Management.Automation.ItemNotFoundException] {
            $RequestedFile = "$($DriveName):\$localPath"
            $Logger.LogMessage("No route found for Requested File: $RequestedFile", "ERROR", $null, $_)
            $Response.StatusCode = 404
            $Content = [System.Text.Encoding]::UTF8.GetBytes("<h1>404 - Page not found</h1>")
        } catch {

            $Logger.LogMessage("Unexpected Error", "ERROR", $null, $_)

            $Content = [System.Text.Encoding]::UTF8.GetBytes($Logger.Message)
            $Response.StatusCode = 500
        }


        $Response.ContentLength64 = $Content.Length
        $Response.OutputStream.Write($Content, 0, $Content.Length)
        $Response.Close()

        $ResponseStatus = $Response.StatusCode
        $Logger.LogMessage("Initializing Logger", "INFO", $null, $null)
    }

}