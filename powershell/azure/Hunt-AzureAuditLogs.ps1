<#
    CYBERNETHUNTER SECURITY OPERATIONS :)
    Author: Diego Perez (@darkquassar)
    Version: 1.0.0
    Module: Hunt-AzureAuditLogs.ps1
    Description: This module contains some utilities to search through Azure and O365 unified audit log.
#>

using namespace System.IO

class TimeStamp {

    # Public Properties
    [float] $Interval
    [System.Globalization.CultureInfo] $AUCulture
    [DateTime] $StartTime
    [DateTime] $EndTime
    [DateTime] $StartTimeSlice
    [DateTime] $EndTimeSlice
    [DateTime] $StartTimeUTC
    [DateTime] $EndTimeUTC
    [DateTime] $StartTimeSliceUTC
    [DateTime] $EndTimeSliceUTC

    # Default, Overloaded Constructor
    TimeStamp([String] $StartTime, [String] $EndTime) {
        $this.AUCulture = New-Object System.Globalization.CultureInfo("en-AU")
        $this.StartTime = $this.ParseDateString($StartTime)
        $this.EndTime = $this.ParseDateString($EndTime)
        $this.UpdateUTCTimestamp()
    }

    # Default, Parameterless Constructor
    TimeStamp() {
        $this.AUCulture = New-Object System.Globalization.CultureInfo("en-AU")
    }

    # Constructor
    [DateTime]ParseDateString ([String] $TimeStamp) {
        return [DateTime]::ParseExact($TimeStamp, $this.AUCulture.DateTimeFormat.SortableDateTimePattern, $null)
    }

    Reset() {
        $this.StartTimeSlice = [DateTime]::new(0)
        $this.EndTimeSlice = [DateTime]::new(0)
    }

    IncrementTimeSlice ([float] $HourlySlice) {

        $this.Interval = $HourlySlice

        # if running method for the first time, configure $StartTimeSlice with the $ParsedDate
        if(($this.StartTimeSlice -lt $this.StartTime) -and ($this.EndTimeSlice -lt $this.StartTime)) {
            $this.StartTimeSlice = $this.StartTime
            $this.EndTimeSlice = $this.StartTime.AddHours($HourlySlice)
        }
        else {
            $this.StartTimeSlice = $this.EndTimeSlice
            $this.EndTimeSlice = $this.StartTimeSlice.AddHours($HourlySlice)
        }

        $this.UpdateUTCTimestamp()
    }

    [void]UpdateUTCTimestamp () {
        $this.StartTimeUTC = $this.StartTime.ToUniversalTime()
        $this.EndTimeUTC = $this.EndTime.ToUniversalTime()
        $this.StartTimeSliceUTC = $this.StartTimeSlice.ToUniversalTime()
        $this.EndTimeSliceUTC = $this.EndTimeSlice.ToUniversalTime()
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

    [Hashtable]$Dictionary
    [ValidateSet('DEBUG','ERROR','LOW','INFO','SPECIAL','REMOTELOG')]
    [string]$MessageType
    [string]$CallingModule = $( if(Get-PSCallStack){ $(Get-PSCallStack)[1].FunctionName } else {"NA"} )
    [string]$ScriptPath
    [string]$LogFileJSON
    [string]$LogFileTXT
    [string]$MessageColor
    [string]$BackgroundColor
    $Message
    [string]$LogRecordStdOut

    Logger () {

        # *** Getting a handle to the running script path so that we can refer to it *** #
        if ($MyInvocation.MyCommand.Name) { 
            $this.ScriptPath = [System.IO.DirectoryInfo]::new($(Split-Path -Parent $MyInvocation.MyCommand.Definition))
        } 
        else {
            $this.ScriptPath = [System.IO.DirectoryInfo]::new([Directory]::GetCurrentDirectory())
        }

        $strTimeNow = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss")
        $this.LogFileJSON = "$($this.ScriptPath)\$($env:COMPUTERNAME)-azurehunter-$strTimeNow.json"
        $this.LogFileTXT = "$($this.ScriptPath)\$($env:COMPUTERNAME)-azurehunter-$strTimeNow.txt"
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
                $this.MessageColor = "Gray"
                $this.BackgroundColor = "Black"
            }
            "Info" {
                $this.MessageColor = "Yellow"
                $this.BackgroundColor = "Black"
            }
            "Low" {
                $this.MessageColor = "Green"
                $this.BackgroundColor = "DarkCyan"
            }
            "Special" {
                $this.MessageColor = "White"
                $this.BackgroundColor = "Red"
            }
            "RemoteLog" {
                $this.MessageColor = "DarkGreen"
                $this.BackgroundColor = "Green"
            }
            "Debug" {
                $this.MessageColor = "Green"
                $this.BackgroundColor = "Black"
            }

        }

        # Finally emit the logs
        $LogRecord | Out-File $this.LogFileJSON -Append ascii
        $this.LogRecordStdOut | Out-File $this.LogFileTXT -Append ascii
        Write-Host $this.LogRecordStdOut -ForegroundColor $this.MessageColor -BackgroundColor $this.BackgroundColor
    }
}

enum AzureRecordType {
    AeD
    AipDiscover
    AipFileDeleted
    AipHeartBeat
    AipProtectionAction
    AipSensitivityLabelAction
    AirAdminActionInvestigation
    AirInvestigation
    AirManualInvestigation
    ApplicationAudit
    AttackSim
    AzureActiveDirectory
    AzureActiveDirectoryAccountLogon
    AzureActiveDirectoryStsLogon
    CDPClassificationDocument
    CDPClassificationMailItem
    CDPHygieneSummary
    CDPMlInferencingResult
    CDPPostMailDeliveryAction
    CDPUnifiedFeedback
    CRM
    Campaign
    ComplianceDLPExchange
    ComplianceDLPExchangeClassification
    ComplianceDLPSharePoint
    ComplianceDLPSharePointClassification
    ComplianceSupervisionExchange
    ConsumptionResource
    CortanaBriefing
    CustomerKeyServiceEncryption
    DLPEndpoint
    DataCenterSecurityCmdlet
    DataGovernance
    DataInsightsRestApiAudit
    Discovery
    DlpSensitiveInformationType
    ExchangeAdmin
    ExchangeAggregatedOperation
    ExchangeItem
    ExchangeItemAggregated
    ExchangeItemGroup
    ExchangeSearch
    HRSignal
    HealthcareSignal
    HygieneEvent
    InformationBarrierPolicyApplication
    InformationWorkerProtection
    Kaizala
    LabelContentExplorer
    LargeContentMetadata
    MAPGAlerts
    MAPGPolicy
    MAPGRemediation
    MCASAlerts
    MDATPAudit
    MIPLabel
    MS365DCustomDetection
    MSDEGeneralSettings
    MSDEIndicatorsSettings
    MSDEResponseActions
    MSDERolesSettings
    MSTIC
    MailSubmission
    Microsoft365Group
    MicrosoftFlow
    MicrosoftForms
    MicrosoftStream
    MicrosoftTeams
    MicrosoftTeamsAdmin
    MicrosoftTeamsAnalytics
    MicrosoftTeamsDevice
    MicrosoftTeamsShifts
    MipAutoLabelExchangeItem
    MipAutoLabelProgressFeedback
    MipAutoLabelSharePointItem
    MipAutoLabelSharePointPolicyLocation
    MipAutoLabelSimulationCompletion
    MipAutoLabelSimulationProgress
    MipAutoLabelSimulationStatistics
    MipExactDataMatch
    MyAnalyticsSettings
    OfficeNative
    OfficeScripts
    OnPremisesFileShareScannerDlp
    OnPremisesSharePointScannerDlp
    OneDrive
    PhysicalBadgingSignal
    PowerAppsApp
    PowerAppsPlan
    PowerBIAudit
    PrivacyDataMinimization
    PrivacyDigestEmail
    PrivacyRemediationAction
    Project
    Quarantine
    Search
    SecurityComplianceAlerts
    SecurityComplianceCenterEOPCmdlet
    SecurityComplianceInsights
    SecurityComplianceRBAC
    SecurityComplianceUserChange
    SensitivityLabelAction
    SensitivityLabelPolicyMatch
    SensitivityLabeledFileAction
    SharePoint
    SharePointCommentOperation
    SharePointContentTypeOperation
    SharePointFieldOperation
    SharePointFileOperation
    SharePointListItemOperation
    SharePointListOperation
    SharePointSearch
    SharePointSharingOperation
    SkypeForBusinessCmdlets
    SkypeForBusinessPSTNUsage
    SkypeForBusinessUsersBlocked
    Sway
    SyntheticProbe
    TABLEntryRemoved
    TeamsEasyApprovals
    TeamsHealthcare
    ThreatFinder
    ThreatIntelligence
    ThreatIntelligenceAtpContent
    ThreatIntelligenceUrl
    UserTraining
    WDATPAlerts
    WorkplaceAnalytics
    Yammer
}

Function Search-AzureCloudUnifiedLog {
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
            Mandatory=$True,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False,
            Position=0,
            HelpMessage='Start Date in the form: year-month-dayThour:minute:seconds'
        )]
        [ValidatePattern("\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")]
        [ValidateNotNullOrEmpty()]
        [string]$StartDate,

        [Parameter( 
            Mandatory=$True,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            Position=1,
            HelpMessage='End Date in the form: year-month-dayThour:minute:seconds'
        )]
        [ValidatePattern("\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")]
        [ValidateNotNullOrEmpty()]
        [string]$EndDate,

        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            Position=2,
            HelpMessage='Time Interval in hours. This represents the interval windows that will be queried between StartDate and EndDate'
        )]
        [ValidateNotNullOrEmpty()]
        [float]$TimeInterval=12,

        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False,
            Position=3,
            HelpMessage='The users you would like to investigate. If this parameter is not provided it will default to all users'
        )]
        [string]$UserIDs,

        [Parameter( 
            Mandatory=$False,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False,
            Position=4,
            HelpMessage='The amount of records you would like returned from the search. Defaults to 5000. If value is 0 it means ALL records will be returned'
        )]
        [ValidateNotNullOrEmpty()]
        [int]$ResultSize,

        [Parameter( 
            Mandatory=$False,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False,
            Position=5,
            HelpMessage='This parameter will adjust the TimeInterval windows between your Start and End Dates so as to capture as many records as possible. If the size of returned results for the current interval is 5000, then it will decrease the window by half.'
        )]
        [ValidateNotNullOrEmpty()]
        [switch]$AutomaticTimeWindowReduction
    )

    PROCESS {

        # Grab Start and End Timestamps
        $TimeSlicer = [TimeStamp]::New($StartDate, $EndDate)
        $TimeSlicer.IncrementTimeSlice($TimeInterval)

        # Initialize Logger
        $Logger = [Logger]::New()
        
        while($TimeSlicer.StartTimeSlice -le $TimeSlicer.EndTime) {

            # do things
            # search audit log between $StartTime.StartTimeSlice and $StartTime.EndTimeSlice
            $Logger.LogMessage("Querying Azure to estimate result size", "INFO", $null, $null)
            $ResultCountEstimate = (Search-UnifiedAuditLog -StartDate $TimeSlicer.StartTimeSlice -EndDate $TimeSlicer.EndTimeSlice -ResultSize 1).ResultCount
            $Logger.LogMessage("Result Size: $ResultCountEstimate", "INFO", $null, $null)

            if((($ResultCountEstimate -eq 0) -or ($ResultCountEstimate -gt 50000)) -and $AutomaticTimeWindowReduction) {

                $OptimalTimeSlice = (50000 * $TimeInterval) / $ResultCountEstimate
                $Logger.LogMessage("Optimal Time Interval: $OptimalTimeSlice", "DEBUG", $null, $null)

                if($OptimalTimeSlice -lt 0.5) {
                    $Logger.LogMessage("Density of logs is too high and Azure does not allow Time Intervals of less than 30min. Setting new interval at 30min", "DEBUG", $null, $null)
                    $TimeInterval = 0.5
                    $TimeSlicer.Reset()
                    $TimeSlicer.IncrementTimeSlice($TimeInterval)

                }
                else {
                    $Logger.LogMessage("Size of results is too big. Reducing Time Interval to $OptimalTimeSlice", "INFO", $null, $null)
                    $TimeInterval = $OptimalTimeSlice
                    $TimeSlicer.Reset()
                    $TimeSlicer.IncrementTimeSlice($TimeInterval)
                }

                # Go to next cycle, start again with new timeslice
                continue

            }


            #[System.Collections.ArrayList]$ResultCumulus = @()
            $TimeNow = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss")
            $ExportFileName = "$($Logger.ScriptPath)\$($env:COMPUTERNAME)-azurehunter-$TimeNow.csv"
            $RandomSessionName = "azurehunter-$(Get-Random)"
            $Results = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -SessionCommand ReturnLargeSet -SessionId $RandomSessionName

            # Loop through paged results and extract all of them sequentially, before going into the next TimeSlice cycle
            while((($Results[($Results.Count - 1)].ResultIndex -ne $Results[0].ResultCount)) -or $Results[($Results.Count - 1)].ResultIndex -eq 50000) {

                $Results = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -SessionCommand ReturnLargeSet -SessionId $RandomName

                # Export Results
                $StartingResultIndex = $Results[0].ResultIndex
                $EndResultIndex = $Results[($Results.Count - 1)].ResultIndex
                $Logger.LogMessage("Exporting records from $StartingResultIndex to $EndResultIndex", "INFO", $null, $null)
                $Results | Export-Csv $ExportFileName -NoTypeInformation -NoClobber -Append 
                #$Results | ForEach-Object { $ResultCumulus.add($_) }
            }

            # Increase time slice for the next loop
            $TimeSlicer.IncrementTimeSlice($TimeInterval)
        }
    }
}

