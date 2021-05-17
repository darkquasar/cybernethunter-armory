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
    [bool] $IntervalAdjusted
    [System.Globalization.CultureInfo] $Culture
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
        $this.Culture = New-Object System.Globalization.CultureInfo("en-AU")
        $this.StartTime = $this.ParseDateString($StartTime)
        $this.EndTime = $this.ParseDateString($EndTime)
        $this.UpdateUTCTimestamp()
    }

    # Default, Parameterless Constructor
    TimeStamp() {
        $this.Culture = New-Object System.Globalization.CultureInfo("en-AU")
    }

    # Constructor
    [DateTime]ParseDateString ([String] $TimeStamp) {
        return [DateTime]::ParseExact($TimeStamp, $this.Culture.DateTimeFormat.SortableDateTimePattern, $null)
    }

    Reset() {
        $this.StartTimeSlice = [DateTime]::new(0)
        $this.EndTimeSlice = [DateTime]::new(0)
    }

    IncrementTimeSlice ([float] $HourlySlice) {

        $this.Interval = $HourlySlice

        # if running method for the first time, set $StartTimeSlice to $StartTime
        if(($this.StartTimeSlice -le $this.StartTime) -and ($this.EndTimeSlice -lt $this.StartTime)) {
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
        } 
        else {
            $this.ScriptPath = [System.IO.DirectoryInfo]::new([Directory]::GetCurrentDirectory())
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
        $InitialTimeInterval = ($TimeSlicer.EndDate - $TimeSlicer.StartDate).TotalMinutes

        # Initialize Logger
        $Logger = [Logger]::New()
        $Logger.LogMessage("Logs will be written to: $($Logger.ScriptPath)", "DEBUG", $null, $null)

        # Records Counter
        $StartRecordIndex = 1
        $EndRecordIndex = 0
        $TotalRecords = 0

        # Flow Control
        $NumberOfAttempts = 1   # How many times a call to the API should be attempted before proceeding to the next block
        $LogExtractionOk = $false # Wether log extraction succeeded or not
        $ResultCountEstimate = 0 # Start with a value that triggers the time window reduction loop

        while($TimeSlicer.StartTimeSlice -le $TimeSlicer.EndTime) {

            # Search audit log between $TimeSlicer.StartTimeSlice and $TimeSlicer.EndTimeSlice
            # Only run this block once to determine optimal time interval (likely to be less than 30 min anyway)
            # We need to avoid scenarios where the time interval initially setup by the user is less than 30 min
            if((($ResultCountEstimate -eq 0) -or ($ResultCountEstimate -ge 20000) -or ($InitialTimeInterval -lt 5)) -and $AutomaticTimeWindowReduction -and -not ($TimeSlicer.IntervalAdjusted -eq $true)) {

                # Run initial query to estimate results and adjust time intervals
                $Logger.LogMessage("Querying Azure to estimate initial result size", "INFO", $null, $null)
                $ResultCountEstimate = (Search-UnifiedAuditLog -StartDate $TimeSlicer.StartTimeSliceUTC -EndDate $TimeSlicer.EndTimeSliceUTC -ResultSize 1).ResultCount
                $Logger.LogMessage("Initial Result Size estimate: $ResultCountEstimate", "INFO", $null, $null)

                <#
                $OptimalTimeSlice = (5000 * $TimeInterval) / $ResultCountEstimate

                $OptimalTimeSlice = [math]::Round($OptimalTimeSlice, 3)
                $Logger.LogMessage("Optimal Hourly Time Interval: $OptimalTimeSlice", "DEBUG", $null, $null)

                if($OptimalTimeSlice -lt 0.5) {
                    $Logger.LogMessage("Density of logs is too high and Azure does not allow Time Intervals of less than 15 min. Setting new interval at 15 min", "DEBUG", $null, $null)
                    $TimeInterval = 0.15
                    $TimeSlicer.Reset()
                    $TimeSlicer.IncrementTimeSlice($TimeInterval)

                }
                else {
                    $Logger.LogMessage("Size of results is too big. Reducing Hourly Time Interval to $OptimalTimeSlice", "INFO", $null, $null)
                    $TimeInterval = $OptimalTimeSlice
                    $TimeSlicer.Reset()
                    $TimeSlicer.IncrementTimeSlice($TimeInterval)
                }
                #>

                $HalvedHourlyTimeInterval = $TimeInterval / 2
                $Logger.LogMessage("Size of results is too big. Reducing Hourly Time Interval by half to $HalvedHourlyTimeInterval hours", "INFO", $null, $null)
                $TimeInterval = $HalvedHourlyTimeInterval
                $TimeSlicer.Reset()
                $TimeSlicer.IncrementTimeSlice($TimeInterval)

                # Check if the ResultEstimate is within expected limits.
                # If it is, go to next cycle, start log extraction process with new timeslice
                # And skip 
                if($ResultCountEstimate -le 20000) {
                    $TimeSlicer.IntervalAdjusted = $true
                }
                continue

            }

            # We need the result cumulus to keep track of the batch of 50k logs
            # These logs will get sort by date and the last date used as the new $StartTimeSlice value
            [System.Collections.ArrayList]$ResultCumulus = @()
            $Logger.LogMessage("Proceeding to log extraction", "INFO", $null, $null)
            $Logger.LogMessage("Current TimeSlice in local time: [StartDate] $($TimeSlicer.StartTimeSlice.ToString($TimeSlicer.Culture)) - [EndDate] $($TimeSlicer.EndTimeSlice.ToString($TimeSlicer.Culture))", "INFO", $null, $null)

            $ExportFileName = "$($Logger.ScriptPath)\$($env:COMPUTERNAME)-azurehunter-$($Logger.strTimeNow).csv"
            $RandomSessionName = "azurehunter-$(Get-Random)"

            while ($NumberOfAttempts -le 3) {

                Write-Host "NUmber of attemepts: $NumberOfAttempts"

                try {
                    $Script:Results = Search-UnifiedAuditLog -StartDate $TimeSlicer.StartTimeSliceUTC -EndDate $TimeSlicer.EndTimeSliceUTC -ResultSize 5000 -SessionCommand ReturnLargeSet -SessionId $RandomSessionName
                    $ResultCountEstimate = $Results[0].ResultCount
                    $EndResultIndex = $Results[($Results.Count - 1)].ResultIndex
                    $Logger.LogMessage("Result Size: $ResultCountEstimate", "INFO", $null, $null)

                    # Reset NumberOfAttempts if it succeded and this loop is running after a fail
                    if (($NumberOfAttempts -gt 1) -and ($Results.Count -ge 1)) {
                        $NumberOfAttempts = 1
                    }

                    # Log extraction most likely succeeded
                    break
                }
                catch {
                    $Logger.LogMessage("Failed to query Azure API: Attempt $NumberOfAttempts of 3", "ERROR", $null, $_)
                    $NumberOfAttempts++
                    continue
                }

            }

            # If we are continuing regular code execution after 3 failed attempts
            # need to increment timeslice for next run and reset $NumberOfAttempts counter
            if ($NumberOfAttempts -eq 3) {
                $Logger.LogMessage("Too many failed API call attempts. Incrementing time slice and continuing log extraction", "ERROR", $null, $null)
                $TimeSlicer.EndTimeSlice = $LastCreationDateRecord.ToLocalTime()
                $TimeSlicer.IncrementTimeSlice($TimeInterval)
                $NumberOfAttempts = 1
                continue
            }

            # Loop through paged results and extract all of them sequentially, before going into the next TimeSlice cycle
            # PROBLEM: the problem with this approach is that at some point Azure would start returning result indices 
            # that were not sequential and thus messing up the script. However this is the best way to export the highest
            # amount of logs within a timespan of 30 min (considering less than that is not accepted by Azure API). So the 
            # solution should be to implement a check and abort log exporting when result index stops being sequential.
            while((($EndResultIndex -ne $Results[0].ResultCount)) -xor $Results.Count -eq 0) {

                # Debug
                
                $Logger.LogMessage("ResultIndex End: $EndResultIndex", "DEBUG", $null, $null)
                $LastLogJSON = ($Results[($Results.Count - 1)] | ConvertTo-Json -Compress).ToString()
                $Logger.LogMessage($LastLogJSON, "LOW", $null, $null)

                # Export Results
                $StartingResultIndex = $Results[0].ResultIndex
                $Logger.LogMessage("Exporting records from $StartingResultIndex to $EndResultIndex", "INFO", $null, $null)
                $Results | Export-Csv $ExportFileName -NoTypeInformation -NoClobber -Append 
                $Results | ForEach-Object { $ResultCumulus.add($_) | Out-Null }

                # Run for next loop
                $Logger.LogMessage("Fetching next batch of logs. Session: $RandomSessionName", "DEBUG", $null, $null)
                $Results = Search-UnifiedAuditLog -StartDate $TimeSlicer.StartTimeSliceUTC -EndDate $TimeSlicer.EndTimeSliceUTC -ResultSize 5000 -SessionCommand ReturnLargeSet -SessionId $RandomSessionName
                $EndResultIndex = $Results[($Results.Count - 1)].ResultIndex
            }

            $Logger.LogMessage("Exporting records from $StartRecordIndex to $($TotalRecords + $EndResultIndex)", "DEBUG", $null, $null)
            $TotalRecords = $TotalRecords + $EndResultIndex
            $Logger.LogMessage("Total exported records so far: $TotalRecords", "INFO", $null, $null)
            $StartRecordIndex = $TotalRecords

            $SortedResults = $Results | Sort-Object -Property CreationDate
            $SortedResults | Export-Csv $ExportFileName -NoTypeInformation -NoClobber -Append 
            $LastCreationDateRecord = $SortedResults[($SortedResults.Count -1)].CreationDate

            $Logger.LogMessage("TimeStamp of latest received record in local time: $($LastCreationDateRecord.ToLocalTime().ToString($TimeSlicer.Culture))", "DEBUG", $null, $null)
            $TimeSlicer.EndTimeSlice = $LastCreationDateRecord.ToLocalTime()
            $TimeSlicer.IncrementTimeSlice($TimeInterval)

            <#
            # Increase time slice for the next loop according to timestamp of latest received event
            # Azure records are returned in UTC, so we need to provide the local value equivalent for $TimeSlicer.EndTimeSlice
            # The TimeSlicer class takes care of generating equivalent UTC timestamps
            # Here, setting $TimeSlicer.EndTimeSlice to the latest timestamp of received records, causes the slicer to consider that as the starting point for the next slice calculation
            $SortedCumulus = $ResultCumulus | Sort-Object -Property CreationDate
            $LastCreationDateRecord = $SortedCumulus[($SortedCumulus.Count -1)].CreationDate
            $Logger.LogMessage("TimeStamp of latest received record in local time: $($LastCreationDateRecord.ToLocalTime())", "INFO", $null, $null)
            $TimeSlicer.EndTimeSlice = $LastCreationDateRecord.ToLocalTime()
            $TimeSlicer.IncrementTimeSlice($TimeInterval)
            #>
        }
    }
}

