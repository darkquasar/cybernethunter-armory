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
    [String] $DateTime
    [Int32] $Interval
    [System.Globalization.CultureInfo] $AUCulture
    [DateTime] $ParsedDate
    [DateTime] $StartTimeSlice
    [DateTime] $EndTimeSlice

    # Default, Parameterless Constructor
    TimeStamp() {
        $this.AUCulture = New-Object System.Globalization.CultureInfo("en-AU")
    }

    # Constructor
    ParseDateString ([String] $TimeStamp) {
        $this.ParsedDate = [DateTime]::ParseExact($TimeStamp, $this.AUCulture.DateTimeFormat.SortableDateTimePattern, $null)
    }

    IncrementTimeSlice ([float] $HourlySlice) {

        # if running method for the first time, configure $StartTimeSlice with the $ParsedDate
        if(($this.StartTimeSlice -lt $this.ParsedDate) -and ($this.EndTimeSlice -lt $this.ParsedDate)) {
            $this.StartTimeSlice = $this.ParsedDate
            $this.EndTimeSlice = $this.ParsedDate.AddHours($HourlySlice)
        }
        else {
            $this.StartTimeSlice = $this.EndTimeSlice
            $this.EndTimeSlice = $this.StartTimeSlice.AddHours($HourlySlice)
        }
    }
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
            HelpMessage='The amount of records you would like returned from the search. Defaults to 100. If value is 0 it means ALL records will be returned'
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
        [int]$AutomaticTimeWindowReduction
    )

    PROCESS {

        # Grab Start and End Timestamps
        $StartTime = [TimeStamp]::New()
        $EndTime = [TimeStamp]::New()
        $StartTime.ParseDateString($StartDate)
        $EndTime.ParseDateString($EndDate)
        $StartTime.IncrementTimeSlice($TimeInterval)
        
        #while($StartTime.StartTimeSlice -ne $EndTime.ParsedDate) {
            # do things
            # search audit log between $StartTime.StartTimeSlice and $StartTime.EndTimeSlice

            if(($Results.Count -eq 5000) -and $AutomaticTimeWindowReduction) {
                $TimeInterval = $TimeInterval / 2
            }
            # increase time slice
            # $StartTime.IncrementTimeSlice($TimeInterval)
        #}
    }
}

