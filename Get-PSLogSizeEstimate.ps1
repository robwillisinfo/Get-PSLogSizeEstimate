function Get-PSLogSizeEstimate {
<# 
.SYNOPSIS

Get-PSLogSizeEstimate - Estimates SIEM storage requirements for PowerShell logs.

.DESCRIPTION

This function will produce a report based on the Microsoft-Windows-PowerShell/Operational
log with two estimations (All Events vs Specified Events) of how much space would be 
required to store the logs given the specified rentention time in days.

This is extremely useful data to have if you are interested in the amount of storage 
that will be required when ingesting these logs into a central respository or SIEM.

How the estimate is calculated:
1. The size of the log divided by the total number of events in the log = The average event size
2. Retention period divided by timespan of the newest and oldest events in the log = Log Rotations per
   the defined retention period 
3. Building off the data from the two previous steps:
   Number of events x average event size x estimated log rotations per specified rentention period = 
   estimated storage requirement

Author: Rob Willis (robwillis.info) 

.PARAMETER -EventID

Specifies the Event ID's to be included in the estimation excluding all others. Useful to 
decrease the amount of storage required. Alias -e.

.PARAMETER -Retention

The retention period in days to use in the estimation. Alias -r.

.PARAMETER -OutputFile

The location/name of the file to output the report data to. Alias -o.

.PARAMETER -ComputerName

This parameter can be used to get the logs from a remote host and create the report based off of 
the data. It is assumed that the user running the script has the correct permissions to 
access the remote host. Alias -c.

.EXAMPLE

C:\PS> Get-PSLogSizeEstimate -EventID 4103,4104 -Retention 30 -Verbose -OutputFile localhost.txt -Verbose
C:\PS> Get-PSLogSizeEstimate -e 4103,4104 -r 30 -Verbose -OutputFile localhost.txt -Verbose

.EXAMPLE

C:\PS> Get-PSLogSizeEstimate -EventID 4103,4104 -Retention 90 -ComputerName DC01 -Verbose -OutputFile DC01.txt -Verbose

.LINK

#>

    [CmdletBinding()] Param(
    [Parameter(Mandatory = $true)]
    [Alias("e")]
    [String[]]  
    $EventID,

    [Parameter(Mandatory = $true)]
    [Alias("r")]
    [int]  
    $Retention,

    [Parameter(Mandatory = $false)]
    [Alias("o")]
    [String]
    $OutputFile = "Get-PSLogSizeEstimate-output.txt",

    [Parameter(Mandatory = $false)]
    [Alias("c")]
    [String]
    $ComputerName = "localhost"
    )

    # If no ComputerName is entered, use the local hostname
    if ($ComputerName -eq "localhost") {
        $ComputerName = hostname
    }

    # Gather the inital PowerShell logs
    Write-Verbose "Gathering the PowerShell event logs from $ComputerName..."
    $RawPSEvents = Get-WinEvent Microsoft-Windows-PowerShell/Operational -ComputerName $ComputerName
    Write-Verbose ("Total events in the PowerShell Operational log: " + $RawPSEvents.count)
    
    # Get the max size of the log - Default is 15 MB or 15360 KB
    $PSMaxLogSize = Get-WinEvent -ListLog Microsoft-Windows-PowerShell/Operational
    $PSMaxLogSizeMB = [math]::Round(($PSMaxLogSize.MaximumSizeInBytes / 1MB),2)
    Write-Verbose ("Maximum size for the PowerShell Operational log: " + $PSMaxLogSizeMB + "MB")
    # Get the size of the current evtx file to see if the log is full
    $PSLogFileSize = (Get-ChildItem C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx).Length
    $PSLogFileSizeMB = [math]::Round(($PSLogFileSize / 1MB),2)
    Write-Verbose ("The current size of the Microsoft-Windows-PowerShell%4Operational.evtx log file: " + $PSLogFileSizeMB + "MB")
    # Compare the max size vs the current size of the evtx, use the lower value for accuracy
    if ($PSLogFileSize -lt $PSMaxLogSize.MaximumSizeInBytes) {
        Write-Verbose ("The size of Microsoft-Windows-PowerShell%4Operational.evtx is smaller than the max log size, using this value instead: " + $PSLogFileSizeMB + "MB")
        $PSLogSize = $PSLogFileSize - 68000 # Removing the 68KB overhead for the log file itself
    } else {
        Write-Verbose ("The PowerShell log appears to be full, using the max log size value: " + $PSMaxLogSizeMB + "MB")
        $PSLogSize = $PSMaxLogSize.MaximumSizeInBytes - 68000 # Removing the 68KB overhead for the log file itself
    }
    
    # Convert from bytes to MB for use in the report later
    $PSLogSizeMB = [math]::Round(($PSLogSize / 1MB),2)
    Write-Verbose ("Log size value subtracting the 68KB log overhead: " + $PSLogSizeMB + "MB")

    # Get the average event size by dividing the max log size by the total event count
    $AvgEventSize = $PSLogSize / $RawPSEvents.count
    $AvgEventSizeKB = [math]::Round(($AvgEventSize / 1KB),2)
    Write-Verbose ("Average event size: " + $AvgEventSizeKB + "KB")
    
    # Get the newest and oldest event time stamps along with the span between them
    $NewestPSEvent = $RawPSEvents | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
    Write-Verbose ("Newest event in log timestamp: " + $NewestPSEvent.TimeCreated)
    $OldestPSEvent = $RawPSEvents | Sort-Object -Property TimeCreated | Select-Object -First 1
    Write-Verbose ("Oldest event in log timeStamp: " + $OldestPSEvent.TimeCreated)
    $LogTimeSpan = New-TimeSpan -Start $NewestPSEvent.TimeCreated -End $OldestPSEvent.TimeCreated 
    Write-Verbose ("Timespan between events: " + $LogTimeSpan)
    # Estimate how many times the log will roll based off the Timespan between the first and last log event and the specified rentention period in days
    $TimeSpan = (New-TimeSpan -Days $Retention)
    $EstimatedLogRotations = ($TimeSpan.TotalSeconds / $LogTimeSpan.TotalSeconds) * -1
    Write-Verbose ("Estimated log rotations in $Retention days: " + $EstimatedLogRotations)

    # Parse data out for the specific Event IDs
    # Create an empty hash table to store data
    $FilteredEventCounts = @{}
    foreach ($ID in $EventID) {
        Write-Verbose "Filtering out data for event ID $ID..."
        $FilteredEvents = $RawPSEvents | Where-Object {$_.ID -match "^($ID)$"}
        Write-Verbose ("Total $ID events: " + $FilteredEvents.count)
        # Build out a hash table with the data
        $FilteredEventCounts.Add($ID, $FilteredEvents.count)
    }

    # Caculating the estimated log sizes
    $EstimatedPSLogSizeAllEvents = $RawPSEvents.count * $AvgEventSize * $EstimatedLogRotations
    $EstimatedPSLogSizeAllEventsKB = [math]::Round(($EstimatedPSLogSizeAllEvents / 1KB),2)
    $EstimatedPSLogSizeAllEventsMB = [math]::Round(($EstimatedPSLogSizeAllEvents / 1MB),2)
    $EstimatedPSLogSizeAllEventsGB = [math]::Round(($EstimatedPSLogSizeAllEvents / 1GB),2)
    Write-Verbose ("The estimated storage required for $Retention days of events: " + $EstimatedPSLogSizeAllEventsKB + "KB / " + $EstimatedPSLogSizeAllEventsMB + "MB / " + $EstimatedPSLogSizeAllEventsGB + "GB")

    $TotalCountFilteredEvents = ($FilteredEventCounts.values | Measure-Object -Sum).Sum
    $EstimatedPSLogSizeFilteredEvents = $TotalCountFilteredEvents * $AvgEventSize * $EstimatedLogRotations
    $EstimatedPSLogSizeFilteredEventsKB = [math]::Round(($EstimatedPSLogSizeFilteredEvents / 1KB),2)
    $EstimatedPSLogSizeFilteredEventsMB = [math]::Round(($EstimatedPSLogSizeFilteredEvents / 1MB),2)
    $EstimatedPSLogSizeFilteredEventsGB = [math]::Round(($EstimatedPSLogSizeFilteredEvents / 1GB),2)
    Write-Verbose ("Filtering out the following event ID's: " + $FilteredEventCounts.Keys)
    Write-Verbose ("Total number of filtered events: " + $TotalCountFilteredEvents)
    Write-Verbose ("The estimated storage required for $Retention days of events with filtering applied: " + $EstimatedPSLogSizeFilteredEventsKB + "KB / "+ $EstimatedPSLogSizeFilteredEventsMB + "MB / " + $EstimatedPSLogSizeFilteredEventsGB + "GB")
    
    # Build the report
    Write-Verbose "Building the report..."
    
"[+]-------------------------------------------------------------------------------------------------------------------------------------------" +
"`r`n |  Get-PSLogSizeEstimate Output - Hostname: " + $ComputerName +
"`r`n[+]-------------------------------------------------------------------------------------------------------------------------------------------" +
"`r`n |  Stats from this sample of log data:                                  " +
"`r`n |                                                                       " +
"`r`n |  Total events in the PowerShell Operational log: " + $RawPSEvents.count +
"`r`n |  Total events after filtering by the specified event ID(s): " + $TotalCountFilteredEvents +
"`r`n |  Maximum size for the PowerShell Operational log: " + $PSMaxLogSizeMB + "MB" +
"`r`n |  Microsoft-Windows-PowerShell%4Operational.evtx log size: " + $PSLogFileSizeMB + "MB" +
"`r`n |  Log size used in calculations (subtracting the 68KB log overhead): " + $PSLogSizeMB + "MB" +
"`r`n |  Average event size: " + $AvgEventSizeKB + "KB" + 
"`r`n |  Newest event in log timestamp: " + $NewestPSEvent.TimeCreated +
"`r`n |  Oldest event in log timestamp: " + $OldestPSEvent.TimeCreated +
"`r`n |  Timespan between events: " + $LogTimeSpan +
"`r`n |  Estimated log rotations in $Retention days (retention period / timespan of first and last log events): " + $EstimatedLogRotations +
"`r`n[+]-------------------------------------------------------------------------------------------------------------------------------------------" +
"`r`n |  Storage Estimations                                                  " +
"`r`n[+]-------------------------------------------------------------------------------------------------------------------------------------------" +
"`r`n |  How the estimations are calculated:                                  " + 
"`r`n |  # of events x average event size x estimated log rotations per specified rentention period" +
"`r`n |                                                                       " +
"`r`n |  All Events (No Filtering)                                            " +
"`r`n |  The estimated storage required for $Retention days of events: " + $EstimatedPSLogSizeAllEventsKB + "KB / " + $EstimatedPSLogSizeAllEventsMB + "MB / " + $EstimatedPSLogSizeAllEventsGB + "GB" +
"`r`n |                                                                       " +
"`r`n |  Filtered Data                                                        " +
"`r`n |  Filtered events ID's: " + $FilteredEventCounts.Keys +
"`r`n |  The estimated storage required for $Retention days of events with filtering applied: " + $EstimatedPSLogSizeFilteredEventsKB + "KB / " + $EstimatedPSLogSizeFilteredEventsMB + "MB / " + $EstimatedPSLogSizeFilteredEventsGB + "GB" +
"`r`n[+]-------------------------------------------------------------------------------------------------------------------------------------------" | Out-File -FilePath $OutputFile    

    Write-Verbose "Report saved to $OutputFile"

} # End of Function
