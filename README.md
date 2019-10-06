# Get-PSLogSizeEstimate
Get-PSLogSizeEstimate - Estimate SIEM storage requirements for PowerShell logs

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

# Usage

!(https://github.com/robwillisinfo/Get-PSLogSizeEstimate/blob/master/Get-PSLogSizeEstimate.jpg)

Use the following command to load the script into the current PowerShell session:

PS> . .\Get-PSLogSizeEstimate.ps1

Get-PSLogSizeEstimate accepts the following command line parameters:

    -EventID / -e: Required, the event ID’s to filter out, ex 4103, 4104.
    -Retention / -r: Required, the rentention period in days, ex 30.
    -ComputerName / -c: Optional, a remote machine to gather the PowerShell logs from, ex Win-DC01.
    -OutputFile / -o: Optional, the name of the file to save the output to, ex test-output.txt.
                      Default value – Get-PSLogSizeEstimate-output.txt.

Example usage:

Gather log info from the local host:

PS> Get-PSLogSizeEstimate -EventID 4103,4104 -Retention 30 -Verbose

Gather log info from a remote host:

PS> Get-PSLogSizeEstimate -EventID 4103,4104 -Retention 30 -ComputerName DC01 -OutputFile Get-PSLogSizeEstimate-DC01.txt -Verbose

And the shorthand version of the previous command:

PS> Get-PSLogSizeEstimate -e 4103,4104 -r 30 -c DC01 -o Get-PSLogSizeEstimate-DC01.txt -Verbose


