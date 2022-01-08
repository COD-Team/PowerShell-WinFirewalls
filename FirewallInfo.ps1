<#
    .DESCRIPTION
        Script pulls Firewall Log from Local Workstation.

    .OUTPUTS
        Report found under $logPath below, default is c:\COD-Logs\COMPUTERNAME\DATETIME
    
    .EXAMPLE
        1. PowerShell 5.1 Command Prompt (Admin) 
            "powershell -Executionpolicy Bypass -File PATH\FILENAME.ps1"
        2. Powershell 7.2.1 Command Prompt (Admin) 
            "pwsh -Executionpolicy Bypass -File PATH\FILENAME.ps1"

    .NOTES
        Author Perkins
        Last Update 1/7/22
        Updated 1/7/22 Tested and Validated PowerShell 5.1 and 7.2.1
    
        Powershell 5 or higher
        Run as Administrator
    
    .FUNCTIONALITY
        PowerShell Language
        Active Directory
    
    .Link
        https://github.com/COD-Team
        YouTube Video https://youtu.be/4LSMP0gj1IQ
        
    Thanks to Twan van Beers - Across my Lab I noticed that two computers were not functioning as intented
    All the firewall settings were in place, but there were no logs. 
    https://neroblanco.co.uk/2017/03/windows-firewall-not-writing-logfiles/

    Thanks to Martin Norlunn for the Class
    https://www.powershellgallery.com/packages/Get-WindowsFwLog/1.0/Content/Get-WindowsFwLog.ps1
#>

# If you are not an Administrator, Script will Exit
#Requires -RunAsAdministrator

# If you are not on Powershell version 5.1 or higher, Script will Exit
$versionMinimum = [Version]'5.1.000.000'
    if ($versionMinimum -gt $PSVersionTable.PSVersion)
    { throw "This script requires PowerShell $versionMinimum" }

$ComputerName = $env:computername    

$logpath = "C:\COD-Logs\$ComputerName\$(get-date -format "yyyyMMdd-hhmmss")"
If(!(test-path $logpath))
{
        New-Item -ItemType Directory -Force -Path $logpath
}

# Added 1/7/21 PowerShell 7.2.1 Compatibility for Out-File not printing escape characters
if ($PSVersionTable.PSVersion.major -ge 7) {$PSStyle.OutputRendering = 'PlainText'}

$OutputFile = "$logpath\FirewallInformation.log"
$ExportFile = "$Logpath\FirewallLog.CSV"

# Windows Default Firewall Log Path and Files
#$LogFile = 'C:\Windows\system32\LogFiles\Firewall\pfirewall.log.old'
$LogFile = 'C:\Windows\system32\LogFiles\Firewall\pfirewall.log'


class WindowsFwLogEntry
{
    [datetime]$DateTime
    [string]$Action
    [string]$Protocol
    [String]$SourceIP
    [String]$DestinationIP
    [string]$SourcePort
    [string]$DestinationPort
    [string]$Size
    [string]$TcpFlags
    [string]$TcpSync
    [string]$TcpAck
    [string]$TcpWin
    [string]$IcmpType
    [string]$IcmpCode
    [string]$Info
    [string]$Path

    WindowsFwLogEntry ([string]$Raw)
    {
        $Parts = $Raw -split " "
        $this.DateTime = "$($Parts[0]) $($Parts[1])"
        $this.Action = $Parts[2]
        $this.Protocol = $Parts[3]
        $this.SourceIP = $Parts[4]
        $this.DestinationIP = $Parts[5]
        $this.SourcePort = $Parts[6]
        $this.DestinationPort = $Parts[7]
        $this.Size = $Parts[8]
        $this.TcpFlags = $Parts[9]
        $this.TcpSync = $Parts[10]
        $this.TcpAck = $Parts[11]
        $this.TcpWin = $Parts[12]
        $this.IcmpType = $Parts[13]
        $this.IcmpCode = $Parts[14]
        $this.Info = $Parts[15]
        $this.Path = $Parts[16]
    }
}
Write-Host -ForegroundColor Yellow "Getting Firewall Log: $LogFile"

# Skipping first 5 lines, the pfirewall.log has 5 rows of junk.
$LogEntries = Get-Content -Path $LogFile | Select-Object -Skip 5 #-first 10
$Lines = $LogEntries.length

Write-Host -ForegroundColor Yellow "Parsing $Lines Lines of the Firewall Log"
$LogEntries = $LogEntries | ForEach-Object {
    Try {[WindowsFwLogEntry]::new($_)}
    Catch {}
}

# Add and Modify for your Environment - Just added a few to allow you to start analyzing your logs


$LogEntries | Select-Object Protocol, DestinationPort, Action | Group-Object Protocol, Destinationport, Action | Select-Object Count, Name | Out-File $OutputFile -append

# Return Unique SourceIPAddress that were Dropped
$LogEntries | Select-Object SourceIP, Action -Unique | Where-Object Action -eq Drop | Sort-Object SourceIP | Out-File $OutputFile -append 

# Returns Unique SourcesIP, Action, DestinationPort and Action
$LogEntries | Select-Object SourceIP, Action, DestinationPort -Unique | Sort-Object SourceIP, DestinationPort | Out-File $OutputFile -append
 

$LogEntries | Select-Object DateTime, Action, Protocol, SourceIP, SourcePort, DestinationIP, DestinationPort, Size, TcpFlags, TcpSync, TcpWin, IcmpType, IcmpCode, Info, Path | Export-CSV $ExportFile -NoTypeInformation

Write-Output "Log File Saved to $OutputFile" | Out-File $OutputFile -append
Write-Output "CSV File Saved to $ExportFile" | Out-File $OutputFile -append
Write-Host -ForegroundColor Green "Log File Saved to $OutputFile"

Start-Process Notepad.exe $OutputFile -NoNewWindow
$LogEntries | Select-Object DateTime, Action, Protocol, SourceIP, SourcePort, DestinationIP, DestinationPort, Size, TcpFlags, TcpSync, TcpWin, IcmpType, IcmpCode, Info, Path | Out-GridView -PassThru
